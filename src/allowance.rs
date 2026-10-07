//! Owner allowance (EXT-8, `mesh://extensions/allowance/v1`) — what an owner
//! will let their own agent spend.
//!
//! The budget's complement, and easy to conflate with it: a **budget** (§7.7)
//! travels with work between parties and guards the *requester's* money; an
//! **allowance** stays at home, guards the *owner's* money against their own
//! agent's appetite, and binds nobody but that agent's own node. It is a
//! locally-held signed policy document, never a wire field — no counterparty
//! ever sees it — and the seam between the two ceilings is §7.7's
//! refusal-with-estimate: on the wire an allowance-broke refusal is
//! deliberately indistinguishable from a budget-broke one.
//!
//! What lives here:
//!
//!  - [`Allowance`] — the EXT-8 §1 document: owner-signed under the
//!    `agentmesh-allowance-v1` tag (the same tagged canonical-JSON convention
//!    as the envelope, the vouch and the room descriptor), absent fields
//!    OMITTED, never null. [`load_allowance`] is the enforcement loader
//!    (shape + signature); [`sign_allowance`] is the owner-tooling half;
//!    [`verify_allowance_signature`] judges the signature alone, over the raw
//!    document, so shape rejection never depends on a signature failure.
//!  - **Fail-closed** (EXT-8 §1): a node configured with an allowance that
//!    does not verify MUST NOT treat it as absent — every ceiling reads as
//!    exhausted (the document's `on_exhausted` behaviour still applies) until
//!    a valid document replaces it. [`AllowanceMeter::arm`] implements exactly
//!    that: a failed arm is observable (the error returns, and
//!    [`AllowanceMeter::status`] says [`AllowanceStatus::FailClosed`]) but the
//!    meter is armed shut, not disarmed.
//!  - **Metering** (EXT-8 §2): the node cannot see the model's bill, so the
//!    host reports usage ([`Usage::Tokens`] or [`Usage::CostMicro`]) and the
//!    meter converts by the owner's declared [`AllowanceCostModel`]:
//!    `cost_micro = floor(tokens × per_1k_tokens_micro / 1000)`, integer
//!    arithmetic, FLOOR pinned by `conformance/allowance.json` so two nodes
//!    never disagree by a micro-unit. Metered spend is accounted to the Task,
//!    to its `context_id`, and to the UTC day — the [`SpendLedger`].
//!  - **Admission** ([`AllowanceMeter::check_admission`]): every applicable
//!    ceiling applies at once; specificity decides what a ceiling *covers*,
//!    never which one wins — the **binding** ceiling is whichever applicable
//!    one has the smallest *remaining* amount. Work whose estimate exceeds
//!    the binding remainder is refused ([`allowance_insufficient`],
//!    `BUDGET_INSUFFICIENT` with `details.estimate` as the price) or, under
//!    `on_exhausted: "ask_owner"`, surfaced to the owner channel instead.
//!  - **Estimation** ([`estimate_tokens`]): the default admission estimate,
//!    used when the host registers no estimator of its own.
//!
//! `conformance/allowance.json` is the authority on all of it
//! (`tests/allowance_conformance.rs`); when this module and the fixture
//! disagree, this module is what changes.

use std::collections::HashMap;

use chrono::Utc;
use nkeys::KeyPair;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::budget::{budget_insufficient, CostCeiling};
use crate::error::{ErrorCode, MeshError, Result};
use crate::identity::{b64url, canonical_json, tagged_sig_bytes, unb64url, verify_tagged};
use crate::inbound::{inbound_text_length, parse_instant_ms};
use crate::trial::TrialFunds;

/// The domain tag inside an allowance's signed bytes (EXT-8 §1): the ASCII
/// prefix, one newline, then the canonical JSON (§5.3) of the document
/// excluding `sig`. The prefix exists only inside the signed bytes — it never
/// appears in the document itself.
pub const ALLOWANCE_SIG_PREFIX: &str = "agentmesh-allowance-v1\n";

/// The default estimation basis: one token per this many characters of sender
/// text, rounded up. See [`estimate_tokens`].
pub const ESTIMATE_CHARS_PER_TOKEN: u64 = 4;

// ─── the document (EXT-8 §1) ────────────────────────────────────────────────

/// The owner's **declared** conversion from the agent's tokens to money. The
/// node cannot learn the model's price; the owner states it. A token rate is
/// legitimate here where §7.7 forbids it on the wire: tokens are the
/// responder's private units, and inside one household the owner knows exactly
/// whose units they are.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowanceCostModel {
    /// Integer micro-units of `currency` per 1,000 tokens (§19.3: no floating
    /// point ever touches money).
    pub per_1k_tokens_micro: u64,
    /// ISO 4217 currency code (e.g. `"USD"`).
    pub currency: String,
}

/// A ceiling's scope — a **closed** enum (EXT-8 §1). A consumer MUST reject an
/// unknown scope rather than ignore the ceiling: an ignored ceiling is an
/// unenforced one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CeilingScope {
    /// Applies to each Task individually — or, narrowed by `task_id`, to that
    /// one Task.
    Task,
    /// Applies to each context individually — or, narrowed by `context_id`,
    /// to that one context ("$3.00 at this event").
    Context,
    /// The UTC calendar day of the metering instant.
    Day,
    /// Trial work per UTC day (Common Agent 7.5 and 7.7): what the owner
    /// lets trial requests cost the publisher in one day. Trial spend counts
    /// against this ceiling AND every wider one (task, context, day);
    /// ordinary work never counts against it, and it never applies to
    /// ordinary admission.
    Trial,
}

impl CeilingScope {
    pub fn as_str(self) -> &'static str {
        match self {
            CeilingScope::Task => "task",
            CeilingScope::Context => "context",
            CeilingScope::Day => "day",
            CeilingScope::Trial => "trial",
        }
    }
}

/// One spending ceiling. `task_id` / `context_id` are OMITTED when absent
/// (never null), per the document's canonicalization discipline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowanceCeiling {
    pub scope: CeilingScope,
    /// Narrows a `task` ceiling to that one Task.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    /// Narrows a `context` ceiling to that one context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    /// Non-negative integer micro-units. Zero is legal — a ceiling pinned
    /// shut.
    pub amount_micro: u64,
}

/// What the node does when admitting work would cross a ceiling (EXT-8 §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnExhausted {
    /// Refuse at admission with `BUDGET_INSUFFICIENT` carrying
    /// `details.estimate` — no owner interaction, no work performed.
    Refuse,
    /// Do NOT refuse: hold the work unstarted and surface the question through
    /// the node's owner channel; proceed only if the owner approves, and
    /// refuse with the same `BUDGET_INSUFFICIENT` shape if the owner declines.
    AskOwner,
}

/// The EXT-8 §1 allowance document: a single JSON document per agent, signed
/// by the owner key and held at the agent's node. Replaced whole — the latest
/// `updated_at` under a valid signature is the policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Allowance {
    /// The document format version — the integer `1`.
    pub v: u64,
    /// The agent key this allowance governs. One document per agent.
    pub agent: String,
    /// The signer. A node MUST verify `sig` against it before enforcing.
    pub owner_key: String,
    pub cost_model: AllowanceCostModel,
    /// One or more ceilings, every applicable one applied at once.
    pub ceilings: Vec<AllowanceCeiling>,
    pub on_exhausted: OnExhausted,
    /// RFC 3339 UTC.
    pub updated_at: String,
    /// base64url owner-key signature over [`ALLOWANCE_SIG_PREFIX`] + the
    /// canonical document (sig excluded). OMITTED when absent — the unsigned
    /// state exists only in owner tooling on its way to [`sign_allowance`];
    /// [`load_allowance`] refuses a document without one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
}

// ─── shape validation ───────────────────────────────────────────────────────

fn shape_err(message: impl Into<String>) -> MeshError {
    MeshError::code(ErrorCode::InvalidEnvelope, message)
}

/// A money field per §19.3: a non-negative integer number of micro-units.
/// The two spellings of "not money" get their own refusals so a fixture case
/// is rejected for exactly its stated reason.
fn money_u64(v: Option<&Value>, field: &str) -> Result<u64> {
    let Some(v) = v else {
        return Err(shape_err(format!("Allowance {field} is required (EXT-8 §1)")));
    };
    if let Some(u) = v.as_u64() {
        return Ok(u);
    }
    if v.is_number() {
        if v.as_f64().is_some_and(|f| f < 0.0) {
            return Err(shape_err(format!(
                "Allowance {field} must be non-negative — a pinned-shut ceiling is 0, never \
                 negative (EXT-8 §1)"
            )));
        }
        return Err(shape_err(format!(
            "Allowance {field} must be an integer number of micro-units — never a float \
             (§19.3: no floats near money)"
        )));
    }
    Err(shape_err(format!("Allowance {field} must be an integer (§19.3)")))
}

fn required_str<'v>(map: &'v serde_json::Map<String, Value>, field: &str) -> Result<&'v str> {
    match map.get(field).and_then(Value::as_str) {
        Some(s) if !s.is_empty() => Ok(s),
        _ => Err(shape_err(format!(
            "Allowance {field} is required and must be a non-empty string (EXT-8 §1)"
        ))),
    }
}

/// Validate the EXT-8 §1 document shape over the raw JSON, `sig` excepted —
/// see [`validate_allowance_value`] for the enforcement-side judgement that
/// includes it. Deliberately a `Value`-level check rather than serde's, so
/// each fixture `invalid` case is refused for exactly its stated reason and
/// shape rejection never depends on a signature failure.
fn validate_allowance_shape(doc: &Value) -> Result<()> {
    let Some(map) = doc.as_object() else {
        return Err(shape_err("An allowance is a JSON object (EXT-8 §1)"));
    };
    if map.get("v").and_then(Value::as_u64) != Some(1) {
        return Err(shape_err("Allowance v must be the integer 1 (EXT-8 §1)"));
    }
    required_str(map, "agent")?;
    required_str(map, "owner_key")?;

    // cost_model is REQUIRED: a ceiling without a declared conversion cannot
    // be metered against, and a document that cannot be metered against
    // enforces nothing.
    let Some(cost_model) = map.get("cost_model").and_then(Value::as_object) else {
        return Err(shape_err(
            "Allowance cost_model is required (EXT-8 §1: without a declared conversion the \
             ceilings cannot be metered against)",
        ));
    };
    money_u64(cost_model.get("per_1k_tokens_micro"), "cost_model.per_1k_tokens_micro")?;
    required_str(cost_model, "currency")?;

    let Some(ceilings) = map.get("ceilings").and_then(Value::as_array) else {
        return Err(shape_err("Allowance ceilings is required and must be an array (EXT-8 §1)"));
    };
    if ceilings.is_empty() {
        return Err(shape_err("Allowance ceilings must hold one or more ceilings (EXT-8 §1)"));
    }
    for c in ceilings {
        let Some(c) = c.as_object() else {
            return Err(shape_err("Each allowance ceiling is a JSON object (EXT-8 §1)"));
        };
        match c.get("scope").and_then(Value::as_str) {
            Some("task") | Some("context") | Some("day") | Some("trial") => {}
            other => {
                return Err(shape_err(format!(
                    "Allowance ceiling scope {} is not in the closed enum task | context | day | \
                     trial (EXT-8 §1: an ignored ceiling is an unenforced one)",
                    other.map(|s| format!("'{s}'")).unwrap_or_else(|| "(missing)".to_string()),
                )));
            }
        }
        money_u64(c.get("amount_micro"), "ceilings[].amount_micro")?;
        for narrow in ["task_id", "context_id"] {
            match c.get(narrow) {
                None => {}
                Some(Value::String(s)) if !s.is_empty() => {}
                // Absent fields are OMITTED in canonical JSON, never null —
                // a null narrow is a second spelling of absence, which
                // canonical signing cannot tolerate.
                Some(_) => {
                    return Err(shape_err(format!(
                        "Allowance ceiling {narrow}, when present, must be a non-empty string — \
                         absent is omitted, never null (EXT-8 §1)"
                    )));
                }
            }
        }
    }

    match map.get("on_exhausted").and_then(Value::as_str) {
        Some("refuse") | Some("ask_owner") => {}
        _ => {
            return Err(shape_err(
                "Allowance on_exhausted must be one of refuse | ask_owner (EXT-8 §1)",
            ));
        }
    }

    let updated_at = required_str(map, "updated_at")?;
    if parse_instant_ms(updated_at).is_none() {
        return Err(shape_err(format!(
            "Allowance updated_at '{updated_at}' is not an RFC 3339 instant (EXT-8 §1)"
        )));
    }
    Ok(())
}

/// Validate the full enforcement-side document shape: [the §1
/// shape](validate_allowance_shape) plus a present, non-empty `sig` — a node
/// MUST NOT enforce an unsigned document.
pub fn validate_allowance_value(doc: &Value) -> Result<()> {
    validate_allowance_shape(doc)?;
    match doc.get("sig").and_then(Value::as_str) {
        Some(s) if !s.is_empty() => Ok(()),
        _ => Err(shape_err(
            "Allowance sig is required: a node MUST NOT enforce an unsigned document, and MUST \
             NOT treat it as absent — it fails closed until a valid document replaces it \
             (EXT-8 §1)",
        )),
    }
}

// ─── signing and verification ───────────────────────────────────────────────

/// The canonical bytes a signature covers, before tagging: the canonical JSON
/// (§5.3) of the document excluding `sig`.
pub fn canonical_allowance_bytes(doc: &Value) -> Result<Vec<u8>> {
    let mut v = doc.clone();
    let Some(map) = v.as_object_mut() else {
        return Err(shape_err("An allowance is a JSON object (EXT-8 §1)"));
    };
    map.remove("sig");
    Ok(canonical_json(&v).into_bytes())
}

/// Verify a document's `sig` against its own `owner_key`, over the raw JSON —
/// no shape judgement. The signature question and the shape question are
/// deliberately separable: every fixture `invalid` case except `missing_sig`
/// carries a GENUINE owner signature, so shape rejection never depends on a
/// signature failure and this predicate answers `true` for them.
pub fn verify_allowance_signature(doc: &Value) -> bool {
    let Some(owner_key) = doc.get("owner_key").and_then(Value::as_str) else { return false };
    let Some(sig_str) = doc.get("sig").and_then(Value::as_str) else { return false };
    let Ok(sig) = unb64url(sig_str) else { return false };
    let Ok(canonical) = canonical_allowance_bytes(doc) else { return false };
    match KeyPair::from_public_key(owner_key) {
        Ok(vpub) => verify_tagged(&vpub, ALLOWANCE_SIG_PREFIX, &canonical, &sig),
        Err(_) => false,
    }
}

/// Owner tooling: sign an allowance with the owner keypair, setting
/// `owner_key` from it and `sig` over the tagged canonical bytes
/// ([`ALLOWANCE_SIG_PREFIX`] + canonical JSON, sig excluded). The document is
/// shape-checked first — owner tooling has no business signing a document the
/// agent's node would then have to fail closed on.
pub fn sign_allowance(doc: &mut Allowance, owner_kp: &KeyPair) -> Result<()> {
    doc.owner_key = owner_kp.public_key();
    doc.sig = None;
    let v = serde_json::to_value(&*doc)?;
    validate_allowance_shape(&v)?;
    let bytes = tagged_sig_bytes(ALLOWANCE_SIG_PREFIX, &canonical_allowance_bytes(&v)?);
    let sig = owner_kp.sign(&bytes).map_err(|e| MeshError::Nkey(e.to_string()))?;
    doc.sig = Some(b64url(&sig));
    Ok(())
}

/// The enforcement loader: shape (EXT-8 §1, `sig` required), then the owner
/// signature, then the typed document. The caller arming a node should treat
/// an `Err` here as **fail-closed, not absent** — [`AllowanceMeter::arm`]
/// does exactly that.
pub fn load_allowance(doc: &Value) -> Result<Allowance> {
    validate_allowance_value(doc)?;
    if !verify_allowance_signature(doc) {
        return Err(MeshError::code(
            ErrorCode::IdentityMismatch,
            "Allowance sig does not verify against owner_key (EXT-8 §1: the node fails closed — \
             every ceiling exhausted — until a valid document replaces this one)",
        ));
    }
    serde_json::from_value(doc.clone()).map_err(MeshError::from)
}

// ─── metering (EXT-8 §2) ────────────────────────────────────────────────────

/// `cost_micro = floor(tokens × per_1k_tokens_micro / 1000)`, integer
/// arithmetic throughout. FLOOR, pinned by the fixture: rounding toward zero
/// means the node never charges a partial micro-unit against the owner's
/// ceiling, and any two nodes that meter the same invocation agree to the
/// micro-unit. Computed in 128-bit and saturated at `u64::MAX`, so no product
/// of two legal u64 fields can wrap money.
pub fn meter_cost_micro(tokens: u64, per_1k_tokens_micro: u64) -> u64 {
    u64::try_from((tokens as u128 * per_1k_tokens_micro as u128) / 1000).unwrap_or(u64::MAX)
}

/// What the host reports for a model invocation — the SDK cannot see the
/// host's model bill, so the host states usage and the meter does the
/// arithmetic. Tokens convert by the armed document's declared
/// [`AllowanceCostModel`]; a host that already knows money reports it
/// directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Usage {
    /// Model tokens consumed; converted via [`meter_cost_micro`].
    Tokens(u64),
    /// Spend already denominated in integer micro-units of the allowance's
    /// currency.
    CostMicro(u64),
}

/// The default admission estimate: `ceil(chars / 4)` tokens, where `chars` is
/// the request's **sender text** (the §22.6 extraction ladder) counted in
/// UTF-16 code units — the same counting the §22.5 inbound cap uses, so the
/// SDK has exactly one definition of "characters".
///
/// The basis is documented rather than fixture-pinned: `conformance/
/// allowance.json` pins the token→money CONVERSION (floor arithmetic), not
/// how a host guesses tokens — an estimate is a price quote, and the host's
/// estimator hook ([`crate::AgentMesh::set_cost_estimator`]) replaces this
/// default wholesale.
pub fn estimate_tokens(input: &Value) -> u64 {
    (inbound_text_length(input) as u64).div_ceil(ESTIMATE_CHARS_PER_TOKEN)
}

/// Today's UTC calendar day, `YYYY-MM-DD` — the `day` key metering and
/// admission account against (EXT-8 §2: "the UTC calendar day of the metering
/// instant").
pub fn today_utc() -> String {
    Utc::now().format("%Y-%m-%d").to_string()
}

// ─── the ledger ─────────────────────────────────────────────────────────────

/// The household's books: metered spend accounted to the Task, to the Task's
/// `context_id`, and to the UTC day — one recording lands in all three at
/// once (EXT-8 §2), which is what lets every applicable ceiling be judged
/// against its own scope's total.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SpendLedger {
    by_task: HashMap<String, u64>,
    by_context: HashMap<String, u64>,
    by_day: HashMap<String, u64>,
    /// Trial spend per UTC day (Common Agent 7.5): a fourth book, kept beside
    /// the other three rather than instead of them, so the owner's total
    /// stays the total.
    by_trial_day: HashMap<String, u64>,
}

impl SpendLedger {
    fn record(
        &mut self,
        task_id: &str,
        context_id: Option<&str>,
        day: &str,
        cost_micro: u64,
        trial: bool,
    ) {
        let add = |slot: &mut u64| *slot = slot.saturating_add(cost_micro);
        add(self.by_task.entry(task_id.to_string()).or_default());
        if let Some(ctx) = context_id {
            add(self.by_context.entry(ctx.to_string()).or_default());
        }
        add(self.by_day.entry(day.to_string()).or_default());
        if trial {
            add(self.by_trial_day.entry(day.to_string()).or_default());
        }
    }

    /// Micro-units of trial work accounted to a UTC day (`YYYY-MM-DD`).
    pub fn trial_spend(&self, day: &str) -> u64 {
        self.by_trial_day.get(day).copied().unwrap_or(0)
    }

    /// Micro-units accounted to a Task.
    pub fn task_spend(&self, task_id: &str) -> u64 {
        self.by_task.get(task_id).copied().unwrap_or(0)
    }

    /// Micro-units accounted to a context.
    pub fn context_spend(&self, context_id: &str) -> u64 {
        self.by_context.get(context_id).copied().unwrap_or(0)
    }

    /// Micro-units accounted to a UTC day (`YYYY-MM-DD`).
    pub fn day_spend(&self, day: &str) -> u64 {
        self.by_day.get(day).copied().unwrap_or(0)
    }
}

// ─── admission (EXT-8 §2) ───────────────────────────────────────────────────

/// The work an admission decision is about, as scoped by the request envelope:
/// its `task_id` and `context_id`, either absent. A ceiling narrowed to a
/// different task or context does not apply; an un-narrowed `task` ceiling
/// applies to this work's Task (a fresh Task has spent nothing yet).
#[derive(Debug, Clone, Copy, Default)]
pub struct WorkScope<'a> {
    pub task_id: Option<&'a str>,
    pub context_id: Option<&'a str>,
}

/// The ceiling that decided an admission: the applicable ceiling with the
/// smallest **remaining** amount. Specificity determines what a ceiling
/// covers, never which one wins — a `day` ceiling with less left binds before
/// a `task` ceiling with more (pinned by the fixture's precedence cases).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingCeiling {
    pub scope: CeilingScope,
    pub amount_micro: u64,
    /// Spend already accounted to this ceiling's scope.
    pub spent_micro: u64,
    /// `amount_micro − spent_micro` (saturating).
    pub remaining_micro: u64,
}

/// An admission judgement against the armed allowance.
#[derive(Debug, Clone, PartialEq)]
pub enum AllowanceDecision {
    /// No allowance is armed — the meter stays out of the way entirely.
    Unenforced,
    /// The estimate fits inside every applicable ceiling. `binding` names the
    /// tightest one, when any applied at all.
    Admit { binding: Option<BindingCeiling> },
    /// Admitting the work would cross the binding ceiling (or the meter is
    /// fail-closed): act per `on_exhausted`. `estimate` is the node's price
    /// for the work, `cost_ceiling`-shaped, ready for `details.estimate`;
    /// `None` only in the fail-closed state, where no trusted cost model
    /// exists to price with.
    Exhausted {
        on_exhausted: OnExhausted,
        binding: Option<BindingCeiling>,
        estimate: Option<CostCeiling>,
    },
}

/// The question surfaced through the owner channel under
/// `on_exhausted: "ask_owner"` (EXT-8 §2): the work is held unstarted, and
/// proceeds only if the owner approves.
#[derive(Debug, Clone)]
pub struct AllowanceQuestion {
    /// The requester (signature-verified `from`).
    pub from: String,
    /// The offering the request names.
    pub offering: String,
    pub task_id: Option<String>,
    pub context_id: Option<String>,
    /// The node's price for the work, when one could be computed.
    pub estimate: Option<CostCeiling>,
    /// The ceiling that would be crossed. `None` only in the fail-closed
    /// state.
    pub binding: Option<BindingCeiling>,
}

/// The armed policy, or the reason there is none.
#[derive(Debug, Clone, PartialEq)]
pub enum AllowanceStatus {
    /// No document configured; nothing is metered or enforced.
    Unarmed,
    /// A verified document is the policy.
    Armed(Allowance),
    /// A document was configured and did NOT verify (or did not parse):
    /// every ceiling reads as exhausted — `on_exhausted` still applies when
    /// it was readable — until a valid document replaces it (EXT-8 §1:
    /// failing open here is failing open on the owner's money).
    FailClosed { on_exhausted: OnExhausted, reason: String },
}

enum ArmState {
    Unarmed,
    Armed(Allowance),
    FailClosed { on_exhausted: OnExhausted, reason: String },
}

/// The node-side allowance machine: the armed document, the
/// [`SpendLedger`], metering, and the admission judgement. Pure and
/// transport-free — [`crate::AgentMesh`] holds one and wires it into inbound
/// admission automatically; owner tooling and tests drive it directly.
///
/// The ledger belongs to the meter, not to the document: replacing the policy
/// does not launder the spend already on the books.
pub struct AllowanceMeter {
    state: ArmState,
    ledger: SpendLedger,
}

impl Default for AllowanceMeter {
    fn default() -> Self {
        AllowanceMeter::new()
    }
}

impl AllowanceMeter {
    pub fn new() -> AllowanceMeter {
        AllowanceMeter { state: ArmState::Unarmed, ledger: SpendLedger::default() }
    }

    /// Arm the meter with a document. A document that loads and verifies
    /// becomes the policy; one that does not leaves the meter **fail-closed**
    /// — armed with every ceiling exhausted, `on_exhausted` preserved when
    /// readable (defaulting to refuse, the behaviour that cannot spend) — and
    /// the error is returned so the failure is observable. It is NEVER
    /// treated as absent (EXT-8 §1).
    pub fn arm(&mut self, doc: &Value) -> Result<()> {
        self.arm_checked(doc, None)
    }

    /// [`arm`](Self::arm) bound to the agent being armed: a document whose
    /// `agent` names a DIFFERENT agent is a policy for someone else's node —
    /// enforcing it here would enforce ceilings the owner never set on this
    /// agent, and ignoring it would leave this agent unguarded when the owner
    /// believes it is guarded. So it fails **closed**, exactly like a bad
    /// signature (matching the TS SDK). [`crate::AgentMesh::set_allowance`]
    /// arms through this.
    pub fn arm_for(&mut self, doc: &Value, agent: &str) -> Result<()> {
        self.arm_checked(doc, Some(agent))
    }

    fn arm_checked(&mut self, doc: &Value, expected_agent: Option<&str>) -> Result<()> {
        let loaded = load_allowance(doc).and_then(|a| match expected_agent {
            Some(me) if a.agent != me => Err(MeshError::code(
                ErrorCode::IdentityMismatch,
                format!(
                    "Allowance governs agent {}, not this agent {me} (EXT-8 §1: one document per \
                     agent) — failing closed until a document for this agent replaces it",
                    a.agent
                ),
            )),
            _ => Ok(a),
        });
        match loaded {
            Ok(a) => {
                self.state = ArmState::Armed(a);
                Ok(())
            }
            Err(e) => {
                let on_exhausted = match doc.get("on_exhausted").and_then(Value::as_str) {
                    Some("ask_owner") => OnExhausted::AskOwner,
                    _ => OnExhausted::Refuse,
                };
                self.state = ArmState::FailClosed { on_exhausted, reason: e.to_string() };
                Err(e)
            }
        }
    }

    /// Remove the policy entirely (the owner un-configuring an allowance is
    /// not the same act as a document failing to verify — this one is
    /// deliberate). The ledger is kept.
    pub fn disarm(&mut self) {
        self.state = ArmState::Unarmed;
    }

    /// Whether admission checking has anything to say — armed or fail-closed.
    pub fn enforcing(&self) -> bool {
        !matches!(self.state, ArmState::Unarmed)
    }

    pub fn status(&self) -> AllowanceStatus {
        match &self.state {
            ArmState::Unarmed => AllowanceStatus::Unarmed,
            ArmState::Armed(a) => AllowanceStatus::Armed(a.clone()),
            ArmState::FailClosed { on_exhausted, reason } => AllowanceStatus::FailClosed {
                on_exhausted: *on_exhausted,
                reason: reason.clone(),
            },
        }
    }

    /// The books, as currently kept.
    pub fn ledger(&self) -> &SpendLedger {
        &self.ledger
    }

    /// Reported usage in micro-units, when this meter can price it: tokens
    /// need the armed document's cost model; already-monied usage needs
    /// nothing.
    pub fn usage_micro(&self, usage: Usage) -> Option<u64> {
        match usage {
            Usage::CostMicro(m) => Some(m),
            Usage::Tokens(t) => match &self.state {
                ArmState::Armed(a) => Some(meter_cost_micro(t, a.cost_model.per_1k_tokens_micro)),
                _ => None,
            },
        }
    }

    /// Meter reported usage and account it — to the Task, to `context_id`
    /// when the work has one, and to the UTC day `day` (EXT-8 §2). Returns
    /// the micro-units recorded. `Usage::Tokens` requires an armed, valid
    /// cost model to convert by; `Usage::CostMicro` is bookkeeping the meter
    /// can always do.
    pub fn report_at(
        &mut self,
        task_id: &str,
        context_id: Option<&str>,
        day: &str,
        usage: Usage,
    ) -> Result<u64> {
        self.report_work_at(task_id, context_id, day, usage, false)
    }

    /// [`report_at`](Self::report_at) for trial work (Common Agent 7.5,
    /// 7.7): accounted to the Task, its context and the day like any spend,
    /// and also to the day's trial book, which only the `trial` ceiling
    /// reads.
    pub fn report_trial_at(
        &mut self,
        task_id: &str,
        context_id: Option<&str>,
        day: &str,
        usage: Usage,
    ) -> Result<u64> {
        self.report_work_at(task_id, context_id, day, usage, true)
    }

    /// The one metering path behind [`report_at`](Self::report_at) and
    /// [`report_trial_at`](Self::report_trial_at).
    pub fn report_work_at(
        &mut self,
        task_id: &str,
        context_id: Option<&str>,
        day: &str,
        usage: Usage,
        trial: bool,
    ) -> Result<u64> {
        let cost_micro = self.usage_micro(usage).ok_or_else(|| {
            MeshError::code(
                ErrorCode::InvalidEnvelope,
                "Reported token usage cannot be metered: no valid allowance cost_model is armed \
                 (EXT-8 §1/§2)",
            )
        })?;
        self.ledger.record(task_id, context_id, day, cost_micro, trial);
        Ok(cost_micro)
    }

    /// [`report_at`](Self::report_at) against today's UTC day — the metering
    /// instant's day, which is the enforcing node's normal call.
    pub fn report(&mut self, task_id: &str, context_id: Option<&str>, usage: Usage) -> Result<u64> {
        self.report_at(task_id, context_id, &today_utc(), usage)
    }

    /// The §19.3 spend report for a Task's terminal `respond`: the micro-units
    /// accounted to it, denominated by the armed cost model's currency. `None`
    /// when nothing was accounted or no valid document is armed (no currency
    /// to denominate a report in).
    pub fn task_cost(&self, task_id: &str) -> Option<CostCeiling> {
        let ArmState::Armed(a) = &self.state else { return None };
        match self.ledger.task_spend(task_id) {
            0 => None,
            spent => Some(CostCeiling::new(spent, a.cost_model.currency.clone())),
        }
    }

    /// The EXT-8 §2 admission judgement, at UTC day `day`: every applicable
    /// ceiling at once, the binding one being whichever has the smallest
    /// remaining amount (ties keep the earlier ceiling in document order).
    /// The work is exhausted when the estimate EXCEEDS the binding remainder
    /// — an estimate that lands exactly on it still fits ("would exceed a
    /// ceiling", EXT-8 §2; the fixture pins strict inequality on both sides).
    ///
    /// Applicability: a ceiling narrowed by `task_id`/`context_id` applies
    /// only to that task/context. An un-narrowed `task` ceiling applies to
    /// this work's Task — including a Task that does not exist yet, whose
    /// spend is zero. An un-narrowed `context` ceiling applies to the work's
    /// context; work outside any context has nothing a context ceiling could
    /// be accounted against, so none applies (metered spend without a
    /// `context_id` is accounted to task and day only). A `day` ceiling
    /// always applies.
    ///
    /// Fail-closed: every ceiling reads as exhausted, whatever the estimate,
    /// with no price (no trusted cost model to quote from).
    pub fn check_admission_at(
        &self,
        work: WorkScope<'_>,
        estimate_micro: u64,
        day: &str,
    ) -> AllowanceDecision {
        let doc = match &self.state {
            ArmState::Unarmed => return AllowanceDecision::Unenforced,
            ArmState::FailClosed { on_exhausted, .. } => {
                return AllowanceDecision::Exhausted {
                    on_exhausted: *on_exhausted,
                    binding: None,
                    estimate: None,
                };
            }
            ArmState::Armed(doc) => doc,
        };

        match self.binding_of(doc, work, day, false) {
            Some(b) if estimate_micro > b.remaining_micro => AllowanceDecision::Exhausted {
                on_exhausted: doc.on_exhausted,
                binding: Some(b),
                estimate: Some(CostCeiling::new(estimate_micro, doc.cost_model.currency.clone())),
            },
            binding => AllowanceDecision::Admit { binding },
        }
    }

    /// The applicable ceiling with the smallest remaining amount. For
    /// ordinary work the `trial` ceiling never applies; for trial work it
    /// applies beside every wider one, so trial work fits only where both
    /// the trial share and the owner's total have room.
    fn binding_of(
        &self,
        doc: &Allowance,
        work: WorkScope<'_>,
        day: &str,
        trial: bool,
    ) -> Option<BindingCeiling> {
        let mut binding: Option<BindingCeiling> = None;
        for c in &doc.ceilings {
            let spent_micro = match c.scope {
                CeilingScope::Trial => {
                    if !trial {
                        continue;
                    }
                    self.ledger.trial_spend(day)
                }
                CeilingScope::Task => {
                    if let Some(narrow) = c.task_id.as_deref() {
                        if work.task_id != Some(narrow) {
                            continue;
                        }
                    }
                    work.task_id.map(|t| self.ledger.task_spend(t)).unwrap_or(0)
                }
                CeilingScope::Context => {
                    let Some(work_ctx) = work.context_id else { continue };
                    if let Some(narrow) = c.context_id.as_deref() {
                        if narrow != work_ctx {
                            continue;
                        }
                    }
                    self.ledger.context_spend(work_ctx)
                }
                CeilingScope::Day => self.ledger.day_spend(day),
            };
            let remaining_micro = c.amount_micro.saturating_sub(spent_micro);
            if binding.as_ref().map_or(true, |b| remaining_micro < b.remaining_micro) {
                binding = Some(BindingCeiling {
                    scope: c.scope,
                    amount_micro: c.amount_micro,
                    spent_micro,
                    remaining_micro,
                });
            }
        }
        binding
    }

    /// The trial ceiling's answer for trial work of `estimate_micro` at UTC
    /// day `day` (Common Agent 7.5, 7.7):
    ///
    /// - [`TrialFunds::None`]: no allowance is armed, or the armed one sets no
    ///   `trial` ceiling. The node refuses trial work on `funds` rather than
    ///   spend unbounded.
    /// - [`TrialFunds::Full`]: the estimate exceeds the remainder of the trial
    ///   ceiling or of any wider applicable ceiling; also the answer of a
    ///   fail-closed meter, whose every ceiling reads exhausted.
    /// - [`TrialFunds::Room`]: it fits under all of them. Landing exactly on a
    ///   remainder fits, as for ordinary admission.
    ///
    /// `ask_owner` does not apply here: a trial is the publisher's gift, and
    /// a gift that needs the owner's approval each time is not one a host can
    /// list.
    pub fn trial_funds_at(&self, work: WorkScope<'_>, estimate_micro: u64, day: &str) -> TrialFunds {
        let doc = match &self.state {
            ArmState::Unarmed => return TrialFunds::None,
            ArmState::FailClosed { .. } => return TrialFunds::Full,
            ArmState::Armed(doc) => doc,
        };
        if !doc.ceilings.iter().any(|c| c.scope == CeilingScope::Trial) {
            return TrialFunds::None;
        }
        match self.binding_of(doc, work, day, true) {
            Some(b) if estimate_micro > b.remaining_micro => TrialFunds::Full,
            _ => TrialFunds::Room,
        }
    }

    /// [`trial_funds_at`](Self::trial_funds_at) against today's UTC day.
    pub fn trial_funds(&self, work: WorkScope<'_>, estimate_micro: u64) -> TrialFunds {
        self.trial_funds_at(work, estimate_micro, &today_utc())
    }

    /// [`report`](Self::report) for trial work: see
    /// [`report_trial_at`](Self::report_trial_at).
    pub fn report_trial(
        &mut self,
        task_id: &str,
        context_id: Option<&str>,
        usage: Usage,
    ) -> Result<u64> {
        self.report_trial_at(task_id, context_id, &today_utc(), usage)
    }

    /// [`check_admission_at`](Self::check_admission_at) against today's UTC
    /// day.
    pub fn check_admission(&self, work: WorkScope<'_>, estimate_micro: u64) -> AllowanceDecision {
        self.check_admission_at(work, estimate_micro, &today_utc())
    }
}

/// The allowance-broke admission refusal (EXT-8 §2 / §7.7 / §12.2):
/// `BUDGET_INSUFFICIENT` with `details.estimate` carrying the node's price.
/// §19.3's quote sentence makes this legal even against a request that
/// offered no ceiling at all — the estimate is a price quote, and a
/// resubmission at or above it is acceptance.
///
/// The message is the generic budget one, deliberately: on the wire a refusal
/// driven by the responder's own spending policy MUST be indistinguishable
/// from one driven by a too-low offer, and a message that says "allowance"
/// would un-say that.
pub fn allowance_insufficient(estimate: Option<CostCeiling>) -> MeshError {
    budget_insufficient(
        estimate,
        "Refused at admission: the work cannot be done within the offered cost ceiling (§7.7)",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn signed_doc(ceilings: Value, on_exhausted: &str) -> (Value, KeyPair) {
        let owner = KeyPair::new_user();
        let mut doc = Allowance {
            v: 1,
            agent: KeyPair::new_user().public_key(),
            owner_key: String::new(),
            cost_model: AllowanceCostModel { per_1k_tokens_micro: 1500, currency: "USD".into() },
            ceilings: serde_json::from_value(ceilings).unwrap(),
            on_exhausted: serde_json::from_value(Value::String(on_exhausted.into())).unwrap(),
            updated_at: "2026-07-28T15:00:00.000Z".into(),
            sig: None,
        };
        sign_allowance(&mut doc, &owner).unwrap();
        (serde_json::to_value(&doc).unwrap(), owner)
    }

    #[test]
    fn the_default_estimate_is_ceil_utf16_chars_over_four_of_sender_text() {
        assert_eq!(estimate_tokens(&json!("")), 0);
        assert_eq!(estimate_tokens(&json!("abcd")), 1, "4 chars is exactly one token");
        assert_eq!(estimate_tokens(&json!("abcde")), 2, "5 chars rounds UP");
        // The §22.6 sender-text ladder, not the raw JSON: `text` is the text.
        assert_eq!(estimate_tokens(&json!({ "text": "12345678" })), 2);
        // UTF-16 code units — the same counting as the §22.5 cap: 𝄞 is two.
        assert_eq!(estimate_tokens(&json!("𝄞𝄞𝄞")), 2, "3 astral chars = 6 UTF-16 units = 2 tokens");
    }

    #[test]
    fn metering_floors_and_saturates() {
        assert_eq!(meter_cost_micro(333, 100), 33);
        assert_eq!(meter_cost_micro(u64::MAX, u64::MAX), u64::MAX, "money saturates, never wraps");
    }

    #[test]
    fn one_recording_lands_in_all_three_books() {
        let mut ledger = SpendLedger::default();
        ledger.record("t1", Some("ctx"), "2026-07-28", 40, false);
        ledger.record("t1", None, "2026-07-28", 2, false);
        assert_eq!(ledger.trial_spend("2026-07-28"), 0, "ordinary spend never lands in the trial book");
        assert_eq!(ledger.task_spend("t1"), 42);
        assert_eq!(ledger.context_spend("ctx"), 40, "the no-context recording skipped this book");
        assert_eq!(ledger.day_spend("2026-07-28"), 42);
        assert_eq!(ledger.task_spend("t2"), 0);
    }

    #[test]
    fn unarmed_is_unenforced_and_cannot_meter_tokens() {
        let mut meter = AllowanceMeter::new();
        assert!(!meter.enforcing());
        assert_eq!(meter.status(), AllowanceStatus::Unarmed);
        assert_eq!(
            meter.check_admission(WorkScope::default(), u64::MAX),
            AllowanceDecision::Unenforced
        );
        assert!(meter.report("t", None, Usage::Tokens(1000)).is_err(), "no cost model to convert");
        // Money-denominated bookkeeping needs no policy.
        assert_eq!(meter.report("t", None, Usage::CostMicro(7)).unwrap(), 7);
        assert_eq!(meter.ledger().task_spend("t"), 7);
    }

    #[test]
    fn sign_load_report_admit_round_trip() {
        let (doc, _) = signed_doc(json!([{ "scope": "day", "amount_micro": 1000 }]), "refuse");
        let mut meter = AllowanceMeter::new();
        meter.arm(&doc).unwrap();
        assert!(matches!(meter.status(), AllowanceStatus::Armed(_)));
        // 500 tokens at 1500/1k = 750 micro, accounted to task/context/day.
        let metered =
            meter.report_at("t1", Some("ctx"), "2026-07-28", Usage::Tokens(500)).unwrap();
        assert_eq!(metered, 750);
        // 250 remaining on the day: an estimate of 250 fits exactly...
        let work = WorkScope { task_id: None, context_id: Some("ctx") };
        assert!(matches!(
            meter.check_admission_at(work, 250, "2026-07-28"),
            AllowanceDecision::Admit { binding: Some(BindingCeiling { remaining_micro: 250, .. }) }
        ));
        // ...251 does not; and the spend report is denominated in the model's currency.
        assert!(matches!(
            meter.check_admission_at(work, 251, "2026-07-28"),
            AllowanceDecision::Exhausted { on_exhausted: OnExhausted::Refuse, .. }
        ));
        assert_eq!(meter.task_cost("t1"), Some(CostCeiling::new(750, "USD")));
        assert_eq!(meter.task_cost("t2"), None);
        // A new day has its own book.
        assert!(matches!(
            meter.check_admission_at(work, 1000, "2026-07-29"),
            AllowanceDecision::Admit { .. }
        ));
    }

    #[test]
    fn a_bad_signature_fails_closed_observably_until_replaced() {
        let (mut doc, _) = signed_doc(json!([{ "scope": "day", "amount_micro": 1000 }]), "ask_owner");
        let good = doc.clone();
        // Flip the document under the signature.
        doc["updated_at"] = json!("2027-01-01T00:00:00.000Z");
        let mut meter = AllowanceMeter::new();
        assert!(meter.arm(&doc).is_err(), "the failure is observable at arm time");
        let AllowanceStatus::FailClosed { on_exhausted, .. } = meter.status() else {
            panic!("fail-closed, never absent");
        };
        assert_eq!(on_exhausted, OnExhausted::AskOwner, "on_exhausted still applies (EXT-8 §1)");
        // Every ceiling exhausted: even zero-cost work is not admitted.
        assert!(matches!(
            meter.check_admission(WorkScope::default(), 0),
            AllowanceDecision::Exhausted {
                on_exhausted: OnExhausted::AskOwner,
                binding: None,
                estimate: None
            }
        ));
        assert!(meter.enforcing());
        // Until a valid document replaces it.
        meter.arm(&good).unwrap();
        assert!(matches!(meter.status(), AllowanceStatus::Armed(_)));
        // Disarming, by contrast, is the owner's own act and un-enforces.
        meter.disarm();
        assert!(!meter.enforcing());
    }

    #[test]
    fn ties_keep_the_earlier_ceiling_in_document_order() {
        let (doc, _) = signed_doc(
            json!([
                { "scope": "task", "amount_micro": 100 },
                { "scope": "day", "amount_micro": 100 }
            ]),
            "refuse",
        );
        let mut meter = AllowanceMeter::new();
        meter.arm(&doc).unwrap();
        let AllowanceDecision::Admit { binding: Some(b) } =
            meter.check_admission(WorkScope::default(), 50)
        else {
            panic!("admitted with a binding ceiling");
        };
        assert_eq!(b.scope, CeilingScope::Task, "equal remainders: document order holds");
    }

    #[test]
    fn the_trial_scope_joins_a_closed_enum_that_stays_closed() {
        let (doc, _) = signed_doc(json!([{ "scope": "trial", "amount_micro": 100 }]), "refuse");
        assert!(load_allowance(&doc).is_ok(), "trial is a scope");
        let mut week = doc.clone();
        week["ceilings"][0]["scope"] = json!("week");
        let err = validate_allowance_value(&week).unwrap_err().to_string();
        assert!(err.contains("closed enum"), "{err}");
    }

    #[test]
    fn a_trial_ceiling_never_binds_ordinary_work_and_trial_spend_counts_everywhere() {
        let (doc, _) = signed_doc(
            json!([
                { "scope": "day", "amount_micro": 1000 },
                { "scope": "trial", "amount_micro": 300 }
            ]),
            "refuse",
        );
        let mut meter = AllowanceMeter::new();
        meter.arm(&doc).unwrap();
        let day = "2026-10-05";
        let work = WorkScope::default();
        meter.report_trial_at("t1", Some("c"), day, Usage::CostMicro(250)).unwrap();
        assert_eq!(meter.ledger().trial_spend(day), 250);
        assert_eq!(meter.ledger().day_spend(day), 250, "trial spend counts toward the day");
        assert_eq!(meter.ledger().context_spend("c"), 250);
        assert_eq!(meter.trial_funds_at(work, 50, day), TrialFunds::Room, "lands exactly on 50 left");
        assert_eq!(meter.trial_funds_at(work, 51, day), TrialFunds::Full);
        // Ordinary work sees the day ceiling only: 750 left.
        assert!(matches!(
            meter.check_admission_at(work, 700, day),
            AllowanceDecision::Admit { binding: Some(BindingCeiling { scope: CeilingScope::Day, .. }) }
        ));
        // Ordinary spend eats the day, so the wider ceiling now binds trials.
        meter.report_at("t2", None, day, Usage::CostMicro(740)).unwrap();
        assert_eq!(meter.ledger().trial_spend(day), 250, "ordinary spend never counts as trial");
        assert_eq!(meter.trial_funds_at(work, 11, day), TrialFunds::Full, "the day has 10 left");
    }

    #[test]
    fn trial_funds_are_none_without_a_trial_ceiling_and_full_when_failing_closed() {
        let mut meter = AllowanceMeter::new();
        assert_eq!(meter.trial_funds(WorkScope::default(), 0), TrialFunds::None, "no allowance");
        let (doc, _) = signed_doc(json!([{ "scope": "day", "amount_micro": 1000 }]), "refuse");
        meter.arm(&doc).unwrap();
        assert_eq!(meter.trial_funds(WorkScope::default(), 0), TrialFunds::None, "no trial ceiling");
        let (mut bad, _) = signed_doc(json!([{ "scope": "trial", "amount_micro": 1000 }]), "refuse");
        bad["updated_at"] = json!("2027-01-01T00:00:00.000Z");
        assert!(meter.arm(&bad).is_err());
        assert_eq!(meter.trial_funds(WorkScope::default(), 0), TrialFunds::Full, "fails closed");
    }
}
