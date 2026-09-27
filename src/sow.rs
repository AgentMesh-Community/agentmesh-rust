//! Agent SoW pricing arrangements (Agent SoW spec 0.7.0-draft, §5.5).
//!
//! An Agent SoW engagement declares exactly one **pricing arrangement**: work is
//! priced per task at a published rate (`fixed_fee`, §5.5.1), as a rate schedule
//! over declared meters (`time_and_materials`, §5.5.2), or not at all
//! (`no_charge`, §5.5.7). There is no undeclared default — a price clause naming
//! no arrangement is a validation error, and a runtime MUST refuse a proposal
//! that carries one.
//!
//! `no_charge` exists so that free work has an arrangement it can declare
//! honestly. The alternative, a fixed fee of zero, puts the decision in a magic
//! value a reader cannot tell apart from a price nobody filled in. The clause
//! carries the arrangement and its grade and NO price field of any kind:
//! [`SowPrice::NoCharge`] has one field, `grade`, so there is no slot to put a
//! currency, a rate, a schedule, a cap, a reservation or a ceiling into, and
//! [`validate_sow_price`] refuses any member beyond those two arriving as raw
//! JSON. Nothing settles under it either — [`rate_usage`] refuses to rate it and
//! [`admit_settlement`] is the client node's refusal of a settlement record that
//! cites one.
//!
//! Four properties carry the time-and-materials design:
//!
//!  - **The cap and the reservation are not optional.** §5.5.3: there is no
//!    uncapped time and materials engagement, and §5.5.4: no unreserved one
//!    either. [`SowPrice::TimeAndMaterials`] holds `cap: SowCap` and
//!    `reservation: SowReservation`, never `Option`, so a clause missing either
//!    cannot be constructed and will not deserialize; [`validate_sow_price`]
//!    refuses one arriving as raw JSON. The cap is a not-to-exceed number, not a
//!    forecast: units the provider incurs past it are the provider's to bear.
//!    The reservation is what makes the arrangement a purchase order rather than
//!    an open account.
//!  - **The metered unit is machine-readable.** §5.5.2: a schedule line carries
//!    `per`, the divisor turning raw meter counts into billable units, and
//!    `unit` is only a label. Rating happens on raw counts, so the buyer hands
//!    in the token count it reads off its own records.
//!  - **Reaching the cap is not a failure.** §5.5.5: the engagement moves to
//!    `exhausted`, a task in flight ends `exhausted` with its artifacts
//!    attached, and a runtime MUST NOT record either as failed. `exhausted` sits
//!    beside `lapsed` and `terminated` in §7.1 as a way an engagement ends.
//!  - **Materials are billed at cost, with proof.** §5.5.6: a resold line is
//!    marked `pass_through` and every settlement record for it references the
//!    upstream receipt. A pass-through line MUST NOT be priced above the
//!    upstream cost; a provider wanting margin prices its own metered line.
//!
//! The two §6.2 organizational-authority fields live here too: `organization` on
//! a party and `mandate` on an approval record. Both sit INSIDE the signed
//! bytes, so neither can be added, removed or altered after signing without
//! breaking the signature, and both are additive — a document that omits them is
//! conformant. A runtime that does not perform the Agent Mandate §7 checks MUST
//! NOT present a document carrying them as mandate-verified.
//!
//! This module mirrors `sdk-typescript/src/sow.ts` field for field and refusal
//! for refusal. Shapes and canonical bytes are pinned by
//! `conformance/sow-pricing.json`, which both SDKs read; when the two disagree,
//! the fixture is the authority.
//!
//! See <https://agentsow.com> — the specification this module implements.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{ErrorCode, MeshError, Result};
use crate::identity::{b64url, canonical_json, tagged_sig_bytes, unb64url, verify_tagged};
use nkeys::KeyPair;

/// The domain tag inside an Agent SoW document's signed bytes (§6): each `sig`
/// covers this prefix + the JCS canonical JSON of the document with the
/// `signatures` array removed. The prefix exists only inside the signed bytes —
/// it never appears in the document itself.
pub const SOW_SIG_PREFIX: &str = "agent-sow-v1\n";

fn invalid(msg: impl Into<String>) -> MeshError {
    MeshError::code(ErrorCode::InvalidEnvelope, format!("sow price: {} (§5.5)", msg.into()))
}

// ── §2 / §5.5: the pricing arrangement ──────────────────────────────────────

/// The basis on which an engagement prices work (§2, §5.5). Every engagement
/// declares one; there is no undeclared default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PricingArrangement {
    FixedFee,
    TimeAndMaterials,
    NoCharge,
}

impl PricingArrangement {
    pub fn as_str(&self) -> &'static str {
        match self {
            PricingArrangement::FixedFee => "fixed_fee",
            PricingArrangement::TimeAndMaterials => "time_and_materials",
            PricingArrangement::NoCharge => "no_charge",
        }
    }
}

/// The closed set. A price clause naming anything else is a validation error.
pub const PRICING_ARRANGEMENTS: [&str; 3] = ["fixed_fee", "time_and_materials", "no_charge"];

/// The enforcement gradient (§3). Every clause object carries one (§4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SowGrade {
    Enforced,
    Evidence,
    Recorded,
}

const SOW_GRADES: [&str; 3] = ["enforced", "evidence", "recorded"];

/// The window a spend ceiling is measured over (§5.5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SowPeriod {
    Month,
}

// ── §5.5.1: fixed fee ───────────────────────────────────────────────────────

/// One published rate: this offering costs this much per task. Money is an
/// integer in the smallest unit of the clause's `currency` — never a float.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SowFixedFeeRate {
    pub offering: String,
    pub per_task: u64,
}

/// An optional spend ceiling per period (§5.5.1). Work beyond it is refused
/// with a quote rather than performed and billed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SowCeiling {
    pub amount: u64,
    pub period: SowPeriod,
}

// ── §5.5.2: time and materials ──────────────────────────────────────────────

/// One line of a rate schedule (§5.5.2): a meter, the divisor that turns its
/// raw counts into billable units, the price of one unit, and a label a person
/// reads.
///
/// `per` is the divisor — how many raw meter counts make one billable unit. A
/// positive integer, defaulting to 1. `unit` is a LABEL FOR PEOPLE and carries
/// no arithmetic: a runtime MUST rate on `per` and MUST NOT parse `unit`.
///
/// That split is the buyer's protection, not decoration. Time and materials has
/// no deliverable to accept (§5.5.5), so all the buyer has is a meter it can
/// check independently — and a unit of "1000 tokens" that only a human can
/// convert defeats exactly that. The divisor puts the conversion inside the
/// signed bytes, where both parties compute the same charge from the same
/// counts.
///
/// `pass_through` marks a line the provider bought elsewhere (§5.5.6). It is
/// billed at cost against an upstream receipt, never above it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SowScheduleLine {
    pub meter: String,
    pub unit: String,
    /// The divisor (§5.5.2). Positive integer; `None` rates as 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per: Option<u64>,
    pub per_unit: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pass_through: Option<bool>,
}

impl SowScheduleLine {
    /// A line that prices its meter one raw count at a time (`per` = 1).
    pub fn new(meter: impl Into<String>, unit: impl Into<String>, per_unit: u64) -> Self {
        Self { meter: meter.into(), unit: unit.into(), per: None, per_unit, pass_through: None }
    }

    /// A line whose billable unit is `per` raw meter counts (§5.5.2).
    pub fn per(
        meter: impl Into<String>,
        unit: impl Into<String>,
        per: u64,
        per_unit: u64,
    ) -> Self {
        Self {
            meter: meter.into(),
            unit: unit.into(),
            per: Some(per),
            per_unit,
            pass_through: None,
        }
    }

    /// Mark this line as resold at cost (§5.5.6). Every settlement record for
    /// it will then require an upstream receipt.
    pub fn pass_through(mut self) -> Self {
        self.pass_through = Some(true);
        self
    }

    pub fn is_pass_through(&self) -> bool {
        self.pass_through == Some(true)
    }

    /// The divisor this line rates by: its `per`, or 1 when it names none.
    pub fn divisor(&self) -> u64 {
        self.per.unwrap_or(1)
    }

    /// What this line charges for a raw meter count:
    /// `floor(count × per_unit / per)` (§5.5.2).
    ///
    /// The floor is deliberate and it favours the buyer — a partial unit never
    /// charges a partial unit's money. The arithmetic widens to `u128` because
    /// `count × per_unit` overflows a `u64` long before either factor does, and
    /// two SDKs that disagree by one micro-unit are two SDKs that disagree
    /// about the bill.
    pub fn rate(&self, count: u64) -> Result<u64> {
        let divisor = self.divisor();
        if divisor == 0 {
            return Err(invalid("per is a positive integer (§5.5.2)"));
        }
        let amount = (count as u128 * self.per_unit as u128) / divisor as u128;
        if amount > MAX_SAFE_INTEGER as u128 {
            return Err(invalid(format!(
                "rating '{}' overflows an exact integer — split the settlement",
                self.meter
            )));
        }
        Ok(amount as u64)
    }
}

/// The not-to-exceed cap (§5.5.3). Mandatory on every time and materials
/// engagement: there is no uncapped one, and this is the single number an Agent
/// Mandate ceiling check tests before formation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SowCap {
    pub amount: u64,
}

impl SowCap {
    pub fn new(amount: u64) -> Self {
        Self { amount }
    }
}

/// The reservation window (§5.5.4). Funds are reserved for the cap amount when
/// the engagement forms and the unused remainder is released at the end of the
/// window. The window MUST NOT extend beyond `ends_at`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SowReservation {
    pub window_days: u64,
}

impl SowReservation {
    pub fn new(window_days: u64) -> Self {
        Self { window_days }
    }
}

/// The price clause (§5.5), discriminated on `arrangement`.
///
/// The discriminant is serde's internal tag, so the wire shape is exactly the
/// spec's: `{"arrangement": "time_and_materials", "currency": …}`. The
/// `TimeAndMaterials` variant's `cap` is a plain `SowCap`, never an
/// `Option<SowCap>` — that is the type-level half of §5.5.3's "there is no
/// uncapped time and materials engagement". A JSON document missing `cap` fails
/// to deserialize into this enum at all.
///
/// `NoCharge` carries `grade` and nothing else, which is the type-level half of
/// §5.5.7: there is no field on the variant to put a currency, a rate, a
/// schedule, a cap, a reservation or a ceiling into, so a malformed clause
/// cannot be constructed and one that is deserialized cannot carry a price
/// anywhere.
///
/// The deserializing half is [`load_sow_price`], not serde. Serde's internally
/// tagged representation ignores unrecognized members, and
/// `deny_unknown_fields` is not available on a variant of one, so
/// `{"arrangement":"no_charge","currency":"XCR"}` would otherwise deserialize
/// with the offending member quietly dropped. §5.5.7 says a runtime MUST REFUSE
/// that document rather than sanitize it, so `load_sow_price` validates the raw
/// JSON first and never reaches serde on a clause carrying a price field. Build
/// clauses with the constructors and read them with `load_sow_price`; a bare
/// `serde_json::from_value::<SowPrice>` skips the check that §5.5.7 requires.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "arrangement", rename_all = "snake_case")]
pub enum SowPrice {
    FixedFee {
        currency: String,
        rates: Vec<SowFixedFeeRate>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ceiling: Option<SowCeiling>,
        grade: SowGrade,
    },
    TimeAndMaterials {
        currency: String,
        schedule: Vec<SowScheduleLine>,
        /// REQUIRED (§5.5.3). Never make this an `Option`.
        cap: SowCap,
        /// REQUIRED (§5.5.4). Never make this an `Option`: the arrangement is a
        /// purchase order, and one that commits no funds and names no period
        /// has no defined settlement behaviour.
        reservation: SowReservation,
        grade: SowGrade,
    },
    NoCharge { grade: SowGrade },
}

impl SowPrice {
    /// Build a `fixed_fee` price clause (§5.5.1).
    ///
    /// The arrangement is stamped here, so a caller that already constructed a
    /// fixed fee price before 0.4.0 introduced the field does not have to learn
    /// about it. What is NOT offered is a reader that infers `fixed_fee` from a
    /// clause that names no arrangement: §5.5 makes that a validation error a
    /// runtime MUST refuse, and a silent upgrade at admission would be exactly
    /// the defaulting the spec forbids.
    pub fn fixed_fee(currency: impl Into<String>, rates: Vec<SowFixedFeeRate>) -> Result<Self> {
        let price = SowPrice::FixedFee {
            currency: currency.into(),
            rates,
            ceiling: None,
            grade: SowGrade::Enforced,
        };
        price.validated()
    }

    /// Build a `time_and_materials` price clause (§5.5.2).
    ///
    /// `cap` and `reservation` are positional parameters of concrete type, not
    /// options with defaults: §5.5.3 says there is no uncapped time and
    /// materials engagement and §5.5.4 says there is no unreserved one, so
    /// there is no call shape here that produces either.
    pub fn time_and_materials(
        currency: impl Into<String>,
        schedule: Vec<SowScheduleLine>,
        cap: SowCap,
        reservation: SowReservation,
    ) -> Result<Self> {
        let price = SowPrice::TimeAndMaterials {
            currency: currency.into(),
            schedule,
            cap,
            reservation,
            grade: SowGrade::Enforced,
        };
        price.validated()
    }

    /// Build a `no_charge` price clause (§5.5.7).
    ///
    /// There is nothing to pass but the grade, and that is the whole design.
    /// The variant has no slot for a currency, a rate, a schedule, a cap, a
    /// reservation or a ceiling, so a caller cannot supply one at all.
    pub fn no_charge() -> Result<Self> {
        SowPrice::NoCharge { grade: SowGrade::Enforced }.validated()
    }

    /// Attach the §5.5.1 per-period spend ceiling. Refuses on a time and
    /// materials clause, which carries a cap instead (§5.5.3), and on a
    /// no-charge clause, which has no ceiling to test (§5.5.7).
    pub fn with_ceiling(mut self, ceiling: SowCeiling) -> Result<Self> {
        match &mut self {
            SowPrice::FixedFee { ceiling: slot, .. } => *slot = Some(ceiling),
            SowPrice::TimeAndMaterials { .. } => {
                return Err(invalid(
                    "a time_and_materials clause carries a cap, not a per-period ceiling (§5.5.3)",
                ))
            }
            SowPrice::NoCharge { .. } => {
                return Err(invalid(
                    "a no_charge clause carries no ceiling. There is no rate to state and no                      spend to bound (§5.5.7)",
                ))
            }
        }
        self.validated()
    }

    /// Replace the §5.5.4 reservation window. Refuses on a fixed fee clause,
    /// which reserves nothing, and on a no-charge clause, which draws nothing.
    /// There is no way to REMOVE one: §5.5.4 makes it mandatory, which is why
    /// the constructor takes it rather than this.
    pub fn with_reservation(mut self, reservation: SowReservation) -> Result<Self> {
        match &mut self {
            SowPrice::TimeAndMaterials { reservation: slot, .. } => *slot = reservation,
            SowPrice::FixedFee { .. } => {
                return Err(invalid("a fixed_fee clause reserves nothing (§5.5.4)"))
            }
            SowPrice::NoCharge { .. } => {
                return Err(invalid(
                    "a no_charge clause reserves nothing. Nothing is drawn, so there is no cap                      to hold funds against (§5.5.7)",
                ))
            }
        }
        self.validated()
    }

    pub fn with_grade(mut self, grade: SowGrade) -> Result<Self> {
        match &mut self {
            SowPrice::FixedFee { grade: slot, .. } => *slot = grade,
            SowPrice::TimeAndMaterials { grade: slot, .. } => *slot = grade,
            SowPrice::NoCharge { grade: slot } => *slot = grade,
        }
        self.validated()
    }

    pub fn arrangement(&self) -> PricingArrangement {
        match self {
            SowPrice::FixedFee { .. } => PricingArrangement::FixedFee,
            SowPrice::TimeAndMaterials { .. } => PricingArrangement::TimeAndMaterials,
            SowPrice::NoCharge { .. } => PricingArrangement::NoCharge,
        }
    }

    /// The settlement currency, where there is one. `None` under `no_charge`:
    /// nothing settles, so there is no currency to settle in (§5.5.7).
    pub fn currency(&self) -> Option<&str> {
        match self {
            SowPrice::FixedFee { currency, .. } | SowPrice::TimeAndMaterials { currency, .. } => {
                Some(currency)
            }
            SowPrice::NoCharge { .. } => None,
        }
    }

    pub fn is_time_and_materials(&self) -> bool {
        matches!(self, SowPrice::TimeAndMaterials { .. })
    }

    pub fn is_fixed_fee(&self) -> bool {
        matches!(self, SowPrice::FixedFee { .. })
    }

    pub fn is_no_charge(&self) -> bool {
        matches!(self, SowPrice::NoCharge { .. })
    }

    fn validated(self) -> Result<Self> {
        validate_sow_price(&serde_json::to_value(&self)?)?;
        Ok(self)
    }
}

// ── validation ──────────────────────────────────────────────────────────────

fn is_currency(s: &str) -> bool {
    s.len() == 3 && s.bytes().all(|b| b.is_ascii_uppercase())
}

fn is_meter_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// §6.2 — an Agent Mandate reference, `org_...` or `mnd_...`.
fn is_mandate_ref(s: &str, prefix: &str) -> bool {
    let Some(rest) = s.strip_prefix(prefix) else { return false };
    !rest.is_empty()
        && rest.len() <= 64
        && rest.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// The largest integer a double represents exactly — the ceiling the TypeScript
/// SDK's `Number.isSafeInteger` imposes. Money above it cannot round-trip
/// through the two SDKs identically, so both refuse it.
const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

/// `Number.isSafeInteger(v) && v >= 0`, over a raw JSON value. `as_f64` on
/// purpose: an integral float (`5.0`) IS a non-negative integer to a JSON
/// parser that only has doubles, and the two SDKs must refuse the same inputs.
fn as_non_neg_int(v: Option<&Value>) -> Option<u64> {
    let n = v?.as_f64()?;
    if !n.is_finite() || n.fract() != 0.0 || !(0.0..=MAX_SAFE_INTEGER).contains(&n) {
        return None;
    }
    Some(n as u64)
}

fn as_pos_int(v: Option<&Value>) -> Option<u64> {
    as_non_neg_int(v).filter(|n| *n > 0)
}

/// The two members a `no_charge` clause may carry, and nothing else (§5.5.7).
const NO_CHARGE_MEMBERS: [&str; 2] = ["arrangement", "grade"];

/// Shape check for a price clause (§5.5), per `conformance/sow-pricing.json`.
///
/// Validation runs over the raw JSON rather than over [`SowPrice`] so that each
/// `invalid` row in the fixture is refused for exactly its stated reason — a
/// serde failure would collapse several distinct faults into one message. For
/// `no_charge` it is also the ONLY place the refusal can happen: serde's
/// internally tagged enum ignores unrecognized members, so a clause carrying a
/// currency would otherwise deserialize with the currency dropped.
///
/// The three refusals that matter most: a clause naming no arrangement (§5.5), a
/// time and materials clause with no cap (§5.5.3), and a no-charge clause
/// carrying a price field (§5.5.7). All three are the spec's own MUSTs and all
/// three fail closed — a proposal carrying any of them is refused rather than
/// repaired.
pub fn validate_sow_price(v: &Value) -> Result<()> {
    let Some(p) = v.as_object() else {
        return Err(invalid("must be an object"));
    };

    let Some(arrangement) = p.get("arrangement") else {
        return Err(invalid(
            "every engagement declares an arrangement — there is no undeclared default",
        ));
    };
    let Some(arrangement) = arrangement.as_str().filter(|a| PRICING_ARRANGEMENTS.contains(a)) else {
        return Err(invalid("arrangement is 'fixed_fee', 'time_and_materials' or 'no_charge'"));
    };

    if !p.get("grade").and_then(Value::as_str).is_some_and(|g| SOW_GRADES.contains(&g)) {
        return Err(invalid("grade is 'enforced', 'evidence' or 'recorded' (§4.2)"));
    }

    if arrangement == "no_charge" {
        // §5.5.7 refuses a named list and then everything else, so this is a
        // membership check rather than six field checks: a clause carrying any
        // member beyond the arrangement and its grade is malformed.
        for member in p.keys() {
            if NO_CHARGE_MEMBERS.contains(&member.as_str()) {
                continue;
            }
            return Err(invalid(format!(
                "a no_charge clause carries the arrangement and its grade and nothing else, so                  it MUST NOT carry '{member}'. There is no rate to state, no ceiling to test,                  and no cap to reserve against (§5.5.7)"
            )));
        }
        return Ok(());
    }

    if !p.get("currency").and_then(Value::as_str).is_some_and(is_currency) {
        return Err(invalid("currency is a three-letter uppercase code"));
    }

    if arrangement == "fixed_fee" {
        let rates = p.get("rates").and_then(Value::as_array).filter(|r| !r.is_empty());
        let Some(rates) = rates else {
            return Err(invalid(
                "fixed_fee prices work per offering — rates must be a non-empty array",
            ));
        };
        let mut seen: Vec<&str> = Vec::with_capacity(rates.len());
        for r in rates {
            if !r.is_object() {
                return Err(invalid("each rate is an object"));
            }
            let Some(offering) =
                r.get("offering").and_then(Value::as_str).filter(|o| !o.is_empty())
            else {
                return Err(invalid("each rate names an offering"));
            };
            if seen.contains(&offering) {
                return Err(invalid(format!("two rates for offering '{offering}'")));
            }
            seen.push(offering);
            if as_non_neg_int(r.get("per_task")).is_none() {
                return Err(invalid(
                    "per_task is a non-negative integer in the smallest unit of currency",
                ));
            }
        }
        if let Some(ceiling) = p.get("ceiling") {
            validate_ceiling(ceiling)?;
        }
        if p.contains_key("schedule") {
            return Err(invalid("a fixed_fee clause carries no schedule"));
        }
        if p.contains_key("cap") {
            return Err(invalid("a fixed_fee clause carries no cap — it carries a ceiling"));
        }
        return Ok(());
    }

    // time_and_materials
    let schedule = p.get("schedule").and_then(Value::as_array).filter(|s| !s.is_empty());
    let Some(schedule) = schedule else {
        return Err(invalid(
            "time_and_materials is a rate schedule — schedule must be a non-empty array",
        ));
    };
    let mut meters: Vec<&str> = Vec::with_capacity(schedule.len());
    for line in schedule {
        if !line.is_object() {
            return Err(invalid("each schedule line is an object"));
        }
        let Some(meter) = line.get("meter").and_then(Value::as_str).filter(|m| is_meter_name(m))
        else {
            return Err(invalid("each schedule line names a meter matching ^[a-z0-9_]{1,64}$"));
        };
        if meters.contains(&meter) {
            return Err(invalid(format!("the schedule prices '{meter}' twice")));
        }
        meters.push(meter);
        if !line.get("unit").and_then(Value::as_str).is_some_and(|u| !u.is_empty()) {
            return Err(invalid("each schedule line carries a unit label for the people reading it"));
        }
        if line.get("per").is_some() && as_pos_int(line.get("per")).is_none() {
            return Err(invalid(
                "per is the divisor — how many raw meter counts make one billable unit — and is \
                 a positive integer, defaulting to 1 when absent (§5.5.2)",
            ));
        }
        if as_non_neg_int(line.get("per_unit")).is_none() {
            return Err(invalid(
                "per_unit is a non-negative integer in the smallest unit of currency",
            ));
        }
        if let Some(pt) = line.get("pass_through") {
            if pt != &Value::Bool(true) {
                return Err(invalid("pass_through, when present, is the literal true (§5.5.6)"));
            }
        }
    }

    let Some(cap) = p.get("cap") else {
        return Err(invalid(
            "a time and materials engagement MUST carry a not-to-exceed cap — there is no \
             uncapped time and materials engagement (§5.5.3)",
        ));
    };
    if !cap.is_object() {
        return Err(invalid("cap is an object carrying an amount (§5.5.3)"));
    }
    if as_pos_int(cap.get("amount")).is_none() {
        return Err(invalid(
            "cap.amount is a positive integer — a zero cap admits no work at all (§5.5.3)",
        ));
    }

    let Some(reservation) = p.get("reservation") else {
        return Err(invalid(
            "a time and materials engagement MUST carry a reservation with a stated window — the \
             arrangement is a purchase order, and one that commits no funds and names no period \
             has no defined settlement behaviour (§5.5.4)",
        ));
    };
    if !reservation.is_object() {
        return Err(invalid("reservation is an object carrying window_days (§5.5.4)"));
    }
    if as_pos_int(reservation.get("window_days")).is_none() {
        return Err(invalid("reservation.window_days is a positive integer (§5.5.4)"));
    }

    if p.contains_key("rates") {
        return Err(invalid("a time_and_materials clause carries no rates"));
    }
    if p.contains_key("ceiling") {
        return Err(invalid(
            "a time_and_materials clause carries a cap, not a per-period ceiling (§5.5.3)",
        ));
    }
    Ok(())
}

fn validate_ceiling(v: &Value) -> Result<()> {
    if !v.is_object() {
        return Err(invalid("ceiling is an object"));
    }
    if as_pos_int(v.get("amount")).is_none() {
        return Err(invalid("ceiling.amount is a positive integer"));
    }
    if v.get("period").and_then(Value::as_str) != Some("month") {
        return Err(invalid("ceiling.period is 'month'"));
    }
    Ok(())
}

/// Shape, then the arrangement's own rules, then into the typed clause.
pub fn load_sow_price(v: &Value) -> Result<SowPrice> {
    validate_sow_price(v)?;
    serde_json::from_value(v.clone()).map_err(|e| invalid(format!("{e}")))
}

/// §5.5.2 — a schedule MUST NOT price a meter the offering does not declare.
///
/// The other half of that sentence (a runtime MUST NOT bill a meter the schedule
/// does not price) is enforced by [`rate_usage`], which refuses an unpriced
/// meter rather than dropping it.
pub fn validate_schedule_against_meters(
    price: &SowPrice,
    declared_meters: &[impl AsRef<str>],
) -> Result<()> {
    let SowPrice::TimeAndMaterials { schedule, .. } = price else { return Ok(()) };
    for line in schedule {
        if !declared_meters.iter().any(|m| m.as_ref() == line.meter) {
            return Err(invalid(format!(
                "the schedule prices '{}', which the offering does not declare — this is a \
                 validation error, not a default to be filled in (§5.5.2)",
                line.meter
            )));
        }
    }
    Ok(())
}

// ── §5.5.4: the reservation window ──────────────────────────────────────────

/// When the reservation releases: `window_days` after the engagement forms.
/// The unused remainder of the cap returns to the client at this instant.
pub fn reservation_release_at(reservation: &SowReservation, starts_at: &str) -> Result<String> {
    let start = chrono::DateTime::parse_from_rfc3339(starts_at)
        .map_err(|_| invalid("starts_at must be an RFC-3339 instant (§5.5.4)"))?;
    let window = chrono::Duration::try_days(reservation.window_days as i64)
        .ok_or_else(|| invalid("reservation.window_days is out of range (§5.5.4)"))?;
    let release = start
        .checked_add_signed(window)
        .ok_or_else(|| invalid("the reservation window overflows the calendar (§5.5.4)"))?;
    Ok(release
        .with_timezone(&chrono::Utc)
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}

/// §5.5.4 — the window MUST NOT extend beyond `ends_at`.
///
/// An engagement whose term outlasts its window needs a new reservation before
/// more work runs; an engagement whose window outlasts its term is holding the
/// client's money past the point any work can consume it.
pub fn reservation_within_term(
    reservation: &SowReservation,
    starts_at: &str,
    ends_at: &str,
) -> bool {
    let Ok(release) = reservation_release_at(reservation, starts_at) else { return false };
    let (Ok(release), Ok(end)) = (
        chrono::DateTime::parse_from_rfc3339(&release),
        chrono::DateTime::parse_from_rfc3339(ends_at),
    ) else {
        return false;
    };
    release <= end
}

// ── rating, the cap, and §5.5.5 exhaustion ──────────────────────────────────

/// A RAW meter count, in the meter's own natural grain (§5.5.2). Raw, not
/// pre-divided: the schedule's `per` does the conversion, inside the signed
/// bytes, so the buyer's own token count is the number it hands in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SowMeteredCount {
    pub meter: String,
    pub count: u64,
}

impl SowMeteredCount {
    pub fn new(meter: impl Into<String>, count: u64) -> Self {
        Self { meter: meter.into(), count }
    }
}

/// One line of a settlement record (§5.5, §5.5.6).
///
/// It carries everything the charge was computed from — the raw `count`, the
/// `per` divisor and the `per_unit` price — so a buyer can recompute `amount`
/// from its own records without holding the engagement. That is the whole point
/// of §5.5.2's machine-readable divisor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SowSettlementLine {
    pub meter: String,
    /// The human label the schedule carried. Never parsed.
    pub unit: String,
    pub count: u64,
    /// The divisor actually applied, written out even when it is 1.
    pub per: u64,
    pub per_unit: u64,
    pub amount: u64,
    /// Present and `true` only on a line the provider bought elsewhere.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pass_through: Option<bool>,
    /// REQUIRED on a pass-through line (§5.5.6): the upstream receipt that
    /// evidences the cost. The proof is usually free — the upstream engagement
    /// settled and issued its own record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_receipt: Option<String>,
    /// OPTIONAL evidence of what the upstream actually charged. When present it
    /// is checked: a pass-through line MUST NOT be priced above the upstream
    /// cost (§5.5.6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_amount: Option<u64>,
}

/// What rating a batch of metered units produced (§5.5.2, §5.5.3, §5.5.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SowRating {
    pub currency: String,
    pub lines: Vec<SowSettlementLine>,
    /// The sum of `lines`: the PROVIDER's rated total, already clamped so that
    /// it plus the operator fee taken on it never exceeds the cap (§5.5.3).
    pub total: u64,
    /// The operator fee taken on `total` (§5.5.8). Present only where a basis
    /// was supplied AND something was rated: a fee is a cut out of what the
    /// client pays, so where nothing was billed nothing was taken.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_fee: Option<SowOperatorFee>,
    /// What the CLIENT pays for this rating: `total` plus the fee inside it.
    /// Equal to `total` where no operator stands in the path.
    pub client_total: u64,
    /// How much of the cap remains after this rating, measured as REMAINING
    /// CLIENT EXPOSURE — cap less everything the client has been billed, fees
    /// included (§5.5.3). Where no fee is in play this is the same number it
    /// has always been.
    pub cap_remaining: u64,
    /// True when the cap has been reached: admission stops and the engagement
    /// moves to `exhausted` (§5.5.5). "Reached" means no further rated work
    /// fits under the remaining exposure once the fee on it is counted.
    pub exhausted: bool,
    /// What the schedule would have charged before the cap clamped it. The
    /// difference is the provider's to bear (§5.5.3).
    pub unbilled: u64,
}

/// Rate raw meter counts against a time and materials schedule, honouring the
/// cap.
///
/// Counts are RAW, in each meter's natural grain: the schedule's `per` divisor
/// does the conversion (§5.5.2), so the buyer hands in the same token count it
/// can read off its own records and gets back the same charge either side
/// computes.
///
/// Two MUSTs are enforced here. A meter the schedule does not price is refused
/// rather than billed (§5.5.2). And metered usage is not billed past the cap
/// (§5.5.3) — the total clamps, `unbilled` records what the provider absorbed,
/// and `exhausted` says the work is concluded.
///
/// `already_billed` is what the CLIENT has been billed under this engagement so
/// far, INCLUDING any operator fees inside those charges, so the cap is measured
/// over the engagement rather than over one batch and measures the client's real
/// exposure. `receipts` maps a pass-through meter to the upstream receipt that
/// evidences its cost (§5.5.6); a pass-through line with no receipt is refused
/// rather than settled.
///
/// This is the no-operator call, and it is unchanged: every number it returns
/// means what it has always meant. [`rate_usage_with_operator_fee`] is the same
/// function with §5.5.8's cut in the path.
pub fn rate_usage(
    price: &SowPrice,
    usage: &[SowMeteredCount],
    already_billed: u64,
    receipts: &[(String, String)],
) -> Result<SowRating> {
    rate_usage_with_operator_fee(price, usage, already_billed, receipts, None, None)
}

/// Rate raw meter counts with an operator's cut inside the price (§5.5.8).
///
/// **The cap bounds what the CLIENT pays, fee included** (§5.5.3, §5.5.8). An
/// operator fee is not charged on top of the cap: the provider's rated work runs
/// to the cap LESS the fee taken on it, and reaching that limit reaches the cap
/// in the ordinary way — the engagement concludes `exhausted` under §5.5.5, and
/// metered units past that point are the provider's to bear. A runtime MUST NOT
/// bill the client a sum of provider lines and operator fees greater than the
/// cap.
///
/// `fee_basis` is a basis rather than a built line, because the amount follows
/// from the rated total and the rated total is what this function decides.
/// `operator` names who takes the cut on the line it produces.
pub fn rate_usage_with_operator_fee(
    price: &SowPrice,
    usage: &[SowMeteredCount],
    already_billed: u64,
    receipts: &[(String, String)],
    fee_basis: Option<SowOperatorFeeBasis>,
    operator: Option<&str>,
) -> Result<SowRating> {
    // §5.5.7's first prohibition: a runtime MUST NOT rate work under a
    // no-charge engagement. Rating it would produce a zero-valued settlement
    // record for every task, which is the design §5.5.7 exists to rule out.
    if price.is_no_charge() {
        return Err(invalid(
            "this engagement is priced no_charge, so a runtime MUST NOT rate work under it and              there is no settlement record to hold (§5.5.7)",
        ));
    }
    let SowPrice::TimeAndMaterials { currency, schedule, cap, .. } = price else {
        return Err(invalid("rating a schedule requires a time_and_materials clause (§5.5.2)"));
    };

    // §5.5.3: the cap bounds what the client pays, fee included. What is left of
    // the client's exposure is the cap less everything already billed to it;
    // what is left for the PROVIDER is that, less the fee this rating will take.
    let exposure = cap.amount.saturating_sub(already_billed);
    let mut budget = max_rated_total_under_cap(exposure, fee_basis.as_ref());
    let mut total: u64 = 0;
    let mut unbilled: u64 = 0;
    let mut lines = Vec::with_capacity(usage.len());

    for u in usage {
        let Some(line) = schedule.iter().find(|l| l.meter == u.meter) else {
            return Err(invalid(format!(
                "a runtime MUST NOT bill '{}' — the schedule does not price it (§5.5.2)",
                u.meter
            )));
        };
        let gross = line.rate(u.count)?;
        let billed = gross.min(budget);
        budget -= billed;
        total = total.saturating_add(billed);
        unbilled = unbilled.saturating_add(gross - billed);

        let mut settled = SowSettlementLine {
            meter: line.meter.clone(),
            unit: line.unit.clone(),
            count: u.count,
            per: line.divisor(),
            per_unit: line.per_unit,
            amount: billed,
            pass_through: None,
            upstream_receipt: None,
            upstream_amount: None,
        };
        if line.is_pass_through() {
            settled.pass_through = Some(true);
            settled.upstream_receipt = receipts
                .iter()
                .find(|(meter, _)| meter == &line.meter)
                .map(|(_, receipt)| receipt.clone());
        }
        validate_settlement_line(&serde_json::to_value(&settled)?)?;
        lines.push(settled);
    }

    // The fee follows the rated total, and a fee is a cut out of what the client
    // pays: where nothing was rated nothing was charged, so nothing was taken
    // and no line is written. Under a fixed basis that is load-bearing rather
    // than tidy — a fixed charge is `basis.fixed` whatever the base, so a line
    // on a zero total would bill the client for work it did not receive.
    let fee = match fee_basis {
        Some(basis) if total > 0 => Some(operator_fee(operator, basis, total)?),
        _ => None,
    };
    let client_total = total.saturating_add(fee.as_ref().map_or(0, |f| f.amount));
    let cap_remaining = exposure.saturating_sub(client_total);

    Ok(SowRating {
        currency: currency.clone(),
        lines,
        operator_fee: fee,
        total,
        client_total,
        cap_remaining,
        // §5.5.5 — reaching the cap concludes the work. "Reached" is the point
        // at which no further rated work fits under what is left once the fee on
        // it is counted, which with no fee is exactly the old
        // `cap_remaining == 0`.
        exhausted: max_rated_total_under_cap(cap_remaining, fee_basis.as_ref()) == 0,
        unbilled,
    })
}

/// §5.5.6 — every settlement record for a pass-through line MUST reference the
/// upstream receipt, and MUST NOT be priced above the upstream cost.
///
/// A pass-through line with no receipt is a bare assertion that a cost was
/// incurred, which is the thing "at cost, with proof" exists to rule out.
pub fn validate_settlement_line(v: &Value) -> Result<()> {
    if !v.is_object() {
        return Err(invalid("a settlement line is an object"));
    }
    if !v.get("meter").and_then(Value::as_str).is_some_and(is_meter_name) {
        return Err(invalid("line.meter is a meter name"));
    }
    if !v.get("unit").and_then(Value::as_str).is_some_and(|u| !u.is_empty()) {
        return Err(invalid("line.unit is required"));
    }
    if as_non_neg_int(v.get("count")).is_none() {
        return Err(invalid("line.count is a non-negative integer"));
    }
    if as_pos_int(v.get("per")).is_none() {
        return Err(invalid(
            "line.per is the divisor actually applied, written out even when it is 1 (§5.5.2)",
        ));
    }
    if as_non_neg_int(v.get("per_unit")).is_none() {
        return Err(invalid("line.per_unit is a non-negative integer"));
    }
    let Some(amount) = as_non_neg_int(v.get("amount")) else {
        return Err(invalid("line.amount is a non-negative integer"));
    };

    let Some(pass_through) = v.get("pass_through") else {
        if v.get("upstream_receipt").is_some() {
            return Err(invalid("upstream_receipt belongs to a pass_through line (§5.5.6)"));
        }
        return Ok(());
    };
    if pass_through != &Value::Bool(true) {
        return Err(invalid("pass_through, when present, is the literal true (§5.5.6)"));
    }
    if !v.get("upstream_receipt").and_then(Value::as_str).is_some_and(|r| !r.is_empty()) {
        return Err(invalid(
            "a pass-through settlement record MUST reference the upstream receipt that \
             evidences the cost (§5.5.6)",
        ));
    }
    if let Some(upstream) = v.get("upstream_amount") {
        let Some(upstream) = as_non_neg_int(Some(upstream)) else {
            return Err(invalid("upstream_amount is a non-negative integer"));
        };
        if amount > upstream {
            return Err(invalid(
                "a pass-through line MUST NOT be priced above the upstream cost — price resold \
                 work as your own metered line if you want a margin (§5.5.6)",
            ));
        }
    }
    Ok(())
}

/// The pass-through lines of a schedule (§5.5.6): what this provider resells
/// rather than performs, and therefore what it owes receipts for.
pub fn pass_through_lines(price: &SowPrice) -> Vec<&SowScheduleLine> {
    match price {
        SowPrice::TimeAndMaterials { schedule, .. } => {
            schedule.iter().filter(|l| l.is_pass_through()).collect()
        }
        SowPrice::FixedFee { .. } | SowPrice::NoCharge { .. } => Vec::new(),
    }
}

// ── §5.5.7: nothing settles ─────────────────────────────────────────────────

/// Whether an engagement priced this way settles at all (§5.5).
///
/// True under `fixed_fee` and `time_and_materials`, where every billable unit of
/// work is rated at the engagement's price and produces a settlement record both
/// parties hold. False under `no_charge`, which has no billable units: §5.5.7
/// says a runtime MUST NOT rate the work, MUST NOT draw from the client's
/// balance, MUST NOT produce a settlement record, and MUST NOT call clearing.
pub fn settles(price: &SowPrice) -> bool {
    !price.is_no_charge()
}

/// §5.5.7 — the refusal a client node owes a settlement record that cites a
/// no-charge engagement, and the same refusal on the way in for a runtime about
/// to rate or draw against one.
///
/// Written as a prohibition rather than left to implementations because the
/// alternative design produces a settlement record of zero for every task, and
/// those records carry no information while sitting in both accounts' books
/// beside the records that do.
///
/// `act` names what was attempted, so the sentence reads as what happened rather
/// than as a category.
pub fn admit_settlement(price: &SowPrice, act: &str) -> Result<()> {
    if price.is_no_charge() {
        return Err(invalid(format!(
            "this engagement is priced no_charge, so a runtime MUST NOT {act} it and there is no              settlement record to hold. Nothing was billed and nothing is owed (§5.5.7)"
        )));
    }
    Ok(())
}

/// The committed price of an engagement — the single number an Agent Mandate
/// ceiling check tests before formation (§5.5.3, §5.5.7).
///
/// For time and materials it is the cap, which is the whole point of requiring
/// one. For no charge it is zero, and any ceiling covers it. For fixed fee it is
/// the ceiling when the clause states one; a fixed fee clause with no ceiling
/// commits no bounded total, and `None` says so rather than inventing a number.
pub fn committed_price(price: &SowPrice) -> Option<u64> {
    match price {
        SowPrice::TimeAndMaterials { cap, .. } => Some(cap.amount),
        SowPrice::NoCharge { .. } => Some(0),
        SowPrice::FixedFee { ceiling, .. } => ceiling.as_ref().map(|c| c.amount),
    }
}

// ── §5.5.8: the operator fee ────────────────────────────────────────────────

/// The basis an operator fee was computed from (§5.5.8): a percentage, or a
/// fixed charge.
///
/// `percent` is a NON-NEGATIVE INTEGER. §5.5.8 does not say whether a fractional
/// percentage is permitted, and this SDK does not accept one: a fraction inside
/// the signed bytes is a float two implementations must print identically
/// forever, and the arithmetic rule below ("`amount` MUST equal the basis
/// applied to `base`") stops being exact the moment one appears. Nothing is
/// lost. An operator wanting two and a half percent of 2500000 states the fixed
/// charge it computed, `{ kind: "fixed", fixed: 62500 }`, against the same
/// `base` — which discloses strictly more than a rate the buyer would have had
/// to multiply out itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SowOperatorFeeBasis {
    Percent { percent: u64 },
    Fixed { fixed: u64 },
}

/// §5.5.8 — the operator's own cut, disclosed on its own line.
///
/// An **operator** is a party that stands between the client and the provider
/// when money moves: it hosts one or both agents, builds the quote, settles the
/// charge, or does more than one of those. Its fee is not the provider's price
/// and it is not a §5.5.6 pass-through, which is a cost bought elsewhere and
/// billed at cost. This is a margin, and it is the operator's to charge — what
/// it is not is invisible.
///
/// Three members are required. `amount` is the cut in the settlement currency,
/// `basis` is what it was computed from, and `base` is what that basis was
/// applied to. `base` is not decoration: ten percent of the provider's price and
/// ten percent of the total the buyer pays are different numbers from the same
/// percentage, so a client node MUST NOT infer the base. `operator` is optional
/// and names who took it.
///
/// Disclosure binds at two moments and both are required: in the quote, before
/// the client commits, and in the settlement record afterwards. A quote or
/// record carrying no line asserts that no operator fee is inside its total —
/// see [`check_settlement`], which is the client node's side of that.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SowOperatorFee {
    /// OPTIONAL (§5.5.8). Who took the cut.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator: Option<String>,
    pub basis: SowOperatorFeeBasis,
    /// REQUIRED. A percentage is uncheckable without the number it was taken
    /// from, and a client node MUST NOT infer it.
    pub base: u64,
    pub amount: u64,
}

/// The exact fee a basis applied to a base produces, before flooring, as a
/// numerator over 100. Kept rational so the check below never compares floats.
fn fee_numerator(basis: &SowOperatorFeeBasis, base: u64) -> u128 {
    match basis {
        SowOperatorFeeBasis::Percent { percent } => *percent as u128 * base as u128,
        SowOperatorFeeBasis::Fixed { fixed } => *fixed as u128 * 100,
    }
}

/// The whole-unit fee a basis applied to a base produces (§5.5.8).
///
/// There is ONE rule and it takes no argument. Under a percentage basis the
/// amount is `floor(base × percent / 100)`; under a fixed basis nothing is
/// rounded and the amount is `basis.fixed`, whatever the base is. Flooring is
/// the direction §5.5.2 already applies to usage rating, so money is computed
/// one way throughout the specification, and the floor favours the buyer.
///
/// There is no rounding parameter and there was one until 0.9.0-draft. It
/// existed because §5.5.8 defined no field for a rounding rule, so no rule was
/// ever stated, so a reader had to accept several answers to the same line. The
/// specification now states the rule, so the choice is gone and the check
/// [`check_operator_fee`] performs is exact.
///
/// A percentage of a base too small to produce one whole unit produces NOTHING.
/// An operator that intends to charge a whole unit there states a fixed basis of
/// one unit, which discloses the charge as the charge it is.
pub fn operator_fee_amount(basis: &SowOperatorFeeBasis, base: u64) -> Result<u64> {
    if let SowOperatorFeeBasis::Fixed { fixed } = basis {
        return Ok(*fixed);
    }
    let amount = fee_numerator(basis, base) / 100;
    if amount > MAX_SAFE_INTEGER as u128 {
        return Err(invalid(
            "the operator fee overflows an exact integer — split the settlement (§5.5.8)",
        ));
    }
    Ok(amount as u64)
}

/// Build an operator fee line (§5.5.8), computing `amount` from the basis and
/// the base by flooring. Since 0.9.0-draft the check that follows is exact, so a
/// line an operator rounded any way but down is refused at construction.
pub fn operator_fee(
    operator: Option<&str>,
    basis: SowOperatorFeeBasis,
    base: u64,
) -> Result<SowOperatorFee> {
    let fee = SowOperatorFee {
        operator: operator.map(str::to_string),
        basis,
        base,
        amount: operator_fee_amount(&basis, base)?,
    };
    validate_operator_fee(&serde_json::to_value(&fee)?)?;
    check_operator_fee(&fee)?;
    Ok(fee)
}

/// The largest rated total that fits under `cap_remaining` once the operator fee
/// taken on it is counted (§5.5.3, §5.5.8) — **the maximal fit rule**.
///
/// §5.5.8 says the cap bounds what the client pays, fee included, so the
/// provider's rated work runs to the cap less the fee taken on it. Turning that
/// sentence into a number needs one decision the specification does not force,
/// and this is where it is made.
///
/// The obvious closed form, `floor(cap × 100 / (100 + percent))`, is WRONG, or
/// rather it is merely conservative: it assumes the fee scales continuously, and
/// the fee floors. At a cap of 100 with a ten percent fee it gives 90, but 91
/// also fits, because ten percent of 91 floors to 9 and 91 + 9 is exactly 100.
/// Both answers satisfy §5.5.8 and a client reading either record cannot tell
/// them apart, so this is not a specification defect. But two implementations
/// that pick differently disagree by a unit at every boundary, and they disagree
/// inside signed bytes. So the rule is pinned rather than left to taste:
///
/// > **the largest rated total whose sum with its own fee is within the cap.**
///
/// `conformance/sow-pricing.json` carries the cap-100-at-ten-percent case as an
/// explicit fixture so a third implementation cannot get it wrong. The loop
/// below runs at most once — a floored fee can only ever hide one whole unit of
/// headroom — but it is written as a loop because the bound is a proof and the
/// loop is the rule.
///
/// With no basis the answer is the whole remaining cap, which is what every
/// peer-to-peer caller gets and why nothing changes for them.
pub fn max_rated_total_under_cap(cap_remaining: u64, basis: Option<&SowOperatorFeeBasis>) -> u64 {
    let Some(basis) = basis else { return cap_remaining };
    match basis {
        // A fixed charge is taken whole, whatever the base (§5.5.8), so it comes
        // off the top. Where it does not fit at all, nothing does.
        SowOperatorFeeBasis::Fixed { fixed } => cap_remaining.saturating_sub(*fixed),
        SowOperatorFeeBasis::Percent { percent } => {
            let cap = cap_remaining as u128;
            let percent = *percent as u128;
            let mut fit = (cap * 100) / (100 + percent);
            while (fit + 1) + ((fit + 1) * percent) / 100 <= cap {
                fit += 1;
            }
            fit as u64
        }
    }
}

/// Shape check for an operator fee line (§5.5.8). Arithmetic is
/// [`check_operator_fee`]: a line can be well formed and still not close, and
/// those are different failures to a client node reading a settlement record.
pub fn validate_operator_fee(v: &Value) -> Result<()> {
    if !v.is_object() {
        return Err(invalid(
            "an operator fee line is an object carrying amount, basis and base (§5.5.8)",
        ));
    }
    if let Some(operator) = v.get("operator") {
        if !operator.as_str().is_some_and(|o| !o.is_empty()) {
            return Err(invalid(
                "operator_fee.operator, when present, names the operator that took the cut (§5.5.8)",
            ));
        }
    }
    let Some(basis) = v.get("basis").filter(|b| b.is_object()) else {
        return Err(invalid(
            "operator_fee.basis is an object — a percentage or a fixed charge (§5.5.8)",
        ));
    };
    match basis.get("kind").and_then(Value::as_str) {
        Some("percent") => {
            if as_non_neg_int(basis.get("percent")).is_none() {
                return Err(invalid(
                    "operator_fee.basis.percent is a non-negative integer — a fractional \
                     percentage would put a float inside the signed bytes and would make the \
                     arithmetic check inexact; state the charge you computed as a fixed basis \
                     instead (§5.5.8)",
                ));
            }
            if basis.get("fixed").is_some() {
                return Err(invalid("a percent basis carries no fixed charge (§5.5.8)"));
            }
        }
        Some("fixed") => {
            if as_non_neg_int(basis.get("fixed")).is_none() {
                return Err(invalid(
                    "operator_fee.basis.fixed is a non-negative integer in the settlement \
                     currency (§5.5.8)",
                ));
            }
            if basis.get("percent").is_some() {
                return Err(invalid("a fixed basis carries no percentage (§5.5.8)"));
            }
        }
        _ => {
            return Err(invalid(
                "operator_fee.basis.kind is 'percent' or 'fixed' — a basis is one or the other \
                 (§5.5.8)",
            ))
        }
    }
    if v.get("base").is_none() {
        return Err(invalid(
            "operator_fee.base is REQUIRED — a percentage is not checkable until the buyer knows \
             what it was applied to, and a client node MUST NOT infer the base (§5.5.8)",
        ));
    }
    if as_non_neg_int(v.get("base")).is_none() {
        return Err(invalid("operator_fee.base is a non-negative integer (§5.5.8)"));
    }
    if as_non_neg_int(v.get("amount")).is_none() {
        return Err(invalid(
            "operator_fee.amount is a non-negative integer in the settlement currency (§5.5.8)",
        ));
    }
    Ok(())
}

/// §5.5.8 — does the disclosed amount follow from the disclosed basis and base?
///
/// EXACT, both kinds. `amount` MUST equal the basis applied to `base`, computed
/// by flooring: `floor(base × percent / 100)` under a percentage, and
/// `basis.fixed` under a fixed charge. There is no tolerance for a difference of
/// one unit or of any other size.
///
/// The one-whole-unit tolerance this function applied until 0.9.0-draft is
/// WITHDRAWN. It existed because the subsection defined no field for a rounding
/// rule, so no rule was ever stated, so the fallback always applied and an
/// arithmetic check called `enforced` accepted several answers to the same line
/// forever. With one rule the check is exact, which is the point of stating it.
///
/// This check is the `enforced` half of §5.5.8. It runs on bytes the client
/// already holds, so a violation produces a mechanical refusal rather than a
/// grievance. What it does NOT establish is that the disclosed basis is the rate
/// the operator actually agreed with the provider — the client is not party to
/// that agreement, so the basis itself grades `evidence`
/// ([`OPERATOR_FEE_BASIS_GRADE`]).
pub fn check_operator_fee(fee: &SowOperatorFee) -> Result<()> {
    match fee.basis {
        SowOperatorFeeBasis::Fixed { fixed } => {
            if fee.amount != fixed {
                return Err(invalid(format!(
                    "the operator fee states {} against a fixed basis of {fixed} — a fixed \
                     charge is rounded by nothing, so amount MUST equal it exactly (§5.5.8)",
                    fee.amount
                )));
            }
        }
        SowOperatorFeeBasis::Percent { percent } => {
            let floored = fee_numerator(&fee.basis, fee.base) / 100;
            if fee.amount as u128 != floored {
                return Err(invalid(format!(
                    "the operator fee states {}, and {percent}% of {} floors to {floored}. A \
                     client node MUST reject an amount that is not the floored figure, and there \
                     is no tolerance of one unit or of any other size. An operator whose rate is \
                     finer than a whole percent states the charge that rate produced as a fixed \
                     basis against the same base (§5.5.8)",
                    fee.amount, fee.base
                )));
            }
        }
    }
    Ok(())
}

/// §5.5.8 — the basis itself grades `evidence`, always. A client node can check
/// that the disclosed percentage was applied to the disclosed base; it cannot
/// check that the disclosed percentage is the rate the operator agreed with the
/// provider, because it is not party to that agreement.
pub const OPERATOR_FEE_BASIS_GRADE: SowGrade = SowGrade::Evidence;

/// The grade §5.5.8 earns on a given money path. Never guess upward.
///
/// `Enforced` requires BOTH: the operator built the quote and the operator
/// settled the charge. Presence and arithmetic are then mechanically checkable
/// against two records the client holds.
///
/// Anything less is `Recorded`. Where no operator constructed the quote there is
/// no second record to test the quote's assertion against, so a client node can
/// check a disclosed line's arithmetic — and MUST — but cannot detect a line
/// that was never written. §5.5.8 names the both-ends case and the neither-end
/// case and is silent on the mixed one; this returns `Recorded` for it, because
/// an omission at the end nobody operates is exactly the omission nothing can
/// refuse, and grading it `Enforced` would be the laundering of trust as
/// enforcement §8.2 forbids.
pub fn operator_fee_grade(operator_built_quote: bool, operator_settled: bool) -> SowGrade {
    if operator_built_quote && operator_settled {
        SowGrade::Enforced
    } else {
        SowGrade::Recorded
    }
}

/// A quote: a total offered before commitment, and the operator fee inside it.
/// §5.5.8 defines the LINE, not the envelope carrying it, so this is the minimum
/// a client node needs to hold in order to test the settlement record that
/// follows. Implementations carry whatever else they carry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SowQuote {
    pub total: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    /// Absent asserts that no operator fee is inside `total` (§5.5.8).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_fee: Option<SowOperatorFee>,
}

/// A settlement record: what was actually charged, line by line. `total` is what
/// the client pays, and the operator fee is one of the lines that total MUST
/// account for — the fee is inside the total, and the total minus the fee is the
/// provider's net (§5.5.8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SowSettlementRecord {
    pub total: u64,
    pub lines: Vec<SowSettlementLine>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    /// Absent asserts that no operator fee is inside `total` (§5.5.8).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_fee: Option<SowOperatorFee>,
}

/// What a record's own lines account for: the rated lines plus the operator's
/// cut. §5.5.8 gives the fee the shape of a §5.5.6 pass-through line, and a
/// pass-through line is part of the total, so this one is too.
pub fn settlement_total(record: &SowSettlementRecord) -> u64 {
    record
        .lines
        .iter()
        .fold(0u64, |sum, l| sum.saturating_add(l.amount))
        .saturating_add(record.operator_fee.as_ref().map_or(0, |f| f.amount))
}

/// What the provider receives: the total minus the operator's cut (§5.5.8).
/// This is the number disclosure reveals, and the specification says so rather
/// than leaving an implementer to discover it.
pub fn provider_net(total: u64, fee: Option<&SowOperatorFee>) -> u64 {
    total.saturating_sub(fee.map_or(0, |f| f.amount))
}

/// §5.5.3, §5.5.8 — the refusal a total owes a cap it exceeds. The cap bounds
/// what the CLIENT pays, and the fee is inside that total, so a quote or a
/// record stating more than the cap states a charge the engagement forbids.
fn within_cap(total: u64, cap: Option<u64>, what: &str) -> Result<()> {
    let Some(cap) = cap else { return Ok(()) };
    if total > cap {
        return Err(invalid(format!(
            "this {what} states a total of {total} against a not-to-exceed cap of {cap}. The cap \
             bounds what the client pays, operator fee included, so the provider's rated work \
             runs to the cap less the fee taken on it and a runtime MUST NOT bill past it \
             (§5.5.3, §5.5.8)"
        )));
    }
    Ok(())
}

/// Build the quote §5.5.8 requires: the provider's total, the operator's cut
/// beside it, and a total that is the sum of the two. A quote built with no fee
/// asserts there is none inside it, which is an assertion §5.10 tests if it
/// later proves false.
///
/// Pass `cap` where one is in play (§5.5.3) and the resulting total is asserted
/// against it, fee included — a quote whose total exceeds the cap is a quote for
/// work the engagement will not admit.
pub fn quote_with_operator_fee(
    provider_total: u64,
    fee: Option<SowOperatorFee>,
    currency: Option<&str>,
    cap: Option<u64>,
) -> Result<SowQuote> {
    if let Some(f) = fee.as_ref() {
        validate_operator_fee(&serde_json::to_value(f)?)?;
        check_operator_fee(f)?;
    }
    let total = provider_total.saturating_add(fee.as_ref().map_or(0, |f| f.amount));
    within_cap(total, cap, "quote")?;
    Ok(SowQuote { total, currency: currency.map(str::to_string), operator_fee: fee })
}

/// Build the settlement record §5.5.8 requires from a [`rate_usage`] result: the
/// same lines, the same fee line the quote carried, and a total its own lines
/// account for. Rating is not re-done here and no arithmetic of the schedule is
/// repeated — the rating is the authority for what the work cost.
///
/// `fee` defaults to the line the rating already took, so a caller that rated
/// against an operator basis cannot forget to disclose the cut that rating
/// clamped the work for. Pass `cap` to assert the record's total against the
/// not-to-exceed cap (§5.5.3), fee included.
pub fn settlement_with_operator_fee(
    rating: &SowRating,
    fee: Option<SowOperatorFee>,
    cap: Option<u64>,
) -> Result<SowSettlementRecord> {
    let fee = fee.or_else(|| rating.operator_fee.clone());
    if let Some(f) = fee.as_ref() {
        validate_operator_fee(&serde_json::to_value(f)?)?;
        check_operator_fee(f)?;
    }
    let total = rating.total.saturating_add(fee.as_ref().map_or(0, |f| f.amount));
    within_cap(total, cap, "settlement record")?;
    Ok(SowSettlementRecord {
        total,
        lines: rating.lines.clone(),
        currency: Some(rating.currency.clone()),
        operator_fee: fee,
    })
}

/// Why a settlement is disputed (§5.5.8). The first three are the three checks
/// §5.5.8 requires a client node to make. The fourth is the mirror of the first:
/// a record disclosing a fee where the quote disclosed none contradicts the
/// quote's own assertion that no operator fee was inside that total, which
/// §5.5.8 states as an assertion without naming the check that catches it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SowDisputeReason {
    OperatorFeeMissing,
    OperatorFeeArithmetic,
    TotalUnaccounted,
    OperatorFeeUndisclosed,
}

impl SowDisputeReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::OperatorFeeMissing => "operator_fee_missing",
            Self::OperatorFeeArithmetic => "operator_fee_arithmetic",
            Self::TotalUnaccounted => "total_unaccounted",
            Self::OperatorFeeUndisclosed => "operator_fee_undisclosed",
        }
    }
}

/// A disputed settlement (§5.5.8), holding both documents exactly as they were
/// compared.
///
/// The two documents are OWNED COPIES BEHIND SHARED REFERENCES. §5.5.8 says a
/// client node MUST NOT repair the record by supplying the missing line or
/// recomputing the total, because a record the client rewrote is no longer
/// evidence of what the operator claimed. This module offers no repair function,
/// and the accessors hand out `&` so the held copies cannot be written through.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SowDisputedSettlement {
    reason: SowDisputeReason,
    detail: String,
    quote: SowQuote,
    record: SowSettlementRecord,
}

impl SowDisputedSettlement {
    pub fn reason(&self) -> SowDisputeReason {
        self.reason
    }
    pub fn detail(&self) -> &str {
        &self.detail
    }
    /// The quote as it was compared. Read only, deliberately (§5.5.8).
    pub fn quote(&self) -> &SowQuote {
        &self.quote
    }
    /// The record as it arrived. Read only, deliberately: a record the client
    /// rewrote is no longer evidence of what the operator claimed (§5.5.8).
    pub fn record(&self) -> &SowSettlementRecord {
        &self.record
    }
}

/// The verdict of [`check_settlement`]. On a dispute the charge is NOT settled
/// in the client's evidence chain: the discrepancy is what gets recorded
/// (§5.5.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SowSettlementVerdict {
    Settled,
    Disputed(SowDisputedSettlement),
}

impl SowSettlementVerdict {
    pub fn is_settled(&self) -> bool {
        matches!(self, Self::Settled)
    }
    pub fn disputed(&self) -> Option<&SowDisputedSettlement> {
        match self {
            Self::Disputed(d) => Some(d),
            Self::Settled => None,
        }
    }
}

/// The client node's read of a settlement record against the quote it holds
/// (§5.5.8).
///
/// Three checks, in the specification's own order: that an operator fee line is
/// present where the quote carried one, that the line's `amount` follows from
/// its `basis` and `base`, and that the record's total accounts for every line
/// the record carries. A record failing any of them is a **disputed
/// settlement**, and on one the client node MUST NOT record the charge as
/// settled, MUST record the discrepancy instead holding both documents, MUST
/// raise it under the engagement's dispute clause (§5.10) where it counts as a
/// failed obligation for §5.9 and §5.10, and MUST NOT repair the record.
///
/// It MAY continue to admit work — one discrepancy is not by itself grounds to
/// stop — and SHOULD refuse further work under the same operator after a second
/// one ([`refuse_further_work_under_operator`]).
///
/// Nothing is mutated and nothing is repaired. The returned dispute holds copies
/// of exactly what was compared, and hands them back by shared reference only.
pub fn check_settlement(quote: &SowQuote, record: &SowSettlementRecord) -> SowSettlementVerdict {
    let dispute = |reason: SowDisputeReason, detail: String| {
        SowSettlementVerdict::Disputed(SowDisputedSettlement {
            reason,
            detail,
            quote: quote.clone(),
            record: record.clone(),
        })
    };

    if quote.operator_fee.is_some() && record.operator_fee.is_none() {
        return dispute(
            SowDisputeReason::OperatorFeeMissing,
            "the quote disclosed an operator fee and the settlement record carries no operator \
             fee line. Every settlement record for a charge that carried an operator fee MUST \
             carry the same line, with the amount actually taken (§5.5.8)"
                .to_string(),
        );
    }
    if quote.operator_fee.is_none() && record.operator_fee.is_some() {
        return dispute(
            SowDisputeReason::OperatorFeeUndisclosed,
            "the settlement record discloses an operator fee the quote did not. A quote that \
             states a total and carries no operator fee line asserts that no operator fee is \
             inside that total, and this record contradicts that assertion (§5.5.8)"
                .to_string(),
        );
    }
    if let Some(fee) = record.operator_fee.as_ref() {
        if let Err(err) = check_operator_fee(fee) {
            return dispute(SowDisputeReason::OperatorFeeArithmetic, err.to_string());
        }
    }
    let accounted = settlement_total(record);
    if record.total != accounted {
        return dispute(
            SowDisputeReason::TotalUnaccounted,
            format!(
                "the settlement record states a total of {} and its own lines account for \
                 {accounted}. A settlement record MUST NOT state a total that its own lines do \
                 not account for (§5.5.8)",
                record.total
            ),
        );
    }
    SowSettlementVerdict::Settled
}

/// §5.5.8 — a client node SHOULD refuse further work under the same operator
/// after a SECOND disputed settlement. One discrepancy is not by itself grounds
/// to stop the work.
pub fn refuse_further_work_under_operator(prior_disputes: u32) -> bool {
    prior_disputes >= 2
}

// ── §5.10: disputes ─────────────────────────────────────────────────────────

/// The closed posture vocabulary (§5.10). Exactly one per clause:
///
///  - `None`: settlements are final; disagreement ends the engagement at most.
///  - `RefundOnFailedTask`: a task that fails, including failure by the
///    deliverable-form rule of §5.4, is refunded in full through clearing.
///    The machine's completion check decides; no quality argument is required.
///  - `EscalateToOwners`: the owners read the signed record together and
///    settle it as people.
///  - `Arbiter`: both parties bind, in this document, an independent agent
///    holding the published arbiter role contract whose verdict on the
///    disputed amount both commit in advance to accept (§5.10.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SowDisputesPosture {
    None,
    RefundOnFailedTask,
    EscalateToOwners,
    Arbiter,
}

impl SowDisputesPosture {
    pub fn as_str(&self) -> &'static str {
        match self {
            SowDisputesPosture::None => "none",
            SowDisputesPosture::RefundOnFailedTask => "refund_on_failed_task",
            SowDisputesPosture::EscalateToOwners => "escalate_to_owners",
            SowDisputesPosture::Arbiter => "arbiter",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "none" => Some(SowDisputesPosture::None),
            "refund_on_failed_task" => Some(SowDisputesPosture::RefundOnFailedTask),
            "escalate_to_owners" => Some(SowDisputesPosture::EscalateToOwners),
            "arbiter" => Some(SowDisputesPosture::Arbiter),
            _ => None,
        }
    }
}

/// The closed set.
pub const SOW_DISPUTES_POSTURES: [&str; 4] =
    ["none", "refund_on_failed_task", "escalate_to_owners", "arbiter"];

/// Who bears the arbiter's price (§5.10.1): `Split` — the parties bear it
/// equally — or `FollowsFinding` — each party bears it in proportion to the
/// split found against them. The arbiter's price is its own business,
/// declared like any offering's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SowArbiterFee {
    Split,
    FollowsFinding,
}

impl SowArbiterFee {
    pub fn as_str(&self) -> &'static str {
        match self {
            SowArbiterFee::Split => "split",
            SowArbiterFee::FollowsFinding => "follows_finding",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "split" => Some(SowArbiterFee::Split),
            "follows_finding" => Some(SowArbiterFee::FollowsFinding),
            _ => None,
        }
    }
}

/// The closed set.
pub const SOW_ARBITER_FEES: [&str; 2] = ["split", "follows_finding"];

/// The standard role name for the published arbiter contract
/// (<https://agentroles.ai/arbiter.html>). The clause's `role` member is
/// validated as a non-empty string, NOT pinned to this constant: the role is
/// referenced abstractly because it is a published contract any conforming
/// agent can hold, and a deployment may publish its own role registry. This
/// constant is the name the standard registry publishes, offered so callers
/// spell it once.
pub const ROLE_ARBITER: &str = "role-arbiter";

/// What the parties choose about the arbiter forum (§5.10.1), bound in the
/// signed document.
///
/// `agent` is OPTIONAL: bound at formation, both parties signed over the
/// specific judge; absent, the parties appoint one when a dispute opens, both
/// countersigning the appointment, and failing to appoint within
/// `deadline_days` the `fallback` governs. `independence_days` is the window
/// for the role's independence rule — no shared owner, no engagement with
/// either party inside it — both facts a runtime checks, at binding and again
/// at verdict. A verdict not produced inside `deadline_days` is a refusal by
/// silence, and a late verdict is void: the role's own contract says a late
/// verdict is not a verdict.
///
/// `fallback` is one of the OTHER three postures, never `Arbiter` — the type
/// cannot say so, so [`validate_sow_disputes`] does: an arbiter can decline,
/// conflict out, or fall silent, and a dispute with no working forum must
/// land somewhere the parties already agreed to — which cannot be the forum
/// that just died.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SowArbiterBinding {
    pub role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    pub independence_days: u64,
    pub deadline_days: u64,
    pub fee: SowArbiterFee,
    pub fallback: SowDisputesPosture,
}

/// The disputes clause (§5.10). Shapes pinned by
/// `conformance/sow-disputes.json`.
///
/// Graded `Evidence`, flatly: the enforced parts of §5.10 are ACTIONS
/// clearing takes — the refund where reversal is supported (§8.2), the freeze
/// on the disputed amount, the split moving on a verdict's signature — never
/// the clause's own grade. Quality judgment is out of scope for the runtime
/// and always will be: no machine here judges whether work was good. The
/// `Arbiter` posture does not change that; it names who judges, and what the
/// machinery enforces is only what is mechanical about the naming and the
/// outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SowDisputes {
    pub posture: SowDisputesPosture,
    /// REQUIRED when `posture` is `Arbiter` — an arbiter posture naming no
    /// arbiter terms names no forum — and REFUSED on every other posture.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arbiter: Option<SowArbiterBinding>,
    pub grade: SowGrade,
}

/// Backstops, not policy — the same ceiling every name-shaped string in this
/// file gets.
const ARBITER_ROLE_MAX: usize = 64;
const ARBITER_AGENT_MAX: usize = 64;

/// Shape check for a disputes clause (§5.10), per
/// `conformance/sow-disputes.json`. Over the raw JSON, like
/// [`validate_sow_reporting`], so each `invalid` row in the fixture is
/// refused for exactly its stated reason.
pub fn validate_sow_disputes(v: &Value) -> Result<()> {
    let Some(d) = v.as_object() else {
        return Err(invalid("a disputes clause is an object carrying posture and grade (§5.10)"));
    };
    let posture = d
        .get("posture")
        .and_then(|p| p.as_str())
        .and_then(SowDisputesPosture::from_str);
    let Some(posture) = posture else {
        return Err(invalid(
            "a disputes clause's posture is 'none', 'refund_on_failed_task', 'escalate_to_owners' or 'arbiter' — exactly one, from a closed set (§5.10)",
        ));
    };
    if d.get("grade").and_then(|g| g.as_str()) != Some("evidence") {
        return Err(invalid(
            "a disputes clause is graded 'evidence', flatly: the signed record a dispute is read against is exportable, and what is enforced under §5.10 is the actions clearing takes — the refund, the freeze, the split — never the clause's own grade. \
             Not 'enforced' — no machine here judges whether work was good — and not 'recorded', because the record a dispute rests on is more than a record of the clause (§5.10, §4.2)",
        ));
    }
    let binding = d.get("arbiter");
    if posture == SowDisputesPosture::Arbiter {
        if binding.is_none() {
            return Err(invalid(
                "an arbiter posture naming no arbiter terms names no forum: the arbiter member — role, independence_days, deadline_days, fee, fallback — is required when the posture is 'arbiter' (§5.10.1)",
            ));
        }
    } else if binding.is_some() {
        return Err(invalid(
            "only the arbiter posture carries the arbiter member: a clause naming a judge under a posture that never convenes one is two clauses disagreeing about which it is (§5.10, §5.10.1)",
        ));
    }
    let Some(binding) = binding else { return Ok(()) };
    let Some(a) = binding.as_object() else {
        return Err(invalid(
            "the arbiter member is an object carrying role, independence_days, deadline_days, fee and fallback (§5.10.1)",
        ));
    };
    let role_ok = a
        .get("role")
        .and_then(|r| r.as_str())
        .is_some_and(|r| !r.trim().is_empty() && r.chars().count() <= ARBITER_ROLE_MAX);
    if !role_ok {
        return Err(invalid(format!(
            "the arbiter's role names the published role contract the serving agent must hold — '{ROLE_ARBITER}' is the standard registry's — up to {ARBITER_ROLE_MAX} characters, and not blank (§5.10.1)"
        )));
    }
    if let Some(agent) = a.get("agent") {
        let ok = agent
            .as_str()
            .is_some_and(|s| !s.trim().is_empty() && s.chars().count() <= ARBITER_AGENT_MAX);
        if !ok {
            return Err(invalid(format!(
                "the arbiter's agent, when bound at formation, is the judge's public key as a non-empty string up to {ARBITER_AGENT_MAX} characters — shape only: whether the key is real is the platform's problem (§5.10.1)"
            )));
        }
    }
    if as_pos_int(a.get("independence_days")).is_none() {
        return Err(invalid(
            "independence_days is a positive whole number of days: the window inside which the arbiter must share no owner with either party and have held no engagement with either (§5.10.1)",
        ));
    }
    if as_pos_int(a.get("deadline_days")).is_none() {
        return Err(invalid(
            "deadline_days is a positive whole number of days, running from the dispute's opening; a verdict not produced inside it is a refusal by silence, and a late verdict is void (§5.10.1)",
        ));
    }
    if a.get("fee").and_then(|f| f.as_str()).and_then(SowArbiterFee::from_str).is_none() {
        return Err(invalid(
            "the arbiter's fee is 'split' — the parties bear it equally — or 'follows_finding' — each bears it in proportion to the split found against them (§5.10.1)",
        ));
    }
    let fallback = a
        .get("fallback")
        .and_then(|f| f.as_str())
        .and_then(SowDisputesPosture::from_str);
    if !matches!(
        fallback,
        Some(SowDisputesPosture::None)
            | Some(SowDisputesPosture::RefundOnFailedTask)
            | Some(SowDisputesPosture::EscalateToOwners)
    ) {
        return Err(invalid(
            "every arbiter clause states where a dead forum lands, and it cannot land on itself: fallback is one of the OTHER three postures — 'none', 'refund_on_failed_task' or 'escalate_to_owners', never 'arbiter' (§5.10.1)",
        ));
    }
    Ok(())
}

/// The clause a document declares, unvalidated, or `None` where it declares
/// none. Same contract as [`reporting_of`].
///
/// There is deliberately NO default posture for an absent clause: absent
/// means the document has not said, and a reader MUST NOT invent a posture on
/// its behalf — unlike reporting, where an absent clause honestly offers the
/// mechanical record, an unstated dispute posture is not any particular one
/// of the four.
pub fn disputes_of(doc: &Value) -> Option<&Value> {
    doc.get("disputes").filter(|d| d.is_object())
}

// ── §5.10.1: the arbiter's verdict ──────────────────────────────────────────

/// The domain tag inside an arbiter verdict's signed bytes
/// (agentroles.ai/arbiter.html §4): the ASCII tag, one newline, then the JCS
/// canonical JSON of the verdict with `signatures` removed — the family
/// convention, under the verdict's own tag. The prefix exists only inside the
/// signed bytes; it never appears in the document itself.
pub const ARBITER_VERDICT_SIG_PREFIX: &str = "agent-arbiter-verdict-v1\n";

/// One record a verdict excluded from its basis, with the reason — anything
/// that failed verification is excluded and NAMED as excluded, because a
/// verdict resting on unverified evidence does not conform
/// (arbiter.html §3.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SowArbiterExclusion {
    pub id: String,
    pub why: String,
}

/// The signature on a verdict. One signer — the arbiter, whose key the
/// verdict's `by` names — so unlike [`SowSignature`] there is no role member
/// to carry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SowArbiterVerdictSignature {
    pub key: String,
    pub signed_at: String,
    pub sig: String,
}

/// The money the parties' signatures granted authority over
/// (arbiter.html §4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SowArbiterDisputed {
    pub currency: String,
    pub amount: u64,
}

/// The one operative division of the disputed amount: full release to the
/// provider through any split to full refund to the client, in whole units,
/// summing exactly (arbiter.html §4 rule 1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SowArbiterSplit {
    pub provider: u64,
    pub client: u64,
}

/// The exact record set the verdict ruled from, committed by hash so either
/// party can recompute what was before the judge (arbiter.html §3.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SowArbiterBasis {
    pub count: u64,
    /// sha256 over the JCS array of the record ids, sorted — the same
    /// convention as the bookkeeper's statement. 64 lowercase hex.
    pub ids_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub excluded: Option<Vec<SowArbiterExclusion>>,
}

/// Whether each party's submission was received. Silence from a party is
/// recorded, never punished by inference: the record decides, not the
/// absence (arbiter.html §3.6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SowArbiterHeard {
    pub provider: bool,
    pub client: bool,
}

/// The document an arbiter produces (agentroles.ai/arbiter.html §4) — the
/// answer to the role's one question: given this signed engagement and this
/// evidence, how does the disputed amount divide between the parties?
///
/// The operative parts are `split` and `attribution`. Machines read those;
/// people read `reasons`, and a runtime that settles from the reasons
/// instead of the split does not conform. `attribution` comes from the Agent
/// SoW failure vocabulary but is validated as a non-empty name, not a closed
/// set here: the vocabulary lives with the failure clauses, and pinning a
/// copy of it in the verdict validator is how two lists drift.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SowArbiterVerdict {
    /// Always `"v1"`.
    pub verdict: String,
    /// Always `"arbiter"`.
    pub role: String,
    pub engagement: String,
    pub dispute: String,
    pub disputed: SowArbiterDisputed,
    pub split: SowArbiterSplit,
    pub attribution: String,
    pub basis: SowArbiterBasis,
    pub heard: SowArbiterHeard,
    pub reasons: String,
    pub produced_at: String,
    /// The arbiter agent's public key.
    pub by: String,
    #[serde(default)]
    pub signatures: Vec<SowArbiterVerdictSignature>,
}

/// What the CLAUSE side already knows when it receives a verdict: the amount
/// the dispute was opened against, in the engagement's currency. Handing it
/// to [`validate_arbiter_verdict`] makes the verdict-vs-dispute match part of
/// the shape check.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ArbiterVerdictExpectation {
    pub disputed_amount: Option<u64>,
    pub currency: Option<String>,
}

const ARBITER_NAME_MAX: usize = 64;

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn is_arbiter_name(s: &str) -> bool {
    !s.trim().is_empty() && s.chars().count() <= ARBITER_NAME_MAX
}

/// Shape rules for a verdict (arbiter.html §4), plus — when `expected` is
/// given — the clause side of the check: the verdict must be about the amount
/// and currency the dispute was opened against.
///
/// The load-bearing rule is rule 1: `split.provider + split.client` MUST
/// equal `disputed.amount` exactly, in whole units. Money divides one way in
/// this family: by integers, with nothing left over and nothing invented —
/// the same safe-integer discipline as the price validators, so two SDKs
/// cannot disagree by one at the boundary.
pub fn validate_arbiter_verdict(
    v: &Value,
    expected: Option<&ArbiterVerdictExpectation>,
) -> Result<()> {
    let Some(w) = v.as_object() else {
        return Err(invalid(
            "an arbiter verdict is an object — the role's signed document (arbiter.html §4)",
        ));
    };
    if w.get("verdict").and_then(|x| x.as_str()) != Some("v1") {
        return Err(invalid("verdict is 'v1' (arbiter.html §4)"));
    }
    if w.get("role").and_then(|x| x.as_str()) != Some("arbiter") {
        return Err(invalid("a verdict's role is 'arbiter' (arbiter.html §4)"));
    }
    if !w.get("engagement").and_then(|x| x.as_str()).is_some_and(is_arbiter_name) {
        return Err(invalid(
            "a verdict names the engagement it was handed, and nothing outside it is in the grant (arbiter.html §4)",
        ));
    }
    if !w.get("dispute").and_then(|x| x.as_str()).is_some_and(is_arbiter_name) {
        return Err(invalid("a verdict names the dispute it concludes (arbiter.html §4)"));
    }
    let Some(disputed) = w.get("disputed").and_then(|x| x.as_object()) else {
        return Err(invalid(
            "disputed is an object carrying currency and amount — the money the parties' signatures granted authority over (arbiter.html §4)",
        ));
    };
    let currency = disputed.get("currency").and_then(|c| c.as_str()).filter(|c| is_currency(c));
    let Some(currency) = currency else {
        return Err(invalid("disputed.currency is a three-letter uppercase code"));
    };
    let Some(amount) = as_non_neg_int(disputed.get("amount")) else {
        return Err(invalid(
            "disputed.amount is a non-negative integer in the smallest unit of the currency — never a float",
        ));
    };
    let Some(split) = w.get("split").and_then(|x| x.as_object()) else {
        return Err(invalid(
            "split is an object carrying provider and client — the one operative division of the disputed amount (arbiter.html §4)",
        ));
    };
    let provider = as_non_neg_int(split.get("provider"));
    let client = as_non_neg_int(split.get("client"));
    let (Some(provider), Some(client)) = (provider, client) else {
        return Err(invalid(
            "split.provider and split.client are non-negative integers: the answer runs from full release to full refund, in whole units, and a negative share is authority nobody granted (arbiter.html §4)",
        ));
    };
    if provider + client != amount {
        return Err(invalid(
            "split.provider + split.client must equal disputed.amount exactly, in whole units: money divides one way in this family — by integers, with nothing left over and nothing invented (arbiter.html §4 rule 1)",
        ));
    }
    if let Some(expected) = expected {
        if expected.disputed_amount.is_some_and(|want| amount != want) {
            return Err(invalid(
                "the verdict's disputed.amount is not the amount this dispute was opened against; the parties' signatures granted authority over that amount and nothing else (§5.10.2, arbiter.html §4)",
            ));
        }
        if expected.currency.as_deref().is_some_and(|want| currency != want) {
            return Err(invalid(
                "the verdict's currency is not the engagement's; a split in some other money divides nothing this clause froze (§5.10.2, arbiter.html §4)",
            ));
        }
    }
    if !w.get("attribution").and_then(|x| x.as_str()).is_some_and(is_arbiter_name) {
        return Err(invalid(
            "attribution names a failure from the Agent SoW failure vocabulary, so the finding becomes the same kind of evidence as a failure recorded honestly in the first place — a non-empty name (arbiter.html §4 rule 2)",
        ));
    }
    let Some(basis) = w.get("basis").and_then(|x| x.as_object()) else {
        return Err(invalid(
            "basis is an object carrying count and ids_sha256 — no cited basis, no conforming verdict (arbiter.html §3.5)",
        ));
    };
    if as_non_neg_int(basis.get("count")).is_none() {
        return Err(invalid(
            "basis.count is a non-negative integer: how many records were before the judge",
        ));
    }
    if !basis.get("ids_sha256").and_then(|x| x.as_str()).is_some_and(is_sha256_hex) {
        return Err(invalid(
            "basis.ids_sha256 is exactly 64 lowercase hex characters — sha256 over the JCS array of the record ids, sorted, so a verifier holding the records recomputes and compares (arbiter.html §4 rule 3)",
        ));
    }
    if let Some(excluded) = basis.get("excluded") {
        let Some(list) = excluded.as_array() else {
            return Err(invalid(
                "excluded is a list of the records that failed verification, each named with the reason (arbiter.html §3.1)",
            ));
        };
        if list.is_empty() {
            return Err(invalid(
                "an empty excluded list declares nothing, which OMITTING the member already means; two spellings of one state is how implementations come to disagree about which is which",
            ));
        }
        for e in list {
            let Some(x) = e.as_object() else {
                return Err(invalid("each exclusion is an object carrying id and why"));
            };
            if !x.get("id").and_then(|i| i.as_str()).is_some_and(is_arbiter_name) {
                return Err(invalid("an exclusion names the record it excludes"));
            }
            if !x.get("why").and_then(|y| y.as_str()).is_some_and(|s| !s.trim().is_empty()) {
                return Err(invalid(
                    "an exclusion carries the reason the record fell out of the basis; excluded and unexplained is indistinguishable from suppressed (arbiter.html §3.1)",
                ));
            }
        }
    }
    let Some(heard) = w.get("heard").and_then(|x| x.as_object()) else {
        return Err(invalid(
            "heard is an object saying whether each party's submission was received (arbiter.html §3.6)",
        ));
    };
    if !heard.get("provider").is_some_and(|b| b.is_boolean())
        || !heard.get("client").is_some_and(|b| b.is_boolean())
    {
        return Err(invalid(
            "heard carries BOTH booleans, provider and client: the verdict must say whether each was received, and silence from a party is recorded, never punished by inference (arbiter.html §3.6)",
        ));
    }
    if !w.get("reasons").and_then(|x| x.as_str()).is_some_and(|s| !s.trim().is_empty()) {
        return Err(invalid(
            "reasons is the prose a person reads; machines read the split and the attribution (arbiter.html §4 rule 5)",
        ));
    }
    if !w.get("produced_at").and_then(|x| x.as_str()).is_some_and(is_rfc3339_instant) {
        return Err(invalid(
            "produced_at must be an RFC-3339 instant — a late verdict is not a verdict, so when it was produced is load-bearing (arbiter.html §3.8)",
        ));
    }
    if !w.get("by").and_then(|x| x.as_str()).is_some_and(is_arbiter_name) {
        return Err(invalid("by is the arbiter agent's public key (arbiter.html §4)"));
    }
    if let Some(signatures) = w.get("signatures") {
        if !signatures.is_array() {
            return Err(invalid(
                "signatures is the list the arbiter's signature is appended to (arbiter.html §4)",
            ));
        }
    }
    Ok(())
}

/// The exact bytes an arbiter signs: [`ARBITER_VERDICT_SIG_PREFIX`] + the JCS
/// canonical JSON of the verdict with `signatures` removed. The
/// canonicalization is [`canonical_sow_json`]'s — document minus
/// `signatures`, canonicalized — deliberately reused rather than
/// re-implemented, under the verdict's own tag.
pub fn arbiter_verdict_signed_bytes(verdict: &Value) -> Vec<u8> {
    tagged_sig_bytes(ARBITER_VERDICT_SIG_PREFIX, canonical_sow_json(verdict).as_bytes())
}

/// Sign a verdict as the arbiter, appending to `signatures` — the borrowed
/// authority the parties' signatures granted is spent the moment this record
/// is appended (arbiter.html §3.3).
pub fn sign_arbiter_verdict(verdict: &mut Value, kp: &KeyPair, signed_at: &str) -> Result<()> {
    let sig = kp
        .sign(&arbiter_verdict_signed_bytes(verdict))
        .map_err(|e| MeshError::Nkey(e.to_string()))?;
    let record = serde_json::to_value(SowArbiterVerdictSignature {
        key: kp.public_key(),
        signed_at: signed_at.to_string(),
        sig: b64url(&sig),
    })?;
    let Some(map) = verdict.as_object_mut() else {
        return Err(invalid("a verdict is an object"));
    };
    let existing = map.remove("signatures").and_then(|s| match s {
        Value::Array(a) => Some(a),
        _ => None,
    });
    let key = kp.public_key();
    let mut signatures: Vec<Value> = existing
        .unwrap_or_default()
        .into_iter()
        .filter(|s| s.get("key").and_then(Value::as_str) != Some(key.as_str()))
        .collect();
    signatures.push(record);
    map.insert("signatures".to_string(), Value::Array(signatures));
    Ok(())
}

/// Verify one signature record against the verdict's canonical bytes. Where
/// clearing honors the clause, this verification is what money moves on:
/// verifying the arbiter's signature is arithmetic even though its judgment
/// is not.
pub fn verify_arbiter_verdict_signature(
    verdict: &Value,
    signature: &SowArbiterVerdictSignature,
) -> bool {
    let Ok(sig) = unb64url(&signature.sig) else { return false };
    let canonical = canonical_sow_json(verdict);
    match KeyPair::from_public_key(&signature.key) {
        Ok(vpub) => verify_tagged(&vpub, ARBITER_VERDICT_SIG_PREFIX, canonical.as_bytes(), &sig),
        Err(_) => false,
    }
}

// ── §5.11: confidentiality and retention ────────────────────────────────────

/// The closed promise vocabulary (§5.11), and the only spelling a promise
/// has: presence, as the literal `true`. Absence carries the weak meaning
/// throughout — a promise left out is a promise not made, and a reader MUST
/// NOT infer it. There is no `false`: it is spelled by omission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SowConfidentialityPromise {
    NoTraining,
    NoThirdPartySharing,
    NoHumanReading,
}

impl SowConfidentialityPromise {
    pub fn as_str(&self) -> &'static str {
        match self {
            SowConfidentialityPromise::NoTraining => "no_training",
            SowConfidentialityPromise::NoThirdPartySharing => "no_third_party_sharing",
            SowConfidentialityPromise::NoHumanReading => "no_human_reading",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "no_training" => Some(SowConfidentialityPromise::NoTraining),
            "no_third_party_sharing" => Some(SowConfidentialityPromise::NoThirdPartySharing),
            "no_human_reading" => Some(SowConfidentialityPromise::NoHumanReading),
            _ => None,
        }
    }
}

/// The closed set.
pub const SOW_CONFIDENTIALITY_PROMISES: [&str; 3] =
    ["no_training", "no_third_party_sharing", "no_human_reading"];

/// One service a client's content passes through so the work can happen
/// (§5.11): the model API behind the agent, a transcription service, any host
/// that can read what it holds. `service` is the one REQUIRED member — the
/// client is owed the name so it can go read that service's terms. `domain`
/// says which service of that name is meant; `purpose` is the narrowest true
/// statement of what it is used for. Declaring a processor is neither
/// endorsement nor a transfer of obligation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SowProcessor {
    pub service: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
}

/// The transport sub-clause (§5.11): runtime-checkable, so always graded
/// `Enforced`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SowConfidentialityTransport {
    pub sealed: bool,
    pub grade: SowGrade,
}

/// The retention sub-clause (§5.11): a ceiling in whole days,
/// runtime-checkable, so always graded `Enforced`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SowConfidentialityRetention {
    pub max_days: u64,
    pub grade: SowGrade,
}

/// The promises a provider makes about what happens inside its own walls
/// (§5.11). Only `true` is ever stored: a promise left out is a promise not
/// made — `false` is not a value, it is omission, and validation refuses it.
/// `no_third_party_sharing` quantifies over everything EXCEPT the declared
/// processors: it is the promise that content goes nowhere beyond that list,
/// not the fiction that it goes nowhere at all. Always graded `Recorded`:
/// what a party does inside its own walls is checkable by nobody.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SowConfidentialityPromises {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_training: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_third_party_sharing: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_human_reading: Option<bool>,
    pub grade: SowGrade,
}

/// The canonical split clause (§5.11). Sub-clauses are graded separately and
/// MUST NOT be merged: sealed transport and retention windows are
/// runtime-checkable and graded `Enforced`; what a party does with data
/// inside its own walls is checkable by nobody, so the promises are
/// `Recorded`, and a conforming renderer MUST NOT present them as enforced.
///
/// Absence carries the weak meaning throughout. An EMPTY `processors` list is
/// itself a statement — content leaves the provider for nowhere — while
/// omitting the member entirely states nothing, and a reader MUST NOT mistake
/// silence for either answer. Shapes pinned by
/// `conformance/sow-data-use.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SowConfidentiality {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<SowConfidentialityTransport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention: Option<SowConfidentialityRetention>,
    /// `Some(vec![])` is meaningful and serializes as `[]`: empty states
    /// "nowhere", omission states nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub processors: Option<Vec<SowProcessor>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub promises: Option<SowConfidentialityPromises>,
}

/// What a client requires of a counterparty's confidentiality clause — the
/// requirement side of §5.11's pre-admission shadow, compared by
/// [`confidentiality_shortfall`]. Every required promise must be declared,
/// and a declared retention window must be no longer than the required
/// ceiling.
///
/// Processor ACCEPTABILITY is deliberately not here in v1: which processors a
/// client will tolerate is a policy question with its own machinery, and
/// tracker #145 owns it. The list is still validated and still signed — it is
/// only the comparison that does not read it yet.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SowConfidentialityRequirement {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub promises: Option<Vec<SowConfidentialityPromise>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention_max_days: Option<u64>,
    /// The jurisdictions content may be processed in. The document's declared
    /// `processed_in` must be stated and a subset of this list: the same test
    /// §5.15 applies going down a subcontract chain, applied here between a
    /// requirement and the document answering it, and for the same reason.
    /// Silence fails rather than passing, because an unstated jurisdiction may
    /// be any jurisdiction.
    ///
    /// An EMPTY list asks nothing, exactly as an empty `promises` list does. A
    /// requirement allowing no jurisdiction at all would forbid the work rather
    /// than confine it, and is not a thing anybody means.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub processed_in: Option<Vec<String>>,
}

/// Backstops, not policy. A clause naming dozens of processors is a data-flow
/// inventory wearing a clause's clothes.
const CONFIDENTIALITY_PROCESSORS_MAX: usize = 16;
const PROCESSOR_SERVICE_MAX: usize = 120;
const PROCESSOR_DOMAIN_MAX: usize = 120;
const PROCESSOR_PURPOSE_MAX: usize = 300;

/// Shape check for a confidentiality clause (§5.11), per
/// `conformance/sow-data-use.json`. Over the raw JSON, like
/// [`validate_sow_reporting`], so each `invalid` row in the fixture is
/// refused for exactly its stated reason.
pub fn validate_sow_confidentiality(v: &Value) -> Result<()> {
    let Some(c) = v.as_object() else {
        return Err(invalid(
            "a confidentiality clause is an object of separately graded sub-clauses — transport, retention, processors, promises (§5.11)",
        ));
    };
    if let Some(t) = c.get("transport") {
        let Some(t) = t.as_object() else {
            return Err(invalid("transport is an object carrying sealed and grade (§5.11)"));
        };
        if !t.get("sealed").is_some_and(|s| s.is_boolean()) {
            return Err(invalid(
                "transport.sealed is a boolean: the channel either is sealed or it is not (§5.11)",
            ));
        }
        if t.get("grade").and_then(|g| g.as_str()) != Some("enforced") {
            return Err(invalid(
                "transport is graded 'enforced': whether the channel is sealed is runtime-checkable, and a clause claiming less understates what ships (§5.11, §4.2)",
            ));
        }
    }
    if let Some(r) = c.get("retention") {
        let Some(r) = r.as_object() else {
            return Err(invalid("retention is an object carrying max_days and grade (§5.11)"));
        };
        if as_pos_int(r.get("max_days")).is_none() {
            return Err(invalid(
                "retention.max_days is a positive whole number of days; a fractional ceiling invites two implementations to round differently (§5.11)",
            ));
        }
        if r.get("grade").and_then(|g| g.as_str()) != Some("enforced") {
            return Err(invalid(
                "retention is graded 'enforced': a retention window is runtime-checkable, and a clause claiming less understates what ships (§5.11, §4.2)",
            ));
        }
    }
    if let Some(processors) = c.get("processors") {
        let Some(list) = processors.as_array() else {
            return Err(invalid(
                "processors is a list of the services content passes through, even with one entry — and an empty list is itself a statement: content leaves the provider for nowhere (§5.11)",
            ));
        };
        // NO minimum: [] is valid and meaningful (§5.11's absence paragraph —
        // empty states "nowhere", omission states nothing). This deliberately
        // differs from additions/rests_on, where empty is a second spelling
        // of omission and refused for it.
        if list.len() > CONFIDENTIALITY_PROCESSORS_MAX {
            return Err(invalid(format!(
                "a confidentiality clause names at most {CONFIDENTIALITY_PROCESSORS_MAX} processors; a clause naming dozens is a data-flow inventory wearing a clause's clothes (§5.11)"
            )));
        }
        let mut seen = std::collections::HashSet::new();
        for p in list {
            let Some(p) = p.as_object() else {
                return Err(invalid(
                    "each processor is an object carrying service, and optionally domain and purpose (§5.11)",
                ));
            };
            let service = p.get("service").and_then(|s| s.as_str()).filter(|s| {
                !s.trim().is_empty() && s.chars().count() <= PROCESSOR_SERVICE_MAX
            });
            let Some(service) = service else {
                return Err(invalid(format!(
                    "a processor's service is the one required member — the client is owed the name so it can go read that service's terms — up to {PROCESSOR_SERVICE_MAX} characters, and not blank (§5.11)"
                )));
            };
            if let Some(domain) = p.get("domain") {
                let ok = domain.as_str().is_some_and(|s| {
                    !s.trim().is_empty() && s.chars().count() <= PROCESSOR_DOMAIN_MAX
                });
                if !ok {
                    return Err(invalid(format!(
                        "a processor's domain says which service of that name is meant, up to {PROCESSOR_DOMAIN_MAX} characters, and not blank (§5.11)"
                    )));
                }
            }
            if let Some(purpose) = p.get("purpose") {
                let ok = purpose.as_str().is_some_and(|s| {
                    !s.trim().is_empty() && s.chars().count() <= PROCESSOR_PURPOSE_MAX
                });
                if !ok {
                    return Err(invalid(format!(
                        "a processor's purpose is the narrowest true statement of what it is used for, up to {PROCESSOR_PURPOSE_MAX} characters, and not blank (§5.11)"
                    )));
                }
            }
            let key = format!(
                "{service}\n{}",
                p.get("domain").and_then(|d| d.as_str()).unwrap_or("")
            );
            if !seen.insert(key) {
                return Err(invalid(
                    "the same service and domain pair twice states nothing new; a reader cannot tell whether the second entry is a mistake or a different service (§5.11)",
                ));
            }
        }
    }
    if let Some(promises) = c.get("promises") {
        let Some(p) = promises.as_object() else {
            return Err(invalid(
                "promises is an object of the promises made, each spelled as the literal true, plus its grade (§5.11)",
            ));
        };
        for name in SOW_CONFIDENTIALITY_PROMISES {
            if let Some(v) = p.get(name) {
                if v.as_bool() != Some(true) {
                    return Err(invalid(format!(
                        "a promise is spelled by presence: {name} is either the literal true or absent — false is not a value, it is spelled by omission, because a promise left out is a promise not made (§5.11)"
                    )));
                }
            }
        }
        if p.get("grade").and_then(|g| g.as_str()) != Some("recorded") {
            return Err(invalid(
                "promises are graded 'recorded': what a party does with data inside its own walls is checkable by nobody, and a conforming renderer MUST NOT present these as enforced (§5.11, §4.2)",
            ));
        }
    }
    Ok(())
}

/// The clause a document declares, unvalidated, or `None` where it declares
/// none. Same contract as [`reporting_of`].
pub fn confidentiality_of(doc: &Value) -> Option<&Value> {
    doc.get("confidentiality").filter(|c| c.is_object())
}

/// The deterministic comparison §5.11's pre-admission shadow rests on: does
/// this document meet `required`? `None` where it meets — including a
/// retention ceiling met exactly, because the test is a ceiling, and
/// including any document at all against an empty requirement, which asks
/// nothing.
///
/// A shortfall is a SENTENCE, not a refusal — same contract as
/// [`reporting_shortfall`], and the wording is pinned by the fixture for the
/// same reason: a client reads one message whichever SDK evaluated it. Three
/// facts get three kinds of sentence — declared nothing, declared something
/// unreadable, and declared less than was required — checked in that order,
/// with required promises compared in the REQUIREMENT'S declared order (the
/// first missing one is reported), then retention, then jurisdictions.
///
/// The jurisdiction test is §5.15's, applied between a requirement and the
/// document answering it rather than between a prime and its subcontract: the
/// declared set must be stated and a subset of the required one, and silence
/// fails because an unstated jurisdiction may be any jurisdiction. It reads
/// `processed_in` as declared structure, which is the posture
/// [`subcontract_conformance`] already takes and the reason there is one
/// implementation of this rule rather than two.
///
/// Unlike reporting, absence here is NOT a level that meets a floor: a
/// document declaring no clause against a requirement that states terms is
/// counted as not meeting rather than read charitably — silence is not an
/// answer (§5.11).
///
/// Processor acceptability is deliberately not compared in v1 — tracker #145
/// owns it. See [`SowConfidentialityRequirement`].
pub fn confidentiality_shortfall(
    required: &SowConfidentialityRequirement,
    doc: &Value,
) -> Option<String> {
    let wanted_promises: &[SowConfidentialityPromise] =
        required.promises.as_deref().unwrap_or(&[]);
    let wanted_in: &[String] = required.processed_in.as_deref().unwrap_or(&[]);
    let wants_anything = !wanted_promises.is_empty()
        || required.retention_max_days.is_some()
        || !wanted_in.is_empty();
    if !wants_anything {
        return None;
    }
    let raw = doc.get("confidentiality").filter(|c| !c.is_null());
    let Some(raw) = raw else {
        return Some(
            "the requirement states confidentiality terms and this document declares none; silence is not an answer, and it is counted as not meeting rather than read charitably (§5.11)"
                .to_string(),
        );
    };
    if validate_sow_confidentiality(raw).is_err() {
        return Some(
            "the requirement states confidentiality terms and this document's confidentiality clause is in a shape that cannot be read, so what it promises cannot be established; it is counted as not meeting rather than passed unread (§5.11)"
                .to_string(),
        );
    }
    for name in wanted_promises {
        let made = raw
            .get("promises")
            .and_then(|p| p.get(name.as_str()))
            .and_then(|v| v.as_bool())
            == Some(true);
        if !made {
            return Some(format!(
                "the requirement includes the promise {} and this document does not make it; a promise left out is a promise not made (§5.11)",
                name.as_str()
            ));
        }
    }
    if let Some(n) = required.retention_max_days {
        let Some(retention) = raw.get("retention") else {
            return Some(format!(
                "the requirement caps retention at {n} days and this document states no retention ceiling; an unstated ceiling does not meet a stated one (§5.11)"
            ));
        };
        let m = as_pos_int(retention.get("max_days")).expect("validated");
        if m > n {
            return Some(format!(
                "the requirement caps retention at {n} days and this document keeps content up to {m} days; the test is a ceiling, and it is not met (§5.11)"
            ));
        }
    }
    if !wanted_in.is_empty() {
        let list = wanted_in.join(", ");
        let Some(declared) = stated_jurisdictions(raw.as_object()) else {
            return Some(format!(
                "the requirement confines processing to {list} and this document states no jurisdictions; an unstated jurisdiction may be any jurisdiction, and it is counted as not meeting rather than read charitably (§5.11)"
            ));
        };
        for j in declared {
            if !wanted_in.iter().any(|w| w.as_str() == j) {
                return Some(format!(
                    "the requirement confines processing to {list} and this document processes in {j}; a party may touch no jurisdiction the requirement allowed (§5.11)"
                ));
            }
        }
    }
    None
}

// ── §5.12: reporting ────────────────────────────────────────────────────────

/// What arrives while there is still time to act (§5.12).
///
/// Everything else in the specification reports at the end of something — a
/// task completes or fails, an engagement lapses, a review is written — and
/// all of it arrives when it is already too late to act. The reporting clause
/// says what arrives DURING the work. Three levels, ordered, and the order is
/// the point: two parties compare as integers, and the test is meets or
/// exceeds, never equals — offering more than was asked is not a violation.
///
/// `CheckIns` exists because of the failure `OnChange` cannot see: an agent
/// that is quietly stuck reports nothing under a change-triggered rule,
/// because from where it stands nothing has changed — its expectation is
/// stable and wrong. Hence the calendar, and hence the rule that a check-in is
/// not a ping: it MUST carry what was completed, what remains and what it
/// waits on, so a stuck provider cannot emit "on track" forever. Risk is
/// contents of `CheckIns`, not a fourth level, and an open risk MUST name what
/// would dissolve it. A missed report rides §5.4's interim-deliverable
/// machinery — no parallel mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SowReportingLevel {
    RecordsOnly,
    OnChange,
    CheckIns,
}

impl SowReportingLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            SowReportingLevel::RecordsOnly => "records_only",
            SowReportingLevel::OnChange => "on_change",
            SowReportingLevel::CheckIns => "check_ins",
        }
    }

    /// Position IS the rank. Derived from the level, never declared, or the
    /// two could drift.
    pub fn rank(&self) -> u8 {
        match self {
            SowReportingLevel::RecordsOnly => 0,
            SowReportingLevel::OnChange => 1,
            SowReportingLevel::CheckIns => 2,
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "records_only" => Some(SowReportingLevel::RecordsOnly),
            "on_change" => Some(SowReportingLevel::OnChange),
            "check_ins" => Some(SowReportingLevel::CheckIns),
            _ => None,
        }
    }
}

/// The closed set, ascending.
pub const SOW_REPORTING_LEVELS: [&str; 3] = ["records_only", "on_change", "check_ins"];

/// What an absent clause offers: the mechanical record — task states,
/// deliveries, spend — and nothing else. The honest default for short or
/// cheap work. Absent is NOT unknown.
pub const DEFAULT_REPORTING_LEVEL: SowReportingLevel = SowReportingLevel::RecordsOnly;

/// §5.12 grades this clause flatly. Not `Enforced`: no runtime can make a
/// provider look honestly at its own work, and a report's content is a claim
/// like any other. Not `Recorded`: detecting the report that did not arrive
/// is a MUST of both runtimes, which is more than a record of the clause.
/// What is mechanical is whether it arrived.
pub const SOW_REPORTING_GRADE: SowGrade = SowGrade::Evidence;

/// The §5.12 test: meets or exceeds, never equals. A provider offering
/// `CheckIns` against a requirement of `OnChange` has exceeded it, not
/// violated it.
pub fn meets_reporting_level(offered: SowReportingLevel, required: SowReportingLevel) -> bool {
    offered.rank() >= required.rank()
}

/// The clause (§5.12). Shapes pinned by `conformance/sow-reporting.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SowReporting {
    pub level: SowReportingLevel,
    /// The cadence, an ISO 8601 duration like `P1W`. `CheckIns` only, and
    /// required there: without it, the report that did not arrive cannot be
    /// detected, and §5.12's miss machinery has nothing to measure against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub every: Option<String>,
    /// What arrives beyond the level's floor, in words a person reads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub additions: Option<Vec<String>>,
    /// Always `Evidence` — see [`SOW_REPORTING_GRADE`].
    pub grade: SowGrade,
}

const REPORTING_ADDITION_MAX: usize = 300;
/// A backstop, not a policy — mirrors §12.1's. A clause stating dozens of
/// additions is a reporting regime wearing a clause's clothes.
const REPORTING_ADDITIONS_MAX: usize = 10;

const MS_PER_DAY: u64 = 86_400_000;

/// The cadence in milliseconds, or a refusal (§5.12).
///
/// ISO 8601 durations restricted to spans of FIXED length: weeks, days,
/// hours, minutes, seconds, in whole units of at most six digits per
/// component, with ISO's own rule that a week term stands alone. Months and
/// years are refused by name: a calendar month is not a fixed span of time,
/// and a cadence two runtimes measure differently is a missed-report detector
/// that disagrees with itself. The millisecond values are pinned by the
/// fixture so both SDKs derive the same deadline from the same document.
pub fn reporting_every_ms(every: &str) -> Result<u64> {
    let shape = || {
        invalid("every is an ISO 8601 duration in whole weeks, days, hours, minutes or seconds — P1W, P3D, PT12H (§5.12)")
    };
    let b = every.as_bytes();
    if b.first() != Some(&b'P') {
        return Err(shape());
    }
    let mut i = 1usize;
    let mut in_time = false;
    let mut saw_weeks = false;
    let mut saw_any = false;
    let mut saw_time_component = false;
    // Order within each part: D before T; then H, M, S once each, in order.
    let mut last = 0u8;
    let mut total = 0u64;
    while i < b.len() {
        if b[i] == b'T' {
            if in_time || saw_weeks {
                return Err(shape());
            }
            in_time = true;
            i += 1;
            continue;
        }
        let mut j = i;
        while j < b.len() && b[j].is_ascii_digit() {
            j += 1;
        }
        if j == i || j - i > 6 || j >= b.len() {
            return Err(shape());
        }
        let n: u64 = every[i..j].parse().expect("digits");
        let unit = b[j];
        if !in_time {
            match unit {
                b'W' => {
                    if saw_any {
                        return Err(invalid(
                            "an ISO 8601 week term stands alone: state the cadence as weeks or as days and time, not both (§5.12)",
                        ));
                    }
                    saw_weeks = true;
                    total += n * 604_800_000;
                }
                b'D' => {
                    if saw_weeks || last > 0 {
                        return Err(shape());
                    }
                    last = 1;
                    total += n * MS_PER_DAY;
                }
                b'M' | b'Y' => {
                    return Err(invalid(
                        "a calendar month or year is not a fixed span of time, so a cadence stated in one is not computable the same way twice; state every in weeks, days or hours (§5.12)",
                    ));
                }
                _ => return Err(shape()),
            }
        } else {
            let order = match unit {
                b'H' => 2u8,
                b'M' => 3u8,
                b'S' => 4u8,
                _ => return Err(shape()),
            };
            if order <= last {
                return Err(shape());
            }
            last = order;
            total += n * match unit {
                b'H' => 3_600_000,
                b'M' => 60_000,
                _ => 1_000,
            };
            saw_time_component = true;
        }
        saw_any = true;
        i = j + 1;
    }
    if !saw_any {
        return Err(shape());
    }
    if in_time && !saw_time_component {
        return Err(shape());
    }
    if total == 0 {
        return Err(invalid("a cadence of zero is no cadence at all (§5.12)"));
    }
    Ok(total)
}

/// Shape check for a reporting clause (§5.12), per
/// `conformance/sow-reporting.json`. Over the raw JSON, like
/// [`validate_sow_price`], so each `invalid` row in the fixture is refused for
/// exactly its stated reason.
pub fn validate_sow_reporting(v: &Value) -> Result<()> {
    let Some(r) = v.as_object() else {
        return Err(invalid("a reporting clause is an object carrying level and grade (§5.12)"));
    };
    let level = r
        .get("level")
        .and_then(|l| l.as_str())
        .and_then(SowReportingLevel::from_str);
    let Some(level) = level else {
        return Err(invalid(
            "a reporting clause's level is 'records_only', 'on_change' or 'check_ins', in ascending order of what the provider owes (§5.12)",
        ));
    };
    if r.get("grade").and_then(|g| g.as_str()) != Some("evidence") {
        return Err(invalid(
            "a reporting clause is graded 'evidence', flatly: the cadence and contents are in the signed document, reports are exportable, and a miss is recorded. \
             Not 'enforced' — no runtime can make a provider look honestly at its own work — and not 'recorded', because detecting the report that did not arrive is a MUST (§5.12, §4.2)",
        ));
    }
    if level == SowReportingLevel::CheckIns {
        let Some(every) = r.get("every").and_then(|e| e.as_str()) else {
            return Err(invalid(
                "check_ins is the level with a calendar: without every, the report that did not arrive cannot be detected, and §5.12's miss machinery has nothing to measure against",
            ));
        };
        reporting_every_ms(every)?;
    } else if r.get("every").is_some() {
        return Err(invalid(
            "only check_ins carries every: on_change is change-triggered with no calendar, and records_only owes nothing beyond the mechanical record (§5.12)",
        ));
    }
    if let Some(additions) = r.get("additions") {
        let Some(list) = additions.as_array() else {
            return Err(invalid("additions is a list of what arrives beyond the level's floor, in words (§5.12)"));
        };
        if list.is_empty() {
            return Err(invalid(
                "an empty additions list declares nothing, which OMITTING the member already means; two spellings of one state is how implementations come to disagree about which is which (§5.12)",
            ));
        }
        if list.len() > REPORTING_ADDITIONS_MAX {
            return Err(invalid(format!(
                "a reporting clause states at most {REPORTING_ADDITIONS_MAX} additions; a clause stating dozens is a reporting regime wearing a clause's clothes (§5.12)"
            )));
        }
        for a in list {
            let ok = a
                .as_str()
                .is_some_and(|s| !s.trim().is_empty() && s.chars().count() <= REPORTING_ADDITION_MAX);
            if !ok {
                return Err(invalid(format!(
                    "each addition is a sentence a person reads, up to {REPORTING_ADDITION_MAX} characters (§5.12)"
                )));
            }
        }
    }
    Ok(())
}

/// The clause a document declares, unvalidated, or `None` where it declares
/// none. Same contract as [`qualifications_of`].
pub fn reporting_of(doc: &Value) -> Option<&Value> {
    doc.get("reporting").filter(|r| r.is_object())
}

/// The advisory comparison a mandate uses: does what this document offers
/// meet `required`? `None` where it meets — including everything against a
/// requirement of `RecordsOnly`, which is the floor every document meets.
///
/// A shortfall is a SENTENCE, not a refusal: an advisory mandate marks the
/// document non-conforming and shows the sentence, and whoever stated the
/// requirement decides what to do about it. Three facts get three different
/// sentences — declared lower, declared nothing, declared something
/// unreadable — because "you offered less" and "what you offered cannot be
/// established" are different statements, and only one of them is about the
/// responder's choice. The exact wording is pinned by the fixture: a
/// responder reads one message whichever SDK evaluated it.
///
/// The comparison is over two DECLARED fields (§5.12: the declaring party
/// owns its own structure) — nothing here reads anyone's prose.
pub fn reporting_shortfall(required: SowReportingLevel, doc: &Value) -> Option<String> {
    if required == DEFAULT_REPORTING_LEVEL {
        return None;
    }
    let raw = doc.get("reporting");
    let Some(raw) = raw.filter(|r| !r.is_null()) else {
        return Some(format!(
            "the required reporting level is {} and this document declares no reporting clause, which offers records_only, the mechanical record only; the test is meets or exceeds, and it does not meet (§5.12)",
            required.as_str()
        ));
    };
    if validate_sow_reporting(raw).is_err() {
        return Some(format!(
            "the required reporting level is {} and this document's reporting clause is in a shape that cannot be read, so what it offers cannot be established; it is counted as not meeting rather than passed unread (§5.12)",
            required.as_str()
        ));
    }
    let offered = raw
        .get("level")
        .and_then(|l| l.as_str())
        .and_then(SowReportingLevel::from_str)
        .expect("validated");
    if meets_reporting_level(offered, required) {
        return None;
    }
    Some(format!(
        "the required reporting level is {} and this document offers {}; the test is meets or exceeds, and it does not meet (§5.12)",
        required.as_str(),
        offered.as_str()
    ))
}

/// §5.12's "cadence follows the money", as the warning a runtime MAY show and
/// the refusal it MUST NOT make.
///
/// Where the engagement has a cap, `every` SHOULD be shorter than the time in
/// which the provider could spend what remains of it — weekly check-ins on an
/// engagement whose whole cap can burn in a day are decoration. The
/// derivation rests on a spend rate neither party knows exactly in advance,
/// so `spend_per_day` is whatever the caller measured (a metering platform
/// has an observed rate; a client node may only have an estimate), and no
/// answer here refuses anything. Zero cap or zero spend is no derivation at
/// all: `None`.
///
/// The boundary is exact: warn when `every_ms * spend_per_day >=
/// cap_remaining * ms_per_day`, cross-multiplied in u128 so two
/// implementations cannot disagree by one at the boundary. "Not shorter"
/// includes "equal": an interval that exactly covers the burn still lets the
/// money be gone when the report arrives.
pub fn reporting_cadence_warning(
    reporting: &SowReporting,
    cap_remaining: u64,
    spend_per_day: u64,
) -> Option<String> {
    if reporting.level != SowReportingLevel::CheckIns {
        return None;
    }
    let every = reporting.every.as_deref()?;
    if cap_remaining == 0 || spend_per_day == 0 {
        return None;
    }
    let every_ms = reporting_every_ms(every).ok()?;
    if (every_ms as u128) * (spend_per_day as u128) < (cap_remaining as u128) * (MS_PER_DAY as u128) {
        return None;
    }
    Some(format!(
        "at {spend_per_day} per day, the remaining cap of {cap_remaining} can be spent within one reporting interval of {every}; the money can be gone before the next check-in arrives (§5.12: cadence follows the money). A runtime MAY warn on this and MUST NOT refuse the engagement over it"
    ))
}

// ── §5.13: liability ────────────────────────────────────────────────────────

/// The liability cap (§5.13): MUTUAL — it bounds each party's total liability
/// to the other — and stated in exactly ONE form, a multiple of fees actually
/// paid or payable, or an absolute figure in a stated currency. Both forms in
/// one cap, or neither, is refused by [`validate_sow_liability`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SowLiabilityCap {
    MultipleOfFees { multiple_of_fees: u64 },
    Amount { amount: u64, currency: String },
}

/// Each party's hold-harmless statements (§5.13), prose a court reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SowIndemnification {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by_provider: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by_client: Option<Vec<String>>,
}

/// The liability clause (§5.13). Shapes pinned by `conformance/sow-terms.json`.
///
/// Everything else in the specification bounds what the CLIENT can lose;
/// nothing bounds what the PROVIDER can lose, and this clause is where the
/// parties bound it, mutually, in the signed bytes. `carve_outs` and
/// `indemnification` are PROSE, deliberately: nothing here refuses or gates
/// on a carve-out, and the sentence a judge reads is the operative artifact.
///
/// Graded `Recorded`, and this is the clause the grade vocabulary exists for:
/// no runtime enforces a liability cap, measures damages, or holds anyone
/// harmless — courts do, reading the signed document. A conforming renderer
/// MUST NOT present any part of this clause as enforced, and a runtime MUST
/// NOT refuse or gate anything on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SowLiability {
    pub cap: SowLiabilityCap,
    /// What the cap does NOT cover, in words a court reads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub carve_outs: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub indemnification: Option<SowIndemnification>,
    /// Always `Recorded` — see [`validate_sow_liability`]'s refusal.
    pub grade: SowGrade,
}

/// The same backstops the §5.12 additions list carries — a backstop, not a
/// policy. A clause stating dozens of carve-outs is a liability regime
/// wearing a clause's clothes.
const LIABILITY_PROSE_MAX: usize = 300;
const LIABILITY_PROSE_ENTRIES_MAX: usize = 10;

fn check_liability_prose(v: &Value, name: &str) -> Result<()> {
    let Some(list) = v.as_array() else {
        return Err(invalid(format!(
            "{name} is a list of prose statements a court reads, even with one entry (§5.13)"
        )));
    };
    if list.is_empty() {
        return Err(invalid(format!(
            "an empty {name} list declares nothing, which OMITTING the member already means; two spellings of one state is how implementations come to disagree about which is which (§5.13)"
        )));
    }
    if list.len() > LIABILITY_PROSE_ENTRIES_MAX {
        return Err(invalid(format!(
            "a liability clause states at most {LIABILITY_PROSE_ENTRIES_MAX} {name} entries; a clause stating dozens is a liability regime wearing a clause's clothes (§5.13)"
        )));
    }
    for e in list {
        let ok = e
            .as_str()
            .is_some_and(|s| !s.trim().is_empty() && s.chars().count() <= LIABILITY_PROSE_MAX);
        if !ok {
            return Err(invalid(format!(
                "each {name} entry is a sentence a court reads, up to {LIABILITY_PROSE_MAX} characters, and not blank (§5.13)"
            )));
        }
    }
    Ok(())
}

/// Shape check for a liability clause (§5.13), per
/// `conformance/sow-terms.json`. Over the raw JSON, like
/// [`validate_sow_price`], so each `invalid` row in the fixture is refused
/// for exactly its stated reason.
pub fn validate_sow_liability(v: &Value) -> Result<()> {
    let Some(l) = v.as_object() else {
        return Err(invalid("a liability clause is an object carrying cap and grade (§5.13)"));
    };
    let Some(cap) = l.get("cap").and_then(|c| c.as_object()) else {
        return Err(invalid(
            "the cap is required, and it is an object: a liability clause exists to bound each party's exposure, and one that names no bound states nothing a court can read a number from (§5.13)",
        ));
    };
    let as_multiple = cap.contains_key("multiple_of_fees");
    let as_amount = cap.contains_key("amount") || cap.contains_key("currency");
    if as_multiple && as_amount {
        return Err(invalid(
            "the cap is stated in exactly ONE form — a multiple of fees, or an absolute amount with its currency, never both: two bounds in one cap is two clauses disagreeing about the number (§5.13)",
        ));
    }
    if !as_multiple && !as_amount {
        return Err(invalid(
            "the cap is stated in exactly ONE form — multiple_of_fees, or amount with currency; a cap naming neither bounds nothing (§5.13)",
        ));
    }
    if as_multiple {
        if as_pos_int(cap.get("multiple_of_fees")).is_none() {
            return Err(invalid(
                "multiple_of_fees is a positive whole number, applied to fees actually paid or payable; a zero multiple caps at nothing, and a fractional one invites two implementations to round differently (§5.13)",
            ));
        }
    } else {
        if as_pos_int(cap.get("amount")).is_none() {
            return Err(invalid(
                "cap.amount is a positive integer in the smallest unit of its currency — never a float, never zero (§5.13)",
            ));
        }
        if !cap.get("currency").and_then(Value::as_str).is_some_and(is_currency) {
            return Err(invalid("cap.currency is a three-letter uppercase code (§5.13)"));
        }
    }
    if let Some(carve_outs) = l.get("carve_outs") {
        check_liability_prose(carve_outs, "carve_outs")?;
    }
    if let Some(ind) = l.get("indemnification") {
        let Some(i) = ind.as_object() else {
            return Err(invalid("indemnification is an object carrying by_provider and/or by_client (§5.13)"));
        };
        if !i.contains_key("by_provider") && !i.contains_key("by_client") {
            return Err(invalid(
                "an indemnification member naming neither party's statements declares nothing, which OMITTING the member already means (§5.13)",
            ));
        }
        if let Some(p) = i.get("by_provider") {
            check_liability_prose(p, "indemnification.by_provider")?;
        }
        if let Some(c) = i.get("by_client") {
            check_liability_prose(c, "indemnification.by_client")?;
        }
    }
    if l.get("grade").and_then(|g| g.as_str()) != Some("recorded") {
        return Err(invalid(
            "a liability clause is graded 'recorded', and this is the clause the grade vocabulary exists for: no runtime enforces a liability cap, measures damages, or holds anyone harmless — courts do, reading the signed document. \
             Not 'enforced' — a conforming renderer MUST NOT present any part of this clause as enforced, and a runtime MUST NOT refuse or gate anything on it — and not 'evidence', because what the machinery provides is exactly the record of what was agreed, nothing more (§5.13, §4.2)",
        ));
    }
    Ok(())
}

/// The clause a document declares, unvalidated, or `None` where it declares
/// none. Same contract as [`disputes_of`].
///
/// ABSENCE STATES NOTHING (§5.13). A document without a liability clause
/// leaves the parties wherever the law leaves them, which for the provider
/// usually means unbounded. There is deliberately no default cap: silence is
/// not a number, and a party that wants a bound writes one — so `None` here
/// is `None`, never a synthesized clause.
pub fn liability_of(doc: &Value) -> Option<&Value> {
    doc.get("liability").filter(|l| l.is_object())
}

// ── §5.14: service floors ───────────────────────────────────────────────────

/// One floor (§5.14): a bound over facts BOTH parties' records already hold.
///
/// One kind in this revision — `each_task_within`, the span from a task's
/// request arriving to its terminal response, in the §5.12 duration grammar
/// ([`reporting_every_ms`] is the ONE duration reading in the system). The
/// vocabulary is closed and deliberately small, and it grows only where a
/// record exists to measure against: a floor written over something neither
/// party's records can check is not a floor, it is decoration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SowServiceFloor {
    /// 1-40 lowercase letters, digits and dashes — the qualification-id
    /// shape, and what a recorded miss names.
    pub id: String,
    pub each_task_within: String,
}

/// The stated consequence (§5.14): after `misses` floor misses inside
/// `within`, the client MAY terminate for cause (§5.9), citing the recorded
/// misses. MAY, deliberately — the machinery counts and records, and the
/// client decides. `remedy` comes from a closed set whose one member is
/// `terminate_for_cause`; the set grows only with the spec, because a remedy
/// invented here would promise an enforcement no runtime performs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SowServiceFloorsBreach {
    pub misses: u64,
    pub within: String,
    pub remedy: String,
}

/// The closed remedy set (§5.14) — one member, deliberately, and it grows
/// only with the spec.
pub const SOW_FLOOR_REMEDIES: [&str; 1] = ["terminate_for_cause"];

/// The service floors clause (§5.14). Shapes pinned by
/// `conformance/sow-terms.json`.
///
/// The reporting clause (§5.12) catches the agent that is silently stuck;
/// this one catches the agent that is honestly, measurably slow. A miss is a
/// RECORDED OBLIGATION FAILURE, not a money movement: a task that ran past
/// its floor is recorded on the engagement the way a failed deliverable-form
/// check is (§5.4), from timestamps, with no new machinery. A refused task
/// misses no floor — refusal is its own record; floors bind work the
/// provider took.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SowServiceFloors {
    pub floors: Vec<SowServiceFloor>,
    /// REQUIRED: a floor without a stated consequence is decoration.
    pub breach: SowServiceFloorsBreach,
    /// Always `Evidence` — see [`validate_sow_service_floors`]'s refusal.
    pub grade: SowGrade,
}

/// A backstop, not a policy — the qualifications ceiling, for the same
/// reason: a clause stating dozens of floors is an SLA wearing a clause's
/// clothes.
const SERVICE_FLOORS_MAX: usize = 10;

/// Shape check for a service floors clause (§5.14), per
/// `conformance/sow-terms.json`. Over the raw JSON, like
/// [`validate_sow_price`], so each `invalid` row in the fixture is refused
/// for exactly its stated reason.
pub fn validate_sow_service_floors(v: &Value) -> Result<()> {
    let Some(s) = v.as_object() else {
        return Err(invalid("a service floors clause is an object carrying floors, breach and grade (§5.14)"));
    };
    let floors = s.get("floors").and_then(|f| f.as_array());
    let Some(floors) = floors.filter(|f| !f.is_empty()) else {
        return Err(invalid(
            "floors is a non-empty list: a service floors clause that names no floor bounds nothing (§5.14)",
        ));
    };
    if floors.len() > SERVICE_FLOORS_MAX {
        return Err(invalid(format!(
            "a service floors clause states at most {SERVICE_FLOORS_MAX} floors; a clause stating dozens is an SLA wearing a clause's clothes (§5.14)"
        )));
    }
    let mut seen = std::collections::HashSet::new();
    for raw in floors {
        if !raw.is_object() {
            return Err(invalid("each floor is an object carrying id and each_task_within (§5.14)"));
        }
        let id = raw.get("id").and_then(Value::as_str).unwrap_or_default();
        if !is_qualification_id(id) {
            return Err(invalid(
                "a floor's id is 1-40 lowercase letters, digits and dashes — it is what a recorded miss names (§5.14)",
            ));
        }
        if !seen.insert(id) {
            return Err(invalid(format!(
                "two floors share the id \"{id}\", and a recorded miss has to name one of them (§5.14)"
            )));
        }
        let Some(bound) = raw.get("each_task_within").and_then(Value::as_str) else {
            return Err(invalid(
                "each_task_within is the span from a task's request arriving to its terminal response, in the §5.12 duration grammar (§5.14)",
            ));
        };
        // The §5.12 grammar, reused — ONE duration reading in the system. Its
        // own refusals ride along: a calendar month is refused by name here
        // exactly as it is on a reporting cadence.
        reporting_every_ms(bound)?;
    }
    let Some(b) = s.get("breach").and_then(|b| b.as_object()) else {
        return Err(invalid(
            "breach — misses, within, remedy — is required: a floor without a stated consequence is decoration (§5.14)",
        ));
    };
    if as_pos_int(b.get("misses")).is_none() {
        return Err(invalid("breach.misses is a positive whole number of floor misses (§5.14)"));
    }
    let Some(within) = b.get("within").and_then(Value::as_str) else {
        return Err(invalid(
            "breach.within is the window the misses are counted inside, in the §5.12 duration grammar (§5.14)",
        ));
    };
    reporting_every_ms(within)?;
    if b.get("remedy").and_then(Value::as_str) != Some("terminate_for_cause") {
        return Err(invalid(
            "the remedy vocabulary is closed, and in this revision it has one member: 'terminate_for_cause' — §5.9's existing machinery carrying a stated cause. It grows only with the spec; a remedy invented here would promise an enforcement no runtime performs (§5.14)",
        ));
    }
    if s.get("grade").and_then(|g| g.as_str()) != Some("evidence") {
        return Err(invalid(
            "a service floors clause is graded 'evidence', flatly: the timestamps are in the records, the misses are recorded, and the termination-for-cause path is §5.9's existing machinery carrying a stated cause. \
             Not 'enforced' — nothing here pauses a slow task or makes a fast one, and a conforming renderer presents floors as agreed bounds with a record, never as a guarantee — and not 'recorded', because detecting the task that ran past its floor is a mechanical MUST, which is more than a record of the clause (§5.14, §4.2)",
        ));
    }
    Ok(())
}

/// The clause a document declares, unvalidated, or `None` where it declares
/// none. Same contract as [`liability_of`].
///
/// ABSENCE STATES NOTHING (§5.14): no floors were agreed, and no speed is
/// implied either way — `None` here is `None`, never a default bound.
pub fn service_floors_of(doc: &Value) -> Option<&Value> {
    doc.get("service_floors").filter(|s| s.is_object())
}

// ── §5.15: subcontracting ───────────────────────────────────────────────────

/// The closed posture vocabulary (§5.15). Exactly one per clause:
///
///  - `None`: the provider performs the work itself. On a mesh where
///    delegation forms engagements, this is not merely a promise: the
///    platform holds the engagement records, so on-mesh delegation under a
///    `none` posture is discoverable evidence, not an argument.
///  - `Disclosed`: delegation is permitted, and every subcontractor is named
///    in `subcontractors` before its work begins, each entry carrying who
///    and the narrowest true statement of what is delegated.
///  - `Approved`: as `disclosed`, and each subcontractor additionally
///    requires the client's countersigned approval before its work begins,
///    riding the same two-seat machinery amendments use.
///
/// Whatever the posture, the first principle is the one everything else
/// hangs from: THE BUYER'S CONTRACT IS WITH THE PRIME, FULL STOP. Delegation
/// never dilutes accountability — a subcontractor's failure surfaces to the
/// client as the provider's failure with its cause named, every remedy runs
/// against the provider, and a subcontractor answers to the provider, who is
/// its client in a separate engagement under this same specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SowSubcontractingPosture {
    None,
    Disclosed,
    Approved,
}

impl SowSubcontractingPosture {
    pub fn as_str(&self) -> &'static str {
        match self {
            SowSubcontractingPosture::None => "none",
            SowSubcontractingPosture::Disclosed => "disclosed",
            SowSubcontractingPosture::Approved => "approved",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "none" => Some(SowSubcontractingPosture::None),
            "disclosed" => Some(SowSubcontractingPosture::Disclosed),
            "approved" => Some(SowSubcontractingPosture::Approved),
            _ => None,
        }
    }
}

/// The closed set.
pub const SOW_SUBCONTRACTING_POSTURES: [&str; 3] = ["none", "disclosed", "approved"];

/// One named delegate (§5.15): a mesh agent by key or handle, or a published
/// role a conforming agent holds — at least one of the three — plus `scope`,
/// the narrowest true statement of what is delegated.
///
/// **An entry names a party on the mesh, and the vocabulary offers no other
/// kind.** There is deliberately no free-text field for an off-mesh
/// organisation, for the same reason the qualification vocabulary (§12.1)
/// has no probe kind a runtime cannot check: a vocabulary must not express
/// what nothing can verify, and a disclosure nobody can look up, vouch,
/// rate, or hold to account is decoration wearing disclosure's clothes.
/// Under any stated posture, delegating work to a party this clause cannot
/// name is undisclosed subcontracting, which is breach. The parties remain
/// free to arrange anything they like outside this clause and outside this
/// machinery; what the vocabulary refuses to do is bless it.
///
/// A subcontractor does WORK; a processor supplies a CAPABILITY. A party
/// that produces part of the deliverable or exercises judgment over the work
/// belongs here; a metered service under the provider's own direction (the
/// model API behind the agent) belongs in §5.11's processor list, where
/// off-mesh services are permitted because they are the provider's tools,
/// not its delegates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SowSubcontractorEntry {
    /// The delegate's agent public key. Shape only: whether the key is real
    /// is the platform's problem.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    /// The delegate's mesh handle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    /// A published role contract a conforming agent holds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// REQUIRED: the narrowest true statement of what is delegated.
    pub scope: String,
    /// The §4.1 identifier of the countersigned engagement this delegation
    /// runs under: the pin. Optional, because §5.15 also serves plain
    /// disclosure; a runtime that requires pins says so itself
    /// ([`SubcontractOpts::require_pins`]) rather than the document carrying
    /// a flag about it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engagement: Option<String>,
}

/// The subcontracting clause (§5.15). Shapes pinned by
/// `conformance/sow-subcontracting.json`.
///
/// Graded `Evidence`, flatly: the named chain and the on-mesh engagement
/// records are checkable and exportable, while the claim that nothing was
/// delegated off-mesh is `recorded` like every statement about conduct
/// beyond the mesh's sight — breach is its consequence, not detection its
/// guarantee.
///
/// The chain composes by the same rules, all the way down: disclosure
/// flattens upward, and terms only narrow going down — the deterministic
/// comparison [`subcontract_conformance`] computes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SowSubcontracting {
    pub posture: SowSubcontractingPosture,
    /// REFUSED when `posture` is `none` — a none clause naming delegates
    /// contradicts itself. Optional under the other postures: a disclosing
    /// clause with nobody named yet omits the member.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subcontractors: Option<Vec<SowSubcontractorEntry>>,
    pub grade: SowGrade,
}

/// Backstops, not policy — the same ceilings this file's other name-shaped
/// strings get.
const SUBCONTRACTORS_MAX: usize = 16;
const SUBCONTRACTOR_AGENT_MAX: usize = 64;
const SUBCONTRACTOR_HANDLE_MAX: usize = 120;
const SUBCONTRACTOR_ROLE_MAX: usize = 64;
const SUBCONTRACTOR_SCOPE_MAX: usize = 300;
const SUBCONTRACTOR_ENGAGEMENT_MAX: usize = 128;

/// Shape check for a subcontracting clause (§5.15), per
/// `conformance/sow-subcontracting.json`. Over the raw JSON, like
/// [`validate_sow_reporting`], so each `invalid` row in the fixture is
/// refused for exactly its stated reason.
pub fn validate_sow_subcontracting(v: &Value) -> Result<()> {
    let Some(s) = v.as_object() else {
        return Err(invalid("a subcontracting clause is an object carrying posture and grade (§5.15)"));
    };
    let posture = s
        .get("posture")
        .and_then(|p| p.as_str())
        .and_then(SowSubcontractingPosture::from_str);
    let Some(posture) = posture else {
        return Err(invalid(
            "a subcontracting clause's posture is 'none', 'disclosed' or 'approved' — exactly one, from a closed set (§5.15)",
        ));
    };
    if s.get("grade").and_then(|g| g.as_str()) != Some("evidence") {
        return Err(invalid(
            "a subcontracting clause is graded 'evidence', flatly: the named chain and the on-mesh engagement records are checkable and exportable. \
             Not 'enforced' — the claim that nothing was delegated off-mesh is beyond the mesh's sight, with breach as its consequence rather than detection as its guarantee — and not 'recorded', because on this mesh delegation forms engagements the platform holds, which is more than a record of the clause (§5.15, §4.2)",
        ));
    }
    let Some(subcontractors) = s.get("subcontractors") else {
        return Ok(());
    };
    if posture == SowSubcontractingPosture::None {
        return Err(invalid(
            "only a disclosing posture names delegates: a 'none' clause naming subcontractors is two clauses disagreeing about whether the provider delegates at all (§5.15)",
        ));
    }
    let Some(list) = subcontractors.as_array() else {
        return Err(invalid("subcontractors is a list of the named delegates, even with one entry (§5.15)"));
    };
    if list.is_empty() {
        return Err(invalid(
            "an empty subcontractors list declares nothing, which OMITTING the member already means — a disclosing clause with nobody named yet omits it; two spellings of one state is how implementations come to disagree about which is which (§5.15)",
        ));
    }
    if list.len() > SUBCONTRACTORS_MAX {
        return Err(invalid(format!(
            "a subcontracting clause names at most {SUBCONTRACTORS_MAX} subcontractors; a clause naming dozens is an org chart wearing a clause's clothes (§5.15)"
        )));
    }
    let mut seen_agents = std::collections::HashSet::new();
    let mut seen_handles = std::collections::HashSet::new();
    for raw in list {
        let Some(e) = raw.as_object() else {
            return Err(invalid(
                "each subcontractor entry is an object carrying who — agent, handle or role — and the scope delegated (§5.15)",
            ));
        };
        let named = |key: &str, max: usize| -> Option<bool> {
            // None: absent. Some(true): present and well-shaped.
            // Some(false): present and malformed.
            e.get(key).map(|v| {
                v.as_str()
                    .is_some_and(|s| !s.trim().is_empty() && s.chars().count() <= max)
            })
        };
        let agent = named("agent", SUBCONTRACTOR_AGENT_MAX);
        if agent == Some(false) {
            return Err(invalid(format!(
                "a subcontractor's agent is the delegate's public key as a non-empty string up to {SUBCONTRACTOR_AGENT_MAX} characters — shape only: whether the key is real is the platform's problem (§5.15)"
            )));
        }
        let handle = named("handle", SUBCONTRACTOR_HANDLE_MAX);
        if handle == Some(false) {
            return Err(invalid(format!(
                "a subcontractor's handle names the delegate's mesh handle, up to {SUBCONTRACTOR_HANDLE_MAX} characters, and not blank (§5.15)"
            )));
        }
        let role = named("role", SUBCONTRACTOR_ROLE_MAX);
        if role == Some(false) {
            return Err(invalid(format!(
                "a subcontractor's role names the published role contract the delegate holds, up to {SUBCONTRACTOR_ROLE_MAX} characters, and not blank (§5.15)"
            )));
        }
        if agent.is_none() && handle.is_none() && role.is_none() {
            return Err(invalid(
                "a subcontractor entry names a party on the mesh — an agent by key or handle, or a published role a conforming agent holds — and this one names nobody; a disclosure nobody can look up, vouch, rate, or hold to account is decoration wearing disclosure's clothes (§5.15, §12.1)",
            ));
        }
        let scope_ok = e.get("scope").and_then(|v| v.as_str()).is_some_and(|s| {
            !s.trim().is_empty() && s.chars().count() <= SUBCONTRACTOR_SCOPE_MAX
        });
        if !scope_ok {
            return Err(invalid(format!(
                "a subcontractor's scope is the narrowest true statement of what is delegated, up to {SUBCONTRACTOR_SCOPE_MAX} characters, and not blank — an entry that names who without what has disclosed nothing (§5.15)"
            )));
        }
        if named("engagement", SUBCONTRACTOR_ENGAGEMENT_MAX) == Some(false) {
            return Err(invalid(format!(
                "a subcontractor's engagement is the §4.1 identifier of the countersigned engagement this delegation runs under, up to {SUBCONTRACTOR_ENGAGEMENT_MAX} characters, and not blank — the pin is what stops a delegate's terms moving under the party that promised them (§5.15)"
            )));
        }
        if let Some(a) = e.get("agent").and_then(|v| v.as_str()) {
            if !seen_agents.insert(a.to_string()) {
                return Err(invalid(
                    "two subcontractor entries name the same agent; a reader cannot tell whether the second is a mistake or a second delegation — state the whole delegated scope on one entry (§5.15)",
                ));
            }
        }
        if let Some(h) = e.get("handle").and_then(|v| v.as_str()) {
            if !seen_handles.insert(h.to_string()) {
                return Err(invalid(
                    "two subcontractor entries name the same handle; a reader cannot tell whether the second is a mistake or a second delegation — state the whole delegated scope on one entry (§5.15)",
                ));
            }
        }
    }
    Ok(())
}

/// The clause a document declares, unvalidated, or `None` where it declares
/// none. Same contract as [`disputes_of`], and the same discipline about
/// silence: ABSENCE STATES NOTHING (§5.15). A document without this clause
/// has said nothing about delegation either way, and a reader MUST NOT infer
/// a posture.
pub fn subcontracting_of(doc: &Value) -> Option<&Value> {
    doc.get("subcontracting").filter(|s| s.is_object())
}

// The structural reads the flow-down comparison rests on. DECLARED structure
// only: whether a clause validates is the validators' question, answered at
// document validation, not smuggled into a comparison that was asked
// something else — a member that does not read structurally is a member the
// document has not stated.
fn confidentiality_clause_of(doc: &Value) -> Option<&serde_json::Map<String, Value>> {
    doc.get("confidentiality").and_then(|c| c.as_object())
}

fn stated_promises(clause: Option<&serde_json::Map<String, Value>>) -> Vec<&'static str> {
    let Some(p) = clause.and_then(|c| c.get("promises")).and_then(|p| p.as_object()) else {
        return Vec::new();
    };
    SOW_CONFIDENTIALITY_PROMISES
        .into_iter()
        .filter(|name| p.get(*name).and_then(|v| v.as_bool()) == Some(true))
        .collect()
}

fn stated_retention_days(clause: Option<&serde_json::Map<String, Value>>) -> Option<u64> {
    as_pos_int(clause.and_then(|c| c.get("retention")).and_then(|r| r.get("max_days")))
}

fn stated_jurisdictions(clause: Option<&serde_json::Map<String, Value>>) -> Option<Vec<&str>> {
    let list = clause.and_then(|c| c.get("processed_in")).and_then(|j| j.as_array())?;
    let mut out = Vec::with_capacity(list.len());
    for v in list {
        let s = v.as_str()?;
        if s.trim().is_empty() {
            return None;
        }
        out.push(s);
    }
    Some(out)
}

fn stated_reporting_level(doc: &Value) -> Option<SowReportingLevel> {
    doc.get("reporting")
        .and_then(|r| r.as_object())
        .and_then(|r| r.get("level"))
        .and_then(|l| l.as_str())
        .and_then(SowReportingLevel::from_str)
}

fn stated_time_and_materials_cap(doc: &Value) -> Option<u64> {
    let price = doc.get("price").and_then(|p| p.as_object())?;
    if price.get("arrangement").and_then(|a| a.as_str()) != Some("time_and_materials") {
        return None;
    }
    as_pos_int(price.get("cap").and_then(|c| c.get("amount")))
}

/// §5.15's chain rule as the computation it claims to be: does `sub_doc`
/// (the delegate's engagement with the provider) narrow every checkable term
/// of `prime_doc` (the provider's engagement with its own client)? EMPTY
/// where it does — including terms met exactly, because narrowing includes
/// staying put — else one pinned sentence per violation, in a pinned order.
///
/// Each term is checked ONLY where the prime states it: a prime that says
/// nothing constrains nothing. What "states" means is structural — the
/// member reads as its declared shape — because whether a clause validates
/// is the validators' question at document validation, and a comparison that
/// silently re-validated would answer a question nobody asked it. The v1
/// checks, in the order violations are reported:
///
///  (a) confidentiality promises: every promise the prime's clause makes
///      must be made by the sub's — a sub that may train on content the
///      prime promised never trains on breaks the chain. Compared in the
///      closed vocabulary's declared order.
///  (b) retention: the sub's ceiling is stated and no longer than the
///      prime's; a sub silent while the prime states is a violation, because
///      an unstated ceiling narrows nothing.
///  (c) jurisdiction: the sub's `processed_in` is stated and a subset of the
///      prime's; silent-while-stated violates for the same reason, and each
///      jurisdiction outside the prime's set is its own sentence, in the
///      sub's declared order.
///  (d) reporting: the sub's level meets or exceeds the prime's. Silence
///      here is §5.12's honest default — records_only — so it violates
///      exactly where that floor does not meet the prime's level: the link
///      above cannot meet its own reporting over a silent delegate.
///  (e) the cap: where the caller supplies `prime_cap_remaining` (only the
///      platform holding the money knows it) and the sub is time and
///      materials, the sub's cap fits inside the remainder.
///
/// The sentences are pinned by `conformance/sow-subcontracting.json`,
/// byte-identical across SDKs: a provider refused a subcontract reads one
/// message whichever runtime computed the chain. A runtime MAY use a
/// violation to refuse forming a subcontract that could put the provider in
/// breach of the engagement above it; nothing in this function refuses
/// anything itself.
pub fn subcontract_conformance(
    prime_doc: &Value,
    sub_doc: &Value,
    prime_cap_remaining: Option<u64>,
) -> Vec<String> {
    subcontract_conformance_with(
        prime_doc,
        sub_doc,
        &SubcontractOpts { prime_cap_remaining, require_pins: false },
    )
}

/// What the caller brings to the flow-down comparison.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SubcontractOpts {
    /// What is left of the prime's cap; only the platform holding the money
    /// knows it, so absent means no cap check.
    pub prime_cap_remaining: Option<u64>,
    /// Every named delegate must be PINNED to a countersigned engagement,
    /// and each that is not is violation (f).
    ///
    /// OFF BY DEFAULT, and the default is the decision. §5.15 also serves
    /// plain disclosure: naming who you delegate to, with no engagement of
    /// your own to point at, is a true statement and not a breach. What
    /// requires pins is a particular kind of offer, a solution, where one
    /// organisation promises terms for parts it does not own and can only
    /// keep that promise for parts it has already contracted. That is the
    /// publishing runtime's policy, so the runtime says it here.
    pub require_pins: bool,
}

/// [`subcontract_conformance`] with every option, the pin check included.
pub fn subcontract_conformance_with(prime_doc: &Value, sub_doc: &Value, opts: &SubcontractOpts) -> Vec<String> {
    let prime_cap_remaining = opts.prime_cap_remaining;
    let mut violations = Vec::new();

    // (f) The pin, when the caller requires one. Reported FIRST because it is
    // the finding that invalidates the others: every check below compares the
    // prime against a sub document, and without a pin nothing says that this
    // document is the one the delegation actually runs under.
    if opts.require_pins {
        let entries = subcontracting_of(prime_doc)
            .and_then(|c| c.get("subcontractors"))
            .and_then(|s| s.as_array());
        for e in entries.into_iter().flatten() {
            let pinned = e.get("engagement").and_then(|v| v.as_str()).is_some_and(|s| !s.trim().is_empty());
            if pinned {
                continue;
            }
            let who = ["handle", "agent", "role"]
                .iter()
                .find_map(|k| e.get(*k).and_then(|v| v.as_str()))
                .unwrap_or("a delegate");
            violations.push(format!(
                "{who} is named as a delegate with no engagement pinned to it; terms that are not pinned can change after this is signed, and a party cannot promise terms it does not hold (§5.15)"
            ));
        }
    }
    let prime_conf = confidentiality_clause_of(prime_doc);
    let sub_conf = confidentiality_clause_of(sub_doc);

    // (a) The promises the prime made, in the closed vocabulary's order.
    let sub_makes = stated_promises(sub_conf);
    for name in stated_promises(prime_conf) {
        if !sub_makes.contains(&name) {
            violations.push(format!(
                "the prime promises {name} and this subcontract does not; a delegate may not be freer with the content than the party that took it (§5.15)"
            ));
        }
    }

    // (b) Retention: a ceiling, and silence narrows nothing.
    if let Some(prime_days) = stated_retention_days(prime_conf) {
        match stated_retention_days(sub_conf) {
            None => violations.push(format!(
                "the prime caps retention at {prime_days} days and this subcontract states no retention ceiling; an unstated ceiling narrows nothing, and terms only narrow going down (§5.15)"
            )),
            Some(sub_days) if sub_days > prime_days => violations.push(format!(
                "the prime caps retention at {prime_days} days and this subcontract keeps content up to {sub_days} days; a delegate may retain no longer than the party that took the content (§5.15)"
            )),
            Some(_) => {}
        }
    }

    // (c) Jurisdiction: a set, and the test is subset.
    if let Some(prime_in) = stated_jurisdictions(prime_conf) {
        let list = prime_in.join(", ");
        match stated_jurisdictions(sub_conf) {
            None => violations.push(format!(
                "the prime confines processing to {list} and this subcontract states no jurisdictions; an unstated jurisdiction may be any jurisdiction, and terms only narrow going down (§5.15)"
            )),
            Some(sub_in) => {
                for j in sub_in {
                    if !prime_in.contains(&j) {
                        violations.push(format!(
                            "the prime confines processing to {list} and this subcontract processes in {j}; a delegate may touch no jurisdiction the party above it did not (§5.15)"
                        ));
                    }
                }
            }
        }
    }

    // (d) Reporting: ordinal, silence is the §5.12 floor, and the test is
    // meets or exceeds.
    if let Some(prime_level) = stated_reporting_level(prime_doc) {
        match stated_reporting_level(sub_doc) {
            None => {
                if !meets_reporting_level(DEFAULT_REPORTING_LEVEL, prime_level) {
                    violations.push(format!(
                        "the prime owes {} reporting and this subcontract declares none, which offers records_only; a delegate's reporting must be sufficient for the link above to meet its own (§5.15)",
                        prime_level.as_str()
                    ));
                }
            }
            Some(sub_level) => {
                if !meets_reporting_level(sub_level, prime_level) {
                    violations.push(format!(
                        "the prime owes {} reporting and this subcontract offers {}; a delegate's reporting must be sufficient for the link above to meet its own (§5.15)",
                        prime_level.as_str(),
                        sub_level.as_str()
                    ));
                }
            }
        }
    }

    // (e) The cap, where the caller knows the remainder.
    if let Some(remaining) = prime_cap_remaining {
        if let Some(sub_cap) = stated_time_and_materials_cap(sub_doc) {
            if sub_cap > remaining {
                violations.push(format!(
                    "the subcontract's cap of {sub_cap} is larger than what remains of the cap above it ({remaining}); at every link the cap fits inside the remainder of the cap above (§5.15)"
                ));
            }
        }
    }

    violations
}

// ── §7.1: document states, including `exhausted` ────────────────────────────

/// The document states of §7.1, by signature count and time.
///
/// `exhausted` is not a failure. `lapsed` means the term ran out; `exhausted`
/// means the cap ran out (§5.5.5). A runtime MUST NOT record an exhausted
/// engagement as failed, and MUST treat lapse, exhaustion and termination
/// identically at the gate: the counterparty reverts to general admission
/// policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SowDocumentState {
    Template,
    StandingProposal,
    Agreed,
    Active,
    AmendmentProposed,
    Amended,
    Exhausted,
    Lapsed,
    Terminated,
}

impl SowDocumentState {
    pub fn as_str(&self) -> &'static str {
        match self {
            SowDocumentState::Template => "template",
            SowDocumentState::StandingProposal => "standing_proposal",
            SowDocumentState::Agreed => "agreed",
            SowDocumentState::Active => "active",
            SowDocumentState::AmendmentProposed => "amendment_proposed",
            SowDocumentState::Amended => "amended",
            SowDocumentState::Exhausted => "exhausted",
            SowDocumentState::Lapsed => "lapsed",
            SowDocumentState::Terminated => "terminated",
        }
    }

    /// §7.1 — lapse, exhaustion and termination are the same answer at
    /// admission: no. Nothing breaks and nothing lingers.
    pub fn admits_work(&self) -> bool {
        matches!(self, SowDocumentState::Active)
    }

    pub fn is_end_state(&self) -> bool {
        SOW_END_STATES.contains(&self.as_str())
    }

    /// §5.5.5 — an engagement that ends `exhausted` is recorded as a fact and
    /// is not scored, the same way terminations are recorded unscored.
    pub fn is_scored_outcome(&self) -> bool {
        !matches!(self, SowDocumentState::Exhausted | SowDocumentState::Terminated)
    }
}

/// The three ways an engagement ends (§7.1). Identical at the gate.
pub const SOW_END_STATES: [&str; 3] = ["exhausted", "lapsed", "terminated"];

// ── §5.1 + §6.2: parties and organizational authority ───────────────────────

/// A seat in the engagement (§5.1). `organization` is the §6.2 addition: the
/// organization on whose behalf this seat engages. Optional and additive — a
/// document that omits it is conformant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SowParty {
    pub agent: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    pub owner: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
}

pub fn validate_sow_party(v: &Value) -> Result<()> {
    if !v.is_object() {
        return Err(invalid("a party is an object"));
    }
    if !v.get("agent").and_then(Value::as_str).is_some_and(|a| !a.is_empty()) {
        return Err(invalid("a party names its agent's public key"));
    }
    if !v.get("owner").and_then(Value::as_str).is_some_and(|o| !o.is_empty()) {
        return Err(invalid("a party names its owner"));
    }
    if v.get("handle").is_some_and(|h| !h.is_string()) {
        return Err(invalid("handle is a string"));
    }
    if let Some(org) = v.get("organization") {
        if !org.as_str().is_some_and(|o| is_mandate_ref(o, "org_")) {
            return Err(invalid("organization is an Agent Mandate org reference, 'org_...' (§6.2)"));
        }
    }
    Ok(())
}

// ── §12.1.1: the standing proposal that names its counterparty ──────────────

/// The one party a standing proposal is offered to (§12.1.1).
///
/// A proposal carrying this clause is a DIRECTED standing proposal: an offer to
/// that party, not to the market. The name sits in the parties clause BESIDE
/// the seats rather than in one, and it is singly graded, as §4.2 requires of a
/// clause that splits across grades from the seats it sits next to.
///
/// It is INSIDE THE SIGNED BYTES, because the signed bytes are the canonical
/// document less `signatures` (§6). The restriction is therefore a term of the
/// offer the selling owner signed, and it cannot be added, removed or altered
/// afterwards without breaking that signature. A platform that wants the
/// restriction MUST put it in the bytes before the provider signs; one that
/// lays it over a document that does not carry it has produced a document whose
/// signature does not verify.
///
/// Naming a counterparty does not fill the client seat. The seat stays blank,
/// `starts_at` stays null, and formation remains the two-step gate of §12.1: a
/// countersign is a REQUEST to form, and the provider's runtime completes
/// formation with a fresh signature over the completed bytes.
///
/// `expires_at` is the lapse §12.1.1 requires. A directed offer does not
/// outlive its occasion, and one bounded by neither an expiry nor a named
/// occasion is a validation error — an offer to one party with no end is an
/// open account of a different kind, held for months and countersigned at a
/// price set for a market that has moved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SowOfferedTo {
    pub agent: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    pub owner: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    /// The instant the offer lapses (§12.1.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// §4.2: `enforced` only where one platform both puts this clause inside
    /// the bytes it signs AND checks the countersigning party at formation.
    /// Both ends, or the restriction is evidence a dispute is read from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grade: Option<SowGrade>,
}

/// The §12.1.1 clause: exactly one party, optionally bounded.
///
/// A LIST is the shape refused loudest. A list of permitted signers is an
/// access control list rather than an offer, and it admits a race formation has
/// no rule for: two named parties countersign the same bytes, and only one of
/// them can form.
pub fn validate_sow_offered_to(v: &Value) -> Result<()> {
    if let Some(list) = v.as_array() {
        return Err(invalid(if list.len() == 1 {
            "offered_to names its one party directly, not as a list of one (§12.1.1)"
        } else {
            "offered_to names exactly one party — a list of permitted signers is an access control list rather than an offer, and two named parties countersigning the same bytes is a race formation has no rule for (§12.1.1)"
        }));
    }
    validate_sow_party(v)?;
    if let Some(expires) = v.get("expires_at") {
        if !expires.as_str().is_some_and(is_rfc3339_instant) {
            return Err(invalid("offered_to.expires_at must be an RFC-3339 instant (§12.1.1)"));
        }
    }
    if let Some(grade) = v.get("grade") {
        if !grade.as_str().is_some_and(|g| SOW_GRADES.contains(&g)) {
            return Err(invalid(
                "offered_to carries its own grade: 'enforced', 'evidence' or 'recorded' (§4.2)",
            ));
        }
    }
    Ok(())
}

/// The offered_to clause of a document, unvalidated, or None where the document
/// offers to the market.
fn offered_to_clause(doc: &Value) -> Option<&Value> {
    match doc.get("parties").and_then(|p| p.get("offered_to")) {
        Some(Value::Null) | None => None,
        Some(v) => Some(v),
    }
}

/// §12.1.1: does this document name its counterparty?
///
/// The listing surfaces are the caller. A catalog, marketplace, directory or
/// board MUST NOT derive a public listing from a directed standing proposal and
/// MUST NOT contribute its scope examples to a public index — §12.2 makes those
/// examples the listing's representative queries, and a document only one party
/// may form has no business answering the market's searches.
///
/// Directedness is a FACT ABOUT THE OFFER, not a qualification about a
/// counterparty, exactly so that a surface deciding whether it may list a
/// document can read it without interpreting prose.
pub fn is_directed_proposal(doc: &Value) -> bool {
    offered_to_clause(doc).is_some()
}

/// The §12.1.1 formation gate: may this party form under this document, now?
///
/// Returns None where nothing in the document stands in the way, and a refusal
/// naming the restriction otherwise — the counterparty acted on a document it
/// was handed and deserves a reason, not a shrug.
///
/// Four things end a directed offer, and this reads the two that live in the
/// bytes: the expiry it states, and the party it names. Withdrawal is the
/// provider's act and being spent by the formation it completes is the
/// runtime's own record; neither is readable from a document alone.
///
/// A directed offer whose expiry this reader cannot find is REFUSED rather than
/// read as unbounded. §12.1.1 allows the lapse to be a named occasion defined
/// outside the specification, and says in the same breath that a runtime which
/// does not understand the occasion a document names MUST refuse formation.
/// This reader understands no occasion vocabulary, so an offer stating no
/// `expires_at` is exactly that case.
pub fn directed_offer_refusal(doc: &Value, client_agent: &str, now_ms: i64) -> Option<String> {
    let raw = offered_to_clause(doc)?;
    if let Err(err) = validate_sow_offered_to(raw) {
        return Some(format!(
            "this document names a counterparty in a shape that cannot be read, so who may form under it cannot be established: {err}"
        ));
    }
    let Some(expires_at) = raw.get("expires_at").and_then(Value::as_str) else {
        return Some(
            "this offer names one counterparty and states no expiry, so nothing in it says when it ends; a runtime that cannot tell when a directed offer lapses refuses formation rather than reading the offer as unbounded (§12.1.1)".to_string(),
        );
    };
    let lapses_ms = chrono::DateTime::parse_from_rfc3339(expires_at)
        .map(|t| t.timestamp_millis())
        .unwrap_or(i64::MIN);
    if now_ms >= lapses_ms {
        return Some(format!(
            "this offer was made to one named party and lapsed at {expires_at}; a lapsed offer stays readable, but nothing forms under it (§12.1.1)"
        ));
    }
    // The match is on the agent key. `handle` and `owner` are labels for
    // people, and a handle pointed at a new key names a different party (§5.1).
    let agent = raw.get("agent").and_then(Value::as_str).unwrap_or_default();
    if client_agent != agent {
        let named = raw
            .get("handle")
            .and_then(Value::as_str)
            .or_else(|| raw.get("owner").and_then(Value::as_str))
            .unwrap_or_default();
        return Some(format!(
            "this offer names {named} as the one party entitled to countersign it, and the client seat names a different agent key — only the named party may form under a directed standing proposal (§12.1.1)"
        ));
    }
    None
}

// ── §12.1: qualifications, the conditions a counterparty must meet ──────────

/// What a qualification tests, and therefore whether any runtime can test it.
///
/// §12.1 rule 1 admits three families: a passed validation probe (§13), account
/// standing, and capability requirements. This vocabulary is the part of that a
/// runtime can actually establish about a counterparty, plus the honest name for
/// everything else.
///
/// - `mesh_registration` — the countersigning agent has a current registration
///   in the mesh registry the checking runtime reads. A fact the runtime holds.
/// - `publishes_offering` — that registration publishes the named offering.
///   §12.1's capability requirement, and the one a seller reaches for when the
///   work only makes sense against a counterparty that can do something back.
/// - `platform_account` — the countersigning agent is attached to an account on
///   the platform completing formation. The weakest true reading of §12.1's
///   "account standing", and deliberately named for what it checks rather than
///   for what "standing" might be taken to imply: it says an account exists, and
///   it says nothing about that account's conduct, funding, or screening.
/// - `asserted` — a statement the counterparty makes about itself that no
///   runtime here can check. A current third-party licence is the case this
///   exists for.
///
/// There is deliberately NO probe kind. §13's qualification is checkable
/// because the probe left a signed outcome, and a runtime that holds no probe
/// records would either invent one or publish a condition nothing can ever
/// satisfy. §13 forbids the first and §12.1 rule 2 makes the second a published
/// offer that refuses every counterparty. A deployment that records probes adds
/// the kind with the records.
pub const SOW_QUALIFICATION_KINDS: [&str; 4] = [
    "mesh_registration",
    "publishes_offering",
    "platform_account",
    "asserted",
];

/// The kinds a runtime tests against a fact it holds, as opposed to the one it
/// can only hold a signed statement about.
///
/// The split IS the enforcement gradient (§3) applied to this clause, and it is
/// why the vocabulary is closed rather than free text. A condition written as
/// prose can be graded anything a seller likes; a condition written as a kind
/// is graded by what the kind can be tested against.
pub const CHECKABLE_QUALIFICATION_KINDS: [&str; 3] = [
    "mesh_registration",
    "publishes_offering",
    "platform_account",
];

/// The highest grade a kind can honestly carry (§3 rule 1).
///
/// A checkable kind reaches `enforced` in a deployment that actually performs
/// the refusal, which for a standing proposal is the deployment that both
/// publishes the document and completes formation under it. `asserted` tops out
/// at `evidence` and §12.1 rule 4 says so in as many words: the record is
/// evidence that the party asserted the thing, not proof that the thing is
/// true. A seller who grades a licence condition `enforced` has made the false
/// enforcement claim the whole gradient exists to prevent, so the validator
/// below refuses it rather than trusting the seller's own reading.
pub fn qualification_grade_ceiling(kind: &str) -> SowGrade {
    if CHECKABLE_QUALIFICATION_KINDS.contains(&kind) {
        SowGrade::Enforced
    } else {
        SowGrade::Evidence
    }
}

/// One condition a counterparty must meet for its countersign to be accepted
/// (§12.1 rule 1).
///
/// Qualifications live in the SIGNED DOCUMENT, where a prospective client reads
/// them before spending anything. That is not decoration: a condition a buyer
/// cannot see before committing is a trap, and a condition outside the signed
/// bytes is one the seller can change after the buyer has read it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SowQualification {
    /// Stable within the document, and what a refusal names.
    pub id: String,
    pub kind: String,
    /// The sentence a person reads. Required on every kind, including the
    /// checkable ones, because the buyer is owed the condition in words rather
    /// than a vocabulary term.
    pub statement: String,
    /// §4.2: each qualification is singly graded, because this clause splits
    /// across grades by construction.
    pub grade: SowGrade,
    /// `publishes_offering` only: the offering the counterparty must publish.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offering: Option<String>,
}

const QUALIFICATION_STATEMENT_MAX: usize = 300;
/// A backstop, not a policy. A document stating dozens of conditions is an
/// admission process wearing an offer's clothes.
const QUALIFICATIONS_MAX: usize = 10;

fn is_qualification_id(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 40 {
        return false;
    }
    if !(b[0].is_ascii_lowercase() || b[0].is_ascii_digit()) {
        return false;
    }
    b.iter()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

pub fn validate_sow_qualification(v: &Value) -> Result<()> {
    if !v.is_object() {
        return Err(invalid("a qualification is an object (§12.1)"));
    }
    let id = v.get("id").and_then(Value::as_str).unwrap_or_default();
    if !is_qualification_id(id) {
        return Err(invalid(
            "a qualification needs an id of 1-40 lowercase letters, digits and dashes — it is what a refusal names (§12.1)",
        ));
    }
    let kind = v.get("kind").and_then(Value::as_str).unwrap_or_default();
    if !SOW_QUALIFICATION_KINDS.contains(&kind) {
        let mut kinds = SOW_QUALIFICATION_KINDS.to_vec();
        kinds.sort_unstable();
        return Err(invalid(format!(
            "a qualification's kind is one of {}. A condition written as prose can be graded anything a seller likes; a condition written as a kind is graded by what the kind can be tested against (§12.1)",
            kinds.join(", ")
        )));
    }
    let statement = v.get("statement").and_then(Value::as_str).unwrap_or_default();
    if statement.trim().is_empty() || statement.chars().count() > QUALIFICATION_STATEMENT_MAX {
        return Err(invalid(format!(
            "a qualification states its condition in words a person reads, up to {QUALIFICATION_STATEMENT_MAX} characters (§12.1)"
        )));
    }
    let grade = v.get("grade").and_then(Value::as_str).unwrap_or_default();
    if !SOW_GRADES.contains(&grade) {
        return Err(invalid(
            "a qualification is singly graded: 'enforced', 'evidence' or 'recorded' (§4.2)",
        ));
    }
    if grade == "enforced" && kind == "asserted" {
        return Err(invalid(
            "a condition the counterparty asserts about itself, and that no runtime can check, MUST NOT be graded enforced. The record is evidence that the party asserted the thing, not proof that the thing is true (§12.1 rule 4, §3 rule 1)",
        ));
    }
    if kind == "publishes_offering" {
        let offering = v.get("offering").and_then(Value::as_str).unwrap_or_default();
        if offering.trim().is_empty() || offering.chars().count() > 60 {
            return Err(invalid(
                "a publishes_offering qualification names the offering the counterparty must publish (§12.1)",
            ));
        }
    } else if v.get("offering").is_some() {
        return Err(invalid(
            "only a publishes_offering qualification carries an offering (§12.1)",
        ));
    }
    Ok(())
}

/// The clause: a list of singly-graded conditions with distinct ids.
pub fn validate_sow_qualifications(v: &Value) -> Result<()> {
    let Some(list) = v.as_array() else {
        return Err(invalid("qualifications is a list of conditions (§12.1)"));
    };
    if list.len() > QUALIFICATIONS_MAX {
        return Err(invalid(format!(
            "a standing proposal states at most {QUALIFICATIONS_MAX} qualifications (§12.1)"
        )));
    }
    let mut seen: Vec<&str> = Vec::new();
    for q in list {
        validate_sow_qualification(q)?;
        let id = q.get("id").and_then(Value::as_str).unwrap_or_default();
        if seen.contains(&id) {
            return Err(invalid(format!(
                "two qualifications share the id \"{id}\", and a refusal has to name one of them (§12.1)"
            )));
        }
        seen.push(id);
    }
    Ok(())
}

/// The conditions a document states, unvalidated, or an empty slice where it
/// states none. Both a standing proposal and a countersigned instance carry the
/// clause in the same place, because the instance is the proposal plus the seat.
pub fn qualifications_of(doc: &Value) -> Vec<&Value> {
    doc.get("qualifications")
        .and_then(Value::as_array)
        .map(|l| l.iter().collect())
        .unwrap_or_default()
}

/// The ids a countersign of this document MUST assert, sorted.
///
/// Sorted because the list rides inside the client's signed bytes: two clients
/// accepting the same offer produce the same bytes, and a runtime rebuilding
/// what the instance must be has one answer rather than a permutation of them.
pub fn required_assertions(doc: &Value) -> Vec<String> {
    let mut ids: Vec<String> = qualifications_of(doc)
        .into_iter()
        .filter(|q| q.get("kind").and_then(Value::as_str) == Some("asserted"))
        .filter_map(|q| q.get("id").and_then(Value::as_str).map(str::to_string))
        .collect();
    ids.sort();
    ids
}

/// What a runtime established about the counterparty, for the checkable kinds.
///
/// A field left `None` is a fact the runtime did NOT establish, which is not the
/// same as a fact it established as false, and the gate treats it as a refusal
/// rather than a pass. A registry that could not be read is a condition that was
/// not checked, and §12.1 rule 2 makes completing formation the thing a runtime
/// does for a counterparty that MEETS the conditions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SowQualificationFacts {
    /// The agent key these facts describe. Checked against the client seat, so
    /// a runtime cannot gather facts about one party and admit another.
    pub subject: String,
    /// Does the counterparty hold a current registration in the mesh registry?
    pub registered: Option<bool>,
    /// The offerings that registration publishes.
    pub offerings: Option<Vec<String>>,
    /// Is the counterparty's agent attached to an account on this platform?
    pub account: Option<bool>,
}

/// The §12.1 formation gate: does this counterparty meet the conditions this
/// offer states, and has it made the assertions the offer requires?
///
/// Returns None where every stated condition is met, and a refusal NAMING THE
/// UNMET CONDITION otherwise — rule 2 says the refusal names it, and a
/// counterparty that read a published offer and acted on it is owed the reason
/// rather than a shrug.
///
/// One function rather than two on purpose. The assertion half needs nothing
/// but the document, the fact half needs lookups, and a runtime that called
/// only the cheap one would have a gate that passes every unverifiable
/// condition in silence.
///
/// What this is NOT: a screen. §12.1 is explicit that where an operator is
/// merchant of record, sanctions screening, customer identification and tax
/// status are that operator's obligations to the authorities that impose them;
/// a seller cannot discharge them by stating a condition and a buyer cannot
/// discharge them by asserting it is met. Those belong at account admission and
/// at settlement. Nothing here may be read as having performed one.
pub fn qualification_refusal(
    doc: &Value,
    client_agent: &str,
    asserted: &[String],
    facts: Option<&SowQualificationFacts>,
) -> Option<String> {
    let raw = match doc.get("qualifications") {
        None | Some(Value::Null) => return None,
        Some(v) => v,
    };
    if let Err(err) = validate_sow_qualifications(raw) {
        return Some(format!(
            "this offer states conditions in a shape that cannot be read, so whether you meet them cannot be established: {err}"
        ));
    }
    let quals = raw.as_array().expect("validated as an array");
    if quals.is_empty() {
        return None;
    }
    let find = |id: &str| quals.iter().find(|q| q.get("id").and_then(Value::as_str) == Some(id));
    let statement_of = |q: &Value| q.get("statement").and_then(Value::as_str).unwrap_or_default().to_string();

    // The assertions the countersign carries, held to the offer's own list
    // BEFORE anything else: an unknown id means the two sides are reading
    // different documents, and that is worth saying plainly.
    let mut previous: Option<&str> = None;
    for id in asserted {
        if previous.is_some_and(|p| p >= id.as_str()) {
            return Some(
                "the asserted conditions are listed once each, in sorted order, because the list rides inside the bytes both parties sign (§12.1)"
                    .to_string(),
            );
        }
        previous = Some(id.as_str());
        let Some(q) = find(id) else {
            return Some(format!(
                "this offer states no condition called \"{id}\", and a countersign asserts only the conditions the offer states (§12.1)"
            ));
        };
        if q.get("kind").and_then(Value::as_str) != Some("asserted") {
            return Some(format!(
                "\"{id}\" is a condition this runtime checks rather than one you state, so a countersign does not assert it (§12.1)"
            ));
        }
    }
    for id in required_assertions(doc) {
        if !asserted.contains(&id) {
            let statement = find(&id).map(statement_of).unwrap_or_default();
            return Some(format!(
                "this offer requires the countersigning party to state that it meets \"{id}\": {statement} The countersign carries no such statement, so it is refused. Nothing here verifies the statement; what is held afterwards is evidence that you made it (§12.1)"
            ));
        }
    }

    // The checkable half.
    let checkable: Vec<&Value> = quals
        .iter()
        .filter(|q| q.get("kind").and_then(Value::as_str) != Some("asserted"))
        .collect();
    if checkable.is_empty() {
        return None;
    }
    let Some(facts) = facts else {
        return Some(
            "this offer states conditions on who may countersign it, and this runtime checked none of them; an unchecked condition refuses formation rather than passing it (§12.1)"
                .to_string(),
        );
    };
    if facts.subject != client_agent {
        return Some(
            "the conditions were checked against a different party than the one filling the client seat, so nothing has been established about the countersigning agent (§12.1)"
                .to_string(),
        );
    }
    let unchecked = |q: &Value| {
        let id = q.get("id").and_then(Value::as_str).unwrap_or_default();
        Some(format!(
            "this offer states the condition \"{id}\": {} This runtime could not check it just now, and an unchecked condition refuses formation rather than passing it (§12.1)",
            statement_of(q)
        ))
    };
    let unmet = |q: &Value, because: String| {
        let id = q.get("id").and_then(Value::as_str).unwrap_or_default();
        Some(format!(
            "this offer states a condition the countersigning party does not meet, \"{id}\": {} {because} (§12.1)",
            statement_of(q)
        ))
    };
    for q in checkable {
        match q.get("kind").and_then(Value::as_str).unwrap_or_default() {
            "mesh_registration" => match facts.registered {
                None => return unchecked(q),
                Some(false) => {
                    return unmet(q, "That agent holds no current registration on this mesh.".to_string())
                }
                Some(true) => {}
            },
            "publishes_offering" => {
                let offering = q.get("offering").and_then(Value::as_str).unwrap_or_default();
                match &facts.offerings {
                    None => return unchecked(q),
                    Some(offerings) => {
                        if !offerings.iter().any(|o| o == offering) {
                            return unmet(
                                q,
                                format!("That agent's published manifest does not offer \"{offering}\"."),
                            );
                        }
                    }
                }
            }
            "platform_account" => match facts.account {
                None => return unchecked(q),
                Some(false) => {
                    return unmet(q, "That agent is not attached to an account on this platform.".to_string())
                }
                Some(true) => {}
            },
            // A kind this reader does not know is a condition it cannot test,
            // and reading it as met is how a document's own terms get waived by
            // the runtime that could not parse them.
            other => {
                return Some(format!(
                    "this offer states a condition of a kind this runtime does not understand, \"{other}\", so it cannot tell whether you meet it; formation is refused rather than completed unchecked (§12.1)"
                ))
            }
        }
    }
    None
}

// ── §6.1 + §6.2: approval authority and the mandate reference ───────────────

/// What kind of actor may bind an act (§6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalAuthority {
    Agent,
    Person,
    AgentThenPerson,
}

pub const APPROVAL_AUTHORITIES: [&str; 3] = ["agent", "person", "agent_then_person"];

/// §6.1 defaults when unstated: formation is `agent`, amendments are `person`.
pub const DEFAULT_FORMATION_AUTHORITY: ApprovalAuthority = ApprovalAuthority::Agent;
pub const DEFAULT_AMENDMENT_AUTHORITY: ApprovalAuthority = ApprovalAuthority::Person;

/// Which act an approval record covers (§6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SowApprovalAct {
    Formation,
    Amendment,
}

/// An approval record (§6.1), optionally carrying the §6.2 mandate reference.
///
/// `mandate` names the mandate under which the approving person acted. It sits
/// inside the signed bytes and is additive. A runtime that does not perform the
/// Agent Mandate §7 checks MUST NOT present a document carrying it as
/// mandate-verified: the reference is then `evidence` that a mandate was cited,
/// not `enforced` authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SowApprovalRecord {
    pub act: SowApprovalAct,
    pub authority: ApprovalAuthority,
    pub key: String,
    pub approved_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mandate: Option<String>,
}

pub fn validate_sow_approval(v: &Value) -> Result<()> {
    if !v.is_object() {
        return Err(invalid("an approval record is an object"));
    }
    match v.get("act").and_then(Value::as_str) {
        Some("formation") | Some("amendment") => {}
        _ => return Err(invalid("act is 'formation' or 'amendment'")),
    }
    let Some(authority) =
        v.get("authority").and_then(Value::as_str).filter(|a| APPROVAL_AUTHORITIES.contains(a))
    else {
        return Err(invalid("authority is 'agent', 'person' or 'agent_then_person' (§6.1)"));
    };
    if !v.get("key").and_then(Value::as_str).is_some_and(|k| !k.is_empty()) {
        return Err(invalid("an approval names the approving key"));
    }
    if !v.get("approved_at").and_then(Value::as_str).is_some_and(is_rfc3339_instant) {
        return Err(invalid("approved_at must be an RFC-3339 instant"));
    }
    if let Some(mandate) = v.get("mandate") {
        if !mandate.as_str().is_some_and(|m| is_mandate_ref(m, "mnd_")) {
            return Err(invalid("mandate is an Agent Mandate reference, 'mnd_...' (§6.2)"));
        }
        if authority == "agent" {
            return Err(invalid(
                "a mandate names the mandate under which the approving PERSON acted (§6.2) — an \
                 agent-authority approval has no person to hold one",
            ));
        }
    }
    Ok(())
}

/// §6.2 — whether a runtime may present this approval as mandate-verified.
///
/// Only where the deployment actually performs the Agent Mandate §7 checks. The
/// honest default is `false`: the reference is then evidence a mandate was
/// cited, and a runtime MUST NOT present it as a legal opinion either way.
pub fn mandate_verified(approval: &SowApprovalRecord, checks_performed: bool) -> bool {
    checks_performed && approval.mandate.is_some()
}

/// RFC-3339 instant, hand-rolled to match the TypeScript SDK's regex without
/// pulling in a regex engine (the same shape `agreement.rs` accepts).
fn is_rfc3339_instant(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() < 20 {
        return false;
    }
    let digits = |r: std::ops::Range<usize>| r.into_iter().all(|i| b[i].is_ascii_digit());
    if !(digits(0..4) && b[4] == b'-' && digits(5..7) && b[7] == b'-' && digits(8..10)) {
        return false;
    }
    if b[10] != b'T' {
        return false;
    }
    if !(digits(11..13) && b[13] == b':' && digits(14..16) && b[16] == b':' && digits(17..19)) {
        return false;
    }
    let mut i = 19;
    if b.get(i) == Some(&b'.') {
        i += 1;
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i == start {
            return false;
        }
    }
    match b.get(i) {
        Some(b'Z') => i + 1 == b.len(),
        Some(b'+') | Some(b'-') => {
            b.len() == i + 6
                && b[i + 1].is_ascii_digit()
                && b[i + 2].is_ascii_digit()
                && b[i + 3] == b':'
                && b[i + 4].is_ascii_digit()
                && b[i + 5].is_ascii_digit()
        }
        _ => false,
    }
}

// ── §6: canonicalization and signing ────────────────────────────────────────

/// One owner's signature over the document (§6). Owners sign, not agents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SowSignature {
    pub role: String,
    pub key: String,
    pub signed_at: String,
    pub sig: String,
}

/// The canonical JSON an Agent SoW signature covers (§6): the JCS canonical
/// JSON of the document with the `signatures` array removed.
///
/// The TypeScript SDK produces the same string for the same document; that byte
/// equality is what `conformance/sow-pricing.json` pins.
pub fn canonical_sow_json(doc: &Value) -> String {
    let mut v = doc.clone();
    if let Some(map) = v.as_object_mut() {
        map.remove("signatures");
    }
    canonical_json(&v)
}

/// The exact bytes a signer signs: [`SOW_SIG_PREFIX`] + the canonical JSON.
pub fn sow_signed_bytes(doc: &Value) -> Vec<u8> {
    tagged_sig_bytes(SOW_SIG_PREFIX, canonical_sow_json(doc).as_bytes())
}

/// Sign a document as one role, appending to `signatures` (§6).
///
/// Formation always ends with a fresh provider signature over the COMPLETED
/// document: a standing proposal's provider signature covers the template bytes,
/// and the moment a client countersigns, the client seat and start instant fill
/// in and the bytes change. A pre-signature authenticates the offer; it does not
/// pre-authorize every formation (§6, §12.1). This function therefore always
/// signs the document as it stands now.
pub fn sign_sow(doc: &mut Value, kp: &KeyPair, role: &str, signed_at: &str) -> Result<()> {
    if role != "provider" && role != "client" {
        return Err(invalid("a signature's role is 'provider' or 'client' (§6)"));
    }
    let sig = kp
        .sign(&sow_signed_bytes(doc))
        .map_err(|e| MeshError::Nkey(e.to_string()))?;
    let record = serde_json::to_value(SowSignature {
        role: role.to_string(),
        key: kp.public_key(),
        signed_at: signed_at.to_string(),
        sig: b64url(&sig),
    })?;
    let Some(map) = doc.as_object_mut() else {
        return Err(invalid("a document is an object"));
    };
    let existing = map.remove("signatures").and_then(|s| match s {
        Value::Array(a) => Some(a),
        _ => None,
    });
    let mut signatures: Vec<Value> = existing
        .unwrap_or_default()
        .into_iter()
        .filter(|s| s.get("role").and_then(Value::as_str) != Some(role))
        .collect();
    signatures.push(record);
    map.insert("signatures".to_string(), Value::Array(signatures));
    Ok(())
}

/// Verify one signature record against the document's canonical bytes (§6).
pub fn verify_sow_signature(doc: &Value, signature: &SowSignature) -> bool {
    let Ok(sig) = unb64url(&signature.sig) else { return false };
    let canonical = canonical_sow_json(doc);
    match KeyPair::from_public_key(&signature.key) {
        Ok(vpub) => verify_tagged(&vpub, SOW_SIG_PREFIX, canonical.as_bytes(), &sig),
        Err(_) => false,
    }
}

/// §6 — a document is **agreed** when both roles have valid signatures over the
/// same canonical bytes. Not "both roles signed something"; both signatures must
/// verify against the bytes the document has right now.
pub fn sow_agreed(doc: &Value) -> bool {
    let Some(signatures) = doc.get("signatures").and_then(Value::as_array) else { return false };
    let mut provider = false;
    let mut client = false;
    for s in signatures {
        let Ok(record) = serde_json::from_value::<SowSignature>(s.clone()) else { return false };
        if !verify_sow_signature(doc, &record) {
            return false;
        }
        match record.role.as_str() {
            "provider" => provider = true,
            "client" => client = true,
            _ => {}
        }
    }
    provider && client
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tm() -> SowPrice {
        SowPrice::time_and_materials(
            "XCR",
            vec![
                SowScheduleLine::per("tokens_out", "1000 tokens", 1000, 1500),
                SowScheduleLine::new("tool_calls", "call", 2000),
            ],
            SowCap::new(40_000_000),
            SowReservation::new(30),
        )
        .expect("a capped, reserved schedule is valid")
    }

    #[test]
    fn an_uncapped_time_and_materials_price_does_not_deserialize() {
        // The type-level half of §5.5.3: `cap` is not an Option, so serde has
        // nothing to fill in and the whole clause is refused.
        let uncapped = serde_json::json!({
            "arrangement": "time_and_materials",
            "currency": "XCR",
            "schedule": [{"meter": "tokens_out", "unit": "1000 tokens", "per": 1000, "per_unit": 1500}],
            "reservation": {"window_days": 30},
            "grade": "enforced"
        });
        assert!(serde_json::from_value::<SowPrice>(uncapped.clone()).is_err());
        assert!(validate_sow_price(&uncapped).is_err());
        assert!(load_sow_price(&uncapped).is_err());
    }

    #[test]
    fn an_unreserved_time_and_materials_price_does_not_deserialize() {
        // §5.5.4, the same treatment: `reservation` is not an Option either.
        let unreserved = serde_json::json!({
            "arrangement": "time_and_materials",
            "currency": "XCR",
            "schedule": [{"meter": "tokens_out", "unit": "1000 tokens", "per": 1000, "per_unit": 1500}],
            "cap": {"amount": 40_000_000},
            "grade": "enforced"
        });
        assert!(serde_json::from_value::<SowPrice>(unreserved.clone()).is_err());
        let err = validate_sow_price(&unreserved).unwrap_err().to_string();
        assert!(err.contains("no defined settlement behaviour"), "{err}");
    }

    #[test]
    fn a_clause_naming_no_arrangement_is_refused() {
        let legacy = serde_json::json!({
            "currency": "XCR",
            "rates": [{"offering": "reconcile-statement", "per_task": 2_500_000}],
            "grade": "enforced"
        });
        let err = validate_sow_price(&legacy).unwrap_err().to_string();
        assert!(err.contains("no undeclared default"), "{err}");
    }

    #[test]
    fn the_divisor_converts_raw_counts_and_floors() {
        let line = SowScheduleLine::per("tokens_out", "1000 tokens", 1000, 1500);
        assert_eq!(line.divisor(), 1000);
        // Exactly two units.
        assert_eq!(line.rate(2000).unwrap(), 3000);
        // A partial unit never charges a partial unit's money: floor, and it
        // favours the buyer.
        assert_eq!(line.rate(2999).unwrap(), 4498);
        assert_eq!(line.rate(999).unwrap(), 1498);
        assert_eq!(line.rate(0).unwrap(), 0);
        // A line naming no divisor rates one raw count at a time.
        assert_eq!(SowScheduleLine::new("tool_calls", "call", 2000).divisor(), 1);
        assert_eq!(SowScheduleLine::new("tool_calls", "call", 2000).rate(3).unwrap(), 6000);
    }

    #[test]
    fn the_unit_label_is_never_parsed() {
        // A label that contradicts the divisor is a rendering bug, not an
        // arithmetic one: §5.5.2 says rate on `per`.
        let lying = SowScheduleLine::per("tokens_out", "1 token", 1000, 1500);
        assert_eq!(lying.rate(1000).unwrap(), 1500);
    }

    #[test]
    fn rating_widens_so_a_large_count_does_not_wrap() {
        let line = SowScheduleLine::per("tokens_out", "1000 tokens", 1000, 1_000_000);
        // count × per_unit here is ~4.6e18, past u64's comfort but exact in u128.
        assert_eq!(line.rate(4_600_000_000_000).unwrap(), 4_600_000_000_000_000);
    }

    #[test]
    fn rating_stops_at_the_cap_and_the_remainder_is_the_providers() {
        let price = SowPrice::time_and_materials(
            "XCR",
            vec![SowScheduleLine::new("tool_calls", "call", 1000)],
            SowCap::new(5_000),
            SowReservation::new(30),
        )
        .unwrap();
        let rated = rate_usage(&price, &[SowMeteredCount::new("tool_calls", 8)], 0, &[]).unwrap();
        assert_eq!(rated.total, 5_000);
        assert_eq!(rated.unbilled, 3_000);
        assert_eq!(rated.cap_remaining, 0);
        assert!(rated.exhausted);
    }

    #[test]
    fn a_settlement_line_carries_what_the_buyer_needs_to_recompute_it() {
        let rated =
            rate_usage(&tm(), &[SowMeteredCount::new("tokens_out", 2500)], 0, &[]).unwrap();
        let line = &rated.lines[0];
        assert_eq!(line.count, 2500);
        assert_eq!(line.per, 1000);
        assert_eq!(line.per_unit, 1500);
        assert_eq!(line.amount, 3750);
        // The buyer recomputes from its own token count and gets the same number.
        assert_eq!((line.count as u128 * line.per_unit as u128 / line.per as u128) as u64, line.amount);
    }

    #[test]
    fn an_unpriced_meter_is_refused_not_dropped() {
        let err = rate_usage(&tm(), &[SowMeteredCount::new("elapsed", 4)], 0, &[])
            .unwrap_err()
            .to_string();
        assert!(err.contains("MUST NOT bill 'elapsed'"), "{err}");
    }

    #[test]
    fn a_pass_through_line_without_a_receipt_is_refused() {
        let price = SowPrice::time_and_materials(
            "XCR",
            vec![SowScheduleLine::new("vendor_lookups", "lookup", 9000).pass_through()],
            SowCap::new(1_000_000),
            SowReservation::new(14),
        )
        .unwrap();
        assert!(rate_usage(&price, &[SowMeteredCount::new("vendor_lookups", 2)], 0, &[]).is_err());
        let ok = rate_usage(
            &price,
            &[SowMeteredCount::new("vendor_lookups", 2)],
            0,
            &[("vendor_lookups".to_string(), "rcpt_abc".to_string())],
        )
        .unwrap();
        assert_eq!(ok.lines[0].upstream_receipt.as_deref(), Some("rcpt_abc"));
    }

    #[test]
    fn the_committed_price_of_time_and_materials_is_the_cap() {
        assert_eq!(committed_price(&tm()), Some(40_000_000));
        let ff = SowPrice::fixed_fee(
            "XCR",
            vec![SowFixedFeeRate { offering: "flag-exceptions".into(), per_task: 400_000 }],
        )
        .unwrap();
        assert_eq!(committed_price(&ff), None);
    }

    #[test]
    fn a_no_charge_clause_has_no_slot_for_a_price() {
        // The type-level half of §5.5.7: the variant carries `grade` and
        // nothing else, so the constructor takes nothing else either. There is
        // no call shape here that produces a clause with a currency, a rate, a
        // schedule, a cap, a reservation or a ceiling in it.
        let price = SowPrice::no_charge().expect("the clause §5.5.7 writes is valid");
        assert_eq!(
            serde_json::to_value(&price).unwrap(),
            serde_json::json!({"arrangement": "no_charge", "grade": "enforced"})
        );
        assert!(price.is_no_charge());
        assert_eq!(price.currency(), None);
        assert_eq!(price.arrangement().as_str(), "no_charge");

        // The two builders that attach a price instrument refuse it by name.
        let err = price.clone().with_ceiling(SowCeiling { amount: 1, period: SowPeriod::Month })
            .unwrap_err()
            .to_string();
        assert!(err.contains("no ceiling"), "{err}");
        let err = price.with_reservation(SowReservation::new(30)).unwrap_err().to_string();
        assert!(err.contains("reserves nothing"), "{err}");
    }

    #[test]
    fn nothing_settles_and_the_committed_price_is_zero() {
        let price = SowPrice::no_charge().unwrap();
        assert!(!settles(&price));
        assert!(settles(&tm()));
        assert_eq!(committed_price(&price), Some(0));

        let err = rate_usage(&price, &[SowMeteredCount::new("tokens_out", 125_501)], 0, &[])
            .unwrap_err()
            .to_string();
        assert!(err.contains("MUST NOT rate work under it"), "{err}");
        assert!(admit_settlement(&price, "settle").is_err());
        assert!(admit_settlement(&tm(), "settle").is_ok());
    }

    #[test]
    fn exhausted_ends_the_engagement_and_is_not_scored() {
        let s = SowDocumentState::Exhausted;
        assert!(!s.admits_work());
        assert!(s.is_end_state());
        assert!(!s.is_scored_outcome());
        assert_eq!(serde_json::to_value(s).unwrap(), serde_json::json!("exhausted"));
    }
}
