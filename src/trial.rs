//! Trials (Common Agent 7.7): an offering's `trial` declaration, the
//! `trial: true` request marker, and admission at the node.
//!
//! Everything here is pure: no clock but the one handed in, no network. A
//! node keeps its own counts (in memory, a file, a database: the
//! [`TrialLedger`] trait) and hands them to [`trial_admission`]; a host (the
//! platform that lists agents) runs the same function over the counts it can
//! see. Both refuse with the same `TRIAL_REFUSED` shape, so a requester reads
//! one answer whoever refused. This module is the Rust twin of
//! `sdk-typescript/src/trial.ts`, and `conformance/trial.json` is the
//! authority over both (`tests/trial_conformance.rs`).
//!
//! The order is the specification's: a budget on a trial request first (a
//! requester who owes nothing has nothing to offer), then
//!
//!  1. the offering declares `trial`              (`not_offered`)
//!  2. the requester qualifies under `who`        (`not_eligible`)
//!  3. every input fits the shape's limit         (`input`)
//!  4. no count in `limits` is reached            (`requester_day`, `day`, `requester_ever`)
//!  5. the trial ceiling of the allowance has room (`funds`)
//!
//! and the first failure is the answer. A refused trial is not counted; the
//! caller counts a trial only once it is admitted, and a trial that fails
//! after admission stays counted, because the publisher paid for it.

use std::collections::HashMap;
use std::sync::Mutex;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::error::{ErrorCode, ErrorObject, MeshError};
use crate::sku::{SkuPrice, SkuPriceModel};

/// The closed set of `who` values.
pub const TRIAL_WHO: [&str; 3] = ["anyone", "signed_in", "verified"];

/// The limit names a shape input may carry.
pub const TRIAL_LIMIT_KEYS: [&str; 5] = ["max_chars", "max_bytes", "max_pages", "max_seconds", "max_items"];

/// The limits a node can check at admission, before anything is fetched.
pub const ADMISSION_LIMIT_KEYS: [&str; 2] = ["max_chars", "max_bytes"];

/// The refusal reasons, in the order admission checks them.
pub const TRIAL_REASONS: [&str; 8] = [
    "budget",
    "not_offered",
    "not_eligible",
    "input",
    "requester_day",
    "day",
    "requester_ever",
    "funds",
];

const LIMIT_KEYS: [&str; 3] = ["per_requester_per_day", "per_day", "per_requester_ever"];

/// Who may ask for trial work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrialWho {
    /// Any requester, a visitor a host vouches for included.
    Anyone,
    /// A requester holding an account where the request is made.
    SignedIn,
    /// A requester whose owner is verified under the binding.
    Verified,
}

/// How tight one trial input is. A node checks what it can measure before
/// any work (characters and bytes of what was sent); a limit only the work
/// can measure (pages read from an address, seconds of a recording, items in
/// a list behind a link) is handed to the work as its cap ([`work_caps`]).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrialInputLimitValue {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_chars: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_pages: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_items: Option<u64>,
}

/// One declared input with a tighter trial limit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrialInputLimit {
    pub name: String,
    pub limit: TrialInputLimitValue,
}

/// What changes in a trial. An absent member changes nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrialShape {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inputs: Option<Vec<TrialInputLimit>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub omits: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub live_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keeps_days: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub marked: Option<bool>,
}

/// Counts, never money. At least one is present.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrialLimits {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_requester_per_day: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_day: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_requester_ever: Option<u64>,
}

/// An offering's `trial` member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrialDeclaration {
    pub who: TrialWho,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shape: Option<TrialShape>,
    pub limits: TrialLimits,
}

/// Why a trial request was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrialReason {
    Budget,
    NotOffered,
    NotEligible,
    Input,
    RequesterDay,
    Day,
    RequesterEver,
    Funds,
}

impl TrialReason {
    pub fn as_str(self) -> &'static str {
        match self {
            TrialReason::Budget => "budget",
            TrialReason::NotOffered => "not_offered",
            TrialReason::NotEligible => "not_eligible",
            TrialReason::Input => "input",
            TrialReason::RequesterDay => "requester_day",
            TrialReason::Day => "day",
            TrialReason::RequesterEver => "requester_ever",
            TrialReason::Funds => "funds",
        }
    }
}

// ─── validation ─────────────────────────────────────────────────────────────

/// A whole, non-negative number, as JavaScript's `Number.isInteger(v) && v >= 0`
/// reads it: `3` and `3.0` are whole, `2.5` and `-1` are not.
fn whole_non_negative(v: &Value) -> Option<u64> {
    if let Some(u) = v.as_u64() {
        return Some(u);
    }
    let f = v.as_f64()?;
    if f.is_finite() && f >= 0.0 && f.fract() == 0.0 && f <= 9_007_199_254_740_991.0 {
        Some(f as u64)
    } else {
        None
    }
}

fn names_of(offering: Option<&Value>, member: &str) -> Vec<String> {
    offering
        .and_then(|o| o.get(member))
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(|e| e.get("name").and_then(Value::as_str).map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// Why a trial declaration is not acceptable, or `None` when it is. The
/// registry MUST refuse a trial with no count (7.7): a trial nothing bounds is
/// not a declaration a counterparty can rely on. `offering`, when given, is
/// the offering the trial sits on, so a shape naming an input or an output
/// the offering does not declare is refused rather than silently ignored.
pub fn validate_trial(trial: &Value, offering: Option<&Value>) -> Option<String> {
    let Some(trial) = trial.as_object() else {
        return Some("trial must be an object with who, limits and, optionally, shape.".into());
    };
    match trial.get("who").and_then(Value::as_str) {
        Some(w) if TRIAL_WHO.contains(&w) => {}
        _ => return Some(format!("trial.who must be one of {}.", TRIAL_WHO.join(", "))),
    }
    let Some(limits) = trial.get("limits").and_then(Value::as_object) else {
        return Some("trial.limits is required: a trial with no count is not bounded.".into());
    };
    let mut counted = 0;
    for k in LIMIT_KEYS {
        let Some(v) = limits.get(k) else { continue };
        if whole_non_negative(v).is_none() {
            return Some(format!("trial.limits.{k} must be a whole number of trial tasks."));
        }
        counted += 1;
    }
    for k in limits.keys() {
        if !LIMIT_KEYS.contains(&k.as_str()) {
            return Some(format!(
                "trial.limits.{k} is not a count this specification defines; limits are counts, never money."
            ));
        }
    }
    if counted == 0 {
        return Some(
            "trial.limits must carry at least one of per_requester_per_day, per_day and \
             per_requester_ever: a trial with no count is not bounded."
                .into(),
        );
    }
    let Some(shape) = trial.get("shape") else { return None };
    let Some(shape) = shape.as_object() else {
        return Some("trial.shape must be an object.".into());
    };
    let input_names = names_of(offering, "inputs");
    let output_names = names_of(offering, "outputs");
    if let Some(inputs) = shape.get("inputs") {
        let Some(inputs) = inputs.as_array() else {
            return Some("trial.shape.inputs must be a list.".into());
        };
        for entry in inputs {
            let name = match entry.get("name").and_then(Value::as_str) {
                Some(n) if entry.is_object() && !n.is_empty() => n,
                _ => return Some("each trial.shape.inputs entry needs the name of a declared input.".into()),
            };
            if offering.is_some() && !input_names.iter().any(|n| n == name) {
                return Some(format!(
                    "trial.shape.inputs names \"{name}\", which the offering does not declare."
                ));
            }
            let Some(limit) = entry.get("limit").and_then(Value::as_object) else {
                return Some(format!("trial.shape.inputs \"{name}\" needs a limit."));
            };
            for (k, v) in limit {
                if !TRIAL_LIMIT_KEYS.contains(&k.as_str()) {
                    return Some(format!(
                        "trial.shape.inputs \"{name}\" limit {k} is not one of {}.",
                        TRIAL_LIMIT_KEYS.join(", ")
                    ));
                }
                if !matches!(whole_non_negative(v), Some(n) if n > 0) {
                    return Some(format!(
                        "trial.shape.inputs \"{name}\" limit {k} must be a whole number above zero."
                    ));
                }
            }
            if limit.is_empty() {
                return Some(format!("trial.shape.inputs \"{name}\" names no limit."));
            }
        }
    }
    if let Some(omits) = shape.get("omits") {
        let names: Option<Vec<&str>> = omits.as_array().and_then(|list| {
            list.iter().map(|n| n.as_str().filter(|s| !s.is_empty())).collect()
        });
        let Some(names) = names else {
            return Some("trial.shape.omits must be a list of output names.".into());
        };
        if offering.is_some() {
            for n in names {
                if !output_names.iter().any(|o| o == n) {
                    return Some(format!(
                        "trial.shape.omits names \"{n}\", which the offering does not declare as an output."
                    ));
                }
            }
        }
    }
    for k in ["live_seconds", "keeps_days"] {
        if let Some(v) = shape.get(k) {
            if whole_non_negative(v).is_none() {
                return Some(format!("trial.shape.{k} must be a whole number."));
            }
        }
    }
    if let Some(m) = shape.get("marked") {
        if !m.is_boolean() {
            return Some("trial.shape.marked must be true or false.".into());
        }
    }
    None
}

/// Every offering's trial in a Descriptor, checked. The first problem, named
/// with its offering, or `None`. A Descriptor with no trial anywhere passes.
pub fn validate_descriptor_trials(doc: &Value) -> Option<String> {
    let offerings = doc.get("offerings").and_then(Value::as_array)?;
    for o in offerings {
        let Some(trial) = o.as_object().and_then(|m| m.get("trial")) else { continue };
        if let Some(why) = validate_trial(trial, Some(o)) {
            let id = o.get("id").and_then(Value::as_str).unwrap_or("(no id)");
            return Some(format!("offering {id}: {why}"));
        }
    }
    if let Some(r) = doc.get("samples_ref") {
        if !r.as_str().is_some_and(|s| s.starts_with("https://")) {
            return Some("samples_ref must be an https address of the agent's samples document.".into());
        }
    }
    None
}

/// Whole-valued floats (`3.0`) read as integers, so a declaration that
/// validated also deserializes into the typed shape.
fn whole_numbers(v: &Value) -> Value {
    match v {
        Value::Number(n) if n.as_u64().is_none() => match whole_non_negative(v) {
            Some(u) => json!(u),
            None => Value::Number(n.clone()),
        },
        Value::Array(a) => Value::Array(a.iter().map(whole_numbers).collect()),
        Value::Object(m) => {
            Value::Object(m.iter().map(|(k, v)| (k.clone(), whole_numbers(v))).collect::<Map<_, _>>())
        }
        other => other.clone(),
    }
}

/// The trial declared on one offering, read leniently: a member that does not
/// validate is no trial (9.6: never the flattering reading), so a request for
/// it is refused `not_offered`.
pub fn trial_of(offering: &Value) -> Option<TrialDeclaration> {
    let trial = offering.get("trial")?;
    if validate_trial(trial, Some(offering)).is_some() {
        return None;
    }
    serde_json::from_value(whole_numbers(trial)).ok()
}

/// [`trial_of`] for a declaration held on its own, with no offering to check
/// input and output names against (the SDK manifest's offerings declare no
/// named inputs or outputs).
pub fn trial_declaration_of(trial: &Value) -> Option<TrialDeclaration> {
    if validate_trial(trial, None).is_some() {
        return None;
    }
    serde_json::from_value(whole_numbers(trial)).ok()
}

/// Whether a request payload carries the trial marker. Only `true` is a trial.
pub fn is_trial_request(payload: &Value) -> bool {
    payload.get("trial") == Some(&Value::Bool(true))
}

// ─── requester, counts, quote ───────────────────────────────────────────────

/// What kind of requester is asking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrialRequesterKind {
    Account,
    Agent,
    /// A visitor a host vouches for, under an id the host issues.
    Visitor,
}

/// Who is asking, as the node or the host can tell. `id` is stable for the
/// requester: an account id, a sender key, or a host-issued visitor id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrialRequester {
    pub id: String,
    pub kind: TrialRequesterKind,
    /// Holds an account where the request is made. A vouched visitor never does.
    pub signed_in: bool,
    /// The requester's owner is verified under the binding.
    pub verified: bool,
}

/// A host's `trial_requester` vouch from a request payload, read strictly:
/// an `id`, a known `kind`, and the two flags (absent is false). A visitor
/// never holds an account, whatever the vouch says. `None` when the member is
/// absent or malformed.
pub fn trial_requester_of(payload: &Value) -> Option<TrialRequester> {
    let v = payload.get("trial_requester")?.as_object()?;
    let id = v.get("id").and_then(Value::as_str).filter(|s| !s.is_empty())?;
    let kind = match v.get("kind").and_then(Value::as_str)? {
        "account" => TrialRequesterKind::Account,
        "agent" => TrialRequesterKind::Agent,
        "visitor" => TrialRequesterKind::Visitor,
        _ => return None,
    };
    let flag = |k: &str| v.get(k).and_then(Value::as_bool).unwrap_or(false);
    let visitor = kind == TrialRequesterKind::Visitor;
    Some(TrialRequester {
        id: id.to_string(),
        kind,
        signed_in: !visitor && flag("signed_in"),
        verified: !visitor && flag("verified"),
    })
}

/// The trials already counted for this requester and offering.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TrialCounts {
    pub requester_day: u64,
    pub day: u64,
    pub requester_ever: u64,
}

/// What the same work costs as an ordinary request, so a requester refused a
/// trial is told how to have the work anyway. `amount_micro` is null only
/// when the offering carries no usable price; `words` always says it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrialQuote {
    pub amount_micro: Option<u64>,
    pub currency: Option<String>,
    pub words: String,
}

/// A price declaration (the SKU price shape) read as a quote.
pub fn quote_from_price(price: Option<&SkuPrice>) -> TrialQuote {
    let no_price = |currency: Option<String>| TrialQuote {
        amount_micro: None,
        currency,
        words: "it has no published price; ask the agent for a quote".into(),
    };
    let Some(price) = price else { return no_price(None) };
    let cur = price.currency.clone().unwrap_or_else(|| "USD".into());
    if price.model == SkuPriceModel::Free {
        return TrialQuote {
            amount_micro: Some(0),
            currency: Some(cur),
            words: "it is free as an ordinary request".into(),
        };
    }
    let Some(amt) = price.amount_micro else { return no_price(Some(cur)) };
    let money = money_words(amt, &cur);
    let words = match price.model {
        SkuPriceModel::Flat => format!("{money} as an ordinary request"),
        SkuPriceModel::PerUnit => format!(
            "{money} per {} {} as an ordinary request",
            price.per.unwrap_or(1),
            price.meter.as_deref().unwrap_or("units")
        ),
        _ => format!("from {money} as an ordinary request"),
    };
    TrialQuote { amount_micro: Some(amt), currency: Some(cur), words }
}

/// Integer micro-units as words a person reads: "$5.00", "12 XCR", "1.5 XCR".
pub fn money_words(amount_micro: u64, currency: &str) -> String {
    if currency == "USD" {
        let cents = (amount_micro + 5_000) / 10_000;
        return format!("${}.{:02}", cents / 100, cents % 100);
    }
    let whole = amount_micro / 1_000_000;
    let frac = amount_micro % 1_000_000;
    if frac == 0 {
        format!("{whole} {currency}")
    } else {
        let digits = format!("{frac:06}");
        format!("{whole}.{} {currency}", digits.trim_end_matches('0'))
    }
}

/// The next UTC midnight after `now`: when a per-day count resets, as an
/// ISO 8601 instant with milliseconds ("2026-10-06T00:00:00.000Z").
pub fn next_utc_midnight(now: DateTime<Utc>) -> String {
    let next = (now.date_naive() + Duration::days(1)).and_hms_opt(0, 0, 0).expect("midnight exists");
    next.and_utc().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// The UTC day a trial is counted under (`YYYY-MM-DD`).
pub fn trial_day_of(now: DateTime<Utc>) -> String {
    now.format("%Y-%m-%d").to_string()
}

// ─── the refusal ────────────────────────────────────────────────────────────

/// The fixed fields of a `TRIAL_REFUSED` refusal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrialRefusalDetails {
    pub reason: TrialReason,
    pub quote: TrialQuote,
    /// The declared number that was reached, where there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
    /// An absolute UTC time, where waiting will help.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resets_at: Option<String>,
    /// For `input`: which input.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<String>,
    /// For `input`: its trial limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<TrialInputLimitValue>,
}

impl TrialRefusalDetails {
    fn new(reason: TrialReason, quote: TrialQuote) -> Self {
        TrialRefusalDetails { reason, quote, limit: None, resets_at: None, input: None, max: None }
    }
}

/// A `TRIAL_REFUSED` refusal: the code, the passage for a person, and the
/// details. Never retryable as sent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrialRefusal {
    pub code: String,
    /// The passage for a person.
    pub message: String,
    pub retryable: bool,
    pub details: TrialRefusalDetails,
}

impl TrialRefusal {
    /// The refusal as the wire error object.
    pub fn error_object(&self) -> ErrorObject {
        ErrorObject {
            code: self.code.clone(),
            message: self.message.clone(),
            details: serde_json::to_value(&self.details).ok(),
            retryable: false,
            retry_after_ms: None,
        }
    }

    /// The refusal as a [`MeshError::Refusal`], the shape the dispatcher
    /// answers with its details intact.
    pub fn to_error(&self) -> MeshError {
        MeshError::Refusal(self.error_object())
    }
}

/// One measured input over its trial limit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputOver {
    pub input: String,
    pub max: TrialInputLimitValue,
}

/// The first measured input over its trial limit, or `None`. Characters are
/// Unicode code points; bytes are the UTF-8 length of a string, or the
/// `size` an attachment object states. Nothing is fetched.
pub fn input_over_limit(shape: Option<&TrialShape>, inputs: &Value) -> Option<InputOver> {
    for entry in shape.and_then(|s| s.inputs.as_deref()).unwrap_or_default() {
        let value = match inputs.get(&entry.name) {
            None | Some(Value::Null) => continue,
            Some(v) => v,
        };
        let text = value.as_str();
        let bytes: Option<f64> = match text {
            Some(t) => Some(t.len() as f64),
            None => value.as_object().and_then(|m| m.get("size")).and_then(Value::as_f64),
        };
        let over = |max: Option<u64>, measured: Option<f64>| {
            matches!((max, measured), (Some(m), Some(x)) if x > m as f64)
        };
        if over(entry.limit.max_chars, text.map(|t| t.chars().count() as f64))
            || over(entry.limit.max_bytes, bytes)
        {
            return Some(InputOver { input: entry.name.clone(), max: entry.limit.clone() });
        }
    }
    None
}

/// What the work is told it may do: one input's limit that only the work
/// can measure (pages, seconds, items).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkCap {
    pub input: String,
    pub limit: TrialInputLimitValue,
}

/// The caps handed to the work, for limits only the work can measure.
pub fn work_caps(shape: Option<&TrialShape>) -> Vec<WorkCap> {
    let mut out = Vec::new();
    for entry in shape.and_then(|s| s.inputs.as_deref()).unwrap_or_default() {
        let rest = TrialInputLimitValue {
            max_pages: entry.limit.max_pages,
            max_seconds: entry.limit.max_seconds,
            max_items: entry.limit.max_items,
            ..Default::default()
        };
        if rest != TrialInputLimitValue::default() {
            out.push(WorkCap { input: entry.name.clone(), limit: rest });
        }
    }
    out
}

fn limit_words(max: &TrialInputLimitValue) -> String {
    if let Some(n) = max.max_chars {
        return format!("{n} characters");
    }
    if let Some(n) = max.max_bytes {
        return format!("{n} bytes");
    }
    if let Some(n) = max.max_pages {
        return format!("{n} pages");
    }
    if let Some(n) = max.max_seconds {
        return format!("{n} seconds");
    }
    format!("{} items", max.max_items.unwrap_or(0))
}

fn tries(n: u64) -> String {
    if n == 1 {
        "1 try".into()
    } else {
        format!("{n} tries")
    }
}

fn cap(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

/// The passage for a person, one per reason. Plain, and always ends with how
/// to have the work anyway.
pub fn trial_refusal_words(d: &TrialRefusalDetails, agent_name: Option<&str>, who: Option<TrialWho>) -> String {
    let name = agent_name.unwrap_or("this agent");
    let anyway = if d.quote.amount_micro.is_none() {
        format!(" You can still ask for the full work: {}.", d.quote.words)
    } else {
        format!(" You can still have the full work: {}.", d.quote.words)
    };
    let lead = match d.reason {
        TrialReason::Budget => format!(
            "A trial is free, so it carries no budget. Send it without a budget to try {name}, or send an ordinary request with your budget."
        ),
        TrialReason::NotOffered => format!("{} does not offer a trial of this work.", cap(name)),
        TrialReason::NotEligible => {
            if who == Some(TrialWho::Verified) {
                "This trial is open only to people whose account is verified.".into()
            } else {
                "This trial is open only to people who are signed in. Sign in, then try again.".into()
            }
        }
        TrialReason::Input => format!(
            "A trial takes at most {} of {}. Send a shorter one to try it.",
            d.max.as_ref().map(limit_words).unwrap_or_else(|| "less".into()),
            d.input.as_deref().unwrap_or("this input")
        ),
        TrialReason::RequesterDay => format!(
            "You have used today's {} of {name}. You can try it again after midnight UTC.",
            tries(d.limit.unwrap_or(0))
        ),
        TrialReason::Day => {
            format!("Today's trials of {name} are used up for everyone. They start again after midnight UTC.")
        }
        TrialReason::RequesterEver => {
            format!("You have used all {} of {name} there are.", tries(d.limit.unwrap_or(0)))
        }
        TrialReason::Funds => format!(
            "{} has no room left for trials today. Trials start again after midnight UTC.",
            cap(name)
        ),
    };
    lead + &anyway
}

/// A `TRIAL_REFUSED` refusal with its passage for a person.
pub fn trial_refusal(details: TrialRefusalDetails, agent_name: Option<&str>, who: Option<TrialWho>) -> TrialRefusal {
    TrialRefusal {
        code: ErrorCode::TrialRefused.as_str().to_string(),
        message: trial_refusal_words(&details, agent_name, who),
        retryable: false,
        details,
    }
}

/// The refusal as a [`MeshError`], for a node that answers by returning one.
pub fn trial_refused(details: TrialRefusalDetails, agent_name: Option<&str>) -> MeshError {
    trial_refusal(details, agent_name, None).to_error()
}

// ─── admission ──────────────────────────────────────────────────────────────

/// The trial ceiling's answer ([`crate::allowance::AllowanceMeter::trial_funds_at`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrialFunds {
    /// The estimate fits under the trial ceiling and every wider one.
    Room,
    /// It does not.
    Full,
    /// The owner set no trial ceiling (or no allowance at all), so the node
    /// refuses on funds rather than spend unbounded (7.5, 7.7).
    None,
}

/// What one trial admission is judged on. The caller reads the counts before
/// and records one only when admitted.
#[derive(Debug, Clone)]
pub struct TrialAdmissionArgs<'a> {
    pub trial: Option<&'a TrialDeclaration>,
    pub has_budget: bool,
    pub requester: &'a TrialRequester,
    /// The request input, an object keyed by input name. Anything else has
    /// no named inputs to measure.
    pub inputs: &'a Value,
    pub counts: TrialCounts,
    pub funds: TrialFunds,
    pub quote: &'a TrialQuote,
    pub now: DateTime<Utc>,
    pub agent_name: Option<&'a str>,
}

/// Admission of one trial request, in the specification's order. `Ok(())`
/// admits; `Err` is the first failure's refusal.
pub fn trial_admission(args: TrialAdmissionArgs<'_>) -> Result<(), TrialRefusal> {
    let who = args.trial.map(|t| t.who);
    let no = |d: TrialRefusalDetails| Err(trial_refusal(d, args.agent_name, who));
    let base = |reason| TrialRefusalDetails::new(reason, args.quote.clone());
    if args.has_budget {
        return no(base(TrialReason::Budget));
    }
    let Some(trial) = args.trial else { return no(base(TrialReason::NotOffered)) };
    let r = args.requester;
    let eligible = match trial.who {
        TrialWho::Anyone => true,
        TrialWho::SignedIn => r.kind != TrialRequesterKind::Visitor && r.signed_in,
        TrialWho::Verified => r.kind != TrialRequesterKind::Visitor && r.verified,
    };
    if !eligible {
        return no(base(TrialReason::NotEligible));
    }
    if let Some(over) = input_over_limit(trial.shape.as_ref(), args.inputs) {
        return no(TrialRefusalDetails { input: Some(over.input), max: Some(over.max), ..base(TrialReason::Input) });
    }
    let l = &trial.limits;
    let midnight = next_utc_midnight(args.now);
    let reached = |limit: Option<u64>, count: u64| limit.filter(|&n| count >= n);
    if let Some(n) = reached(l.per_requester_per_day, args.counts.requester_day) {
        return no(TrialRefusalDetails {
            limit: Some(n),
            resets_at: Some(midnight),
            ..base(TrialReason::RequesterDay)
        });
    }
    if let Some(n) = reached(l.per_day, args.counts.day) {
        return no(TrialRefusalDetails { limit: Some(n), resets_at: Some(midnight), ..base(TrialReason::Day) });
    }
    if let Some(n) = reached(l.per_requester_ever, args.counts.requester_ever) {
        return no(TrialRefusalDetails { limit: Some(n), ..base(TrialReason::RequesterEver) });
    }
    if args.funds != TrialFunds::Room {
        return no(TrialRefusalDetails { resets_at: Some(midnight), ..base(TrialReason::Funds) });
    }
    Ok(())
}

// ─── counting ───────────────────────────────────────────────────────────────

/// Where a node keeps its trial counts. Keys are the requester id and the
/// offering id; days are UTC. A persistent ledger (a file, a database)
/// implements this and is handed to [`crate::AgentMesh::set_trial_ledger`].
pub trait TrialLedger: Send + Sync {
    /// The trials already counted.
    fn counts(&self, requester: &str, offering: &str, now: DateTime<Utc>) -> TrialCounts;
    /// Count one admitted trial. Never undone: a trial that fails after
    /// admission stays counted.
    fn record(&self, requester: &str, offering: &str, now: DateTime<Utc>);
}

#[derive(Default)]
struct MemoryBooks {
    per_requester_day: HashMap<String, u64>,
    per_day: HashMap<String, u64>,
    ever: HashMap<String, u64>,
}

/// Trial counts held in memory: the default ledger for a node with no
/// store, and the shape a persistent one follows.
#[derive(Default)]
pub struct MemoryTrialLedger {
    books: Mutex<MemoryBooks>,
}

impl MemoryTrialLedger {
    pub fn new() -> Self {
        Self::default()
    }
}

impl TrialLedger for MemoryTrialLedger {
    fn counts(&self, requester: &str, offering: &str, now: DateTime<Utc>) -> TrialCounts {
        let day = trial_day_of(now);
        let b = self.books.lock().unwrap();
        TrialCounts {
            requester_day: b.per_requester_day.get(&format!("{day}|{offering}|{requester}")).copied().unwrap_or(0),
            day: b.per_day.get(&format!("{day}|{offering}")).copied().unwrap_or(0),
            requester_ever: b.ever.get(&format!("{offering}|{requester}")).copied().unwrap_or(0),
        }
    }

    fn record(&self, requester: &str, offering: &str, now: DateTime<Utc>) {
        let day = trial_day_of(now);
        let mut b = self.books.lock().unwrap();
        *b.per_requester_day.entry(format!("{day}|{offering}|{requester}")).or_default() += 1;
        *b.per_day.entry(format!("{day}|{offering}")).or_default() += 1;
        *b.ever.entry(format!("{offering}|{requester}")).or_default() += 1;
    }
}

/// What an offering handler is told about an admitted trial, on
/// [`crate::RequestContext::trial`]: who asked, the shape the work must keep
/// to, and the caps only the work can measure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrialContext {
    pub requester: TrialRequester,
    pub shape: Option<TrialShape>,
    pub caps: Vec<WorkCap>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn money_words_read_like_the_typescript() {
        assert_eq!(money_words(5_000_000, "USD"), "$5.00");
        assert_eq!(money_words(1_234_567, "USD"), "$1.23");
        assert_eq!(money_words(5_000, "USD"), "$0.01", "half a cent rounds up");
        assert_eq!(money_words(12_000_000, "XCR"), "12 XCR");
        assert_eq!(money_words(1_500_000, "XCR"), "1.5 XCR");
        assert_eq!(money_words(1_234_567, "XCR"), "1.234567 XCR");
    }

    #[test]
    fn midnight_and_day() {
        let now: DateTime<Utc> = "2026-12-31T23:59:59.999Z".parse().unwrap();
        assert_eq!(next_utc_midnight(now), "2027-01-01T00:00:00.000Z");
        assert_eq!(trial_day_of(now), "2026-12-31");
    }

    #[test]
    fn a_vouched_visitor_never_holds_an_account() {
        let p = json!({ "trial_requester": { "id": "v-1", "kind": "visitor", "signed_in": true, "verified": true } });
        let r = trial_requester_of(&p).unwrap();
        assert!(!r.signed_in && !r.verified);
        assert!(trial_requester_of(&json!({ "trial_requester": { "id": "x", "kind": "friend" } })).is_none());
    }

    #[test]
    fn quotes_per_model() {
        let p = |v: Value| serde_json::from_value::<SkuPrice>(v).unwrap();
        assert_eq!(quote_from_price(None).amount_micro, None);
        assert_eq!(quote_from_price(Some(&p(json!({ "model": "free" })))).words, "it is free as an ordinary request");
        assert_eq!(
            quote_from_price(Some(&p(json!({ "model": "flat", "amount_micro": 5000000, "currency": "USD" })))).words,
            "$5.00 as an ordinary request"
        );
        assert_eq!(
            quote_from_price(Some(&p(json!({ "model": "per_unit", "amount_micro": 2000000, "currency": "USD", "meter": "pages", "per": 10 })))).words,
            "$2.00 per 10 pages as an ordinary request"
        );
    }
}
