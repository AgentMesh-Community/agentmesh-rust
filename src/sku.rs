//! SKUs and prices (§19.1) — what an agent sells, as declared commercial terms.
//!
//! A SKU names what is covered (`covers`), what it costs (`price`, one of five
//! closed shapes rated against named meters, §13.5), and who bills for it
//! (`provider`, §19.4). Its DIGEST — SHA-256 over the tagged canonical bytes —
//! is the identity of the terms: one moved micro-unit moves it, and every
//! standing agreement (§19.5) goes stale at once. An offering covered by no
//! SKU is FREE: paid is the declared exception, never something a consumer
//! discovers on an invoice.
//!
//! Mirrors `sdk-typescript/src/sku.ts`; shapes, refusals and the digest bytes
//! are pinned by `conformance/commerce.json` — value-level validation,
//! deliberately, so each fixture `invalid` row is refused for exactly its
//! stated reason, and shape rejection never depends on serde's own judgement.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::error::{ErrorCode, MeshError, Result};
use crate::identity::{b64url, canonical_json};

/// The domain tag inside a SKU digest's hashed bytes (§19.1). Never appears in
/// the SKU itself; the hashed bytes are this prefix + LF + the canonical JSON.
pub const SKU_DIGEST_PREFIX: &str = "agentmesh-sku-v1";

/// A UTC calendar period an allowance or aggregate resets over (§19.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SkuPeriod {
    Day,
    Month,
}

/// A price's included allowance: `quantity` metered units per `period`,
/// deducted before rating (§19.6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkuIncluded {
    pub quantity: u64,
    pub period: SkuPeriod,
}

/// One graduated tier of a `tiered` price (§19.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkuTier {
    /// Absent on the LAST tier only: the unbounded tail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub up_to: Option<u64>,
    pub amount_micro: u64,
}

/// The closed five price models (§19.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkuPriceModel {
    Free,
    Flat,
    PerUnit,
    Package,
    Tiered,
}

/// One of five closed shapes (§19.1). Fields not named by a shape are
/// forbidden on it — a price that says more than its model does is malformed,
/// not generous. [`validate_sku_price`] is the judge; this struct is the typed
/// construction surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkuPrice {
    pub model: SkuPriceModel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount_micro: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meter: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub period: Option<SkuPeriod>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tiers: Option<Vec<SkuTier>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub included: Option<SkuIncluded>,
}

/// What a SKU covers: the whole agent XOR a named offerings list (§19.1).
///
/// The deprecated `skills` spelling (§8.5) is read-tolerated AND
/// serialize-preserved: the digest (§19.1) is over the SKU's own bytes, so
/// rewriting the key would strand every agreement already signed against it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SkuCovers {
    /// `{"agent": true}` — every offering this agent has.
    Agent { agent: bool },
    /// `{"offerings": [...]}` — exactly these offering ids.
    Offerings { offerings: Vec<String> },
    /// Pre-rename wire shape (§8.5); read-tolerated, never emitted anew.
    Skills { skills: Vec<String> },
}

impl SkuCovers {
    /// The covered offering ids, whichever spelling carries them; `None` for
    /// an agent-wide SKU.
    pub fn covered_offerings(&self) -> Option<&[String]> {
        match self {
            SkuCovers::Agent { .. } => None,
            SkuCovers::Offerings { offerings } => Some(offerings),
            SkuCovers::Skills { skills } => Some(skills),
        }
    }
}

/// Who bills for a SKU (§19.4): `"internal"` (the deployment's own clearing)
/// or an external commerce provider's name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkuProvider {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terms_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkout_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_ref: Option<String>,
}

/// One declared commercial term (§19.1): id, coverage, price, biller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sku {
    pub sku: String,
    pub covers: SkuCovers,
    pub price: SkuPrice,
    pub provider: SkuProvider,
}

/// The storefront's advertisement of a SKU (§8.7): id, price, and the digest
/// an agreement would bind to — price as pre-admission data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicSku {
    pub sku: String,
    pub price: SkuPrice,
    pub digest: String,
}

// ─── shape validation (value-level, mirroring sku.ts byte for byte) ─────────

fn bad(message: impl Into<String>) -> MeshError {
    MeshError::code(ErrorCode::InvalidManifest, format!("SKU: {} (§19.1)", message.into()))
}

/// JavaScript's `Number.MAX_SAFE_INTEGER` (2⁵³ − 1): the TS validators accept
/// only safe integers, so a count above it is rejected on both sides.
const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

/// `Number.isSafeInteger(v) && v >= 0`, over a raw JSON value. `as_f64` on
/// purpose: an integral float (`5.0`) IS a non-negative integer to a JSON
/// parser that only has doubles, and the two SDKs must refuse the same inputs.
fn is_non_neg_int(v: Option<&Value>) -> bool {
    matches!(v.and_then(Value::as_f64),
        Some(f) if f.is_finite() && f.fract() == 0.0 && (0.0..=MAX_SAFE_INTEGER).contains(&f))
}

fn is_pos_int(v: Option<&Value>) -> bool {
    matches!(v.and_then(Value::as_f64),
        Some(f) if f.is_finite() && f.fract() == 0.0 && f > 0.0 && f <= MAX_SAFE_INTEGER)
}

/// `^[a-z0-9-]{1,64}$`
fn is_sku_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// `^[A-Z]{3}$` — ISO 4217, private-use X-codes included.
fn is_currency(s: &str) -> bool {
    s.len() == 3 && s.bytes().all(|b| b.is_ascii_uppercase())
}

/// The fields each model names. Anything else present on the price refuses.
fn model_fields(model: &str) -> Option<&'static [&'static str]> {
    match model {
        "free" => Some(&["model"]),
        "flat" => Some(&["model", "currency", "amount_micro"]),
        "per_unit" => Some(&["model", "currency", "meter", "per", "amount_micro", "included"]),
        "package" => {
            Some(&["model", "currency", "meter", "size", "amount_micro", "period", "included"])
        }
        "tiered" => Some(&["model", "currency", "meter", "per", "period", "tiers", "included"]),
        _ => None,
    }
}

fn validate_period(v: Option<&Value>, where_: &str) -> Result<()> {
    match v.and_then(Value::as_str) {
        Some("day") | Some("month") => Ok(()),
        _ => Err(bad(format!("{where_} period must be \"day\" or \"month\" (UTC calendar)"))),
    }
}

fn validate_included(v: &Value) -> Result<()> {
    if !(v.is_object() || v.is_array()) {
        return Err(bad("included must be an object"));
    }
    if !is_non_neg_int(v.get("quantity")) {
        return Err(bad("included.quantity must be a non-negative integer"));
    }
    // An allowance without a period never resets.
    validate_period(v.get("period"), "included:")
}

/// Validate one price over the raw JSON. `INVALID_MANIFEST` naming the §19.1
/// rule — value-level, so each `conformance/commerce.json` `invalid` row is
/// refused for exactly its stated reason.
pub fn validate_sku_price(v: &Value) -> Result<()> {
    if !(v.is_object() || v.is_array()) {
        return Err(bad("price must be an object"));
    }
    let model = match v.get("model").and_then(Value::as_str) {
        Some(m) if model_fields(m).is_some() => m,
        _ => return Err(bad("price.model is a closed five: free, flat, per_unit, package, tiered")),
    };
    let allowed = model_fields(model).expect("matched above");
    if let Some(map) = v.as_object() {
        for k in map.keys() {
            if !allowed.contains(&k.as_str()) {
                return Err(bad(if model == "free" {
                    "free names no money fields".to_string()
                } else if model == "flat" && k == "meter" {
                    "flat rates the requests observed meter by definition; naming another is a shape error"
                        .to_string()
                } else {
                    format!("'{k}' is not a field of the {model} shape")
                }));
            }
        }
    }
    if model == "free" {
        return Ok(());
    }

    match v.get("currency").and_then(Value::as_str) {
        Some(c) if is_currency(c) => {}
        _ => return Err(bad("currency must be an ISO 4217 code (a private-use X-code is legal)")),
    }
    if model != "tiered" && !is_non_neg_int(v.get("amount_micro")) {
        return Err(bad(
            "amount_micro must be a non-negative integer — no floats near money (§19.3)",
        ));
    }
    if model == "flat" {
        return Ok(());
    }

    match v.get("meter").and_then(Value::as_str) {
        Some(m) if !m.is_empty() => {}
        _ => return Err(bad(format!("{model} requires the meter it rates"))),
    }
    if let Some(per) = v.get("per") {
        if !is_pos_int(Some(per)) {
            return Err(bad("per must be a positive integer"));
        }
    }
    if let Some(included) = v.get("included") {
        validate_included(included)?;
    }

    if model == "package" {
        if !is_pos_int(v.get("size")) {
            return Err(bad("package requires a positive integer size"));
        }
        // Without a period, "partial package" has no meaning.
        validate_period(v.get("period"), "package")?;
    }
    if model == "tiered" {
        validate_period(v.get("period"), "tiered")?; // tiers aggregate over a period
        let tiers = match v.get("tiers").and_then(Value::as_array) {
            Some(t) if !t.is_empty() => t,
            _ => return Err(bad("tiered requires a non-empty tiers array")),
        };
        let mut prev = 0.0_f64;
        for (i, tier) in tiers.iter().enumerate() {
            if !is_non_neg_int(tier.get("amount_micro")) {
                return Err(bad(format!("tiers[{i}].amount_micro must be a non-negative integer")));
            }
            let last = i == tiers.len() - 1;
            if last {
                if tier.get("up_to").is_some() {
                    return Err(bad(
                        "the last tier must be unbounded — a price with a quantity ceiling is not a price, it is a refusal waiting to be discovered",
                    ));
                }
            } else {
                if !is_pos_int(tier.get("up_to")) {
                    return Err(bad(format!("tiers[{i}].up_to must be a positive integer")));
                }
                let up_to = tier.get("up_to").and_then(Value::as_f64).expect("checked above");
                if up_to <= prev {
                    return Err(bad("tiers up_to must strictly increase"));
                }
                prev = up_to;
            }
        }
    }
    Ok(())
}

/// Validate one SKU over the raw JSON. `INVALID_MANIFEST` naming the rule.
pub fn validate_sku(v: &Value) -> Result<()> {
    if !(v.is_object() || v.is_array()) {
        return Err(bad("a SKU must be an object"));
    }
    match v.get("sku").and_then(Value::as_str) {
        Some(id) if is_sku_id(id) => {}
        _ => return Err(bad("sku must match [a-z0-9-]{1,64}")),
    }
    let covers = match v.get("covers") {
        Some(c) if c.is_object() || c.is_array() => c,
        _ => return Err(bad("covers is required")),
    };
    let has_agent = covers.get("agent") == Some(&Value::Bool(true));
    // Deprecation window (§8.5): SKUs written before the rename say
    // `covers.skills`. Accepted as the same list — and deliberately NOT
    // rewritten in the document, because the digest (§19.1) is over the SKU's
    // own bytes and rewriting would strand every agreement already signed.
    let covered_list = match covers.get("offerings") {
        Some(o) if !o.is_null() => Some(o),
        _ => covers.get("skills"),
    };
    let has_offerings = covered_list.is_some_and(Value::is_array);
    if has_agent == has_offerings {
        return Err(bad("covers is agent XOR offerings"));
    }
    if has_offerings {
        let offerings = covered_list.and_then(Value::as_array).expect("checked above");
        if offerings.is_empty() {
            return Err(bad("an empty offerings list covers nothing"));
        }
        if !offerings.iter().all(|x| x.as_str().is_some_and(|s| !s.is_empty())) {
            return Err(bad("covers.offerings must be offering ids"));
        }
    }
    validate_sku_price(v.get("price").unwrap_or(&Value::Null))?;
    let provider_ok = v
        .get("provider")
        .filter(|p| p.is_object() || p.is_array())
        .and_then(|p| p.get("id"))
        .and_then(Value::as_str)
        .is_some_and(|id| !id.is_empty());
    if !provider_ok {
        return Err(bad("every SKU names who bills for it (§19.4)"));
    }
    Ok(())
}

/// Validate a manifest's `skus` array over the raw JSON: each SKU, plus
/// unique ids.
pub fn validate_skus(v: &Value) -> Result<()> {
    let Some(arr) = v.as_array() else {
        return Err(bad("skus must be an array"));
    };
    let mut seen = std::collections::HashSet::new();
    for s in arr {
        validate_sku(s)?;
        let id = s.get("sku").and_then(Value::as_str).unwrap_or_default();
        if !seen.insert(id.to_string()) {
            return Err(bad(format!("duplicate sku id '{id}' — ids are unique within the manifest")));
        }
    }
    Ok(())
}

// ─── the digest (§19.1) ─────────────────────────────────────────────────────

/// The SKU digest (§19.1) over the raw JSON: base64url (unpadded) SHA-256 over
/// the tagged bytes — [`SKU_DIGEST_PREFIX`] + LF + the canonical JSON (§5.3)
/// of the SKU object. The digest is what an agreement binds to, so no consumer
/// can be rated against terms they never accepted. Byte-identical to the TS
/// SDK's `skuDigest`; pinned by `conformance/commerce.json` and
/// `tests/fixtures/sku_digest.json`.
pub fn sku_digest_value(sku: &Value) -> String {
    let bytes = format!("{SKU_DIGEST_PREFIX}\n{}", canonical_json(sku));
    b64url(&Sha256::digest(bytes.as_bytes()))
}

/// [`sku_digest_value`] for a typed SKU.
pub fn sku_digest(sku: &Sku) -> Result<String> {
    Ok(sku_digest_value(&serde_json::to_value(sku)?))
}

/// The storefront advertisement for a SKU (§8.7): id + price + digest.
pub fn public_sku_of(sku: &Sku) -> Result<PublicSku> {
    Ok(PublicSku { sku: sku.sku.clone(), price: sku.price.clone(), digest: sku_digest(sku)? })
}

/// The SKU covering an offering, under §19.1's most-specific-wins rule: an
/// offering named explicitly beats an agent-wide SKU. `None` means the
/// offering is free.
pub fn sku_for<'a>(skus: Option<&'a [Sku]>, offering_id: &str) -> Option<&'a Sku> {
    let skus = skus.filter(|s| !s.is_empty())?;
    let mut agent_wide: Option<&Sku> = None;
    for s in skus {
        if let Some(covered) = s.covers.covered_offerings() {
            if covered.iter().any(|o| o == offering_id) {
                return Some(s);
            }
        } else if agent_wide.is_none() {
            agent_wide = Some(s);
        }
    }
    agent_wide
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn free_agent_sku(id: &str) -> Value {
        json!({
            "sku": id,
            "covers": { "agent": true },
            "price": { "model": "free" },
            "provider": { "id": "internal" }
        })
    }

    #[test]
    fn integral_floats_are_integers_and_fractional_ones_are_not() {
        // JSON has only doubles: the TS validators accept 5.0 where they
        // accept 5, and both SDKs must refuse the same inputs.
        assert!(is_non_neg_int(Some(&json!(1500.0))));
        assert!(!is_non_neg_int(Some(&json!(1500.5))));
        assert!(!is_non_neg_int(Some(&json!(-1))));
        assert!(!is_non_neg_int(None));
        // Above 2^53 − 1 is not a safe integer on either side.
        assert!(!is_non_neg_int(Some(&json!(9007199254740992_u64))));
        assert!(is_pos_int(Some(&json!(1))));
        assert!(!is_pos_int(Some(&json!(0))));
    }

    #[test]
    fn duplicate_ids_refuse() {
        let skus = json!([free_agent_sku("a"), free_agent_sku("a")]);
        let err = validate_skus(&skus).unwrap_err().to_string();
        assert!(err.contains("duplicate sku id 'a'"), "{err}");
    }

    #[test]
    fn deprecated_skills_spelling_is_read_and_never_rewritten() {
        let raw = json!({
            "sku": "legacy",
            "covers": { "skills": ["summarize"] },
            "price": { "model": "free" },
            "provider": { "id": "internal" }
        });
        validate_sku(&raw).unwrap();
        let typed: Sku = serde_json::from_value(raw.clone()).unwrap();
        assert_eq!(typed.covers.covered_offerings(), Some(&["summarize".to_string()][..]));
        // Round-trip preserves the old key: the digest is over the SKU's own
        // bytes, and rewriting would strand every agreement already signed.
        assert_eq!(serde_json::to_value(&typed).unwrap(), raw);
        assert_eq!(sku_digest(&typed).unwrap(), sku_digest_value(&raw));
    }

    #[test]
    fn most_specific_covers_wins() {
        let skus: Vec<Sku> = serde_json::from_value(json!([
            {
                "sku": "everything",
                "covers": { "agent": true },
                "price": { "model": "flat", "currency": "USD", "amount_micro": 1 },
                "provider": { "id": "internal" }
            },
            {
                "sku": "summaries",
                "covers": { "offerings": ["summarize"] },
                "price": { "model": "free" },
                "provider": { "id": "internal" }
            }
        ]))
        .unwrap();
        assert_eq!(sku_for(Some(&skus), "summarize").unwrap().sku, "summaries");
        assert_eq!(sku_for(Some(&skus), "anything-else").unwrap().sku, "everything");
        assert!(sku_for(None, "summarize").is_none());
        assert!(sku_for(Some(&[]), "summarize").is_none());
    }
}
