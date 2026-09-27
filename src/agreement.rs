//! Agreements (§19.5) — proof the buyer accepted the terms.
//!
//! A declared price and a signed usage receipt are two legs of a stool. The
//! third is this: without it, a receipt is an invoice nobody agreed to pay. An
//! agreement binds a consumer ACCOUNT (the owner key, §8.6) to a SKU at a
//! specific digest, and rating (§19.6) charges nothing where no matching
//! agreement existed.
//!
//! Three properties carry the design:
//!
//!  - **Account-level, never per-agent.** An agent cannot click through a
//!    terms page; its human operator approves once and every agent under that
//!    owner is covered. Same reasoning as the EXT-8 allowance being
//!    owner-signed: it is a human's money.
//!  - **A digest mismatch is a missing agreement.** When the seller changes
//!    price or terms the digest moves and every standing agreement goes stale
//!    at once. There is no grandfathering rule because there is nothing to
//!    grandfather — re-approval IS the rule, and that is what stops a seller
//!    re-pricing under a standing acceptance.
//!  - **Revocation is prospective.** Usage already metered under a live
//!    agreement stays rated; revoking ends future authority, it does not
//!    unwind the past.
//!
//! This module is the document handling (shape, tagged signature, the matching
//! rule) and the typed refusal. Enforcement — checking at admission, before
//! any work — lives on [`crate::client::AgentMesh`], because it happens inside
//! the inbound dispatch. Mirrors `sdk-typescript/src/agreement.ts`; shapes
//! pinned by `conformance/commerce.json`.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::error::{ErrorCode, ErrorObject, MeshError, Result};
use crate::identity::{b64url, canonical_json, tagged_sig_bytes, unb64url, verify_tagged};
use crate::inbound::{now_ms, parse_instant_ms};
use nkeys::KeyPair;

/// The domain tag inside an agreement's signed bytes (§19.5): `sig` covers
/// this prefix + the canonical JSON of the document excluding `sig`. The
/// prefix exists only inside the signed bytes — it never appears in the
/// document itself. Pinned by `conformance/commerce.json`.
pub const AGREEMENT_SIG_PREFIX: &str = "agentmesh-agreement-v1\n";

/// Provider-side confirmation backing an agreement (§19.4/§19.5): a checkout
/// session, a mandate id. Informative to the mesh; authoritative on the
/// provider's own rail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementEvidence {
    pub provider: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#ref: Option<String>,
}

/// The §19.5 agreement document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementDocument {
    /// The document format version, the integer 1.
    pub v: u64,
    /// The consumer's OWNER key (§8.6) — the signer, and the account this
    /// agreement covers. Never an agent key.
    pub consumer_owner: String,
    /// The agent whose SKU this accepts.
    pub seller_agent: String,
    pub sku: String,
    /// The terms accepted: the SKU's tagged SHA-256 digest (§19.1).
    pub sku_digest: String,
    pub agreed_at: String,
    /// OPTIONAL. Absent means the agreement stands until revoked or the digest
    /// moves — both of which are ordinary, so an expiry is a convenience, not
    /// a safety mechanism.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<AgreementEvidence>,
    /// base64url Ed25519 over [`AGREEMENT_SIG_PREFIX`] + the canonical
    /// document excluding `sig`, by `consumer_owner`.
    pub sig: String,
}

fn invalid(message: impl Into<String>) -> MeshError {
    MeshError::code(ErrorCode::InvalidEnvelope, format!("agreement: {} (§19.5)", message.into()))
}

/// `^U[A-Z2-7]{55}$` — a user nkey (an owner or agent public key).
fn is_user_nkey(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 56
        && b[0] == b'U'
        && b[1..].iter().all(|c| c.is_ascii_uppercase() || (b'2'..=b'7').contains(c))
}

/// `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$` — the
/// same shape the TS validator pins, matched without a regex engine.
fn is_rfc3339_instant(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() < 20 {
        return false;
    }
    let d = |i: usize| b[i].is_ascii_digit();
    if !(d(0) && d(1) && d(2) && d(3) && b[4] == b'-' && d(5) && d(6) && b[7] == b'-')
        || !(d(8) && d(9) && b[10] == b'T' && d(11) && d(12) && b[13] == b':')
        || !(d(14) && d(15) && b[16] == b':' && d(17) && d(18))
    {
        return false;
    }
    let mut i = 19;
    if b[i] == b'.' {
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

/// Shape check over the raw JSON, per `conformance/commerce.json`
/// `agreement.invalid`. Signature is [`verify_agreement_signature`]'s job;
/// this is the shape alone.
pub fn validate_agreement(doc: &Value) -> Result<()> {
    if !(doc.is_object() || doc.is_array()) {
        return Err(invalid("must be an object"));
    }
    if doc.get("v").and_then(Value::as_f64) != Some(1.0) {
        return Err(invalid("v is the integer 1"));
    }
    match doc.get("consumer_owner").and_then(Value::as_str) {
        Some(k) if is_user_nkey(k) => {}
        _ => {
            return Err(invalid(
                "consumer_owner must be an owner nkey — the ACCOUNT, never an agent key",
            ));
        }
    }
    match doc.get("seller_agent").and_then(Value::as_str) {
        Some(k) if is_user_nkey(k) => {}
        _ => return Err(invalid("seller_agent must be an agent nkey")),
    }
    match doc.get("sku").and_then(Value::as_str) {
        Some(s) if !s.is_empty() => {}
        _ => return Err(invalid("sku is required")),
    }
    match doc.get("sku_digest").and_then(Value::as_str) {
        Some(s) if !s.is_empty() => {}
        _ => return Err(invalid("an agreement without a digest agrees to nothing")),
    }
    match doc.get("agreed_at").and_then(Value::as_str) {
        Some(s) if is_rfc3339_instant(s) => {}
        _ => return Err(invalid("agreed_at must be an RFC-3339 instant")),
    }
    if let Some(exp) = doc.get("expires_at") {
        if !exp.as_str().is_some_and(is_rfc3339_instant) {
            return Err(invalid("expires_at, when present, must be an RFC-3339 instant"));
        }
    }
    if let Some(evidence) = doc.get("evidence") {
        let provider_ok = (evidence.is_object() || evidence.is_array())
            && evidence.get("provider").and_then(Value::as_str).is_some_and(|p| !p.is_empty());
        if !provider_ok {
            return Err(invalid("evidence names the provider that confirmed it"));
        }
        if let Some(r) = evidence.get("ref") {
            if !r.is_string() {
                return Err(invalid("evidence.ref must be a string"));
            }
        }
    }
    match doc.get("sig").and_then(Value::as_str) {
        Some(s) if !s.is_empty() => {}
        _ => return Err(invalid("sig is required")),
    }
    Ok(())
}

/// The canonical bytes an agreement's `sig` covers, before tagging: the
/// canonical JSON (§5.3) of the document excluding `sig`.
pub fn canonical_agreement_bytes(doc: &Value) -> Result<Vec<u8>> {
    let mut v = doc.clone();
    let Some(map) = v.as_object_mut() else {
        return Err(invalid("must be an object"));
    };
    map.remove("sig");
    Ok(canonical_json(&v).into_bytes())
}

/// Verify `sig` against the document's own `consumer_owner` (§19.5).
/// Signature only — shape is [`validate_agreement`]'s job.
pub fn verify_agreement_signature(doc: &Value) -> bool {
    let Some(owner) = doc.get("consumer_owner").and_then(Value::as_str) else { return false };
    let Some(sig_str) = doc.get("sig").and_then(Value::as_str).filter(|s| !s.is_empty()) else {
        return false;
    };
    let Ok(sig) = unb64url(sig_str) else { return false };
    let Ok(canonical) = canonical_agreement_bytes(doc) else { return false };
    match KeyPair::from_public_key(owner) {
        Ok(vpub) => verify_tagged(&vpub, AGREEMENT_SIG_PREFIX, &canonical, &sig),
        Err(_) => false,
    }
}

/// Sign an agreement with the consumer's OWNER key. Sets `consumer_owner` to
/// the signing key's public key — the signer IS the account by definition, and
/// filling it here makes a mismatch impossible. The signed document is
/// shape-checked before this returns.
pub fn sign_agreement(doc: &mut AgreementDocument, owner_kp: &KeyPair) -> Result<()> {
    doc.consumer_owner = owner_kp.public_key();
    let mut v = serde_json::to_value(&*doc)?;
    if let Some(map) = v.as_object_mut() {
        map.remove("sig");
    }
    let bytes = tagged_sig_bytes(AGREEMENT_SIG_PREFIX, canonical_json(&v).as_bytes());
    let sig = owner_kp.sign(&bytes).map_err(|e| MeshError::Nkey(e.to_string()))?;
    doc.sig = b64url(&sig);
    validate_agreement(&serde_json::to_value(&*doc)?)?;
    Ok(())
}

/// Load an agreement: shape, then signature. `INVALID_ENVELOPE` on a shape
/// fault, `IDENTITY_MISMATCH` on a signature that does not verify. Callers
/// enforcing MUST fail closed on an `Err` — an unverifiable agreement is no
/// agreement, which is the safe direction here (it refuses work rather than
/// authorising it).
pub fn load_agreement(doc: &Value) -> Result<AgreementDocument> {
    validate_agreement(doc)?;
    if !verify_agreement_signature(doc) {
        return Err(MeshError::code(
            ErrorCode::IdentityMismatch,
            "Agreement signature does not verify against consumer_owner (§19.5) — treated as absent",
        ));
    }
    serde_json::from_value(doc.clone()).map_err(MeshError::from)
}

/// What [`agreement_covers`] is asked: does an agreement authorise THIS work?
#[derive(Debug, Clone)]
pub struct AgreementWant<'a> {
    pub consumer_owner: &'a str,
    pub seller_agent: &'a str,
    pub sku: &'a str,
    pub sku_digest: &'a str,
    /// The instant to judge expiry at, in epoch ms; `None` means now.
    pub now_ms: Option<i64>,
}

/// Does this agreement authorise this work, right now?
///
/// Every clause is a MUST, and the digest one is the load-bearing clause: an
/// agreement to yesterday's price does not cover today's. Expiry is compared
/// without a skew tolerance deliberately — unlike a §7.7 deadline, nothing
/// races here: the consumer re-approves, and a second either side of an
/// expiry changes nothing anyone can observe.
pub fn agreement_covers(doc: &AgreementDocument, want: &AgreementWant<'_>) -> bool {
    if doc.consumer_owner != want.consumer_owner
        || doc.seller_agent != want.seller_agent
        || doc.sku != want.sku
        || doc.sku_digest != want.sku_digest
    {
        return false;
    }
    if let Some(expires_at) = doc.expires_at.as_deref() {
        let Some(at) = parse_instant_ms(expires_at) else {
            return false; // an undatable expiry is expired
        };
        if want.now_ms.unwrap_or_else(now_ms) >= at {
            return false;
        }
    }
    true
}

/// What the refusal's `details` carries (§19.5 / `conformance/commerce.json`).
/// The field names are the protocol between implementations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementRequiredDetails {
    pub sku: String,
    pub sku_digest: String,
    pub approval_url: String,
}

/// Admission refusal: the requested work is covered by a paid SKU and the
/// consumer's account holds no agreement at its current digest (§19.5,
/// §12.2). Refused BEFORE any work — §1.3's "payment required", typed.
///
/// `approval_url` is where a human goes to accept: the provider's checkout
/// URL, or the deployment's own approval surface for the `internal` provider.
/// A refusal without one is a dead end, so it is required rather than
/// optional.
pub fn agreement_required(details: AgreementRequiredDetails, message: Option<String>) -> MeshError {
    let message = message.unwrap_or_else(|| {
        format!(
            "Refused at admission: '{}' is a paid offering and this account holds no agreement \
             for its current terms (§19.5). Approve at {}",
            details.sku, details.approval_url,
        )
    });
    MeshError::Refusal(ErrorObject {
        code: ErrorCode::AgreementRequired.as_str().to_string(),
        message,
        details: Some(json!({
            "sku": details.sku,
            "sku_digest": details.sku_digest,
            "approval_url": details.approval_url,
        })),
        retryable: false,
        retry_after_ms: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_shapes() {
        for ok in [
            "2026-08-02T15:00:00Z",
            "2026-08-02T15:00:00.123Z",
            "2026-08-02T15:00:00+02:00",
            "2026-08-02T15:00:00.5-07:00",
        ] {
            assert!(is_rfc3339_instant(ok), "{ok}");
        }
        for nope in [
            "2026-08-02",
            "2026-08-02T15:00:00",
            "2026-08-02T15:00:00.Z",
            "2026-08-02 15:00:00Z",
            "2026-08-02T15:00:00+0200",
            "2026-08-02T15:00:00Zx",
        ] {
            assert!(!is_rfc3339_instant(nope), "{nope}");
        }
    }

    #[test]
    fn sign_load_and_cover() {
        let owner = KeyPair::new_user();
        let seller = KeyPair::new_user().public_key();
        let mut doc = AgreementDocument {
            v: 1,
            consumer_owner: String::new(),
            seller_agent: seller.clone(),
            sku: "caselaw-metered".into(),
            sku_digest: "LQGAJJ9tQ7U185dmHGSztJzvPN55p_V_j-XcauUNDKk".into(),
            agreed_at: "2026-08-02T15:00:00Z".into(),
            expires_at: None,
            evidence: None,
            sig: String::new(),
        };
        sign_agreement(&mut doc, &owner).unwrap();
        assert_eq!(doc.consumer_owner, owner.public_key());
        let v = serde_json::to_value(&doc).unwrap();
        let loaded = load_agreement(&v).unwrap();
        assert!(agreement_covers(
            &loaded,
            &AgreementWant {
                consumer_owner: &owner.public_key(),
                seller_agent: &seller,
                sku: "caselaw-metered",
                sku_digest: "LQGAJJ9tQ7U185dmHGSztJzvPN55p_V_j-XcauUNDKk",
                now_ms: None,
            }
        ));
        // The load-bearing clause: a moved digest is a missing agreement.
        assert!(!agreement_covers(
            &loaded,
            &AgreementWant {
                consumer_owner: &owner.public_key(),
                seller_agent: &seller,
                sku: "caselaw-metered",
                sku_digest: "VW6g3eB7qGHnu6zH3w5Jy10YdjR09p37r5P9Dku6e1E",
                now_ms: None,
            }
        ));
        // Tampered terms: flip the digest in the signed doc, verification fails.
        let mut tampered = v.clone();
        tampered["sku_digest"] = serde_json::json!("VW6g3eB7qGHnu6zH3w5Jy10YdjR09p37r5P9Dku6e1E");
        assert!(load_agreement(&tampered).is_err());
    }

    #[test]
    fn expiry_is_a_hard_edge() {
        let owner = KeyPair::new_user();
        let seller = KeyPair::new_user().public_key();
        let mut doc = AgreementDocument {
            v: 1,
            consumer_owner: String::new(),
            seller_agent: seller.clone(),
            sku: "s".into(),
            sku_digest: "d".into(),
            agreed_at: "2026-08-02T15:00:00Z".into(),
            expires_at: Some("2026-08-03T00:00:00Z".into()),
            evidence: None,
            sig: String::new(),
        };
        sign_agreement(&mut doc, &owner).unwrap();
        let at = parse_instant_ms("2026-08-03T00:00:00Z").unwrap();
        let want = |now: i64| AgreementWant {
            consumer_owner: &doc.consumer_owner,
            seller_agent: &seller,
            sku: "s",
            sku_digest: "d",
            now_ms: Some(now),
        };
        assert!(agreement_covers(&doc, &want(at - 1)));
        assert!(!agreement_covers(&doc, &want(at))); // >= expiry is expired
    }
}
