//! Agent identity and per-envelope signing (AgentMesh 0.2 §4–5).
//!
//! Mirrors the TS SDK's `identity.ts`. The canonical-JSON procedure here MUST
//! produce byte-identical output to the TS `canonicalJSON`, so an envelope
//! signed by a TS agent verifies in Rust and vice versa. Keys are NATS nkeys
//! (Ed25519); an agent's public nkey is its agent ID.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{Duration, Utc};
use nkeys::KeyPair;
use serde_json::Value;

use crate::envelope::Envelope;
use crate::error::{ErrorCode, MeshError, Result};
use crate::manifest::{AgentAttestation, Manifest};

// ── canonical JSON (deterministic, for signing) ─────────────────────────────

/// Canonical JSON per RFC 8785 (JCS) — SPEC.md §5.3. Matches the TS
/// `canonicalJSON` byte for byte; `conformance/canonical-json.json` pins the
/// bytes from both sides (`tests/canonical_json.rs`).
///
/// Delegates to `serde_jcs`, which was source-reviewed and vector-tested against
/// RFC 8785 Appendix B before adoption (2026-07-27). What it settles that a
/// hand-rolled serializer got wrong here before:
///
/// - **Numbers** serialize per ECMAScript `Number::toString` (ECMA-262
///   §7.1.12.1) via ryu-js — shortest round-trip digits, plain decimal notation
///   for magnitudes in [1e-6, 1e21), exponent form outside it, `-0.0` as `0`.
///   serde_json's own formatting used different exponent thresholds (`1e+20`
///   where JCS says `100000000000000000000`, `1e-6` where JCS says `0.000001`)
///   and printed integral floats as `10.0`.
/// - **All numbers are IEEE-754 doubles** (RFC 8785 §3.2.2.3): an i64/u64 with
///   magnitude above 2^53 rounds to the nearest double, exactly as it would in
///   JavaScript. serde_json printed such integers exactly — bytes TypeScript
///   cannot produce, i.e. a signature no TS agent could ever verify.
/// - **Object keys sort by UTF-16 code units** (RFC 8785 §3.2.3). Rust string
///   `Ord` is UTF-8 byte order, which flips the order of a non-BMP key against
///   a key in U+E000..U+FFFF.
///
/// String escaping is unchanged: serde_json's escaping (`\b \t \n \f \r`,
/// lowercase `\u00hh` for the other controls, solidus and U+2028/U+2029
/// unescaped) already matched `JSON.stringify` and RFC 8785 §3.2.2.2.
pub fn canonical_json(v: &Value) -> String {
    // Cannot fail for a `serde_json::Value`: the writer is a Vec and a `Value`
    // holds no non-finite floats (`Number::from_f64` refuses them).
    serde_jcs::to_string(v).expect("JCS serialization of a serde_json::Value cannot fail")
}

/// Canonical bytes of an envelope — the canonical JSON excluding `sig`. NOT the
/// signed bytes on their own: the signature covers `ENVELOPE_SIG_PREFIX` + these
/// bytes (§5.3). Kept separate because fixtures pin the canonical JSON and the
/// prefix independently.
pub fn canonical_envelope_bytes(env: &Envelope) -> Result<Vec<u8>> {
    let mut v = serde_json::to_value(env)?;
    if let Value::Object(ref mut map) = v {
        map.remove("sig");
    }
    Ok(canonical_json(&v).into_bytes())
}

/// The domain tag inside the envelope's signed bytes (§5.3). A signature over
/// bare canonical JSON cannot say what it is — it can be replayed into any
/// other context that signs the same shape — so the signed bytes carry a
/// versioned prefix, exactly as the §8.3 key claim
/// (`agentmesh-manifest-key-v1`) and the §9.7 trust attestation
/// (`agentmesh-trust-attestation-v1`) already do. The prefix never appears in
/// the envelope itself and the `sig` encoding is unchanged. The vouch (§4.4)
/// and the room descriptor (EXT-5 §2) carry sibling prefixes through the
/// shared tagged-sign/tagged-verify machinery below.
pub const ENVELOPE_SIG_PREFIX: &str = "agentmesh-envelope-v1\n";

/// The domain tag inside a node→agent vouch attestation's signed bytes (§4.4).
pub const VOUCH_SIG_PREFIX: &str = "agentmesh-vouch-v1\n";

/// The bytes an envelope's `sig` covers (§5.3): `ENVELOPE_SIG_PREFIX` + the
/// canonical envelope JSON (all fields except `sig`).
pub fn signed_envelope_bytes(env: &Envelope) -> Result<Vec<u8>> {
    Ok(tagged_sig_bytes(ENVELOPE_SIG_PREFIX, &canonical_envelope_bytes(env)?))
}

// ── tagged canonical-JSON signatures (shared machinery) ─────────────────────
//
// Every canonical-JSON signature in the system covers `<prefix>` + the
// canonical JSON of the object excluding `sig`, where the prefix is a
// versioned ASCII domain tag ending in one newline (0x0A). The prefix exists
// only inside the signed bytes — never in the signed object — and the
// signature's encoding is unchanged. One sign path and one verify path,
// parameterized by prefix, so the envelope, the vouch and the room descriptor
// cannot drift apart in how they apply or migrate the tag.

/// `prefix` + `canonical`: the bytes a tagged signature covers.
pub(crate) fn tagged_sig_bytes(prefix: &str, canonical: &[u8]) -> Vec<u8> {
    let mut bytes = prefix.as_bytes().to_vec();
    bytes.extend_from_slice(canonical);
    bytes
}

/// Verify a tagged canonical-JSON signature: the tagged form, and only the
/// tagged form.
///
/// The 0.2 draft window carried a dual-accept here (on a tagged failure, a
/// second try over the bare canonical JSON) so signatures minted before the
/// tag existed kept verifying while everything re-signed. §5.3 closed that
/// window at protocol 0.3: verifiers MUST refuse the untagged form, because a
/// signature over bare canonical JSON cannot say what it is and can be
/// replayed into any other context that signs the same shape. The fallback is
/// deleted rather than gated: nothing in this crate audits pre-0.2 archives,
/// and an off-by-default flag that re-opens a signature bypass is a liability,
/// not a feature.
pub(crate) fn verify_tagged(vpub: &KeyPair, prefix: &str, canonical: &[u8], sig: &[u8]) -> bool {
    vpub.verify(&tagged_sig_bytes(prefix, canonical), sig).is_ok()
}

// ── base64url ───────────────────────────────────────────────────────────────

pub(crate) fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}
pub(crate) fn unb64url(s: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(s.as_bytes())
        .map_err(|e| MeshError::Nkey(format!("base64: {e}")))
}

// ── keypairs ────────────────────────────────────────────────────────────────

/// Create a fresh agent identity: the public nkey (agent ID) and the seed to
/// persist (keep the seed secret — it is the private key).
pub fn create_agent_identity() -> Result<(String, String)> {
    let kp = KeyPair::new_user();
    let public = kp.public_key();
    let seed = kp.seed().map_err(|e| MeshError::Nkey(e.to_string()))?;
    Ok((public, seed))
}

/// Reconstruct a keypair from a persisted seed string.
pub fn keypair_from_seed(seed: &str) -> Result<KeyPair> {
    KeyPair::from_seed(seed).map_err(|e| MeshError::Nkey(e.to_string()))
}

// ── envelope signing / verification ─────────────────────────────────────────

/// Sign an envelope in place with the agent keypair, setting `sig`. Signs the
/// tagged form (`ENVELOPE_SIG_PREFIX` + canonical JSON, §5.3).
pub fn sign_envelope(env: &mut Envelope, kp: &KeyPair) -> Result<()> {
    let bytes = signed_envelope_bytes(env)?;
    let sig = kp.sign(&bytes).map_err(|e| MeshError::Nkey(e.to_string()))?;
    env.sig = Some(b64url(&sig));
    Ok(())
}

/// Verify an envelope's `sig` against its `from` agent public key.
///
/// Tagged form only (§5.3). The 0.2 draft window's dual-accept, the legacy
/// untagged fallback, closed at protocol 0.3; an untagged signature is
/// refused like any other bad signature.
pub fn verify_envelope_sig(env: &Envelope) -> bool {
    let Some(sig_str) = env.sig.as_ref() else { return false };
    let Ok(sig) = unb64url(sig_str) else { return false };
    let Ok(canonical) = canonical_envelope_bytes(env) else { return false };
    match KeyPair::from_public_key(&env.from) {
        Ok(vpub) => verify_tagged(&vpub, ENVELOPE_SIG_PREFIX, &canonical, &sig),
        Err(_) => false,
    }
}

// ── manifest key claim (§8.3) ───────────────────────────────────────────────

/// The domain tag for the manifest's signed claim. Same convention as every
/// other signature in the system (`pan-pair-v1`, `pan-rehome-v1`,
/// `agentmesh-trust-attestation-v1`): the signed bytes say what they ARE, so a
/// verifier rejects a format it does not know instead of misreading it, and a v2
/// can cover more without invalidating a single v1 signature already issued.
pub const MANIFEST_KEY_CLAIM_TYPE: &str = "agentmesh-manifest-key-v1";

/// The canonical bytes of a v1 manifest key claim — UTF-8, newline-joined, no
/// trailing newline:
///
/// ```text
/// agentmesh-manifest-key-v1\n<issued_at>\n<id>\n<encryption_key>
/// ```
///
/// The claim is load-bearing for exactly one thing: key substitution when
/// sealing (§7.3). An attacker who can answer `mesh.registry.get.<id>` puts its
/// own X25519 key in the reply and the room key is sealed to it — it reads every
/// `say` and artifact in a room it was never admitted to, and neither party sees
/// an error. What must be authentic to stop that is the BINDING between an agent
/// id and its encryption key; nothing else in a manifest has that property, so
/// nothing else is covered. `owner`/`visibility`/`sandbox` are rewritten by the
/// registry after the agent signs, and `interaction` is explicitly not a security
/// boundary (§8.3a) and already fails safe (absent reads as `interactive`).
///
/// A newline-joined string rather than canonical JSON, deliberately: JSON brings
/// key ordering, string escaping, number formatting and absent-vs-null to a claim
/// made of three strings — four ways for this SDK and the TS one to drift, for no
/// benefit. Always exactly FOUR components: an absent `encryption_key` is the
/// empty string, so the bytes end with the separator and there is no second
/// shape to get wrong. Only the last component is unbounded, so the encoding is
/// unambiguous; components carrying a newline are refused rather than allowed to
/// shift the framing.
///
/// Byte-identical to the TS SDK's `manifestKeyClaimBytes`, pinned by
/// `conformance/manifest-signing.json` (see `tests/manifest_signing.rs`).
pub fn manifest_key_claim_bytes(id: &str, encryption_key: &str, issued_at: &str) -> Result<Vec<u8>> {
    for part in [issued_at, id, encryption_key] {
        if part.contains('\n') {
            return Err(MeshError::code(
                ErrorCode::InvalidEnvelope,
                "manifest key claim components must not contain a newline (§8.3)",
            ));
        }
    }
    Ok(format!("{MANIFEST_KEY_CLAIM_TYPE}\n{issued_at}\n{id}\n{encryption_key}").into_bytes())
}

/// Sign a manifest's key claim with the agent's own key (§8.3), setting
/// `trust.issued_at` and `trust.signature`. Other `trust` fields (e.g. `tenant`)
/// are preserved.
///
/// `issued_at` is minted as `...T00:00:00.000Z` (millisecond precision, `Z`
/// suffix) to match the TS SDK's `Date.toISOString()`. It rides inside the signed
/// bytes and is published next to the signature, so the format only has to be
/// self-consistent — but two SDKs that stamp the same instant differently make
/// every cross-implementation fixture a special case, so they do not.
pub fn sign_manifest(manifest: &mut Manifest, kp: &KeyPair) -> Result<()> {
    sign_manifest_at(manifest, kp, &now_rfc3339_millis())
}

/// `sign_manifest` with the instant supplied — the seam the conformance fixture
/// needs, since a signature over "now" is not reproducible.
pub fn sign_manifest_at(manifest: &mut Manifest, kp: &KeyPair, issued_at: &str) -> Result<()> {
    let bytes = manifest_key_claim_bytes(
        &manifest.id,
        manifest.encryption_key.as_deref().unwrap_or(""),
        issued_at,
    )?;
    let sig = kp.sign(&bytes).map_err(|e| MeshError::Nkey(e.to_string()))?;
    let mut trust = manifest.trust.take().unwrap_or_default();
    trust.issued_at = Some(issued_at.to_string());
    trust.signature = Some(b64url(&sig));
    manifest.trust = Some(trust);
    Ok(())
}

/// RFC 3339 UTC with millisecond precision and a `Z` suffix — the shape
/// JavaScript's `Date.toISOString()` produces.
pub(crate) fn now_rfc3339_millis() -> String {
    Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// Verify a manifest's `trust.signature` as the agent's own §8.3 key claim.
/// False on an absent, malformed or non-verifying claim.
///
/// What a true answer means, exactly: the agent whose key is `id` declared this
/// `encryption_key` (or declared none) at `issued_at`. It says nothing about the
/// rest of the manifest, nothing about whether the registry that served it is
/// honest, and nothing about the fields the registry rewrites.
pub fn verify_manifest_signature(manifest: &Manifest) -> bool {
    let Some(trust) = manifest.trust.as_ref() else { return false };
    let (Some(sig_str), Some(issued_at)) = (trust.signature.as_deref(), trust.issued_at.as_deref())
    else {
        return false;
    };
    if sig_str.is_empty() || issued_at.is_empty() || manifest.id.is_empty() {
        return false;
    }
    let Ok(sig) = unb64url(sig_str) else { return false };
    let Ok(bytes) = manifest_key_claim_bytes(
        &manifest.id,
        manifest.encryption_key.as_deref().unwrap_or(""),
        issued_at,
    ) else {
        return false;
    };
    match KeyPair::from_public_key(&manifest.id) {
        Ok(vpub) => vpub.verify(&bytes, &sig).is_ok(),
        Err(_) => false,
    }
}

// ── node vouching (attestations, §4.4) ──────────────────────────────────────

/// A node vouches for a hosted agent by signing a node→agent attestation.
/// The signed bytes are the tagged form (§4.4): `VOUCH_SIG_PREFIX` + the
/// canonical JSON of the attestation excluding `sig`.
pub fn create_attestation(node_kp: &KeyPair, agent_public: &str, ttl_ms: i64) -> Result<AgentAttestation> {
    let now = Utc::now();
    let mut att = AgentAttestation {
        node: node_kp.public_key(),
        agent: agent_public.to_string(),
        issued_at: now.to_rfc3339(),
        expires_at: (now + Duration::milliseconds(ttl_ms)).to_rfc3339(),
        sig: String::new(),
    };
    let mut v = serde_json::to_value(&att)?;
    if let Value::Object(ref mut map) = v {
        map.remove("sig");
    }
    let sig = node_kp
        .sign(&tagged_sig_bytes(VOUCH_SIG_PREFIX, canonical_json(&v).as_bytes()))
        .map_err(|e| MeshError::Nkey(e.to_string()))?;
    att.sig = b64url(&sig);
    Ok(att)
}

/// Verify a node→agent attestation's signature (and optionally the bound
/// agent). Tagged form only (§4.4): the 0.2 dual-accept closed at protocol
/// 0.3, so a legacy untagged attestation is refused.
pub fn verify_attestation(att: &AgentAttestation, expected_agent: Option<&str>) -> bool {
    if let Some(a) = expected_agent {
        if att.agent != a {
            return false;
        }
    }
    let mut v = match serde_json::to_value(att) {
        Ok(v) => v,
        Err(_) => return false,
    };
    if let Value::Object(ref mut map) = v {
        map.remove("sig");
    }
    let Ok(sig) = unb64url(&att.sig) else { return false };
    match KeyPair::from_public_key(&att.node) {
        Ok(vpub) => verify_tagged(&vpub, VOUCH_SIG_PREFIX, canonical_json(&v).as_bytes(), &sig),
        Err(_) => false,
    }
}
