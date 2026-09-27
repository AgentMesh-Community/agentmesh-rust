//! Sealed-grade cryptography for rooms (mesh://extensions/rooms/v1 §7.3).
//!
//! Mirrors the TS SDK's `internal/sealed.ts` and is wire-compatible with it:
//! the agent encryption key is X25519, the room key is distributed with a NaCl
//! box (curve25519-xsalsa20-poly1305), and message bodies and artifact bytes
//! are sealed with a NaCl secretbox (xsalsa20-poly1305). A key sealed by a TS
//! agent opens in Rust and vice versa.
//!
//! The encryption keypair is distinct from the Ed25519 signing keypair (core
//! §4.3): signing proves who wrote a thing, the encryption key lets others seal
//! things TO the agent. Its public half travels in the manifest and on the PAN
//! card; the room key travels only sealed to it, and never enters the record.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use crypto_box::{
    aead::{Aead, AeadCore, OsRng},
    PublicKey, SalsaBox, SecretKey,
};
use crypto_secretbox::{aead::KeyInit, XSalsa20Poly1305};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

use crate::error::{MeshError, Result};

const BODY_PREFIX: &str = "sealed:";

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}
fn unb64(s: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(s.trim().as_bytes())
        .map_err(|e| MeshError::Nkey(format!("base64: {e}")))
}
fn arr32(v: &[u8]) -> Result<[u8; 32]> {
    v.try_into().map_err(|_| MeshError::Nkey("expected 32 bytes".into()))
}

/// A room key sealed to one member's X25519 public key (the invite payload).
/// Wire-identical to the TS `SealedKey`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedKey {
    pub v: String,
    /// Ephemeral sender public key (base64url).
    pub epk: String,
    pub nonce: String,
    pub ct: String,
}

/// Create an agent encryption identity: `(public_b64url, secret_b64url)`.
/// Persist the secret (it is the private key); publish the public half in the
/// manifest and on the PAN card.
pub fn create_encryption_identity() -> (String, String) {
    let sk = SecretKey::generate(&mut OsRng);
    let pk = sk.public_key();
    (b64(pk.as_bytes()), b64(&sk.to_bytes()))
}

/// Derive the encryption public key from a persisted secret.
pub fn encryption_public_from_seed(seed: &str) -> Result<String> {
    let sk = SecretKey::from_bytes(arr32(&unb64(seed)?)?);
    Ok(b64(sk.public_key().as_bytes()))
}

/// A fresh 32-byte room key. Possession of it IS membership at the sealed grade.
pub fn new_room_key() -> [u8; 32] {
    use rand::RngCore;
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

/// Room-key fingerprint (descriptor `key_fingerprint`): first 16 bytes of
/// SHA-512(key), base64url. Matches TS.
pub fn room_key_fingerprint(key: &[u8]) -> String {
    let digest = Sha512::digest(key);
    b64(&digest[..16])
}

/// Seal the room key to a recipient's X25519 public key with an ephemeral
/// sender keypair (NaCl box). The result rides in the `rooms.invite` payload.
pub fn seal_key_to(room_key: &[u8], recipient_public_b64: &str) -> Result<SealedKey> {
    let recipient = PublicKey::from(arr32(&unb64(recipient_public_b64)?)?);
    let eph = SecretKey::generate(&mut OsRng);
    let epk = eph.public_key();
    let boxx = SalsaBox::new(&recipient, &eph);
    let nonce = SalsaBox::generate_nonce(&mut OsRng);
    let ct = boxx
        .encrypt(&nonce, room_key)
        .map_err(|e| MeshError::Nkey(format!("seal: {e}")))?;
    Ok(SealedKey {
        v: "sealedkey.v1".to_string(),
        epk: b64(epk.as_bytes()),
        nonce: b64(nonce.as_slice()),
        ct: b64(&ct),
    })
}

/// Open a sealed room key with this agent's encryption secret.
pub fn open_sealed_key(sealed: &SealedKey, recipient_seed: &str) -> Result<[u8; 32]> {
    if sealed.v != "sealedkey.v1" {
        return Err(MeshError::Nkey("unrecognized sealed-key format".into()));
    }
    let sk = SecretKey::from_bytes(arr32(&unb64(recipient_seed)?)?);
    let epk = PublicKey::from(arr32(&unb64(&sealed.epk)?)?);
    let boxx = SalsaBox::new(&epk, &sk);
    let nonce = unb64(&sealed.nonce)?;
    let pt = boxx
        .decrypt(nonce.as_slice().into(), unb64(&sealed.ct)?.as_slice())
        .map_err(|_| MeshError::Nkey("sealed room key did not open (wrong recipient key?)".into()))?;
    arr32(&pt)
}

// ─── EXT-7: the pairwise profile (direct messages) ──────────────────────────

/// The `v` discriminator of a pairwise-sealed payload (EXT-7). Also the marker
/// §22.6 fencing checks for, so it leaves ciphertext alone.
pub const SEALED_PAYLOAD_V1: &str = "sealedpayload.v1";

/// A request/response payload sealed to one agent's X25519 public key — the
/// pairwise profile of `mesh://extensions/e2e-encryption/v1`. Wire-identical to
/// the TS `SealedPayload`.
///
/// The outer keypair is **ephemeral**: the box carries no durable sender key, so
/// it adds nothing to what the envelope signature already says about who sent
/// this. `reply_key` names the key the responder SHOULD seal its answer to; it
/// rides outside the box, so see [`resolve_reply_key`] before honouring it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedPayload {
    pub v: String,
    /// Ephemeral sender public key for this box (base64url).
    pub epk: String,
    pub nonce: String,
    pub ct: String,
    /// Where to seal the reply (the sender's durable encryption key).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_key: Option<String>,
}

/// What [`open_sealed_payload`] yields: the plaintext payload and the key the
/// sender asked to have its reply sealed to.
#[derive(Debug, Clone)]
pub struct OpenedPayload {
    pub payload: serde_json::Value,
    pub reply_key: Option<String>,
}

/// Seal a payload to a recipient's declared X25519 public key with a fresh
/// ephemeral sender keypair. The plaintext is the payload's JSON — an absent
/// payload seals as `null`, matching TS's `JSON.stringify(payload ?? null)`.
pub fn seal_payload_to(
    payload: &serde_json::Value,
    recipient_public_b64: &str,
    reply_key_b64: Option<&str>,
) -> Result<SealedPayload> {
    let recipient = PublicKey::from(arr32(&unb64(recipient_public_b64)?)?);
    let eph = SecretKey::generate(&mut OsRng);
    let epk = eph.public_key();
    let boxx = SalsaBox::new(&recipient, &eph);
    let nonce = SalsaBox::generate_nonce(&mut OsRng);
    let plaintext = serde_json::to_vec(payload)?;
    let ct = boxx
        .encrypt(&nonce, plaintext.as_slice())
        .map_err(|e| MeshError::Nkey(format!("seal payload: {e}")))?;
    Ok(SealedPayload {
        v: SEALED_PAYLOAD_V1.to_string(),
        epk: b64(epk.as_bytes()),
        nonce: b64(nonce.as_slice()),
        ct: b64(&ct),
        reply_key: reply_key_b64.map(str::to_string),
    })
}

/// Open a sealed payload with this agent's encryption secret. `None` on any
/// failure — wrong key, tampered box, garbage — because a failed unseal is not
/// a condition a recipient can distinguish or should act on differently.
pub fn open_sealed_payload(p: &SealedPayload, recipient_seed: &str) -> Option<OpenedPayload> {
    if p.v != SEALED_PAYLOAD_V1 {
        return None;
    }
    let sk = SecretKey::from_bytes(arr32(&unb64(recipient_seed).ok()?).ok()?);
    let epk = PublicKey::from(arr32(&unb64(&p.epk).ok()?).ok()?);
    let boxx = SalsaBox::new(&epk, &sk);
    let nonce = unb64(&p.nonce).ok()?;
    let pt = boxx
        .decrypt(nonce.as_slice().into(), unb64(&p.ct).ok()?.as_slice())
        .ok()?;
    Some(OpenedPayload {
        payload: serde_json::from_slice(&pt).ok()?,
        reply_key: p.reply_key.clone(),
    })
}

/// [`open_sealed_payload`] against an untyped JSON value: the shape the
/// request/respond path actually holds. `None` when the value is not a sealed
/// payload at all, as well as when it is one that does not open, because both
/// mean the same thing to a caller — there is no plaintext here.
pub fn open_sealed_value(v: &serde_json::Value, recipient_seed: &str) -> Option<OpenedPayload> {
    if v.get("v").and_then(serde_json::Value::as_str) != Some(SEALED_PAYLOAD_V1) {
        return None;
    }
    let sealed: SealedPayload = serde_json::from_value(v.clone()).ok()?;
    open_sealed_payload(&sealed, recipient_seed)
}

/// The key a reply may be sealed to, given what the requester **asked for**
/// (`reply_key`, from the opened payload) and what the sender has **published**
/// (its manifest's verified `encryption_key`). `None` means do not seal: answer
/// in the clear, or refuse, but do not encrypt to this key.
///
/// `reply_key` rides outside the box as a sibling of `ct`. On SDK paths the
/// envelope signature covers it, so it cannot be altered in flight — but on its
/// own it is just a string the requester chose, decoupled from the identity the
/// envelope proves. Resolving it against the sender's published key re-couples
/// the two: seal to the key the sender's signed manifest declares, and treat a
/// `reply_key` that disagrees as a refusal rather than quietly honouring it.
pub fn resolve_reply_key(claimed: Option<&str>, declared: Option<&str>) -> Option<String> {
    let declared = declared?;
    if matches!(claimed, Some(c) if c != declared) {
        return None;
    }
    Some(declared.to_string())
}

fn secretbox(key: &[u8]) -> Result<XSalsa20Poly1305> {
    XSalsa20Poly1305::new_from_slice(key).map_err(|e| MeshError::Nkey(format!("key: {e}")))
}

/// Encrypt a `say` body under the room key. Wire form:
/// `sealed:<nonce-b64url>:<ct-b64url>`.
pub fn seal_body(body: &str, room_key: &[u8]) -> Result<String> {
    let cipher = secretbox(room_key)?;
    let nonce = XSalsa20Poly1305::generate_nonce(&mut OsRng);
    let ct = cipher
        .encrypt(&nonce, body.as_bytes())
        .map_err(|e| MeshError::Nkey(format!("seal body: {e}")))?;
    Ok(format!("{BODY_PREFIX}{}:{}", b64(nonce.as_slice()), b64(&ct)))
}

pub fn is_sealed_body(body: &str) -> bool {
    body.starts_with(BODY_PREFIX)
}

/// Decrypt a sealed body; `None` on any failure (wrong key, malformed).
pub fn open_body(body: &str, room_key: &[u8]) -> Option<String> {
    let rest = body.strip_prefix(BODY_PREFIX)?;
    let (nonce_b64, ct_b64) = rest.split_once(':')?;
    let nonce = unb64(nonce_b64).ok()?;
    let ct = unb64(ct_b64).ok()?;
    let cipher = secretbox(room_key).ok()?;
    let pt = cipher.decrypt(nonce.as_slice().into(), ct.as_slice()).ok()?;
    String::from_utf8(pt).ok()
}

/// Encrypt artifact bytes: the stored blob is `nonce(24) || secretbox(data)`.
/// The digest is taken over this stored blob, so the store can verify integrity
/// without the key.
pub fn seal_bytes(data: &[u8], room_key: &[u8]) -> Result<Vec<u8>> {
    let cipher = secretbox(room_key)?;
    let nonce = XSalsa20Poly1305::generate_nonce(&mut OsRng);
    let ct = cipher
        .encrypt(&nonce, data)
        .map_err(|e| MeshError::Nkey(format!("seal bytes: {e}")))?;
    let mut out = Vec::with_capacity(nonce.len() + ct.len());
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypt a `nonce(24) || secretbox(data)` blob; `None` on failure.
pub fn open_bytes(blob: &[u8], room_key: &[u8]) -> Option<Vec<u8>> {
    if blob.len() <= 24 {
        return None;
    }
    let (nonce, ct) = blob.split_at(24);
    let cipher = secretbox(room_key).ok()?;
    cipher.decrypt(nonce.into(), ct).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_seal_round_trips_and_rejects_others() {
        let (a_pub, a_sec) = create_encryption_identity();
        let (_b_pub, b_sec) = create_encryption_identity();
        let key = new_room_key();
        let sealed = seal_key_to(&key, &a_pub).unwrap();
        assert_eq!(open_sealed_key(&sealed, &a_sec).unwrap(), key);
        assert!(open_sealed_key(&sealed, &b_sec).is_err());
    }

    #[test]
    fn public_is_stable_from_seed() {
        let (pubk, sec) = create_encryption_identity();
        assert_eq!(encryption_public_from_seed(&sec).unwrap(), pubk);
    }

    #[test]
    fn body_and_bytes_round_trip() {
        let key = new_room_key();
        let wire = seal_body("confidential", &key).unwrap();
        assert!(is_sealed_body(&wire) && !wire.contains("confidential"));
        assert_eq!(open_body(&wire, &key).as_deref(), Some("confidential"));
        assert!(open_body(&wire, &new_room_key()).is_none());

        let data = b"quarterly numbers 42";
        let blob = seal_bytes(data, &key).unwrap();
        assert!(!blob.windows(9).any(|w| w == b"quarterly"));
        assert_eq!(open_bytes(&blob, &key).unwrap(), data);
        assert!(open_bytes(&blob, &new_room_key()).is_none());
    }

    #[test]
    fn pairwise_payload_round_trips_and_rejects_others() {
        let (a_pub, a_sec) = create_encryption_identity();
        let (b_pub, b_sec) = create_encryption_identity();
        let payload = serde_json::json!({ "text": "quarterly numbers", "n": 42 });

        let sealed = seal_payload_to(&payload, &a_pub, Some(&b_pub)).unwrap();
        assert_eq!(sealed.v, SEALED_PAYLOAD_V1);
        // The plaintext must not survive anywhere in the wire form.
        let wire = serde_json::to_string(&sealed).unwrap();
        assert!(!wire.contains("quarterly"));
        assert!(crate::inbound::is_sealed_payload(&serde_json::to_value(&sealed).unwrap()));

        let opened = open_sealed_payload(&sealed, &a_sec).expect("recipient opens it");
        assert_eq!(opened.payload, payload);
        assert_eq!(opened.reply_key.as_deref(), Some(b_pub.as_str()));

        // Anyone else gets nothing — and learns nothing from the failure.
        assert!(open_sealed_payload(&sealed, &b_sec).is_none());
    }

    #[test]
    fn a_null_payload_seals_and_opens_as_null() {
        let (pubk, sec) = create_encryption_identity();
        let sealed = seal_payload_to(&serde_json::Value::Null, &pubk, None).unwrap();
        assert!(sealed.reply_key.is_none());
        assert_eq!(open_sealed_payload(&sealed, &sec).unwrap().payload, serde_json::Value::Null);
    }

    #[test]
    fn a_tampered_box_does_not_open() {
        let (pubk, sec) = create_encryption_identity();
        let mut sealed = seal_payload_to(&serde_json::json!({ "a": 1 }), &pubk, None).unwrap();
        // Flip the last ciphertext character to something else in the alphabet.
        let mut ct = sealed.ct.clone();
        let last = ct.pop().unwrap();
        ct.push(if last == 'A' { 'B' } else { 'A' });
        sealed.ct = ct;
        assert!(open_sealed_payload(&sealed, &sec).is_none());
    }

    #[test]
    fn reply_key_resolves_only_when_the_claim_matches_the_published_key() {
        // Nothing published: never seal, whatever was claimed.
        assert_eq!(resolve_reply_key(None, None), None);
        assert_eq!(resolve_reply_key(Some("KCLAIM"), None), None);
        // Published and unclaimed: seal to what the sender published.
        assert_eq!(resolve_reply_key(None, Some("KPUB")), Some("KPUB".to_string()));
        // Agreement: seal. Disagreement: refuse rather than honour the claim.
        assert_eq!(resolve_reply_key(Some("KPUB"), Some("KPUB")), Some("KPUB".to_string()));
        assert_eq!(resolve_reply_key(Some("KOTHER"), Some("KPUB")), None);
    }

    #[test]
    fn fingerprint_matches_shape() {
        let key = new_room_key();
        // 16 bytes → 22 base64url chars, no padding.
        assert_eq!(room_key_fingerprint(&key).len(), 22);
    }
}
