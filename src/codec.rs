//! Wire codec (AgentMesh 0.2 §5). `decode` performs structural validation +
//! signature verification against `from` (§5.3), mirroring the TS SDK.
//!
//! IMPORTANT: verification runs over the RECEIVED JSON (parse → drop `sig` →
//! canonicalize), never over a struct re-serialization. A struct round-trip
//! silently changes the byte stream — optional fields another implementation
//! signed as explicit `null` get omitted, and fields this struct doesn't know
//! about get dropped — which breaks cross-implementation verification.

use serde_json::Value;

use crate::envelope::{Envelope, PROTOCOL_VERSION};
use crate::error::{ErrorCode, MeshError, Result};
use crate::identity::{canonical_json, unb64url, ENVELOPE_SIG_PREFIX};
use nkeys::KeyPair;

/// Encode an envelope to UTF-8 JSON bytes. The envelope SHOULD already be signed.
pub fn encode(env: &Envelope) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(env)?)
}

/// Decode bytes to an envelope: version check + signature verification over
/// the received JSON. Errors with `IDENTITY_MISMATCH` on a missing/invalid
/// signature.
pub fn decode(data: &[u8]) -> Result<Envelope> {
    // Parse the raw JSON first — this is what the sender actually signed.
    let mut raw: Value = serde_json::from_slice(data)?;
    let env: Envelope = serde_json::from_slice(data)?;

    let major = env.v.split('.').next().unwrap_or("");
    let expected = PROTOCOL_VERSION.split('.').next().unwrap_or("");
    if major != expected {
        return Err(MeshError::code(
            ErrorCode::InvalidVersion,
            format!("Unsupported protocol version '{}'. Expected major {}.", env.v, expected),
        ));
    }

    let sig_str = match env.sig {
        Some(ref s) if !s.is_empty() => s.clone(),
        _ => return Err(MeshError::code(ErrorCode::IdentityMismatch, "Envelope is missing a signature (`sig`)")),
    };

    if !verify_json_sig(&mut raw, &env.from, &sig_str) {
        return Err(MeshError::code(
            ErrorCode::IdentityMismatch,
            format!("Envelope signature does not verify against 'from' ({})", env.from),
        ));
    }
    Ok(env)
}

/// Verify `sig` against the canonical form of the received JSON value (all
/// fields except `sig`), the only correct verification base (§5.3). Mutates
/// `raw` by removing `sig`.
///
/// The signed bytes are `ENVELOPE_SIG_PREFIX` + the canonical JSON (§5.3), and
/// only that form: the 0.2 draft window's dual-accept, a second try over the
/// bare canonical JSON, closed at protocol 0.3, so an untagged legacy
/// signature is refused like any other bad signature.
pub(crate) fn verify_json_sig(raw: &mut Value, from: &str, sig_str: &str) -> bool {
    if let Value::Object(ref mut map) = raw {
        map.remove("sig");
    }
    let mut tagged = ENVELOPE_SIG_PREFIX.as_bytes().to_vec();
    tagged.extend_from_slice(canonical_json(raw).as_bytes());
    unb64url(sig_str)
        .ok()
        .and_then(|sig| KeyPair::from_public_key(from).ok().map(|k| (k, sig)))
        .map(|(k, sig)| k.verify(&tagged, &sig).is_ok())
        .unwrap_or(false)
}

/// Decode with structural validation but WITHOUT signature verification — for
/// trusted/local-delivery paths where the node has already verified identity.
pub fn decode_unverified(data: &[u8]) -> Result<Envelope> {
    Ok(serde_json::from_slice(data)?)
}
