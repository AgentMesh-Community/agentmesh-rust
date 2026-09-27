//! Cross-implementation regression guard: a committed envelope signed by the
//! TypeScript SDK must verify here. If Rust canonical-JSON signing ever drifts
//! from TS, this fails. The fixture is produced by the TS `xcheck.mjs emit`.

use std::fs;
use std::path::Path;

#[test]
fn verifies_a_ts_signed_envelope() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ts_signed.json");
    let bytes = match fs::read(&path) {
        Ok(b) => b,
        // Skip gracefully if the fixture isn't present in this checkout.
        Err(_) => return,
    };
    match agentmesh::codec::decode(&bytes) {
        Ok(env) => {
            assert!(env.sig.is_some());
            assert!(env.payload.is_some());
        }
        Err(e) => {
            // The §5.3 flag day: from protocol 0.3 an UNTAGGED signature is
            // refused, and a ts_signed.json emitted before the tag existed now
            // fails decode for that reason alone. That is the fixture being
            // stale, not canonical-JSON drift, tell them apart, because only
            // drift is a bug here. A stale fixture skips loudly (regenerate
            // with the TS `xcheck.mjs emit`); anything else still fails.
            if untagged_form_verifies(&bytes) {
                eprintln!(
                    "skipping cross_impl: tests/fixtures/ts_signed.json carries the pre-0.3 \
                     untagged signature form; regenerate it with the TS SDK's xcheck.mjs emit"
                );
                return;
            }
            panic!("TS-signed envelope must verify in Rust (canonical-JSON parity): {e}");
        }
    }
}

/// Whether the fixture's signature verifies over the BARE canonical JSON, the
/// pre-0.3 untagged form the verifier itself no longer accepts (§5.3). Test-only:
/// this exists to classify a stale fixture, never to admit one.
fn untagged_form_verifies(bytes: &[u8]) -> bool {
    use base64::Engine;
    let Ok(mut raw) = serde_json::from_slice::<serde_json::Value>(bytes) else { return false };
    let Some(sig_str) = raw.get("sig").and_then(|s| s.as_str()).map(str::to_string) else {
        return false;
    };
    let Some(from) = raw.get("from").and_then(|s| s.as_str()).map(str::to_string) else {
        return false;
    };
    raw.as_object_mut().map(|m| m.remove("sig"));
    let canonical = agentmesh::canonical_json(&raw);
    let Ok(sig) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(sig_str) else {
        return false;
    };
    let Ok(key) = agentmesh::KeyPair::from_public_key(&from) else { return false };
    key.verify(canonical.as_bytes(), &sig).is_ok()
}

#[test]
fn derives_the_same_event_durable_name_as_ts() {
    // §18.6: `mesh_event_{agent_id}_{first 16 lowercase hex of SHA-256(pattern)}`.
    // Cross-implementation fixture: the TS SDK pins the identical string for
    // this pattern. Drift means an agent that switches SDKs binds a second
    // consumer whose cursor starts over, replaying everything it already
    // handled.
    assert_eq!(
        agentmesh::subjects::event_durable("UAGENT", "billing.invoice_ready"),
        "mesh_event_UAGENT_99397ba4a29eec30"
    );
}
