//! Cross-implementation guard for EXT-7 pairwise sealing.
//!
//! A payload sealed by one SDK must open in the other. Ed25519 signing parity
//! is already guarded by `cross_impl.rs`; this covers the other direction of
//! the crypto surface, where a mismatch is silent — a wrong construction still
//! produces a well-formed box, it just never opens, and nothing about the
//! failure says which side was wrong.
//!
//! Two fixtures, one per direction, keyed off FIXED secrets so both languages
//! can hold the same key without a handshake:
//!
//!   `fixtures/sealed_payload_rust.json` — emitted here, opened by the TS side
//!   `fixtures/sealed_payload_ts.json`   — emitted by TS, opened here
//!
//! Regenerate with `tools/xcheck-sealed.mjs` after running this test. Both
//! sides skip gracefully when the other's fixture is absent, so a fresh
//! checkout is never red for a reason it cannot fix.

use std::fs;
use std::path::PathBuf;

use agentmesh::{encryption_public_from_seed, open_sealed_payload, seal_payload_to, SealedPayload};
use serde_json::json;

/// Fixed X25519 secrets (base64url of bytes 1..32 and 200..169). Test vectors,
/// never anything real: they are committed, so anything sealed to them is
/// public by construction.
const RECIPIENT_SECRET: &str = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA";
const SENDER_SECRET: &str = "yMfGxcTDwsHAv769vLu6ubi3trW0s7KxsK-urayrqqk";

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn subject() -> serde_json::Value {
    json!({
        "text": "cross-impl pairwise subject",
        "n": 42,
        "nested": { "ok": true, "list": [1, 2, 3] },
        "unicode": "héllo → 🌍",
    })
}

/// Emit the Rust-sealed fixture the TypeScript side opens.
#[test]
fn emits_a_rust_sealed_payload_for_typescript() {
    let recipient_public = encryption_public_from_seed(RECIPIENT_SECRET).expect("derive recipient public");
    let reply_key = encryption_public_from_seed(SENDER_SECRET).expect("derive sender public");

    let sealed = seal_payload_to(&subject(), &recipient_public, Some(&reply_key)).expect("seal");

    // Round-trips locally before we ask anyone else to open it.
    let opened = open_sealed_payload(&sealed, RECIPIENT_SECRET).expect("opens with the recipient secret");
    assert_eq!(opened.payload, subject());
    assert_eq!(opened.reply_key.as_deref(), Some(reply_key.as_str()));

    let dir = fixtures();
    fs::create_dir_all(&dir).expect("fixtures dir");
    let out = json!({
        "note": "Sealed by the Rust SDK for the TypeScript cross-check. Test vectors only.",
        "recipient_secret": RECIPIENT_SECRET,
        "recipient_public": recipient_public,
        "reply_key": reply_key,
        "sealed": sealed,
        "expect_payload": subject(),
    });
    fs::write(
        dir.join("sealed_payload_rust.json"),
        serde_json::to_string_pretty(&out).unwrap(),
    )
    .expect("write rust fixture");
}

/// Open the TypeScript-sealed fixture. This is the assertion that actually
/// proves wire compatibility rather than internal self-consistency.
#[test]
fn opens_a_typescript_sealed_payload() {
    let path = fixtures().join("sealed_payload_ts.json");
    let Ok(bytes) = fs::read(&path) else {
        eprintln!("skipping: no TS fixture at {} — run tools/xcheck-sealed.mjs", path.display());
        return;
    };
    let doc: serde_json::Value = serde_json::from_slice(&bytes).expect("fixture parses");

    let sealed: SealedPayload =
        serde_json::from_value(doc["sealed"].clone()).expect("fixture carries a sealed payload");
    let secret = doc["recipient_secret"].as_str().unwrap_or(RECIPIENT_SECRET);

    let opened = open_sealed_payload(&sealed, secret)
        .expect("a TS-sealed payload must open in Rust (EXT-7 wire parity)");
    assert_eq!(
        opened.payload, doc["expect_payload"],
        "plaintext survived the TS→Rust crossing intact"
    );

    // The reply key rides outside the box and must survive verbatim.
    if let Some(expected) = doc["reply_key"].as_str() {
        assert_eq!(opened.reply_key.as_deref(), Some(expected));
    }

    // A different recipient must get nothing, on the same box.
    assert!(
        open_sealed_payload(&sealed, SENDER_SECRET).is_none(),
        "the wrong secret must not open a TS-sealed payload"
    );
}
