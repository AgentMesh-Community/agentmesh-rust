//! The three newly domain-tagged canonical-JSON signatures (SPEC.md §4.4
//! vouch, EXT-5 §2 room descriptor, EXT-6 §3 admission roster), asserted
//! against `conformance/signature-tags.json`.
//!
//! **The fixture is the authority.** The TS SDK generated and signed the
//! vectors; this SDK must derive the identical canonical bytes and verify the
//! identical signatures over `<prefix> + canonical` — one byte of drift is a
//! vouch or descriptor that verifies in one SDK and not the other. Each block
//! is additionally held to the STRICT tagged form (the bare canonical bytes
//! must NOT verify), the property the 0.3 flag day made normative for the
//! verifiers themselves (§5.3), pinned here at the byte level.
//!
//! `include_str!`'d rather than read at run time so editing the fixture
//! forces a rebuild.

use agentmesh::{
    canonical_json, verify_attestation, verify_descriptor, AgentAttestation, KeyPair,
    RoomDescriptor, ROOM_DESCRIPTOR_SIG_PREFIX, VOUCH_SIG_PREFIX,
};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde_json::Value;

static FIXTURE_JSON: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/conformance/signature-tags.json"));

fn fixture() -> Value {
    serde_json::from_str(FIXTURE_JSON).expect("conformance/signature-tags.json parses")
}

/// The block's `signed` object minus `sig`, canonicalized — must reproduce the
/// pinned `canonical` string exactly.
fn canonical_of(block: &Value) -> String {
    let mut v = block["signed"].clone();
    v.as_object_mut().expect("signed is an object").remove("sig");
    canonical_json(&v)
}

/// Assert the invariants common to all three blocks: the pinned prefix, byte
/// reproduction of the canonical form, and a signature that covers STRICTLY
/// prefix + canonical.
fn assert_tagged_block(block: &Value, expected_prefix: &str, sig: &[u8]) {
    let prefix = block["signed_bytes_prefix"].as_str().expect("signed_bytes_prefix");
    assert_eq!(prefix, expected_prefix);
    let canonical = canonical_of(block);
    assert_eq!(canonical, block["canonical"].as_str().expect("canonical"), "canonical bytes drift");
    let f = fixture();
    let vpub = KeyPair::from_public_key(f["identities"]["sender"].as_str().unwrap()).unwrap();
    let mut tagged = prefix.as_bytes().to_vec();
    tagged.extend_from_slice(canonical.as_bytes());
    assert!(vpub.verify(&tagged, sig).is_ok(), "sig must cover prefix + canonical");
    assert!(vpub.verify(canonical.as_bytes(), sig).is_err(), "the bare form is not what was signed");
}

// ─── §4.4 vouch ─────────────────────────────────────────────────────────────

#[test]
fn the_pinned_vouch_reproduces_and_verifies() {
    let f = fixture();
    let block = &f["vouch"];
    let sig = URL_SAFE_NO_PAD.decode(block["signed"]["sig"].as_str().unwrap()).unwrap();
    assert_tagged_block(block, VOUCH_SIG_PREFIX, &sig);

    let att: AgentAttestation = serde_json::from_value(block["signed"].clone()).unwrap();
    let agent = f["identities"]["recipient"].as_str().unwrap();
    assert!(verify_attestation(&att, None));
    assert!(verify_attestation(&att, Some(agent)));

    let mut tampered = att.clone();
    tampered.agent = f["identities"]["sender"].as_str().unwrap().to_string();
    assert!(!verify_attestation(&tampered, None));
}

// ─── EXT-5 §2 room descriptor ───────────────────────────────────────────────

#[test]
fn the_pinned_descriptor_reproduces_and_verifies() {
    let f = fixture();
    let block = &f["room_descriptor"];
    let sig = URL_SAFE_NO_PAD.decode(block["signed"]["sig"].as_str().unwrap()).unwrap();
    assert_tagged_block(block, ROOM_DESCRIPTOR_SIG_PREFIX, &sig);

    let d: RoomDescriptor = serde_json::from_value(block["signed"].clone()).unwrap();
    assert!(verify_descriptor(&d));

    let mut tampered = d.clone();
    tampered.name = Some("renamed".to_string());
    assert!(!verify_descriptor(&tampered));
}

// ─── EXT-6 §3 admission roster ──────────────────────────────────────────────

#[test]
fn the_pinned_roster_reproduces_and_verifies() {
    // This SDK carries no roster type — the verifier of record lives in
    // services — but the canonicalization and the signed bytes are the
    // cross-implementation contract, so they are asserted here generically.
    // Note the roster's sig encoding: STANDARD base64 with padding (the
    // signer's historical encoding), not base64url.
    let f = fixture();
    let block = &f["admission_roster"];
    let sig = STANDARD.decode(block["signed"]["sig"].as_str().unwrap()).unwrap();
    assert_tagged_block(block, "agentmesh-admission-roster-v1\n", &sig);
}
