//! Manifest key claim (§8.3) — the signed binding between an agent id and the
//! `encryption_key` secrets get sealed to.
//!
//! The exact-bytes assertions exist because a drift between this SDK and the TS
//! one does NOT throw: it makes one SDK refuse to seal to agents registered by
//! the other, silently, at the moment a room key is being handed out. The shared
//! fixture `conformance/manifest-signing.json` is asserted from both sides —
//! here and in `sdk-typescript/__tests__/unit/manifest-signing.test.ts` — so a
//! divergence fails a test rather than turning up in production as "sealed
//! invites mysteriously stopped working". If this fails after an edit, the fix is
//! to agree with the fixture: deployed agents hold registered manifests signed
//! over exactly these bytes.

use agentmesh::identity::{
    manifest_key_claim_bytes, sign_manifest_at, verify_manifest_signature, MANIFEST_KEY_CLAIM_TYPE,
};
use agentmesh::manifest::{AgentAttestation, Manifest, NodeRef, Trust};
use agentmesh::KeyPair;
use serde_json::Value;

fn fixture() -> Value {
    let raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/conformance/manifest-signing.json"
    ))
    .expect("conformance/manifest-signing.json");
    serde_json::from_str(&raw).expect("fixture parses")
}

/// A manifest carrying only the fields the claim reads. Everything else is §8.1
/// filler — deliberately so: if the claim ever starts depending on another field,
/// this helper stops compiling or the fixture stops matching.
fn manifest(id: &str, encryption_key: Option<&str>) -> Manifest {
    Manifest {
        id: id.to_string(),
        name: "fixture".to_string(),
        description: String::new(),
        version: "0.1.0".to_string(),
        protocol_version: "0.2".to_string(),
        encryption_key: encryption_key.map(str::to_string),
        endpoint: format!("mesh.agent.{id}.inbox"),
        endpoints: None,
        limits: None,
        node: NodeRef {
            id: id.to_string(),
            attestation: AgentAttestation {
                node: id.to_string(),
                agent: id.to_string(),
                issued_at: String::new(),
                expires_at: String::new(),
                sig: String::new(),
            },
            profile: None,
        },
        capabilities: vec![],
        offerings: vec![],
        emits: None,
        accepts: None,
        meta: None,
        trust: None,
        visibility: None,
        // §8.3a: deliberately outside the claim, so the fixture must keep matching
        // whatever this says.
        interaction: None,
        harness: None,
        harness_version: None,
        model: None,
        works_with: None,
        sealing: None,
        data_use: None,
        compliance: None,
        audience: None,
        coverage: None,
        edge: None,
        serves: None,
        acts: None,
        parties: None,
        origin: None,
        public: None,
        skus: None,
        availability: None,
        owner: None,
        owner_attestation: None,
    }
}

#[test]
fn canonical_bytes_match_the_fixture() {
    let f = fixture();
    for case in ["key_claim_v1", "key_claim_v1_no_encryption_key"] {
        let c = &f[case];
        let bytes = manifest_key_claim_bytes(
            c["id"].as_str().unwrap(),
            c["encryption_key"].as_str().unwrap(),
            c["issued_at"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            c["canonical"].as_str().unwrap(),
            "{case}: canonical bytes"
        );
    }
    assert_eq!(MANIFEST_KEY_CLAIM_TYPE, f["key_claim_v1"]["type"].as_str().unwrap());
}

#[test]
fn signature_matches_the_fixture_byte_for_byte() {
    let f = fixture();
    for case in ["key_claim_v1", "key_claim_v1_no_encryption_key"] {
        let c = &f[case];
        let kp = KeyPair::from_seed(c["agent_seed"].as_str().unwrap()).expect("fixture seed");
        assert_eq!(kp.public_key(), c["id"].as_str().unwrap(), "{case}: seed -> id");

        // An absent key and an empty key are the same claim: both sign over the
        // empty string, which is what makes the four-component form the ONLY form.
        let key = c["encryption_key"].as_str().unwrap();
        let mut m = manifest(&kp.public_key(), if key.is_empty() { None } else { Some(key) });
        sign_manifest_at(&mut m, &kp, c["issued_at"].as_str().unwrap()).unwrap();

        let trust = m.trust.as_ref().unwrap();
        assert_eq!(trust.issued_at.as_deref(), Some(c["issued_at"].as_str().unwrap()), "{case}: issued_at");
        assert_eq!(
            trust.signature.as_deref(),
            Some(c["signature"].as_str().unwrap()),
            "{case}: signature (TS/Rust parity — see conformance/manifest-signing.json)"
        );
        assert!(verify_manifest_signature(&m), "{case}: own signature verifies");
    }
}

#[test]
fn verifies_the_fixture_claim_as_published() {
    // The read path: a manifest arrives from the registry carrying the claim, and
    // nothing local re-signs it. This is the case that must hold for a Rust agent
    // to seal a room key to a TS-registered agent.
    let f = fixture();
    let c = &f["key_claim_v1"];
    let mut m = manifest(c["id"].as_str().unwrap(), Some(c["encryption_key"].as_str().unwrap()));
    m.trust = Some(Trust {
        tenant: None,
        issued_at: Some(c["issued_at"].as_str().unwrap().to_string()),
        signature: Some(c["signature"].as_str().unwrap().to_string()),
    });
    assert!(verify_manifest_signature(&m));
}

#[test]
fn refuses_a_substituted_encryption_key() {
    // The whole reason the claim exists (assessment 2026-07-25, finding 6.5).
    let f = fixture();
    let c = &f["key_claim_v1"];
    let mut m = manifest(c["id"].as_str().unwrap(), Some(c["encryption_key"].as_str().unwrap()));
    m.trust = Some(Trust {
        tenant: None,
        issued_at: Some(c["issued_at"].as_str().unwrap().to_string()),
        signature: Some(c["signature"].as_str().unwrap().to_string()),
    });
    m.encryption_key = Some("ATTACKERSOWNX25519PUBLICKEYAAAAAAAAAAAAAAAAA".to_string());
    assert!(!verify_manifest_signature(&m));
}

#[test]
fn refuses_a_claim_signed_by_another_key_or_relabelled() {
    let kp = KeyPair::new_user();
    let impostor = KeyPair::new_user();
    let key = "B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9_AsrhtHHw";

    // Signed by someone other than the manifest's id.
    let mut m = manifest(&kp.public_key(), Some(key));
    sign_manifest_at(&mut m, &impostor, "2026-07-25T00:00:00.000Z").unwrap();
    assert!(!verify_manifest_signature(&m));

    // A signed manifest for B served as the answer for A: the claim covers `id`,
    // so relabelling breaks it (and `encryption_key_for` checks the id too).
    let mut m = manifest(&kp.public_key(), Some(key));
    sign_manifest_at(&mut m, &kp, "2026-07-25T00:00:00.000Z").unwrap();
    m.id = impostor.public_key();
    assert!(!verify_manifest_signature(&m));
}

#[test]
fn refuses_a_moved_issued_at_and_a_missing_claim() {
    let kp = KeyPair::new_user();
    let mut m = manifest(&kp.public_key(), Some("K"));
    sign_manifest_at(&mut m, &kp, "2026-07-25T00:00:00.000Z").unwrap();
    m.trust.as_mut().unwrap().issued_at = Some("2020-01-01T00:00:00.000Z".to_string());
    assert!(!verify_manifest_signature(&m));

    // No claim at all means no sealing — the pre-§8.3 manifests on a live
    // registry land here, and refusing them is the intended behaviour.
    let mut bare = manifest(&kp.public_key(), Some("K"));
    assert!(!verify_manifest_signature(&bare));
    bare.trust = Some(Trust::default());
    assert!(!verify_manifest_signature(&bare));
    bare.trust = Some(Trust { tenant: None, issued_at: Some("x".into()), signature: None });
    assert!(!verify_manifest_signature(&bare));
}

#[test]
fn refuses_newline_bearing_components() {
    // Only the last component is unbounded, so the encoding is unambiguous — but
    // a newline is refused outright rather than allowed to shift the framing.
    assert!(manifest_key_claim_bytes("U", "a\nb", "2026-07-25T00:00:00.000Z").is_err());
    assert!(manifest_key_claim_bytes("U", "k", "2026\n07").is_err());

    // On the read path that is a refusal, not a panic: an attacker must not be
    // able to take a verifier down by putting a newline in a manifest.
    let kp = KeyPair::new_user();
    let mut m = manifest(&kp.public_key(), Some("k"));
    sign_manifest_at(&mut m, &kp, "2026-07-25T00:00:00.000Z").unwrap();
    m.encryption_key = Some("a\nb".to_string());
    assert!(!verify_manifest_signature(&m));
}

#[test]
fn preserves_other_trust_fields_and_replaces_a_stale_claim() {
    let kp = KeyPair::new_user();
    let mut m = manifest(&kp.public_key(), Some("K"));
    m.trust = Some(Trust {
        tenant: Some("acme".to_string()),
        issued_at: Some("stale".to_string()),
        signature: Some("stale".to_string()),
    });
    sign_manifest_at(&mut m, &kp, "2026-01-01T00:00:00.000Z").unwrap();
    let trust = m.trust.as_ref().unwrap();
    assert_eq!(trust.tenant.as_deref(), Some("acme"));
    assert_eq!(trust.issued_at.as_deref(), Some("2026-01-01T00:00:00.000Z"));
    assert!(verify_manifest_signature(&m));
}

#[test]
fn is_domain_separated_so_a_v2_cannot_be_read_as_v1() {
    // The tag is inside the signed bytes. A v2 claim covering more fields signs
    // different bytes under a different tag, so every v1 signature already issued
    // keeps verifying and no v1 verifier can misread a v2 claim.
    let kp = KeyPair::new_user();
    let v1 = manifest_key_claim_bytes(&kp.public_key(), "K", "2026-07-25T00:00:00.000Z").unwrap();
    let sig = kp.sign(&v1).unwrap();
    assert!(kp.verify(&v1, &sig).is_ok());
    let v2 = String::from_utf8(v1).unwrap().replace("-v1", "-v2").into_bytes();
    assert!(kp.verify(&v2, &sig).is_err());
}

#[test]
fn trust_block_serialises_with_the_wire_field_names() {
    // The bytes are only half the contract: a reader looks up `trust.issued_at`
    // and `trust.signature` by name, so the names are pinned by the fixture too.
    let f = fixture();
    let expected = &f["key_claim_v1"]["trust"];
    let kp = KeyPair::from_seed(f["key_claim_v1"]["agent_seed"].as_str().unwrap()).unwrap();
    let mut m = manifest(&kp.public_key(), Some(f["key_claim_v1"]["encryption_key"].as_str().unwrap()));
    sign_manifest_at(&mut m, &kp, f["key_claim_v1"]["issued_at"].as_str().unwrap()).unwrap();
    let json = serde_json::to_value(m.trust.as_ref().unwrap()).unwrap();
    assert_eq!(json["issued_at"], expected["issued_at"]);
    assert_eq!(json["signature"], expected["signature"]);
    // `tenant` is absent, not null: the TS side omits undefined fields.
    assert!(json.get("tenant").is_none());
}
