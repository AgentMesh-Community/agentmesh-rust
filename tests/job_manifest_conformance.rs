//! The job manifest (`job-manifest-v1`), asserted against
//! `conformance/job-manifest.json`.
//!
//! **The fixture is the authority.** The TS SDK generated and signed the
//! vectors; this SDK must derive the identical canonical bytes from the same
//! document, the identical signature from the same seed, give the pinned
//! reason for each invalid case, and compute the pinned reuse count for the
//! prior/revision pair. One byte of drift is a manifest that verifies in one
//! SDK and not the other.
//!
//! `include_str!`'d rather than read at run time so editing the fixture
//! forces a rebuild.

use agentmesh::{
    canonical_job_manifest_bytes, canonical_json, job_manifest_reuse,
    job_manifest_reuse_claim_holds, keypair_from_seed, sign_job_manifest, validate_job_manifest,
    verify_job_manifest, JobManifest, JobManifestReason, JobManifestReused, KeyPair,
    JOB_MANIFEST_FORMAT, JOB_MANIFEST_SIG_PREFIX,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Value};

static FIXTURE_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/conformance/job-manifest.json"
));

fn fixture() -> Value {
    serde_json::from_str(FIXTURE_JSON).expect("conformance/job-manifest.json parses")
}

fn seed() -> KeyPair {
    let f = fixture();
    keypair_from_seed(f["identities"]["sender_seed"].as_str().unwrap()).unwrap()
}

/// The signed object minus `sig`, canonicalized — must reproduce the pinned
/// `canonical` string exactly.
fn canonical_of(signed: &Value) -> String {
    let mut v = signed.clone();
    v.as_object_mut()
        .expect("signed is an object")
        .remove("sig");
    canonical_json(&v)
}

fn typed(v: &Value) -> JobManifest {
    serde_json::from_value(v.clone()).expect("a pinned manifest parses into JobManifest")
}

// ─── the pinned first delivery ──────────────────────────────────────────────

#[test]
fn the_pinned_manifest_pins_the_format_and_the_prefix() {
    let f = fixture();
    let block = &f["job_manifest"];
    assert_eq!(block["format"].as_str().unwrap(), JOB_MANIFEST_FORMAT);
    assert_eq!(
        block["signed_bytes_prefix"].as_str().unwrap(),
        JOB_MANIFEST_SIG_PREFIX
    );
    assert_eq!(
        block["signed"]["format"].as_str().unwrap(),
        JOB_MANIFEST_FORMAT
    );
}

#[test]
fn the_pinned_manifest_reproduces_its_canonical_bytes() {
    let f = fixture();
    let block = &f["job_manifest"];
    let want = block["canonical"].as_str().unwrap();
    assert_eq!(
        canonical_of(&block["signed"]),
        want,
        "canonical bytes drift"
    );
    assert_eq!(
        canonical_job_manifest_bytes(&block["signed"]).unwrap(),
        want.as_bytes(),
        "canonical_job_manifest_bytes drift"
    );
    // And through the typed round-trip, so serde emits exactly the bytes TS
    // canonicalized: nulls kept, an absent produced_from omitted, nothing
    // renamed.
    let mut t = typed(&block["signed"]);
    t.sig.clear();
    let mut v = serde_json::to_value(&t).unwrap();
    v.as_object_mut().unwrap().remove("sig");
    assert_eq!(canonical_json(&v), want, "typed round-trip drift");
}

#[test]
fn the_sig_covers_prefix_plus_canonical_and_nothing_else() {
    let f = fixture();
    let block = &f["job_manifest"];
    let sig = URL_SAFE_NO_PAD
        .decode(block["signed"]["sig"].as_str().unwrap())
        .unwrap();
    let canonical = canonical_of(&block["signed"]);
    let vpub = KeyPair::from_public_key(f["identities"]["sender"].as_str().unwrap()).unwrap();
    let mut tagged = JOB_MANIFEST_SIG_PREFIX.as_bytes().to_vec();
    tagged.extend_from_slice(canonical.as_bytes());
    assert!(
        vpub.verify(&tagged, &sig).is_ok(),
        "sig must cover prefix + canonical"
    );
    assert!(
        vpub.verify(canonical.as_bytes(), &sig).is_err(),
        "the bare form is not what was signed"
    );
}

#[test]
fn the_pinned_manifest_validates_and_verifies_bound_to_the_agent() {
    let f = fixture();
    let signed = &f["job_manifest"]["signed"];
    let sender = f["identities"]["sender"].as_str().unwrap();
    assert_eq!(validate_job_manifest(signed), Ok(()));
    assert_eq!(verify_job_manifest(signed, None), Ok(()));
    assert_eq!(verify_job_manifest(signed, Some(sender)), Ok(()));
    assert_eq!(signed["agent"].as_str().unwrap(), sender);
}

#[test]
fn the_sdk_signer_reproduces_the_pinned_signature_from_the_seed() {
    // Ed25519 is deterministic (RFC 8032): same seed, same bytes, same sig.
    let f = fixture();
    let signed = &f["job_manifest"]["signed"];
    let mut doc = typed(signed);
    doc.sig.clear();
    doc.agent.clear();
    sign_job_manifest(&mut doc, &seed()).unwrap();
    assert_eq!(doc.sig, signed["sig"].as_str().unwrap(), "signature drift");
    assert_eq!(
        serde_json::to_value(&doc).unwrap(),
        *signed,
        "the signed document drifts"
    );
}

#[test]
fn signing_refuses_to_attribute_to_a_key_other_than_the_signers() {
    let f = fixture();
    let mut doc = typed(&f["job_manifest"]["signed"]);
    doc.sig.clear();
    doc.agent = f["identities"]["recipient"].as_str().unwrap().to_string();
    let err = sign_job_manifest(&mut doc, &seed()).unwrap_err();
    assert!(err.to_string().contains("IDENTITY_MISMATCH"), "{err}");
}

// ─── the invalid cases ──────────────────────────────────────────────────────

#[test]
fn every_invalid_case_gives_the_pinned_reason_and_member() {
    let f = fixture();
    let cases = f["invalid"]["cases"].as_array().unwrap();
    assert!(cases.len() >= 3);
    for case in cases {
        let name = case["case"].as_str().unwrap();
        let want_reason = case["reason"].as_str().unwrap();
        let want_member = case["member"].as_str().unwrap();
        let expected_agent = case["expected_agent"].as_str();
        let fault = verify_job_manifest(&case["document"], expected_agent)
            .expect_err(&format!("case {name} must refuse"));
        assert_eq!(
            (fault.reason.as_str(), fault.member.as_str()),
            (want_reason, want_member),
            "case {name}: {fault}"
        );
        match fault.reason {
            JobManifestReason::Malformed | JobManifestReason::WrongFormat => {
                let shape = validate_job_manifest(&case["document"])
                    .expect_err(&format!("case {name} is a shape fault"));
                assert_eq!(
                    (shape.reason, shape.member.as_str()),
                    (fault.reason, want_member)
                );
            }
            // bad_signature and agent_mismatch are sound documents: shape passes.
            JobManifestReason::BadSignature | JobManifestReason::AgentMismatch => {
                assert_eq!(
                    validate_job_manifest(&case["document"]),
                    Ok(()),
                    "case {name}"
                );
            }
        }
    }
}

#[test]
fn the_invalid_cases_cover_each_reason() {
    let f = fixture();
    let reasons: Vec<&str> = f["invalid"]["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["reason"].as_str().unwrap())
        .collect();
    for want in [
        "wrong_format",
        "malformed",
        "bad_signature",
        "agent_mismatch",
    ] {
        assert!(reasons.contains(&want), "fixture has a {want} case");
    }
}

#[test]
fn a_document_of_another_format_is_refused_before_its_signature_is_read() {
    // Beyond the fixture's row: even with an unreadable sig, format wins.
    let f = fixture();
    let mut doc = f["job_manifest"]["signed"].clone();
    doc["format"] = json!("agentmesh-vouch-v1");
    doc["sig"] = json!("not base64url!");
    let fault = verify_job_manifest(&doc, None).unwrap_err();
    assert_eq!(fault.reason, JobManifestReason::WrongFormat);
    assert_eq!(fault.member, "format");
}

// ─── the pinned prior/revision pair ─────────────────────────────────────────

#[test]
fn prior_is_the_pinned_first_delivery_byte_for_byte() {
    let f = fixture();
    assert_eq!(f["reuse"]["prior"], f["job_manifest"]["signed"]);
}

#[test]
fn the_revision_reproduces_its_canonical_bytes_and_verifies_as_the_same_agent() {
    let f = fixture();
    let r = &f["reuse"];
    assert_eq!(
        canonical_of(&r["revision"]),
        r["revision_canonical"].as_str().unwrap()
    );
    let sender = f["identities"]["sender"].as_str().unwrap();
    assert_eq!(verify_job_manifest(&r["revision"], Some(sender)), Ok(()));
    let prior = typed(&r["prior"]);
    let revision = typed(&r["revision"]);
    assert_eq!(revision.version, prior.version + 1);
    assert_eq!(revision.revises.as_deref(), Some(prior.task_id.as_str()));
    assert_eq!(revision.job, prior.job);
}

#[test]
fn the_sdk_signer_reproduces_the_revisions_signature_from_the_seed() {
    let f = fixture();
    let signed = &f["reuse"]["revision"];
    let mut doc = typed(signed);
    doc.sig.clear();
    doc.agent.clear();
    sign_job_manifest(&mut doc, &seed()).unwrap();
    assert_eq!(
        serde_json::to_value(&doc).unwrap(),
        *signed,
        "the revision drifts"
    );
}

#[test]
fn computes_the_pinned_reuse_count() {
    let f = fixture();
    let prior = typed(&f["reuse"]["prior"]);
    let revision = typed(&f["reuse"]["revision"]);
    let expected: JobManifestReused =
        serde_json::from_value(f["reuse"]["expected"].clone()).unwrap();
    assert_eq!(job_manifest_reuse(Some(&prior), &revision), expected);
    assert_eq!(revision.reused, expected);
}

#[test]
fn a_first_delivery_reuses_nothing() {
    let f = fixture();
    let prior = typed(&f["reuse"]["prior"]);
    assert_eq!(
        job_manifest_reuse(None, &prior),
        JobManifestReused {
            pieces: 0,
            of: prior.pieces.len() as u64
        }
    );
}

#[test]
fn the_claim_holds_for_both_and_not_when_the_bytes_moved_or_the_flags_lie() {
    let f = fixture();
    let prior = typed(&f["reuse"]["prior"]);
    let revision = typed(&f["reuse"]["revision"]);
    let expected = job_manifest_reuse(Some(&prior), &revision);
    assert!(job_manifest_reuse_claim_holds(None, &prior));
    assert!(job_manifest_reuse_claim_holds(Some(&prior), &revision));

    // Same ref, different digest: not reused, so the claim of 1 no longer holds.
    let mut moved = revision.clone();
    moved.pieces[0].digest = format!("sha256:{}", "0".repeat(64));
    assert_eq!(
        job_manifest_reuse(Some(&prior), &moved),
        JobManifestReused { pieces: 0, of: 2 }
    );
    assert!(!job_manifest_reuse_claim_holds(Some(&prior), &moved));

    // Same digest, different ref: not reused either — both must match.
    let mut rehomed = revision.clone();
    rehomed.pieces[0].r#ref = "mesh:artifacts:elsewhere".into();
    assert_eq!(
        job_manifest_reuse(Some(&prior), &rehomed),
        JobManifestReused { pieces: 0, of: 2 }
    );

    // Right count, flags on the wrong pieces: the claim does not hold.
    let mut swapped = revision.clone();
    swapped.pieces[0].reused = false;
    swapped.pieces[1].reused = true;
    assert_eq!(job_manifest_reuse(Some(&prior), &swapped), expected);
    assert!(!job_manifest_reuse_claim_holds(Some(&prior), &swapped));

    // A prior that lacks the piece's name+step: new, not reused.
    let mut renamed = prior.clone();
    renamed.pieces[0].step = "rewrite-the-story".into();
    assert_eq!(
        job_manifest_reuse(Some(&renamed), &revision),
        JobManifestReused { pieces: 0, of: 2 }
    );
}
