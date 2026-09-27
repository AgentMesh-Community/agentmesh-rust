//! Agent SoW disputes (agentsow.com 0.15.0-draft §5.10) and the arbiter's
//! verdict (agentroles.ai/arbiter.html §4), asserted against
//! `conformance/sow-disputes.json` — the same file the TypeScript SDK's
//! disputes conformance test reads.
//!
//! **The fixture is the authority.** When a case here fails, the fix is in
//! `src/sow.rs`, never in the JSON; a fixture changes only with a spec change
//! alongside. Cases are executed by ITERATING the fixture, so a row added to
//! the JSON runs here without this file changing.
//!
//! The load-bearing assertions are the cross-SDK ones: the closed posture and
//! fee sets, the exact-sum boundary rows (both off-by-one directions), the
//! clause-side expectation check, and the two byte contracts — the clause
//! inside the engagement's signed bytes under the agent-sow-v1 tag, and the
//! verdict as its own signed document under agent-arbiter-verdict-v1, with a
//! REALLY SIGNED verdict both SDKs must verify byte for byte.

use serde_json::Value;

use agentmesh::{
    arbiter_verdict_signed_bytes, canonical_sow_json, disputes_of, keypair_from_seed,
    sign_arbiter_verdict, validate_arbiter_verdict, validate_sow_disputes,
    verify_arbiter_verdict_signature, ArbiterVerdictExpectation, SowArbiterVerdict,
    SowArbiterVerdictSignature, SowDisputes, ARBITER_VERDICT_SIG_PREFIX, ROLE_ARBITER,
    SOW_ARBITER_FEES, SOW_DISPUTES_POSTURES,
};

static FIXTURE_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/conformance/sow-disputes.json"
));

fn fixture() -> Value {
    serde_json::from_str(FIXTURE_JSON).expect("conformance/sow-disputes.json parses")
}

fn strs(v: &Value) -> Vec<String> {
    v.as_array()
        .expect("array")
        .iter()
        .map(|s| s.as_str().expect("string").to_string())
        .collect()
}

fn expectation_of(row: &Value) -> Option<ArbiterVerdictExpectation> {
    row.get("expected").map(|e| ArbiterVerdictExpectation {
        disputed_amount: e.get("disputed_amount").and_then(Value::as_u64),
        currency: e.get("currency").and_then(Value::as_str).map(str::to_string),
    })
}

// ─── §5.10 the closed sets ──────────────────────────────────────────────────

#[test]
fn the_posture_set_is_closed_ordered_and_matches_the_fixture() {
    let f = fixture();
    let want = strs(&f["postures"]["all"]);
    let got: Vec<String> = SOW_DISPUTES_POSTURES.iter().map(|s| s.to_string()).collect();
    assert_eq!(got, want, "the posture set is the fixture's, in the fixture's order");
    let fees = strs(&f["postures"]["fees"]);
    let got_fees: Vec<String> = SOW_ARBITER_FEES.iter().map(|s| s.to_string()).collect();
    assert_eq!(got_fees, fees, "the fee set is the fixture's");
    assert_eq!(
        ROLE_ARBITER,
        f["postures"]["role"].as_str().expect("postures.role"),
        "the standard role name — a name offered, not a pin"
    );
}

#[test]
fn an_absent_clause_has_no_default_posture() {
    // Absent means the document has not said, and a reader MUST NOT invent a
    // posture on its behalf.
    assert!(disputes_of(&serde_json::json!({})).is_none());
    assert!(disputes_of(&serde_json::json!({ "disputes": null })).is_none());
}

// ─── §5.10 the clause shape ─────────────────────────────────────────────────

#[test]
fn every_valid_disputes_clause_validates_and_round_trips_through_serde() {
    let f = fixture();
    for clause in f["clause"]["valid"].as_array().expect("clause.valid") {
        validate_sow_disputes(clause)
            .unwrap_or_else(|e| panic!("valid clause refused: {e}\n{clause:#}"));
        // The typed clause re-serializes to the same canonical bytes — the
        // clause sits inside the signed document, so serde may not add or
        // drop a member.
        let typed: SowDisputes =
            serde_json::from_value(clause.clone()).expect("a valid clause deserializes");
        assert_eq!(
            agentmesh::canonical_json(&serde_json::to_value(&typed).unwrap()),
            agentmesh::canonical_json(clause),
            "the typed clause must re-serialize to the bytes it came from"
        );
        // The accessor hands back what a document carrying it declares.
        let doc = serde_json::json!({ "disputes": clause });
        assert_eq!(disputes_of(&doc), Some(clause));
    }
}

#[test]
fn every_invalid_disputes_clause_is_refused() {
    let f = fixture();
    for row in f["clause"]["invalid"].as_array().expect("clause.invalid") {
        let case = row["case"].as_str().unwrap();
        let why = row["why"].as_str().unwrap();
        assert!(
            validate_sow_disputes(&row["disputes"]).is_err(),
            "'{case}' must be refused — {why}"
        );
    }
}

// ─── arbiter.html §4 the verdict ────────────────────────────────────────────

#[test]
fn every_valid_verdict_validates_and_round_trips_through_serde() {
    let f = fixture();
    for row in f["verdict"]["valid"].as_array().expect("verdict.valid") {
        let name = row["name"].as_str().unwrap();
        let expected = expectation_of(row);
        validate_arbiter_verdict(&row["verdict"], expected.as_ref())
            .unwrap_or_else(|e| panic!("'{name}' refused: {e}"));
        // A verdict valid against an expectation is valid on its own shape too.
        validate_arbiter_verdict(&row["verdict"], None)
            .unwrap_or_else(|e| panic!("'{name}' refused without expectation: {e}"));
        let typed: SowArbiterVerdict =
            serde_json::from_value(row["verdict"].clone()).expect("a valid verdict deserializes");
        assert_eq!(
            agentmesh::canonical_json(&serde_json::to_value(&typed).unwrap()),
            agentmesh::canonical_json(&row["verdict"]),
            "'{name}': the typed verdict must re-serialize to the bytes it came from"
        );
    }
}

#[test]
fn every_invalid_verdict_is_refused() {
    let f = fixture();
    for row in f["verdict"]["invalid"].as_array().expect("verdict.invalid") {
        let case = row["case"].as_str().unwrap();
        let why = row["why"].as_str().unwrap();
        let expected = expectation_of(row);
        assert!(
            validate_arbiter_verdict(&row["verdict"], expected.as_ref()).is_err(),
            "'{case}' must be refused — {why}"
        );
    }
}

// ─── the two byte contracts ─────────────────────────────────────────────────

#[test]
fn the_verdict_prefix_is_the_fixtures() {
    let f = fixture();
    assert_eq!(
        ARBITER_VERDICT_SIG_PREFIX,
        f["signing"]["verdict_signed_bytes_prefix"].as_str().expect("prefix")
    );
}

#[test]
fn a_document_carrying_an_arbiter_clause_canonicalizes_to_the_fixtures_bytes() {
    let f = fixture();
    assert_eq!(
        canonical_sow_json(&f["signing"]["document"]),
        f["signing"]["canonical"].as_str().expect("signing.canonical"),
        "one byte of canonical drift is a document that verifies in one SDK and is worthless \
         in the other"
    );
}

#[test]
fn the_verdict_canonicalizes_to_the_fixtures_bytes_signatures_removed() {
    let f = fixture();
    let canonical = f["signing"]["verdict_canonical"].as_str().expect("verdict_canonical");
    assert_eq!(canonical_sow_json(&f["signing"]["verdict"]), canonical);
    let bytes = arbiter_verdict_signed_bytes(&f["signing"]["verdict"]);
    let want: Vec<u8> = [ARBITER_VERDICT_SIG_PREFIX.as_bytes(), canonical.as_bytes()].concat();
    assert_eq!(bytes, want, "the signed bytes are the ASCII tag, one newline, the canonical JSON");
}

#[test]
fn the_really_signed_verdict_verifies_and_resigning_reproduces_the_pinned_signature() {
    let f = fixture();
    let signed = &f["signing"]["verdict"];
    let record: SowArbiterVerdictSignature =
        serde_json::from_value(signed["signatures"][0].clone()).expect("a signature record");
    assert!(
        verify_arbiter_verdict_signature(signed, &record),
        "a TypeScript-signed verdict must verify in Rust"
    );
    assert_eq!(record.key, f["identities"]["sender"].as_str().unwrap());
    // Ed25519 is deterministic: signing the same bytes with the published
    // seed must reproduce the pinned base64url signature exactly.
    let kp = keypair_from_seed(f["identities"]["sender_seed"].as_str().unwrap()).unwrap();
    let mut unsigned = signed.clone();
    unsigned.as_object_mut().unwrap().remove("signatures");
    sign_arbiter_verdict(&mut unsigned, &kp, &record.signed_at).unwrap();
    assert_eq!(
        unsigned["signatures"][0],
        signed["signatures"][0],
        "the Rust-signed record is byte-for-byte the fixture's"
    );
    // And the signed verdict is a valid verdict.
    validate_arbiter_verdict(signed, None).expect("the signed verdict validates");
}

#[test]
fn tampering_with_any_pinned_field_breaks_the_signature() {
    let f = fixture();
    let signed = &f["signing"]["verdict"];
    let record: SowArbiterVerdictSignature =
        serde_json::from_value(signed["signatures"][0].clone()).expect("a signature record");
    for path in strs(&f["signing"]["tamper"]["fields"]) {
        let mut doc = signed.clone();
        let mut cursor = &mut doc;
        let parts: Vec<&str> = path.split('.').collect();
        for p in &parts[..parts.len() - 1] {
            cursor = cursor.get_mut(*p).unwrap_or_else(|| panic!("path {path}"));
        }
        let leaf = parts[parts.len() - 1];
        let prior = cursor.get(leaf).unwrap_or_else(|| panic!("path {path}")).clone();
        let tampered = match prior {
            Value::Number(n) => Value::from(n.as_u64().expect("integer") + 1),
            Value::String(s) => Value::from(format!("{s}x")),
            other => panic!("unexpected leaf type at {path}: {other}"),
        };
        cursor[leaf] = tampered;
        assert!(
            !verify_arbiter_verdict_signature(&doc, &record),
            "tampering with {path} must break the signature — no re-signing, no repair"
        );
    }
}
