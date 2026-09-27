//! Agent SoW confidentiality and retention (agentsow.com 0.14.0-draft §5.11),
//! asserted against `conformance/sow-data-use.json` — the same file the
//! TypeScript SDK's data-use conformance test reads.
//!
//! **The fixture is the authority.** When a case here fails, the fix is in
//! `src/sow.rs`, never in the JSON; a fixture changes only with a spec change
//! alongside. Cases are executed by ITERATING the fixture, so a row added to
//! the JSON runs here without this file changing.
//!
//! The load-bearing assertions are the cross-SDK ones: the closed promise
//! vocabulary spelled only by presence, the clause shapes (empty processors
//! VALID and meaningful, false refused because it is spelled by omission,
//! the promises grade never more than `recorded`), the exact shortfall
//! sentences a client reads whichever SDK evaluated them, and the canonical
//! bytes of a document whose confidentiality clause sits INSIDE what is
//! signed.

use serde_json::Value;

use agentmesh::{
    canonical_sow_json, confidentiality_of, confidentiality_shortfall,
    validate_sow_confidentiality, SowConfidentiality, SowConfidentialityPromise,
    SowConfidentialityRequirement, SOW_CONFIDENTIALITY_PROMISES,
};

static FIXTURE_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/conformance/sow-data-use.json"
));

fn fixture() -> Value {
    serde_json::from_str(FIXTURE_JSON).expect("conformance/sow-data-use.json parses")
}

fn strs(v: &Value) -> Vec<String> {
    v.as_array()
        .expect("array")
        .iter()
        .map(|s| s.as_str().expect("string").to_string())
        .collect()
}

// ─── §5.11 the promise vocabulary ───────────────────────────────────────────

#[test]
fn the_promise_vocabulary_is_closed_and_matches_the_fixture() {
    let f = fixture();
    let want = strs(&f["promises"]["all"]);
    let got: Vec<String> = SOW_CONFIDENTIALITY_PROMISES.iter().map(|s| s.to_string()).collect();
    assert_eq!(got, want, "the promise vocabulary is the fixture's");
    // Every name round-trips through the typed enum, and nothing outside the
    // closed vocabulary parses.
    for name in &want {
        let promise = SowConfidentialityPromise::from_str(name)
            .unwrap_or_else(|| panic!("'{name}' is a known promise"));
        assert_eq!(promise.as_str(), name);
    }
    assert!(SowConfidentialityPromise::from_str("no_selling").is_none());
}

// ─── §5.11 the clause shape ─────────────────────────────────────────────────

#[test]
fn every_valid_confidentiality_clause_validates_and_round_trips_through_serde() {
    let f = fixture();
    for clause in f["clause"]["valid"].as_array().expect("clause.valid") {
        validate_sow_confidentiality(clause)
            .unwrap_or_else(|e| panic!("valid clause refused: {e}\n{clause:#}"));
        // The typed clause re-serializes to the same canonical bytes — the
        // clause sits inside the signed document, so serde may not add or drop
        // a member. An EMPTY processors list must survive: empty states
        // "nowhere", omission states nothing, and the two are different bytes.
        let typed: SowConfidentiality =
            serde_json::from_value(clause.clone()).expect("a valid clause deserializes");
        assert_eq!(
            agentmesh::canonical_json(&serde_json::to_value(&typed).unwrap()),
            agentmesh::canonical_json(clause),
            "the typed clause must re-serialize to the bytes it came from"
        );
    }
}

#[test]
fn every_invalid_confidentiality_clause_is_refused() {
    let f = fixture();
    for row in f["clause"]["invalid"].as_array().expect("clause.invalid") {
        let case = row["case"].as_str().unwrap();
        let why = row["why"].as_str().unwrap();
        assert!(
            validate_sow_confidentiality(&row["confidentiality"]).is_err(),
            "'{case}' must be refused — {why}"
        );
    }
}

// ─── §5.11 the accessor ─────────────────────────────────────────────────────

#[test]
fn confidentiality_of_returns_the_declared_clause_unvalidated_or_none() {
    let f = fixture();
    assert!(confidentiality_of(&serde_json::json!({})).is_none());
    assert!(confidentiality_of(&serde_json::json!({ "confidentiality": null })).is_none());
    assert!(confidentiality_of(&serde_json::json!({ "confidentiality": "sealed" })).is_none());
    let doc = &f["signing"]["document"];
    assert_eq!(
        confidentiality_of(doc),
        Some(&doc["confidentiality"]),
        "the declared clause comes back untouched"
    );
}

// ─── §5.11 the deterministic pre-admission comparison ───────────────────────

#[test]
fn every_shortfall_case_reproduces_the_pinned_sentence_exactly() {
    let f = fixture();
    for c in f["shortfall"]["cases"].as_array().expect("shortfall.cases") {
        let name = c["name"].as_str().unwrap();
        let required: SowConfidentialityRequirement =
            serde_json::from_value(c["required"].clone())
                .unwrap_or_else(|e| panic!("'{name}': the requirement deserializes: {e}"));
        let got = confidentiality_shortfall(&required, &c["document"]);
        match c["expected"].as_str() {
            // The wording is part of the fixture: a client reads one message
            // whichever SDK evaluated it. String equality, not contains.
            Some(sentence) => assert_eq!(
                got.as_deref(),
                Some(sentence),
                "'{name}': the sentence is pinned"
            ),
            None => assert_eq!(got, None, "'{name}': meets, so no shortfall"),
        }
    }
}

// ─── §6 the clause sits inside the signed bytes ─────────────────────────────

#[test]
fn the_canonical_bytes_of_a_confidentiality_document_reproduce_exactly() {
    let f = fixture();
    assert_eq!(
        canonical_sow_json(&f["signing"]["document"]),
        f["signing"]["canonical"].as_str().expect("signing.canonical"),
        "one byte of canonical drift is a document that verifies in one SDK and is worthless \
         in the other"
    );
}
