//! Agent SoW liability and service floors (agentsow.com 0.16.0-draft §5.13,
//! §5.14), asserted against `conformance/sow-terms.json` — the same file the
//! TypeScript SDK's terms conformance test reads.
//!
//! **The fixture is the authority.** When a case here fails, the fix is in
//! `src/sow.rs`, never in the JSON; a fixture changes only with a spec change
//! alongside. Cases are executed by ITERATING the fixture, so a row added to
//! the JSON runs here without this file changing.
//!
//! The load-bearing assertion is the canonical-bytes one: both clauses sit
//! INSIDE the signed bytes, so one byte of canonical drift between the SDKs
//! is a document that verifies in one and is worthless in the other.

use serde_json::Value;

use agentmesh::{
    canonical_sow_json, liability_of, service_floors_of, validate_sow_liability,
    validate_sow_service_floors, SowLiability, SowServiceFloors, SOW_FLOOR_REMEDIES,
};

static FIXTURE_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/conformance/sow-terms.json"
));

fn fixture() -> Value {
    serde_json::from_str(FIXTURE_JSON).expect("conformance/sow-terms.json parses")
}

// ─── §5.13 the liability clause ─────────────────────────────────────────────

#[test]
fn every_valid_liability_clause_validates_and_round_trips_through_serde() {
    let f = fixture();
    for clause in f["liability"]["valid"].as_array().expect("liability.valid") {
        validate_sow_liability(clause)
            .unwrap_or_else(|e| panic!("valid liability clause refused: {e}\n{clause:#}"));
        // The typed clause re-serializes to the same canonical bytes — the
        // clause sits inside the signed document, so serde may not add or
        // drop a member.
        let typed: SowLiability =
            serde_json::from_value(clause.clone()).expect("a valid liability clause deserializes");
        assert_eq!(
            agentmesh::canonical_json(&serde_json::to_value(&typed).unwrap()),
            agentmesh::canonical_json(clause),
            "the typed clause must re-serialize to the bytes it came from"
        );
    }
}

#[test]
fn every_invalid_liability_clause_is_refused() {
    let f = fixture();
    for row in f["liability"]["invalid"].as_array().expect("liability.invalid") {
        let case = row["case"].as_str().unwrap();
        let why = row["why"].as_str().unwrap();
        assert!(
            validate_sow_liability(&row["liability"]).is_err(),
            "'{case}' must be refused — {why}"
        );
    }
}

// ─── §5.14 the service floors clause ────────────────────────────────────────

#[test]
fn the_remedy_set_is_closed_with_the_fixtures_one_member() {
    let f = fixture();
    let want: Vec<String> = f["service_floors"]["remedies"]
        .as_array()
        .expect("service_floors.remedies")
        .iter()
        .map(|s| s.as_str().expect("string").to_string())
        .collect();
    let got: Vec<String> = SOW_FLOOR_REMEDIES.iter().map(|s| s.to_string()).collect();
    assert_eq!(got, want, "the closed remedy set grows only with the spec");
}

#[test]
fn every_valid_service_floors_clause_validates_and_round_trips_through_serde() {
    let f = fixture();
    for clause in f["service_floors"]["valid"].as_array().expect("service_floors.valid") {
        validate_sow_service_floors(clause)
            .unwrap_or_else(|e| panic!("valid service floors clause refused: {e}\n{clause:#}"));
        let typed: SowServiceFloors = serde_json::from_value(clause.clone())
            .expect("a valid service floors clause deserializes");
        assert_eq!(
            agentmesh::canonical_json(&serde_json::to_value(&typed).unwrap()),
            agentmesh::canonical_json(clause),
            "the typed clause must re-serialize to the bytes it came from"
        );
    }
}

#[test]
fn every_invalid_service_floors_clause_is_refused() {
    let f = fixture();
    for row in f["service_floors"]["invalid"].as_array().expect("service_floors.invalid") {
        let case = row["case"].as_str().unwrap();
        let why = row["why"].as_str().unwrap();
        assert!(
            validate_sow_service_floors(&row["service_floors"]).is_err(),
            "'{case}' must be refused — {why}"
        );
    }
}

// ─── the accessors: absence states nothing ──────────────────────────────────

#[test]
fn the_accessors_read_unvalidated_and_absence_is_none() {
    let f = fixture();
    let doc = &f["signing"]["document"];
    assert_eq!(liability_of(doc), Some(&doc["liability"]));
    assert_eq!(service_floors_of(doc), Some(&doc["service_floors"]));

    let empty = serde_json::json!({});
    assert_eq!(liability_of(&empty), None, "absence states nothing — never a synthesized clause");
    assert_eq!(service_floors_of(&empty), None, "absence states nothing — never a default bound");

    // A clause in a non-object shape is not a clause this reader hands back.
    let odd = serde_json::json!({ "liability": "capped", "service_floors": ["fast"] });
    assert_eq!(liability_of(&odd), None);
    assert_eq!(service_floors_of(&odd), None);
}

// ─── §5.13 + §5.14 inside the signed bytes ──────────────────────────────────

#[test]
fn the_canonical_bytes_of_a_terms_document_reproduce_exactly() {
    let f = fixture();
    assert_eq!(
        canonical_sow_json(&f["signing"]["document"]),
        f["signing"]["canonical"].as_str().expect("signing.canonical"),
        "one byte of canonical drift is a document that verifies in one SDK and is worthless \
         in the other"
    );
    let canonical = f["signing"]["canonical"].as_str().unwrap();
    assert!(canonical.contains("\"liability\""));
    assert!(canonical.contains("\"service_floors\""));
}

#[test]
fn the_signing_documents_clauses_validate() {
    let f = fixture();
    let doc = &f["signing"]["document"];
    validate_sow_liability(liability_of(doc).expect("the document carries liability"))
        .expect("the signing document's liability clause validates");
    validate_sow_service_floors(service_floors_of(doc).expect("the document carries service_floors"))
        .expect("the signing document's service floors clause validates");
}
