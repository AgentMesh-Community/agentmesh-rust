//! Agent SoW subcontracting (agentsow.com 0.18.0-draft §5.15), asserted
//! against `conformance/sow-subcontracting.json` — the same file the
//! TypeScript SDK's subcontracting conformance test reads.
//!
//! **The fixture is the authority.** When a case here fails, the fix is in
//! `src/sow.rs`, never in the JSON; a fixture changes only with a spec change
//! alongside. Cases are executed by ITERATING the fixture, so a row added to
//! the JSON runs here without this file changing.
//!
//! The load-bearing assertions are the cross-SDK ones: the closed posture
//! set, the clause shape (an entry names a party on the mesh and the
//! vocabulary offers no other kind), the flow-down violation sentences a
//! provider reads whichever SDK computed the chain — string equality on the
//! whole sentence, order included — and the canonical bytes of a document
//! whose subcontracting clause sits INSIDE what is signed.

use serde_json::Value;

use agentmesh::{
    canonical_sow_json, subcontract_conformance_with, subcontracting_of, validate_sow_subcontracting, SubcontractOpts,
    SowSubcontracting, SowSubcontractingPosture, SOW_SUBCONTRACTING_POSTURES,
};

static FIXTURE_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/conformance/sow-subcontracting.json"
));

fn fixture() -> Value {
    serde_json::from_str(FIXTURE_JSON).expect("conformance/sow-subcontracting.json parses")
}

// ─── §5.15 the three postures, a closed set ─────────────────────────────────

#[test]
fn the_posture_set_is_closed_and_matches_the_fixture() {
    let f = fixture();
    let want: Vec<String> = f["postures"]["all"]
        .as_array()
        .expect("postures.all")
        .iter()
        .map(|s| s.as_str().expect("string").to_string())
        .collect();
    let got: Vec<String> = SOW_SUBCONTRACTING_POSTURES.iter().map(|s| s.to_string()).collect();
    assert_eq!(got, want, "the posture set is the fixture's, in the fixture's order");
    for name in &want {
        let posture = SowSubcontractingPosture::from_str(name)
            .unwrap_or_else(|| panic!("'{name}' is a known posture"));
        assert_eq!(posture.as_str(), name, "the wire string round-trips");
    }
    // Nothing outside the closed vocabulary parses.
    assert!(SowSubcontractingPosture::from_str("undisclosed").is_none());
}

#[test]
fn absence_states_nothing() {
    // A document without the clause yields None, never a posture.
    assert!(subcontracting_of(&serde_json::json!({})).is_none());
    assert!(subcontracting_of(&serde_json::json!({ "subcontracting": null })).is_none());
    let doc = serde_json::json!({ "subcontracting": { "posture": "disclosed", "grade": "evidence" } });
    assert!(subcontracting_of(&doc).is_some());
}

// ─── §5.15 the clause shape ─────────────────────────────────────────────────

#[test]
fn every_valid_subcontracting_clause_validates_and_round_trips_through_serde() {
    let f = fixture();
    for clause in f["clause"]["valid"].as_array().expect("clause.valid") {
        validate_sow_subcontracting(clause)
            .unwrap_or_else(|e| panic!("valid clause refused: {e}\n{clause:#}"));
        // The typed clause re-serializes to the same canonical bytes — the
        // clause sits inside the signed document, so serde may not add or
        // drop a member.
        let typed: SowSubcontracting =
            serde_json::from_value(clause.clone()).expect("a valid clause deserializes");
        assert_eq!(
            agentmesh::canonical_json(&serde_json::to_value(&typed).unwrap()),
            agentmesh::canonical_json(clause),
            "the typed clause must re-serialize to the bytes it came from"
        );
    }
}

#[test]
fn every_invalid_subcontracting_clause_is_refused() {
    let f = fixture();
    for row in f["clause"]["invalid"].as_array().expect("clause.invalid") {
        let case = row["case"].as_str().unwrap();
        let why = row["why"].as_str().unwrap();
        assert!(
            validate_sow_subcontracting(&row["subcontracting"]).is_err(),
            "'{case}' must be refused — {why}"
        );
    }
}

// ─── §5.15 the flow-down comparison ─────────────────────────────────────────

#[test]
fn every_conformance_case_reproduces_its_pinned_sentences_exactly() {
    let f = fixture();
    for c in f["conformance"]["cases"].as_array().expect("conformance.cases") {
        let name = c["name"].as_str().unwrap();
        let o = c.get("opts");
        let opts = SubcontractOpts {
            prime_cap_remaining: o.and_then(|o| o.get("prime_cap_remaining")).and_then(|n| n.as_u64()),
            require_pins: o.and_then(|o| o.get("require_pins")).and_then(|b| b.as_bool()).unwrap_or(false),
        };
        let got = subcontract_conformance_with(&c["prime"], &c["sub"], &opts);
        let want: Vec<String> = c["violations"]
            .as_array()
            .expect("violations")
            .iter()
            .map(|s| s.as_str().expect("sentence").to_string())
            .collect();
        // The wording AND the order are part of the fixture: a provider
        // reads one message whichever SDK computed the chain.
        assert_eq!(got, want, "'{name}': the sentences are pinned");
    }
}

// ─── §6 the clause sits inside the signed bytes ─────────────────────────────

#[test]
fn the_canonical_bytes_of_a_subcontracting_document_reproduce_exactly() {
    let f = fixture();
    assert_eq!(
        canonical_sow_json(&f["signing"]["document"]),
        f["signing"]["canonical"].as_str().expect("signing.canonical"),
        "one byte of canonical drift is a document that verifies in one SDK and is worthless \
         in the other"
    );
}
