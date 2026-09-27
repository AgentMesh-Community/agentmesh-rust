//! The five questions (SPEC.md §3.3.1), asserted against
//! `conformance/five-questions.json`.
//!
//! **The fixture is the authority.** When a case here fails, the fix is in
//! `src/interview.rs`, never in the JSON; the fixture itself changes only
//! with a spec change alongside. Cases are executed by **iterating** the
//! fixture: a row added to the JSON runs here without this file changing.
//! The TS suite (`__tests__/unit/five-questions-conformance.test.ts`)
//! asserts the same rows, and both compare through RFC 8785
//! canonicalization, so agreement is byte-exact.

use agentmesh::interview::{
    describe_document_of, diff_answers, project_five_questions, FiveAnswers, FIVE_QUESTIONS,
    REFUSAL_STATEMENT,
};
use agentmesh::canonical_json;
use serde_json::{json, Value};

static FIXTURE_JSON: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/conformance/five-questions.json"));

fn fixture() -> Value {
    serde_json::from_str(FIXTURE_JSON).expect("conformance/five-questions.json parses")
}

fn projection_case<'a>(f: &'a Value, name: &str) -> &'a Value {
    f["projection"]["cases"]
        .as_array()
        .expect("projection cases")
        .iter()
        .find(|c| c["name"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("fixture names no projection case {name}"))
}

#[test]
fn the_refusal_statement_matches_the_fixture_bytes() {
    let f = fixture();
    assert_eq!(REFUSAL_STATEMENT, f["refusal_statement"].as_str().expect("statement"));
}

#[test]
fn the_questions_are_the_five_in_spec_order() {
    assert_eq!(FIVE_QUESTIONS, ["identity", "capabilities", "usage", "terms", "refusals"]);
}

#[test]
fn every_projection_case_projects_to_the_pinned_answers() {
    let f = fixture();
    let cases = f["projection"]["cases"].as_array().expect("projection cases");
    assert!(!cases.is_empty());
    for case in cases {
        let name = case["name"].as_str().unwrap_or("?");
        let answers = project_five_questions(&case["describe"])
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let projected = serde_json::to_value(&answers).expect("answers serialize");
        assert_eq!(
            canonical_json(&projected),
            canonical_json(&case["expected"]),
            "{name}: projection disagrees with the fixture"
        );
    }
}

#[test]
fn a_projection_carries_exactly_the_five_questions() {
    let f = fixture();
    for case in f["projection"]["cases"].as_array().expect("cases") {
        let answers = project_five_questions(&case["describe"]).expect("projects");
        let v = serde_json::to_value(&answers).expect("serializes");
        let mut keys: Vec<&str> =
            v.as_object().expect("object").keys().map(String::as_str).collect();
        keys.sort_unstable();
        let mut expected = FIVE_QUESTIONS;
        expected.sort_unstable();
        assert_eq!(keys, expected);
    }
}

#[test]
fn a_non_object_document_is_refused() {
    for bad in [Value::Null, json!(7), json!("describe"), json!([1, 2])] {
        assert!(project_five_questions(&bad).is_err(), "should refuse {bad}");
    }
}

#[test]
fn every_diff_case_reports_the_pinned_mismatches() {
    let f = fixture();
    let cases = f["diff"]["cases"].as_array().expect("diff cases");
    assert!(!cases.is_empty());
    for case in cases {
        let name = case["name"].as_str().unwrap_or("?");
        let declared_case = case["declared_case"].as_str().expect("declared_case");
        let declared = project_five_questions(&projection_case(&f, declared_case)["describe"])
            .unwrap_or_else(|e| panic!("{name}: declared projection: {e}"));
        let claimed: &Value = match case["claimed_case"].as_str() {
            Some(claimed_case) => &projection_case(&f, claimed_case)["expected"],
            None => &case["claimed"],
        };
        let mismatches = diff_answers(&declared, claimed).unwrap_or_else(|e| panic!("{name}: {e}"));
        let reported = serde_json::to_value(&mismatches).expect("mismatches serialize");
        assert_eq!(
            canonical_json(&reported),
            canonical_json(&case["expected"]),
            "{name}: diff disagrees with the fixture"
        );
    }
}

#[test]
fn a_projection_diffed_against_itself_is_empty() {
    let f = fixture();
    for case in f["projection"]["cases"].as_array().expect("cases") {
        let declared = project_five_questions(&case["describe"]).expect("projects");
        let as_claim = serde_json::to_value(&declared).expect("serializes");
        assert_eq!(diff_answers(&declared, &as_claim).expect("diffs"), vec![]);
    }
}

#[test]
fn a_non_object_claim_set_is_refused() {
    let declared: FiveAnswers =
        project_five_questions(&json!({ "agent_id": "U1" })).expect("projects");
    for bad in [Value::Null, json!(7), json!("yes"), json!(["identity"])] {
        assert!(diff_answers(&declared, &bad).is_err(), "should refuse {bad}");
    }
}

#[test]
fn unknown_question_keys_in_a_claim_are_ignored() {
    let declared = project_five_questions(&json!({ "agent_id": "U1" })).expect("projects");
    let claimed = json!({ "reputation": { "score": 11 } });
    assert_eq!(diff_answers(&declared, &claimed).expect("diffs"), vec![]);
}

#[test]
fn an_offering_detail_without_an_id_is_skipped_not_invented() {
    let answers = project_five_questions(&json!({
        "agent_id": "U1",
        "public": { "offering_details": [ { "name": "nameless" }, "not an object" ] }
    }))
    .expect("projects");
    assert!(answers.usage.is_empty());
    // The details themselves are still capabilities data, verbatim.
    assert_eq!(
        answers.capabilities["offering_details"],
        json!([{ "name": "nameless" }, "not an object"])
    );
    assert_eq!(answers.refusals["boundary"], json!([]));
}

#[test]
fn boundary_deduplicates_preserving_first_seen_order() {
    let answers = project_five_questions(&json!({
        "agent_id": "U1",
        "public": { "offerings": ["b", "a", "b", 7, ""] }
    }))
    .expect("projects");
    assert_eq!(answers.refusals["boundary"], json!(["b", "a"]));
}

#[test]
fn a_differing_claimed_member_mismatches_with_both_values_named() {
    let declared = project_five_questions(&json!({ "agent_id": "U1" })).expect("projects");
    let mismatches = diff_answers(&declared, &json!({ "identity": { "agent_id": "U2" } }))
        .expect("diffs");
    assert_eq!(
        serde_json::to_value(&mismatches).expect("serializes"),
        json!([{
            "question": "identity",
            "path": "identity.agent_id",
            "declared": "U1",
            "claimed": "U2"
        }])
    );
}

#[test]
fn describe_document_of_carries_the_storefront_fields_and_never_the_card() {
    // Built as JSON and deserialized, because a Manifest's required members
    // (node, attestation) are beside the point here.
    let manifest: agentmesh::Manifest = serde_json::from_value(json!({
        "id": "UAKQRYZBYFOC65OQZVJ3QPCIERDTRNNZPMOJUYXC3DGPRCDWSKD4HV5A",
        "name": "Text Stats",
        "description": "unpublished internal description",
        "version": "1.0.0",
        "protocol_version": "0.2",
        "endpoint": "mesh.agent.UAKQ.inbox",
        "node": {
            "id": "UB1",
            "attestation": {
                "node": "UB1",
                "agent": "UAKQ",
                "issued_at": "2026-08-10T00:00:00Z",
                "expires_at": "2026-08-11T00:00:00Z",
                "sig": "c2ln"
            }
        },
        "capabilities": [],
        "offerings": [],
        "owner": "UBMBH4BK6EIHQFVMHLSABFSQXB3JXUFZOXVZQTIERO33AD4HHAI3D7QP",
        "interaction": "service",
        "sealing": "preferred",
        "public": { "description": "Counts words.", "offerings": ["text-stats"], "admission": "Open." }
    }))
    .expect("manifest parses");

    let doc = describe_document_of(&manifest).expect("derives");
    let obj = doc.as_object().expect("object");
    assert_eq!(obj["agent_id"], manifest.id.clone());
    assert_eq!(obj["name"], json!("Text Stats"));
    assert_eq!(obj["interaction"], json!("service"));
    assert_eq!(obj["sealing"], json!("preferred"));
    assert!(obj.get("card").is_none(), "the registry get carries no card; none may be invented");
    assert!(
        obj.get("description").is_none(),
        "the internal description is not pre-admission data; only public.description answers strangers"
    );

    let answers = project_five_questions(&doc).expect("projects");
    assert_eq!(answers.capabilities["description"], json!("Counts words."));
    assert_eq!(answers.terms["admission"], json!("Open."));
    assert_eq!(answers.refusals["boundary"], json!(["text-stats"]));
    assert_eq!(answers.refusals["statement"], json!(REFUSAL_STATEMENT));
}
