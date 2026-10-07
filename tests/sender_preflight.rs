//! The §6.4b sender pre-flight, asserted against
//! `conformance/sender-preflight.json`.
//!
//! **The fixture is the authority.** When a case here fails, the fix is in
//! `src/preflight.rs`, never in the JSON; the fixture itself changes only with
//! a spec change alongside. Every case pins a LOCAL decision made before an
//! envelope is published — there are no wire bytes and nothing to sign, so all
//! of it runs with no broker, no connection and no clock (§22.8).
//!
//! Cases are executed by **iterating** the fixture (the `inbound-protections`
//! pattern): a row added to the JSON runs here without this file changing,
//! and fails until the implementation honors it.

use agentmesh::{
    input_media_type, preflight_content_types, preflight_envelope_size, preflight_sender_text,
    utf16_len, AgentAttestation, ErrorCode, Manifest, MeshError, NodeRef, Offering,
};
use serde_json::{json, Value};

static FIXTURE_JSON: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/conformance/sender-preflight.json"));

fn fixture() -> Value {
    serde_json::from_str(FIXTURE_JSON).expect("conformance/sender-preflight.json parses")
}

/// The refusal's wire error object, or a panic naming the case: every
/// `refuse_local` row pins a [`MeshError::Refusal`] carrying the recipient's
/// own code.
fn refusal_of(err: MeshError, case: &str) -> agentmesh::ErrorObject {
    match err {
        MeshError::Refusal(eo) => eo,
        other => panic!("case '{case}': a pre-flight refusal keeps its wire error object, got {other}"),
    }
}

// ─── measurement ────────────────────────────────────────────────────────────

#[test]
fn the_unit_is_utf16_code_units_and_at_cap_is_legal() {
    let f = fixture();
    let m = &f["measurement"];
    assert!(m["unit"].as_str().unwrap().contains("UTF-16"));
    // U+1F600 counts 2 (§22.5) — the sender counts as the receiver counts.
    assert_eq!(utf16_len("\u{1F600}"), 2);
    assert_eq!(utf16_len("\u{1F600}a"), 3);
}

// ─── sender_text cases ──────────────────────────────────────────────────────

/// The text a case measures: the literal `text` when the fixture gives one,
/// else a synthesized string of exactly `text_utf16_len` code units.
fn case_text(case: &Value) -> String {
    if let Some(text) = case["text"].as_str() {
        let expected = case["text_utf16_len"].as_u64().unwrap() as usize;
        assert_eq!(utf16_len(text), expected, "the fixture's own length claim holds");
        return text.to_string();
    }
    "a".repeat(case["text_utf16_len"].as_u64().unwrap() as usize)
}

#[test]
fn every_sender_text_case_decides_as_pinned() {
    let f = fixture();
    assert_eq!(
        f["sender_text"]["default_max_inbound_chars"].as_u64().unwrap(),
        agentmesh::DEFAULT_MAX_INBOUND_CHARS as u64,
        "the undeclared default is 22.5's"
    );
    let cases = f["sender_text"]["cases"].as_array().expect("sender_text.cases");
    assert!(!cases.is_empty());
    for case in cases {
        let id = case["id"].as_str().unwrap_or("?");
        let declared_cap = case["declared_cap"].as_u64(); // null → None → default governs
        let input = json!({ "text": case_text(case) });
        let verdict = preflight_sender_text(&input, declared_cap);
        match case["verdict"].as_str().unwrap() {
            "publish" => assert!(verdict.is_ok(), "case '{id}' must publish: {verdict:?}"),
            "refuse_local" => {
                let eo = refusal_of(verdict.expect_err(&format!("case '{id}' must refuse")), id);
                assert_eq!(eo.code, case["error_code"].as_str().unwrap(), "case '{id}' code");
                assert_eq!(eo.retryable, case["retryable"].as_bool().unwrap(), "case '{id}' retryable");
            }
            other => panic!("unknown verdict '{other}' in case '{id}'"),
        }
    }
}

// ─── envelope_size cases ────────────────────────────────────────────────────

#[test]
fn every_envelope_size_case_decides_as_pinned() {
    let f = fixture();
    let cases = f["envelope_size"]["cases"].as_array().expect("envelope_size.cases");
    assert!(!cases.is_empty());
    for case in cases {
        let id = case["id"].as_str().unwrap_or("?");
        let max = case["max_payload_bytes"].as_u64().unwrap() as usize;
        let bytes = case["envelope_bytes"].as_u64().unwrap() as usize;
        let verdict = preflight_envelope_size(bytes, max);
        match case["verdict"].as_str().unwrap() {
            "publish" => assert!(verdict.is_ok(), "case '{id}' must publish: {verdict:?}"),
            "refuse_local" => {
                let eo = refusal_of(verdict.expect_err(&format!("case '{id}' must refuse")), id);
                assert_eq!(eo.code, case["error_code"].as_str().unwrap(), "case '{id}' code");
                assert_eq!(eo.retryable, case["retryable"].as_bool().unwrap(), "case '{id}' retryable");
                // error.details names the limit that fired, so an operator can
                // tell the two 'too large' refusals apart.
                assert_eq!(
                    eo.details.as_ref().and_then(|d| d.get("limit")).and_then(Value::as_str),
                    case["details_limit"].as_str(),
                    "case '{id}' details.limit"
                );
            }
            other => panic!("unknown verdict '{other}' in case '{id}'"),
        }
    }
}

// ─── content_type cases ─────────────────────────────────────────────────────

/// A minimal §8.1 manifest declaring one offering with the case's output modes.
fn manifest_with_offering(offering_id: &str, output_modes: Vec<String>) -> Manifest {
    Manifest {
        id: "URECIPIENT".to_string(),
        name: "fixture".to_string(),
        description: String::new(),
        version: "0.1.0".to_string(),
        protocol_version: "0.2".to_string(),
        encryption_key: None,
        endpoint: "mesh.agent.URECIPIENT.inbox".to_string(),
        endpoints: None,
        limits: None,
        node: NodeRef {
            id: "URECIPIENT".to_string(),
            attestation: AgentAttestation {
                node: "URECIPIENT".to_string(),
                agent: "URECIPIENT".to_string(),
                issued_at: String::new(),
                expires_at: String::new(),
                sig: String::new(),
            },
            profile: None,
        },
        capabilities: vec![],
        offerings: vec![Offering {
            id: offering_id.to_string(),
            name: offering_id.to_string(),
            description: String::new(),
            tags: None,
            input_modes: None,
            output_modes: Some(output_modes),
            streaming: None,
                needs: None,
                delivers: None, reporting: None, trial: None,
        }],
        emits: None,
        accepts: None,
        meta: None,
        trust: None,
        visibility: None,
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
fn every_content_type_case_decides_as_pinned() {
    let f = fixture();
    let cases = f["content_type"]["cases"].as_array().expect("content_type.cases");
    assert!(!cases.is_empty());
    for case in cases {
        let id = case["id"].as_str().unwrap_or("?");
        let output_modes: Vec<String> =
            serde_json::from_value(case["offering_output_modes"].clone()).unwrap();
        let accepted: Vec<String> = serde_json::from_value(case["accepted_output"].clone()).unwrap();
        let manifest = manifest_with_offering("the-offering", output_modes);
        let verdict =
            preflight_content_types(&manifest, "the-offering", Some(&accepted), &json!({ "q": 1 }));
        match case["verdict"].as_str().unwrap() {
            "publish" => assert!(verdict.is_ok(), "case '{id}' must publish: {verdict:?}"),
            "refuse_local" => {
                let eo = refusal_of(verdict.expect_err(&format!("case '{id}' must refuse")), id);
                assert_eq!(eo.code, case["error_code"].as_str().unwrap(), "case '{id}' code");
                assert_eq!(eo.retryable, case["retryable"].as_bool().unwrap(), "case '{id}' retryable");
            }
            other => panic!("unknown verdict '{other}' in case '{id}'"),
        }
    }
}

#[test]
fn input_modes_exclude_by_declared_list_only() {
    // The input-mode side of the content check: a string input is prose, a
    // structured input rides as JSON, and only a DECLARED list excludes.
    assert_eq!(input_media_type(&json!("hello")), "text/plain");
    assert_eq!(input_media_type(&json!({ "q": 1 })), "application/json");
    let mut m = manifest_with_offering("s", vec!["text/plain".into()]);
    m.offerings[0].input_modes = Some(vec!["text/plain".into()]);
    assert!(preflight_content_types(&m, "s", None, &json!("prose")).is_ok());
    let err = preflight_content_types(&m, "s", None, &json!({ "structured": true }))
        .expect_err("JSON input against a text-only offering refuses");
    assert_eq!(refusal_of(err, "input_modes").code, ErrorCode::ContentTypeNotSupported.as_str());
    // Undeclared modes exclude nothing; an undeclared offering checks nothing.
    let bare = manifest_with_offering("s", vec![]);
    assert!(preflight_content_types(&bare, "not-declared", Some(&["image/png".to_string()]), &json!({})).is_ok());
}

// ─── the mirror ─────────────────────────────────────────────────────────────

#[test]
fn a_preflight_refusal_and_a_remote_refusal_are_indistinguishable() {
    // mirror.same_code / same_retryable: a remote CONTEXT_TOO_LARGE error
    // envelope surfaces as the SAME MeshError variant, code and retryable as
    // the local pre-flight refusal, so no caller has to know where a refusal
    // happened. Scope differs (nothing was published locally), shape does not.
    let f = fixture();
    assert_eq!(f["mirror"]["same_code"], json!(true));
    assert_eq!(f["mirror"]["same_retryable"], json!(true));
    assert_eq!(f["mirror"]["nothing_published_on_refusal"], json!(true));

    let local = preflight_sender_text(&json!({ "text": "yy" }), Some(1))
        .expect_err("2 units over a cap of 1");
    let MeshError::Refusal(local_eo) = local else { panic!("local refusal keeps the object") };
    // What the recipient would have sent, arriving as a wire error object.
    let remote = MeshError::from_error_object(&agentmesh::ErrorObject {
        code: ErrorCode::ContextTooLarge.as_str().to_string(),
        message: "some other wording — deliberately not part of the contract".to_string(),
        details: None,
        retryable: false,
        retry_after_ms: None,
    });
    let MeshError::Refusal(remote_eo) = remote else {
        panic!("the remote refusal surfaces as the same variant")
    };
    assert_eq!(local_eo.code, remote_eo.code);
    assert_eq!(local_eo.retryable, remote_eo.retryable);
}
