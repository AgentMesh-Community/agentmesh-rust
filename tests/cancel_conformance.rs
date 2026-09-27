//! The §10.8 cancel wire shapes, asserted against `conformance/cancel.json`.
//!
//! **THE FIXTURE IS THE AUTHORITY.** When a case here fails, the fix is in
//! `src/cancel.rs` (or `src/client.rs`), never in the JSON; the fixture
//! itself changes only with a spec change alongside. Two independent
//! implementations do not disagree about Ed25519 — they disagree about
//! whether `cancelled` has one l or two, whether an absent note is omitted or
//! null, and whether a propagated note joins with `: ` or ` - `. Those are
//! exactly the bytes this fixture pins.
//!
//! Cases are executed by **iterating** the fixture rather than by naming them
//! in Rust (the `budget_conformance` pattern): a row added to the JSON runs
//! here without this file changing, and fails until the implementation honors
//! it.
//!
//! `include_str!`'d rather than read at run time so editing the fixture
//! forces a rebuild.

use std::collections::BTreeSet;

use agentmesh::{
    cancel_request_payload, canceled_update_payload, canonical_json, codec, failed_update_payload,
    is_terminal_task_state, is_unmet_need_ref, need_ref_of, parse_unmet_need_ref,
    propagated_cancel_note, validate_cancel_input, validate_stop_qualifier, CancelReason,
    StopQualifier, CANCEL_OFFERING, NEED_KINDS, TERMINAL_TASK_STATES,
};
use serde_json::Value;

static FIXTURE_JSON: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/conformance/cancel.json"));

fn fixture() -> Value {
    serde_json::from_str(FIXTURE_JSON).expect("conformance/cancel.json parses")
}

/// The fixture's `reason` strings, parsed strictly — a test that consumed a
/// reason the enum refuses would be asserting against nothing.
fn reason_of(v: &Value) -> CancelReason {
    CancelReason::from_wire(v.as_str().expect("fixture reason is a string"))
        .expect("fixture reasons are in the closed enum")
}

// ─── reasons: the closed enum, exact bytes ──────────────────────────────────

#[test]
fn every_reason_string_parses_and_serializes_back_to_the_same_bytes() {
    let f = fixture();
    let reasons = f["reasons"]["enum"].as_array().expect("reasons.enum");
    assert_eq!(reasons.len(), 8, "the §10.8 enum is eight values, closed");
    for wire in reasons {
        let wire = wire.as_str().expect("fixture reason is a string");
        let parsed = CancelReason::from_wire(wire)
            .unwrap_or_else(|| panic!("fixture reason '{wire}' must parse"));
        assert_eq!(parsed.as_str(), wire, "as_str returns the exact wire bytes");
        assert_eq!(
            serde_json::to_value(parsed).unwrap(),
            Value::String(wire.to_string()),
            "serde serializes '{wire}' back to the same bytes"
        );
        assert_eq!(
            serde_json::from_value::<CancelReason>(Value::String(wire.to_string())).unwrap(),
            parsed,
            "serde deserializes '{wire}' to the same variant"
        );
        assert_eq!(
            wire.parse::<CancelReason>().unwrap(),
            parsed,
            "FromStr agrees with from_wire for '{wire}'"
        );
    }
}

#[test]
fn the_descriptions_cover_exactly_the_enum() {
    // A description for a reason outside the enum — or an enum value nobody
    // described — is the fixture and the spec drifting apart.
    let f = fixture();
    let enum_set: BTreeSet<&str> = f["reasons"]["enum"]
        .as_array()
        .expect("reasons.enum")
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    let described: BTreeSet<&str> = f["reasons"]["descriptions"]
        .as_object()
        .expect("reasons.descriptions")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(enum_set, described);
}

// ─── invalid: rejected at the door, as INVALID_ENVELOPE ─────────────────────

#[test]
fn every_invalid_case_is_rejected_as_invalid_envelope() {
    let f = fixture();
    let cases = f["invalid"]["cases"].as_array().expect("invalid.cases");
    assert!(!cases.is_empty());
    for case in cases {
        let name = case["case"].as_str().unwrap_or("?");
        let why = case["why"].as_str().unwrap_or("");
        let err = validate_cancel_input(&case["input"])
            .expect_err(&format!("fixture case '{name}' must be refused ({why})"));
        assert!(
            err.to_string().contains("INVALID_ENVELOPE"),
            "case '{name}' must refuse as INVALID_ENVELOPE, got: {err}"
        );
    }
}

// ─── propagation: the pinned forwarded bytes ────────────────────────────────

#[test]
fn every_propagation_case_produces_the_pinned_forwarded_bytes() {
    let f = fixture();
    let cases = f["propagation"]["cases"].as_array().expect("propagation.cases");
    assert!(!cases.is_empty());
    for case in cases {
        let name = case["case"].as_str().unwrap_or("?");
        let original_reason = reason_of(&case["original"]["reason"]);
        let original_note = case["original"]["note"].as_str();
        // The forwarded reason is upstream_cancelled at every hop — the
        // fixture states it per case, and it is never anything else.
        assert_eq!(
            CancelReason::UpstreamCancelled.as_str(),
            case["forwarded"]["reason"].as_str().unwrap(),
            "case '{name}': the forwarded reason"
        );
        assert_eq!(
            propagated_cancel_note(original_reason, original_note),
            case["forwarded"]["note"].as_str().unwrap(),
            "case '{name}': the forwarded note, byte for byte"
        );
    }
}

// ─── shapes: both legs of the cancel ────────────────────────────────────────

/// The qualifier a pinned shape carries, read straight off the JSON.
fn qualifier_of(v: &Value) -> StopQualifier {
    StopQualifier {
        unmet_need: v.get("unmet_need").and_then(Value::as_str).map(str::to_string),
        dependency: v.get("dependency").and_then(Value::as_str).map(str::to_string),
    }
}

#[test]
fn the_request_payload_shapes_validate_and_rebuild_exactly() {
    let f = fixture();
    for key in ["cancel_request_payload", "cancel_request_payload_no_note"] {
        let pinned = &f["shapes"][key];
        assert_eq!(pinned["offering"].as_str().unwrap(), CANCEL_OFFERING, "{key}: the offering name");
        // The inbound door accepts the fixture's input...
        let input = validate_cancel_input(&pinned["input"])
            .unwrap_or_else(|e| panic!("{key} must validate: {e}"));
        // ...and this SDK rebuilds the identical payload from the typed parts,
        // including the note OMITTED (not null) when the fixture omits it.
        let rebuilt = cancel_request_payload(
            &input.task_id,
            input.reason,
            input.note.as_deref(),
            Some(&input.qualifier),
        );
        assert_eq!(&rebuilt, pinned, "{key}: rebuilt payload");
        if pinned["input"].get("note").is_none() {
            assert!(
                rebuilt["input"].get("note").is_none(),
                "{key}: an absent note stays absent — never null"
            );
        }
    }
}

#[test]
fn the_canceled_update_payload_shapes_rebuild_exactly() {
    let f = fixture();
    for key in [
        "canceled_update_payload",
        "canceled_update_payload_no_note",
        "canceled_update_payload_unmet_need",
    ] {
        let pinned = &f["shapes"][key];
        assert_eq!(pinned["status"].as_str().unwrap(), "canceled");
        let reason = reason_of(&pinned["reason"]);
        let note = pinned["note"].as_str();
        let qualifier = qualifier_of(pinned);
        validate_stop_qualifier(Some(reason), Some(&qualifier))
            .unwrap_or_else(|e| panic!("{key} must validate: {e}"));
        let rebuilt = canceled_update_payload(reason, note, Some(&qualifier));
        assert_eq!(&rebuilt, pinned, "{key}: rebuilt payload");
        if note.is_none() {
            assert!(
                rebuilt.get("note").is_none(),
                "{key}: an absent note stays absent — never null"
            );
        }
    }
}

#[test]
fn the_failed_update_payload_shapes_rebuild_exactly() {
    // §10.8: the same vocabulary ends a `failed` Task, and there the reason is
    // OPTIONAL — a Task that simply did not work out is a complete statement.
    let f = fixture();
    for key in [
        "failed_update_payload",
        "failed_update_payload_unmet_need",
        "failed_update_payload_bare",
    ] {
        let pinned = &f["shapes"][key];
        assert_eq!(pinned["status"].as_str().unwrap(), "failed");
        let reason = pinned.get("reason").map(reason_of);
        let note = pinned["note"].as_str();
        let qualifier = qualifier_of(pinned);
        validate_stop_qualifier(reason, Some(&qualifier))
            .unwrap_or_else(|e| panic!("{key} must validate: {e}"));
        assert_eq!(
            &failed_update_payload(reason, note, Some(&qualifier)),
            pinned,
            "{key}: rebuilt payload"
        );
    }
}

// ─── unmet_need: the reference a claim about the caller has to name ─────────

#[test]
fn the_fixtures_need_kinds_are_this_sdks_need_kinds() {
    let f = fixture();
    let kinds: BTreeSet<&str> = f["unmet_need"]["kinds"]
        .as_array()
        .expect("unmet_need.kinds")
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(kinds, NEED_KINDS.iter().copied().collect::<BTreeSet<&str>>());
}

#[test]
fn every_valid_unmet_need_parses_and_every_invalid_one_is_refused() {
    let f = fixture();
    for v in f["unmet_need"]["valid"].as_array().expect("unmet_need.valid") {
        let r = v.as_str().unwrap();
        assert!(is_unmet_need_ref(r), "'{r}' must be a well-formed reference");
        let (kind, value) = parse_unmet_need_ref(r).unwrap();
        assert!(NEED_KINDS.contains(&kind), "'{r}': kind is one of the §8.5.1 four");
        // Split at the FIRST colon only: the value may carry its own.
        assert_eq!(format!("{kind}:{value}"), r);
        validate_stop_qualifier(
            Some(CancelReason::NeedsNotFurnished),
            Some(&StopQualifier::unmet_need(r)),
        )
        .unwrap_or_else(|e| panic!("'{r}' must be accepted: {e}"));
    }
    for v in f["unmet_need"]["invalid"].as_array().expect("unmet_need.invalid") {
        let r = v.as_str().unwrap();
        assert!(!is_unmet_need_ref(r), "'{r}' must be refused as a reference");
        assert!(
            validate_stop_qualifier(
                Some(CancelReason::NeedsNotFurnished),
                Some(&StopQualifier::unmet_need(r)),
            )
            .is_err(),
            "'{r}' must be refused at the door"
        );
    }
}

#[test]
fn a_need_entry_maps_onto_the_reference_its_offering_would_be_judged_by() {
    // The platform compares two strings: one the manifest wrote at
    // registration, one the failing agent wrote at the end. Both come from
    // here, which is why they can be compared at all (§10.8a).
    assert_eq!(
        need_ref_of(&serde_json::json!({ "credential": "Salesforce", "scope": "read invoices" })),
        Some("credential:Salesforce".to_string())
    );
    assert_eq!(
        need_ref_of(&serde_json::json!({ "resource": "git-repo", "access": "read-write" })),
        Some("resource:git-repo".to_string())
    );
    assert_eq!(need_ref_of(&serde_json::json!({ "description": "no kind" })), None);
}

#[test]
fn a_reason_that_takes_no_qualifier_refuses_one() {
    // Each qualifier is meaningful with exactly one reason (§10.8). Letting
    // one ride any other reason would make the claim unreadable, and an
    // unreadable claim is the thing §10.8a exists to prevent.
    assert!(validate_stop_qualifier(
        Some(CancelReason::Policy),
        Some(&StopQualifier::unmet_need("credential:Salesforce"))
    )
    .is_err());
    assert!(validate_stop_qualifier(
        Some(CancelReason::UserRequested),
        Some(&StopQualifier::dependency("Colorado DMV"))
    )
    .is_err());
    // A bare failure carries neither.
    assert!(validate_stop_qualifier(None, Some(&StopQualifier::unmet_need("file:text/csv"))).is_err());
    assert!(validate_stop_qualifier(None, None).is_ok());
    // And needs_not_furnished without one is refused outright.
    assert!(validate_stop_qualifier(Some(CancelReason::NeedsNotFurnished), None).is_err());
}

// ─── envelope: canonical bytes and the signature over them ──────────────────

#[test]
fn the_pinned_envelopes_canonical_bytes_reproduce_exactly() {
    // The TS SDK generated `canonical` and signed it; this SDK must derive
    // the identical byte string from the signed envelope minus `sig`. One
    // byte of drift here is a cancel that verifies in one SDK and not the
    // other.
    let f = fixture();
    let mut unsigned = f["envelope"]["signed"].clone();
    unsigned.as_object_mut().expect("signed is an object").remove("sig");
    assert_eq!(
        canonical_json(&unsigned),
        f["envelope"]["canonical"].as_str().expect("envelope.canonical"),
    );
}

#[test]
fn the_signature_covers_the_pinned_prefix_plus_canonical() {
    use base64::Engine;
    let f = fixture();
    let prefix = f["envelope"]["signed_bytes_prefix"].as_str().expect("signed_bytes_prefix");
    assert_eq!(prefix, agentmesh::ENVELOPE_SIG_PREFIX);
    let canonical = f["envelope"]["canonical"].as_str().unwrap();
    let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(f["envelope"]["signed"]["sig"].as_str().unwrap())
        .unwrap();
    let vpub =
        agentmesh::KeyPair::from_public_key(f["envelope"]["signed"]["from"].as_str().unwrap())
            .unwrap();
    let mut tagged = prefix.as_bytes().to_vec();
    tagged.extend_from_slice(canonical.as_bytes());
    assert!(vpub.verify(&tagged, &sig).is_ok(), "sig must cover prefix + canonical");
    assert!(vpub.verify(canonical.as_bytes(), &sig).is_err(), "the bare form is not what was signed");
}

#[test]
fn the_pinned_envelope_verifies_and_one_changed_reason_byte_does_not() {
    let f = fixture();
    let signed = &f["envelope"]["signed"];

    // As published: decodes, verifies (§5.3), and the input passes the door.
    let bytes = serde_json::to_vec(signed).unwrap();
    let env = codec::decode(&bytes).expect("the fixture envelope verifies");
    let input = validate_cancel_input(&env.payload.as_ref().unwrap()["input"])
        .expect("the fixture envelope's input validates");
    assert_eq!(input.reason, CancelReason::Superseded);
    assert_eq!(input.task_id, signed["payload"]["input"]["task_id"].as_str().unwrap());
    assert_eq!(input.note.as_deref(), signed["payload"]["input"]["note"].as_str());

    // Reason swapped for another perfectly legal one: the signature is what
    // stops a middleman rewriting WHY a task died.
    let mut tampered = signed.clone();
    tampered["payload"]["input"]["reason"] = Value::from("policy");
    let err = codec::decode(&serde_json::to_vec(&tampered).unwrap()).unwrap_err();
    assert!(format!("{err}").contains("IDENTITY_MISMATCH"));

    // One byte of the note, same verdict.
    let mut tampered = signed.clone();
    let note = tampered["payload"]["input"]["note"].as_str().unwrap().replace("broader", "brOader");
    tampered["payload"]["input"]["note"] = Value::from(note);
    let err = codec::decode(&serde_json::to_vec(&tampered).unwrap()).unwrap_err();
    assert!(format!("{err}").contains("IDENTITY_MISMATCH"));
}

// ─── transitions: which states may cancel ───────────────────────────────────

#[test]
fn the_transitions_agree_with_the_crates_terminal_states() {
    // §7.3 has nine states — the original eight plus `exhausted`, which Agent
    // SoW §5.5.5 (https://agentsow.com) added to the terminal side: a task in
    // flight when a time-and-materials cap is reached ends there. The fixture
    // splits them into cancelable and not. The crate's TERMINAL_TASK_STATES
    // must be exactly the "not" side — a state in both lists, or in neither, is
    // two SDKs disagreeing about when TASK_NOT_CANCELABLE begins.
    let f = fixture();
    let cancelable: BTreeSet<&str> = f["transitions"]["cancelable_from"]
        .as_array()
        .expect("cancelable_from")
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    let not_cancelable: BTreeSet<&str> = f["transitions"]["not_cancelable_from"]
        .as_array()
        .expect("not_cancelable_from")
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();

    assert!(cancelable.is_disjoint(&not_cancelable));
    assert_eq!(cancelable.len() + not_cancelable.len(), 9, "the nine §7.3 states, covered");

    let terminal: BTreeSet<&str> = TERMINAL_TASK_STATES.iter().copied().collect();
    assert_eq!(terminal, not_cancelable, "terminal IS not-cancelable");
    for state in &not_cancelable {
        assert!(is_terminal_task_state(state), "'{state}' is terminal");
    }
    for state in &cancelable {
        assert!(!is_terminal_task_state(state), "'{state}' may still cancel");
    }
}
