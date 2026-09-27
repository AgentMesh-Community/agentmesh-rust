//! The §7.7 budget wire shapes, asserted against `conformance/budget.json`.
//!
//! **The fixture is the authority.** When a case here fails, the fix is in
//! `src/budget.rs`, never in the JSON; the fixture itself changes only with a
//! spec change alongside. Two independent implementations do not disagree
//! about Ed25519 — they disagree about whether an absent axis is omitted or
//! null, whether the estimate field is named for its type or its meaning, and
//! which side of a skew bound "past" begins on. Those are exactly the bytes
//! this fixture pins.
//!
//! Cases are executed by **iterating** the fixture rather than by naming them
//! in Rust (the `inbound-protections` pattern): a row added to the JSON runs
//! here without this file changing, and fails until `src/budget.rs` honors it.
//!
//! `include_str!`'d rather than read at run time so editing the fixture forces
//! a rebuild.

use agentmesh::{
    budget_exhausted_update, budget_insufficient, canonical_json, codec, deadline_unmeetable,
    parse_instant_ms, Budget, CostCeiling, ErrorCode, MeshError, TaskBudgets,
    DEADLINE_SKEW_TOLERANCE_MS,
};
use serde_json::Value;

static FIXTURE_JSON: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/conformance/budget.json"));

fn fixture() -> Value {
    serde_json::from_str(FIXTURE_JSON).expect("conformance/budget.json parses")
}

/// Parse-and-validate, as one judgement: the fixture's `invalid` rows are
/// refused wherever the implementation naturally refuses them — some at
/// deserialization (a float amount never becomes a `u64`), some at
/// `Budget::validate` (both axes absent). The fixture pins the verdict, not
/// the layer.
fn block_is_accepted(block: &Value) -> bool {
    serde_json::from_value::<Budget>(block.clone())
        .map(|b| b.validate().is_ok())
        .unwrap_or(false)
}

fn ceiling_of(v: &Value) -> CostCeiling {
    CostCeiling::new(
        v["amount_micro"].as_u64().expect("fixture amount_micro"),
        v["currency"].as_str().expect("fixture currency"),
    )
}

// ─── block: valid / invalid ─────────────────────────────────────────────────

#[test]
fn every_valid_block_parses_and_validates() {
    let f = fixture();
    let valid = f["block"]["valid"].as_array().expect("block.valid");
    assert!(!valid.is_empty());
    for block in valid {
        assert!(block_is_accepted(block), "fixture says valid, refused: {block}");
    }
}

#[test]
fn every_invalid_block_is_refused() {
    let f = fixture();
    let invalid = f["block"]["invalid"].as_array().expect("block.invalid");
    assert!(!invalid.is_empty());
    for case in invalid {
        let name = case["case"].as_str().unwrap_or("?");
        let why = case["why"].as_str().unwrap_or("");
        assert!(
            !block_is_accepted(&case["block"]),
            "fixture case '{name}' must be refused ({why}): {}",
            case["block"]
        );
    }
}

// ─── envelope: canonical bytes and the signature over them ──────────────────

#[test]
fn the_pinned_envelopes_canonical_bytes_reproduce_exactly() {
    // The TS SDK generated `canonical` and signed it; this SDK must derive the
    // identical byte string from the signed envelope minus `sig`. One byte of
    // drift here is a budget-carrying envelope that verifies in one SDK and
    // not the other.
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
    // Strictly the TAGGED form (§5.3). The 0.2 dual-accept that once made
    // this pin the only guard closed at 0.3; the pin stays because the
    // fixture states the exact signed bytes, not merely that decode accepts.
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
fn the_pinned_envelope_verifies_and_one_changed_micro_unit_does_not() {
    let f = fixture();
    let signed = &f["envelope"]["signed"];

    // As published: decodes, verifies (§5.3), and the typed budget survives.
    let bytes = serde_json::to_vec(signed).unwrap();
    let env = codec::decode(&bytes).expect("the fixture envelope verifies");
    let budget = env.budget.expect("budget decoded");
    assert_eq!(
        serde_json::to_value(&budget).unwrap(),
        signed["budget"],
        "the typed budget round-trips the fixture block"
    );
    assert!(budget.validate().is_ok());

    // One micro-unit more than was signed: the exact tamper the coverage
    // exists to catch (a middleman "improving" the offer).
    let mut tampered = signed.clone();
    let raised = tampered["budget"]["cost_ceiling"]["amount_micro"].as_u64().unwrap() + 1;
    tampered["budget"]["cost_ceiling"]["amount_micro"] = Value::from(raised);
    let err = codec::decode(&serde_json::to_vec(&tampered).unwrap()).unwrap_err();
    assert!(format!("{err}").contains("IDENTITY_MISMATCH"));
}

// ─── revisions: latest wins, absolutely ─────────────────────────────────────

fn run_revision_case(case: &Value) -> Value {
    let budgets = TaskBudgets::new();
    for block in case["applied_in_order"].as_array().expect("applied_in_order") {
        let budget: Budget = serde_json::from_value(block.clone()).expect("fixture revision parses");
        budgets.apply("task", &budget);
    }
    serde_json::to_value(budgets.get("task").expect("a current budget")).unwrap()
}

#[test]
fn revision_ordering_matches_the_fixture() {
    // Lower-after-higher ignored; an equal revision ignored (first writer
    // wins); the winner's block is the ENTIRE truth.
    let f = fixture();
    let case = &f["revisions"]["ordering_case"];
    assert_eq!(run_revision_case(case), case["expect_current"], "{}", case["why"]);
}

#[test]
fn a_revision_is_absolute_and_inherits_nothing() {
    // Rev 1 omits the deadline, so the current budget HAS no deadline — the
    // one behavior a delta-merging implementation gets wrong silently.
    let f = fixture();
    let case = &f["revisions"]["absolute_case"];
    assert_eq!(run_revision_case(case), case["expect_current"], "{}", case["why"]);
}

// ─── refusals and the pause: pinned codes and detail field names ────────────

#[test]
fn budget_insufficient_matches_the_pinned_shape() {
    let f = fixture();
    let pinned = &f["refusals"]["budget_insufficient"];
    let err = budget_insufficient(Some(ceiling_of(&pinned["details"]["estimate"])), "over budget");
    let MeshError::Refusal(eo) = err else { panic!("expected a structured refusal") };
    assert_eq!(eo.code, pinned["error_code"].as_str().unwrap());
    assert_eq!(serde_json::to_value(eo.details).unwrap(), pinned["details"]);
}

#[test]
fn deadline_unmeetable_matches_the_pinned_shape() {
    // `details.earliest_completion`, NOT `details.estimate`: the two refusals
    // carry differently-typed estimates under different names so a reader
    // never type-sniffs.
    let f = fixture();
    let pinned = &f["refusals"]["deadline_unmeetable"];
    let earliest = pinned["details"]["earliest_completion"].as_str().unwrap();
    let err = deadline_unmeetable(Some(earliest.to_string()), "too soon");
    let MeshError::Refusal(eo) = err else { panic!("expected a structured refusal") };
    assert_eq!(eo.code, pinned["error_code"].as_str().unwrap());
    assert_eq!(serde_json::to_value(eo.details).unwrap(), pinned["details"]);
}

#[test]
fn the_budget_exhausted_pause_matches_the_pinned_shape() {
    // A NON-TERMINAL respond: `status: input_required`, and the two numbers —
    // `spent` (not "spend") + `estimate_to_finish`, both cost_ceiling-shaped —
    // ride in the ERROR OBJECT's details, not in the payload.
    let f = fixture();
    let pinned = &f["refusals"]["budget_exhausted_pause"];
    let env = budget_exhausted_update(
        "URESPONDER",
        "task-1",
        Some("UREQUESTER"),
        &ceiling_of(&pinned["details"]["spent"]),
        &ceiling_of(&pinned["details"]["estimate_to_finish"]),
        "ceiling reached",
    );
    assert_eq!(
        env.payload.as_ref().unwrap()["status"],
        pinned["status"],
        "the pause is the input_required state, and the input required is money"
    );
    let error = env.error.as_ref().expect("the pause carries the error object");
    assert_eq!(error.code, pinned["error_code"].as_str().unwrap());
    assert_eq!(
        serde_json::to_value(error.details.as_ref()).unwrap(),
        pinned["details"],
        "spent + estimate_to_finish live in error.details"
    );
}

#[test]
fn deadline_exceeded_is_a_marker_this_sdk_can_spell() {
    // Never a refusal an SDK sends at admission — the task record's marker on
    // late completions. Pinned so both SDKs spell it identically when reading.
    let f = fixture();
    assert_eq!(
        ErrorCode::DeadlineExceeded.as_str(),
        f["refusals"]["deadline_exceeded_marker"]["error_code"].as_str().unwrap()
    );
}

// ─── the deadline boundary ──────────────────────────────────────────────────

#[test]
fn the_skew_tolerance_and_granularity_are_the_fixtures() {
    let f = fixture();
    assert_eq!(
        DEADLINE_SKEW_TOLERANCE_MS,
        f["deadline"]["skew_tolerance_ms"].as_i64().unwrap(),
        "§7.7 reuses §22.3's tolerance; a divergence here is two SDKs disagreeing when 'overdue' begins"
    );
    assert_eq!(f["deadline"]["granularity_ms"].as_i64().unwrap(), 1000);
}

#[test]
fn every_deadline_case_matches_past_deadline() {
    let f = fixture();
    let cases = f["deadline"]["cases"].as_array().expect("deadline.cases");
    assert!(!cases.is_empty());
    for case in cases {
        let deadline = case["deadline"].as_str().unwrap();
        let now = parse_instant_ms(case["now"].as_str().unwrap()).expect("fixture 'now' parses");
        let expect_past = case["past"].as_bool().unwrap();
        let why = case["why"].as_str().unwrap_or("");
        let budget = Budget::with_deadline(deadline);
        assert!(budget.validate().is_ok(), "fixture deadlines are valid budgets");
        assert_eq!(
            budget.past_deadline(now),
            expect_past,
            "deadline {deadline} at now {} — {why}",
            case["now"]
        );
    }
}
