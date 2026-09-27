//! §7.7 budget: wire shape, signing, monotonicity, deadline semantics, and the
//! refusal/pause helper shapes.
//!
//! The wire-shape tests here are the cross-implementation contract: the budget
//! block rides INSIDE the signed envelope (§5.2/§5.3), so its canonical form —
//! sorted keys, absent fields omitted rather than null — must byte-match what
//! the TypeScript SDK's `canonicalJSON` produces, or a budget-carrying envelope
//! signed by one SDK stops verifying in the other.

use agentmesh::identity::canonical_envelope_bytes;
use agentmesh::inbound::MAX_CLOCK_SKEW_AHEAD_MS;
use agentmesh::{
    budget_exhausted_update, budget_insufficient, budget_revision_update, canonical_json, codec,
    deadline_unmeetable, parse_instant_ms, sign_envelope, verify_envelope_sig, Budget, CostCeiling,
    Envelope, ErrorCode, MeshError, PrimitiveType, TaskBudgets, DEADLINE_SKEW_TOLERANCE_MS,
};
use nkeys::KeyPair;
use serde_json::{json, Value};

fn full_budget() -> Budget {
    Budget::with_deadline("2026-08-01T00:00:00Z").and_ceiling(CostCeiling::new(4_000_000, "USD"))
}

// ─── wire shape (canonical JSON, §5.2/§5.3) ─────────────────────────────────

#[test]
fn a_budget_canonicalizes_sorted_and_complete() {
    let mut env = Envelope::new(PrimitiveType::Request, "UREQUESTER");
    env.budget = Some(full_budget());
    let canonical = String::from_utf8(canonical_envelope_bytes(&env).unwrap()).unwrap();
    // Keys sorted at every level: cost_ceiling < deadline < revision, and
    // amount_micro < currency. This is the exact byte run the TS SDK's
    // canonicalJSON produces for the same block.
    assert!(canonical.contains(
        r#""budget":{"cost_ceiling":{"amount_micro":4000000,"currency":"USD"},"deadline":"2026-08-01T00:00:00Z","revision":0}"#
    ), "canonical form was: {canonical}");
}

#[test]
fn an_absent_axis_is_omitted_never_null() {
    // §5.3 + TS canonicalJSON: absent fields are LEFT OUT. A `null` here would
    // change the signed bytes between the two SDKs.
    let deadline_only = serde_json::to_value(Budget::with_deadline("2026-08-01T00:00:00Z")).unwrap();
    assert_eq!(
        canonical_json(&deadline_only),
        r#"{"deadline":"2026-08-01T00:00:00Z","revision":0}"#
    );
    let ceiling_only = serde_json::to_value(Budget::with_ceiling(CostCeiling::new(1, "EUR"))).unwrap();
    assert_eq!(
        canonical_json(&ceiling_only),
        r#"{"cost_ceiling":{"amount_micro":1,"currency":"EUR"},"revision":0}"#
    );
}

#[test]
fn an_absent_budget_leaves_the_envelope_without_the_key() {
    // An envelope with no budget must serialize WITHOUT the key — pre-budget
    // SDKs sign envelopes that never mention it, and those signatures must
    // keep verifying here unchanged.
    let env = Envelope::new(PrimitiveType::Request, "UREQUESTER");
    let wire = serde_json::to_value(&env).unwrap();
    assert!(wire.get("budget").is_none());
}

#[test]
fn a_budget_envelope_round_trips_through_encode_decode() {
    let kp = KeyPair::new_user();
    let mut env = Envelope::new(PrimitiveType::Request, kp.public_key());
    env.payload = Some(json!({ "offering": "summarize", "input": "..." }));
    env.budget = Some(full_budget());
    sign_envelope(&mut env, &kp).unwrap();

    let decoded = codec::decode(&codec::encode(&env).unwrap()).unwrap();
    assert_eq!(decoded.budget, Some(full_budget()));
}

// ─── signing (§5.3): the budget is under the signature ──────────────────────

#[test]
fn a_signed_budget_envelope_verifies_and_a_tampered_ceiling_does_not() {
    let kp = KeyPair::new_user();
    let mut env = Envelope::new(PrimitiveType::Request, kp.public_key());
    env.budget = Some(full_budget());
    sign_envelope(&mut env, &kp).unwrap();
    assert!(verify_envelope_sig(&env));

    // Raising the ceiling after signing is exactly the tamper the coverage
    // exists to catch: a middleman "improving" the offer.
    env.budget.as_mut().unwrap().cost_ceiling.as_mut().unwrap().amount_micro = 9_000_000;
    assert!(!verify_envelope_sig(&env));
}

#[test]
fn a_budget_envelope_signed_over_raw_json_verifies_here() {
    // The other-implementation path: an envelope built as raw JSON with keys in
    // arbitrary (insertion) order, signed over the tagged canonical form
    // (§5.3) — which is how the TS SDK signs. `codec::decode` must verify it
    // over the RECEIVED bytes, budget included.
    let kp = KeyPair::new_user();
    let mut raw = json!({
        "v": "0.3.0",
        "id": "0198abcd-0000-7000-8000-000000000001",
        "type": "request",
        "ts": "2026-07-27T00:00:00.000Z",
        "from": kp.public_key(),
        "trace": {
            "trace_id": "0af7651916cd43dd8448eb211c80319c",
            "span_id": "b7ad6b7169203331",
            "parent_span_id": null
        },
        // Deliberately unsorted relative to canonical order:
        "budget": {
            "revision": 2,
            "deadline": "2026-08-01T00:00:00+02:00",
            "cost_ceiling": { "currency": "USD", "amount_micro": 4000000 }
        },
        "payload": { "offering": "summarize" }
    });
    let sig_over = format!("{}{}", agentmesh::ENVELOPE_SIG_PREFIX, canonical_json(&raw));
    let sig = kp.sign(sig_over.as_bytes()).unwrap();
    use base64::Engine;
    raw["sig"] = json!(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig));

    let bytes = serde_json::to_vec(&raw).unwrap();
    let env = codec::decode(&bytes).unwrap();
    let budget = env.budget.expect("budget decoded");
    assert_eq!(budget.revision, 2);
    assert_eq!(budget.deadline.as_deref(), Some("2026-08-01T00:00:00+02:00"));
    assert_eq!(budget.cost_ceiling, Some(CostCeiling::new(4_000_000, "USD")));

    // …and the same bytes with one micro-unit added must not decode.
    let mut tampered: Value = serde_json::from_slice(&bytes).unwrap();
    tampered["budget"]["cost_ceiling"]["amount_micro"] = json!(4000001);
    let err = codec::decode(&serde_json::to_vec(&tampered).unwrap()).unwrap_err();
    assert!(format!("{err}").contains("IDENTITY_MISMATCH"));
}

// ─── validation (§7.7) ──────────────────────────────────────────────────────

#[test]
fn a_budget_without_a_revision_does_not_deserialize() {
    // `revision` is REQUIRED (§7.7). The type system enforces it: the field is
    // non-optional, so the JSON never becomes a Budget at all.
    let r: Result<Budget, _> = serde_json::from_str(r#"{"deadline":"2026-08-01T00:00:00Z"}"#);
    assert!(r.is_err());
}

#[test]
fn a_budget_must_state_at_least_one_axis() {
    let empty: Budget = serde_json::from_str(r#"{"revision":0}"#).unwrap();
    let err = empty.validate().unwrap_err();
    assert!(format!("{err}").contains("at least one"));
    // Either axis alone is a legitimate budget.
    assert!(Budget::with_deadline("2026-08-01T00:00:00Z").validate().is_ok());
    assert!(Budget::with_ceiling(CostCeiling::new(1, "USD")).validate().is_ok());
    assert!(full_budget().validate().is_ok());
}

#[test]
fn a_deadline_must_parse_as_rfc_3339_but_any_rfc_3339_form_counts() {
    for bad in ["tomorrow", "2026-08-01", "2026-08-01T00:00:00", ""] {
        let err = Budget::with_deadline(bad).validate().unwrap_err();
        assert!(format!("{err}").contains("RFC 3339"), "'{bad}' should be refused");
    }
    // §22.3 rule 1 applies to deadlines too: a numeric UTC offset is a
    // perfectly good instant, not just a trailing Z.
    assert!(Budget::with_deadline("2026-08-01T02:00:00+02:00").validate().is_ok());
    assert!(Budget::with_deadline("2026-08-01T00:00:00.500Z").validate().is_ok());
}

// ─── monotonic revisions, latest wins (§7.7) ────────────────────────────────

#[test]
fn latest_revision_wins_and_lower_or_equal_is_ignored() {
    let budgets = TaskBudgets::new();
    let rev0 = full_budget();
    assert!(budgets.apply("t1", &rev0), "first sight is recorded");
    assert!(!budgets.apply("t1", &rev0), "the same revision restated adds nothing");

    let rev2 = rev0.clone().revised().revised().and_ceiling(CostCeiling::new(8_000_000, "USD"));
    assert!(budgets.apply("t1", &rev2), "a higher revision supersedes");

    // A reordered (late) revision 1 arrives after 2: ignored, the highest
    // revision is the whole truth.
    let rev1 = rev0.clone().revised();
    assert!(!budgets.apply("t1", &rev1));
    let current = budgets.get("t1").unwrap();
    assert_eq!(current.revision, 2);
    assert_eq!(current.cost_ceiling.as_ref().unwrap().amount_micro, 8_000_000);
}

#[test]
fn a_revision_arriving_before_the_initial_budget_is_not_clobbered() {
    // Cross-subject ordering is not guaranteed (§5.4): revision 1 can be seen
    // before the request's revision 0. Latest-wins makes the order irrelevant.
    let budgets = TaskBudgets::new();
    let rev1 = full_budget().revised();
    assert!(budgets.apply("t1", &rev1));
    assert!(!budgets.apply("t1", &full_budget()), "revision 0 arriving late is ignored");
    assert_eq!(budgets.get("t1").unwrap().revision, 1);
}

#[test]
fn outgoing_revisions_are_locally_monotonic() {
    let budgets = TaskBudgets::new();
    // No recorded budget: nothing to be non-monotonic against.
    assert!(budgets.ensure_monotonic("t1", 0).is_ok());
    budgets.apply("t1", &full_budget().revised()); // recorded at revision 1

    for stale in [0, 1] {
        let err = budgets.ensure_monotonic("t1", stale).unwrap_err();
        assert!(
            format!("{err}").contains("TASK_INVALID_TRANSITION"),
            "revision {stale} must be refused with the task manager's own code"
        );
    }
    assert!(budgets.ensure_monotonic("t1", 2).is_ok());
    // A different task is a different counter.
    assert!(budgets.ensure_monotonic("t2", 0).is_ok());
}

#[test]
fn a_forgotten_task_forgets_its_budget() {
    let budgets = TaskBudgets::new();
    budgets.apply("t1", &full_budget());
    budgets.forget("t1");
    assert!(budgets.get("t1").is_none());
}

// ─── the deadline predicate (§7.7 + §22.3) ──────────────────────────────────

#[test]
fn the_deadline_tolerance_is_the_shared_clock_skew_constant() {
    // §7.7 points at §22.3's tolerance rather than minting a new number; the
    // day these diverge, an agent's overdue judgement and its freshness window
    // disagree about what a clock can be wrong by.
    assert_eq!(DEADLINE_SKEW_TOLERANCE_MS, MAX_CLOCK_SKEW_AHEAD_MS);
    assert_eq!(DEADLINE_SKEW_TOLERANCE_MS, 5 * 60_000);
}

#[test]
fn past_deadline_honors_skew_tolerance_and_second_granularity() {
    let b = full_budget();
    let deadline_ms = parse_instant_ms("2026-08-01T00:00:00Z").unwrap();
    let skew = DEADLINE_SKEW_TOLERANCE_MS;

    // Before, at, and shortly after the deadline: not past — the tolerance is
    // for a local clock that runs fast, and it is inclusive like §22.3's bounds.
    assert!(!b.past_deadline(deadline_ms - 1_000));
    assert!(!b.past_deadline(deadline_ms));
    assert!(!b.past_deadline(deadline_ms + skew));
    // Sub-second overshoot past the tolerance floors away: §7.7 says a
    // deadline finer than one second measures network jitter, not the work.
    assert!(!b.past_deadline(deadline_ms + skew + 999));
    // One whole second beyond the tolerance IS past.
    assert!(b.past_deadline(deadline_ms + skew + 1_000));
}

#[test]
fn a_budget_without_a_deadline_is_never_past_one() {
    let b = Budget::with_ceiling(CostCeiling::new(1, "USD"));
    assert!(!b.past_deadline(i64::MAX));
    // An unparseable deadline is validate()'s refusal, not an invented overdue.
    let broken = Budget { deadline: Some("not-a-date".into()), revision: 0, cost_ceiling: None };
    assert!(!broken.past_deadline(0));
}

// ─── admission refusals (§7.7 refuse-with-estimate) ─────────────────────────

#[test]
fn budget_insufficient_carries_the_price_as_the_estimate() {
    let err = budget_insufficient(Some(CostCeiling::new(6_000_000, "USD")), "6 USD to do this well");
    let MeshError::Refusal(eo) = &err else { panic!("expected a structured refusal") };
    assert_eq!(eo.code, "BUDGET_INSUFFICIENT");
    assert_eq!(eo.message, "6 USD to do this well");
    assert!(!eo.retryable, "§12.2: resubmitting better terms is the retry");
    let estimate = &eo.details.as_ref().unwrap()["estimate"];
    assert_eq!(estimate["amount_micro"], json!(6_000_000));
    assert_eq!(estimate["currency"], json!("USD"));
    // The accessor a refused requester reads the counter-offer through.
    assert!(err.error_object().is_some());
}

#[test]
fn deadline_unmeetable_carries_the_earliest_completion_under_its_own_name() {
    // conformance/budget.json: `details.earliest_completion`, NOT
    // `details.estimate` — the two refusals carry differently-typed estimates
    // under different names so a reader never type-sniffs.
    let err = deadline_unmeetable(Some("2026-08-02T12:00:00Z".into()), "earliest is tomorrow noon");
    let MeshError::Refusal(eo) = err else { panic!("expected a structured refusal") };
    assert_eq!(eo.code, "DEADLINE_UNMEETABLE");
    assert!(!eo.retryable);
    let details = eo.details.unwrap();
    assert_eq!(details["earliest_completion"], json!("2026-08-02T12:00:00Z"));
    assert!(details.get("estimate").is_none());
}

#[test]
fn a_refusal_error_object_round_trips_from_the_wire_with_its_estimate() {
    // The requester side of the same coin: an error envelope carrying a budget
    // refusal must surface as MeshError::Refusal WITH details — flattening it
    // to code+message would discard the counter-offer, which is the mechanism.
    let MeshError::Refusal(eo) = budget_insufficient(Some(CostCeiling::new(1, "USD")), "no") else {
        panic!()
    };
    let back = MeshError::from_error_object(&eo);
    let survived = back.error_object().expect("details survive the trip");
    assert_eq!(survived.details, eo.details);
    assert_eq!(format!("{back}"), "[BUDGET_INSUFFICIENT] no");
}

#[test]
fn the_four_error_codes_spell_exactly_what_12_2_spells() {
    assert_eq!(ErrorCode::BudgetInsufficient.as_str(), "BUDGET_INSUFFICIENT");
    assert_eq!(ErrorCode::DeadlineUnmeetable.as_str(), "DEADLINE_UNMEETABLE");
    assert_eq!(ErrorCode::BudgetExhausted.as_str(), "BUDGET_EXHAUSTED");
    assert_eq!(ErrorCode::DeadlineExceeded.as_str(), "DEADLINE_EXCEEDED");
}

// ─── the ceiling pause and revision updates (§7.7) ──────────────────────────

#[test]
fn the_budget_exhausted_pause_is_an_input_required_update_with_both_numbers() {
    let env = budget_exhausted_update(
        "URESPONDER",
        "task-1",
        Some("UREQUESTER"),
        &CostCeiling::new(4_000_000, "USD"),
        &CostCeiling::new(2_500_000, "USD"),
        "ceiling reached; 2.50 USD to finish",
    );
    assert_eq!(env.kind, PrimitiveType::Respond);
    assert_eq!(env.task_id.as_deref(), Some("task-1"));
    assert_eq!(env.to.as_deref(), Some("UREQUESTER"));
    // §7.7: the Task moves to input_required — the input required is money.
    assert_eq!(env.payload.as_ref().unwrap()["status"], json!("input_required"));
    let error = env.error.as_ref().unwrap();
    assert_eq!(error.code, "BUDGET_EXHAUSTED");
    assert!(!error.retryable, "§12.2: resolved by revision or cancellation, not retry");
    let details = error.details.as_ref().unwrap();
    assert_eq!(details["spent"]["amount_micro"], json!(4_000_000));
    assert_eq!(details["estimate_to_finish"]["amount_micro"], json!(2_500_000));
    // Unsigned by construction: the connected-client path signs it.
    assert!(env.sig.is_none());
}

#[test]
fn a_revision_update_carries_only_the_budget_block() {
    let revised = full_budget().revised().and_ceiling(CostCeiling::new(8_000_000, "USD"));
    let env = budget_revision_update("UREQUESTER", "task-1", Some("URESPONDER"), &revised);
    assert_eq!(env.kind, PrimitiveType::Respond);
    assert_eq!(env.task_id.as_deref(), Some("task-1"));
    assert_eq!(env.budget.as_ref(), Some(&revised));
    // "carrying only the `budget` block" (§7.7): no payload, no error, no
    // artifacts — the budget is the entire content of a revision.
    assert!(env.payload.is_none());
    assert!(env.error.is_none());
    assert!(env.artifacts.is_none());
}

#[test]
fn a_signed_revision_update_verifies_with_the_budget_under_the_signature() {
    let kp = KeyPair::new_user();
    let revised = full_budget().revised();
    let mut env = budget_revision_update(&kp.public_key(), "task-1", None, &revised);
    sign_envelope(&mut env, &kp).unwrap();
    let decoded = codec::decode(&codec::encode(&env).unwrap()).unwrap();
    assert_eq!(decoded.budget, Some(revised));
}
