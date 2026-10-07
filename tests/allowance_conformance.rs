//! The EXT-8 owner allowance, asserted against `conformance/allowance.json`.
//!
//! **The fixture is the authority.** When a case here fails, the fix is in
//! `src/allowance.rs`, never in the JSON; the fixture itself changes only with
//! a spec change alongside. Two independent node implementations do not
//! disagree about Ed25519 — they disagree about whether the prefix is inside
//! or outside the signed bytes, whether 0.999 of a micro-unit rounds up,
//! whether a more specific ceiling outranks a smaller remainder, and what a
//! node does with a document it cannot verify. Those are exactly the points
//! this fixture pins.
//!
//! Cases are executed by **iterating** the fixture (the `budget_conformance`
//! pattern): a row added to the JSON runs here without this file changing,
//! and fails until `src/allowance.rs` honors it.

use agentmesh::{
    allowance_insufficient, canonical_allowance_bytes, canonical_json, load_allowance,
    meter_cost_micro, sign_allowance, verify_allowance_signature, Allowance, AllowanceDecision,
    AllowanceMeter, AllowanceStatus, CostCeiling, KeyPair, MeshError, OnExhausted, Usage,
    WorkScope, ALLOWANCE_SIG_PREFIX,
};
use serde_json::Value;

static FIXTURE_JSON: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/conformance/allowance.json"));

fn fixture() -> Value {
    serde_json::from_str(FIXTURE_JSON).expect("conformance/allowance.json parses")
}

/// The fixture's OWNER (the signer): the published sender test vector.
fn owner_kp(f: &Value) -> KeyPair {
    KeyPair::from_seed(f["identities"]["sender_seed"].as_str().expect("sender_seed"))
        .expect("fixture seed parses")
}

/// All signed vectors — the `valid` documents plus every `invalid` one that
/// carries a `sig` (all but `missing_sig` do, genuinely, so that shape
/// rejection never depends on a signature failure).
fn signed_vectors(f: &Value) -> Vec<(String, Value)> {
    let mut out = Vec::new();
    for case in f["document"]["valid"].as_array().expect("document.valid") {
        let name = case["case"].as_str().expect("case name").to_string();
        out.push((name, case["signed"].clone()));
    }
    for case in f["document"]["invalid"].as_array().expect("document.invalid") {
        if case["document"].get("sig").is_some() {
            let name = case["case"].as_str().expect("case name").to_string();
            out.push((name, case["document"].clone()));
        }
    }
    out
}

// ─── the document: canonical bytes, the tag, the seven signatures ───────────

#[test]
fn the_pinned_prefix_is_the_modules() {
    let f = fixture();
    assert_eq!(
        f["document"]["signed_bytes_prefix"].as_str().expect("signed_bytes_prefix"),
        ALLOWANCE_SIG_PREFIX,
        "the ASCII tag plus exactly one newline (EXT-8 §1)"
    );
}

#[test]
fn every_valid_documents_canonical_bytes_reproduce_exactly() {
    // The TS SDK generated `canonical` and signed it; this SDK must derive the
    // identical byte string from the signed document minus `sig`. One byte of
    // drift is an allowance that verifies on one node and fails closed on the
    // other — same policy, different enforcement.
    let f = fixture();
    let valid = f["document"]["valid"].as_array().expect("document.valid");
    assert!(!valid.is_empty());
    for case in valid {
        let name = case["case"].as_str().unwrap_or("?");
        let pinned = case["canonical"].as_str().expect("canonical");
        assert_eq!(
            canonical_allowance_bytes(&case["signed"]).expect("canonicalizes"),
            pinned.as_bytes(),
            "case '{name}': canonical bytes must reproduce the fixture's"
        );
        // And the sig-less serialization agrees (absent fields OMITTED, never
        // null — the discipline the canonical form depends on).
        let mut unsigned = case["signed"].clone();
        unsigned.as_object_mut().expect("an object").remove("sig");
        assert_eq!(canonical_json(&unsigned), pinned, "case '{name}'");
    }
}

#[test]
fn every_signed_vector_verifies() {
    // The signature question, judged alone over the raw JSON: every genuinely
    // signed vector — the four valid documents (one with a trial ceiling) AND the four shape-invalid
    // ones — verifies, which is what guarantees each invalid case is refused
    // for exactly its single stated reason.
    let f = fixture();
    let vectors = signed_vectors(&f);
    assert_eq!(vectors.len(), 8, "four valid + four signed invalids");
    for (name, doc) in vectors {
        assert!(verify_allowance_signature(&doc), "vector '{name}' must verify");
    }
}

#[test]
fn the_signature_covers_the_tagged_form_not_the_bare() {
    use base64::Engine;
    let f = fixture();
    let case = &f["document"]["valid"][0];
    let canonical = case["canonical"].as_str().unwrap();
    let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(case["signed"]["sig"].as_str().unwrap())
        .unwrap();
    let vpub = KeyPair::from_public_key(case["signed"]["owner_key"].as_str().unwrap()).unwrap();
    let mut tagged = ALLOWANCE_SIG_PREFIX.as_bytes().to_vec();
    tagged.extend_from_slice(canonical.as_bytes());
    assert!(vpub.verify(&tagged, &sig).is_ok(), "sig covers prefix + canonical");
    assert!(
        vpub.verify(canonical.as_bytes(), &sig).is_err(),
        "the bare canonical form is not what was signed — the prefix lives INSIDE the signed bytes"
    );
}

#[test]
fn every_valid_document_loads_and_round_trips() {
    let f = fixture();
    for case in f["document"]["valid"].as_array().unwrap() {
        let name = case["case"].as_str().unwrap_or("?");
        let doc = load_allowance(&case["signed"])
            .unwrap_or_else(|e| panic!("fixture says valid, refused '{name}': {e}"));
        assert_eq!(
            serde_json::to_value(&doc).unwrap(),
            case["signed"],
            "case '{name}': the typed document round-trips the fixture bytes"
        );
        assert_eq!(doc.v, 1);
        assert_eq!(doc.owner_key, owner_kp(&f).public_key(), "the owner key is the fixture signer");
        assert_eq!(doc.agent, f["identities"]["recipient"].as_str().unwrap());
    }
}

#[test]
fn every_invalid_document_is_refused_for_its_stated_reason() {
    // Each invalid case has exactly one fault; the refusal must name IT — a
    // float rejected as a bad signature is a validator leaning on the wrong
    // check. An unmapped case name fails loudly so a fixture row added later
    // forces this list to grow with it.
    let f = fixture();
    let invalid = f["document"]["invalid"].as_array().expect("document.invalid");
    assert!(!invalid.is_empty());
    for case in invalid {
        let name = case["case"].as_str().unwrap_or("?");
        let why = case["why"].as_str().unwrap_or("");
        let expect_fragment = match name {
            "missing_sig" => "sig is required",
            "float_money" => "never a float",
            "unknown_scope" => "closed enum",
            "negative_amount" => "non-negative",
            "missing_cost_model" => "cost_model is required",
            other => panic!("fixture case '{other}' has no expected refusal mapped here"),
        };
        let err = load_allowance(&case["document"])
            .expect_err(&format!("fixture case '{name}' must be refused ({why})"));
        let msg = err.to_string();
        assert!(
            msg.contains(expect_fragment),
            "case '{name}' must be refused for its stated reason — wanted '{expect_fragment}' \
             in: {msg}"
        );
    }
}

// ─── fail-closed: a bad document is armed shut, never absent ────────────────

#[test]
fn every_invalid_document_arms_fail_closed_with_every_ceiling_exhausted() {
    // EXT-8 §1: a node configured with an allowance that does not load MUST
    // NOT treat it as absent. The failure is observable (arm errs, status
    // says fail-closed) and even zero-cost work is not admitted, with the
    // document's on_exhausted still applied when it was readable.
    let f = fixture();
    for case in f["document"]["invalid"].as_array().unwrap() {
        let name = case["case"].as_str().unwrap_or("?");
        let expect_on_exhausted = match case["document"]["on_exhausted"].as_str() {
            Some("ask_owner") => OnExhausted::AskOwner,
            _ => OnExhausted::Refuse,
        };
        let mut meter = AllowanceMeter::new();
        assert!(meter.arm(&case["document"]).is_err(), "case '{name}': arm must report failure");
        let AllowanceStatus::FailClosed { on_exhausted, reason } = meter.status() else {
            panic!("case '{name}': fail-closed, never absent");
        };
        assert_eq!(on_exhausted, expect_on_exhausted, "case '{name}': on_exhausted still applies");
        assert!(!reason.is_empty());
        assert!(
            matches!(
                meter.check_admission(WorkScope::default(), 0),
                AllowanceDecision::Exhausted { binding: None, estimate: None, .. }
            ),
            "case '{name}': every ceiling reads as exhausted, whatever the estimate"
        );
    }
}

#[test]
fn a_tampered_ceiling_fails_closed_until_a_valid_document_replaces_it() {
    // One micro-unit more than the owner signed: the exact tamper the
    // signature exists to catch (the agent "improving" its own allowance).
    let f = fixture();
    let good = f["document"]["valid"][0]["signed"].clone();
    let mut tampered = good.clone();
    let raised = tampered["ceilings"][0]["amount_micro"].as_u64().unwrap() + 1;
    tampered["ceilings"][0]["amount_micro"] = Value::from(raised);
    let mut meter = AllowanceMeter::new();
    let err = meter.arm(&tampered).expect_err("a tampered document must not arm");
    assert!(err.to_string().contains("IDENTITY_MISMATCH"), "refused as a signature failure: {err}");
    assert!(matches!(meter.status(), AllowanceStatus::FailClosed { .. }));
    assert!(matches!(
        meter.check_admission(WorkScope::default(), 0),
        AllowanceDecision::Exhausted { .. }
    ));
    // Until a valid document replaces it.
    meter.arm(&good).expect("the genuine document arms");
    assert!(matches!(meter.status(), AllowanceStatus::Armed(_)));
    assert!(matches!(
        meter.check_admission(WorkScope::default(), 0),
        AllowanceDecision::Admit { .. }
    ));
}

#[test]
fn a_document_for_a_different_agent_fails_closed_when_armed_bound() {
    // One document per agent (EXT-8 §1). Arming bound to an agent the
    // document does not govern fails CLOSED, exactly like a bad signature
    // (and exactly like the TS SDK): enforcing someone else's policy and
    // silently ignoring it are both wrong, and only failing closed guards
    // the owner's money while saying so. `AgentMesh::set_allowance` always
    // arms through this binding.
    let f = fixture();
    let doc = &f["document"]["valid"][0]["signed"];
    let governed = f["identities"]["recipient"].as_str().unwrap();

    let mut meter = AllowanceMeter::new();
    let err = meter
        .arm_for(doc, "USOMEOTHERAGENTAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        .expect_err("a document governing a different agent must not arm");
    assert!(err.to_string().contains("not this agent"), "the mismatch is named: {err}");
    assert!(matches!(meter.status(), AllowanceStatus::FailClosed { .. }));
    assert!(matches!(
        meter.check_admission(WorkScope::default(), 0),
        AllowanceDecision::Exhausted { .. }
    ));

    // Bound to the agent it DOES govern, the same document arms.
    meter.arm_for(doc, governed).expect("the governed agent arms it");
    assert!(matches!(meter.status(), AllowanceStatus::Armed(_)));
}

// ─── metering: floor, pinned ────────────────────────────────────────────────

#[test]
fn every_metering_case_floors_exactly() {
    let f = fixture();
    assert_eq!(f["metering"]["rounding"].as_str().unwrap(), "floor");
    let cases = f["metering"]["cases"].as_array().expect("metering.cases");
    assert!(!cases.is_empty());
    for case in cases {
        let tokens = case["tokens"].as_u64().unwrap();
        let rate = case["per_1k_tokens_micro"].as_u64().unwrap();
        let why = case["why"].as_str().unwrap_or("");
        assert_eq!(
            meter_cost_micro(tokens, rate),
            case["cost_micro"].as_u64().unwrap(),
            "{tokens} tokens at {rate}/1k — {why}"
        );
    }
}

#[test]
fn metered_spend_is_accounted_to_task_context_and_day_at_once() {
    // EXT-8 §2's triple accounting, driven through the armed meter with the
    // reference vector's cost model (1500 micro / 1k tokens): one report
    // lands in all three books, and the ceiling check uses the metered value,
    // not a re-derivation — 1 token meters as 0 and moves nothing.
    let f = fixture();
    let mut meter = AllowanceMeter::new();
    meter.arm(&f["document"]["valid"][0]["signed"]).expect("reference vector arms");
    let metered =
        meter.report_at("task-1", Some("meetup-s1-e4"), "2026-07-28", Usage::Tokens(1000)).unwrap();
    assert_eq!(metered, 1500);
    assert_eq!(meter.ledger().task_spend("task-1"), 1500);
    assert_eq!(meter.ledger().context_spend("meetup-s1-e4"), 1500);
    assert_eq!(meter.ledger().day_spend("2026-07-28"), 1500);
    // The §19.3 spend report the terminal respond carries.
    assert_eq!(meter.task_cost("task-1"), Some(CostCeiling::new(1500, "USD")));

    // The pinned tiny-invocation case through a meter: at the ask_owner
    // vector's 900/1k rate, one token is 0.9 micro-units and floors to ZERO —
    // it moves no book, and the ceiling check uses the metered value, not a
    // re-derivation.
    let ask_vector = f["document"]["valid"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["case"] == "ask_owner")
        .expect("the ask_owner vector");
    let mut tiny = AllowanceMeter::new();
    tiny.arm(&ask_vector["signed"]).unwrap();
    assert_eq!(tiny.report_at("t", None, "2026-07-28", Usage::Tokens(1)).unwrap(), 0);
    assert_eq!(tiny.ledger().task_spend("t"), 0);
    assert_eq!(tiny.task_cost("t"), None, "zero metered spend reports no cost");
}

// ─── precedence: smallest remaining binds ───────────────────────────────────

/// Build, sign and arm a meter for one precedence case: the case's
/// `applicable` ceilings under the reference cost model, with each ceiling's
/// pinned `spent_micro` seeded into the ledger via scope-appropriate
/// recordings (day spend on the admission day under a foreign task; context
/// spend on a DIFFERENT day, so the day book stays at the case's zero).
fn armed_for_case(f: &Value, case: &Value, admission_day: &str) -> AllowanceMeter {
    let owner = owner_kp(f);
    let mut doc = Allowance {
        v: 1,
        agent: f["identities"]["recipient"].as_str().unwrap().to_string(),
        owner_key: String::new(),
        cost_model: serde_json::from_value(
            serde_json::json!({ "per_1k_tokens_micro": 1500, "currency": "USD" }),
        )
        .unwrap(),
        ceilings: Vec::new(),
        on_exhausted: OnExhausted::Refuse,
        updated_at: "2026-07-28T15:00:00.000Z".to_string(),
        sig: None,
    };
    let mut seedings: Vec<(Option<String>, String, u64)> = Vec::new();
    for c in case["applicable"].as_array().expect("applicable") {
        let mut ceiling = c.clone();
        let spent = ceiling.as_object_mut().unwrap().remove("spent_micro");
        let spent = spent.and_then(|s| s.as_u64()).expect("spent_micro");
        let scope = ceiling["scope"].as_str().expect("scope").to_string();
        if spent > 0 {
            match scope.as_str() {
                // Day spend: on the admission day, under a task/context the
                // admission never asks about.
                "day" => seedings.push((None, admission_day.to_string(), spent)),
                // Context spend: to the ceiling's own context, on ANOTHER day
                // (a context outlives a day; the case pins day spend 0).
                "context" => seedings.push((
                    Some(ceiling["context_id"].as_str().expect("context_id").to_string()),
                    "1999-01-01".to_string(),
                    spent,
                )),
                other => panic!("no seeding strategy for pre-spent scope '{other}'"),
            }
        }
        doc.ceilings.push(serde_json::from_value(ceiling).expect("fixture ceiling parses"));
    }
    sign_allowance(&mut doc, &owner).expect("case document signs");
    let mut meter = AllowanceMeter::new();
    meter.arm(&serde_json::to_value(&doc).unwrap()).expect("case document arms");
    for (context, day, spent) in seedings {
        meter.report_at("seed-task", context.as_deref(), &day, Usage::CostMicro(spent)).unwrap();
    }
    meter
}

#[test]
fn every_precedence_case_binds_and_decides_as_pinned() {
    const DAY: &str = "2026-07-28";
    let f = fixture();
    let cases = f["precedence"]["cases"].as_array().expect("precedence.cases");
    assert!(!cases.is_empty());
    for case in cases {
        let name = case["case"].as_str().unwrap_or("?");
        let why = case["why"].as_str().unwrap_or("");
        let meter = armed_for_case(&f, case, DAY);
        let work = WorkScope {
            task_id: None, // fresh work: a Task that has spent nothing yet
            context_id: case["request_context_id"].as_str(),
        };
        let estimate = case["estimate_micro"].as_u64().expect("estimate_micro");
        let decision = meter.check_admission_at(work, estimate, DAY);
        let binding = match (&decision, case["expect"].as_str().expect("expect")) {
            (AllowanceDecision::Admit { binding: Some(b) }, "accept") => b,
            (
                AllowanceDecision::Exhausted {
                    on_exhausted: OnExhausted::Refuse,
                    binding: Some(b),
                    estimate: Some(est),
                },
                "refuse",
            ) => {
                assert_eq!(
                    est,
                    &CostCeiling::new(estimate, "USD"),
                    "case '{name}': the refusal's estimate is the node's price for the work"
                );
                b
            }
            (other, expect) => panic!("case '{name}': expected {expect}, got {other:?} — {why}"),
        };
        assert_eq!(
            binding.scope.as_str(),
            case["binding_scope"].as_str().unwrap(),
            "case '{name}': the binding ceiling is the smallest REMAINING, never specificity — {why}"
        );
        assert_eq!(
            binding.remaining_micro,
            case["remaining_micro"].as_u64().unwrap(),
            "case '{name}': pinned remainder arithmetic — {why}"
        );
    }
}

// ─── the refusal shape ──────────────────────────────────────────────────────

#[test]
fn the_refusal_is_byte_identical_to_the_budget_shape() {
    // Deliberately indistinguishable on the wire from budget.json's
    // budget_insufficient: same code, same details.estimate, and a message
    // that does not say "allowance".
    let f = fixture();
    let pinned = &f["refusal"]["budget_insufficient"];
    let est = &pinned["details"]["estimate"];
    let err = allowance_insufficient(Some(CostCeiling::new(
        est["amount_micro"].as_u64().unwrap(),
        est["currency"].as_str().unwrap(),
    )));
    let MeshError::Refusal(eo) = err else { panic!("a structured refusal, estimate intact") };
    assert_eq!(eo.code, pinned["error_code"].as_str().unwrap());
    assert_eq!(serde_json::to_value(&eo.details).unwrap(), pinned["details"]);
    assert!(
        !eo.message.to_lowercase().contains("allowance"),
        "the message must not reveal WHICH ceiling refused: {}",
        eo.message
    );
    assert!(!eo.retryable, "resolved by resubmitting at the quote, not by retry");
}

#[test]
fn a_pinned_shut_ceiling_refuses_with_the_estimate_as_the_price() {
    // The narrowed_zero_ceiling vector end to end: work on the named Task
    // meets a zero ceiling, and the §19.3 quote sentence makes the refusal
    // legal against a request that offered no budget at all.
    let f = fixture();
    let vector = f["document"]["valid"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["case"] == "narrowed_zero_ceiling")
        .expect("the narrowed_zero_ceiling vector");
    let mut meter = AllowanceMeter::new();
    meter.arm(&vector["signed"]).unwrap();
    let task_id = vector["signed"]["ceilings"][0]["task_id"].as_str().unwrap();
    let decision = meter
        .check_admission(WorkScope { task_id: Some(task_id), context_id: None }, 500000);
    let AllowanceDecision::Exhausted { on_exhausted, binding: Some(b), estimate: Some(est) } =
        decision
    else {
        panic!("a zero ceiling admits nothing with a price: {decision:?}");
    };
    assert_eq!(on_exhausted, OnExhausted::Refuse);
    assert_eq!(b.remaining_micro, 0);
    assert_eq!(est, CostCeiling::new(500000, "USD"));
    // A DIFFERENT task is outside the narrow: no applicable ceiling at all.
    assert!(matches!(
        meter.check_admission(WorkScope { task_id: Some("some-other-task"), context_id: None }, 500000),
        AllowanceDecision::Admit { binding: None }
    ));
}

// ─── exhaustion behaviours ──────────────────────────────────────────────────

#[test]
fn both_exhaustion_behaviours_are_carried_on_the_decision() {
    // The meter's decision carries the document's on_exhausted for the
    // dispatcher to act on: refuse answers the refusal-with-estimate at
    // admission; ask_owner holds the work for the owner channel instead of
    // refusing (and refuses with the same shape only if the owner declines) —
    // the client wires exactly that.
    let f = fixture();
    assert_eq!(f["exhaustion"]["refuse"]["on_exhausted"].as_str().unwrap(), "refuse");
    assert_eq!(f["exhaustion"]["ask_owner"]["on_exhausted"].as_str().unwrap(), "ask_owner");

    // three_scopes: on_exhausted refuse; the 500000 task ceiling binds fresh work.
    let mut refuse = AllowanceMeter::new();
    refuse.arm(&f["document"]["valid"][0]["signed"]).unwrap();
    assert!(matches!(
        refuse.check_admission(WorkScope::default(), 600000),
        AllowanceDecision::Exhausted { on_exhausted: OnExhausted::Refuse, .. }
    ));

    // ask_owner: a single 2000000 EUR day ceiling.
    let ask_vector = f["document"]["valid"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["case"] == "ask_owner")
        .expect("the ask_owner vector");
    let mut ask = AllowanceMeter::new();
    ask.arm(&ask_vector["signed"]).unwrap();
    let decision = ask.check_admission(WorkScope::default(), 2000001);
    let AllowanceDecision::Exhausted { on_exhausted, estimate: Some(est), .. } = decision else {
        panic!("over the day ceiling: {decision:?}");
    };
    assert_eq!(on_exhausted, OnExhausted::AskOwner, "held for the owner, not refused outright");
    assert_eq!(est.currency, "EUR", "priced in the document's own currency");
    // At the ceiling exactly is NOT over it: 'would exceed', strictly.
    assert!(matches!(
        ask.check_admission(WorkScope::default(), 2000000),
        AllowanceDecision::Admit { .. }
    ));
}

// ─── owner tooling: the sign helper reproduces the reference vector ─────────

#[test]
fn sign_allowance_reproduces_the_reference_vector_byte_for_byte() {
    // Ed25519 is deterministic: signing the identical canonical bytes under
    // the identical tag with the fixture's owner key must reproduce the
    // fixture's signature exactly — one assertion that covers the canonical
    // form, the tag, and the encoding at once.
    let f = fixture();
    let owner = owner_kp(&f);
    assert_eq!(owner.public_key(), f["identities"]["sender"].as_str().unwrap());
    for case in f["document"]["valid"].as_array().unwrap() {
        let name = case["case"].as_str().unwrap_or("?");
        let mut doc: Allowance =
            serde_json::from_value(case["signed"].clone()).expect("fixture vector parses");
        doc.sig = None;
        sign_allowance(&mut doc, &owner).expect("signs");
        assert_eq!(doc.owner_key, case["signed"]["owner_key"], "case '{name}'");
        assert_eq!(
            doc.sig.as_deref(),
            case["signed"]["sig"].as_str(),
            "case '{name}': the sign helper must reproduce the TS-generated signature exactly"
        );
        assert!(verify_allowance_signature(&serde_json::to_value(&doc).unwrap()));
    }
}
