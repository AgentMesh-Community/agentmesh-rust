//! Trials (Common Agent 7.7, with 7.5's trial allowance scope), asserted
//! against `conformance/trial.json`.
//!
//! **The fixture is the authority.** When a case here fails, the fix is in
//! `src/trial.rs` or `src/allowance.rs`, never in the JSON. Cases are run by
//! iterating the fixture, so a row added to it runs here without this file
//! changing.

use agentmesh::{
    quote_from_price, sign_allowance, trial_admission, trial_of, validate_trial, Allowance,
    AllowanceCeiling, AllowanceCostModel, AllowanceMeter, ErrorCode, KeyPair, MemoryTrialLedger,
    OnExhausted, SkuPrice, TrialAdmissionArgs, TrialCounts, TrialDeclaration, TrialFunds,
    TrialLedger, TrialRequester, TrialRequesterKind, Usage, WorkScope, TRIAL_REASONS,
};
use chrono::{DateTime, Duration, Utc};
use serde_json::{json, Value};

static FIXTURE_JSON: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/conformance/trial.json"));

fn fixture() -> Value {
    serde_json::from_str(FIXTURE_JSON).expect("conformance/trial.json parses")
}

fn explainer(f: &Value) -> TrialDeclaration {
    let mut offering = f["offering"].clone();
    offering["trial"] = f["declarations"]["valid"][0]["trial"].clone();
    trial_of(&offering).expect("the explainer declaration reads")
}

fn now(f: &Value) -> DateTime<Utc> {
    f["admission"]["now"].as_str().unwrap().parse().unwrap()
}

fn quote_price(f: &Value) -> SkuPrice {
    let q = &f["admission"]["quote"];
    serde_json::from_value(json!({
        "model": "flat",
        "amount_micro": q["amount_micro"],
        "currency": q["currency"],
    }))
    .unwrap()
}

/// "500+1" stands for a string of 501 characters.
fn expand_inputs(inputs: &Value) -> Value {
    let mut out = inputs.clone();
    if let Some(m) = out.as_object_mut() {
        for v in m.values_mut() {
            if let Some((n, plus)) = v.as_str().and_then(|s| s.split_once('+')) {
                if let (Ok(n), Ok(plus)) = (n.parse::<usize>(), plus.parse::<usize>()) {
                    *v = Value::String("x".repeat(n + plus));
                }
            }
        }
    }
    out
}

fn requester(v: &Value) -> TrialRequester {
    TrialRequester {
        id: "requester-1".into(),
        kind: serde_json::from_value::<TrialRequesterKind>(v["kind"].clone()).unwrap(),
        signed_in: v["signed_in"].as_bool().unwrap(),
        verified: v["verified"].as_bool().unwrap(),
    }
}

fn counts(v: &Value) -> TrialCounts {
    let n = |i: usize| v[i].as_u64().unwrap();
    TrialCounts { requester_day: n(0), day: n(1), requester_ever: n(2) }
}

fn funds(v: &Value) -> TrialFunds {
    match v.as_str().unwrap() {
        "room" => TrialFunds::Room,
        "full" => TrialFunds::Full,
        "none" => TrialFunds::None,
        other => panic!("unknown funds {other}"),
    }
}

#[test]
fn the_code_and_reasons_are_the_fixtures() {
    let f = fixture();
    assert_eq!(ErrorCode::TrialRefused.as_str(), f["code"].as_str().unwrap());
    let reasons: Vec<&str> = f["reasons"].as_array().unwrap().iter().map(|r| r.as_str().unwrap()).collect();
    assert_eq!(reasons, TRIAL_REASONS.to_vec());
}

#[test]
fn valid_declarations_pass_and_invalid_ones_are_refused() {
    let f = fixture();
    let offering = &f["offering"];
    for case in f["declarations"]["valid"].as_array().unwrap() {
        let why = validate_trial(&case["trial"], Some(offering));
        assert!(why.is_none(), "{}: {:?}", case["case"], why);
        let mut o = offering.clone();
        o["trial"] = case["trial"].clone();
        assert!(trial_of(&o).is_some(), "{} reads as a trial", case["case"]);
    }
    for case in f["declarations"]["invalid"].as_array().unwrap() {
        assert!(
            validate_trial(&case["trial"], Some(offering)).is_some(),
            "{} must be refused: {}",
            case["case"],
            case["why"]
        );
        let mut o = offering.clone();
        o["trial"] = case["trial"].clone();
        assert!(trial_of(&o).is_none(), "{}: an invalid member is no trial", case["case"]);
    }
}

#[test]
fn every_admission_case_answers_as_the_fixture_says() {
    let f = fixture();
    let decl = explainer(&f);
    let quote = quote_from_price(Some(&quote_price(&f)));
    assert_eq!(quote.amount_micro, Some(5_000_000));
    for case in f["admission"]["cases"].as_array().unwrap() {
        let name = case["case"].as_str().unwrap();
        let trial = if case.get("trial") == Some(&Value::Null) { None } else { Some(&decl) };
        let inputs = expand_inputs(&case["inputs"]);
        let req = requester(&case["requester"]);
        let got = trial_admission(TrialAdmissionArgs {
            trial,
            has_budget: case["has_budget"].as_bool().unwrap_or(false),
            requester: &req,
            inputs: &inputs,
            counts: counts(&case["counts"]),
            funds: funds(&case["funds"]),
            quote: &quote,
            now: now(&f),
            agent_name: None,
        });
        let expect = &case["expect"];
        if expect["ok"].as_bool().unwrap() {
            assert!(got.is_ok(), "{name}: expected admission, got {got:?}");
            continue;
        }
        let refusal = got.expect_err(name);
        assert_eq!(refusal.code, "TRIAL_REFUSED", "{name}");
        assert!(!refusal.retryable, "{name}");
        assert!(!refusal.message.is_empty(), "{name}: a passage for a person");
        let details = serde_json::to_value(&refusal.details).unwrap();
        assert_eq!(details["reason"], expect["reason"], "{name}");
        assert_eq!(details.get("limit"), expect.get("limit"), "{name}: limit");
        assert_eq!(details.get("resets_at"), expect.get("resets_at"), "{name}: resets_at");
        if let Some(input) = expect.get("input") {
            assert_eq!(&details["input"], input, "{name}: input");
            assert!(details["max"].is_object(), "{name}: max");
        }
        assert_eq!(details["quote"]["amount_micro"], json!(5_000_000), "{name}: every refusal carries the quote");
        assert_eq!(details["quote"]["currency"], json!("USD"), "{name}");
        // On the wire it travels as a structured refusal with details intact.
        let err = refusal.to_error();
        let eo = err.error_object().expect("structured refusal");
        assert_eq!(eo.code, "TRIAL_REFUSED");
        assert_eq!(eo.details.as_ref().unwrap()["reason"], expect["reason"]);
    }
}

#[test]
fn the_counting_walk() {
    let f = fixture();
    let c = &f["counting"];
    let decl = explainer(&f);
    let quote = quote_from_price(Some(&quote_price(&f)));
    let ledger = MemoryTrialLedger::new();
    let at = now(&f);
    let req = TrialRequester { id: "r".into(), kind: TrialRequesterKind::Account, signed_in: true, verified: false };
    let inputs = json!({});
    let mut admitted = 0;
    for _ in 0..c["requests"].as_u64().unwrap() {
        let got = trial_admission(TrialAdmissionArgs {
            trial: Some(&decl),
            has_budget: false,
            requester: &req,
            inputs: &inputs,
            counts: ledger.counts("r", "make-an-explainer", at),
            funds: TrialFunds::Room,
            quote: &quote,
            now: at,
            agent_name: None,
        });
        match got {
            Ok(()) => {
                admitted += 1;
                ledger.record("r", "make-an-explainer", at);
            }
            Err(r) => assert_eq!(r.details.reason.as_str(), "requester_day"),
        }
    }
    assert_eq!(admitted, c["admitted"].as_u64().unwrap());
    assert_eq!(ledger.counts("r", "make-an-explainer", at), counts(&c["counts_after"]), "the refused one was not counted");
    let next = ledger.counts("r", "make-an-explainer", at + Duration::days(1));
    assert_eq!(next.requester_day, c["next_day_requester_day"].as_u64().unwrap());
    assert_eq!(next.requester_ever, 2, "the ever count stays");
}

fn armed(ceilings: &Value) -> AllowanceMeter {
    let owner = KeyPair::new_user();
    let mut doc = Allowance {
        v: 1,
        agent: KeyPair::new_user().public_key(),
        owner_key: String::new(),
        cost_model: AllowanceCostModel { per_1k_tokens_micro: 1000, currency: "USD".into() },
        ceilings: serde_json::from_value::<Vec<AllowanceCeiling>>(ceilings.clone()).unwrap(),
        on_exhausted: OnExhausted::Refuse,
        updated_at: "2026-10-05T00:00:00.000Z".into(),
        sig: None,
    };
    sign_allowance(&mut doc, &owner).unwrap();
    let mut meter = AllowanceMeter::new();
    meter.arm(&serde_json::to_value(&doc).unwrap()).unwrap();
    meter
}

#[test]
fn the_allowance_walk() {
    let f = fixture();
    let a = &f["allowance"];
    let day = "2026-10-05";
    let mut meter = armed(&a["ceilings"]);
    let ceiling = |scope: &str| {
        a["ceilings"].as_array().unwrap().iter().find(|c| c["scope"] == scope).unwrap()["amount_micro"].as_u64().unwrap()
    };
    let work = WorkScope::default();
    for (i, step) in a["steps"].as_array().unwrap().iter().enumerate() {
        let trial = step["trial"].as_bool().unwrap();
        if let Some(spend) = step["spend_micro"].as_u64() {
            let task = format!("task-{i}");
            meter.report_work_at(&task, None, day, Usage::CostMicro(spend), trial).unwrap();
            let then = &step["then"];
            let ledger = meter.ledger();
            assert_eq!(ceiling("trial") - ledger.trial_spend(day), then["trial_remaining"].as_u64().unwrap(), "step {i}");
            assert_eq!(ceiling("day") - ledger.day_spend(day), then["day_remaining"].as_u64().unwrap(), "step {i}");
        } else {
            let estimate = step["estimate_micro"].as_u64().unwrap();
            let expect = step["expect"].as_str().unwrap();
            let answer = if trial {
                match meter.trial_funds_at(work, estimate, day) {
                    TrialFunds::Room => "room",
                    TrialFunds::Full => "full",
                    TrialFunds::None => "none",
                }
            } else {
                match meter.check_admission_at(work, estimate, day) {
                    agentmesh::AllowanceDecision::Exhausted { .. } => "full",
                    _ => "room",
                }
            };
            assert_eq!(answer, expect, "step {i}");
        }
    }
    let none = armed(&a["no_trial_ceiling"]["ceilings"]);
    assert_eq!(none.trial_funds_at(work, 0, day), TrialFunds::None);
    assert_eq!(a["no_trial_ceiling"]["trial_answer"], "none");

    // The scope joins a closed enum that stays closed.
    for scope in a["scopes"].as_array().unwrap() {
        let c = json!([{ "scope": scope, "amount_micro": 1 }]);
        assert!(serde_json::from_value::<Vec<AllowanceCeiling>>(c).is_ok(), "{scope}");
    }
    assert!(serde_json::from_value::<Vec<AllowanceCeiling>>(json!([{ "scope": "week", "amount_micro": 1 }])).is_err());
}
