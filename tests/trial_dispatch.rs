//! Trials at the node's door (Common Agent 7.7): the gate `dispatch_inbound`
//! runs for a request marked `trial: true`. Behavioural, so these run against
//! a live NATS server at 127.0.0.1:4222 and skip without one, like
//! `tests/accept_signal.rs`. The pure admission logic is pinned by
//! `tests/trial_conformance.rs` with no broker.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use agentmesh::{
    sign_allowance, Allowance, AllowanceCeiling, AllowanceCostModel, AgentMesh, Budget,
    ConnectOptions, CostCeiling, KeyPair, Offering, OnExhausted, RegisterOptions, RequestOptions,
    TrialRequester, TrialRequesterKind,
};
use serde_json::{json, Value};

const URL: &str = "nats://127.0.0.1:4222";

async fn connect_pair() -> Option<(AgentMesh, AgentMesh)> {
    let opts = || ConnectOptions { allow_unnamed: true, ..Default::default() };
    let responder = AgentMesh::connect(URL, opts()).await.ok()?;
    let requester = AgentMesh::connect(URL, opts()).await.ok()?;
    Some((responder, requester))
}

fn explain_offering() -> Offering {
    serde_json::from_value(json!({
        "id": "explain",
        "name": "Explain",
        "description": "explains a thing",
        "trial": {
            "who": "anyone",
            "shape": {
                "inputs": [
                    { "name": "focus", "limit": { "max_chars": 5 } },
                    { "name": "site", "limit": { "max_pages": 3 } }
                ],
                "marked": true
            },
            "limits": { "per_requester_per_day": 2 }
        }
    }))
    .unwrap()
}

fn allowance_for(agent: &str, ceilings: Value) -> Value {
    let owner = KeyPair::new_user();
    let mut doc = Allowance {
        v: 1,
        agent: agent.to_string(),
        owner_key: String::new(),
        cost_model: AllowanceCostModel { per_1k_tokens_micro: 1000, currency: "USD".into() },
        ceilings: serde_json::from_value::<Vec<AllowanceCeiling>>(ceilings).unwrap(),
        on_exhausted: OnExhausted::Refuse,
        updated_at: "2026-10-05T00:00:00.000Z".into(),
        sig: None,
    };
    sign_allowance(&mut doc, &owner).unwrap();
    serde_json::to_value(&doc).unwrap()
}

/// Handler that records the trial context it was handed, and how often it ran.
fn serve(responder: &AgentMesh) -> Arc<Mutex<Vec<Option<agentmesh::TrialContext>>>> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = seen.clone();
    responder.on_request_ctx("explain", move |_input, ctx| {
        let sink = sink.clone();
        async move {
            sink.lock().unwrap().push(ctx.trial.clone());
            Ok(json!({ "explained": true }))
        }
    });
    seen
}

fn trial() -> RequestOptions {
    RequestOptions { trial: true, timeout: Some(Duration::from_secs(5)), ..Default::default() }
}

fn reason_of(err: &agentmesh::MeshError) -> String {
    let eo = err.error_object().expect("a structured refusal");
    assert_eq!(eo.code, "TRIAL_REFUSED");
    let d = eo.details.as_ref().expect("details");
    assert!(d["quote"].is_object(), "every refusal carries the quote");
    d["reason"].as_str().unwrap().to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trials_are_admitted_counted_and_refused_at_the_door() {
    let Some((responder, requester)) = connect_pair().await else {
        eprintln!("skipping trial dispatch tests: no NATS server at {URL}");
        return;
    };
    let seen = serve(&responder);
    responder
        .register(RegisterOptions {
            name: "explainer".into(),
            offerings: vec![explain_offering()],
            ..Default::default()
        })
        .await
        .expect("register");
    tokio::time::sleep(Duration::from_millis(150)).await;

    // No allowance: no trial ceiling, so funds.
    let err = requester.request_with_options(responder.id(), "explain", json!({}), trial()).await.unwrap_err();
    assert_eq!(reason_of(&err), "funds");

    responder
        .set_allowance(&allowance_for(
            responder.id(),
            json!([{ "scope": "day", "amount_micro": 10000000 }, { "scope": "trial", "amount_micro": 5000000 }]),
        ))
        .expect("arm");

    // A budget on a trial: refused budget, before anything else.
    let with_budget = RequestOptions {
        budget: Some(Budget {
            deadline: None,
            revision: 0,
            cost_ceiling: Some(CostCeiling::new(1_000_000, "USD")),
        }),
        ..trial()
    };
    let err = requester.request_with_options(responder.id(), "explain", json!({}), with_budget).await.unwrap_err();
    assert_eq!(reason_of(&err), "budget");

    // Over the shape's measured limit: refused input, naming it.
    let err = requester
        .request_with_options(responder.id(), "explain", json!({ "focus": "too long" }), trial())
        .await
        .unwrap_err();
    assert_eq!(reason_of(&err), "input");

    // Two fit; the handler sees the trial, its shape and the work caps.
    for _ in 0..2 {
        let res = requester
            .request_with_options(responder.id(), "explain", json!({ "focus": "ok", "site": "https://x" }), trial())
            .await
            .expect("admitted");
        assert_eq!(res.payload["status"], json!("completed"));
    }
    {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 2, "refused trials never reached the handler");
        let t = seen[0].as_ref().expect("trial context");
        assert_eq!(t.requester.id, requester.id());
        assert_eq!(t.requester.kind, TrialRequesterKind::Agent);
        assert_eq!(t.caps.len(), 1);
        assert_eq!(t.caps[0].input, "site");
        assert_eq!(t.caps[0].limit.max_pages, Some(3));
        assert_eq!(t.shape.as_ref().unwrap().marked, Some(true));
    }

    // The third is past per_requester_per_day.
    let err = requester.request_with_options(responder.id(), "explain", json!({}), trial()).await.unwrap_err();
    assert_eq!(reason_of(&err), "requester_day");
    let eo = err.error_object().unwrap();
    assert_eq!(eo.details.as_ref().unwrap()["limit"], json!(2));
    assert!(eo.details.as_ref().unwrap()["resets_at"].is_string());

    // Ordinary work is untouched by the trial gate, and its context has no trial.
    requester.request(responder.id(), "explain", json!({})).await.expect("ordinary request");
    assert!(seen.lock().unwrap().last().unwrap().is_none());

    requester.close().await;
    responder.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_trusted_hosts_vouch_names_the_requester_and_an_untrusted_one_is_ignored() {
    let Some((responder, host)) = connect_pair().await else {
        eprintln!("skipping trial dispatch tests: no NATS server at {URL}");
        return;
    };
    let seen = serve(&responder);
    responder
        .register(RegisterOptions {
            name: "explainer".into(),
            offerings: vec![explain_offering()],
            ..Default::default()
        })
        .await
        .expect("register");
    responder
        .set_allowance(&allowance_for(responder.id(), json!([{ "scope": "trial", "amount_micro": 5000000 }])))
        .expect("arm");
    tokio::time::sleep(Duration::from_millis(150)).await;

    let visitor = TrialRequester {
        id: "visitor-7".into(),
        kind: TrialRequesterKind::Visitor,
        signed_in: false,
        verified: false,
    };
    let vouched = || RequestOptions { trial_requester: Some(visitor.clone()), ..trial() };

    // Not trusted yet: the requester is the sender.
    host.request_with_options(responder.id(), "explain", json!({}), vouched()).await.expect("admitted");
    assert_eq!(seen.lock().unwrap()[0].as_ref().unwrap().requester.id, host.id());

    // Trusted: the visitor is the requester, counted under its own id.
    responder.trust_trial_host(host.id());
    for _ in 0..2 {
        host.request_with_options(responder.id(), "explain", json!({}), vouched()).await.expect("admitted");
    }
    assert_eq!(seen.lock().unwrap()[1].as_ref().unwrap().requester.id, "visitor-7");
    let err = host.request_with_options(responder.id(), "explain", json!({}), vouched()).await.unwrap_err();
    assert_eq!(reason_of(&err), "requester_day", "the visitor's own two are used");

    host.close().await;
    responder.close().await;
}
