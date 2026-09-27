//! The §6.4a accept signal, asserted against `conformance/accept-signal.json`.
//!
//! **The fixture is the authority.** When a case here fails, the fix is in the
//! implementation, never in the JSON; the fixture itself changes only with a
//! spec change alongside. What it pins is the distinction one byte of drift
//! collapses: `"accepted"` asserts admission and a handler about to run;
//! `queued` asserts only that a mailbox holds the message.
//!
//! Wire-shape cases run with no broker, no connection and no clock (§22.8).
//! The ordering and caller-semantics cases are behavioral, so they run against
//! a live NATS server at 127.0.0.1:4222 and skip gracefully without one,
//! exactly like `tests/e2e.rs`.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::StreamExt;

use agentmesh::{
    accept_envelope, budget_insufficient, canonical_json, codec, is_accept_signal, queued_ack_of,
    AgentMesh, ConnectOptions, DeliverySignal, Envelope, ErrorCode, InboundOptions, KeyPair,
    PrimitiveType, RegisterOptions, RequestOptions,
};
use serde_json::{json, Value};

static FIXTURE_JSON: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/conformance/accept-signal.json"));

fn fixture() -> Value {
    serde_json::from_str(FIXTURE_JSON).expect("conformance/accept-signal.json parses")
}

const URL: &str = "nats://127.0.0.1:4222";

// ─── the wire shape (no broker, no clock) ───────────────────────────────────

#[test]
fn the_fixtures_signed_accept_verifies_and_its_canonical_bytes_rebuild() {
    let f = fixture();
    let envelope = &f["accept"]["envelope"];
    assert_eq!(
        envelope["signed_bytes_prefix"].as_str().unwrap(),
        agentmesh::ENVELOPE_SIG_PREFIX,
        "the domain prefix is the envelope's own (§5.3)"
    );

    // Any conforming implementation MUST rebuild the signed bytes from the
    // envelope and verify the signature. `codec::decode` does exactly that.
    let wire = serde_json::to_vec(&envelope["signed"]).unwrap();
    let env = codec::decode(&wire).expect("the fixture's really-signed accept verifies");
    assert_eq!(env.from, f["identities"]["responder"].as_str().unwrap());
    assert_eq!(env.to.as_deref(), Some(f["identities"]["requester"].as_str().unwrap()));
    assert!(is_accept_signal(&env), "the pinned envelope is recognized as an accept");
    assert!(env.task_id.is_none(), "task_id: absent on the wire, null at the API");

    // The canonical bytes (envelope minus sig, RFC 8785) match the pinned string.
    let mut minus_sig = envelope["signed"].clone();
    minus_sig.as_object_mut().unwrap().remove("sig");
    assert_eq!(
        canonical_json(&minus_sig),
        envelope["canonical"].as_str().unwrap(),
        "canonical envelope bytes match the fixture"
    );
}

#[test]
fn our_accept_builder_produces_the_required_shape() {
    let f = fixture();
    let required = &f["accept"]["required"];
    assert_eq!(required["type"], json!("respond"));
    assert_eq!(required["payload_status"], json!("accepted"));
    assert_eq!(required["terminal"], json!(false));
    assert_eq!(required["emitted_before_handler"], json!(true));

    let mut req = Envelope::new(PrimitiveType::Request, "UREQUESTERAAAAAAAAAAAAAAAAAAAAAA");
    req.to = Some("URESPONDERAAAAAAAAAAAAAAAAAAAAAA".to_string());
    let acc = accept_envelope("URESPONDERAAAAAAAAAAAAAAAAAAAAAA", &req);
    let wire = serde_json::to_value(&acc).unwrap();
    assert_eq!(wire["type"], json!("respond"));
    assert_eq!(wire["payload"], json!({ "status": "accepted" }));
    assert_eq!(wire["in_reply_to"], json!(req.id), "in_reply_to is the admitted request's id");
    // §5.3 absent-members rule: the spec's prose "task_id: null" is the API
    // normalization, never a serialized null.
    assert!(wire.get("task_id").is_none(), "task_id ABSENT on the wire");
    assert!(is_accept_signal(&acc));
}

#[test]
fn the_queued_ack_shape_is_pinned_and_disjoint_from_the_accept() {
    let f = fixture();
    // The pinned points, as data: queued is boolean true, inbox_id present and
    // non-empty, text informative only.
    let shape = &f["queued_ack"]["shape"];
    assert_eq!(shape["queued"], json!(true));
    let ack = queued_ack_of(Some(&json!({
        "queued": true,
        "inbox_id": "1c1c1c1c-0000-7000-8000-000000000001",
        "text": "informative, implementation-chosen"
    })))
    .expect("the pinned shape is recognized");
    assert_eq!(ack.inbox_id.as_deref(), Some("1c1c1c1c-0000-7000-8000-000000000001"));
    // "queued is boolean true, not a string".
    assert!(queued_ack_of(Some(&json!({ "queued": "true", "inbox_id": "x" }))).is_none());
    // Disjointness: an accept is never a queued ack and vice versa.
    let mut req = Envelope::new(PrimitiveType::Request, "UREQ");
    req.to = Some("URESP".to_string());
    let acc = accept_envelope("URESP", &req);
    assert!(queued_ack_of(acc.payload.as_ref()).is_none());
    let mut queued_env = Envelope::new(PrimitiveType::Respond, "UNODE");
    queued_env.payload = Some(json!({ "status": "completed", "output": { "queued": true, "inbox_id": "i" } }));
    assert!(!is_accept_signal(&queued_env));
    assert!(queued_ack_of(queued_env.payload.as_ref()).is_some());
}

#[test]
fn accepted_is_not_a_terminal_status_and_not_a_task_state() {
    // §7.2's state set never contains "accepted"; a respond carrying it is not
    // the Task-creating non-terminal respond of §6.4. Locally checkable side:
    // the recognizer refuses every real state.
    for task_state in ["submitted", "working", "input_required", "auth_required", "completed", "failed", "canceled"] {
        let mut env = Envelope::new(PrimitiveType::Respond, "U");
        env.payload = Some(json!({ "status": task_state }));
        assert!(!is_accept_signal(&env), "{task_state} is substantive, not an accept");
    }
}

// ─── the ordering cases (live; skip without a broker) ───────────────────────

/// Collects the §6.4a delivery signals a caller observes.
fn signal_recorder() -> (Arc<Mutex<Vec<String>>>, agentmesh::DeliverySignalSink) {
    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = seen.clone();
    let cb: agentmesh::DeliverySignalSink = Arc::new(move |s: DeliverySignal| {
        let tag = match s {
            DeliverySignal::Accepted { .. } => "accepted".to_string(),
            DeliverySignal::Queued { inbox_id } => {
                format!("queued:{}", inbox_id.as_deref().unwrap_or("-"))
            }
        };
        sink.lock().unwrap().push(tag);
    });
    (seen, cb)
}

async fn connect_pair() -> Option<(AgentMesh, AgentMesh)> {
    let responder = AgentMesh::connect(URL, ConnectOptions { allow_unnamed: true, ..Default::default() }).await.ok()?;
    let requester = AgentMesh::connect(URL, ConnectOptions { allow_unnamed: true, ..Default::default() }).await.ok()?;
    Some((responder, requester))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admitted_live_answers_the_accept_first_then_the_substantive_respond() {
    // Fixture ordering case `admitted_live`.
    let Some((responder, requester)) = connect_pair().await else {
        eprintln!("skipping accept-signal live tests: no NATS server at {URL}");
        return;
    };
    responder.on_request("echo", |input| async move { Ok(json!({ "echoed": input })) });
    responder
        .register(RegisterOptions { name: "accepting".into(), ..Default::default() })
        .await
        .expect("register");
    tokio::time::sleep(Duration::from_millis(150)).await;

    let (signals, sink) = signal_recorder();
    let res = requester
        .request_with_options(
            responder.id(),
            "echo",
            json!({ "hi": 1 }),
            RequestOptions { on_signal: Some(sink), ..Default::default() },
        )
        .await
        .expect("substantive respond");
    assert!(res.accepted, "an accept preceded the substantive respond");
    assert_eq!(signals.lock().unwrap().as_slice(), ["accepted"], "first reply was the accept");
    assert_eq!(res.payload["status"], json!("completed"));
    assert!(res.task_id.is_none());

    requester.close().await;
    responder.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_budget_refusal_at_admission_is_the_first_reply_and_no_accept_is_sent() {
    // Fixture ordering case `budget_refused_at_admission`: refusals of
    // admission happen INSTEAD of an accept, never after one.
    let Some((responder, requester)) = connect_pair().await else {
        eprintln!("skipping accept-signal live tests: no NATS server at {URL}");
        return;
    };
    responder.on_admission("priced", |_input, _ctx| {
        Err(budget_insufficient(
            Some(agentmesh::CostCeiling::new(6_000_000, "USD")),
            "6 USD to do this well",
        ))
    });
    responder.on_request("priced", |_input| async move { Ok(json!({ "never": "runs" })) });
    responder
        .register(RegisterOptions { name: "refusing".into(), ..Default::default() })
        .await
        .expect("register");
    tokio::time::sleep(Duration::from_millis(150)).await;

    let (signals, sink) = signal_recorder();
    let err = requester
        .request_with_options(
            responder.id(),
            "priced",
            json!({ "job": "big" }),
            RequestOptions { on_signal: Some(sink), ..Default::default() },
        )
        .await
        .expect_err("refused at admission");
    let eo = err.error_object().expect("the refusal keeps its wire error object");
    assert_eq!(eo.code, ErrorCode::BudgetInsufficient.as_str());
    assert_eq!(eo.details.as_ref().unwrap()["estimate"]["amount_micro"], json!(6_000_000));
    assert!(signals.lock().unwrap().is_empty(), "accept_sent: false — no accept before a refusal");

    requester.close().await;
    responder.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_oversize_request_is_refused_without_an_accept() {
    // Fixture ordering case `oversize_refused`. The responder's declared world
    // is a 32-unit cap; the sender holds no manifest, so its own pre-flight
    // (default cap) publishes, and the REMOTE §22.5 refusal is the first and
    // only reply — same code either way, which is §6.4b's mirror.
    let Some((responder, requester)) = connect_pair().await else {
        eprintln!("skipping accept-signal live tests: no NATS server at {URL}");
        return;
    };
    responder.set_inbound_options(InboundOptions { max_inbound_chars: 32, ..Default::default() });
    responder.on_request("echo", |input| async move { Ok(input) });
    responder
        .register(RegisterOptions { name: "capped".into(), ..Default::default() })
        .await
        .expect("register");
    tokio::time::sleep(Duration::from_millis(150)).await;

    let (signals, sink) = signal_recorder();
    let err = requester
        .request_with_options(
            responder.id(),
            "echo",
            json!({ "text": "y".repeat(33) }),
            RequestOptions { on_signal: Some(sink), ..Default::default() },
        )
        .await
        .expect_err("refused over the cap");
    assert!(err.to_string().contains(ErrorCode::ContextTooLarge.as_str()));
    assert!(signals.lock().unwrap().is_empty(), "accept_sent: false");

    requester.close().await;
    responder.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stale_envelope_gets_nothing_not_even_an_accept() {
    // Fixture ordering case `stale_or_misaddressed`: silent by design (§22.7).
    let Some((responder, _requester)) = connect_pair().await else {
        eprintln!("skipping accept-signal live tests: no NATS server at {URL}");
        return;
    };
    responder.on_request("echo", |input| async move { Ok(input) });
    responder
        .register(RegisterOptions { name: "silent-refuser".into(), ..Default::default() })
        .await
        .expect("register");
    tokio::time::sleep(Duration::from_millis(150)).await;

    let probe = async_nats::connect(URL).await.expect("probe connect");
    let kp = KeyPair::new_user();
    let mut env = Envelope::new(PrimitiveType::Request, kp.public_key());
    env.to = Some(responder.id().to_string());
    env.ts = "2020-01-01T00:00:00Z".to_string(); // far outside the live window
    env.payload = Some(json!({ "offering": "echo", "input": { "hi": 1 } }));
    agentmesh::sign_envelope(&mut env, &kp).expect("sign");
    let reply_inbox = probe.new_inbox();
    let mut replies = probe.subscribe(reply_inbox.clone()).await.expect("subscribe");
    probe
        .publish_with_reply(
            format!("mesh.agent.{}.inbox", responder.id()),
            reply_inbox,
            codec::encode(&env).unwrap().into(),
        )
        .await
        .expect("publish");
    probe.flush().await.expect("flush");
    let silence = tokio::time::timeout(Duration::from_millis(750), replies.next()).await;
    assert!(silence.is_err(), "first_reply: nothing — the refusal is silent (§22.7)");

    responder.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failure_of_the_work_follows_the_accept() {
    // Fixture ordering case `work_fails_after_accept`: OFFERING_NOT_FOUND is
    // discovered at dispatch — after admission — so it legally FOLLOWS the
    // accept; only a refusal of admission may not.
    let Some((responder, requester)) = connect_pair().await else {
        eprintln!("skipping accept-signal live tests: no NATS server at {URL}");
        return;
    };
    responder.on_request("echo", |input| async move { Ok(input) });
    responder
        .register(RegisterOptions { name: "dispatch-fail".into(), ..Default::default() })
        .await
        .expect("register");
    tokio::time::sleep(Duration::from_millis(150)).await;

    let (signals, sink) = signal_recorder();
    let err = requester
        .request_with_options(
            responder.id(),
            "no-such-offering",
            json!({}),
            RequestOptions { on_signal: Some(sink), ..Default::default() },
        )
        .await
        .expect_err("the work failed");
    assert!(err.to_string().contains("OFFERING_NOT_FOUND"));
    assert_eq!(
        signals.lock().unwrap().as_slice(),
        ["accepted"],
        "accept_sent: true, then the terminal error respond"
    );

    requester.close().await;
    responder.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_queued_ack_is_recognized_and_never_resolves_the_request() {
    // Fixture ordering case `attended_inbox` + caller_semantics
    // `request_still_outstanding`: the queued ack never resolves the request.
    // After it, the reply channel will never carry anything more (the real
    // reply goes to this agent's own inbox, §6.4), so the wait rejects
    // PROMPTLY — well inside the timeout — with the SDK-local REQUEST_QUEUED,
    // ack fields and request id in details, the signal hook fired first.
    let Ok(requester) = AgentMesh::connect(URL, ConnectOptions { allow_unnamed: true, ..Default::default() }).await else {
        eprintln!("skipping accept-signal live tests: no NATS server at {URL}");
        return;
    };

    // A stand-in node holding an attended inbox (§16.4): answers the queued
    // ack synchronously, never "accepted", and no substantive respond ever
    // arrives on this reply subject.
    let node = async_nats::connect(URL).await.expect("node connect");
    let node_kp = KeyPair::new_user();
    let node_id = node_kp.public_key();
    let target_kp = KeyPair::new_user();
    let target_id = target_kp.public_key();
    let mut inbox_sub = node
        .subscribe(format!("mesh.agent.{target_id}.inbox"))
        .await
        .expect("node subscribes the attended inbox");
    node.flush().await.expect("flush");
    let answering = tokio::spawn({
        let node = node.clone();
        async move {
            if let Some(msg) = inbox_sub.next().await {
                let req = codec::decode(&msg.payload).expect("request verifies");
                let mut ack = Envelope::new(PrimitiveType::Respond, &node_id);
                ack.to = Some(req.from.clone());
                ack.in_reply_to = Some(req.id.clone());
                ack.payload = Some(json!({
                    "status": "completed",
                    "output": { "queued": true, "inbox_id": "held-42", "text": "a live session replies later" }
                }));
                agentmesh::sign_envelope(&mut ack, &node_kp).expect("sign");
                if let Some(reply) = msg.reply {
                    let _ = node.publish(reply, codec::encode(&ack).unwrap().into()).await;
                }
            }
        }
    });

    let (signals, sink) = signal_recorder();
    let started = std::time::Instant::now();
    let err = requester
        .request_with_options(
            &target_id,
            "chat",
            json!({ "message": "hello" }),
            RequestOptions {
                timeout: Some(Duration::from_secs(10)),
                on_signal: Some(sink),
                ..Default::default()
            },
        )
        .await
        .expect_err("a queued ack must not resolve the request");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the rejection is prompt — the 10s timeout was not consumed"
    );
    let eo = err.error_object().expect("REQUEST_QUEUED keeps its error object");
    assert_eq!(eo.code, "REQUEST_QUEUED");
    assert!(!eo.retryable);
    let details = eo.details.as_ref().expect("details carry the ack fields");
    assert_eq!(details["queued"], json!(true));
    assert_eq!(details["inbox_id"], json!("held-42"));
    assert!(
        details["request_id"].as_str().is_some_and(|s| !s.is_empty()),
        "details carry the request id — the correlation handle for the late reply"
    );
    assert_eq!(
        signals.lock().unwrap().as_slice(),
        ["queued:held-42"],
        "the signal hook fired before the rejection"
    );
    let _ = answering.await;

    requester.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_interactive_agent_emits_no_accept() {
    // §6.4a × §8.3a: an agent registered `interaction: "interactive"` is an
    // attended surface — a person is in the loop, so "a handler will run now"
    // is not a promise its dispatcher may make. The MUST NOT for the attended
    // case covers an SDK-hosted interactive agent as much as a node-held
    // inbox: no accept, only the substantive respond.
    let Some((responder, requester)) = connect_pair().await else {
        eprintln!("skipping accept-signal live tests: no NATS server at {URL}");
        return;
    };
    responder.on_request("chat", |input| async move { Ok(json!({ "echoed": input })) });
    responder
        .register(RegisterOptions {
            name: "attended".into(),
            interaction: Some("interactive".into()),
            ..Default::default()
        })
        .await
        .expect("register");
    tokio::time::sleep(Duration::from_millis(150)).await;

    let (signals, sink) = signal_recorder();
    let res = requester
        .request_with_options(
            responder.id(),
            "chat",
            json!({ "message": "hi" }),
            RequestOptions { on_signal: Some(sink), ..Default::default() },
        )
        .await
        .expect("the substantive respond still arrives");
    assert!(!res.accepted, "no accept preceded the respond");
    assert!(signals.lock().unwrap().is_empty(), "no delivery signal was emitted");
    assert_eq!(res.payload["status"], json!("completed"));

    // …and a `service` declaration keeps emitting accepts: suppression is the
    // attended token only, never a side effect of declaring anything.
    let service_agent = AgentMesh::connect(URL, ConnectOptions { allow_unnamed: true, ..Default::default() })
        .await
        .expect("connect service agent");
    service_agent.on_request("chat", |input| async move { Ok(input) });
    service_agent
        .register(RegisterOptions {
            name: "unattended".into(),
            interaction: Some("service".into()),
            ..Default::default()
        })
        .await
        .expect("register");
    tokio::time::sleep(Duration::from_millis(150)).await;
    let res = requester
        .request(service_agent.id(), "chat", json!({ "message": "hi" }))
        .await
        .expect("respond");
    assert!(res.accepted, "a service agent still accepts");

    service_agent.close().await;
    requester.close().await;
    responder.close().await;
}

// ─── caller semantics: the timeout reset ────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_accept_resets_the_response_timeout() {
    // caller_semantics.timeout_reset: the handler takes LONGER than the
    // caller's whole timeout, and the request still succeeds because the
    // accept — arriving at admission, immediately — restarted the wait. The
    // §7.7 deadline, had one been attached, would not have moved.
    let Some((responder, requester)) = connect_pair().await else {
        eprintln!("skipping accept-signal live tests: no NATS server at {URL}");
        return;
    };
    responder.on_request("slow", |input| async move {
        tokio::time::sleep(Duration::from_millis(900)).await;
        Ok(json!({ "echoed": input }))
    });
    responder
        .register(RegisterOptions { name: "slow-worker".into(), ..Default::default() })
        .await
        .expect("register");
    tokio::time::sleep(Duration::from_millis(150)).await;

    let res = requester
        .request_with_options(
            responder.id(),
            "slow",
            json!({ "n": 1 }),
            RequestOptions { timeout: Some(Duration::from_millis(600)), ..Default::default() },
        )
        .await
        .expect("the accept reset the 600ms timeout, so 900ms of work fits");
    assert!(res.accepted);
    assert_eq!(res.payload["status"], json!("completed"));

    requester.close().await;
    responder.close().await;
}
