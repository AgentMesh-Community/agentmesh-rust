//! §5.3: "Receivers MUST refuse a message signed by a revoked agent key."
//!
//! The receive path asks the registry about each sender (with a short memo),
//! refuses a revoked one with UNAUTHORIZED / agent_key_revoked and a paused
//! one with UNAUTHORIZED / agent_paused, lets everyone through when the
//! registry cannot answer, and never forgets a key it has seen revoked. The
//! Rust mirror of the TypeScript SDK's `revoked-senders.test.ts`; the memo's
//! own cases are unit tests in `src/revoked_senders.rs`.
//!
//! These need a real subscription, so they skip when no NATS server is
//! reachable, exactly like `tests/e2e.rs`. A fake registry answers
//! `mesh.registry.get.<key>` for the keys each test names, and for no others.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use agentmesh::envelope::{Envelope, PrimitiveType};
use agentmesh::identity::sign_envelope;
use agentmesh::{
    decode, encode, AgentMesh, ConnectOptions, ErrorCode, ErrorObject, InboundOptions, KeyPair,
    RegisterOptions,
};
use futures::StreamExt;
use serde_json::json;

const URL: &str = "nats://127.0.0.1:4222";

#[derive(Clone)]
enum Says {
    Revoked,
    Paused,
    NotFound,
}

struct Registry {
    gets: Arc<AtomicUsize>,
    down: Arc<AtomicBool>,
    answers: Arc<Mutex<HashMap<String, Says>>>,
}

/// A registry that answers `get` for the keys in `answers`, and is silent for
/// every other key so it cannot disturb anything else on the broker.
async fn fake_registry() -> Option<Registry> {
    let conn = async_nats::connect(URL).await.ok()?;
    let mut sub = conn.subscribe("mesh.registry.get.*").await.ok()?;
    let kp = KeyPair::new_user();
    let reg = Registry {
        gets: Arc::new(AtomicUsize::new(0)),
        down: Arc::new(AtomicBool::new(false)),
        answers: Arc::new(Mutex::new(HashMap::new())),
    };
    let (gets, down, answers) = (reg.gets.clone(), reg.down.clone(), reg.answers.clone());
    tokio::spawn(async move {
        while let Some(msg) = sub.next().await {
            let key = msg.subject.as_str().trim_start_matches("mesh.registry.get.").to_string();
            let Some(says) = answers.lock().unwrap().get(&key).cloned() else { continue };
            gets.fetch_add(1, Ordering::SeqCst);
            if down.load(Ordering::SeqCst) {
                continue;
            }
            let Some(reply) = msg.reply.clone() else { continue };
            let Ok(req) = decode(&msg.payload) else { continue };
            let mut env = Envelope::new(PrimitiveType::Respond, &kp.public_key());
            env.to = Some(req.from.clone());
            env.in_reply_to = Some(req.id.clone());
            match says {
                Says::Revoked => {
                    env.error = Some(ErrorObject {
                        code: ErrorCode::Unauthorized.as_str().into(),
                        message: "revoked".into(),
                        details: Some(json!({
                            "reason": "agent_key_revoked",
                            "revoked_at": "2026-09-27T00:00:00.000Z",
                            "replaced_by": "UNEWKEY",
                        })),
                        retryable: false,
                        retry_after_ms: None,
                    })
                }
                Says::Paused => {
                    env.payload = Some(json!({
                        "id": key,
                        "status": "paused",
                        "status_since": "2026-09-27T10:00:00.000Z",
                    }))
                }
                Says::NotFound => {
                    env.error = Some(ErrorObject {
                        code: ErrorCode::AgentUnavailable.as_str().into(),
                        message: "not found".into(),
                        details: None,
                        retryable: false,
                        retry_after_ms: None,
                    })
                }
            }
            sign_envelope(&mut env, &kp).expect("sign");
            let _ = conn.publish(reply, encode(&env).expect("encode").into()).await;
        }
    });
    Some(reg)
}

async fn connect() -> Option<AgentMesh> {
    AgentMesh::connect(URL, ConnectOptions { allow_unnamed: true, ..Default::default() }).await.ok()
}

struct Receiver {
    agent: AgentMesh,
    handled: Arc<Mutex<Vec<String>>>,
    warnings: Arc<Mutex<Vec<(String, Option<String>)>>>,
}

async fn receiver(refuse: bool) -> Receiver {
    let agent = connect().await.expect("receiver connect");
    let handled: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let warnings: Arc<Mutex<Vec<(String, Option<String>)>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = warnings.clone();
    agent.on_security_warning(move |w| sink.lock().unwrap().push((w.code, w.from)));
    if !refuse {
        agent.set_inbound_options(InboundOptions { refuse_revoked_senders: false, ..Default::default() });
    }
    let recorder = handled.clone();
    agent.on_request_ctx("chat", move |_input, ctx| {
        let recorder = recorder.clone();
        async move {
            recorder.lock().unwrap().push(ctx.from.clone());
            Ok(json!({ "ok": true }))
        }
    });
    agent
        .register(RegisterOptions { name: "receiver".into(), ..Default::default() })
        .await
        .expect("register");
    Receiver { agent, handled, warnings }
}

macro_rules! need_broker {
    () => {{
        let Some(reg) = fake_registry().await else {
            eprintln!("skipping the §5.3 receive check test: no NATS server at {URL}");
            return;
        };
        reg
    }};
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refuses_a_revoked_key_and_handles_a_good_one() {
    let reg = need_broker!();
    let bad = connect().await.expect("connect");
    let good = connect().await.expect("connect");
    reg.answers.lock().unwrap().insert(bad.id().to_string(), Says::Revoked);
    reg.answers.lock().unwrap().insert(good.id().to_string(), Says::NotFound);
    let rx = receiver(true).await;

    let err = bad.request(rx.agent.id(), "chat", json!({ "text": "hi" })).await.expect_err("refused");
    let text = err.to_string();
    assert!(text.contains("UNAUTHORIZED"), "{text}");
    assert!(text.contains("revoked"), "{text}");
    assert!(rx.handled.lock().unwrap().is_empty());
    assert!(rx
        .warnings
        .lock()
        .unwrap()
        .iter()
        .any(|(c, f)| c == "revoked_sender" && f.as_deref() == Some(bad.id())));

    good.request(rx.agent.id(), "chat", json!({ "text": "hi" })).await.expect("handled");
    assert_eq!(*rx.handled.lock().unwrap(), vec![good.id().to_string()]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refuses_a_paused_sender() {
    let reg = need_broker!();
    let paused = connect().await.expect("connect");
    reg.answers.lock().unwrap().insert(paused.id().to_string(), Says::Paused);
    let rx = receiver(true).await;

    let err = paused.request(rx.agent.id(), "chat", json!({ "text": "hi" })).await.expect_err("refused");
    let text = err.to_string();
    assert!(text.contains("UNAUTHORIZED") && text.contains("paused"), "{text}");
    assert!(rx.handled.lock().unwrap().is_empty());
    assert!(rx.warnings.lock().unwrap().iter().any(|(c, _)| c == "stopped_sender"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lets_a_sender_through_when_the_registry_cannot_answer() {
    let reg = need_broker!();
    let sender = connect().await.expect("connect");
    reg.answers.lock().unwrap().insert(sender.id().to_string(), Says::Revoked);
    reg.down.store(true, Ordering::SeqCst);
    let rx = receiver(true).await;
    sender.request(rx.agent.id(), "chat", json!({ "text": "hi" })).await.expect("handled");
    assert_eq!(*rx.handled.lock().unwrap(), vec![sender.id().to_string()]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn keeps_refusing_a_key_it_has_seen_revoked_after_the_registry_goes_quiet() {
    let reg = need_broker!();
    let bad = connect().await.expect("connect");
    reg.answers.lock().unwrap().insert(bad.id().to_string(), Says::Revoked);
    let rx = receiver(true).await;
    bad.request(rx.agent.id(), "chat", json!({})).await.expect_err("refused");
    reg.down.store(true, Ordering::SeqCst);
    let err = bad.request(rx.agent.id(), "chat", json!({})).await.expect_err("still refused");
    assert!(err.to_string().contains("revoked"), "{err}");
    assert!(rx.handled.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn asks_once_per_sender_not_once_per_message() {
    let reg = need_broker!();
    let sender = connect().await.expect("connect");
    reg.answers.lock().unwrap().insert(sender.id().to_string(), Says::NotFound);
    let rx = receiver(true).await;
    let before = reg.gets.load(Ordering::SeqCst);
    sender.request(rx.agent.id(), "chat", json!({})).await.expect("handled");
    sender.request(rx.agent.id(), "chat", json!({})).await.expect("handled");
    assert_eq!(reg.gets.load(Ordering::SeqCst) - before, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn does_nothing_when_the_host_turned_it_off() {
    let reg = need_broker!();
    let bad = connect().await.expect("connect");
    reg.answers.lock().unwrap().insert(bad.id().to_string(), Says::Revoked);
    let rx = receiver(false).await;
    bad.request(rx.agent.id(), "chat", json!({})).await.expect("handled");
    assert_eq!(*rx.handled.lock().unwrap(), vec![bad.id().to_string()]);
    assert_eq!(reg.gets.load(Ordering::SeqCst), 0);
}
