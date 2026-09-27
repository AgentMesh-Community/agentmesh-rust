//! End-to-end test: two agents exchange a request over a live NATS server.
//! Requires nats-server on 127.0.0.1:4222 (skips gracefully if absent).

use agentmesh::{decode, AgentMesh, ConnectOptions, MeshNode, NodeConnectOptions, RegisterOptions};
use futures::StreamExt;
use serde_json::json;

const URL: &str = "nats://127.0.0.1:4222";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_agents_bare_request_respond() {
    // Skip if no server is reachable.
    let responder = match AgentMesh::connect(URL, ConnectOptions { allow_unnamed: true, ..Default::default() }).await {
        Ok(a) => a,
        Err(_) => {
            eprintln!("skipping e2e: no NATS server at {URL}");
            return;
        }
    };

    let responder_echo_id = responder.id().to_string();
    responder.on_request("echo", |input| async move {
        Ok(json!({ "echoed": input }))
    });
    responder
        .register(RegisterOptions {
            name: "responder".into(),
            capabilities: vec!["echo".into()],
            ..Default::default()
        })
        .await
        .expect("register");

    let requester = AgentMesh::connect(URL, ConnectOptions { allow_unnamed: true, ..Default::default() }).await.expect("connect requester");
    // Give the responder's inbox subscription a moment to establish.
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    let res = requester
        .request(&responder_echo_id, "echo", json!({ "hi": 42 }))
        .await
        .expect("request");

    // Bare response: no Task, terminal completed, correct output, signed+verified.
    assert!(res.task_id.is_none(), "bare response has no task_id");
    assert_eq!(res.payload["status"], "completed");
    assert_eq!(res.payload["output"], json!({ "echoed": { "hi": 42 } }));
    assert!(res.envelope.sig.is_some(), "response was signed (and verified on decode)");
    assert_eq!(res.envelope.from, responder_echo_id, "response from = responder's verified key");

    // Unknown offering → OFFERING_NOT_FOUND (bare error).
    let err = requester.request(&responder_echo_id, "nope", json!({})).await.unwrap_err();
    assert!(format!("{err}").contains("OFFERING_NOT_FOUND"));

    requester.close().await;
    responder.close().await;
}

/// The event path, end to end: §18.8's Nats-Msg-Id on the wire, §22.2 dedup on
/// delivery, and the subscription dying with `close()`.
///
/// The subscriber is NODE-HOSTED on purpose: a standalone agent's `close()`
/// drains the whole connection, which would kill the subscription whether or not
/// the spawned event loop is tracked. A hosted agent leaves the shared
/// connection open, so only the (once-discarded) task handle being aborted can
/// end its event loop.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn events_carry_msg_id_dedup_duplicates_and_stop_at_close() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    const SUBJECT: &str = "mesh.event.e2e_events.happened";

    let node = match MeshNode::connect(URL, NodeConnectOptions::default()).await {
        Ok(n) => n,
        Err(_) => {
            eprintln!("skipping events e2e: no NATS server at {URL}");
            return;
        }
    };
    let subscriber = node.add_agent(None).expect("add subscriber");

    // A raw probe plays the part of a capturing stream: it sees the published
    // message as JetStream would, headers included.
    let raw = async_nats::connect(URL).await.expect("raw connect");
    let mut probe = raw.subscribe(SUBJECT).await.expect("probe subscribe");

    let count = Arc::new(AtomicUsize::new(0));
    let seen = count.clone();
    subscriber
        .subscribe("e2e_events.happened", move |_data, _env| {
            seen.fetch_add(1, Ordering::SeqCst);
        })
        .await
        .expect("subscribe");

    let emitter = AgentMesh::connect(URL, ConnectOptions { allow_unnamed: true, ..Default::default() }).await.expect("emitter");
    tokio::time::sleep(Duration::from_millis(200)).await;
    emitter.emit("e2e_events.happened", json!({ "n": 1 })).await.expect("emit");

    // §18.8: the Nats-Msg-Id header equals the envelope id, byte for byte.
    // That equality is what lets any stream capturing this subject drop a
    // duplicate publish inside its duplicate window.
    let msg = tokio::time::timeout(Duration::from_secs(2), probe.next())
        .await
        .expect("an event on the wire within 2s")
        .expect("probe subscription still open");
    let env = decode(&msg.payload).expect("the published event decodes and verifies");
    let headers = msg.headers.as_ref().expect("emit publishes WITH headers");
    assert_eq!(
        headers.get(async_nats::header::NATS_MESSAGE_ID).map(|v| v.as_str()),
        Some(env.id.as_str()),
        "Nats-Msg-Id must be the envelope id (§18.8)"
    );

    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(count.load(Ordering::SeqCst), 1, "the first delivery dispatched");

    // §22.2 on the event path: the same signed bytes republished (a
    // redelivery, as far as the subscriber can tell) dispatch nothing.
    raw.publish(SUBJECT, msg.payload.clone()).await.expect("republish");
    raw.flush().await.expect("flush");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(count.load(Ordering::SeqCst), 1, "a duplicate (from, id) dispatches once");

    // close() aborts the tracked event-loop task. The node's connection is
    // still open underneath, so a handler invocation after this point would
    // mean the loop outlived its agent, which is exactly what happened while
    // the JoinHandle was discarded.
    subscriber.close().await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    emitter.emit("e2e_events.happened", json!({ "n": 2 })).await.expect("emit after close");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(count.load(Ordering::SeqCst), 1, "close() ended the event subscription");

    emitter.close().await;
    node.close().await;
}

/// The §22.2 event memory is scoped PER SUBSCRIPTION pattern: an agent that
/// deliberately overlaps an exact topic with a wildcard registered two
/// handlers and gets the event in each, while a repeat of the same envelope
/// on either subscription still dispatches nothing (the c01 regression, fixed
/// in 0.17.1 / TS 0.44.1).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn overlapping_subscriptions_each_deliver_and_each_still_dedup() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    const SUBJECT: &str = "mesh.event.e2e_overlap.built";

    let node = match MeshNode::connect(URL, NodeConnectOptions::default()).await {
        Ok(n) => n,
        Err(_) => {
            eprintln!("skipping events e2e: no NATS server at {URL}");
            return;
        }
    };
    let subscriber = node.add_agent(None).expect("add subscriber");
    let raw = async_nats::connect(URL).await.expect("raw connect");
    let mut probe = raw.subscribe(SUBJECT).await.expect("probe subscribe");

    let exact = Arc::new(AtomicUsize::new(0));
    let wild = Arc::new(AtomicUsize::new(0));
    let seen_exact = exact.clone();
    let seen_wild = wild.clone();
    subscriber
        .subscribe("e2e_overlap.built", move |_data, _env| {
            seen_exact.fetch_add(1, Ordering::SeqCst);
        })
        .await
        .expect("subscribe exact");
    subscriber
        .subscribe("e2e_overlap.*", move |_data, _env| {
            seen_wild.fetch_add(1, Ordering::SeqCst);
        })
        .await
        .expect("subscribe wildcard");

    let emitter = AgentMesh::connect(URL, ConnectOptions { allow_unnamed: true, ..Default::default() }).await.expect("emitter");
    tokio::time::sleep(Duration::from_millis(200)).await;
    emitter.emit("e2e_overlap.built", json!({ "n": 1 })).await.expect("emit");

    let msg = tokio::time::timeout(Duration::from_secs(2), probe.next())
        .await
        .expect("an event on the wire within 2s")
        .expect("probe subscription still open");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(exact.load(Ordering::SeqCst), 1, "the exact subscription dispatched");
    assert_eq!(wild.load(Ordering::SeqCst), 1, "the overlapping wildcard dispatched too");

    // A republish of the same signed bytes is a repeat within EACH
    // subscription's own scope: neither dispatches again.
    raw.publish(SUBJECT, msg.payload.clone()).await.expect("republish");
    raw.flush().await.expect("flush");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(exact.load(Ordering::SeqCst), 1, "a duplicate dispatches nothing on the exact sub");
    assert_eq!(wild.load(Ordering::SeqCst), 1, "a duplicate dispatches nothing on the wildcard sub");

    subscriber.close().await;
    emitter.close().await;
    node.close().await;
}
/// §7.0 deferral, end to end (`HandlerOptions::defer_after` +
/// `AgentMesh::await_task`): a handler that outlives the threshold answers
/// the live wait with a non-terminal `working` respond carrying a task id,
/// and the terminal completion travels the task update channel where
/// `await_task` finds it. The same threshold on a fast handler changes
/// nothing: inside it, the answer stays bare.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_slow_handler_defers_and_await_task_recovers_the_answer() {
    let responder = match AgentMesh::connect(URL, ConnectOptions { allow_unnamed: true, ..Default::default() }).await {
        Ok(a) => a,
        Err(_) => {
            eprintln!("skipping e2e: no NATS server at {URL}");
            return;
        }
    };
    let responder_id = responder.id().to_string();
    responder.on_request("slow", |input| async move {
        tokio::time::sleep(std::time::Duration::from_millis(700)).await;
        Ok(json!({ "echoed": input }))
    });
    responder.on_request("fast", |input| async move { Ok(json!({ "echoed": input })) });
    let defer = agentmesh::HandlerOptions {
        defer_after: Some(std::time::Duration::from_millis(150)),
        ..Default::default()
    };
    responder.set_handler_options("slow", defer.clone());
    responder.set_handler_options("fast", defer);
    responder
        .register(RegisterOptions {
            name: "deferring responder".into(),
            capabilities: vec!["slow".into(), "fast".into()],
            ..Default::default()
        })
        .await
        .expect("register");

    let requester = AgentMesh::connect(URL, ConnectOptions { allow_unnamed: true, ..Default::default() }).await.expect("connect requester");
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    // Slow: the live wait resolves with the §7.0 non-terminal respond...
    let res = requester
        .request(&responder_id, "slow", json!({ "q": 1 }))
        .await
        .expect("request");
    assert_eq!(res.payload["status"], "working", "the threshold elapsed, so the respond defers");
    let task_id = res.task_id.clone().expect("a deferred respond carries the task id");

    // ...and the terminal statement arrives on the task update channel.
    let terminal = requester
        .await_task(&task_id, std::time::Duration::from_secs(10))
        .await
        .expect("await_task");
    assert_eq!(terminal["status"], "completed");
    assert_eq!(terminal["output"], json!({ "echoed": { "q": 1 } }));

    // Fast: same threshold, finishes inside it, stays bare.
    let res = requester
        .request(&responder_id, "fast", json!({ "q": 2 }))
        .await
        .expect("request");
    assert!(res.task_id.is_none(), "inside the threshold the answer is bare");
    assert_eq!(res.payload["status"], "completed");
    assert_eq!(res.payload["output"], json!({ "echoed": { "q": 2 } }));

    requester.close().await;
    responder.close().await;
}
