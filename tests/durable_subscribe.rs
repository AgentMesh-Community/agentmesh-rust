//! §18.6 durable event subscriptions, end to end against a live JetStream.
//!
//! What only a broker can prove: that the consumer the SDK binds really is the
//! §18.6 one (named durable, filtered, explicit-ack), that `stop()` ends
//! delivery WITHOUT touching the durable, and that rebinding the same pattern
//! resumes the server-side cursor — only what was emitted in between arrives,
//! nothing already acked is replayed. The second bind runs on a fresh
//! connection with the same agent seed, so the §22.2 memory is empty and the
//! cursor is the only thing that can be doing the work.
//!
//! Requires nats-server on 127.0.0.1:4222 **with JetStream enabled**; skips
//! gracefully otherwise. The platform creates `MESH_EVENTS` on a real mesh;
//! this test stands in for it (Interest retention, 24h max_age, 2m duplicate
//! window) and deletes it on the way out. One test function on purpose: the
//! stream is a shared name, and two tests racing its creation and deletion
//! would fail each other.

use std::time::Duration;

use agentmesh::{AgentMesh, ConnectOptions, DurableSubscribeOptions, KeyPair};
use serde_json::json;

const URL: &str = "nats://127.0.0.1:4222";
const PATTERN: &str = "billing.invoice_ready";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn durable_delivery_stops_cleanly_and_the_rebind_resumes_the_cursor() {
    let Ok(probe) = async_nats::connect(URL).await else {
        eprintln!("skipping durable subscribe: no NATS server at {URL}");
        return;
    };
    let js = async_nats::jetstream::new(probe.clone());
    // A leftover stream from an aborted run would break the missing-stream
    // assertion below.
    let _ = js.delete_stream("MESH_EVENTS").await;

    let kp = KeyPair::new_user();
    let seed = kp.seed().expect("seed");
    let Ok(agent) = AgentMesh::connect(
        URL,
        ConnectOptions { allow_unnamed: true, agent_seed: Some(seed.clone()), ..Default::default() },
    )
    .await
    else {
        eprintln!("skipping durable subscribe: no NATS server at {URL}");
        return;
    };

    // ── A missing stream is a loud error, never a silent ephemeral fallback ──
    let missing = agent
        .subscribe_durable(PATTERN, |_data, _env| {}, DurableSubscribeOptions::default())
        .await;
    match missing {
        Ok(_) => panic!("subscribe_durable must fail without the MESH_EVENTS stream"),
        Err(e) => {
            let msg = e.to_string();
            assert!(msg.contains("MESH_EVENTS"), "the error names the stream: {msg}");
        }
    }

    // ── The platform's stream, stood in for by the test ──
    let created = js
        .create_stream(async_nats::jetstream::stream::Config {
            name: "MESH_EVENTS".to_string(),
            subjects: vec!["mesh.event.>".to_string()],
            retention: async_nats::jetstream::stream::RetentionPolicy::Interest,
            max_age: Duration::from_secs(24 * 60 * 60),
            duplicate_window: Duration::from_secs(120),
            ..Default::default()
        })
        .await;
    if created.is_err() {
        eprintln!("skipping durable subscribe: JetStream unavailable at {URL}");
        agent.close().await;
        return;
    }

    // ── Bind, and receive durably ──
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<serde_json::Value>();
    let sub = agent
        .subscribe_durable(
            PATTERN,
            move |data, env| {
                assert!(!env.from.is_empty(), "the envelope arrived verified");
                let _ = tx.send(data);
            },
            DurableSubscribeOptions::default(),
        )
        .await
        .expect("durable subscribe binds once the stream exists");
    // The §18.6 name, derived — the durable really exists on the server under it.
    let expected_durable = format!("mesh_event_{}_99397ba4a29eec30", agent.id());
    assert_eq!(sub.durable_name(), expected_durable);
    let stream = js.get_stream("MESH_EVENTS").await.expect("stream");
    stream
        .get_consumer::<async_nats::jetstream::consumer::pull::Config>(&expected_durable)
        .await
        .expect("the durable consumer exists server-side under the §18.6 name");

    agent.emit(PATTERN, json!({ "n": 1 })).await.expect("emit 1");
    agent.emit(PATTERN, json!({ "n": 2 })).await.expect("emit 2");
    let first = tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .expect("event 1 delivered durably")
        .expect("channel open");
    let second = tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .expect("event 2 delivered durably")
        .expect("channel open");
    assert_eq!(first["n"], json!(1));
    assert_eq!(second["n"], json!(2));

    // ── stop() ends delivery and nothing else ──
    sub.stop();
    tokio::time::sleep(Duration::from_millis(200)).await;
    agent.emit(PATTERN, json!({ "n": 3 })).await.expect("emit 3");
    agent.emit(PATTERN, json!({ "n": 4 })).await.expect("emit 4");
    // Stopping aborts the delivery loop, which drops the handler and closes
    // the channel — so "nothing delivered" is either a timeout or a clean
    // close; only an actual value is a failure.
    let silent = tokio::time::timeout(Duration::from_secs(1), rx.recv()).await;
    assert!(!matches!(silent, Ok(Some(_))), "a stopped subscription delivers nothing");

    // ── The rebind resumes the cursor: only what was missed arrives ──
    // A fresh connection with the same seed: same agent id, same durable name,
    // EMPTY §22.2 memory — so if 1 and 2 came back, nothing local would
    // suppress them, and the test would see them. They must not come back,
    // because the server remembers they were acked.
    let agent2 = AgentMesh::connect(
        URL,
        ConnectOptions { allow_unnamed: true, agent_seed: Some(seed), ..Default::default() },
    )
    .await
    .expect("reconnect as the same agent");
    let (tx2, mut rx2) = tokio::sync::mpsc::unbounded_channel::<serde_json::Value>();
    let sub2 = agent2
        .subscribe_durable(
            PATTERN,
            move |data, _env| {
                let _ = tx2.send(data);
            },
            DurableSubscribeOptions::default(),
        )
        .await
        .expect("rebind the same durable");
    assert_eq!(sub2.durable_name(), expected_durable, "same agent, same pattern, same durable");
    let third = tokio::time::timeout(Duration::from_secs(10), rx2.recv())
        .await
        .expect("the event emitted while stopped arrives on rebind")
        .expect("channel open");
    let fourth = tokio::time::timeout(Duration::from_secs(10), rx2.recv())
        .await
        .expect("both missed events arrive")
        .expect("channel open");
    assert_eq!(third["n"], json!(3), "resumed at the cursor, not replayed from the start");
    assert_eq!(fourth["n"], json!(4));
    let done = tokio::time::timeout(Duration::from_secs(1), rx2.recv()).await;
    assert!(done.is_err(), "only the missed events arrive — 1 and 2 stay acked");

    agent2.close().await;
    agent.close().await;
    let _ = js.delete_stream("MESH_EVENTS").await;
}
