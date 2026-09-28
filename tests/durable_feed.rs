//! §18.6 Feed Consumer, end to end against a live JetStream.
//!
//! What only a broker can prove: that the agent's one consumer on MESH_FEED
//! really is `mesh_feed_{agent_id}` with the pinned config, that later binds
//! (including two at once) add their feeds to its filter subjects rather than
//! making a second consumer, that `stop()` leaves the consumer in place, and
//! that publishes made while the follower was away arrive when it comes back.
//! The comeback runs on a fresh connection with the same seed, so the §22.2
//! memory is empty and the server's cursor is the only thing doing the work.
//!
//! Requires nats-server **with JetStream** at `AGENTMESH_NATS_URL` (default
//! nats://127.0.0.1:4222); skips gracefully otherwise. The platform creates
//! `MESH_FEED` on a real mesh; this test stands in for it and deletes it on
//! the way out. One test function on purpose: the stream is a shared name.

use std::time::Duration;

use agentmesh::{AgentMesh, ConnectOptions, FeedKind, KeyPair};
use serde_json::{json, Value};

async fn recv(rx: &mut tokio::sync::mpsc::UnboundedReceiver<Value>, what: &str) -> Value {
    tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .unwrap_or_else(|_| panic!("{what}: timed out"))
        .expect("channel open")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn durable_feed_binds_one_consumer_and_delivers_what_was_missed() {
    let url = std::env::var("AGENTMESH_NATS_URL").unwrap_or_else(|_| "nats://127.0.0.1:4222".into());
    let Ok(probe) = async_nats::connect(&url).await else {
        eprintln!("skipping durable feed: no NATS server at {url}");
        return;
    };
    let js = async_nats::jetstream::new(probe.clone());
    let _ = js.delete_stream("MESH_FEED").await;

    let connect = |seed: Option<String>| {
        let url = url.clone();
        async move {
            AgentMesh::connect(
                &url,
                ConnectOptions { allow_unnamed: true, agent_seed: seed, ..Default::default() },
            )
            .await
        }
    };
    let Ok(owner) = connect(None).await else {
        eprintln!("skipping durable feed: no NATS server at {url}");
        return;
    };
    let seed = KeyPair::new_user().seed().expect("seed");
    let follower = connect(Some(seed.clone())).await.expect("follower connects");
    let owner_id = owner.id().to_string();

    // ── A missing stream is a loud error, never a live fallback ──
    match follower.subscribe_feed_durable(&owner_id, "status", |_, _| {}).await {
        Ok(_) => panic!("subscribe_feed_durable must fail without the MESH_FEED stream"),
        Err(e) => {
            let msg = e.to_string();
            assert!(msg.contains("MESH_FEED"), "the error names the stream: {msg}");
            assert!(msg.contains("renew"), "the error says the credential may need renewing: {msg}");
        }
    }

    let created = js
        .create_stream(async_nats::jetstream::stream::Config {
            name: "MESH_FEED".to_string(),
            subjects: vec!["mesh.feed.>".to_string()],
            max_age: Duration::from_secs(24 * 60 * 60),
            duplicate_window: Duration::from_secs(120),
            ..Default::default()
        })
        .await;
    if created.is_err() {
        eprintln!("skipping durable feed: JetStream unavailable at {url}");
        owner.close().await;
        follower.close().await;
        return;
    }

    // ── The first bind creates the consumer to the §18.6 pins ──
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Value>();
    let tx_status = tx.clone();
    let status = follower
        .subscribe_feed_durable(&owner_id, "status", move |payload, _env| {
            let _ = tx_status.send(payload);
        })
        .await
        .expect("durable feed subscribe binds once the stream exists");
    let durable = format!("mesh_feed_{}", follower.id());
    let status_subject = format!("mesh.feed.{owner_id}.status");
    assert_eq!(status.durable(), durable);
    assert_eq!(status.subject(), status_subject);

    let stream = js.get_stream("MESH_FEED").await.expect("stream");
    let info = stream.consumer_info(&durable).await.expect("the consumer exists under its name");
    assert_eq!(info.config.filter_subjects, vec![status_subject.clone()]);
    assert_eq!(info.config.ack_policy, async_nats::jetstream::consumer::AckPolicy::Explicit);
    assert_eq!(info.config.deliver_policy, async_nats::jetstream::consumer::DeliverPolicy::New);
    assert_eq!(info.config.ack_wait, Duration::from_secs(30));
    assert_eq!(info.config.max_deliver, 5);

    // ── Two binds at once both land in the one consumer's filters ──
    let (tx_a, tx_b) = (tx.clone(), tx.clone());
    let (rounds, alerts) = tokio::join!(
        follower.subscribe_feed_durable(&owner_id, "rounds", move |p, _| {
            let _ = tx_a.send(p);
        }),
        follower.subscribe_feed_durable(&owner_id, "alerts", move |p, _| {
            let _ = tx_b.send(p);
        }),
    );
    let (rounds, alerts) = (rounds.expect("rounds binds"), alerts.expect("alerts binds"));
    let mut filters = stream.consumer_info(&durable).await.expect("info").config.filter_subjects;
    filters.sort();
    let mut expected = vec![
        status_subject.clone(),
        format!("mesh.feed.{owner_id}.rounds"),
        format!("mesh.feed.{owner_id}.alerts"),
    ];
    expected.sort();
    assert_eq!(filters, expected, "one consumer, every durably followed feed in its filters");

    // ── Delivery through the shared loop, to the matching handler ──
    owner.publish_feed("status", json!({ "n": 1 }), FeedKind::Stream).await.expect("publish 1");
    let got = recv(&mut rx, "status 1").await;
    assert_eq!(got["topic"], json!("status"));
    assert_eq!(got["data"]["n"], json!(1));
    owner.publish_feed("rounds", json!({ "r": 7 }), FeedKind::Stream).await.expect("publish round");
    let got = recv(&mut rx, "round").await;
    assert_eq!(got["topic"], json!("rounds"));

    // ── stop() ends delivery and keeps the consumer and its filters ──
    alerts.stop().await;
    rounds.stop().await;
    status.stop().await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let after = stream.consumer_info(&durable).await.expect("the consumer survives stop");
    assert_eq!(after.config.filter_subjects.len(), 3, "no filter is removed on stop");

    owner.publish_feed("status", json!({ "n": 2 }), FeedKind::Stream).await.expect("publish 2");
    owner.publish_feed("status", json!({ "n": 3 }), FeedKind::Stream).await.expect("publish 3");
    let silent = tokio::time::timeout(Duration::from_secs(1), rx.recv()).await;
    assert!(!matches!(silent, Ok(Some(_))), "a stopped subscription delivers nothing");
    follower.close().await;

    // ── Coming back: what was published while away arrives ──
    let back = connect(Some(seed)).await.expect("the same agent reconnects");
    let (tx2, mut rx2) = tokio::sync::mpsc::unbounded_channel::<Value>();
    let again = back
        .subscribe_feed_durable(&owner_id, "status", move |p, _| {
            let _ = tx2.send(p);
        })
        .await
        .expect("rebind the same consumer");
    assert_eq!(again.durable(), durable);
    assert_eq!(recv(&mut rx2, "missed 2").await["data"]["n"], json!(2));
    assert_eq!(recv(&mut rx2, "missed 3").await["data"]["n"], json!(3));
    let done = tokio::time::timeout(Duration::from_secs(1), rx2.recv()).await;
    assert!(done.is_err(), "only the missed publishes arrive; 1 stays acked");

    again.stop().await;
    back.close().await;
    owner.close().await;
    let _ = js.delete_stream("MESH_FEED").await;
}
