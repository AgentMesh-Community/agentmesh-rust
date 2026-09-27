//! The §9.6 presence surface: subscribe-before-snapshot, live.
//!
//! The MUST this file exercises: a consumer tracking liveness subscribes to
//! the presence transition stream BEFORE reading the snapshot, so a transition
//! firing inside the read window is delivered rather than lost. The stand-in
//! presence service below engineers exactly that window — it receives the
//! `get_presence` request, publishes an `online` transition, waits, and only
//! then answers with a deliberately stale `offline` snapshot. An
//! implementation that subscribed after the snapshot arrived would miss the
//! transition and end `offline`; the §9.6 ordering ends `online`.
//!
//! (The pure state-fold rules — the twice-seen transition absorbed, the stale
//! snapshot unable to roll back a live transition — are unit tests in
//! `src/presence.rs`.)
//!
//! Requires nats-server on 127.0.0.1:4222 (skips gracefully if absent).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::StreamExt;

use agentmesh::{
    codec, AgentMesh, Availability, ConnectOptions, Envelope, KeyPair, PrimitiveType,
};
use serde_json::json;

const URL: &str = "nats://127.0.0.1:4222";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_transition_inside_the_snapshot_window_is_not_lost() {
    let Ok(consumer) = AgentMesh::connect(URL, ConnectOptions { allow_unnamed: true, ..Default::default() }).await else {
        eprintln!("skipping presence surface: no NATS server at {URL}");
        return;
    };

    // The tracked node's identity: heartbeats are believed from its own
    // verified key, so the stand-in service heartbeats WITH that key.
    let node_kp = KeyPair::new_user();
    let node_id = node_kp.public_key();

    // A stand-in presence service. On `get_presence`: first the transition,
    // then a pause, then the STALE snapshot.
    let service = async_nats::connect(URL).await.expect("service connect");
    let service_kp = KeyPair::new_user();
    let service_id = service_kp.public_key();
    let mut gets = service.subscribe("mesh.presence.get").await.expect("subscribe presence.get");
    service.flush().await.expect("flush");
    let answering = tokio::spawn({
        let service = service.clone();
        let node_kp_seed = node_kp.seed().expect("node seed");
        let node_id = node_id.clone();
        async move {
            let Some(msg) = gets.next().await else { return };
            let req = codec::decode(&msg.payload).expect("get_presence request verifies");
            assert_eq!(req.payload.as_ref().unwrap()["node"], json!(node_id.clone()));

            // The transition, INSIDE the consumer's read window. Only a
            // subscription established before the get was sent can see it.
            let node_kp = KeyPair::from_seed(&node_kp_seed).unwrap();
            let mut hb = Envelope::new(PrimitiveType::Emit, &node_id);
            hb.payload = Some(json!({ "node": node_id.clone(), "availability": "online" }));
            agentmesh::sign_envelope(&mut hb, &node_kp).expect("sign heartbeat");
            service
                .publish(format!("mesh.heartbeat.{node_id}"), codec::encode(&hb).unwrap().into())
                .await
                .expect("publish transition");
            service.flush().await.expect("flush");
            tokio::time::sleep(Duration::from_millis(300)).await;

            // The snapshot the service computed BEFORE the transition: stale.
            let mut snap = Envelope::new(PrimitiveType::Respond, &service_id);
            snap.to = Some(req.from.clone());
            snap.in_reply_to = Some(req.id.clone());
            snap.payload = Some(json!({ "node": node_id, "status": "offline", "last_seen": 0 }));
            agentmesh::sign_envelope(&mut snap, &service_kp).expect("sign snapshot");
            if let Some(reply) = msg.reply {
                let _ = service.publish(reply, codec::encode(&snap).unwrap().into()).await;
            }
        }
    });

    let seen: Arc<Mutex<Vec<Availability>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = seen.clone();
    consumer
        .track_presence(&node_id, move |p| sink.lock().unwrap().push(p.status))
        .await
        .expect("track_presence");
    let _ = answering.await;
    // Let the (absorbed) snapshot and any straggling deliveries settle.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let seen = seen.lock().unwrap().clone();
    assert_eq!(
        seen,
        vec![Availability::Online],
        "the in-window transition was delivered (subscribe-before-snapshot) and the \
         stale offline snapshot could not roll it back; idempotent application \
         reported exactly one change"
    );

    consumer.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_presence_reads_the_snapshot_shape() {
    let Ok(consumer) = AgentMesh::connect(URL, ConnectOptions { allow_unnamed: true, ..Default::default() }).await else {
        eprintln!("skipping presence surface: no NATS server at {URL}");
        return;
    };
    let service = async_nats::connect(URL).await.expect("service connect");
    let service_kp = KeyPair::new_user();
    let service_id = service_kp.public_key();
    let mut gets = service.subscribe("mesh.presence.get").await.expect("subscribe");
    service.flush().await.expect("flush");
    let answering = tokio::spawn({
        let service = service.clone();
        async move {
            let Some(msg) = gets.next().await else { return };
            let req = codec::decode(&msg.payload).expect("request verifies");
            let mut resp = Envelope::new(PrimitiveType::Respond, &service_id);
            resp.to = Some(req.from.clone());
            resp.in_reply_to = Some(req.id.clone());
            resp.payload =
                Some(json!({ "node": "UNODE", "status": "busy", "last_seen": 1_753_000_000_000i64 }));
            agentmesh::sign_envelope(&mut resp, &service_kp).expect("sign");
            if let Some(reply) = msg.reply {
                let _ = service.publish(reply, codec::encode(&resp).unwrap().into()).await;
            }
        }
    });

    let p = consumer.get_presence("UNODE").await.expect("snapshot");
    assert_eq!(p.node, "UNODE");
    assert_eq!(p.status, Availability::Busy);
    assert_eq!(p.last_seen, Some(1_753_000_000_000));
    let _ = answering.await;

    consumer.close().await;
}
