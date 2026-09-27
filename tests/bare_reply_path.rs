//! §6.4a reply path, end to end: a respond to a request is published to the
//! REQUESTER's inbox, correlated by `in_reply_to`, and never as data on the
//! transport reply subject, which stays liveness-only. The reply-subject
//! exceptions are exactly two: the registry reaper's `__registry_probe__`
//! (pinned here) and the EXT-6 guarded relay (pinned in
//! `guarded_registration.rs`).
//!
//! Requires nats-server on 127.0.0.1:4222; skips gracefully otherwise, in the
//! same shape as the rest of this crate's broker-dependent suites.

use std::time::Duration;

use agentmesh::{
    codec, decode, encode, sign_envelope, AgentMesh, ConnectOptions, Envelope, KeyPair,
    PrimitiveType, RegisterOptions,
};
use futures::StreamExt;
use serde_json::json;

const URL: &str = "nats://127.0.0.1:4222";

/// A signed bare request from `kp` to `to`.
fn bare_request(kp: &KeyPair, to: &str, offering: &str, input: serde_json::Value) -> Envelope {
    let mut env = Envelope::new(PrimitiveType::Request, kp.public_key());
    env.to = Some(to.to_string());
    env.payload = Some(json!({ "offering": offering, "input": input }));
    sign_envelope(&mut env, kp).expect("sign");
    env
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bare_round_trip_resolves_via_the_requesters_inbox() {
    // The public-API path: the requester never registers, yet its request
    // resolves — because `request` listens on its own inbox and the responder
    // answers there. A raw observer proves the answer really travelled the
    // inbox subject and not merely "somewhere that worked".
    let Ok(responder) = AgentMesh::connect(URL, ConnectOptions { allow_unnamed: true, ..Default::default() }).await else {
        eprintln!("skipping bare reply path: no NATS server at {URL}");
        return;
    };
    let requester = AgentMesh::connect(URL, ConnectOptions { allow_unnamed: true, ..Default::default() })
        .await
        .expect("connect requester");
    let probe = async_nats::connect(URL).await.expect("probe connect");

    responder.on_request("echo", |input| async move { Ok(json!({ "echoed": input })) });
    responder
        .register(RegisterOptions { name: "inbox-answerer".into(), ..Default::default() })
        .await
        .expect("register");
    tokio::time::sleep(Duration::from_millis(150)).await;

    let requester_id = requester.id().to_string();
    let mut requester_inbox = probe
        .subscribe(format!("mesh.agent.{requester_id}.inbox"))
        .await
        .expect("subscribe requester inbox");
    probe.flush().await.expect("flush");

    let res = requester
        .request(responder.id(), "echo", json!({ "n": 7 }))
        .await
        .expect("bare request resolves");
    assert_eq!(res.payload["status"], json!("completed"));
    assert_eq!(res.payload["output"]["echoed"]["n"], json!(7));
    assert!(res.accepted, "the §6.4a accept also travelled the inbox");

    // The observer saw the answer on the inbox subject: the accept first, the
    // substantive respond after, both correlated to the same request.
    let mut statuses = Vec::new();
    let mut request_ids = std::collections::HashSet::new();
    while let Ok(Some(msg)) =
        tokio::time::timeout(Duration::from_millis(750), requester_inbox.next()).await
    {
        let env = decode(&msg.payload).expect("inbox message verifies");
        if let Some(irt) = env.in_reply_to.clone() {
            request_ids.insert(irt);
        }
        if let Some(status) = env.payload.as_ref().and_then(|p| p.get("status")).cloned() {
            statuses.push(status);
        }
    }
    assert_eq!(statuses, vec![json!("accepted"), json!("completed")]);
    assert_eq!(request_ids.len(), 1, "both correlated to the one request id");

    requester.close().await;
    responder.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_response_data_travels_the_transport_reply_subject() {
    // A raw prober plays the requester so the reply subject is observable:
    // publish a signed bare request with a reply subject, and everything the
    // responder says — the accept and the answer — arrives at the prober's
    // INBOX, while the reply subject stays silent.
    let Ok(responder) = AgentMesh::connect(URL, ConnectOptions { allow_unnamed: true, ..Default::default() }).await else {
        eprintln!("skipping bare reply path: no NATS server at {URL}");
        return;
    };
    responder.on_request("echo", |input| async move { Ok(json!({ "echoed": input })) });
    responder
        .register(RegisterOptions { name: "reply-silent".into(), ..Default::default() })
        .await
        .expect("register");
    tokio::time::sleep(Duration::from_millis(150)).await;

    let probe = async_nats::connect(URL).await.expect("probe connect");
    let kp = KeyPair::new_user();
    let sender_id = kp.public_key();
    let mut sender_inbox = probe
        .subscribe(format!("mesh.agent.{sender_id}.inbox"))
        .await
        .expect("subscribe sender inbox");
    let reply_subject = probe.new_inbox();
    let mut reply_sub = probe.subscribe(reply_subject.clone()).await.expect("subscribe reply");
    probe.flush().await.expect("flush");

    let req = bare_request(&kp, responder.id(), "echo", json!({ "n": 1 }));
    let req_id = req.id.clone();
    probe
        .publish_with_reply(
            format!("mesh.agent.{}.inbox", responder.id()),
            reply_subject,
            encode(&req).unwrap().into(),
        )
        .await
        .expect("publish");
    probe.flush().await.expect("flush");

    // The inbox carries the whole exchange: accept, then the answer.
    let mut statuses = Vec::new();
    while let Ok(Some(msg)) =
        tokio::time::timeout(Duration::from_secs(5), sender_inbox.next()).await
    {
        let env = decode(&msg.payload).expect("inbox message verifies");
        assert_eq!(env.in_reply_to.as_deref(), Some(req_id.as_str()));
        let status = env.payload.as_ref().and_then(|p| p.get("status")).cloned();
        statuses.push(status.unwrap_or(json!(null)));
        if statuses.last() == Some(&json!("completed")) {
            break;
        }
    }
    assert_eq!(statuses, vec![json!("accepted"), json!("completed")]);

    // …and the reply subject carried no data at all.
    let silence = tokio::time::timeout(Duration::from_millis(750), reply_sub.next()).await;
    assert!(
        silence.is_err(),
        "the transport reply subject is liveness-only: no accept, no answer, nothing"
    );

    responder.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_attended_agents_queued_ack_rides_the_transport_reply_subject() {
    // The §6.4a carve-out beside the probe and the guarded relay: an agent
    // registered `interactive` whose handler answers the queued ack is the
    // NODE speaking about delivery, and that signal rides the transport reply
    // channel (§18.7) — the caller's live wait is what it exists to release.
    // The sender's inbox stays silent until a live session really replies.
    let Ok(responder) = AgentMesh::connect(URL, ConnectOptions { allow_unnamed: true, ..Default::default() }).await else {
        eprintln!("skipping bare reply path: no NATS server at {URL}");
        return;
    };
    responder.on_request("chat", |_input| async move {
        Ok(json!({ "queued": true, "inbox_id": "held-c13", "text": "a live session replies later" }))
    });
    responder
        .register(RegisterOptions {
            name: "attended-node".into(),
            interaction: Some("interactive".into()),
            ..Default::default()
        })
        .await
        .expect("register");
    tokio::time::sleep(Duration::from_millis(150)).await;

    let probe = async_nats::connect(URL).await.expect("probe connect");
    let kp = KeyPair::new_user();
    let sender_id = kp.public_key();
    let mut sender_inbox = probe
        .subscribe(format!("mesh.agent.{sender_id}.inbox"))
        .await
        .expect("subscribe sender inbox");
    let reply_subject = probe.new_inbox();
    let mut reply_sub = probe.subscribe(reply_subject.clone()).await.expect("subscribe reply");
    probe.flush().await.expect("flush");

    let req = bare_request(&kp, responder.id(), "chat", json!({ "text": "hi" }));
    probe
        .publish_with_reply(
            format!("mesh.agent.{}.inbox", responder.id()),
            reply_subject,
            encode(&req).unwrap().into(),
        )
        .await
        .expect("publish");
    probe.flush().await.expect("flush");

    // The queued ack arrives on the reply subject, alone — an interactive
    // agent emits no accept, and the ack carries nothing of the answer.
    let msg = tokio::time::timeout(Duration::from_secs(5), reply_sub.next())
        .await
        .expect("the queued ack arrives on the reply subject within 5s")
        .expect("reply subscription open");
    let ack = decode(&msg.payload).expect("the ack verifies");
    assert_eq!(ack.in_reply_to.as_deref(), Some(req.id.as_str()));
    let out = &ack.payload.as_ref().expect("payload")["output"];
    assert_eq!(out["queued"], json!(true));
    assert_eq!(out["inbox_id"], json!("held-c13"));

    // Nothing at the sender's inbox: the ack is a delivery-status signal,
    // not the answer, and no substantive respond exists yet.
    let silence = tokio::time::timeout(Duration::from_millis(750), sender_inbox.next()).await;
    assert!(silence.is_err(), "the sender's inbox stays silent until a session replies");

    responder.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_streaming_opening_travels_the_requesters_inbox() {
    // §11.3 step 2: the signed `working` opening is a respond like any other,
    // so it arrives at the requester's inbox; only the chunks that follow are
    // subject-addressed on the task's stream subject. The chunk subscription
    // is bound before the request goes out, so nothing races the inbox hop.
    let Ok(responder) = AgentMesh::connect(URL, ConnectOptions { allow_unnamed: true, ..Default::default() }).await else {
        eprintln!("skipping bare reply path: no NATS server at {URL}");
        return;
    };
    responder.on_stream_request("count", |_input, writer| async move {
        writer.write(json!({ "n": 1 }), None).await?;
        writer.end(Some(json!({ "n": 2 }))).await?;
        Ok(())
    });
    responder
        .register(RegisterOptions { name: "stream-opener".into(), ..Default::default() })
        .await
        .expect("register");
    tokio::time::sleep(Duration::from_millis(150)).await;

    let requester = AgentMesh::connect(URL, ConnectOptions { allow_unnamed: true, ..Default::default() })
        .await
        .expect("connect requester");
    let probe = async_nats::connect(URL).await.expect("probe connect");
    let mut requester_inbox = probe
        .subscribe(format!("mesh.agent.{}.inbox", requester.id()))
        .await
        .expect("subscribe requester inbox");
    probe.flush().await.expect("flush");

    let mut res = requester
        .request_stream(responder.id(), "count", json!({ "go": true }), false)
        .await
        .expect("the stream opens via the requester's inbox");
    assert_eq!(res.initial.payload.as_ref().unwrap()["status"], json!("working"));

    // The chunk contract is unchanged: ordered chunks, signed final.
    let first = res.chunks.recv().await.expect("chunk 1").expect("ok");
    assert!(!first.is_final);
    assert_eq!(first.data["n"], json!(1));
    let last = res.chunks.recv().await.expect("final chunk").expect("ok");
    assert!(last.is_final);

    // The observer saw the §6.4a accept and then the opening on the inbox
    // subject, both as verified envelopes.
    let mut statuses = Vec::new();
    while let Ok(Some(msg)) =
        tokio::time::timeout(Duration::from_millis(750), requester_inbox.next()).await
    {
        let env = decode(&msg.payload).expect("inbox message verifies");
        if let Some(status) = env.payload.as_ref().and_then(|p| p.get("status")).cloned() {
            statuses.push(status);
        }
    }
    assert_eq!(statuses, vec![json!("accepted"), json!("working")]);

    requester.close().await;
    responder.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_registry_probe_still_answers_on_the_reply_subject() {
    // The exception: `__registry_probe__` is the reaper's liveness check, and
    // its answer stays on the transport reply subject — no inbox round trip.
    let Ok(responder) = AgentMesh::connect(URL, ConnectOptions { allow_unnamed: true, ..Default::default() }).await else {
        eprintln!("skipping bare reply path: no NATS server at {URL}");
        return;
    };
    responder.on_request("__registry_probe__", |_input| async move { Ok(json!({ "alive": true })) });
    responder
        .register(RegisterOptions { name: "probe-answerer".into(), ..Default::default() })
        .await
        .expect("register");
    tokio::time::sleep(Duration::from_millis(150)).await;

    let probe = async_nats::connect(URL).await.expect("probe connect");
    let kp = KeyPair::new_user();
    let sender_id = kp.public_key();
    let mut sender_inbox = probe
        .subscribe(format!("mesh.agent.{sender_id}.inbox"))
        .await
        .expect("subscribe sender inbox");
    let reply_subject = probe.new_inbox();
    let mut reply_sub = probe.subscribe(reply_subject.clone()).await.expect("subscribe reply");
    probe.flush().await.expect("flush");

    let req = bare_request(&kp, responder.id(), "__registry_probe__", serde_json::Value::Null);
    probe
        .publish_with_reply(
            format!("mesh.agent.{}.inbox", responder.id()),
            reply_subject,
            encode(&req).unwrap().into(),
        )
        .await
        .expect("publish");
    probe.flush().await.expect("flush");

    // Read the reply subject until the substantive answer (the §6.4a accept
    // precedes it on the same subject, as it always did for the probe).
    let mut alive = false;
    while let Ok(Some(msg)) = tokio::time::timeout(Duration::from_secs(5), reply_sub.next()).await
    {
        let env = codec::decode(&msg.payload).expect("probe reply verifies");
        let payload = env.payload.unwrap_or(json!(null));
        if payload.get("status") == Some(&json!("completed")) {
            assert_eq!(payload["output"]["alive"], json!(true));
            alive = true;
            break;
        }
    }
    assert!(alive, "the probe was answered on the reply subject");

    // Nothing for the probe went to the prober's inbox.
    let stray = tokio::time::timeout(Duration::from_millis(750), sender_inbox.next()).await;
    assert!(stray.is_err(), "a probe answer takes no inbox round trip");

    responder.close().await;
}
