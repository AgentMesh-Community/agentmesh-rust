//! EXT-6 §7.1 guarded registration, against a live broker.
//!
//! The judgement itself — which replies count as an ok — is pure and unit-tested
//! in `src/client.rs`. What only a broker can prove is what these check: that a
//! refused guard leaves the agent listening on the subject everybody writes to,
//! that the withdrawal actually goes out on the wire, and that an accepted guard
//! moves the subscription to the private subject and nowhere else.
//!
//! Requires nats-server on 127.0.0.1:4222; skips gracefully otherwise (an early
//! return rather than `#[ignore]`, matching this crate's other broker-dependent
//! suites).

use std::time::Duration;

use agentmesh::{decode, encode, sign_envelope, AgentMesh, ConnectOptions, Envelope, KeyPair, PrimitiveType, RegisterOptions};
use futures::StreamExt;
use serde_json::json;

const URL: &str = "nats://127.0.0.1:4222";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_admission_service_means_unguarded_and_still_reachable() {
    // Nobody answers `mesh.admission.guard` here, so core NATS returns
    // no-responders immediately. That is a refusal, and the agent must stay on its
    // PUBLIC inbox — the failure this replaces had it unsubscribe from the only
    // inbox anybody writes to and then look perfectly healthy.
    let Ok(probe) = async_nats::connect(URL).await else {
        eprintln!("skipping guarded registration: no NATS server at {URL}");
        return;
    };
    let Ok(agent) = AgentMesh::connect(URL, ConnectOptions { allow_unnamed: true, ..Default::default() }).await else {
        eprintln!("skipping guarded registration: no NATS server at {URL}");
        return;
    };
    let agent_id = agent.id().to_string();

    // The withdrawal is published, not requested, so watch for it rather than
    // waiting on an answer.
    let mut unguard = probe
        .subscribe("mesh.admission.unguard")
        .await
        .expect("subscribe unguard");
    // Flushed, so the SUB is on the server before the agent publishes.
    probe.flush().await.expect("flush");

    agent.on_request("echo", |input| async move { Ok(json!({ "echoed": input })) });
    agent
        .register(RegisterOptions {
            name: "guard-refused".into(),
            guarded: true,
            ..Default::default()
        })
        .await
        .expect("a refused guard must not fail the registration");

    assert!(
        !agent.listening_on_guarded(),
        "a refusal leaves the agent on its public inbox"
    );

    // …and it says so, so the mesh can drop a stale entry from a previous run
    // instead of relaying this agent's mail to a subject nobody is listening on.
    let msg = tokio::time::timeout(Duration::from_secs(5), unguard.next())
        .await
        .expect("an unguard was published")
        .expect("message");
    let env = decode(&msg.payload).expect("the unguard is signed and verifies");
    assert_eq!(env.from, agent_id, "the service derives the inbox from this");
    assert_eq!(
        env.payload.as_ref().and_then(|p| p.as_object()).map(|o| o.len()),
        Some(0),
        "empty payload (§7.1): there is no way to unguard somebody else's inbox"
    );

    // The point of all of it: mail still arrives.
    let requester = AgentMesh::connect(URL, ConnectOptions { allow_unnamed: true, ..Default::default() })
        .await
        .expect("connect requester");
    tokio::time::sleep(Duration::from_millis(150)).await;
    let res = requester
        .request(&agent_id, "echo", json!({ "hi": 1 }))
        .await
        .expect("the public inbox is still being served");
    assert_eq!(res.payload["status"], json!("completed"));

    requester.close().await;
    agent.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_explicit_ok_moves_the_agent_to_the_private_subject() {
    // A stand-in admission service that agrees. It replies the way the real one
    // does — a signed `respond` bound to the request, `payload.output.ok = true` —
    // because anything less than that is refused by design.
    let Ok(service) = async_nats::connect(URL).await else {
        eprintln!("skipping guarded registration: no NATS server at {URL}");
        return;
    };
    let Ok(agent) = AgentMesh::connect(URL, ConnectOptions { allow_unnamed: true, ..Default::default() }).await else {
        eprintln!("skipping guarded registration: no NATS server at {URL}");
        return;
    };
    let agent_id = agent.id().to_string();

    let service_kp = KeyPair::new_user();
    let service_id = service_kp.public_key();
    let mut guard_reqs = service
        .subscribe("mesh.admission.guard")
        .await
        .expect("subscribe guard");
    // Flushed, so the stand-in service is reachable before the handshake starts —
    // otherwise the request races the SUB and gets no-responders, which the SDK
    // correctly reads as a refusal and the test would read as a bug.
    service.flush().await.expect("flush");
    let answering = {
        let service = service.clone();
        tokio::spawn(async move {
            if let Some(msg) = guard_reqs.next().await {
                let req = decode(&msg.payload).expect("the guard request is signed");
                let mut resp = Envelope::new(PrimitiveType::Respond, &service_id);
                resp.to = Some(req.from.clone());
                resp.in_reply_to = Some(req.id.clone());
                resp.payload = Some(json!({ "output": { "ok": true, "guarded": true } }));
                sign_envelope(&mut resp, &service_kp).expect("sign");
                if let Some(reply) = msg.reply {
                    let _ = service.publish(reply, encode(&resp).unwrap().into()).await;
                }
            }
        })
    };

    agent.on_request("echo", |input| async move { Ok(json!({ "echoed": input })) });
    agent
        .register(RegisterOptions {
            name: "guard-granted".into(),
            guarded: true,
            ..Default::default()
        })
        .await
        .expect("register");
    let _ = answering.await;

    assert!(
        agent.listening_on_guarded(),
        "an explicit ok is what moves the subscription to the private subject"
    );

    // The private subject is now where mail has to go — and the public inbox has
    // no subscriber at all, which on core NATS is an immediate no-responders
    // rather than a timeout. That asymmetry is exactly why believing a refused
    // guard is silent and total rather than merely unfiltered.
    let requester_kp = KeyPair::new_user();
    let mut req = Envelope::new(PrimitiveType::Request, requester_kp.public_key());
    req.to = Some(agent_id.clone());
    req.payload = Some(json!({ "offering": "echo", "input": { "hi": 2 } }));
    sign_envelope(&mut req, &requester_kp).expect("sign");
    // Raw reply channel rather than a one-shot request: §6.4a means the FIRST
    // reply on the guarded subject is the accept, and the substantive respond
    // follows it on the same reply subject, because on a GUARDED delivery the
    // requester of record is the admission relay, which forwards the reply
    // data to the true sender itself. The true sender's inbox is watched below
    // to prove nothing routed around the relay.
    let mut true_sender_inbox = service
        .subscribe(format!("mesh.agent.{}.inbox", requester_kp.public_key()))
        .await
        .expect("subscribe true sender inbox");
    let reply_inbox = service.new_inbox();
    let mut replies = service.subscribe(reply_inbox.clone()).await.expect("subscribe reply inbox");
    service
        .publish_with_reply(
            format!("mesh.agent.{agent_id}.inbox.guarded"),
            reply_inbox,
            encode(&req).unwrap().into(),
        )
        .await
        .expect("publish to the guarded subject");
    let first = tokio::time::timeout(Duration::from_secs(5), replies.next())
        .await
        .expect("the guarded subject answered")
        .expect("message");
    let accept = decode(&first.payload).expect("the accept verifies");
    assert_eq!(accept.from, agent_id);
    assert_eq!(
        accept.payload.as_ref().unwrap()["status"],
        json!("accepted"),
        "§6.4a: admission answers first, before the handler's output"
    );
    let second = tokio::time::timeout(Duration::from_secs(5), replies.next())
        .await
        .expect("the substantive respond followed")
        .expect("message");
    let answer = decode(&second.payload).expect("the answer verifies");
    assert_eq!(answer.from, agent_id);
    assert_eq!(answer.payload.as_ref().unwrap()["status"], json!("completed"));
    // Nothing bypassed the relay: the true sender's inbox stayed silent.
    let bypass = tokio::time::timeout(Duration::from_millis(750), true_sender_inbox.next()).await;
    assert!(
        bypass.is_err(),
        "a guarded delivery's answer goes back through the relay's reply subject, never \
         directly to the sender's inbox"
    );

    // Nothing is listening on the public inbox any more: core NATS says so
    // immediately, which is the whole risk of getting the guard handshake wrong.
    let mut public = Envelope::new(PrimitiveType::Request, requester_kp.public_key());
    public.to = Some(agent_id.clone());
    public.payload = Some(json!({ "offering": "echo", "input": { "hi": 3 } }));
    sign_envelope(&mut public, &requester_kp).expect("sign");
    let to_public = tokio::time::timeout(
        Duration::from_secs(5),
        service.request(
            format!("mesh.agent.{agent_id}.inbox"),
            encode(&public).unwrap().into(),
        ),
    )
    .await
    .expect("core NATS answers a subject with no subscriber immediately");
    assert!(
        to_public.is_err(),
        "a guarded agent is NOT listening on its public inbox"
    );

    agent.close().await;
}
