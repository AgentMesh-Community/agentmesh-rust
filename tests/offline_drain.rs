//! §16.4 offline mailbox drain, end to end.
//!
//! What only a live broker can prove, and therefore what is here rather than in
//! `src/client.rs`'s unit tests: that the JetStream calls the drain makes are the
//! right ones against a real server, that a durable consumer bound a second time
//! resumes instead of replaying, and that a message the agent was not present for
//! actually reaches its handler with an answer sent back to a sender who has
//! since gone away.
//!
//! Requires nats-server on 127.0.0.1:4222 **with JetStream enabled**; skips
//! gracefully otherwise, in the same shape as the rest of this crate's
//! broker-dependent suites (an early return rather than `#[ignore]`, so a run
//! without a server is quiet rather than misleadingly green with skips).
//!
//! These tests stand in for the registry: on a real mesh the registry creates
//! `MESH_INBOX_{id}` at registration (§18.6) and nothing else does, so a test
//! that wants a mailbox has to make one. The probe side deliberately uses a raw
//! `async_nats` connection rather than a second `AgentMesh` — it is playing the
//! part of the infrastructure, not of an agent.

use std::time::Duration;

use agentmesh::{
    decode, encode, sign_envelope, AgentMesh, ConnectOptions, Envelope, KeyPair, PrimitiveType,
    RegisterOptions,
};
use futures::StreamExt;
use serde_json::json;

const URL: &str = "nats://127.0.0.1:4222";

/// A signed `request` from `sender_kp` to `to`, deliberately dated `age_ms` ago.
///
/// The age is the point of several of these: a buffered envelope is old by
/// construction, so one dated outside the live §22.3 window but inside the
/// mailbox's is the only thing that can tell the two windows apart.
fn aged_request(
    sender_kp: &KeyPair,
    to: &str,
    offering: &str,
    input: serde_json::Value,
    age_ms: i64,
) -> Envelope {
    let mut env = Envelope::new(PrimitiveType::Request, sender_kp.public_key());
    env.to = Some(to.to_string());
    env.payload = Some(json!({ "offering": offering, "input": input }));
    let then = chrono::Utc::now() - chrono::Duration::milliseconds(age_ms);
    env.ts = then.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    sign_envelope(&mut env, sender_kp).expect("sign");
    env
}

/// Create the per-agent mailbox the registry would have created (§18.6).
/// `None` means this server has no JetStream, which is also the SDK's cue to do
/// nothing at all.
async fn make_mailbox(
    client: &async_nats::Client,
    agent_id: &str,
) -> Option<async_nats::jetstream::Context> {
    make_mailbox_with(client, agent_id, &[]).await
}

/// The same mailbox, plus extra capture subjects.
///
/// The extra subjects exist for one test and stand in for a **reconnect gap**: a
/// window in which a message reaches the mailbox stream but not the agent's live
/// subscription. A real gap is a transport disconnect; a second capture subject
/// produces the identical situation for the drain, which sees stream sequences and
/// nothing else, and produces it deterministically instead of by timing a reconnect.
async fn make_mailbox_with(
    client: &async_nats::Client,
    agent_id: &str,
    extra_subjects: &[String],
) -> Option<async_nats::jetstream::Context> {
    let js = async_nats::jetstream::new(client.clone());
    let mut subjects = vec![format!("mesh.agent.{agent_id}.inbox")];
    subjects.extend_from_slice(extra_subjects);
    let cfg = async_nats::jetstream::stream::Config {
        name: format!("MESH_INBOX_{agent_id}"),
        subjects,
        max_age: Duration::from_secs(7 * 24 * 60 * 60),
        ..Default::default()
    };
    js.create_stream(cfg).await.ok()?;
    Some(js)
}

/// What this agent's mailbox consumer still owes: undelivered plus delivered-but-
/// unacked. Zero means the cursor is at the head of the stream — which is the fact
/// the re-drain exists to maintain, and the fact a single bounded pass destroys.
async fn mailbox_backlog(js: &async_nats::jetstream::Context, agent_id: &str) -> u64 {
    let stream = js
        .get_stream(format!("MESH_INBOX_{agent_id}"))
        .await
        .expect("the mailbox exists");
    let mut consumer: async_nats::jetstream::consumer::PullConsumer = stream
        .get_consumer(&format!("inbox_{agent_id}"))
        .await
        .expect("the drain bound its durable");
    let info = consumer.info().await.expect("consumer info");
    info.num_pending + info.num_ack_pending as u64
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_message_buffered_while_the_agent_was_away_reaches_its_handler() {
    let Ok(probe) = async_nats::connect(URL).await else {
        eprintln!("skipping offline drain: no NATS server at {URL}");
        return;
    };
    let Ok(agent) = AgentMesh::connect(URL, ConnectOptions { allow_unnamed: true, ..Default::default() }).await else {
        eprintln!("skipping offline drain: no NATS server at {URL}");
        return;
    };
    let agent_id = agent.id().to_string();
    let Some(js) = make_mailbox(&probe, &agent_id).await else {
        eprintln!("skipping offline drain: JetStream unavailable at {URL}");
        return;
    };

    // A sender that will be long gone by the time the agent registers: no live
    // reply subject exists for its request, which is the whole difficulty of
    // §16.4's receiving half.
    let sender_kp = KeyPair::new_user();
    let sender_id = sender_kp.public_key();

    // Watch the SENDER's inbox: that is where a drained message's answer goes,
    // because the `_INBOX.` subject the request was made on died with the
    // sender's process.
    let mut sender_inbox = probe
        .subscribe(format!("mesh.agent.{sender_id}.inbox"))
        .await
        .expect("subscribe sender inbox");

    // Two hours old: outside the live 10-minute window (§22.3) and well inside the
    // mailbox's 7 days. A drain that judged this on the live bound would refuse
    // it, and the only trace would be a local warning.
    let buffered =
        aged_request(&sender_kp, &agent_id, "echo", json!({ "n": 1 }), 2 * 60 * 60 * 1000);
    let buffered_id = buffered.id.clone();
    probe
        .publish(
            format!("mesh.agent.{agent_id}.inbox"),
            encode(&buffered).unwrap().into(),
        )
        .await
        .expect("publish into the mailbox");
    probe.flush().await.expect("flush");

    // Now the agent shows up. Registering binds the mailbox consumer and drains.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<serde_json::Value>(8);
    agent.on_request("echo", move |input| {
        let tx = tx.clone();
        async move {
            let _ = tx.send(input.clone()).await;
            Ok(json!({ "echoed": input }))
        }
    });
    agent
        .register(RegisterOptions { name: "drain-probe".into(), ..Default::default() })
        .await
        .expect("register");

    let handled = tokio::time::timeout(Duration::from_secs(15), rx.recv())
        .await
        .expect("the buffered message reached the handler")
        .expect("handler input");
    assert_eq!(handled["n"], json!(1), "the drained payload reached the handler intact");

    // The answer went to the sender's inbox, correlated by `in_reply_to`.
    let answer = tokio::time::timeout(Duration::from_secs(10), sender_inbox.next())
        .await
        .expect("an answer was published to the sender's inbox")
        .expect("message");
    let answer_env = decode(&answer.payload).expect("the answer verifies");
    assert_eq!(answer_env.from, agent_id, "answered by the agent that drained it");
    assert_eq!(
        answer_env.in_reply_to.as_deref(),
        Some(buffered_id.as_str()),
        "correlated to the buffered request, which is all the sender has to match on"
    );
    assert_eq!(answer_env.payload.as_ref().unwrap()["status"], json!("completed"));

    agent.close().await;
    let _ = js.delete_stream(format!("MESH_INBOX_{agent_id}")).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_register_resumes_the_durable_rather_than_replaying_it() {
    let Ok(probe) = async_nats::connect(URL).await else {
        eprintln!("skipping offline drain: no NATS server at {URL}");
        return;
    };
    let Ok(agent) = AgentMesh::connect(URL, ConnectOptions { allow_unnamed: true, ..Default::default() }).await else {
        eprintln!("skipping offline drain: no NATS server at {URL}");
        return;
    };
    let agent_id = agent.id().to_string();
    let Some(js) = make_mailbox(&probe, &agent_id).await else {
        eprintln!("skipping offline drain: JetStream unavailable at {URL}");
        return;
    };

    let sender_kp = KeyPair::new_user();
    let buffered = aged_request(&sender_kp, &agent_id, "echo", json!({ "n": 7 }), 60 * 60 * 1000);
    probe
        .publish(
            format!("mesh.agent.{agent_id}.inbox"),
            encode(&buffered).unwrap().into(),
        )
        .await
        .expect("publish into the mailbox");
    probe.flush().await.expect("flush");

    let (tx, mut rx) = tokio::sync::mpsc::channel::<serde_json::Value>(8);
    agent.on_request("echo", move |input| {
        let tx = tx.clone();
        async move {
            let _ = tx.send(input).await;
            Ok(json!({ "ok": true }))
        }
    });
    agent
        .register(RegisterOptions { name: "drain-once".into(), ..Default::default() })
        .await
        .expect("register");
    tokio::time::timeout(Duration::from_secs(15), rx.recv())
        .await
        .expect("drained once")
        .expect("handler input");

    // A second registration must not deliver it again. Two guards are at work and
    // both matter: the durable consumer's server-side cursor (a differently-named
    // durable would replay everything), and the §22.2 memory the drain shares with
    // the live inbox (a redelivery inside one process is still a duplicate).
    agent
        .register(RegisterOptions { name: "drain-once".into(), ..Default::default() })
        .await
        .expect("re-register");
    let again = tokio::time::timeout(Duration::from_secs(3), rx.recv()).await;
    assert!(again.is_err(), "the same buffered message must not be handled twice");

    agent.close().await;
    let _ = js.delete_stream(format!("MESH_INBOX_{agent_id}")).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_message_that_arrives_after_the_bind_belongs_to_the_live_subscription() {
    // The drain is bounded to the backlog present when it bound, which makes
    // the live subscription the only path a post-bind message can take. Both
    // paths now answer the same destination, the sender's inbox (§6.4a), so
    // the old reply-destination race cannot recur; what an unbounded drain
    // would do TODAY is dispatch the live message a second time and, §22.2
    // dedup willing, answer it twice. So the pins are: the live request
    // resolves, the handler runs once for it, and exactly one substantive
    // answer reaches the requester's inbox.
    let Ok(probe) = async_nats::connect(URL).await else {
        eprintln!("skipping offline drain: no NATS server at {URL}");
        return;
    };
    let Ok(agent) = AgentMesh::connect(URL, ConnectOptions { allow_unnamed: true, ..Default::default() }).await else {
        eprintln!("skipping offline drain: no NATS server at {URL}");
        return;
    };
    let agent_id = agent.id().to_string();
    let Some(js) = make_mailbox(&probe, &agent_id).await else {
        eprintln!("skipping offline drain: JetStream unavailable at {URL}");
        return;
    };

    // Give the drain real work, so it genuinely binds, dispatches and stops
    // rather than finding an empty mailbox and never running at all.
    let away_kp = KeyPair::new_user();
    let buffered = aged_request(&away_kp, &agent_id, "echo", json!({ "n": 1 }), 60 * 60 * 1000);
    probe
        .publish(
            format!("mesh.agent.{agent_id}.inbox"),
            encode(&buffered).unwrap().into(),
        )
        .await
        .expect("publish into the mailbox");
    probe.flush().await.expect("flush");

    let (tx, mut rx) = tokio::sync::mpsc::channel::<serde_json::Value>(8);
    agent.on_request("echo", move |input| {
        let tx = tx.clone();
        async move {
            let _ = tx.send(input.clone()).await;
            Ok(json!({ "echoed": input }))
        }
    });
    agent
        .register(RegisterOptions { name: "bounded-drain".into(), ..Default::default() })
        .await
        .expect("register");
    tokio::time::timeout(Duration::from_secs(15), rx.recv())
        .await
        .expect("the buffered message drained")
        .expect("handler input");

    // Now a LIVE requester, whose request lands on the very subject the mailbox
    // captures. Its answer arrives at its own inbox (§6.4a), once.
    let requester = AgentMesh::connect(URL, ConnectOptions { allow_unnamed: true, ..Default::default() })
        .await
        .expect("connect requester");
    let requester_id = requester.id().to_string();
    // A raw observer on the same inbox subject the requester resolves from,
    // counting substantive answers: a second one is the signature of the drain
    // having dispatched live traffic too.
    let mut requester_inbox = probe
        .subscribe(format!("mesh.agent.{requester_id}.inbox"))
        .await
        .expect("subscribe requester inbox");
    probe.flush().await.expect("flush");

    let res = requester
        .request(&agent_id, "echo", json!({ "n": 2 }))
        .await
        .expect("the live request resolves via the requester's own inbox");
    assert_eq!(res.payload["status"], json!("completed"));
    // The handler ran once for the live message, not once per path.
    tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("the live path ran the handler")
        .expect("handler input");
    let again = tokio::time::timeout(Duration::from_millis(750), rx.recv()).await;
    assert!(again.is_err(), "the drain must not dispatch a post-bind (live) message");
    // Exactly one substantive answer reached the inbox (the §6.4a accept also
    // travels this subject and is not counted).
    let mut substantive = 0;
    while let Ok(Some(msg)) =
        tokio::time::timeout(Duration::from_millis(750), requester_inbox.next()).await
    {
        let env = decode(&msg.payload).expect("inbox message verifies");
        if env.payload.as_ref().and_then(|p| p.get("status")) == Some(&json!("completed")) {
            substantive += 1;
        }
    }
    assert_eq!(
        substantive, 1,
        "one answer, from one path, a second one means the drain answered live traffic too"
    );

    requester.close().await;
    agent.close().await;
    let _ = js.delete_stream(format!("MESH_INBOX_{agent_id}")).await;
}

/// The re-drain cadence these tests run at. The floor rather than the 60s default,
/// which is sized against §22.2's memory rather than a test's patience.
const FAST_REDRAIN: Duration = Duration::from_secs(1);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_re_drain_acks_the_tail_instead_of_dispatching_it_again() {
    // What a bound alone left behind. The pass stops at the stream's last sequence,
    // so every live message the mailbox captures afterwards sits on the durable
    // consumer undelivered and unacked — the cursor stops where the pass left it and
    // the tail grows for the life of the process. The next restart then binds, sees
    // the whole tail as backlog and dispatches it, with a fresh process's §22.2
    // memory unable to suppress any of it. So the tail has to be cleared while the
    // memory still holds it, which is an ACK without a dispatch.
    let Ok(probe) = async_nats::connect(URL).await else {
        eprintln!("skipping offline drain: no NATS server at {URL}");
        return;
    };
    let Ok(agent) = AgentMesh::connect(
        URL,
        ConnectOptions { allow_unnamed: true, mailbox_drain_interval: Some(FAST_REDRAIN), ..Default::default() },
    )
    .await
    else {
        eprintln!("skipping offline drain: no NATS server at {URL}");
        return;
    };
    let agent_id = agent.id().to_string();
    let Some(js) = make_mailbox(&probe, &agent_id).await else {
        eprintln!("skipping offline drain: JetStream unavailable at {URL}");
        return;
    };

    let (tx, mut rx) = tokio::sync::mpsc::channel::<serde_json::Value>(8);
    agent.on_request("echo", move |input| {
        let tx = tx.clone();
        async move {
            let _ = tx.send(input.clone()).await;
            Ok(json!({ "echoed": input }))
        }
    });
    agent
        .register(RegisterOptions { name: "tail-clearer".into(), ..Default::default() })
        .await
        .expect("register");
    tokio::time::sleep(Duration::from_millis(300)).await;

    // A LIVE request, answered at the requester's own inbox by the live
    // subscription (§6.4a), and captured by the mailbox on the way, because the
    // stream is on that same subject.
    let requester = AgentMesh::connect(URL, ConnectOptions { allow_unnamed: true, ..Default::default() })
        .await
        .expect("connect requester");
    let requester_id = requester.id().to_string();
    // A raw observer on the answer destination. Exactly one substantive answer
    // may ever arrive here: a second is one the re-drain dispatched again.
    let mut requester_inbox = probe
        .subscribe(format!("mesh.agent.{requester_id}.inbox"))
        .await
        .expect("subscribe requester inbox");
    probe.flush().await.expect("flush");

    let res = requester
        .request(&agent_id, "echo", json!({ "n": 1 }))
        .await
        .expect("live request answered");
    assert_eq!(res.payload["status"], json!("completed"));
    tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("the live path ran the handler")
        .expect("handler input");
    // Drain the accept + the one legitimate answer off the observer now, so
    // everything it sees after the re-drain window is stray by construction.
    let mut substantive = 0;
    while let Ok(Some(msg)) =
        tokio::time::timeout(Duration::from_millis(500), requester_inbox.next()).await
    {
        let env = decode(&msg.payload).expect("inbox message verifies");
        if env.payload.as_ref().and_then(|p| p.get("status")) == Some(&json!("completed")) {
            substantive += 1;
        }
    }
    assert_eq!(substantive, 1, "the live path answered once");

    // Let at least one re-drain pass happen.
    tokio::time::sleep(FAST_REDRAIN * 3).await;

    // Handled once, by the live path: §22.2 caught the mailbox's copy.
    let again = tokio::time::timeout(Duration::from_millis(250), rx.recv()).await;
    assert!(again.is_err(), "the re-drain must not run the handler a second time");
    // And no second answer reached the requester's inbox: same destination for
    // both paths now, so a duplicate would land exactly here.
    let stray = tokio::time::timeout(Duration::from_millis(250), requester_inbox.next()).await;
    assert!(
        stray.is_err(),
        "the re-drain must not answer a message the live path already answered"
    );
    // The point of the whole exercise: the cursor is at the head, so a restart has
    // nothing to replay.
    assert_eq!(
        mailbox_backlog(&js, &agent_id).await,
        0,
        "the tail was acked, so nothing is left for the next restart to re-dispatch"
    );

    requester.close().await;
    agent.close().await;
    let _ = js.delete_stream(format!("MESH_INBOX_{agent_id}")).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_re_drain_recovers_what_the_live_subscription_missed() {
    // The reconnect-gap case, and the reason the bound alone was not enough even
    // ignoring the replay: a message that reaches the mailbox while the live
    // subscription is not receiving is above the last pass's bound, so a single
    // bounded pass leaves it there until the process restarts.
    //
    // The gap is produced with a second capture subject rather than by timing a real
    // disconnect — see `make_mailbox_with`. The drain sees stream sequences and
    // nothing else, so the two are the same situation to it.
    let Ok(probe) = async_nats::connect(URL).await else {
        eprintln!("skipping offline drain: no NATS server at {URL}");
        return;
    };
    let Ok(agent) = AgentMesh::connect(
        URL,
        ConnectOptions { allow_unnamed: true, mailbox_drain_interval: Some(FAST_REDRAIN), ..Default::default() },
    )
    .await
    else {
        eprintln!("skipping offline drain: no NATS server at {URL}");
        return;
    };
    let agent_id = agent.id().to_string();
    let gap_subject = format!("test.gap.{agent_id}");
    let Some(js) = make_mailbox_with(&probe, &agent_id, std::slice::from_ref(&gap_subject)).await
    else {
        eprintln!("skipping offline drain: JetStream unavailable at {URL}");
        return;
    };

    let (tx, mut rx) = tokio::sync::mpsc::channel::<serde_json::Value>(8);
    agent.on_request("echo", move |input| {
        let tx = tx.clone();
        async move {
            let _ = tx.send(input.clone()).await;
            Ok(json!({ "echoed": input }))
        }
    });
    agent
        .register(RegisterOptions { name: "gap-recoverer".into(), ..Default::default() })
        .await
        .expect("register");
    tokio::time::sleep(Duration::from_millis(300)).await;

    // The message nothing dispatched: in the mailbox, above the first pass's bound,
    // and absent from the §22.2 memory because no path has ever seen it.
    let sender_kp = KeyPair::new_user();
    let sender_id = sender_kp.public_key();
    let mut sender_inbox = probe
        .subscribe(format!("mesh.agent.{sender_id}.inbox"))
        .await
        .expect("subscribe sender inbox");
    probe.flush().await.expect("flush");
    let missed = aged_request(&sender_kp, &agent_id, "echo", json!({ "n": 42 }), 60 * 1000);
    let missed_id = missed.id.clone();
    probe
        .publish(gap_subject, encode(&missed).unwrap().into())
        .await
        .expect("publish into the mailbox only");
    probe.flush().await.expect("flush");

    // The next pass takes a FRESH bound, which now includes it.
    let handled = tokio::time::timeout(FAST_REDRAIN * 6, rx.recv())
        .await
        .expect("the re-drain recovered the missed message")
        .expect("handler input");
    assert_eq!(handled["n"], json!(42));

    // Answered at the sender's inbox, which is where §16.4 puts the answer to a
    // message whose live reply subject is gone.
    let answer = tokio::time::timeout(Duration::from_secs(10), sender_inbox.next())
        .await
        .expect("an answer reached the sender's inbox")
        .expect("message");
    let answer_env = decode(&answer.payload).expect("the answer verifies");
    assert_eq!(answer_env.in_reply_to.as_deref(), Some(missed_id.as_str()));

    // …once. A later pass finds it acked and in the §22.2 memory.
    tokio::time::sleep(FAST_REDRAIN * 3).await;
    let again = tokio::time::timeout(Duration::from_millis(250), rx.recv()).await;
    assert!(again.is_err(), "recovered once, not once per pass");
    assert_eq!(mailbox_backlog(&js, &agent_id).await, 0, "and the cursor is at the head");

    agent.close().await;
    let _ = js.delete_stream(format!("MESH_INBOX_{agent_id}")).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_mailbox_is_a_silent_no_op_and_live_traffic_still_works() {
    // The common case, and the one a drain must never break: sandbox agents get
    // no mailbox, older deployments have none, and a guest credential often cannot
    // reach the JetStream API at all. None of that is an error, and none of it may
    // cost the agent its live inbox. No mailbox is created here on purpose.
    let Ok(responder) = AgentMesh::connect(URL, ConnectOptions { allow_unnamed: true, ..Default::default() }).await else {
        eprintln!("skipping offline drain: no NATS server at {URL}");
        return;
    };
    let responder_id = responder.id().to_string();
    responder.on_request("echo", |input| async move { Ok(json!({ "echoed": input })) });
    responder
        .register(RegisterOptions { name: "no-mailbox".into(), ..Default::default() })
        .await
        .expect("register succeeds with no mailbox present");

    let requester = AgentMesh::connect(URL, ConnectOptions { allow_unnamed: true, ..Default::default() })
        .await
        .expect("connect requester");
    tokio::time::sleep(Duration::from_millis(150)).await;
    let res = requester
        .request(&responder_id, "echo", json!({ "hi": 1 }))
        .await
        .expect("live request still served");
    assert_eq!(res.payload["status"], json!("completed"));

    requester.close().await;
    responder.close().await;
}
