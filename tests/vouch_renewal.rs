//! Vouch renewal (§4.4), mirroring `sdk-typescript`'s
//! `__tests__/unit/vouch-renewal.test.ts` where the language boundary allows.
//!
//! An agent is on the mesh because a node vouched for it, and the vouch
//! expires. The registry treats that expiry as real at BOTH ends of the
//! lifecycle: it refuses an expired attestation at register (§9.7) and its
//! reaper reclaims a registration whose attestation has lapsed. Nothing used
//! to re-mint it in this crate, so a Rust process that registered once and
//! stayed up silently dropped out of discovery when its vouch (30 days
//! declared, 72h ephemeral) lapsed. These tests pin the fix: the vouch is
//! renewed well before it expires, in both the standalone and node-hosted
//! shapes; the loop is torn down with the agent; and a failed renewal is
//! visible and retried instead of lost.
//!
//! The TS suite drives a fake clock over a duck-typed connection; this crate
//! has no transport seam, so the live-loop tests run against a real
//! nats-server on 127.0.0.1:4222 (skipping gracefully if absent) with
//! millisecond TTLs — everything downstream is derived from the TTL, so a
//! 1.2-second vouch exercises exactly the same arithmetic as a 30-day one.
//! The registry is not required: `register` publishes fire-and-forget, and an
//! observer subscription on `mesh.registry.register` sees exactly what a
//! registry would.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use agentmesh::{
    codec, now_ms, verify_attestation, verify_manifest_signature, AgentMesh, ConnectOptions,
    Manifest, MeshNode, NodeConnectOptions, RegisterOptions, SecurityWarning,
};
use futures::StreamExt;

const URL: &str = "nats://127.0.0.1:4222";

/// A short vouch: renewal due at 800ms, expiry at 1200ms, checks every 100ms.
const TTL_MS: i64 = 1200;

fn ms_of(ts: &str) -> i64 {
    agentmesh::parse_instant_ms(ts).unwrap_or_else(|| panic!("unparseable instant {ts}"))
}

/// Watch `mesh.registry.register` the way a registry would: every accepted
/// (signature-verified, §5.3) registration, with its manifest and arrival time.
struct Observer {
    seen: Arc<Mutex<Vec<(Manifest, i64)>>>,
    _conn: async_nats::Client,
}

impl Observer {
    async fn start() -> Option<Observer> {
        let conn = async_nats::connect(URL).await.ok()?;
        let mut sub = conn.subscribe("mesh.registry.register").await.ok()?;
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        tokio::spawn(async move {
            while let Some(msg) = sub.next().await {
                // decode verifies the envelope signature; an unverifiable
                // registration is exactly what a registry would drop.
                let Ok(env) = codec::decode(&msg.payload) else { continue };
                let Some(payload) = env.payload else { continue };
                let Ok(manifest) = serde_json::from_value::<Manifest>(payload) else { continue };
                sink.lock().unwrap().push((manifest, now_ms()));
            }
        });
        Some(Observer { seen, _conn: conn })
    }

    fn registrations_of(&self, agent_id: &str) -> Vec<(Manifest, i64)> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|(m, _)| m.id == agent_id)
            .cloned()
            .collect()
    }

    /// Wait until `agent_id` has at least `n` registrations, or `timeout`.
    async fn await_registrations(&self, agent_id: &str, n: usize, timeout: Duration) {
        let deadline = tokio::time::Instant::now() + timeout;
        while tokio::time::Instant::now() < deadline {
            if self.registrations_of(agent_id).len() >= n {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
}

macro_rules! observer_or_skip {
    () => {
        match Observer::start().await {
            Some(o) => o,
            None => {
                eprintln!("skipping vouch renewal e2e: no NATS server at {URL}");
                return;
            }
        }
    };
}

// ── standalone agent: renews its own vouch (§4.4) ───────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn standalone_re_registers_with_a_fresh_vouch_before_the_first_one_expires() {
    let observer = observer_or_skip!();
    let agent = AgentMesh::connect(
        URL,
        ConnectOptions { allow_unnamed: true, vouch_ttl_ms: Some(TTL_MS), ..Default::default() },
    )
    .await
    .expect("connect");
    let t0 = now_ms();
    agent
        .register(RegisterOptions { name: "long-lived".into(), ..Default::default() })
        .await
        .expect("register");

    observer.await_registrations(agent.id(), 2, Duration::from_secs(5)).await;
    agent.close().await;

    let registers = observer.registrations_of(agent.id());
    assert!(registers.len() >= 2, "renewed at least once, got {}", registers.len());
    let (first, _) = &registers[0];
    let first_expiry = ms_of(&first.node.attestation.expires_at);
    assert!(first_expiry - t0 <= TTL_MS + 1_000, "explicit TTL honoured");

    let (renewal, renewed_at) = &registers[1];
    // The renewal happened while the ORIGINAL vouch was still valid. That is
    // the whole point: the registry refuses an expired attestation (§9.7), so
    // a renewal that arrives late cannot register at all.
    assert!(*renewed_at < first_expiry, "renewed before the first vouch expired");
    // ... and not before its two-thirds deadline (minus one 100ms check tick
    // of slack for clock granularity).
    assert!(*renewed_at - t0 >= TTL_MS * 2 / 3 - 100, "renewed at the deadline, not eagerly");

    // A genuinely fresh, valid vouch — signed by the same node key, binding
    // THIS agent, expiring later than the one it replaces.
    let att = &renewal.node.attestation;
    assert_eq!(att.node, first.node.attestation.node, "re-signed by the same node key");
    assert_eq!(att.agent, agent.id());
    assert!(verify_attestation(att, Some(agent.id())));
    assert!(ms_of(&att.expires_at) > first_expiry);
    // The manifest key claim (§8.3) is re-signed with it, so the renewed
    // manifest is as verifiable as the original — and it is the SAME manifest
    // the agent first registered.
    assert!(verify_manifest_signature(renewal));
    assert_eq!(renewal.name, first.name);
    assert_eq!(renewal.id, first.id);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn keeps_renewing_cycle_after_cycle() {
    let observer = observer_or_skip!();
    let agent = AgentMesh::connect(
        URL,
        ConnectOptions { allow_unnamed: true, vouch_ttl_ms: Some(900), ..Default::default() },
    )
    .await
    .expect("connect");
    agent
        .register(RegisterOptions { name: "forever".into(), ..Default::default() })
        .await
        .expect("register");

    // Three renewal windows: a one-shot renewal would stop at 2 registrations.
    observer.await_registrations(agent.id(), 4, Duration::from_secs(6)).await;
    agent.close().await;

    let registers = observer.registrations_of(agent.id());
    assert!(registers.len() >= 4, "kept renewing, got {}", registers.len());
    // Never lapsed: every vouch was replaced before the previous one expired.
    for pair in registers.windows(2) {
        let (prev, _) = &pair[0];
        let (_, at) = &pair[1];
        assert!(*at < ms_of(&prev.node.attestation.expires_at));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reports_the_vouch_window_it_is_maintaining() {
    let _observer = observer_or_skip!();
    let agent = AgentMesh::connect(
        URL,
        ConnectOptions { allow_unnamed: true, vouch_ttl_ms: Some(60_000), ..Default::default() },
    )
    .await
    .expect("connect");

    // Not registered: all None.
    let before = agent.vouch();
    assert_eq!(before.expires_at, None);
    assert_eq!(before.renew_at, None);
    assert_eq!(before.last_error, None);

    agent
        .register(RegisterOptions { name: "observable".into(), ..Default::default() })
        .await
        .expect("register");
    let vouch = agent.vouch();
    let expires = ms_of(vouch.expires_at.as_deref().expect("expires_at set"));
    let renew = ms_of(vouch.renew_at.as_deref().expect("renew_at set"));
    // The renewal window is the last third of the TTL.
    let window = expires - renew;
    assert!((window - 20_000).abs() <= 5, "window = ttl/3, got {window}");
    assert_eq!(vouch.last_error, None);
    agent.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn renew_vouch_refuses_when_never_registered_and_when_closed() {
    let _observer = observer_or_skip!();
    let agent = AgentMesh::connect(URL, ConnectOptions { allow_unnamed: true, ..Default::default() }).await.expect("connect");
    let err = agent.renew_vouch().await.expect_err("nothing to re-register");
    assert!(format!("{err}").contains("has not registered"), "{err}");
    agent.close().await;

    let agent = AgentMesh::connect(URL, ConnectOptions { allow_unnamed: true, ..Default::default() }).await.expect("connect");
    agent
        .register(RegisterOptions { name: "closes".into(), ..Default::default() })
        .await
        .expect("register");
    agent.close().await;
    let err = agent.renew_vouch().await.expect_err("closed agent cannot renew");
    assert!(format!("{err}").contains("closed"), "{err}");
}

// ── renewal cleanup ─────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stops_renewing_after_close() {
    let observer = observer_or_skip!();
    let agent = AgentMesh::connect(
        URL,
        ConnectOptions { allow_unnamed: true, vouch_ttl_ms: Some(TTL_MS), ..Default::default() },
    )
    .await
    .expect("connect");
    agent
        .register(RegisterOptions { name: "closes-early".into(), ..Default::default() })
        .await
        .expect("register");
    agent.close().await;

    // Several renewal windows later: nothing beyond the original registration.
    tokio::time::sleep(Duration::from_millis((TTL_MS * 3) as u64)).await;
    assert_eq!(observer.registrations_of(agent.id()).len(), 1);
}

// ── manual renewal: due-ness judged against a supplied clock ────────────────
//
// Hosted agents run no loop of their own (the node's single loop covers them),
// which makes them the deterministic seam for the due/not-due/retry semantics
// the TS suite drives with a fake clock.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn renew_if_due_respects_the_deadline_and_resets_it_on_renewal() {
    let observer = observer_or_skip!();
    let Ok(client) = async_nats::connect(URL).await else {
        eprintln!("skipping vouch renewal e2e: no NATS server at {URL}");
        return;
    };
    // No explicit TTL, no declared availability_class: the §9.2 ephemeral
    // default (72h) applies, so nothing is due on the wall clock and the
    // node's 30-day-cadence loop is idle for the life of this test.
    let node = MeshNode::with_client(client, NodeConnectOptions::default()).expect("node");
    let agent = node.add_agent(None).expect("hosted agent");
    agent
        .register(RegisterOptions { name: "on-demand".into(), ..Default::default() })
        .await
        .expect("register");
    // The observer rides its own connection; wait for the registration to
    // reach it before counting.
    observer.await_registrations(agent.id(), 1, Duration::from_secs(2)).await;

    let t0 = now_ms();
    let vouch = agent.vouch();
    let renew_at = ms_of(vouch.renew_at.as_deref().expect("deadline recorded"));
    assert!((renew_at - t0 - 48 * 3_600_000).abs() < 60_000, "ephemeral: due 48h in");

    // Not due yet → false, and nothing was sent.
    assert!(!agent.renew_vouch_if_due_at(t0).await);
    assert!(!agent.renew_vouch_if_due_at(renew_at - 1).await);
    assert_eq!(observer.registrations_of(agent.id()).len(), 1);

    // Due → renews and says so.
    assert!(agent.renew_vouch_if_due_at(renew_at + 1).await);
    observer.await_registrations(agent.id(), 2, Duration::from_secs(2)).await;
    assert_eq!(observer.registrations_of(agent.id()).len(), 2);

    // The renewal reset the deadline: the instant that was just due is due no
    // longer (the new vouch's two-thirds point is ~48h from NOW).
    assert!(!agent.renew_vouch_if_due_at(renew_at + 1).await);
    assert_eq!(observer.registrations_of(agent.id()).len(), 2);

    // A concurrent burst at a due instant performs ONE renewal, not six: while
    // one is in flight the guard turns the rest away, and any call that lands
    // after it completes finds the deadline already reset. Either way exactly
    // one re-register goes out.
    let due2 = ms_of(agent.vouch().renew_at.as_deref().unwrap()) + 1;
    let burst = futures::future::join_all(
        (0..6).map(|_| { let a = agent.clone(); async move { a.renew_vouch_if_due_at(due2).await } }),
    )
    .await;
    assert_eq!(burst.iter().filter(|renewed| **renewed).count(), 1, "{burst:?}");
    observer.await_registrations(agent.id(), 3, Duration::from_secs(2)).await;
    assert_eq!(observer.registrations_of(agent.id()).len(), 3);

    node.close().await;
}

// ── a failed renewal is visible and retried ─────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_renewal_warns_keeps_the_deadline_and_retries() {
    let _observer = observer_or_skip!();
    let Ok(client) = async_nats::connect(URL).await else {
        eprintln!("skipping vouch renewal e2e: no NATS server at {URL}");
        return;
    };
    let node = MeshNode::with_client(client.clone(), NodeConnectOptions::default()).expect("node");
    let agent = node.add_agent(None).expect("hosted agent");
    let warnings: Arc<Mutex<Vec<SecurityWarning>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&warnings);
    agent.on_security_warning(move |w| sink.lock().unwrap().push(w));
    agent
        .register(RegisterOptions { name: "registry-goes-away".into(), ..Default::default() })
        .await
        .expect("register");
    let vouch_before = agent.vouch();
    let due = ms_of(vouch_before.renew_at.as_deref().unwrap()) + 1;

    // Take the transport away: the re-register publish now fails.
    client.drain().await.expect("drain the shared connection");

    // The failure did not throw, recorded itself, and left the deadline in
    // place so the next tick retries.
    assert!(!agent.renew_vouch_if_due_at(due).await);
    assert!(!agent.renew_vouch_if_due_at(due).await, "retried, not one-shot");
    let warnings = warnings.lock().unwrap();
    let failures: Vec<_> =
        warnings.iter().filter(|w| w.code == "vouch_renewal_failed").collect();
    assert!(failures.len() >= 2, "one warning per failed attempt, got {}", failures.len());
    let failure = failures[0];
    assert_eq!(failure.subject.as_deref(), Some(agent.id()));
    assert!(failure.message.contains("could not renew the node vouch"), "{}", failure.message);
    assert!(failure.message.contains("expires"), "{}", failure.message);
    assert!(failure.message.ends_with("Retrying."), "{}", failure.message);

    // A failing renewal does not corrupt what the agent thinks it holds.
    let vouch = agent.vouch();
    assert!(vouch.last_error.is_some());
    assert_eq!(vouch.expires_at, vouch_before.expires_at);
    assert_eq!(vouch.renew_at, vouch_before.renew_at);
}

// ── node-hosted agents: one node re-vouches many agents (§4.4) ──────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_node_loop_renews_every_hosted_agents_vouch() {
    let observer = observer_or_skip!();
    let node = match MeshNode::connect(
        URL,
        NodeConnectOptions { vouch_ttl_ms: Some(TTL_MS), ..Default::default() },
    )
    .await
    {
        Ok(n) => n,
        Err(_) => {
            eprintln!("skipping vouch renewal e2e: no NATS server at {URL}");
            return;
        }
    };
    let a = node.add_agent(None).expect("agent a");
    let b = node.add_agent(None).expect("agent b");
    a.register(RegisterOptions { name: "hosted-a".into(), ..Default::default() })
        .await
        .expect("register a");
    b.register(RegisterOptions { name: "hosted-b".into(), ..Default::default() })
        .await
        .expect("register b");

    observer.await_registrations(a.id(), 2, Duration::from_secs(5)).await;
    observer.await_registrations(b.id(), 2, Duration::from_secs(5)).await;
    node.close().await;

    for agent in [&a, &b] {
        let mine = observer.registrations_of(agent.id());
        assert!(mine.len() >= 2, "hosted agent renewed, got {}", mine.len());
        let (first, _) = &mine[0];
        let (renewed, _) = &mine[1];
        // The NODE vouched — not the agent for itself.
        assert_eq!(renewed.node.attestation.node, node.id());
        assert!(verify_attestation(&renewed.node.attestation, Some(agent.id())));
        assert!(
            ms_of(&renewed.node.attestation.expires_at)
                > ms_of(&first.node.attestation.expires_at)
        );
        // Still the agent's own signature on the key claim (§8.3).
        assert!(verify_manifest_signature(renewed));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_stops_renewing_on_close_and_skips_the_unregistered_and_the_closed() {
    let observer = observer_or_skip!();
    let node = match MeshNode::connect(
        URL,
        NodeConnectOptions { vouch_ttl_ms: Some(TTL_MS), ..Default::default() },
    )
    .await
    {
        Ok(n) => n,
        Err(_) => {
            eprintln!("skipping vouch renewal e2e: no NATS server at {URL}");
            return;
        }
    };
    let never_registers = node.add_agent(None).expect("agent");
    let detaches = node.add_agent(None).expect("agent");
    let kept = node.add_agent(None).expect("agent");
    detaches
        .register(RegisterOptions { name: "detaches".into(), ..Default::default() })
        .await
        .expect("register");
    kept.register(RegisterOptions { name: "kept".into(), ..Default::default() })
        .await
        .expect("register");
    // Nothing due yet: a fresh pass is a no-op.
    assert_eq!(node.renew_vouches().await, 0);

    // An agent that detached (its own close) stops being renewed; the node
    // does not vouch an unregistered agent into existence.
    detaches.close().await;
    observer.await_registrations(kept.id(), 3, Duration::from_secs(5)).await;
    node.close().await;

    assert!(observer.registrations_of(kept.id()).len() >= 3, "the live agent kept renewing");
    assert_eq!(observer.registrations_of(detaches.id()).len(), 1, "detached: original only");
    assert_eq!(observer.registrations_of(never_registers.id()).len(), 0);

    // After node.close(): several windows later, no further registrations.
    let kept_count = observer.registrations_of(kept.id()).len();
    tokio::time::sleep(Duration::from_millis((TTL_MS * 2) as u64)).await;
    assert_eq!(observer.registrations_of(kept.id()).len(), kept_count);
}
