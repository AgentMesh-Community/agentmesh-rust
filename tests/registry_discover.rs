//! Cross-language integration: a Rust client registers with the (TypeScript)
//! registry service and then discovers itself by capability over live NATS.
//! This proves the `discover()` primitive end-to-end against the REAL registry
//! (vouch verification, presence join, signed response) — not a Rust-only loop.
//!
//! Requires BOTH a JetStream nats-server on 127.0.0.1:4222 AND the TS registry
//! running against it (`npm run start:registry` in services/, with
//! NATS_URL=localhost:4222). Skips gracefully if either is absent, so it's safe
//! in a bare `cargo test`.

use agentmesh::{AgentMesh, ConnectOptions, DiscoverQuery, RegisterOptions, Offering};
use serde_json::json;

const URL: &str = "nats://127.0.0.1:4222";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rust_client_registers_and_discovers_via_ts_registry() {
    let agent = match AgentMesh::connect(URL, ConnectOptions { allow_unnamed: true, ..Default::default() }).await {
        Ok(a) => a,
        Err(_) => {
            eprintln!("skipping: no NATS server at {URL}");
            return;
        }
    };

    // Unique capability so discover() only ever sees THIS run's agent (the
    // registry KV persists across runs).
    let cap = format!("rust-it-{}", agent.id()[..10].to_lowercase());
    let offering_id = format!("{cap}-echo");

    agent.on_request(&offering_id, |input| async move { Ok(json!({ "echoed": input })) });
    agent
        .register(RegisterOptions {
            name: "rust-discover-probe".into(),
            description: "rust ↔ ts-registry integration probe".into(),
            capabilities: vec![cap.clone()],
            offerings: vec![Offering {
                id: offering_id.clone(),
                name: "Echo".into(),
                description: "echoes its input".into(),
                tags: None,
                input_modes: None,
                output_modes: None,
                streaming: None,
                needs: None,
                delivers: None, reporting: None, trial: None,
            }],
            ..Default::default()
        })
        .await
        .expect("register");

    // Let the registry verify the vouch, persist the manifest, and seed presence.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let found = match agent
        .discover(DiscoverQuery {
            capabilities: vec![cap.clone()],
            ..Default::default()
        })
        .await
    {
        Ok(f) => f,
        Err(e) => {
            eprintln!("skipping: registry not answering discover ({e}) — start `npm run start:registry`");
            agent.close().await;
            return;
        }
    };

    // The registry found exactly this run's agent, with its node vouch intact and
    // its capability preserved — over a signed, cross-language round trip.
    assert_eq!(found.len(), 1, "exactly this run's agent is discoverable");
    let m = &found[0];
    assert_eq!(m.id, agent.id(), "discovered manifest is ours");
    assert_eq!(m.node.attestation.agent, agent.id(), "node vouch binds to the agent");
    assert!(m.capabilities.contains(&cap), "capability round-tripped");

    agent.close().await;
}
