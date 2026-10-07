//! Live contract test for the Egg Gateway's mesh inbound bridge (Phase 4b).
//!
//! The Gateway registers a `chat` offering whose input is `{ message }` and whose
//! output is `{ text, input_tokens, output_tokens }` (see egg-daemon
//! `src/mesh/mod.rs`). This test stands up a stub agent exposing that SAME
//! contract, then a client discovers it by capability and drives a chat turn —
//! proving the discover-by-offering + request/respond shape the real daemon speaks,
//! over live NATS + the TS registry. (The daemon's handler runs the real agent
//! via `run_agent_chat`; that's the proven HTTP chat path. The full daemon+LLM
//! run is documented in the egg-daemon repo, MESH_E2E_RUNBOOK.md, and driven by
//! the `gateway_chat` example in this crate.)
//!
//! Requires a JetStream nats-server on 127.0.0.1:4222 + the TS registry running.
//! Skips gracefully otherwise.

use agentmesh::{AgentMesh, ConnectOptions, DiscoverQuery, RegisterOptions, Offering};
use serde_json::json;

const URL: &str = "nats://127.0.0.1:4222";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gateway_chat_offering_contract() {
    let gateway = match AgentMesh::connect(URL, ConnectOptions { allow_unnamed: true, ..Default::default() }).await {
        Ok(a) => a,
        Err(_) => {
            eprintln!("skipping: no NATS server at {URL}");
            return;
        }
    };

    // Unique capability isolates this run; the OFFERING id mirrors the daemon's real
    // `chat` offering so we exercise the exact contract.
    let cap = format!("egg-gateway-{}", gateway.id()[..10].to_lowercase());

    // Stub the Gateway's `chat` handler: input {message} → output {text, ...},
    // exactly as egg-daemon's `install_gateway_handlers` shapes it.
    gateway.on_request("chat", |input| async move {
        let msg = input
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        Ok(json!({
            "text": format!("You said: {msg}"),
            "input_tokens": 0,
            "output_tokens": 0,
        }))
    });
    gateway
        .register(RegisterOptions {
            name: "Egg Gateway".into(),
            description: "Egg's primary agent, reachable over the mesh.".into(),
            capabilities: vec!["chat".into(), cap.clone()],
            offerings: vec![Offering {
                id: "chat".into(),
                name: "Chat".into(),
                description: "Converse with the Egg Gateway's primary agent.".into(),
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
        .expect("register gateway");

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Client: discover the gateway (by our isolating capability), confirm it
    // advertises the `chat` offering, then hold a chat turn.
    let client = AgentMesh::connect(URL, ConnectOptions { allow_unnamed: true, ..Default::default() })
        .await
        .expect("connect client");

    let found = match client
        .discover(DiscoverQuery {
            capabilities: vec![cap.clone()],
            ..Default::default()
        })
        .await
    {
        Ok(f) => f,
        Err(e) => {
            eprintln!("skipping: registry not answering discover ({e}) — start `npm run start:registry`");
            client.close().await;
            gateway.close().await;
            return;
        }
    };

    assert_eq!(found.len(), 1, "discovered the gateway");
    let gw = &found[0];
    assert!(
        gw.offerings.iter().any(|s| s.id == "chat"),
        "gateway advertises the chat offering"
    );

    let res = client
        .request(&gw.id, "chat", json!({ "message": "hello gateway" }))
        .await
        .expect("chat request");

    // Bare terminal response carrying the Gateway's {text} output shape.
    assert!(res.task_id.is_none(), "bare response");
    assert_eq!(res.payload["status"], "completed");

    // §22.6 provenance fencing rewrites the handler's input: the `message` rung
    // reaches the handler wrapped in BEGIN/END markers, so the stub's echo
    // carries the frame, not the bare sentence. This assertion used to expect
    // "You said: hello gateway" and silently encoded the pre-fencing world — the
    // exact assumption a host upgrading across that change needs to see fail.
    let echoed = res.payload["output"]["text"]
        .as_str()
        .expect("gateway returned a text answer");
    assert!(echoed.starts_with("You said: "), "gateway's output shape held: {echoed}");
    assert!(
        echoed.contains("--- BEGIN SENDER MESSAGE ---")
            && echoed.contains("--- END SENDER MESSAGE ---"),
        "inbound text arrived fenced (§22.6): {echoed}"
    );
    assert!(
        echoed.contains("hello gateway"),
        "the sender's words survived the frame: {echoed}"
    );

    client.close().await;
    gateway.close().await;
}
