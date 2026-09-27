//! A standalone Rust responder agent for the cross-language check. Registers an
//! `echo` offering, prints its agent ID, and stays alive.
//! Run: cargo run --example serve

use agentmesh::{AgentMesh, ConnectOptions, RegisterOptions};
use serde_json::json;

#[tokio::main]
async fn main() {
    let a = AgentMesh::connect("nats://127.0.0.1:4222", ConnectOptions::default())
        .await
        .expect("connect");
    a.on_request("echo", |input| async move {
        Ok(json!({ "echoed": input, "lang": "rust" }))
    });
    a.register(RegisterOptions {
        name: "rust-responder".into(),
        capabilities: vec!["echo".into()],
        ..Default::default()
    })
    .await
    .expect("register");

    println!("AGENT_ID={}", a.id());
    // Stay alive to serve requests.
    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
}
