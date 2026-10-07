use agentmesh::{AgentMesh, ConnectOptions, RegisterOptions, Offering};
use serde_json::json;
use std::io::Write;

#[tokio::main]
async fn main() {
    let mesh = AgentMesh::connect("nats://127.0.0.1:4222", ConnectOptions::default()).await.unwrap();
    mesh.on_stream_request("count", |input, w| async move {
        let n = input.get("n").and_then(|v| v.as_u64()).unwrap_or(3);
        for i in 0..n {
            w.write(json!(format!("rust-tick-{i}")), Some("text/plain")).await?;
        }
        w.end(Some(json!({ "total": n }))).await?;
        Ok::<(), agentmesh::MeshError>(())
    });
    mesh.register(RegisterOptions {
        name: "Rust Streamer".into(),
        capabilities: vec!["count".into()],
        offerings: vec![Offering { id: "count".into(), name: "Count".into(), description: "streams N ticks".into(), tags: None, input_modes: None, output_modes: None, streaming: Some(true), needs: None, delivers: None, reporting: None, trial: None }],
        ..Default::default()
    }).await.unwrap();
    let mut f = std::fs::File::create(std::env::var("ID_FILE").unwrap()).unwrap();
    write!(f, "{}", mesh.id()).unwrap();
    eprintln!("[rust producer] ready {}", &mesh.id()[..12]);
    loop { tokio::time::sleep(std::time::Duration::from_secs(3600)).await; }
}
