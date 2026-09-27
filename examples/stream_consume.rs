//! Cross-impl stream proof: consume a TS-produced stream (§11).
use agentmesh::{AgentMesh, ConnectOptions};
use serde_json::json;

#[tokio::main]
async fn main() {
    let url = std::env::var("URL").unwrap_or_else(|_| "nats://127.0.0.1:4222".into());
    let producer = std::env::var("PRODUCER").expect("PRODUCER agent id");
    let sign_chunks = std::env::var("SIGN_CHUNKS").is_ok();

    let mesh = AgentMesh::connect(&url, ConnectOptions::default()).await.expect("connect");
    let mut stream = mesh
        .request_stream(&producer, "count", json!({ "n": 3 }), sign_chunks)
        .await
        .expect("request_stream");

    println!("OPENING_VERIFIED from={}", stream.initial.from);
    let mut n = 0;
    while let Some(item) = stream.chunks.recv().await {
        match item {
            Ok(c) => {
                println!("CHUNK idx={} final={} data={}", c.chunk_index, c.is_final, c.data);
                n += 1;
                if c.is_final { println!("STREAM_COMPLETE chunks={}", n); }
            }
            Err(e) => {
                println!("STREAM_ERROR {}", e);
                std::process::exit(1);
            }
        }
    }
    mesh.close().await;
}
