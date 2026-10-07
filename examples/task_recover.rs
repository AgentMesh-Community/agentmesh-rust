//! Live proof of §11.3 result recovery: a responder streams a task to
//! completion while the requester ABANDONS the stream mid-flight (simulating
//! a disconnect/restart), then recovers the final output from the Task
//! Manager's durable record via `get_task`.
//!
//! Run with two credentials issued to an account (the no-signup guest door,
//! POST /v1/guest, closed on 2026-09-27; there is no credential without one):
//!   URL=... R_JWT=... R_SEED=... Q_JWT=... Q_SEED=... cargo run --example task_recover

use agentmesh::{AgentMesh, ConnectOptions, RegisterOptions, Offering};
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::var("URL")?;

    // Responder: registers a slow streaming offering whose answer we'll recover.
    let responder = AgentMesh::connect(
        &url,
        ConnectOptions { allow_unnamed: true,
            agent_seed: Some(std::env::var("R_SEED")?),
            jwt: Some(std::env::var("R_JWT")?),
            ..Default::default()
        },
    )
    .await?;
    responder.on_stream_request("slowwork", |_input, w| async move {
        for i in 0..3u32 {
            tokio::time::sleep(std::time::Duration::from_millis(800)).await;
            w.write(json!({ "progress": i }), Some("application/json")).await?;
        }
        w.end(Some(json!({ "text": "the-answer-42" }))).await?;
        Ok(())
    });
    responder
        .register(RegisterOptions {
            name: "Task Recover Probe".into(),
            capabilities: vec!["slowwork".into()],
            offerings: vec![Offering {
                id: "slowwork".into(),
                name: "Slow Work".into(),
                description: "streams then completes".into(),
                tags: None,
                input_modes: None,
                output_modes: None,
                streaming: Some(true),
                needs: None,
                delivers: None, reporting: None, trial: None,
            }],
            ..Default::default()
        })
        .await?;
    println!("responder ready {}", &responder.id()[..12]);

    // Requester: opens the stream, reads ONE chunk, then walks away.
    let requester = AgentMesh::connect(
        &url,
        ConnectOptions { allow_unnamed: true,
            agent_seed: Some(std::env::var("Q_SEED")?),
            jwt: Some(std::env::var("Q_JWT")?),
            ..Default::default()
        },
    )
    .await?;
    let task_id = {
        let mut stream = requester
            .request_stream(responder.id(), "slowwork", json!({}), false)
            .await?;
        let first = stream.chunks.recv().await;
        println!("got first chunk: {:?} — abandoning stream now", first.is_some());
        stream.task_id.clone()
        // `stream` dropped here: the requester stops listening mid-task.
    };
    println!("task_id {task_id}");

    // Give the responder time to finish and the Task Manager time to record.
    tokio::time::sleep(std::time::Duration::from_secs(4)).await;

    // Recovery: the durable record should hold state=completed and the
    // completion update's payload.output.
    let record = requester.get_task(&task_id).await?;
    let state = record.get("state").and_then(|v| v.as_str()).unwrap_or("?");
    let output = record
        .get("history")
        .and_then(|h| h.as_array())
        .and_then(|h| {
            h.iter().rev().find_map(|env| {
                env.get("payload")
                    .and_then(|p| p.get("output"))
                    .filter(|o| !o.is_null())
                    .cloned()
            })
        });
    println!("recovered: state={state} output={output:?}");

    responder.deregister().await.ok();
    responder.close().await;
    requester.close().await;

    assert_eq!(state, "completed", "task record should be completed");
    let text = output
        .as_ref()
        .and_then(|o| o.get("text"))
        .and_then(|t| t.as_str());
    assert_eq!(text, Some("the-answer-42"), "output should survive in the task record");
    println!("TASK RECOVERY OK");
    Ok(())
}
