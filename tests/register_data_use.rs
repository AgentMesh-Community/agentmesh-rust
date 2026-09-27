//! §8.10 `data_use` at register — the card-level data-use declaration,
//! settable as a register option instead of by hand-editing a manifest.
//! Mirrors `sdk-typescript`'s `__tests__/unit/register-data-use.test.ts`.
//!
//! What this pins is the pass-through contract: the declaration rides the
//! registered manifest VERBATIM under the field name the spec gives it, the
//! crate never invents one on an agent's behalf (silence stays silence), and
//! the crate does NOT duplicate the registry's drop rules — the registry is
//! the one validator and its verdict must be the only verdict.
//!
//! This crate has no transport seam (register publishes fire-and-forget), so
//! like `vouch_renewal.rs` these run against a real nats-server on
//! 127.0.0.1:4222 with an observer on `mesh.registry.register` standing in
//! for the registry, skipping gracefully if no server is there.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use agentmesh::{
    codec, AgentDataUse, AgentDataUsePromises, AgentDataUseRetention, AgentMesh, ConnectOptions,
    Manifest, RegisterOptions, SowProcessor,
};
use futures::StreamExt;

const URL: &str = "nats://127.0.0.1:4222";

/// Watch `mesh.registry.register` the way a registry would: every accepted
/// (signature-verified, §5.3) registration, as the raw JSON the wire carried —
/// raw, because absence-vs-presence of the `data_use` KEY is itself under test.
struct Observer {
    seen: Arc<Mutex<Vec<serde_json::Value>>>,
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
                let Ok(env) = codec::decode(&msg.payload) else { continue };
                let Some(payload) = env.payload else { continue };
                sink.lock().unwrap().push(payload);
            }
        });
        Some(Observer { seen, _conn: conn })
    }

    /// Wait for `agent_id`'s registration and hand back the raw manifest JSON.
    async fn registration_of(&self, agent_id: &str) -> Option<serde_json::Value> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::time::Instant::now() < deadline {
            let hit = self
                .seen
                .lock()
                .unwrap()
                .iter()
                .find(|v| v.get("id").and_then(|i| i.as_str()) == Some(agent_id))
                .cloned();
            if hit.is_some() {
                return hit;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        None
    }
}

macro_rules! observer_or_skip {
    () => {
        match Observer::start().await {
            Some(o) => o,
            None => {
                eprintln!("skipping data_use register e2e: no NATS server at {URL}");
                return;
            }
        }
    };
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn data_use_rides_the_registered_manifest_verbatim() {
    let observer = observer_or_skip!();
    let agent = AgentMesh::connect(URL, ConnectOptions { allow_unnamed: true, ..Default::default() }).await.expect("connect");

    let declaration = AgentDataUse {
        promises: Some(AgentDataUsePromises {
            no_training: Some(true),
            no_third_party_sharing: Some(true),
            no_human_reading: None,
        }),
        retention: Some(AgentDataUseRetention { max_days: 30 }),
        processors: Some(vec![SowProcessor {
            service: "Anthropic API".into(),
            domain: Some("anthropic.com".into()),
            purpose: Some("model inference".into()),
        }]),
        processed_in: Some(vec!["us".into()]),
    };
    agent
        .register(RegisterOptions {
            name: "careful-rust".into(),
            data_use: Some(declaration.clone()),
            ..Default::default()
        })
        .await
        .expect("register");

    let raw = observer.registration_of(&agent.id()).await.expect("registration observed");
    // Verbatim under its own name — and the wire shape parses back to exactly
    // what was declared (a promise left out stays left out).
    let on_wire: AgentDataUse =
        serde_json::from_value(raw.get("data_use").expect("data_use on the manifest").clone())
            .expect("readable");
    assert_eq!(on_wire, declaration);
    // The typed manifest reads it too, so a registry-less peer sees the same.
    let manifest: Manifest = serde_json::from_value(raw).expect("manifest parses");
    assert_eq!(manifest.data_use, Some(declaration));
    agent.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn silence_stays_silence_and_an_empty_processors_list_is_a_statement() {
    let observer = observer_or_skip!();

    // Did not say: the KEY must be absent — a requirement stated against
    // data_use treats absence as not meeting it, so an invented key would
    // change what this agent is claiming.
    let silent = AgentMesh::connect(URL, ConnectOptions { allow_unnamed: true, ..Default::default() }).await.expect("connect");
    silent
        .register(RegisterOptions { name: "says-nothing".into(), ..Default::default() })
        .await
        .expect("register");
    let raw = observer.registration_of(&silent.id()).await.expect("registration observed");
    assert!(raw.get("data_use").is_none(), "the SDK invented a data_use key: {raw}");
    silent.close().await;

    // Some(vec![]) is a different claim from omission: content leaves the
    // operator for NOWHERE. Pass-through must not normalize it away.
    let nowhere = AgentMesh::connect(URL, ConnectOptions { allow_unnamed: true, ..Default::default() }).await.expect("connect");
    nowhere
        .register(RegisterOptions {
            name: "leaves-nowhere".into(),
            data_use: Some(AgentDataUse { processors: Some(vec![]), ..Default::default() }),
            ..Default::default()
        })
        .await
        .expect("register");
    let raw = observer.registration_of(&nowhere.id()).await.expect("registration observed");
    assert_eq!(
        raw.get("data_use"),
        Some(&serde_json::json!({ "processors": [] })),
        "the empty processors statement must survive verbatim"
    );
    nowhere.close().await;
}
