//! §14.4 — resolve, never construct: when a caller holds the recipient's
//! manifest, the request is addressed to the manifest's CARRIED endpoint
//! subject, not to one assembled from the naming convention. That is what
//! makes a future subject renaming a registry change instead of an ecosystem
//! flag day.
//!
//! The unit tests pin the resolution order (`endpoints.inbox` wins, `endpoint`
//! is the fallback, construction is the SDK's last resort). The live test
//! proves the carried value is what actually goes on the wire: a manifest
//! whose `endpoints.inbox` names a subject nobody serves gets
//! `AGENT_UNAVAILABLE` even though the constructed subject IS served — only an
//! implementation that resolved could fail that way.

use std::time::Duration;

use agentmesh::{
    AgentAttestation, AgentMesh, ConnectOptions, Endpoints, ErrorCode, Limits, Manifest, MeshError,
    NodeRef, RegisterOptions, RequestOptions,
};
use serde_json::json;

const URL: &str = "nats://127.0.0.1:4222";

fn manifest_for(agent_id: &str, endpoints: Option<Endpoints>, endpoint: &str) -> Manifest {
    Manifest {
        id: agent_id.to_string(),
        name: "probe".to_string(),
        description: String::new(),
        version: "0.1.0".to_string(),
        protocol_version: "0.2".to_string(),
        encryption_key: None,
        endpoint: endpoint.to_string(),
        endpoints,
        limits: None,
        node: NodeRef {
            id: agent_id.to_string(),
            attestation: AgentAttestation {
                node: agent_id.to_string(),
                agent: agent_id.to_string(),
                issued_at: String::new(),
                expires_at: String::new(),
                sig: String::new(),
            },
            profile: None,
        },
        capabilities: vec![],
        offerings: vec![],
        emits: None,
        accepts: None,
        meta: None,
        trust: None,
        visibility: None,
        interaction: None,
        harness: None,
        harness_version: None,
        model: None,
        works_with: None,
        sealing: None,
        data_use: None,
        compliance: None,
        // §8.12: declaration-only, like compliance above.
        audience: None,
        coverage: None,
        edge: None,
        serves: None,
        acts: None,
        parties: None,
        origin: None,
        public: None,
        skus: None,
        availability: None,
        owner: None,
        owner_attestation: None,
    }
}

#[test]
fn resolution_order_is_endpoints_inbox_then_endpoint_then_none() {
    // The carried endpoints block wins (§14.4).
    let m = manifest_for(
        "UAGENT",
        Some(Endpoints { inbox: Some("carried.subject".into()), other: Default::default() }),
        "legacy.endpoint",
    );
    assert_eq!(m.resolved_inbox(), Some("carried.subject"));
    // Without the block, the legacy endpoint field is still a carried value.
    let m = manifest_for("UAGENT", None, "legacy.endpoint");
    assert_eq!(m.resolved_inbox(), Some("legacy.endpoint"));
    // An empty inbox entry does not shadow the endpoint field.
    let m = manifest_for(
        "UAGENT",
        Some(Endpoints { inbox: Some(String::new()), other: Default::default() }),
        "legacy.endpoint",
    );
    assert_eq!(m.resolved_inbox(), Some("legacy.endpoint"));
    // A manifest carrying neither resolves nothing; only then may an SDK
    // construct (it is the convention's one legitimate constructor).
    let m = manifest_for("UAGENT", None, "");
    assert_eq!(m.resolved_inbox(), None);
}

#[test]
fn endpoints_and_limits_ride_the_wire_and_round_trip() {
    let mut m = manifest_for(
        "UAGENT",
        Some(Endpoints { inbox: Some("mesh.agent.UAGENT.inbox".into()), other: Default::default() }),
        "mesh.agent.UAGENT.inbox",
    );
    m.limits = Some(Limits { max_inbound_chars: Some(4096) });
    let wire = serde_json::to_value(&m).unwrap();
    assert_eq!(wire["endpoints"], json!({ "inbox": "mesh.agent.UAGENT.inbox" }));
    assert_eq!(wire["limits"], json!({ "max_inbound_chars": 4096 }));
    let back: Manifest = serde_json::from_value(wire).unwrap();
    assert_eq!(back.declared_max_inbound_chars(), Some(4096));
    assert_eq!(back.resolved_inbox(), Some("mesh.agent.UAGENT.inbox"));
    // Absent blocks stay absent on the wire — a §8.1-OPTIONAL field never
    // serializes as null.
    let bare = manifest_for("UAGENT", None, "mesh.agent.UAGENT.inbox");
    let wire = serde_json::to_value(&bare).unwrap();
    assert!(wire.get("endpoints").is_none());
    assert!(wire.get("limits").is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_carried_endpoint_is_what_goes_on_the_wire() {
    let Ok(responder) = AgentMesh::connect(URL, ConnectOptions { allow_unnamed: true, ..Default::default() }).await else {
        eprintln!("skipping resolve addressing: no NATS server at {URL}");
        return;
    };
    let Ok(requester) = AgentMesh::connect(URL, ConnectOptions { allow_unnamed: true, ..Default::default() }).await else {
        eprintln!("skipping resolve addressing: no NATS server at {URL}");
        return;
    };
    responder.on_request("echo", |input| async move { Ok(input) });
    let registered = responder
        .register(RegisterOptions { name: "resolved".into(), ..Default::default() })
        .await
        .expect("register");
    tokio::time::sleep(Duration::from_millis(150)).await;

    // `register` declares the endpoints block itself (§8.1: OPTIONAL on
    // registration, but this SDK carries it so resolution never falls back).
    assert_eq!(
        registered.resolved_inbox(),
        Some(format!("mesh.agent.{}.inbox", responder.id()).as_str())
    );

    // Resolution against the real manifest reaches the agent.
    let res = requester
        .request_with_options(
            responder.id(),
            "echo",
            json!({ "n": 1 }),
            RequestOptions { recipient: Some(registered.clone()), ..Default::default() },
        )
        .await
        .expect("resolved endpoint answers");
    assert_eq!(res.payload["status"], json!("completed"));

    // The proof it RESOLVED rather than constructed: a manifest whose carried
    // inbox names an unserved subject fails with AGENT_UNAVAILABLE, even
    // though the constructible subject is being served right now.
    let mut detoured = registered;
    detoured.endpoints = Some(Endpoints {
        inbox: Some(format!("mesh.agent.{}.inbox.moved", responder.id())),
        other: Default::default(),
    });
    let err = requester
        .request_with_options(
            responder.id(),
            "echo",
            json!({ "n": 2 }),
            RequestOptions {
                recipient: Some(detoured),
                timeout: Some(Duration::from_secs(2)),
                ..Default::default()
            },
        )
        .await
        .expect_err("the carried (unserved) subject was addressed, not the constructed one");
    match &err {
        MeshError::Protocol { code, .. } => {
            assert_eq!(*code, ErrorCode::AgentUnavailable.as_str(), "got: {err}")
        }
        other => panic!("expected AGENT_UNAVAILABLE, got {other}"),
    }

    requester.close().await;
    responder.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_declared_cap_preflights_locally_with_the_recipients_code() {
    // §6.4b + §8.1 end to end: the recipient's DECLARED cap, carried in the
    // manifest a caller holds, refuses locally — nothing is published — with
    // the same code the recipient's §22.5 would have answered.
    let Ok(requester) = AgentMesh::connect(URL, ConnectOptions { allow_unnamed: true, ..Default::default() }).await else {
        eprintln!("skipping resolve addressing: no NATS server at {URL}");
        return;
    };
    let mut manifest = manifest_for("UNOBODY", None, "mesh.agent.UNOBODY.inbox");
    manifest.limits = Some(Limits { max_inbound_chars: Some(8) });
    let err = requester
        .request_with_options(
            "UNOBODY",
            "echo",
            json!({ "text": "nine char" }), // 9 > 8
            RequestOptions { recipient: Some(manifest), ..Default::default() },
        )
        .await
        .expect_err("refused before publishing");
    let eo = err.error_object().expect("pre-flight refusals keep the wire object");
    assert_eq!(eo.code, ErrorCode::ContextTooLarge.as_str());
    assert!(!eo.retryable);
    requester.close().await;
}
