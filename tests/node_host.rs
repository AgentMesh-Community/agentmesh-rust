//! Node-host test (§4.1): one MeshNode, one connection, two hosted agents that
//! exchange a request. Requires nats-server on 127.0.0.1:4222 (skips gracefully
//! if absent).

use agentmesh::{
    verify_attestation, MeshNode, NodeConnectOptions, NodeDeclaredProfile, RegisterOptions,
};
use serde_json::json;

const URL: &str = "nats://127.0.0.1:4222";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_node_hosts_two_agents_over_one_connection() {
    // Skip if no server is reachable.
    let node = match MeshNode::connect(
        URL,
        NodeConnectOptions {
            profile: Some(NodeDeclaredProfile {
                availability_class: Some("always_on".into()),
                reachability: Some("direct".into()),
                ..Default::default()
            }),
            ..Default::default()
        },
    )
    .await
    {
        Ok(n) => n,
        Err(_) => {
            eprintln!("skipping node_host e2e: no NATS server at {URL}");
            return;
        }
    };

    // Two hosted agents: distinct keypairs, neither is the node, one connection.
    let responder = node.add_agent(None).expect("add responder");
    let requester = node.add_agent(None).expect("add requester");
    assert_ne!(responder.id(), requester.id());
    assert_ne!(responder.id(), node.id());

    let responder_id = responder.id().to_string();
    responder.on_request("echo", |input| async move { Ok(json!({ "echoed": input })) });
    let manifest = responder
        .register(RegisterOptions {
            name: "hosted-responder".into(),
            capabilities: vec!["echo".into()],
            ..Default::default()
        })
        .await
        .expect("register");

    // The manifest is vouched by the NODE key and carries the node's profile.
    assert_eq!(manifest.node.id, node.id());
    assert!(verify_attestation(&manifest.node.attestation, Some(&responder_id)));
    let profile = manifest.node.profile.as_ref().expect("node profile attached");
    assert_eq!(profile.availability_class.as_deref(), Some("always_on"));

    // One node heartbeat covers both agents.
    node.send_heartbeat().await.expect("heartbeat");

    // Hosted agent → hosted agent request over the shared connection.
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    let res = requester
        .request(&responder_id, "echo", json!({ "hi": "from-shared-conn" }))
        .await
        .expect("request");
    assert!(res.task_id.is_none());
    assert_eq!(res.payload["status"], "completed");
    assert_eq!(res.payload["output"], json!({ "echoed": { "hi": "from-shared-conn" } }));
    assert_eq!(res.envelope.from, responder_id);

    // Closing one hosted agent detaches it but leaves the shared connection
    // usable: the requester can still operate.
    responder.close().await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let err = requester
        .request(&responder_id, "echo", json!({ "hi": "again" }))
        .await;
    assert!(err.is_err(), "detached responder no longer answers");
    // The shared connection itself is still alive (heartbeat still publishes).
    node.send_heartbeat().await.expect("connection still open after agent close");

    node.close().await;
}

/// Authenticated connect (§18.2): node JWT + nonce signing with the node key.
/// Gated on env vars (set by CI or a local operator-auth server); skips otherwise.
///   AGENTMESH_TEST_URL, AGENTMESH_TEST_JWT, AGENTMESH_TEST_SEED
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_connects_with_jwt_credential() {
    let (url, jwt, seed) = match (
        std::env::var("AGENTMESH_TEST_URL"),
        std::env::var("AGENTMESH_TEST_JWT"),
        std::env::var("AGENTMESH_TEST_SEED"),
    ) {
        (Ok(u), Ok(j), Ok(s)) => (u, j, s),
        _ => {
            eprintln!("skipping jwt auth e2e: AGENTMESH_TEST_URL/JWT/SEED not set");
            return;
        }
    };

    let node = MeshNode::connect(
        &url,
        NodeConnectOptions { node_seed: Some(seed), jwt: Some(jwt), ..Default::default() },
    )
    .await
    .expect("authenticated node connect");

    // Prove the authenticated connection works: publish a heartbeat and host an agent.
    node.send_heartbeat().await.expect("publish over authenticated connection");
    let agent = node.add_agent(None).expect("hosted agent");
    assert_ne!(agent.id(), node.id());
    node.close().await;
}
