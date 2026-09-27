//! The built-in HTTP transport (§4.8, default `http` feature).
//!
//! Why this file exists. The first cut of node-credential renewal shipped only
//! the `CredentialTransport` trait, on the reasoning that a NATS SDK should not
//! grow an HTTP client for one POST a month. That reasoning was right about the
//! dependency and wrong about the outcome: a TypeScript embedder gets renewal
//! by upgrading, and a Rust one would have got an interface plus the job of
//! choosing a timeout, deciding about retries, and reproducing the signing
//! contract byte for byte against a verifier it cannot see. The first symptom
//! of getting the last one wrong is an agent that cannot renew — twenty days
//! after anyone last looked at the code.
//!
//! So the default build ships a transport, and these tests hold it to the same
//! contract the injected ones in `credential_renewal.rs` are held to. Over a
//! real socket, deliberately: "renewal works out of the box" is the claim
//! parity rests on, and a mock transport cannot make it. The stub server here
//! verifies the signatures the way the control plane does, so this fails if the
//! transport ever mangles the bytes on the way out.

use std::sync::{Arc, Mutex};

use agentmesh::{
    create_agent_identity, CredentialRenewer, CredentialRenewerOptions, RenewalAgent,
    RenewalRoster,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

// Split by feature so BOTH configurations build warning-clean. The socket tests
// and the signature checks only exist when there is a built-in transport to
// drive; the warning-sink test only exists when there is not.
#[cfg(feature = "http")]
use agentmesh::{agent_consent_line, node_credential_line, KeyPair};
#[cfg(feature = "http")]
use base64::engine::general_purpose::STANDARD;
#[cfg(feature = "http")]
use std::time::Duration;
#[cfg(not(feature = "http"))]
use agentmesh::SecurityWarning;

/// A NATS user JWT of the real shape. The signature is never verified here —
/// only the broker can check it against the account chain (§4.8).
fn jwt(sub: &str, iat: Option<i64>, exp: Option<i64>) -> String {
    let header = serde_json::json!({ "typ": "JWT", "alg": "ed25519-nkey" });
    let mut claims = serde_json::json!({
        "sub": sub,
        "name": "node",
        "nats": { "type": "user", "version": 2 },
    });
    if let Some(iat) = iat {
        claims["iat"] = serde_json::json!(iat);
    }
    if let Some(exp) = exp {
        claims["exp"] = serde_json::json!(exp);
    }
    let seg = |v: &serde_json::Value| URL_SAFE_NO_PAD.encode(v.to_string().as_bytes());
    format!(
        "{}.{}.{}",
        seg(&header),
        seg(&claims),
        URL_SAFE_NO_PAD.encode([0u8; 64])
    )
}

/// The shared per-request deadline, and the fact that it is SHARED.
///
/// The TS SDK exports `CREDENTIAL_REQUEST_TIMEOUT_MS` with the same value. The
/// two must behave identically under the same failure, so the number is pinned
/// on both sides rather than left to each client's default — Node's `fetch` has
/// no overall deadline at all, which is exactly why TypeScript had to state one
/// too. It matters because while a request hangs the renewer holds its
/// in-flight guard and the periodic loop stops retrying, so one stalled socket
/// would quietly consume the whole renewal window.
#[test]
fn the_request_deadline_is_fifteen_seconds_in_both_sdks() {
    assert_eq!(agentmesh::CREDENTIAL_REQUEST_TIMEOUT_MS, 15_000);
}

/// The feature is ON by default, and that is a deliberate default rather than
/// an accident of Cargo: renewal has to work for a host that did nothing but
/// depend on the crate, because a credential that cannot be renewed stops
/// working. A `default-features = false` build gets `None` and must supply its
/// own transport.
#[test]
fn the_default_build_has_a_transport() {
    let has = agentmesh::default_credential_transport().is_some();
    assert_eq!(
        has,
        cfg!(feature = "http"),
        "default_credential_transport() must be Some exactly when the `http` feature is on"
    );
    #[cfg(feature = "http")]
    assert!(
        has,
        "the `http` feature is on by default; renewal must work out of the box"
    );
}

/// With the feature off and no transport supplied, the renewer says so at
/// construction — loudly and immediately, because the alternative is a renewer
/// that looks armed and discovers it cannot renew twenty days later, when the
/// omission is very hard to connect to its cause.
#[cfg(not(feature = "http"))]
#[test]
fn a_transportless_renewer_warns_at_construction() {
    let (node_id, node_seed) = create_agent_identity().unwrap();
    let seen: Arc<Mutex<Vec<SecurityWarning>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = seen.clone();
    let _renewer = CredentialRenewer::new(CredentialRenewerOptions {
        api_base: "https://api.agentmesh.ai".into(),
        jwt: jwt(&node_id, Some(1_700_000_000), Some(1_702_592_000)),
        node_seed: node_seed.clone(),
        agents: RenewalRoster::Fixed(vec![RenewalAgent::with_seed(&node_id, &node_seed)]),
        transport: None,
        on_renewed: None,
        on_warning: Some(Arc::new(move |w| sink.lock().unwrap().push(w))),
    });
    let warnings = seen.lock().unwrap();
    assert_eq!(warnings.len(), 1);
    assert_eq!(warnings[0].code, "credential_renewal_unavailable");
    assert!(
        warnings[0].message.contains("`http` feature"),
        "{}",
        warnings[0].message
    );
}

/// A minimal HTTP/1.1 stub. Reads one request (headers, then the declared body),
/// hands it back through `captured`, and answers with `status` and `payload`.
#[cfg(feature = "http")]
async fn stub_server(
    status: &'static str,
    payload: String,
    captured: Arc<Mutex<Option<(String, String)>>>,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = Vec::new();
        let head_end = loop {
            let mut chunk = [0u8; 1024];
            let n = sock.read(&mut chunk).await.unwrap();
            if n == 0 {
                break buf.len();
            }
            buf.extend_from_slice(&chunk[..n]);
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
        };
        let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
        let len: usize = head
            .lines()
            .find_map(|l| {
                let lower = l.to_ascii_lowercase();
                lower
                    .strip_prefix("content-length:")
                    .map(|v| v.trim().to_string())
            })
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        while buf.len() < head_end + len {
            let mut chunk = [0u8; 1024];
            let n = sock.read(&mut chunk).await.unwrap();
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        let body = String::from_utf8_lossy(&buf[head_end..]).to_string();
        *captured.lock().unwrap() = Some((head, body));

        let res = format!(
            "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            payload.len(),
            payload
        );
        let _ = sock.write_all(res.as_bytes()).await;
        let _ = sock.flush().await;
    });
    (addr, handle)
}

/// The real thing: a renewer that names NO transport, renewing over a socket.
///
/// This is the parity claim under test. `transport: None` plus an `api_base` is
/// all a Rust host writes, exactly as `credentialRenewal: { apiBase }` is all a
/// TypeScript one writes.
#[cfg(feature = "http")]
#[tokio::test]
async fn the_built_in_transport_renews_over_a_real_socket() {
    let (node_id, node_seed) = create_agent_identity().unwrap();
    let (agent_id, agent_seed) = create_agent_identity().unwrap();
    let fresh = jwt(&node_id, Some(1_700_000_000), Some(1_702_592_000));

    let captured: Arc<Mutex<Option<(String, String)>>> = Arc::new(Mutex::new(None));
    let payload = serde_json::json!({
        "ok": true,
        "jwt": fresh,
        "node_id": "echoed-node",
        "agents": ["echoed-agent"],
        "expires_at": "2026-09-07T00:00:00Z",
    })
    .to_string();
    let (addr, server) = stub_server("200 OK", payload, captured.clone()).await;

    let renewer = CredentialRenewer::new(CredentialRenewerOptions {
        api_base: format!("http://{addr}"),
        // Long expired, so this is also the lapsed-credential path: renewal
        // presents nothing about the credential in hand, so its state cannot
        // stop it.
        jwt: jwt(&node_id, Some(1_600_000_000), Some(1_600_000_060)),
        node_seed: node_seed.clone(),
        agents: RenewalRoster::Fixed(vec![RenewalAgent::with_seed(&agent_id, &agent_seed)]),
        // THE POINT: no transport named. The default build supplies one.
        transport: None,
        on_renewed: None,
        on_warning: None,
    });

    let out = tokio::time::timeout(Duration::from_secs(10), renewer.renew())
        .await
        .expect("the built-in transport must complete well inside its own deadline")
        .expect("renewal must succeed against a live endpoint");

    // The response was parsed, not merely received.
    assert_eq!(out.jwt, fresh);
    assert_eq!(out.node_id, "echoed-node");
    assert_eq!(out.expires_at.as_deref(), Some("2026-09-07T00:00:00Z"));
    // And adopted: the renewer now holds the fresh credential.
    assert_eq!(renewer.credential(), fresh);

    server.await.unwrap();
    let (head, body) = captured.lock().unwrap().clone().expect("the server saw a request");

    // The request shape the control plane expects.
    assert!(head.starts_with("POST /v1/node-credential HTTP/1.1"), "{head}");
    assert!(
        head.to_ascii_lowercase().contains("content-type: application/json"),
        "{head}"
    );

    // And the body is the real signed request, verified the way the server
    // verifies it — so this fails if the transport ever mangles the bytes.
    let sent: serde_json::Value = serde_json::from_str(&body).expect("a JSON body");
    let ts = sent["ts"].as_i64().unwrap();
    assert_eq!(sent["node_id"].as_str().unwrap(), node_id);
    let node_kp = KeyPair::from_public_key(&node_id).unwrap();
    let node_sig = STANDARD.decode(sent["node_sig"].as_str().unwrap()).unwrap();
    node_kp
        .verify(
            node_credential_line(ts, &node_id, &[&agent_id]).as_bytes(),
            &node_sig,
        )
        .expect("the node's roster signature must verify");
    let agent_kp = KeyPair::from_public_key(&agent_id).unwrap();
    let agent_sig = STANDARD
        .decode(sent["agents"][0]["sig"].as_str().unwrap())
        .unwrap();
    agent_kp
        .verify(
            agent_consent_line(ts, &node_id, &agent_id).as_bytes(),
            &agent_sig,
        )
        .expect("the agent's consent signature must verify");
}

/// A refusal reaches the caller as the mesh's own words, through the built-in
/// transport as much as through an injected one. §4.8 makes refusal the shape
/// of revocation, so "retired or revoked" must survive the trip rather than
/// being flattened to "HTTP 403" — that string is the difference between an
/// operator retrying and an operator understanding.
#[cfg(feature = "http")]
#[tokio::test]
async fn the_built_in_transport_carries_a_refusal_verbatim() {
    let (node_id, node_seed) = create_agent_identity().unwrap();
    let captured: Arc<Mutex<Option<(String, String)>>> = Arc::new(Mutex::new(None));
    let payload = serde_json::json!({
        "error": "agent UABCDEFGHIJK… has been retired or revoked (retired by owner)",
    })
    .to_string();
    let (addr, server) = stub_server("403 Forbidden", payload, captured).await;

    let renewer = CredentialRenewer::new(CredentialRenewerOptions {
        api_base: format!("http://{addr}"),
        jwt: jwt(&node_id, Some(1_600_000_000), Some(1_600_000_060)),
        node_seed: node_seed.clone(),
        agents: RenewalRoster::Fixed(vec![RenewalAgent::with_seed(&node_id, &node_seed)]),
        transport: None,
        on_renewed: None,
        on_warning: None,
    });

    let err = tokio::time::timeout(Duration::from_secs(10), renewer.renew())
        .await
        .expect("must not hang")
        .expect_err("a 403 is a refusal, not a success");
    assert!(err.to_string().contains("retired or revoked"), "{err}");
    // The credential in hand is untouched by a refusal: it keeps working until
    // it expires, which is the honest window §4.8 states.
    assert!(!renewer.credential().is_empty());
    let _ = server.await;
}

/// An unreachable mesh reads as unreachable. Nothing is listening on this port,
/// so the connect fails, and the message has to say the mesh could not be
/// reached rather than surfacing a raw client error — this text lands in an
/// operator's warning about a lapsing credential.
#[cfg(feature = "http")]
#[tokio::test]
async fn an_unreachable_mesh_reads_as_unreachable() {
    let (node_id, node_seed) = create_agent_identity().unwrap();
    // Bind and immediately drop, so the port is almost certainly closed.
    let addr = {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap()
    };
    let renewer = CredentialRenewer::new(CredentialRenewerOptions {
        api_base: format!("http://{addr}"),
        jwt: jwt(&node_id, Some(1_600_000_000), Some(1_600_000_060)),
        node_seed: node_seed.clone(),
        agents: RenewalRoster::Fixed(vec![RenewalAgent::with_seed(&node_id, &node_seed)]),
        transport: None,
        on_renewed: None,
        on_warning: None,
    });
    let err = tokio::time::timeout(Duration::from_secs(20), renewer.renew())
        .await
        .expect("the transport's own deadline must bound this, not the test harness")
        .expect_err("nothing is listening");
    assert!(err.to_string().contains("could not reach the mesh"), "{err}");
}
