//! The naming rule on the sending side (`agentmesh::naming_gate`), against
//! `conformance/naming-gate.json`: the owner's words, the handle shape, the
//! proposals and the cache. Then the gate on a stand-in lookup and clock, the
//! registrar answer judged against signed and forged cards, the HTTP lookup
//! against a stand-in naming service, and end to end on a live broker when
//! one is reachable (`AGENTMESH_NATS_URL`, default nats://127.0.0.1:4222;
//! skipped otherwise): an agent connected with `require_named` refuses every
//! send it originates and sends once named.
//!
//! THE FIXTURE IS THE AUTHORITY. The TypeScript SDK and the reference adapter
//! read the same file.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use agentmesh::credential::BoxFuture;
use agentmesh::identity::canonical_json;
use agentmesh::{
    is_standard_handle, judge_resolve_answer, not_named_error, propose_handle, AgentMesh, ConnectOptions, ErrorCode,
    FeedKind, MeshError, NameCheck, NameLookup, NamingGate, RequireNamed, NAMED_TTL_MS, NAMING_STANDARD_WORDS,
    UNNAMED_TTL_MS,
};
use serde_json::{json, Value};

const FIXTURE_JSON: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/conformance/naming-gate.json"));

fn fixture() -> Value {
    serde_json::from_str(FIXTURE_JSON).expect("conformance/naming-gate.json parses")
}

fn code_of(e: &MeshError) -> String {
    e.error_object().map(|o| o.code.clone()).unwrap_or_default()
}

#[test]
fn the_words_codes_and_cache_are_the_fixtures() {
    let f = fixture();
    assert_eq!(NAMING_STANDARD_WORDS, f["words"].as_str().unwrap());
    assert_eq!(
        NAMING_STANDARD_WORDS,
        format!("{} This agent does not have one yet, so nothing was sent.", f["naming_standard"].as_str().unwrap())
    );
    assert_eq!(ErrorCode::NotNamed.as_str(), f["code"].as_str().unwrap());
    assert_eq!(f["outage"], "send");
    assert_eq!(NAMED_TTL_MS, f["cache"]["named_ttl_ms"].as_i64().unwrap());
    assert_eq!(UNNAMED_TTL_MS, f["cache"]["unnamed_ttl_ms"].as_i64().unwrap());
    assert!(!NAMING_STANDARD_WORDS.contains('\u{2014}'), "no em dash in the words");
}

#[test]
fn the_handle_shape_is_the_fixtures() {
    let f = fixture();
    for h in f["standard"].as_array().unwrap() {
        assert!(is_standard_handle(h.as_str().unwrap()), "{h} follows the standard");
    }
    for h in f["not_standard"].as_array().unwrap() {
        assert!(!is_standard_handle(h.as_str().unwrap()), "{h} does not");
    }
}

#[test]
fn the_proposals_are_the_fixtures() {
    for p in fixture()["proposals"].as_array().unwrap() {
        let got = propose_handle(p["name"].as_str(), p["email"].as_str());
        assert_eq!(got.handle, p["handle"].as_str().unwrap(), "proposal for {p}");
        assert_eq!(got.name.as_deref(), p["proposed_name"].as_str(), "name part for {p}");
    }
}

#[test]
fn the_refusal_opens_with_the_words_then_the_proposal() {
    let e = not_named_error(Some("Genesis"), Some("stephen@example.com"));
    let o = e.error_object().expect("a structured refusal");
    assert_eq!(o.code, "NOT_NAMED");
    assert!(!o.retryable);
    assert!(o.message.starts_with(NAMING_STANDARD_WORDS));
    assert!(o.message.contains("The proposed name is genesis.stephen@example.com, and stephen@example.com confirms it with a code we email."));
    assert!(o.message.contains("completeNaming with the code and the name \"genesis\""));
    assert_eq!(o.details.as_ref().unwrap()["proposed_handle"], "genesis.stephen@example.com");
}

/// A lookup that answers from a list (the last answer repeats) and counts.
struct Scripted {
    answers: Mutex<Vec<NameCheck>>,
    asked: AtomicI64,
}
impl Scripted {
    fn new(answers: Vec<NameCheck>) -> Arc<Self> {
        Arc::new(Self { answers: Mutex::new(answers), asked: AtomicI64::new(0) })
    }
    fn set(&self, a: NameCheck) {
        *self.answers.lock().unwrap() = vec![a];
    }
    fn asked(&self) -> i64 {
        self.asked.load(Ordering::SeqCst)
    }
}
impl NameLookup for Scripted {
    fn lookup<'a>(&'a self, _agent_id: &'a str) -> BoxFuture<'a, NameCheck> {
        Box::pin(async move {
            self.asked.fetch_add(1, Ordering::SeqCst);
            let mut a = self.answers.lock().unwrap();
            if a.len() > 1 { a.remove(0) } else { a[0].clone() }
        })
    }
}

fn gate(lookup: Arc<Scripted>, last: Option<&str>) -> (NamingGate, Arc<AtomicI64>) {
    let t = Arc::new(AtomicI64::new(1_000_000));
    let clock = t.clone();
    let cfg = RequireNamed {
        lookup,
        name: Some("Genesis".into()),
        owner_email: Some("stephen@example.com".into()),
        last_verified: last.map(str::to_string),
    };
    (NamingGate::with_clock("UAGENT", cfg, Arc::new(move || clock.load(Ordering::SeqCst))), t)
}

#[tokio::test]
async fn a_named_agent_passes_and_the_answer_is_kept() {
    let l = Scripted::new(vec![NameCheck::Named("genesis.stephen@example.com".into())]);
    let (g, t) = gate(l.clone(), None);
    g.require().await.unwrap();
    t.fetch_add(NAMED_TTL_MS - 1, Ordering::SeqCst);
    g.require().await.unwrap();
    assert_eq!(l.asked(), 1);
    t.fetch_add(2, Ordering::SeqCst);
    g.require().await.unwrap();
    assert_eq!(l.asked(), 2);
}

#[tokio::test]
async fn an_unnamed_agent_is_refused_and_sends_soon_after_naming() {
    let l = Scripted::new(vec![NameCheck::Unnamed(None), NameCheck::Named("genesis.stephen@example.com".into())]);
    let (g, t) = gate(l.clone(), None);
    assert_eq!(code_of(&g.require().await.unwrap_err()), "NOT_NAMED");
    assert_eq!(code_of(&g.require().await.unwrap_err()), "NOT_NAMED");
    assert_eq!(l.asked(), 1);
    t.fetch_add(UNNAMED_TTL_MS, Ordering::SeqCst);
    g.require().await.unwrap();
    assert_eq!(l.asked(), 2);
}

#[tokio::test]
async fn a_handle_in_the_wrong_shape_is_not_a_name() {
    let l = Scripted::new(vec![NameCheck::Named("genesis".into())]);
    let (g, _) = gate(l, None);
    assert_eq!(code_of(&g.require().await.unwrap_err()), "NOT_NAMED");
}

#[tokio::test]
async fn an_outage_lets_the_send_through_and_is_asked_again_soon() {
    let with_last = Scripted::new(vec![NameCheck::Unreachable]);
    let (g, _) = gate(with_last, Some("genesis.stephen@example.com"));
    g.require().await.unwrap();
    let s = g.current().unwrap();
    assert!(s.unchecked && s.named);
    assert_eq!(s.handle.as_deref(), Some("genesis.stephen@example.com"));

    let l = Scripted::new(vec![NameCheck::Unreachable, NameCheck::Unnamed(None)]);
    let (g, t) = gate(l.clone(), None);
    g.require().await.unwrap(); // an outage is not evidence of no name
    t.fetch_add(UNNAMED_TTL_MS, Ordering::SeqCst);
    assert_eq!(code_of(&g.require().await.unwrap_err()), "NOT_NAMED");
    assert_eq!(l.asked(), 2);
}

#[tokio::test]
async fn forget_makes_the_next_send_ask_again() {
    let l = Scripted::new(vec![NameCheck::Unnamed(None), NameCheck::Named("genesis.stephen@example.com".into())]);
    let (g, _) = gate(l.clone(), None);
    assert!(g.require().await.is_err());
    g.forget();
    g.require().await.unwrap();
    assert_eq!(l.asked(), 2);
}

fn signed(card: &Value, by: &nkeys::KeyPair, claimed_key: &str) -> Value {
    use base64::Engine as _;
    let sig = by.sign(canonical_json(card).as_bytes()).unwrap();
    json!({ "ok": true, "card": card, "registrar_key": claimed_key, "registrar_sig": base64::engine::general_purpose::STANDARD.encode(sig) })
}
fn card_for(agent: &str, handle: &str) -> Value {
    json!({ "handle": handle, "operator": { "name": "T" }, "endpoints": [{ "protocol": "agentmesh", "agent_id": agent }] })
}

#[test]
fn a_registrar_answer_is_judged_on_its_signature_and_binding() {
    let reg = nkeys::KeyPair::new_account();
    let forger = nkeys::KeyPair::new_account();
    let keys = vec![reg.public_key()];
    let named = signed(&card_for("UAGENT", "genesis.stephen@example.com"), &reg, &reg.public_key());
    assert_eq!(judge_resolve_answer("UAGENT", 200, Some(&named), &keys), NameCheck::Named("genesis.stephen@example.com".into()));
    let shape = signed(&card_for("UAGENT", "genesis"), &reg, &reg.public_key());
    assert_eq!(judge_resolve_answer("UAGENT", 200, Some(&shape), &keys), NameCheck::Unnamed(Some("genesis".into())));
    assert_eq!(judge_resolve_answer("UAGENT", 404, None, &keys), NameCheck::Unnamed(None));
    let forged = signed(&card_for("UAGENT", "genesis.stephen@example.com"), &forger, &reg.public_key());
    assert_eq!(judge_resolve_answer("UAGENT", 200, Some(&forged), &keys), NameCheck::Unreachable, "a forged signature is not a name");
    let own_key = signed(&card_for("UAGENT", "genesis.stephen@example.com"), &forger, &forger.public_key());
    assert_eq!(judge_resolve_answer("UAGENT", 200, Some(&own_key), &keys), NameCheck::Unreachable, "a key the registrar does not publish is not trusted");
    let unbound = signed(&card_for("USOMEONEELSE", "genesis.stephen@example.com"), &reg, &reg.public_key());
    assert_eq!(judge_resolve_answer("UAGENT", 200, Some(&unbound), &keys), NameCheck::Unreachable, "a card for another key is not this agent's name");
    assert_eq!(judge_resolve_answer("UAGENT", 503, None, &keys), NameCheck::Unreachable);
}

/// A stand-in naming service on loopback: two routes, one answer each time.
async fn serve(reg: Arc<nkeys::KeyPair>, answer: Arc<Mutex<(u16, Value)>>) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else { return };
            let reg = reg.clone();
            let answer = answer.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let n = sock.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let (status, body) = if req.starts_with("GET /api/registrar-key") {
                    (200, json!({ "keys": [reg.public_key()] }))
                } else {
                    answer.lock().unwrap().clone()
                };
                let text = body.to_string();
                let resp = format!("HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{text}", text.len());
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn the_http_lookup_reads_a_real_answer() {
    let reg = Arc::new(nkeys::KeyPair::new_account());
    let answer = Arc::new(Mutex::new((404u16, json!({ "ok": false }))));
    let url = serve(reg.clone(), answer.clone()).await;
    let lookup = agentmesh::RegistrarNameLookup::new(Some(&url));
    assert_eq!(lookup.lookup("UAGENT").await, NameCheck::Unnamed(None));
    *answer.lock().unwrap() = (200, signed(&card_for("UAGENT", "genesis.stephen@example.com"), &reg, &reg.public_key()));
    assert_eq!(lookup.lookup("UAGENT").await, NameCheck::Named("genesis.stephen@example.com".into()));
    *answer.lock().unwrap() = (503, json!({}));
    assert_eq!(lookup.lookup("UAGENT").await, NameCheck::Unreachable);
    assert_eq!(agentmesh::RegistrarNameLookup::new(Some("http://127.0.0.1:9")).lookup("UAGENT").await, NameCheck::Unreachable);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_live_agent_refuses_every_send_until_named() {
    let url = std::env::var("AGENTMESH_NATS_URL").unwrap_or_else(|_| "nats://127.0.0.1:4222".into());
    let lookup = Scripted::new(vec![NameCheck::Unnamed(None)]);
    let cfg = RequireNamed { lookup: lookup.clone(), name: Some("Genesis".into()), owner_email: Some("stephen@example.com".into()), last_verified: None };
    let mesh = match AgentMesh::connect(&url, ConnectOptions { allow_unnamed: true, require_named: Some(cfg), ..Default::default() }).await {
        Ok(m) => m,
        Err(_) => {
            eprintln!("skipping the live naming gate: no NATS server at {url}");
            return;
        }
    };
    let peer = nkeys::KeyPair::new_user().public_key();
    let e = mesh.request(&peer, "chat", json!({ "text": "hi" })).await.unwrap_err();
    assert_eq!(code_of(&e), "NOT_NAMED");
    assert!(e.error_object().unwrap().message.starts_with(NAMING_STANDARD_WORDS));
    assert_eq!(code_of(&mesh.emit("build.done", json!({})).await.unwrap_err()), "NOT_NAMED");
    assert_eq!(code_of(&mesh.publish_feed("status", json!({ "up": true }), FeedKind::State).await.unwrap_err()), "NOT_NAMED");
    match mesh.request_stream(&peer, "chat", json!({ "prompt": "hi" }), false).await {
        Err(e) => assert_eq!(code_of(&e), "NOT_NAMED"),
        Ok(_) => panic!("a stream from an unnamed agent was opened"),
    }
    assert!(!mesh.naming_status().unwrap().named);

    lookup.set(NameCheck::Named("genesis.stephen@example.com".into()));
    let s = mesh.recheck_name().await.unwrap();
    assert!(s.named);
    mesh.emit("build.done", json!({})).await.expect("a named agent sends");
    mesh.publish_feed("status", json!({ "up": true }), FeedKind::State).await.expect("and publishes");
    mesh.close().await;

    // An agent that turned the rule off (tests only) is untouched by it.
    let plain = AgentMesh::connect(&url, ConnectOptions { allow_unnamed: true, ..Default::default() }).await.unwrap();
    assert!(plain.naming_status().is_none());
    plain.emit("build.done", json!({})).await.unwrap();
    plain.close().await;
}

/// 2026-09-27, no anonymous agents: with nothing said, `connect` asks the
/// default naming service (the rule is on by default); `allow_unnamed` is the
/// only way off. Pinned on the builder the default feeds, since `connect`
/// itself needs a live transport.
#[cfg(feature = "http")]
#[test]
fn the_rule_is_on_by_default() {
    assert!(RequireNamed::by_default().is_some(), "with the http feature the default asks the naming service");
    assert!(!ConnectOptions::default().allow_unnamed, "and nothing turns it off unless asked");
}
