//! A stand-in for the platform's service door, for the request tests
//! (tests/services_shapes_generated.rs and tests/services_door.rs): it keeps
//! what each request sent and answers with what it was given, and it checks
//! a request the way the platform does (services/src/platform-services/door.ts).

#![allow(dead_code)]

use std::sync::{Arc, Mutex};

use agentmesh::credential::BoxFuture;
use agentmesh::services::{signed_canonical, ServiceCaller, ServiceHttpResponse, ServiceTransport, SignFn};
use agentmesh::KeyPair;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Value};

/// One request the stand-in received.
#[derive(Debug, Clone)]
pub struct Sent {
    pub url: String,
    pub bearer: Option<String>,
    pub body: Value,
}

/// The stand-in: answers every POST with `status` and `body`.
pub struct StandIn {
    status: u16,
    body: Value,
    pub sent: Arc<Mutex<Vec<Sent>>>,
    key: Arc<KeyPair>,
}

struct Wire {
    status: u16,
    body: Value,
    sent: Arc<Mutex<Vec<Sent>>>,
}

impl ServiceTransport for Wire {
    fn post_json<'a>(&'a self, url: &'a str, bearer: Option<&'a str>, body: String) -> BoxFuture<'a, Result<ServiceHttpResponse, String>> {
        Box::pin(async move {
            self.sent.lock().unwrap().push(Sent { url: url.to_string(), bearer: bearer.map(str::to_string), body: serde_json::from_str(&body).unwrap() });
            Ok(ServiceHttpResponse { status: self.status, body: self.body.to_string() })
        })
    }

    fn get<'a>(&'a self, url: &'a str, bearer: Option<&'a str>) -> BoxFuture<'a, Result<ServiceHttpResponse, String>> {
        Box::pin(async move {
            self.sent.lock().unwrap().push(Sent { url: url.to_string(), bearer: bearer.map(str::to_string), body: Value::Null });
            Ok(ServiceHttpResponse { status: self.status, body: self.body.to_string() })
        })
    }
}

pub const API: &str = "https://api.example.test";

impl StandIn {
    /// Answers 200 with `body`.
    pub fn answering(body: Value) -> Self {
        Self { status: 200, body, sent: Arc::default(), key: Arc::new(KeyPair::new_user()) }
    }

    /// Answers the way the platform refuses: `{ refusal, error }` on a 4xx.
    pub fn refusing(code: &str) -> Self {
        Self { status: 422, body: json!({ "refusal": code, "error": format!("refused with {code}") }), sent: Arc::default(), key: Arc::new(KeyPair::new_user()) }
    }

    /// Answers with this status and body.
    pub fn raw(status: u16, body: Value) -> Self {
        Self { status, body, sent: Arc::default(), key: Arc::new(KeyPair::new_user()) }
    }

    /// The agent the caller signs as.
    pub fn agent(&self) -> String {
        self.key.public_key()
    }

    /// A caller that signs as this stand-in's agent and carries a key.
    pub fn caller(&self) -> ServiceCaller {
        let key = self.key.clone();
        let sign: SignFn = Arc::new(move |m: &str| {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.encode(key.sign(m.as_bytes()).unwrap())
        });
        ServiceCaller::new(Some(API), Some("am_key_for_tests"))
            .with_operator_key(Some("op_key_for_tests"))
            .with_transport(Arc::new(Wire { status: self.status, body: self.body.clone(), sent: self.sent.clone() }))
            .with_agent(&self.agent(), sign)
    }

    /// The one request sent: to the request's address, with its input, the
    /// key its definition calls for as the bearer ("Owner": the account's
    /// token, "Operator": the operator key, "Signature": none), and an agent
    /// signature the platform would accept.
    pub fn check_sent(&self, request: &str, input: Value, key: &str) {
        let sent = self.sent.lock().unwrap();
        assert_eq!(sent.len(), 1, "one request");
        let s = &sent[0];
        assert_eq!(s.url, format!("{API}/v1/svc/{request}"));
        let want = match key {
            "Owner" => Some("am_key_for_tests"),
            "Operator" => Some("op_key_for_tests"),
            _ => None,
        };
        assert_eq!(s.bearer.as_deref(), want, "the key rides only with the requests that need it");
        assert_eq!(s.body["input"], input);
        assert_eq!(s.body["door"], "sdk");
        assert_eq!(s.body["agent"], self.agent());
        let ts = s.body["ts"].as_str().unwrap();
        let nonce = s.body["nonce"].as_str().unwrap();
        let canonical = signed_canonical(&self.agent(), request, ts, nonce, &s.body["input"]);
        use base64::Engine as _;
        let sig = base64::engine::general_purpose::STANDARD.decode(s.body["sig"].as_str().unwrap()).unwrap();
        KeyPair::from_public_key(&self.agent()).unwrap().verify(canonical.as_bytes(), &sig).expect("the signature holds");
    }
}

/// Reads `v` into `T` and writes it back: the same JSON.
pub fn round_trip<T: Serialize + DeserializeOwned>(v: Value) {
    let t: T = serde_json::from_value(v.clone()).unwrap_or_else(|e| panic!("{e}: {v}"));
    assert_eq!(serde_json::to_value(&t).unwrap(), v);
}
