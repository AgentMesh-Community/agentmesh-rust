//! The platform's services and the mesh's own requests, one method per
//! request: `mesh.schedules().create(input)`, `mesh.rooms().open(input)`.
//!
//! Every request is defined once, in `platform-services/<service>.json` at the
//! top of the repository, and `node platform-services/gen.mjs` writes this
//! SDK's half from it (`services_generated.rs`): a struct for what each
//! request sends and one for what it answers, an enum of the refusals it can
//! answer with, and a method per request on a type per service. The same
//! definitions make the TypeScript SDK's `mesh.<service>.<request>()`, the
//! adapter's MCP tools and commands, and the hosted connector's tools, so the
//! names, the fields and the refusals are the same on every door.
//!
//! Why a method per service rather than one per request on [`AgentMesh`]: a
//! service is a group of requests that share who may call them and what they
//! cost, and `mesh.rooms().open(..)` reads the way the other doors name it
//! (`rooms_open`, `agentmesh rooms open`, `mesh.rooms.open()`). The getter is
//! cheap: it borrows the agent, or carries a clone of its caller, and holds no
//! connection of its own.
//!
//! Two kinds of service:
//!
//! - **A platform service** (schedules, runs, jobs, memory and the rest): the
//!   platform answers. Each request is one POST to the platform's service door,
//!   `{api}/v1/svc/<service>.<request>`, signed by the agent's own key over the
//!   request's name, the time, a one-time nonce and a digest of what it sends.
//!   An account API token or an operator key may ride with it as the bearer
//!   (`ConnectOptions::platform_key`), for what only an owner or an operator
//!   may do. A program that is not an agent builds a [`ServiceCaller`] with the
//!   key alone.
//! - **A service done on the mesh** (rooms, board, reviews, and the mesh's own
//!   requests): the work happens in this agent's own connection. The code is
//!   hand-written in `mesh_doors/`, and the generated trait it implements holds
//!   it to the definition.
//!
//! A request answers with its result, or with a [`ServiceError`]: a
//! [`ServiceRefusal`] carries the code from the request's definition, which
//! the request's own refusal enum reads (`SchedulesCreateRefusal::from_code`).

use std::collections::HashSet;
use std::sync::{Arc, Mutex, OnceLock};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use crate::credential::BoxFuture;
use crate::error::MeshError;

pub use crate::services_generated::*;

// ── errors ──────────────────────────────────────────────────────────────────

/// A refusal: the code from the request's definition, and the words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceRefusal {
    /// The request, `<service>.<request>`.
    pub request: String,
    /// The refusal's code, one the request's definition names.
    pub code: String,
    /// What happened, in words a person can act on.
    pub message: String,
}

/// What a request answers with when it does not succeed.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    /// The request was refused, with one of its definition's codes.
    #[error("{} refused {}: {}", .0.request, .0.code, .0.message)]
    Refused(ServiceRefusal),
    /// The platform could not be reached, or answered with something that is not an answer.
    #[error("{0}")]
    Failed(String),
    /// The mesh failed underneath a request done on the mesh.
    #[error(transparent)]
    Mesh(#[from] MeshError),
}

impl ServiceError {
    /// A refusal of `request` with `code`.
    pub fn refused(request: &str, code: &str, words: impl Into<String>) -> Self {
        let message = words.into();
        ServiceError::Refused(ServiceRefusal {
            request: request.to_string(),
            code: code.to_string(),
            message: if message.trim().is_empty() { code.to_string() } else { message },
        })
    }

    /// The refusal, when it is one.
    pub fn refusal(&self) -> Option<&ServiceRefusal> {
        match self {
            ServiceError::Refused(r) => Some(r),
            _ => None,
        }
    }

    /// The refusal's code, when it is one.
    pub fn code(&self) -> Option<&str> {
        self.refusal().map(|r| r.code.as_str())
    }
}

// ── the wire ────────────────────────────────────────────────────────────────

/// The platform's answer to one POST: its HTTP status and its body.
pub struct ServiceHttpResponse {
    pub status: u16,
    pub body: String,
}

/// The one network operation a [`ServiceCaller`] needs. The default is the
/// built-in HTTPS client (feature `http`, on by default); a host that brings
/// its own client implements this, and the tests answer with a stand-in.
///
/// Return `Err` only when nothing answered (DNS, connect, TLS, a read that
/// failed, the time ran out). Any answer, a 500 among them, is a response.
pub trait ServiceTransport: Send + Sync {
    /// POST `body` (JSON) to `url`, with `bearer` as the authorization when given.
    fn post_json<'a>(&'a self, url: &'a str, bearer: Option<&'a str>, body: String) -> BoxFuture<'a, Result<ServiceHttpResponse, String>>;
    /// GET `url`, with `bearer` as the authorization when given. The mesh's
    /// own requests read the naming service with it.
    fn get<'a>(&'a self, url: &'a str, bearer: Option<&'a str>) -> BoxFuture<'a, Result<ServiceHttpResponse, String>>;
}

/// How long one request may take before it is given up: thirty seconds, the
/// TypeScript SDK's.
pub const SERVICE_REQUEST_TIMEOUT_MS: u64 = 30_000;

/// The built-in [`ServiceTransport`], over reqwest with rustls.
#[cfg(feature = "http")]
pub struct HttpServiceTransport {
    client: reqwest::Client,
}

#[cfg(feature = "http")]
impl HttpServiceTransport {
    /// A client with the request timeout set.
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(SERVICE_REQUEST_TIMEOUT_MS))
            .build()
            .unwrap_or_default();
        Self { client }
    }
}

#[cfg(feature = "http")]
impl Default for HttpServiceTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "http")]
impl ServiceTransport for HttpServiceTransport {
    fn post_json<'a>(&'a self, url: &'a str, bearer: Option<&'a str>, body: String) -> BoxFuture<'a, Result<ServiceHttpResponse, String>> {
        Box::pin(async move {
            let mut req = self.client.post(url).header("content-type", "application/json").body(body);
            if let Some(b) = bearer {
                req = req.header("authorization", format!("Bearer {b}"));
            }
            let res = req.send().await.map_err(|e| {
                if e.is_timeout() {
                    format!("the platform did not answer within {} seconds", SERVICE_REQUEST_TIMEOUT_MS / 1000)
                } else {
                    format!("the platform could not be reached: {e}")
                }
            })?;
            let status = res.status().as_u16();
            let bytes = res.bytes().await.map_err(|e| format!("the platform's answer could not be read: {e}"))?;
            Ok(ServiceHttpResponse { status, body: String::from_utf8_lossy(&bytes).into_owned() })
        })
    }

    fn get<'a>(&'a self, url: &'a str, bearer: Option<&'a str>) -> BoxFuture<'a, Result<ServiceHttpResponse, String>> {
        Box::pin(async move {
            let mut req = self.client.get(url);
            if let Some(b) = bearer {
                req = req.header("authorization", format!("Bearer {b}"));
            }
            let res = req.send().await.map_err(|e| format!("{url} could not be reached: {e}"))?;
            let status = res.status().as_u16();
            let bytes = res.bytes().await.map_err(|e| format!("the answer from {url} could not be read: {e}"))?;
            Ok(ServiceHttpResponse { status, body: String::from_utf8_lossy(&bytes).into_owned() })
        })
    }
}

/// The transport a caller uses when it is given none: the built-in HTTPS
/// client, or, without the `http` feature, one that says it has none.
pub fn default_service_transport() -> Arc<dyn ServiceTransport> {
    #[cfg(feature = "http")]
    {
        static SHARED: OnceLock<Arc<HttpServiceTransport>> = OnceLock::new();
        SHARED.get_or_init(|| Arc::new(HttpServiceTransport::new())).clone()
    }
    #[cfg(not(feature = "http"))]
    {
        Arc::new(NoTransport)
    }
}

#[cfg(not(feature = "http"))]
struct NoTransport;

#[cfg(not(feature = "http"))]
impl ServiceTransport for NoTransport {
    fn post_json<'a>(&'a self, _url: &'a str, _bearer: Option<&'a str>, _body: String) -> BoxFuture<'a, Result<ServiceHttpResponse, String>> {
        Box::pin(async { Err("this build has no HTTPS client (the http feature is off); give the caller a ServiceTransport".to_string()) })
    }

    fn get<'a>(&'a self, _url: &'a str, _bearer: Option<&'a str>) -> BoxFuture<'a, Result<ServiceHttpResponse, String>> {
        Box::pin(async { Err("this build has no HTTPS client (the http feature is off); give the caller a ServiceTransport".to_string()) })
    }
}

// ── signing ─────────────────────────────────────────────────────────────────

/// JSON with keys sorted at every level, the bytes the platform hashes
/// (services/src/platform-services/door.ts `stableJson`, the TypeScript SDK's
/// `stableJson`). For JSON values that is RFC 8785, which this crate already
/// uses for signatures.
pub fn stable_json(v: &Value) -> String {
    crate::identity::canonical_json(v)
}

/// What an agent signs for one request: `svc-v1:<agent>:<request>:<ts>:<nonce>:<sha256 of the input>`.
pub fn signed_canonical(agent: &str, request: &str, ts: &str, nonce: &str, input: &Value) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(stable_json(input).as_bytes());
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    format!("svc-v1:{agent}:{request}:{ts}:{nonce}:{hex}")
}

/// The time as JavaScript writes it, `2026-10-05T18:00:00.000Z`.
pub(crate) fn now_js() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// Which key, if any, a request carries beside the agent's signature. The
/// generated methods pass the one their definition calls for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyUse {
    /// The agent's signature alone. A caller that is not an agent sends its key.
    Signature,
    /// An owner's act (the definition's `account_scopes`): the account's API token.
    Owner,
    /// An operator's act (`operator_scopes`): the operator key.
    Operator,
    /// Whatever key the caller has.
    Always,
}

/// Signs a string with an agent's key: base64 of the Ed25519 signature.
pub type SignFn = Arc<dyn Fn(&str) -> String + Send + Sync>;

/// How a request reaches the platform's service door: the platform's address,
/// the keys that may ride as the bearer, the agent that signs, and the
/// transport. `mesh.<service>()` builds one from the agent; a program that is
/// not an agent builds one with a key: `ServiceCaller::new(api, Some(key)).errors().list(..)`.
#[derive(Clone)]
pub struct ServiceCaller {
    api: String,
    key: Option<String>,
    operator_key: Option<String>,
    agent: Option<(String, SignFn)>,
    door: String,
    transport: Arc<dyn ServiceTransport>,
}

impl ServiceCaller {
    /// A caller for the platform at `api` (this environment's when `None`),
    /// carrying `key`: an account API token for an owner's acts, or, for a
    /// program that is not an agent, whatever key it has.
    pub fn new(api: Option<&str>, key: Option<&str>) -> Self {
        Self {
            api: api.unwrap_or(crate::env_generated::AM_URL_API).trim_end_matches('/').to_string(),
            key: key.map(str::to_string),
            operator_key: None,
            agent: None,
            door: "sdk".to_string(),
            transport: default_service_transport(),
        }
    }

    /// Sign each request as this agent: its key (the agent id) and a signer.
    pub fn with_agent(mut self, agent_id: &str, sign: SignFn) -> Self {
        self.agent = Some((agent_id.to_string(), sign));
        self
    }

    /// Carry this operator key with the requests only an operator may make.
    pub fn with_operator_key(mut self, key: Option<&str>) -> Self {
        self.operator_key = key.map(str::to_string);
        self
    }

    /// Send through this transport instead of the built-in client.
    pub fn with_transport(mut self, transport: Arc<dyn ServiceTransport>) -> Self {
        self.transport = transport;
        self
    }

    /// The platform's address this caller sends to.
    pub fn api(&self) -> &str {
        &self.api
    }

    /// Make one request: `request` is `<service>.<request>`. The caller's key
    /// rides with it. The generated methods use [`ServiceCaller::call_keyed`],
    /// which sends the key only with the requests that need it.
    pub async fn call<I: Serialize, O: DeserializeOwned>(&self, request: &str, input: &I) -> Result<O, ServiceError> {
        self.call_keyed(request, KeyUse::Always, input).await
    }

    /// Make one request, sending the caller's key as `key` says.
    pub async fn call_keyed<I: Serialize, O: DeserializeOwned>(&self, request: &str, key: KeyUse, input: &I) -> Result<O, ServiceError> {
        let input = serde_json::to_value(input).map_err(|e| ServiceError::Failed(format!("{request}: the input could not be written as JSON: {e}")))?;
        let result = self.send(request, key, input).await?;
        serde_json::from_value(result).map_err(|e| ServiceError::Failed(format!("{request}: the platform's answer does not match the definition: {e}")))
    }

    /// Make one request with the input and the answer as JSON. The caller's key rides with it.
    pub async fn call_value(&self, request: &str, input: Value) -> Result<Value, ServiceError> {
        self.send(request, KeyUse::Always, input).await
    }

    async fn send(&self, request: &str, key: KeyUse, input: Value) -> Result<Value, ServiceError> {
        // A key rides only with a request that needs it: the account's token
        // with an owner's act, the operator key with an operator's. An agent's
        // other requests carry its signature alone, because the platform reads
        // an account token on any request as the token speaking, and refuses
        // one whose scopes do not cover the mesh (the adapter's svcCall draws
        // the same lines). A caller that is not an agent has only its key.
        let any = || self.key.as_deref().or(self.operator_key.as_deref());
        let agent = self.agent.is_some();
        let bearer = match key {
            KeyUse::Signature if agent => None,
            KeyUse::Owner if agent => self.key.as_deref(),
            KeyUse::Operator if agent => self.operator_key.as_deref(),
            KeyUse::Operator => self.operator_key.as_deref().or(self.key.as_deref()),
            _ => any(),
        };
        let input = if input.is_null() { Value::Object(Default::default()) } else { input };
        let mut body = serde_json::Map::new();
        if let Some((agent, sign)) = &self.agent {
            let ts = now_js();
            let nonce = crate::util::uuid7();
            body.insert("agent".into(), Value::String(agent.clone()));
            body.insert("sig".into(), Value::String(sign(&signed_canonical(agent, request, &ts, &nonce, &input))));
            body.insert("ts".into(), Value::String(ts));
            body.insert("nonce".into(), Value::String(nonce));
        }
        body.insert("input".into(), input);
        body.insert("door".into(), Value::String(self.door.clone()));
        let url = format!("{}/v1/svc/{}", self.api, request);
        let res = self
            .transport
            .post_json(&url, bearer, Value::Object(body).to_string())
            .await
            .map_err(|e| ServiceError::Failed(format!("{request}: {e}")))?;
        let out: Value = serde_json::from_str(&res.body).unwrap_or(Value::Null);
        if (200..300).contains(&res.status) {
            return Ok(out.get("result").cloned().unwrap_or(Value::Null));
        }
        let words = out.get("error").and_then(Value::as_str);
        if let Some(code) = out.get("refusal").and_then(Value::as_str) {
            return Err(ServiceError::refused(request, code, words.unwrap_or(code)));
        }
        Err(ServiceError::Failed(words.map(str::to_string).unwrap_or_else(|| format!("the platform answered {request} with HTTP {}", res.status))))
    }
}

// ── reading answers ─────────────────────────────────────────────────────────

/// Reads a field the definition says is always there, taking `null` (or its
/// absence, with `#[serde(default)]`) as the type's empty value rather than
/// failing the whole answer.
pub fn null_as_default<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

// ── old names ───────────────────────────────────────────────────────────────

/// What an old name says while it still answers. The same sentences every
/// door uses (platform-services/lib.mjs `renamedNotice`, the agent rename's).
pub fn renamed_notice(old: &str, new: &str, day: &str) -> String {
    format!("{old} was renamed to {new}. This name stops working on {day}; use {new}.")
}

/// What an old name says once its window has closed.
pub fn renamed_stopped(old: &str, new: &str, day: &str) -> String {
    format!("{old} was renamed to {new} and stopped working on {day}. Use {new}.")
}

/// Whether the window that closes on `day` (YYYY-MM-DD, UTC) has closed at `now_ms`.
pub fn rename_closed(day: &str, now_ms: i64) -> bool {
    match chrono::NaiveDate::parse_from_str(day, "%Y-%m-%d") {
        Ok(d) => now_ms >= d.and_hms_opt(0, 0, 0).map(|t| t.and_utc().timestamp_millis()).unwrap_or(i64::MAX),
        Err(_) => false,
    }
}

static NOTICED: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();

/// Run by every old method before it does the new one's work: after its
/// window it refuses with the stopped words; inside it, it writes the notice
/// to standard error, once per name per process, and answers.
pub fn old_name(old: &str, new: &str, day: &str) -> Result<(), ServiceError> {
    if rename_closed(day, crate::inbound::now_ms()) {
        return Err(ServiceError::refused(new.trim_end_matches("()"), "RENAMED", renamed_stopped(old, new, day)));
    }
    let first = NOTICED.get_or_init(|| Mutex::new(HashSet::new())).lock().unwrap().insert(old.to_string());
    if first {
        eprintln!("agentmesh: {}", renamed_notice(old, new, day));
    }
    Ok(())
}

// ── on the agent ────────────────────────────────────────────────────────────

/// What an agent keeps for its requests: where the platform is, the key that
/// rides with each request, how to send, the naming service, and the live
/// rooms the rooms door opened or joined.
pub(crate) struct PlatformState {
    pub(crate) api: String,
    pub(crate) key: Option<String>,
    pub(crate) operator_key: Option<String>,
    pub(crate) transport: Arc<dyn ServiceTransport>,
    pub(crate) naming: String,
    pub(crate) rooms: Mutex<std::collections::HashMap<String, crate::rooms::Room>>,
    /// A name claimed with `names().claim`, waiting for its code. This process only.
    pub(crate) name_claim: Mutex<Option<crate::mesh_doors::NameClaim>>,
    /// The feeds this program follows with `feeds().follow`, by `<agent>/<topic>`.
    pub(crate) following: Mutex<std::collections::HashMap<String, crate::mesh_doors::Followed>>,
}

impl PlatformState {
    pub(crate) fn new(api: Option<String>, key: Option<String>, operator_key: Option<String>, transport: Option<Arc<dyn ServiceTransport>>, naming: Option<String>) -> Self {
        Self {
            api: api.unwrap_or_else(|| crate::env_generated::AM_URL_API.to_string()).trim_end_matches('/').to_string(),
            key,
            operator_key,
            transport: transport.unwrap_or_else(default_service_transport),
            naming: naming.unwrap_or_else(|| crate::env_generated::AM_URL_NAMING.to_string()).trim_end_matches('/').to_string(),
            rooms: Mutex::new(Default::default()),
            name_claim: Mutex::new(None),
            following: Mutex::new(Default::default()),
        }
    }
}

impl crate::client::AgentMesh {
    /// The caller every platform service on this agent uses: the platform's
    /// address and key from `ConnectOptions`, each request signed by this
    /// agent's own key.
    pub(crate) fn service_caller(&self) -> ServiceCaller {
        let p = self.platform();
        // A weak handle, so a caller kept after the agent closes neither keeps
        // the connection alive nor signs for it.
        let me = self.downgrade();
        let sign: SignFn = Arc::new(move |m: &str| me.upgrade().map(|a| a.sign_detached(m)).unwrap_or_default());
        ServiceCaller::new(Some(&p.api), p.key.as_deref())
            .with_operator_key(p.operator_key.as_deref())
            .with_transport(p.transport.clone())
            .with_agent(self.id(), sign)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_words_are_the_other_doors_words() {
        assert_eq!(
            renamed_notice("open_room()", "rooms().open()", "2026-11-04"),
            "open_room() was renamed to rooms().open(). This name stops working on 2026-11-04; use rooms().open()."
        );
        assert_eq!(
            renamed_stopped("open_room()", "rooms().open()", "2026-11-04"),
            "open_room() was renamed to rooms().open() and stopped working on 2026-11-04. Use rooms().open()."
        );
    }

    #[test]
    fn a_window_closes_at_midnight_utc() {
        let day = chrono::NaiveDate::from_ymd_opt(2026, 11, 4).unwrap().and_hms_opt(0, 0, 0).unwrap().and_utc().timestamp_millis();
        assert!(!rename_closed("2026-11-04", day - 1));
        assert!(rename_closed("2026-11-04", day));
        assert!(!rename_closed("not a day", day));
    }

    #[test]
    fn an_old_name_answers_inside_its_window_and_refuses_after() {
        assert!(old_name("list_schedules()", "schedules().list()", "2999-01-01").is_ok());
        let err = old_name("list_schedules()", "schedules().list()", "2000-01-01").unwrap_err();
        let r = err.refusal().unwrap();
        assert_eq!(r.code, "RENAMED");
        assert_eq!(r.message, "list_schedules() was renamed to schedules().list() and stopped working on 2000-01-01. Use schedules().list().");
    }

    #[test]
    fn the_signed_string_matches_the_platform() {
        // The platform's signedCanonical over the same input, worked out with
        // services/src/platform-services/door.ts: keys sorted at every level.
        let input = json!({ "zone": "UTC", "name": "n", "answers": { "b": 2, "a": [1, "x"] } });
        assert_eq!(stable_json(&input), r#"{"answers":{"a":[1,"x"],"b":2},"name":"n","zone":"UTC"}"#);
        let s = signed_canonical("UAGENT", "schedules.create", "2026-10-05T18:00:00.000Z", "n1", &input);
        assert_eq!(s, "svc-v1:UAGENT:schedules.create:2026-10-05T18:00:00.000Z:n1:f7c67fbd857159863336c28de3143f78cafb8056130774a666e3f4d5d0328d37");
    }
}
