//! The naming rule, on the sending side. Mirrors `sdk-typescript/src/naming-gate.ts`.
//!
//! Decided by the owner on 2026-09-25: every agent's handle follows one global
//! standard, the agent's name, a dot and its owner's email
//! (`genesis.stephen@example.com`), registered with the naming service, and an
//! agent without one sends nothing, whichever door it uses. The sender is told
//! why before anything leaves, in [`NAMING_STANDARD_WORDS`], with the handle
//! proposed from the name the agent already has. There are no temporary names.
//!
//! The SDK enforces it for an agent that connects with
//! [`ConnectOptions::require_named`](crate::ConnectOptions::require_named),
//! which `connect` turns on by default since 2026-09-27 (`allow_unnamed: true`
//! turns it off, for tests only):
//! every send the agent originates (`request*`, `request_stream`, `emit`,
//! `publish_feed`, `open_room*`, `join_room`) checks first and refuses with a
//! `NOT_NAMED` [`MeshError::Refusal`] before anything is built or signed.
//! Registering, discovery, service calls and answering a request sent TO the
//! agent are left alone: an agent has to be able to register and be named, and
//! a handler's answer is the embedder's to decide
//! ([`AgentMesh::naming_status`](crate::AgentMesh::naming_status) says where
//! the agent stands).
//!
//! The words, the handle shape, the proposals and the cache lifetimes are
//! pinned in `conformance/naming-gate.json`, which the TypeScript SDK and the
//! reference adapter are held to as well.

use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

use crate::credential::BoxFuture;
use crate::error::{ErrorObject, MeshError, Result};

/// The platform's words, exactly (conformance/naming-gate.json `words`:
/// services/src/shared/naming-words.ts NAMING_STANDARD, then the sentence its
/// refusal says next), so every door says the same.
pub const NAMING_STANDARD_WORDS: &str = "AgentMesh uses one global standard for agent names: the agent's name, a dot, and its owner's email. That way no two agents anywhere have the same name. This agent does not have one yet, so nothing was sent.";

/// The refusal's code ([`crate::ErrorCode::NotNamed`]).
pub const NOT_NAMED: &str = "NOT_NAMED";

/// How long a named answer is kept: a handle does not change while a process
/// runs.
pub const NAMED_TTL_MS: i64 = 30 * 60_000;
/// How long "not named" is kept: briefly, so an agent named a moment ago
/// sends at once.
pub const UNNAMED_TTL_MS: i64 = 5_000;

const DEFAULT_REGISTRAR: &str = crate::env_generated::AM_URL_NAMING;

fn bad_char(c: char) -> bool {
    c.is_whitespace() || c == '@'
}

/// Whether a handle follows the global standard: a name with no dot, a dot,
/// then the owner's email. The same test as the TypeScript SDK's
/// `/^[^\s@.]+\.[^\s@]+@[^\s@.]+(\.[^\s@.]+)+$/`, written out.
pub fn is_standard_handle(h: &str) -> bool {
    let Some((name, rest)) = h.split_once('.') else { return false };
    if name.is_empty() || name.chars().any(bad_char) {
        return false;
    }
    let Some((local, domain)) = rest.split_once('@') else { return false };
    if local.is_empty() || local.chars().any(bad_char) {
        return false;
    }
    let labels: Vec<&str> = domain.split('.').collect();
    labels.len() >= 2 && labels.iter().all(|l| !l.is_empty() && !l.chars().any(bad_char))
}

/// Whether an email is usable in a proposal: the TypeScript SDK's
/// `/^[^\s@]+@[^\s@]+\.[^\s@]+$/`, written out.
fn usable_email(e: &str) -> bool {
    let Some((local, domain)) = e.split_once('@') else { return false };
    if local.is_empty() || local.chars().any(bad_char) || domain.chars().any(bad_char) {
        return false;
    }
    let chars: Vec<char> = domain.chars().collect();
    (1..chars.len().saturating_sub(1)).any(|i| chars[i] == '.')
}

/// The handle proposed from the name the agent already has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposedHandle {
    /// The name part, as the naming service would take it; `None` when none.
    pub name: Option<String>,
    /// The owner's email, when a usable one was given.
    pub email: Option<String>,
    /// The whole proposal, with a placeholder for a part that is not known.
    pub handle: String,
}

/// Propose a handle from the agent's own name and its owner's email: lower
/// case, anything the naming service would refuse turned into a dash, runs of
/// them collapsed, dashes trimmed from the ends, 64 characters at most.
pub fn propose_handle(name: Option<&str>, email: Option<&str>) -> ProposedHandle {
    let lowered = name.unwrap_or("").trim().to_lowercase();
    let mut n = String::new();
    let mut dash = false;
    for c in lowered.chars() {
        if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-' {
            if c == '-' {
                if !dash {
                    n.push('-');
                }
                dash = true;
            } else {
                n.push(c);
                dash = false;
            }
        } else if !dash {
            n.push('-');
            dash = true;
        }
    }
    let n: String = n.trim_matches('-').chars().take(64).collect();
    let e = email.map(str::trim).filter(|e| usable_email(e)).map(|e| e.to_lowercase());
    let handle = format!(
        "{}.{}",
        if n.is_empty() { "<agent name>" } else { n.as_str() },
        e.as_deref().unwrap_or("<owner's email>")
    );
    ProposedHandle { name: if n.is_empty() { None } else { Some(n) }, email: e, handle }
}

/// The refusal an unnamed agent gets: the owner's words, then the proposed
/// handle and how to start naming.
pub fn not_named_error(name: Option<&str>, email: Option<&str>) -> MeshError {
    let p = propose_handle(name, email);
    let confirm = match &p.email {
        Some(e) => format!("The proposed name is {}, and {e} confirms it with a code we email.", p.handle),
        None => format!("The proposed name is {}, and the owner confirms it with a code we email.", p.handle),
    };
    let how = format!(
        "To name it, call startNaming with the owner's email and then completeNaming with the code{}, or run agentmesh join.",
        p.name.as_ref().map(|n| format!(" and the name \"{n}\"")).unwrap_or_default()
    );
    MeshError::Refusal(ErrorObject {
        code: NOT_NAMED.to_string(),
        message: format!("{NAMING_STANDARD_WORDS} {confirm} {how}"),
        details: Some(json!({
            "proposed_handle": p.handle,
            "naming": { "sdk": ["startNaming", "verifyNaming", "completeNaming"], "cli": "agentmesh join" },
        })),
        retryable: false,
        retry_after_ms: None,
    })
}

/// What one look at the naming service found for an agent key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameCheck {
    /// A verified card, bound to the key, with this handle.
    Named(String),
    /// The service has no handle for the key, or one not in the standard
    /// shape (carried here).
    Unnamed(Option<String>),
    /// No usable answer.
    Unreachable,
}

/// How a gate asks. Swappable, so an embedder with its own resolver (and the
/// tests) can answer without the network.
pub trait NameLookup: Send + Sync {
    /// Look the agent key up.
    fn lookup<'a>(&'a self, agent_id: &'a str) -> BoxFuture<'a, NameCheck>;
}

/// Judge a registrar's resolve answer (status and parsed body) for
/// `agent_id`, given the card-signing keys the registrar publishes: 404 is
/// not named; a card is named only when its signature verifies with a
/// published key over the canonical card, and it binds `agent_id`. Anything
/// else is unreachable, never named. Pure, so the HTTP lookup and the tests
/// share it.
pub fn judge_resolve_answer(agent_id: &str, status: u16, body: Option<&Value>, published_keys: &[String]) -> NameCheck {
    if status == 404 {
        return NameCheck::Unnamed(None);
    }
    if !(200..300).contains(&status) {
        return NameCheck::Unreachable;
    }
    let Some(body) = body else { return NameCheck::Unreachable };
    let (Some(card), Some(key), Some(sig)) = (
        body.get("card"),
        body.get("registrar_key").and_then(Value::as_str),
        body.get("registrar_sig").and_then(Value::as_str),
    ) else {
        return NameCheck::Unreachable;
    };
    if !published_keys.iter().any(|k| k == key) {
        return NameCheck::Unreachable;
    }
    use base64::Engine as _;
    let Ok(sig_bytes) = base64::engine::general_purpose::STANDARD.decode(sig) else { return NameCheck::Unreachable };
    let Ok(kp) = nkeys::KeyPair::from_public_key(key) else { return NameCheck::Unreachable };
    let canonical = crate::identity::canonical_json(card);
    if kp.verify(canonical.as_bytes(), &sig_bytes).is_err() {
        return NameCheck::Unreachable;
    }
    let bound = card
        .get("endpoints")
        .and_then(Value::as_array)
        .is_some_and(|eps| eps.iter().any(|e| e.get("protocol").and_then(Value::as_str) == Some("agentmesh") && e.get("agent_id").and_then(Value::as_str) == Some(agent_id)));
    if !bound {
        return NameCheck::Unreachable;
    }
    match card.get("handle").and_then(Value::as_str) {
        Some(h) if is_standard_handle(h) => NameCheck::Named(h.to_string()),
        other => NameCheck::Unnamed(other.map(str::to_string)),
    }
}

/// The naming service's reverse lookup over HTTP, verified per SPEC-NAMING
/// §5.3 (the signing key read from the registrar's own `/api/registrar-key`).
#[cfg(feature = "http")]
pub struct RegistrarNameLookup {
    base: String,
    client: reqwest::Client,
    keys: Mutex<Option<(std::time::Instant, Vec<String>)>>,
}

#[cfg(feature = "http")]
impl RegistrarNameLookup {
    /// Ask this registrar (default `https://naming.agentmesh.ai`).
    pub fn new(registrar: Option<&str>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(8_000))
            .build()
            .unwrap_or_default();
        Self {
            base: registrar.unwrap_or(DEFAULT_REGISTRAR).trim_end_matches('/').to_string(),
            client,
            keys: Mutex::new(None),
        }
    }

    async fn signing_keys(&self) -> Vec<String> {
        if let Some((at, keys)) = self.keys.lock().unwrap().as_ref() {
            if at.elapsed() < std::time::Duration::from_secs(3600) {
                return keys.clone();
            }
        }
        let Ok(res) = self.client.get(format!("{}/api/registrar-key", self.base)).send().await else { return vec![] };
        if !res.status().is_success() {
            return vec![];
        }
        let doc: Value = match res.bytes().await { Ok(b) => serde_json::from_slice(&b).unwrap_or(Value::Null), Err(_) => Value::Null };
        let mut keys: Vec<String> = doc.get("keys").and_then(Value::as_array).map(|a| a.iter().filter_map(|k| k.as_str().map(str::to_string)).collect()).unwrap_or_default();
        if let Some(set) = doc.get("key_set").and_then(Value::as_array) {
            keys.extend(set.iter().filter_map(|k| k.get("key").and_then(Value::as_str).map(str::to_string)));
        }
        keys.retain(|k| !k.is_empty());
        if !keys.is_empty() {
            *self.keys.lock().unwrap() = Some((std::time::Instant::now(), keys.clone()));
        }
        keys
    }
}

#[cfg(feature = "http")]
impl NameLookup for RegistrarNameLookup {
    fn lookup<'a>(&'a self, agent_id: &'a str) -> BoxFuture<'a, NameCheck> {
        Box::pin(async move {
            let url = format!("{}/api/resolve?agent_id={}", self.base, agent_id);
            let Ok(res) = self.client.get(url).send().await else { return NameCheck::Unreachable };
            let status = res.status().as_u16();
            if status == 404 {
                return NameCheck::Unnamed(None);
            }
            let body: Option<Value> = match res.bytes().await { Ok(b) => serde_json::from_slice(&b).ok(), Err(_) => None };
            let keys = if (200..300).contains(&status) { self.signing_keys().await } else { vec![] };
            judge_resolve_answer(agent_id, status, body.as_ref(), &keys)
        })
    }
}

/// Where an agent stands, as the gate last saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamingStatus {
    /// Whether it may send.
    pub named: bool,
    /// Its handle, when it has one.
    pub handle: Option<String>,
    /// The naming service did not answer: the agent may send (an outage is
    /// not evidence of no name, as the platform's guard also holds), and
    /// `handle` is the one verified earlier, if any.
    pub unchecked: bool,
    /// When this was decided, in the gate's clock (ms).
    pub checked_at_ms: i64,
}

/// What [`ConnectOptions::require_named`](crate::ConnectOptions::require_named)
/// takes.
#[derive(Clone)]
pub struct RequireNamed {
    /// How to ask.
    pub lookup: Arc<dyn NameLookup>,
    /// The name the agent already has, for the proposed handle.
    pub name: Option<String>,
    /// The owner's email, for the proposed handle.
    pub owner_email: Option<String>,
    /// A handle verified in an earlier run, reported while the naming service
    /// does not answer.
    pub last_verified: Option<String>,
}

impl RequireNamed {
    /// Ask with this lookup.
    pub fn with_lookup(lookup: Arc<dyn NameLookup>) -> Self {
        Self { lookup, name: None, owner_email: None, last_verified: None }
    }

    /// Ask the naming service over HTTP (default `https://naming.agentmesh.ai`).
    #[cfg(feature = "http")]
    pub fn registrar(registrar: Option<&str>) -> Self {
        Self::with_lookup(Arc::new(RegistrarNameLookup::new(registrar)))
    }

    /// What `connect` uses when the caller gave no `require_named` and did not
    /// set `allow_unnamed` (the rule is on by default since 2026-09-27): the
    /// default naming service, over HTTP. `None` without the `http` feature,
    /// where there is no built-in way to ask; such an embedder passes its own
    /// lookup with [`RequireNamed::with_lookup`].
    pub fn by_default() -> Option<Self> {
        #[cfg(feature = "http")]
        {
            Some(Self::registrar(None))
        }
        #[cfg(not(feature = "http"))]
        {
            None
        }
    }
}

/// The one check every send runs, with its cache.
pub struct NamingGate {
    agent_id: String,
    cfg: RequireNamed,
    last_verified: Mutex<Option<String>>,
    status: Mutex<Option<NamingStatus>>,
    now: Arc<dyn Fn() -> i64 + Send + Sync>,
}

impl NamingGate {
    /// A gate for `agent_id`, on the wall clock.
    pub fn new(agent_id: impl Into<String>, cfg: RequireNamed) -> Self {
        Self::with_clock(agent_id, cfg, Arc::new(|| chrono::Utc::now().timestamp_millis()))
    }

    /// A gate on a caller's clock (tests).
    pub fn with_clock(agent_id: impl Into<String>, cfg: RequireNamed, now: Arc<dyn Fn() -> i64 + Send + Sync>) -> Self {
        let last = cfg.last_verified.clone().filter(|h| is_standard_handle(h));
        Self { agent_id: agent_id.into(), cfg, last_verified: Mutex::new(last), status: Mutex::new(None), now }
    }

    /// The last answer, without asking again. `None` before the first check.
    pub fn current(&self) -> Option<NamingStatus> {
        self.status.lock().unwrap().clone()
    }

    /// Forget the cached answer, so the next send asks again (after naming).
    pub fn forget(&self) {
        *self.status.lock().unwrap() = None;
    }

    /// Ask, or use the cached answer while it is fresh.
    pub async fn check(&self) -> NamingStatus {
        let now = (self.now)();
        if let Some(s) = self.status.lock().unwrap().as_ref() {
            let ttl = if s.named && !s.unchecked { NAMED_TTL_MS } else { UNNAMED_TTL_MS };
            if now - s.checked_at_ms < ttl {
                return s.clone();
            }
        }
        let found = self.cfg.lookup.lookup(&self.agent_id).await;
        let at = (self.now)();
        let next = match found {
            NameCheck::Named(h) if is_standard_handle(&h) => {
                *self.last_verified.lock().unwrap() = Some(h.clone());
                NamingStatus { named: true, handle: Some(h), unchecked: false, checked_at_ms: at }
            }
            NameCheck::Named(h) => NamingStatus { named: false, handle: Some(h), unchecked: false, checked_at_ms: at },
            NameCheck::Unnamed(h) => NamingStatus { named: false, handle: h, unchecked: false, checked_at_ms: at },
            // An outage is not evidence of no name: the send goes through, as
            // the platform's guard lets it, and the question is asked again soon.
            NameCheck::Unreachable => NamingStatus {
                named: true,
                handle: self.last_verified.lock().unwrap().clone(),
                unchecked: true,
                checked_at_ms: at,
            },
        };
        *self.status.lock().unwrap() = Some(next.clone());
        next
    }

    /// Refuse with `NOT_NAMED` unless this agent may send.
    pub async fn require(&self) -> Result<()> {
        if self.check().await.named {
            Ok(())
        } else {
            Err(not_named_error(self.cfg.name.as_deref(), self.cfg.owner_email.as_deref()))
        }
    }
}
