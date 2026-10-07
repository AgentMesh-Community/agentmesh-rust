//! Node-credential renewal (§4.8). Mirrors the TS SDK's `credential.ts`.
//!
//! A node credential is a **lease**, exactly like the node vouch it sits under
//! (§4.4): SPEC §4.8 requires it to carry a finite expiry, and an expiry with no
//! renewal is just a scheduled outage. This module is the renewal half.
//!
//! The shape deliberately mirrors [`crate::vouch`], because it is the same
//! problem one layer down and the same answer should not be spelled two ways:
//!
//!   - the deadline is a fixed fraction into the credential's OWN lifetime
//!     (`iat` → `exp` read off the JWT), not a fraction of a configured TTL, so
//!     a credential minted by a different operator policy still gets a
//!     proportionate deadline — and the fraction is literally
//!     [`VOUCH_RENEWAL_FRACTION`], not a second copy of two thirds;
//!   - the loop compares wall-clock against a stored deadline instead of
//!     sleeping until it, so a suspended laptop renews on its first tick after
//!     waking rather than a week late;
//!   - a failure leaves the deadline in place and the next tick retries — two
//!     thirds is chosen precisely so a whole third of the lifetime is left to
//!     recover in.
//!
//! **Renewal does not require a live connection, and does not require the
//! credential to still be valid.** It is a plain HTTPS call authorized by
//! proof-of-possession of the node key and every hosted agent key. That is the
//! property the whole migration rests on: an agent whose lease lapsed while its
//! host was powered off can still renew when it comes back, because the door it
//! knocks on is not the mesh.
//!
//! # The HTTP call: built in, and still replaceable
//!
//! This crate's only other network peer is the broker, over `async-nats`, and
//! there was a case for keeping it that way and letting the host make this one
//! POST. That case was wrong, and the reason is worth writing down: a trait
//! alone is not parity with the TS SDK. A TypeScript embedder gets renewal by
//! upgrading; a Rust one would get an interface and the job of writing the
//! HTTP glue, choosing a timeout, deciding about retries, and getting the
//! request body byte-exact against a verifier it cannot see. Whatever it wrote
//! would drift, and the first symptom of drift is an agent that cannot renew —
//! twenty days after anyone touched the code.
//!
//! So the `http` feature is **on by default** and supplies
//! [`HttpCredentialTransport`]: one pooled `reqwest` client, rustls so no
//! system OpenSSL is needed, the shared [`CREDENTIAL_REQUEST_TIMEOUT_MS`]
//! deadline, and no retry (the renewal loop is the retry, in both SDKs).
//!
//! The trait is unchanged and is still the supported path for anyone who needs
//! it: build with `default-features = false` and the HTTP dependency disappears
//! along with the default, and [`CredentialRenewerOptions::transport`] becomes
//! required. That is the right choice for a constrained target, for a host that
//! already carries an HTTP client, and for anyone with opinions about TLS roots
//! or proxies that a default cannot honour. A renewer built in that
//! configuration with no transport says so immediately on its warning sink
//! rather than looking armed.
//!
//! The pure halves — [`build_credential_request`], [`credential_endpoint`],
//! [`parse_credential_response`] — stay public either way, so a custom
//! transport never has to reconstruct the wire contract.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine as _;
use nkeys::KeyPair;
use serde::{Deserialize, Serialize};

use crate::error::{ErrorCode, MeshError, Result};
use crate::identity::keypair_from_seed;
use crate::inbound::{SecurityWarning, SecurityWarningSink};
use crate::vouch::{ms_to_rfc3339, MAX_VOUCH_CHECK_INTERVAL_MS, VOUCH_RENEWAL_FRACTION};

/// A boxed, `Send` future — the shape every async seam in this module returns,
/// so the traits and callbacks stay object-safe (`dyn`-compatible).
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The lifetime assumed for a credential whose JWT carries an `exp` but no
/// `iat`: the conventional 30-day lease. Used for two things — the notional
/// issue time [`credential_renew_at`] measures its two thirds from, and the
/// check cadence [`CredentialRenewer::start`] picks. An odd mint is better
/// served by a proportionate guess than by never being renewed at all.
pub const ASSUMED_CREDENTIAL_LIFETIME_MS: i64 = 30 * 24 * 3_600_000;

// ── the signing contract (cross-language, byte-exact) ───────────────────────
//
// These two lines are a wire contract shared with the TS SDK and with the
// control plane that verifies them. They are plain ASCII, colon-separated, and
// deliberately NOT canonical JSON: the whole message is four short fields, and
// JSON would bring key ordering, escaping and number formatting to a string
// concatenation for no benefit. Change either format and every existing host
// fails to renew.

/// Domain tag of the node's own line: the node asserting it wants exactly this
/// roster at exactly this instant.
pub const NODE_CREDENTIAL_SIG_PREFIX: &str = "mesh-node-cred-v1";

/// Domain tag of one agent's consent line: the agent asserting it agrees to be
/// hosted by this node at this instant.
pub const NODE_AGENT_CONSENT_SIG_PREFIX: &str = "mesh-node-agent-v1";

/// The exact bytes the node signs: `mesh-node-cred-v1:{ts}:{node_id}:{roster}`,
/// where `roster` is every covered agent id **sorted**, comma-joined.
///
/// Sorted so the same roster produces the same line whatever order the caller
/// assembled it in — the signature covers a set, and a set has no order. (The
/// `agents` array in the request body keeps the caller's order; only the signed
/// line is normalized.)
pub fn node_credential_line(ts: i64, node_id: &str, sorted_agent_ids: &[&str]) -> String {
    format!(
        "{NODE_CREDENTIAL_SIG_PREFIX}:{ts}:{node_id}:{}",
        sorted_agent_ids.join(",")
    )
}

/// The exact bytes one hosted agent signs to consent:
/// `mesh-node-agent-v1:{ts}:{node_id}:{agent_id}`.
pub fn agent_consent_line(ts: i64, node_id: &str, agent_id: &str) -> String {
    format!("{NODE_AGENT_CONSENT_SIG_PREFIX}:{ts}:{node_id}:{agent_id}")
}

// ── claims ──────────────────────────────────────────────────────────────────

/// The three claims renewal scheduling needs out of a NATS user JWT.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CredentialClaims {
    /// The public nkey the credential is bound to — the key whose seed must
    /// sign the renewal request.
    pub sub: Option<String>,
    /// Issued-at, unix seconds.
    pub iat: Option<i64>,
    /// Expiry, unix seconds. `None` means the credential never expires — the
    /// pre-§4.8 shape this module exists to retire.
    pub exp: Option<i64>,
}

/// Decode one base64url (or base64) JWT segment. Padding is optional, both
/// alphabets are accepted — exactly what the TS `decodeSegment` tolerates.
fn decode_segment(seg: &str) -> Option<Vec<u8>> {
    let normalized: String = seg
        .chars()
        .filter(|c| *c != '=')
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            other => other,
        })
        .collect();
    STANDARD_NO_PAD.decode(normalized.as_bytes()).ok()
}

/// Read `sub`/`iat`/`exp` out of a NATS user JWT.
///
/// **Deliberately does NOT verify the signature.** The broker verifies it at
/// connect time against the account chain, which is the only party that can; a
/// client verifying its own credential would prove nothing it does not already
/// assume. This is a read of a value the holder already possesses, for
/// scheduling — never an authorization decision.
///
/// `None` when the string is not a JWT at all (wrong segment count, undecodable
/// payload, payload that is not JSON). A JWT whose payload is valid JSON but
/// carries none of the three claims decodes to an all-`None` [`CredentialClaims`],
/// which is a different and honest answer: it IS a JWT, it just says nothing
/// about its own lifetime.
pub fn decode_credential_claims(jwt: &str) -> Option<CredentialClaims> {
    let mut parts = jwt.split('.');
    let (_header, payload, _sig) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None; // more than three segments is not a JWT
    }
    let claim: serde_json::Value = serde_json::from_slice(&decode_segment(payload)?).ok()?;
    // Any finite JSON number, matching the TS `typeof v === "number"` test —
    // a `serde_json` number is finite by construction.
    let num = |key: &str| claim.get(key).and_then(|v| v.as_f64()).map(|f| f as i64);
    Some(CredentialClaims {
        sub: claim.get("sub").and_then(|v| v.as_str()).map(str::to_string),
        iat: num("iat"),
        exp: num("exp"),
    })
}

/// The instant (ms epoch) at which a credential should be renewed: the same two
/// thirds into its own lifetime that a vouch uses
/// ([`VOUCH_RENEWAL_FRACTION`] — one constant, two leases).
///
/// `None` when the credential carries no usable window — either it never
/// expires (nothing to renew before) or the window is inverted. A `None` here is
/// not an error; it is the honest statement that there is no deadline to
/// schedule from, and [`CredentialRenewer`] treats it as "never due".
///
/// A credential with no `iat` still gets a deadline: the issue time is assumed
/// to be [`ASSUMED_CREDENTIAL_LIFETIME_MS`] before the expiry, so an odd mint is
/// not left unrenewed forever.
///
/// Parity note: as with [`vouch_renew_at`](crate::vouch::vouch_renew_at), the TS
/// function returns a float and this returns whole milliseconds (the fraction
/// truncated). Nothing downstream can observe the sub-millisecond difference.
pub fn credential_renew_at(claims: &CredentialClaims) -> Option<i64> {
    let expires = claims.exp? * 1000;
    let issued = match claims.iat {
        Some(iat) => iat * 1000,
        None => expires - ASSUMED_CREDENTIAL_LIFETIME_MS,
    };
    if expires <= issued {
        return None;
    }
    Some(issued + ((expires - issued) as f64 * VOUCH_RENEWAL_FRACTION) as i64)
}

/// How often to check whether renewal is due, for a credential of this
/// lifetime. Four checks inside the last third, floor 1 ms, capped at
/// [`MAX_VOUCH_CHECK_INTERVAL_MS`] (hourly).
///
/// Identical arithmetic to [`vouch_check_interval`](crate::vouch::vouch_check_interval),
/// and for the identical reason: a periodic check against the wall clock, not
/// one long timer, so a host that suspends renews on the first tick after it
/// wakes.
pub fn credential_check_interval(lifetime_ms: i64) -> Duration {
    let window = lifetime_ms as f64 * (1.0 - VOUCH_RENEWAL_FRACTION);
    let ms = ((window / 4.0).floor() as i64).clamp(1, MAX_VOUCH_CHECK_INTERVAL_MS);
    Duration::from_millis(ms as u64)
}

// ── the roster ──────────────────────────────────────────────────────────────

/// Detached-signature callback: standard base64 (with padding) of an Ed25519
/// signature by the agent's key over the given message.
pub type DetachedSigner = Arc<dyn Fn(&str) -> String + Send + Sync>;

/// One hosted agent, and the means of proving it consents to being hosted.
///
/// Supply exactly one of `seed` or `sign`. `sign` exists so a caller that holds
/// an agent object but not its seed (a [`MeshNode`](crate::MeshNode) and the
/// agents it created) can consent without the key material leaving that object.
#[derive(Clone, Default)]
pub struct RenewalAgent {
    /// The agent's public nkey (`U…`).
    pub id: String,
    /// Its seed (`SU…`). Used only to sign the consent line; never transmitted.
    pub seed: Option<String>,
    /// Detached Ed25519 signature over `message`, standard base64.
    pub sign: Option<DetachedSigner>,
}

impl std::fmt::Debug for RenewalAgent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the seed: this type is routinely logged by hosts.
        f.debug_struct("RenewalAgent")
            .field("id", &self.id)
            .field("seed", &self.seed.as_ref().map(|_| "<redacted>"))
            .field("sign", &self.sign.as_ref().map(|_| "<fn>"))
            .finish()
    }
}

impl RenewalAgent {
    /// Consent proved by the seed this caller holds.
    pub fn with_seed(id: impl Into<String>, seed: impl Into<String>) -> RenewalAgent {
        RenewalAgent { id: id.into(), seed: Some(seed.into()), sign: None }
    }

    /// Consent proved by a signing callback — the seed stays where it lives.
    pub fn with_signer<F>(id: impl Into<String>, sign: F) -> RenewalAgent
    where
        F: Fn(&str) -> String + Send + Sync + 'static,
    {
        RenewalAgent { id: id.into(), seed: None, sign: Some(Arc::new(sign)) }
    }
}

/// A roster, or a function returning the current one. The function form is for
/// a node whose hosted set changes: the roster is read at each renewal, so an
/// agent added after the loop started is covered by the next credential.
#[derive(Clone)]
pub enum RenewalRoster {
    /// A roster fixed for the life of the renewer (the standalone-agent case).
    Fixed(Vec<RenewalAgent>),
    /// Read afresh at every renewal (the node case).
    Dynamic(Arc<dyn Fn() -> Vec<RenewalAgent> + Send + Sync>),
}

impl RenewalRoster {
    /// The roster as of now.
    pub fn resolve(&self) -> Vec<RenewalAgent> {
        match self {
            RenewalRoster::Fixed(v) => v.clone(),
            RenewalRoster::Dynamic(f) => f(),
        }
    }

    /// A roster read afresh at every renewal.
    pub fn dynamic<F>(f: F) -> RenewalRoster
    where
        F: Fn() -> Vec<RenewalAgent> + Send + Sync + 'static,
    {
        RenewalRoster::Dynamic(Arc::new(f))
    }
}

impl From<Vec<RenewalAgent>> for RenewalRoster {
    fn from(v: Vec<RenewalAgent>) -> RenewalRoster {
        RenewalRoster::Fixed(v)
    }
}

// ── the request body ────────────────────────────────────────────────────────

/// One agent's line in a credential request: its id and its consent signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialRequestAgent {
    pub id: String,
    /// Standard base64 (with padding) of the Ed25519 signature over
    /// [`agent_consent_line`].
    pub sig: String,
}

/// The signed body of `POST {api_base}/v1/node-credential`.
///
/// Field order is the serialization order, and matches the TS SDK's object
/// literal — not because the server cares, but because a fixture that pins the
/// bytes should pin the same bytes from both SDKs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialRequest {
    /// The public key derived from the node seed.
    pub node_id: String,
    /// Unix **seconds**. Inside both signed lines, so a captured request cannot
    /// be replayed at another time.
    pub ts: i64,
    /// Standard base64 of the node key's signature over [`node_credential_line`].
    pub node_sig: String,
    /// Every covered agent, in the caller's order.
    pub agents: Vec<CredentialRequestAgent>,
}

fn sign_b64(kp: &KeyPair, message: &str) -> Result<String> {
    let sig = kp
        .sign(message.as_bytes())
        .map_err(|e| MeshError::Nkey(e.to_string()))?;
    Ok(STANDARD.encode(sig))
}

fn short(id: &str) -> String {
    id.chars().take(12).collect()
}

/// Build the signed body of a node-credential request.
///
/// Exported so a host can renew without the loop, and so the signing contract is
/// testable without a server. The node proves it wants exactly this roster; each
/// agent proves it consents to this node. Nothing here grants access to a key the
/// caller did not prove it holds.
///
/// `now_sec` is unix **seconds** — the same unit that goes on the wire.
///
/// Errors on an empty roster (a credential covering nobody is not a thing), on
/// an agent that supplied neither `seed` nor `sign`, and on a seed that does not
/// derive the id it was filed under — which would otherwise produce a request
/// the server rejects with nothing local to explain why.
pub fn build_credential_request(
    node_seed: &str,
    agents: &[RenewalAgent],
    now_sec: i64,
) -> Result<CredentialRequest> {
    if agents.is_empty() {
        return Err(MeshError::code(
            ErrorCode::Internal,
            "a node credential must cover at least one agent",
        ));
    }
    let node_kp = keypair_from_seed(node_seed)?;
    let node_id = node_kp.public_key();

    // Sorted for the signed line only. nkey ids are ASCII base32, so Rust's
    // byte order and JavaScript's UTF-16 code-unit order agree — the two SDKs
    // cannot disagree on what "sorted" means here.
    let mut ids: Vec<&str> = agents.iter().map(|a| a.id.as_str()).collect();
    ids.sort_unstable();
    let node_sig = sign_b64(&node_kp, &node_credential_line(now_sec, &node_id, &ids))?;

    let mut signed = Vec::with_capacity(agents.len());
    for agent in agents {
        let message = agent_consent_line(now_sec, &node_id, &agent.id);
        let sig = match (&agent.sign, &agent.seed) {
            (Some(sign), _) => sign(&message),
            (None, Some(seed)) => {
                let kp = keypair_from_seed(seed)?;
                if kp.public_key() != agent.id {
                    return Err(MeshError::code(
                        ErrorCode::Internal,
                        format!("agent seed does not match id {}…", short(&agent.id)),
                    ));
                }
                sign_b64(&kp, &message)?
            }
            (None, None) => {
                return Err(MeshError::code(
                    ErrorCode::Internal,
                    format!("agent {}… supplied neither seed nor sign", short(&agent.id)),
                ))
            }
        };
        signed.push(CredentialRequestAgent { id: agent.id.clone(), sig });
    }
    Ok(CredentialRequest { node_id, ts: now_sec, node_sig, agents: signed })
}

/// The renewal endpoint for a control-plane origin: `{api_base}/v1/node-credential`,
/// with one trailing slash trimmed (exactly what the TS `replace(/\/$/, "")` does).
pub fn credential_endpoint(api_base: &str) -> String {
    let base = api_base.strip_suffix('/').unwrap_or(api_base);
    format!("{base}/v1/node-credential")
}

// ── the response ────────────────────────────────────────────────────────────

/// A freshly minted credential. The caller keeps the seed it already holds: a
/// renewal never changes the key the credential is bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenewedCredential {
    pub jwt: String,
    /// The key the new credential is bound to — unchanged by a renewal.
    pub node_id: String,
    pub agents: Vec<String>,
    /// RFC 3339, or `None` if this instance still mints without an expiry.
    pub expires_at: Option<String>,
}

/// What a [`CredentialTransport`] hands back: the HTTP status and the raw body.
///
/// The status is kept rather than folded into a `Result` because it carries the
/// distinction that matters: a 4xx **is the answer** (§4.8 — a refusal to renew
/// is how revocation is expressed), while a transport error is a fault to retry.
pub struct CredentialHttpResponse {
    pub status: u16,
    pub body: String,
}

/// The one network operation this module needs, supplied by the host.
///
/// See the module docs for why the crate does not ship an implementation: it has
/// no HTTP client dependency and will not grow one for a single POST. Implement
/// this over `reqwest`, `ureq` on a blocking pool, or whatever the host already
/// uses; the SDK only needs the status and the body back.
///
/// Return `Err` only for a transport-level failure (DNS, connect, TLS, read). A
/// server that answered — with anything, including 500 — is a
/// [`CredentialHttpResponse`].
pub trait CredentialTransport: Send + Sync {
    /// POST `body` to `url` with `content-type: application/json`.
    fn post_json<'a>(&'a self, url: &'a str, body: String) -> BoxFuture<'a, Result<CredentialHttpResponse>>;
}

/// How long one renewal request may take before it is abandoned.
///
/// Explicit, and the same fifteen seconds `CREDENTIAL_REQUEST_TIMEOUT_MS` uses
/// in the TS SDK, because the two must behave identically under the same
/// failure. The reason it must exist at all: while a request hangs,
/// [`CredentialRenewer`] holds its in-flight guard and the periodic loop stops
/// retrying, so one stalled socket would quietly consume the whole renewal
/// window.
///
/// **There is deliberately no retry inside the call**, in either SDK. Retrying
/// here would nest a second, invisible schedule inside the two-thirds one and
/// make the real cadence unknowable. [`CredentialRenewer::renew_if_due`] leaves
/// the deadline in place on failure, so the next tick is the retry — roughly
/// hourly through the last third of the credential's life.
pub const CREDENTIAL_REQUEST_TIMEOUT_MS: u64 = 15_000;

/// The built-in [`CredentialTransport`], compiled in with the default `http`
/// feature.
///
/// Exists so that a Rust embedder gets renewal by upgrading, exactly as a
/// TypeScript one does. Without it the trait alone is not parity: it hands the
/// host the timeout, the retry policy and — worst — the job of getting the
/// request body byte-exact against a verifier it cannot see, where the first
/// symptom of an error is an agent that cannot renew.
///
/// It is a thin wrapper on purpose. One `reqwest::Client`, built once and
/// reused so connections are pooled across renewals, the shared timeout above,
/// and no retry. Anything more opinionated (proxies, pinned roots, a shared
/// client the host already owns) is what the trait is still for.
#[cfg(feature = "http")]
pub struct HttpCredentialTransport {
    client: reqwest::Client,
}

#[cfg(feature = "http")]
impl HttpCredentialTransport {
    /// A transport with the standard timeout.
    ///
    /// Falls back to a default client if building one fails, which in practice
    /// means a TLS backend that would not initialise — the subsequent request
    /// then reports the real error rather than this constructor panicking
    /// inside a renewal loop.
    pub fn new() -> Self {
        Self::with_timeout(Duration::from_millis(CREDENTIAL_REQUEST_TIMEOUT_MS))
    }

    /// A transport with a caller-chosen deadline. Prefer [`new`](Self::new):
    /// the shared number is what keeps the two SDKs comparable.
    pub fn with_timeout(timeout: Duration) -> Self {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .unwrap_or_default();
        Self { client }
    }

    /// Wrap a client the host already owns — its proxy, root and pool settings,
    /// this module's request shape.
    pub fn with_client(client: reqwest::Client) -> Self {
        Self { client }
    }
}

#[cfg(feature = "http")]
impl Default for HttpCredentialTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "http")]
impl CredentialTransport for HttpCredentialTransport {
    fn post_json<'a>(&'a self, url: &'a str, body: String) -> BoxFuture<'a, Result<CredentialHttpResponse>> {
        Box::pin(async move {
            let res = self
                .client
                .post(url)
                .header("content-type", "application/json")
                .body(body)
                .send()
                .await
                .map_err(|e| {
                    // A timeout surfaces as a generic request error, which in a
                    // warning about a lapsing credential reads like an SDK bug
                    // rather than an unreachable mesh. Say which it was — the
                    // TS SDK draws the same distinction.
                    if e.is_timeout() {
                        MeshError::Transport(format!(
                            "credential renewal timed out after {CREDENTIAL_REQUEST_TIMEOUT_MS}ms — the mesh did not answer"
                        ))
                    } else {
                        MeshError::Transport(format!("credential renewal could not reach the mesh: {e}"))
                    }
                })?;
            let status = res.status().as_u16();
            // Bytes, not `text()`: the body is JSON this control plane wrote, so
            // charset sniffing would only add a reqwest feature to guess at
            // something already known.
            let bytes = res
                .bytes()
                .await
                .map_err(|e| MeshError::Transport(format!("credential renewal response could not be read: {e}")))?;
            Ok(CredentialHttpResponse {
                status,
                body: String::from_utf8_lossy(&bytes).into_owned(),
            })
        })
    }
}

/// The transport a [`CredentialRenewal`] uses when it names none.
///
/// `Some` with the `http` feature (the default), `None` without it — which is
/// what makes "renewal works out of the box" true in the default build and
/// makes the feature-off build fail loudly at arm time instead of silently
/// never renewing.
pub fn default_credential_transport() -> Option<Arc<dyn CredentialTransport>> {
    #[cfg(feature = "http")]
    {
        Some(Arc::new(HttpCredentialTransport::new()))
    }
    #[cfg(not(feature = "http"))]
    {
        None
    }
}

/// Turn a control-plane answer into a [`RenewedCredential`], or into the error
/// the server meant.
///
/// `request` supplies the fallbacks for fields the server may omit — the node id
/// and the roster are things the caller already asserted, so echoing them back is
/// a courtesy, not the source of truth.
///
/// A non-2xx, or a 2xx with no `jwt`, is a failure reported with the server's own
/// `error` string when it sent one. That string is the useful half of a refusal:
/// "this node has been revoked" reads very differently from "HTTP 403".
pub fn parse_credential_response(
    status: u16,
    body: &str,
    request: &CredentialRequest,
) -> Result<RenewedCredential> {
    let data: serde_json::Value = serde_json::from_str(body).unwrap_or(serde_json::Value::Null);
    let jwt = data.get("jwt").and_then(|v| v.as_str()).unwrap_or_default();
    if !(200..300).contains(&status) || jwt.is_empty() {
        let reason = data
            .get("error")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| format!("credential renewal failed: HTTP {status}"));
        return Err(MeshError::Transport(reason));
    }
    Ok(RenewedCredential {
        jwt: jwt.to_string(),
        node_id: data
            .get("node_id")
            .and_then(|v| v.as_str())
            .unwrap_or(&request.node_id)
            .to_string(),
        agents: data
            .get("agents")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str()).map(str::to_string).collect())
            .unwrap_or_else(|| request.agents.iter().map(|a| a.id.clone()).collect()),
        expires_at: data
            .get("expires_at")
            .and_then(|v| v.as_str())
            .map(str::to_string),
    })
}

/// Renew (or first-mint) a node credential, stamped with the current clock.
///
/// `api_base` is the mesh's control-plane origin, e.g. `https://api.agentmesh.ai`.
/// Returns the fresh JWT; persisting it is the caller's job — this module does
/// not know where the credential lives.
pub async fn renew_node_credential(
    transport: &dyn CredentialTransport,
    api_base: &str,
    node_seed: &str,
    agents: &[RenewalAgent],
) -> Result<RenewedCredential> {
    renew_node_credential_at(transport, api_base, node_seed, agents, crate::inbound::now_ms() / 1000).await
}

/// [`renew_node_credential`] with the timestamp supplied — the seam a fixture
/// needs, since a signature over "now" is not reproducible.
pub async fn renew_node_credential_at(
    transport: &dyn CredentialTransport,
    api_base: &str,
    node_seed: &str,
    agents: &[RenewalAgent],
    now_sec: i64,
) -> Result<RenewedCredential> {
    let request = build_credential_request(node_seed, agents, now_sec)?;
    let body = serde_json::to_string(&request)?;
    let res = transport.post_json(&credential_endpoint(api_base), body).await?;
    parse_credential_response(res.status, &res.body, &request)
}

// ── status ──────────────────────────────────────────────────────────────────

/// What a host surface (adapter `status`, a health page) needs to render.
/// Mirrors [`VouchStatus`](crate::vouch::VouchStatus) one layer down.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CredentialStatus {
    /// RFC 3339 expiry, or `None` for a credential that carries no expiry — the
    /// pre-§4.8 shape. `None` is a finding, not a clean bill of health.
    pub expires_at: Option<String>,
    /// RFC 3339 renewal deadline, or `None` when there is nothing to schedule.
    pub renew_at: Option<String>,
    /// True once the credential's own expiry is in the past. Such a credential
    /// cannot open a connection — but it CAN still be renewed, which is why this
    /// is a state and not a terminal condition.
    pub expired: bool,
    /// Why the last attempt failed, or `None`.
    pub last_error: Option<String>,
}

/// The §22.7 local signal a failed credential renewal raises: code
/// `credential_renewal_failed`, subject = the key the credential is bound to,
/// and a message naming the cause, the expiry and the consequence. Mirrors the
/// TS SDK's message text.
pub(crate) fn credential_renewal_failed_warning(
    sub: Option<&str>,
    reason: &str,
    expires_at: Option<&str>,
) -> SecurityWarning {
    SecurityWarning {
        code: "credential_renewal_failed".to_string(),
        message: format!(
            "could not renew the node credential for {who}…: {reason}. It expires {expires}; \
             after that this node cannot open a connection to the mesh until it renews. Renewal \
             does not need a working connection, so retrying is the right move — and it will keep \
             retrying.",
            who = sub.map(short).unwrap_or_else(|| "this node".to_string()),
            expires = expires_at.unwrap_or("at an unknown time"),
        ),
        subject: sub.map(str::to_string),
        from: None,
    }
}

// ── the renewer ─────────────────────────────────────────────────────────────

/// Called with the fresh credential after a successful renewal — this is where a
/// host persists it. An `on_renewed` that returns `Err` is reported as a renewal
/// failure, because a credential that was not written down was not really
/// renewed.
pub type OnRenewedFn = Arc<dyn Fn(RenewedCredential) -> BoxFuture<'static, Result<()>> + Send + Sync>;

/// Construction options for [`CredentialRenewer`].
pub struct CredentialRenewerOptions {
    /// Control-plane origin, e.g. `https://api.agentmesh.ai`.
    pub api_base: String,
    /// The credential in hand.
    pub jwt: String,
    /// The seed of the key the credential is bound to (from the `.creds` file).
    pub node_seed: String,
    /// Every agent the credential covers, with the means of consenting. Use
    /// [`RenewalRoster::dynamic`] when the hosted set can change between
    /// renewals.
    pub agents: RenewalRoster,
    /// How the POST is made.
    ///
    /// `None` takes the built-in HTTP transport, which is compiled in with the
    /// default `http` feature — so the ordinary case needs nothing here. With
    /// that feature off there is no default and this is required; a renewer
    /// built without one raises `credential_renewal_unavailable` on its warning
    /// sink at construction rather than looking armed and discovering it has no
    /// way to renew twenty days later.
    pub transport: Option<Arc<dyn CredentialTransport>>,
    /// Where a fresh credential is persisted. Called BEFORE the renewer adopts
    /// it.
    pub on_renewed: Option<OnRenewedFn>,
    /// Where a failed attempt is reported. The loop keeps retrying.
    pub on_warning: Option<SecurityWarningSink>,
}

/// The mutable half: everything a renewal replaces.
struct CredentialState {
    jwt: String,
    claims: Option<CredentialClaims>,
    renew_at_ms: Option<i64>,
    last_error: Option<String>,
}

/// The renewal loop for one node credential.
///
/// Owned by whoever holds the credential file — [`MeshNode`](crate::MeshNode)
/// and [`AgentMesh`](crate::AgentMesh) wire one up when handed credential
/// material, and a reference adapter can drive one directly. Kept as its own
/// object rather than folded into the client because the most important call is
/// [`renew_if_expiring`](Self::renew_if_expiring) **before** connecting, and at
/// that point there is no client yet.
pub struct CredentialRenewer {
    opts: CredentialRenewerOptions,
    /// The transport actually in use: what the caller named, else the built-in
    /// one from the `http` feature. `None` only in a `default-features = false`
    /// build whose host supplied nothing — see [`CredentialRenewer::new`].
    transport: Option<Arc<dyn CredentialTransport>>,
    state: Mutex<CredentialState>,
    /// Guard against overlapping in-flight renewals: the loop's tick and a
    /// manual call may race, and two POSTs at once buy nothing.
    in_flight: AtomicBool,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl CredentialRenewer {
    /// Build a renewer around the credential in hand. Returns an `Arc` because
    /// [`start`](Self::start) hands a weak handle to its own task — the loop
    /// must not be what keeps the renewer alive.
    ///
    /// `opts.transport` may be `None`: with the default `http` feature the
    /// built-in transport is used, which is what makes renewal work out of the
    /// box the way it does in the TS SDK. In a `default-features = false` build
    /// there is no default, and a renewer with no transport says so
    /// IMMEDIATELY on its warning sink instead of waiting until the first
    /// renewal comes due — which is twenty days after the credential was
    /// minted, long past the point where the omission is easy to connect to its
    /// cause.
    pub fn new(opts: CredentialRenewerOptions) -> Arc<CredentialRenewer> {
        let claims = decode_credential_claims(&opts.jwt);
        let renew_at_ms = claims.as_ref().and_then(credential_renew_at);
        let transport = opts.transport.clone().or_else(default_credential_transport);
        if transport.is_none() {
            if let Some(sink) = opts.on_warning.as_ref() {
                sink(SecurityWarning {
                    code: "credential_renewal_unavailable".to_string(),
                    message: "this build of the agentmesh crate was compiled without the `http` \
                              feature and no CredentialTransport was supplied, so the node \
                              credential CANNOT be renewed. It will stop working when it expires. \
                              Enable the default `http` feature, or set \
                              CredentialRenewerOptions::transport."
                        .to_string(),
                    subject: claims.as_ref().and_then(|c| c.sub.clone()),
                    from: None,
                });
            }
        }
        Arc::new(CredentialRenewer {
            state: Mutex::new(CredentialState {
                jwt: opts.jwt.clone(),
                claims,
                renew_at_ms,
                last_error: None,
            }),
            opts,
            transport,
            in_flight: AtomicBool::new(false),
            task: Mutex::new(None),
        })
    }

    /// The credential currently in hand — the fresh one after a renewal.
    pub fn credential(&self) -> String {
        self.state.lock().unwrap().jwt.clone()
    }

    /// Expiry, renewal deadline, whether it has already lapsed, and why the last
    /// attempt failed, as of `now_ms` (ms epoch).
    pub fn status(&self, now_ms: i64) -> CredentialStatus {
        let st = self.state.lock().unwrap();
        let exp_ms = st.claims.as_ref().and_then(|c| c.exp).map(|e| e * 1000);
        CredentialStatus {
            expires_at: exp_ms.and_then(ms_to_rfc3339),
            renew_at: st.renew_at_ms.and_then(ms_to_rfc3339),
            expired: exp_ms.is_some_and(|e| e <= now_ms),
            last_error: st.last_error.clone(),
        }
    }

    /// Renew now, regardless of the schedule.
    ///
    /// A successful renewal replaces the in-hand credential and resets the
    /// deadline. The connection is NOT re-established: an open NATS connection
    /// keeps its authorization for as long as it stays open, so the new
    /// credential matters at the next connect. That is deliberate — reconnecting
    /// a healthy agent to install a credential it does not yet need is the more
    /// disruptive choice.
    pub async fn renew(&self) -> Result<RenewedCredential> {
        let transport = self.transport.as_ref().ok_or_else(|| {
            MeshError::code(
                ErrorCode::Internal,
                "no CredentialTransport: this build has the `http` feature off and the host \
                 supplied none, so the credential cannot be renewed",
            )
        })?;
        let agents = self.opts.agents.resolve();
        let fresh = renew_node_credential(
            transport.as_ref(),
            &self.opts.api_base,
            &self.opts.node_seed,
            &agents,
        )
        .await?;
        // Persist BEFORE adopting: if the host cannot write it down, the renewal
        // did not happen as far as the next start is concerned, and pretending
        // otherwise would clear the deadline that gets us retried.
        if let Some(on_renewed) = &self.opts.on_renewed {
            on_renewed(fresh.clone()).await?;
        }
        let claims = decode_credential_claims(&fresh.jwt);
        let renew_at_ms = claims.as_ref().and_then(credential_renew_at);
        let mut st = self.state.lock().unwrap();
        st.jwt = fresh.jwt.clone();
        st.claims = claims;
        st.renew_at_ms = renew_at_ms;
        st.last_error = None;
        Ok(fresh)
    }

    /// Renew if the deadline has passed as of `now_ms`. Returns `true` when a
    /// renewal happened.
    ///
    /// Never errors: this runs on a timer with no caller to catch it. A failure
    /// records [`CredentialStatus::last_error`], raises a
    /// `credential_renewal_failed` warning on the configured sink, and leaves the
    /// deadline in place so the next tick retries — two thirds is the deadline
    /// precisely so there is a third of the lifetime left to keep trying in.
    /// Overlapping calls are guarded: while one renewal is in flight, the rest
    /// return `false` without doing anything.
    pub async fn renew_if_due(&self, now_ms: i64) -> bool {
        match self.state.lock().unwrap().renew_at_ms {
            None => return false,
            Some(renew_at) if now_ms < renew_at => return false,
            Some(_) => {}
        }
        if self.in_flight.swap(true, SeqCst) {
            return false;
        }
        // RAII so the guard is released even if this future is dropped
        // mid-await (an aborted loop must not wedge a later manual renewal) —
        // the TS `finally`.
        struct InFlight<'a>(&'a AtomicBool);
        impl Drop for InFlight<'_> {
            fn drop(&mut self) {
                self.0.store(false, SeqCst);
            }
        }
        let _guard = InFlight(&self.in_flight);
        match self.renew().await {
            Ok(_) => true,
            Err(err) => {
                let reason = err.to_string();
                let warning = {
                    let mut st = self.state.lock().unwrap();
                    st.last_error = Some(reason.clone());
                    let sub = st.claims.as_ref().and_then(|c| c.sub.clone());
                    let expires_at = st
                        .claims
                        .as_ref()
                        .and_then(|c| c.exp)
                        .map(|e| e * 1000)
                        .and_then(ms_to_rfc3339);
                    credential_renewal_failed_warning(sub.as_deref(), &reason, expires_at.as_deref())
                };
                if let Some(sink) = &self.opts.on_warning {
                    sink(warning);
                }
                false
            }
        }
    }

    /// The startup call: renew if the credential is past its deadline **or
    /// already expired**, before anything tries to connect with it.
    ///
    /// This is what makes a lapsed credential self-healing. A host that was
    /// powered off through its whole renewal window comes back with a dead
    /// credential; `renew_if_due` covers it (an expired credential is by
    /// definition past two thirds), and doing it before connect means the
    /// operator never sees an authentication error they have to fix by hand.
    pub async fn renew_if_expiring(&self, now_ms: i64) -> bool {
        self.renew_if_due(now_ms).await
    }

    /// The credential's own lifetime, or the 30-day convention when the JWT does
    /// not say. A window that is inverted or zero-width falls back too, so a
    /// nonsense mint cannot turn the check into a 1 ms spin.
    fn lifetime_ms(&self) -> i64 {
        let st = self.state.lock().unwrap();
        match st.claims.as_ref().map(|c| (c.iat, c.exp)) {
            Some((Some(iat), Some(exp))) if exp > iat => (exp - iat) * 1000,
            _ => ASSUMED_CREDENTIAL_LIFETIME_MS,
        }
    }

    /// Start the periodic check. Idempotent — a second call replaces the first
    /// loop rather than running two.
    ///
    /// The task holds only a weak handle on the renewer, so the loop never keeps
    /// a renewer (or the node holding it) alive on its own — the analogue of the
    /// TS SDK's unref'd timer.
    pub fn start(self: &Arc<Self>) {
        self.stop();
        let weak = Arc::downgrade(self);
        let interval = credential_check_interval(self.lifetime_ms());
        let handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            // Late ticks (a suspended host) must not burst-replay: each tick
            // reads the real clock, so one late tick already does the work.
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                // The first tick fires immediately; it compares wall clock
                // against the deadline, so a not-yet-due tick is a no-op.
                ticker.tick().await;
                let Some(me) = weak.upgrade() else { break };
                me.renew_if_due(crate::inbound::now_ms()).await;
            }
        });
        *self.task.lock().unwrap() = Some(handle);
    }

    /// Stop the periodic check. Safe to call when not started.
    pub fn stop(&self) {
        if let Some(handle) = self.task.lock().unwrap().take() {
            handle.abort();
        }
    }
}

impl Drop for CredentialRenewer {
    fn drop(&mut self) {
        self.stop();
    }
}

/// The `credential_renewal` connect option (§4.8): keep the connection
/// credential alive for as long as this process runs.
///
/// Unset means the SDK does nothing about the credential — correct for a guest
/// credential (throwaway, re-leased on demand) and for a host that manages
/// credential files itself with its own [`CredentialRenewer`]; wrong for
/// anything durable.
pub struct CredentialRenewal {
    /// Control-plane origin, e.g. `https://api.agentmesh.ai`.
    pub api_base: String,
    /// How the renewal POST is made.
    ///
    /// Leave it `None` — the default `http` feature compiles in
    /// [`HttpCredentialTransport`] and the SDK wires it up, so renewal works
    /// with nothing but an `api_base`. Set it to reuse an HTTP client you
    /// already own, or when you built the crate with `default-features = false`
    /// and there is no built-in one.
    pub transport: Option<Arc<dyn CredentialTransport>>,
    /// Seed of the key the JWT is bound to. Defaults to the seed that holds the
    /// connection — the node seed for a [`MeshNode`](crate::MeshNode), the agent
    /// seed for a standalone [`AgentMesh`](crate::AgentMesh). A bootstrap-minted
    /// credential bound to a separate key must name that key's seed here.
    pub credential_seed: Option<String>,
    /// Where the fresh credential goes. Called before the SDK adopts it, so an
    /// `Err` here is reported as a renewal failure and retried.
    pub on_renewed: Option<OnRenewedFn>,
    /// Optional override for where failures are reported. A standalone agent
    /// defaults to its own
    /// [`on_security_warning`](crate::AgentMesh::on_security_warning) sink,
    /// whenever that gets attached; a node has no such sink, so set this to see
    /// its failures.
    pub on_warning: Option<SecurityWarningSink>,
}

impl std::fmt::Debug for CredentialRenewal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialRenewal")
            .field("api_base", &self.api_base)
            .field("credential_seed", &self.credential_seed.as_ref().map(|_| "<redacted>"))
            .finish_non_exhaustive()
    }
}

/// An all-`None` status: what [`AgentMesh::credential`](crate::AgentMesh::credential)
/// and [`MeshNode::credential`](crate::MeshNode::credential) report when no
/// `credential_renewal` was configured. Not a claim that the credential is
/// healthy — a claim that nothing here is watching it.
pub(crate) fn unwatched_credential_status() -> CredentialStatus {
    CredentialStatus::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_credential_with_no_iat_is_still_scheduled_from_the_30_day_convention() {
        let exp = 1_800_000_000i64;
        let at = credential_renew_at(&CredentialClaims { sub: None, iat: None, exp: Some(exp) })
            .expect("a deadline");
        let issued = exp * 1000 - ASSUMED_CREDENTIAL_LIFETIME_MS;
        assert_eq!(at, issued + (ASSUMED_CREDENTIAL_LIFETIME_MS as f64 * VOUCH_RENEWAL_FRACTION) as i64);
    }

    #[test]
    fn an_inverted_window_has_no_deadline() {
        assert_eq!(
            credential_renew_at(&CredentialClaims {
                sub: None,
                iat: Some(2_000),
                exp: Some(1_000)
            }),
            None
        );
    }

    #[test]
    fn the_endpoint_trims_exactly_one_trailing_slash() {
        assert_eq!(
            credential_endpoint("https://mesh.example"),
            "https://mesh.example/v1/node-credential"
        );
        assert_eq!(
            credential_endpoint("https://mesh.example/"),
            "https://mesh.example/v1/node-credential"
        );
    }

    #[test]
    fn the_failure_warning_names_the_key_the_cause_and_the_consequence() {
        let w = credential_renewal_failed_warning(
            Some("UNODE7SAMPLEKEYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            "connection refused",
            Some("2026-08-24T00:00:00.000Z"),
        );
        assert_eq!(w.code, "credential_renewal_failed");
        assert!(w.message.contains("UNODE7SAMPLE…"), "{}", w.message);
        assert!(w.message.contains("connection refused"));
        assert!(w.message.contains("It expires 2026-08-24T00:00:00.000Z"));
        assert!(w.message.ends_with("it will keep retrying."));

        let unknown = credential_renewal_failed_warning(None, "boom", None);
        assert!(unknown.message.contains("for this node…: boom"));
        assert!(unknown.message.contains("It expires at an unknown time"));
        assert_eq!(unknown.subject, None);
    }
}
