//! The AgentMesh client over async-nats (AgentMesh 0.2). Mirrors the TS
//! `mesh.ts`: connect, register, discover, request (bare-vs-task), respond via
//! offering handlers, emit, subscribe, node-scoped heartbeat. Every outbound
//! envelope is signed (§4.5); every inbound one is verified on decode.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use futures::StreamExt;
use nkeys::KeyPair;
use serde_json::{json, Value};

use crate::accept::{accept_envelope, is_accept_signal, queued_ack_of, QueuedAck};
use crate::agreement::{
    agreement_covers, agreement_required, AgreementDocument, AgreementRequiredDetails,
    AgreementWant,
};
use crate::allowance::{
    allowance_insufficient, estimate_tokens, AllowanceDecision, AllowanceMeter, AllowanceQuestion,
    AllowanceStatus, OnExhausted, SpendLedger, Usage, WorkScope,
};
use crate::budget::{Budget, CostCeiling, TaskBudgets};
use crate::cancel::{
    cancel_request_payload, canceled_update_payload, failed_update_payload, is_terminal_task_state,
    propagated_cancel_note, validate_cancel_input, validate_stop_qualifier, CancelInput,
    CancelReason, StopQualifier, CANCEL_OFFERING,
};
use crate::codec;
use crate::credential::{
    CredentialRenewal, CredentialRenewer, CredentialRenewerOptions, CredentialStatus, RenewalAgent,
    RenewalRoster,
};
use crate::envelope::{Envelope, PrimitiveType};
use crate::error::{ErrorCode, ErrorObject, MeshError, Result};
use crate::identity::{create_attestation, keypair_from_seed, sign_envelope};
use crate::inbound::{
    self, FrameProvenance, InboundOptions, InboundRefusal, InboundSource, SecurityWarning,
    SeenEnvelopes,
};
use crate::manifest::{Manifest, NodeRef, Offering, PublicBlock};
use crate::sku::{public_sku_of, sku_digest, sku_for, validate_skus, Sku, SkuPriceModel};
use crate::revoked_senders::{RevocationAnswer, RevokedSenders};
use crate::subjects;
use crate::util::child_span;
use crate::vouch::{
    vouch_check_interval, vouch_renew_at, VouchStatus, DEFAULT_VOUCH_TTL_MS,
    EPHEMERAL_VOUCH_TTL_MS,
};

pub(crate) const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
/// §11: max wait between stream chunks / for the whole stream (mirrors TS).
const CHUNK_TIMEOUT: Duration = Duration::from_secs(30);
const STREAM_TIMEOUT: Duration = Duration::from_secs(300);
/// How long the EXT-6 guard handshake waits for the admission service (mirrors
/// TS). Silence past this is a refusal, not a retry: see `request_guard`.
const GUARD_TIMEOUT: Duration = Duration::from_secs(5);
/// How long the best-effort §10.8 cancel notification waits for the
/// performer's reply before giving up quietly. Short on purpose: for the
/// requester, cancellation is effective when the task UPDATE is published —
/// this request is notification, and a performer that is offline (the cancel
/// sitting in its mailbox, §16.4) is the mesh working, not a failure.
const CANCEL_NOTIFY_TIMEOUT: Duration = Duration::from_secs(5);
/// §18.6: how long the mailbox consumer may hold a message unacked before the
/// server redelivers it. Redelivery is the point — the ack happens only after a
/// handler has been dispatched, so a crash mid-handling gets another attempt.
const MAILBOX_ACK_WAIT: Duration = Duration::from_secs(30);
/// How long a resolved consumer OWNER is trusted before the registry is asked
/// again (§19.5, mirrors TS). Five minutes: an agent's owner effectively never
/// changes, and this keeps a busy seller from a registry round trip per
/// request.
const AGREEMENT_TTL_MS: i64 = 300_000;
/// Where the platform answers "has this account accepted my terms?" (§19.5).
/// The seller is the verified envelope `from`; the answer is filtered to it.
const AGREEMENT_LOOKUP_SUBJECT: &str = "mesh.agreements.list";
/// §18.6: how many times the server will redeliver one buffered message before
/// giving up on it. Bounded so a message that reliably crashes the handler stops
/// being a loop.
const MAILBOX_MAX_DELIVER: i64 = 5;
/// §18.6 Event Consumer: how long a durable event delivery may sit unacked
/// before redelivery. Same figure as the mailbox's, pinned separately because
/// the spec pins them separately.
const EVENT_ACK_WAIT: Duration = Duration::from_secs(30);
/// §18.6 Event Consumer: redelivery bound, for the same reason as
/// [`MAILBOX_MAX_DELIVER`].
const EVENT_MAX_DELIVER: i64 = 5;
/// The registry reaper's liveness offering. Its answer is the one bare-mode
/// respond that stays on the transport reply subject (§6.4a): the probe asks
/// "is a process subscribed here right now", so the cheap same-subject answer
/// IS the information, and routing it through the reaper's inbox would add a
/// round trip to the hottest periodic path on the mesh while proving less.
const REGISTRY_PROBE_OFFERING: &str = "__registry_probe__";
/// How many mailbox messages one §16.4 drain fetch asks for. Bounds how much of
/// a backlog is in flight at once: a 25 MB mailbox is drained in batches, never
/// requested in one go.
const MAILBOX_DRAIN_BATCH: usize = 100;
/// How often the §16.4 drain is re-run while an agent stays up.
///
/// Each pass is bounded to the backlog present when it binds, and a bound on its
/// own leaves the *tail* — everything the mailbox captured after the bind, which
/// is every live message, because the mailbox stream captures the very subject
/// the live subscription is on — sitting on the durable consumer unacked forever.
/// The cursor stays where the pass left it, the tail grows for the life of the
/// process, and the next restart binds, sees the whole tail as backlog and
/// dispatches it, with a fresh process's §22.2 memory unable to suppress any of
/// it. Re-running the bounded pass keeps the cursor at the head.
///
/// **Why 60 seconds.** The number that matters is how much traffic can pile up
/// between two passes, because a re-drain re-delivers everything the live path
/// already handled and relies on §22.2 to suppress it. That memory holds
/// [`MAX_SEEN_INBOX_IDS`](crate::MAX_SEEN_INBOX_IDS) (5,000) `(from, id)` pairs
/// and evicts oldest-first, and the tail is by construction the *newest* traffic
/// — so every message in a tail of 5,000 or fewer is still remembered, and the
/// re-drain acks it without dispatching. Breaking that at 60s takes a sustained
/// 83 inbound messages a second, for a full minute, on one agent: two orders of
/// magnitude above an agent whose handler calls a model. Against that, a pass
/// costs one `STREAM.INFO` plus one `CONSUMER.INFO`, and a pull only when the
/// tail is non-empty — two JetStream round trips a minute per agent.
pub const DEFAULT_MAILBOX_DRAIN_INTERVAL: Duration = Duration::from_secs(60);
/// Floor on a caller-configured drain interval. A pass is two JetStream requests
/// plus a pull; without a floor, zero is a busy loop against the broker.
pub const MIN_MAILBOX_DRAIN_INTERVAL: Duration = Duration::from_secs(1);

/// A reconnect notification channel fed by async-nats' `event_callback`.
///
/// The transport's own event, not a poll of [`async_nats::Client::connection_state`]:
/// a poll learns "connected" long after the gap it is meant to react to, and a
/// gap is exactly when the live subscription missed messages the mailbox holds.
///
/// A broadcast rather than a `Notify` because one connection can host many agents
/// (§4.1), each running its own drain loop, and every one of them has to hear the
/// same reconnect. It doubles as a manual nudge: a re-`register` on an agent whose
/// loop is already running sends here rather than starting a second loop.
pub(crate) type DrainTrigger = tokio::sync::broadcast::Sender<()>;

/// Whether one async-nats connection event means "the transport came back, look at
/// the mailbox again", updating the seen-a-disconnect state as it goes.
///
/// Named and separated from the connect call because the asymmetry is easy to get
/// wrong in both directions. `Event::Connected` fires for the FIRST connection as
/// well as for every reconnect, so treating it alone as a reconnect costs every
/// process a redundant drain pass at startup; ignoring `Connected` entirely, or
/// firing on `Disconnected`, would miss the only moment that matters — a gap in the
/// live subscription is exactly when the mailbox is holding something nothing
/// dispatched, and the pass has to happen once the transport is back, not while it
/// is away.
fn is_reconnect(event: &async_nats::Event, was_disconnected: &std::sync::atomic::AtomicBool) -> bool {
    use std::sync::atomic::Ordering::SeqCst;
    match event {
        async_nats::Event::Disconnected => {
            was_disconnected.store(true, SeqCst);
            false
        }
        async_nats::Event::Connected => was_disconnected.swap(false, SeqCst),
        _ => false,
    }
}

/// The configured §16.4 re-drain interval, or the default — never below the floor.
/// Clamped rather than trusted: `Duration::ZERO` is a busy loop against the
/// broker's JetStream API.
pub(crate) fn clamp_drain_interval(configured: Option<Duration>) -> Duration {
    match configured {
        Some(d) => d.max(MIN_MAILBOX_DRAIN_INTERVAL),
        None => DEFAULT_MAILBOX_DRAIN_INTERVAL,
    }
}

/// Options for connecting to the mesh.
#[derive(Default)]
pub struct ConnectOptions {
    /// Agent nkey seed. If absent, a fresh agent key is generated.
    pub agent_seed: Option<String>,
    /// Node nkey seed. If absent, the agent self-hosts (node key = agent key).
    pub node_seed: Option<String>,
    /// JWT for an authenticated connection (e.g. the guest credential from the
    /// auth service). The server nonce is signed with the connection's key —
    /// the node seed when set, else the agent seed (§4.2/§18.2). Without a JWT
    /// the connection is anonymous (dev servers only).
    pub jwt: Option<String>,
    /// X25519 encryption secret (base64url, from
    /// [`sealed::create_encryption_identity`](crate::sealed::create_encryption_identity)).
    /// When set, `register` publishes the public half as the manifest's
    /// `encryption_key`, and sealed-room invites addressed to this agent can be
    /// opened. Distinct from the signing key (core §4.3).
    pub encryption_seed: Option<String>,
    /// How often the §16.4 mailbox drain is re-run while this agent stays up.
    /// Default [`DEFAULT_MAILBOX_DRAIN_INTERVAL`] (60s); anything below
    /// [`MIN_MAILBOX_DRAIN_INTERVAL`] is clamped up to it.
    ///
    /// The drain is also re-run immediately on every transport reconnect, which is
    /// the trigger that matters — a reconnect gap is exactly when the mailbox
    /// holds something the live subscription missed. This interval is the backstop,
    /// and what it really bounds is the *tail*: see
    /// [`DEFAULT_MAILBOX_DRAIN_INTERVAL`] for why the bound is the §22.2 memory's
    /// size and why 60s clears it by two orders of magnitude.
    pub mailbox_drain_interval: Option<Duration>,
    /// Lifetime (ms) of the node vouches this agent mints for itself (§4.4),
    /// and the basis of the renewal cadence: the agent re-vouches at two thirds
    /// of the TTL ([`crate::vouch::VOUCH_RENEWAL_FRACTION`]). Default
    /// [`crate::vouch::DEFAULT_VOUCH_TTL_MS`] (30 days) for a registration that
    /// declares an `availability_class`, [`crate::vouch::EPHEMERAL_VOUCH_TTL_MS`]
    /// (72h) otherwise (§9.2). An explicit value here always wins over that
    /// split — mirroring the TS SDK's `vouchTtlMs`.
    pub vouch_ttl_ms: Option<i64>,
    /// Keep the connection credential alive (§4.8).
    ///
    /// The credential is a lease with a finite expiry just like the vouch
    /// above, and no renewal is a scheduled outage. Set this and the SDK renews
    /// it at two thirds of its own lifetime, on the same schedule, through
    /// `POST {api_base}/v1/node-credential`.
    ///
    /// Renewal is a plain HTTPS call authorized by proof-of-possession of the
    /// credential's key and this agent's key, so it needs no live mesh
    /// connection and works on a credential that has ALREADY lapsed. Persist
    /// what `on_renewed` hands you: an unpersisted renewal is undone by the next
    /// restart.
    ///
    /// Ignored when no `jwt` is set — an anonymous connection holds no
    /// credential to renew. See [`CredentialRenewal`].
    pub credential_renewal: Option<CredentialRenewal>,
    /// The naming rule: refuse every send this agent originates (`request*`,
    /// `request_stream`, `emit`, `publish_feed`, `open_room*`, `join_room`)
    /// until its handle follows the global standard, its name, a dot and its
    /// owner's email, at the naming service. A refusal is a `NOT_NAMED`
    /// [`MeshError::Refusal`] whose message is the owner's words and whose
    /// details carry the proposed handle; nothing is built, signed or
    /// published. [`RequireNamed::registrar`](crate::naming_gate::RequireNamed::registrar)
    /// asks https://naming.agentmesh.ai. See [`crate::naming_gate`].
    ///
    /// ON BY DEFAULT since 2026-09-27 (no anonymous agents): `None` means
    /// [`RequireNamed::registrar`](crate::naming_gate::RequireNamed::registrar)
    /// with the default naming service, when the `http` feature is on (it is
    /// by default). Set [`allow_unnamed`](Self::allow_unnamed) to turn it off.
    pub require_named: Option<crate::naming_gate::RequireNamed>,
    /// Turn the naming rule off. For tests only: an agent on a real mesh that
    /// sends without a verified name is refused by the platform as well. The
    /// TypeScript SDK's `requireNamed: false`.
    pub allow_unnamed: bool,
}

/// Connect to NATS, with JWT + nkey nonce-signing auth when a JWT is provided
/// (§18.2), else anonymously (dev servers).
///
/// Returns the client together with a [`DrainTrigger`] that fires on every
/// **re**connect. async-nats reports connection lifecycle through
/// `ConnectOptions::event_callback`, and that callback can only be installed at
/// connect time — hence the channel is created here, before the client exists, and
/// handed back for whoever ends up owning it.
///
/// `Event::Connected` also fires for the FIRST connection, so it is only treated as
/// a reconnect once a `Disconnected` has been seen. Without that, every process
/// would take a redundant extra drain pass at startup.
pub(crate) async fn connect_client(
    url: &str,
    jwt: Option<String>,
    signing_seed: &str,
) -> Result<(async_nats::Client, DrainTrigger)> {
    connect_client_with(url, jwt, signing_seed, None).await
}

/// As [`connect_client`], with an optional custom inbox prefix.
///
/// Needed by the `acl` grade's room-scoped connection: the rooms service mints
/// that credential permitting `mesh.aclroom.<id>.>` and a room-scoped reply
/// space and NOTHING else, and returns the latter as `inbox_prefix`. A connection
/// left on the default `_INBOX.` therefore has its OWN inbox subscription denied
/// by the broker. Room traffic still flows, which is exactly why this is easy to
/// miss — it surfaces later as an unrelated request failing obscurely.
pub(crate) async fn connect_client_with(
    url: &str,
    jwt: Option<String>,
    signing_seed: &str,
    inbox_prefix: Option<&str>,
) -> Result<(async_nats::Client, DrainTrigger)> {
    // Capacity 1: the payload is "something changed, look again", so a second
    // signal that arrives before the first is read adds nothing. A lagging
    // receiver sees `RecvError::Lagged`, which the drain loop treats exactly like
    // a reconnect.
    let (trigger, _) = tokio::sync::broadcast::channel::<()>(1);
    let cb_trigger = trigger.clone();
    let was_disconnected = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut opts = async_nats::ConnectOptions::new().event_callback(move |event| {
        let trigger = cb_trigger.clone();
        let was_disconnected = was_disconnected.clone();
        async move {
            if is_reconnect(&event, &was_disconnected) {
                // No receiver yet (or none any more) is not an error: an agent
                // that never registered has no mailbox to drain.
                let _ = trigger.send(());
            }
        }
    });
    if let Some(prefix) = inbox_prefix {
        opts = opts.custom_inbox_prefix(prefix);
    }
    let client = match jwt {
        Some(jwt) => {
            let seed = signing_seed.to_string();
            opts.jwt(jwt, move |nonce| {
                let seed = seed.clone();
                async move {
                    let kp = KeyPair::from_seed(&seed)
                        .map_err(|e| async_nats::AuthError::new(e.to_string()))?;
                    kp.sign(&nonce).map_err(|e| async_nats::AuthError::new(e.to_string()))
                }
            })
            .connect(url)
            .await
        }
        None => opts.connect(url).await,
    };
    client
        .map(|c| (c, trigger))
        .map_err(|e| MeshError::Transport(e.to_string()))
}

/// Options for registering an agent.
///
/// `Clone` because `register` keeps a copy: a §4.4 vouch renewal months later
/// re-registers what the agent actually registered, not whatever the caller's
/// value has since become.
#[derive(Clone, Default)]
pub struct RegisterOptions {
    pub name: String,
    pub description: String,
    pub version: Option<String>,
    pub capabilities: Vec<String>,
    pub offerings: Vec<Offering>,
    /// The hosting node's declared profile (§9.7). For node-hosted agents this
    /// defaults to the node's profile; set it here to override per-register.
    pub node_profile: Option<crate::manifest::NodeDeclaredProfile>,
    /// Owner identity seed (§8.6). When set (and its key differs from the
    /// node's), the agent registers under this owner key with an owner-signed
    /// attestation — grouping it with the owner's other agents (the roster)
    /// even across nodes/devices. Defaults to node ownership.
    pub owner_seed: Option<String>,
    /// Discovery listing tier (§8.6): "public" (default), "unlisted", or
    /// "private".
    pub visibility: Option<String>,
    /// How inbound requests are handled (§8.2): `"service"` (no person in the
    /// loop) or `"interactive"` (delivered into a live session somebody is
    /// using, so sending may interrupt them).
    ///
    /// Declare it honestly — callers filter on it, and this is the only
    /// machine-readable answer to "does messaging this agent interrupt a human?".
    /// Leaving it unset is legitimate and means unknown, which a careful caller
    /// reads as `interactive` (§8.3a); it is never defaulted to `"service"`.
    pub interaction: Option<String>,
    /// The product answering here ("claude-code", "openclaw", "letta"), its
    /// version, and the model behind it — self-declared, usually prefilled by
    /// the join path. See the same fields on [`crate::manifest::Manifest`].
    pub harness: Option<String>,
    pub harness_version: Option<String>,
    pub model: Option<String>,
    /// Ask the mesh to filter this agent's inbox (EXT-6 admission, §7.1): the
    /// admission service checks each inbound sender against this agent's stored
    /// roster before delivery, dropping blocked and flooding senders, and relays
    /// what survives to the private `.guarded` subject the agent then listens on.
    ///
    /// **Best-effort by design.** The switch to the private subject happens only
    /// on the service's explicit ok; a refusal, a rate limit, a timeout, no
    /// admission service at all, or a raced reply all leave this agent on its
    /// public inbox, unfiltered but *reachable*. That asymmetry is deliberate —
    /// see [`AgentMesh::register`] for why the other direction is silent and
    /// total.
    ///
    /// **Known race against this crate's registration.** The TypeScript SDK
    /// *requests* its registration and waits for the registry's answer before
    /// asking to be guarded; this crate publishes it fire-and-forget (which is
    /// what lets it work peer-to-peer with no registry at all). So the guard
    /// request can arrive before the manifest is stored, and the admission service
    /// refuses to guard an unregistered agent by saying nothing — leaving this
    /// agent unguarded on a mesh that would have guarded it. It fails toward
    /// reachable, which is the right direction, but it does not self-correct
    /// inside one process: the first `register` fixes which subject this agent
    /// listens on, so a second one cannot move it and will *withdraw* the guard
    /// instead. Read [`AgentMesh::listening_on_guarded`] rather than assuming; the
    /// only way back to a guarded subscription is a fresh one, so where guarding is
    /// load-bearing, `close` and reconnect rather than calling `register` twice.
    pub guarded: bool,
    /// Declared commercial terms (§19.1). Validated at registration — where
    /// the operator can see a refusal, not at some later discovery read — and
    /// each SKU's digest (the identity an agreement binds to, §19.5) is cached
    /// for the admission check. An offering covered by no SKU is FREE.
    pub skus: Option<Vec<Sku>>,
    /// The §8.7 public block (the storefront). When SKUs are declared and this
    /// carries no explicit `skus`, `register` fills `public.skus` with each
    /// SKU's id, price, and digest — price as pre-admission data (§19.1). An
    /// explicit `public.skus` wins: advertising less than you sell is a choice
    /// the spec protects.
    pub public: Option<PublicBlock>,
    /// External services this agent integrates with (§8.8) — "works with the
    /// Colorado DMV". An integration claim and nothing more: never a claim of
    /// affiliation or endorsement, verified by nobody, and presenting *as* the
    /// named service rather than alongside it is impersonation. Served
    /// pre-admission, so declare only what is true.
    pub works_with: Option<Vec<crate::manifest::WorksWith>>,
    /// The card-level data-use declaration (§8.10): what happens to content a
    /// caller hands this agent — training, retention, human access, and the
    /// services content passes through. Self-declared, ONE per agent, and
    /// carried on the manifest verbatim: the REGISTRY is the validator, and
    /// it drops an unreadable declaration WHOLE on the way in (a privacy
    /// claim served in part misleads more than none at all). This crate
    /// deliberately does not duplicate those drop rules — pass-through only,
    /// so the registry's verdict is the only verdict. `None` means the agent
    /// has not said, which is a different statement from every declared one.
    pub data_use: Option<crate::manifest::AgentDataUse>,
    /// Whether callers should seal what they send this agent (§8.9).
    ///
    /// Usually left at [`SealingChoice::Derive`]: the SDK reads it off what the
    /// agent already declared, so an offering that asks for a third-party
    /// sign-in gets `required` and an agent that declares `works_with` gets
    /// `preferred`, both without anybody configuring encryption. Set it to
    /// raise the posture, or to [`SealingChoice::None`] to decline one the
    /// derivation would otherwise apply.
    ///
    /// Ignored, rather than refused, when the agent has no `encryption_seed`: a
    /// posture is a promise about reading, and there is nothing here to read
    /// with.
    pub sealing: crate::sealing::SealingChoice,
}

/// Discovery query (§6.2). All fields optional; an empty query returns every
/// registered agent (subject to the registry's limit). Availability is joined
/// from presence at query time (§9.6).
#[derive(Debug, Default, serde::Serialize)]
pub struct DiscoverQuery {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offering_id: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Restrict to agents hosted by a specific node (§9.3).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    /// Restrict to agents grouped under a specific owner key (§8.6) — a
    /// person's or org's roster. Visibility rules still apply.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    /// Only these agents, by agent ID (§9.3). Naming is not browsing: an
    /// unlisted agent, or one the registry keeps off its listings, is
    /// returned when named; a private one still only to its owner.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub agent_ids: Vec<String>,
}

/// How long a `request` waits for the substantive respond (§6.4
/// `config.timeout_ms`'s SDK-side analogue). Reset — not extended — by the
/// §6.4a accept signal: an accept means the wait is no longer blind, and the
/// caller grants the running handler a fresh window. The §7.7 budget deadline,
/// when one was attached, is absolute and never moved by an accept.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// A pre-substantive delivery signal observed while a `request` waits (§6.4a).
/// Neither resolves the request: it stays outstanding until the first
/// `respond` whose `payload.status` is not `"accepted"`.
#[derive(Debug, Clone)]
pub enum DeliverySignal {
    /// The §6.4a accept: delivered and admitted, a handler is running now.
    /// The response timeout has just been reset.
    Accepted {
        /// The verified accept envelope itself.
        envelope: Envelope,
    },
    /// The node-level queued acknowledgement (§6.4a, §16.4): a mailbox holds
    /// the message for an attended session; the real reply arrives later at
    /// this agent's own inbox, correlated by `in_reply_to`. Deliberately not
    /// an admission claim. After this signal the wait rejects promptly with
    /// the SDK-local `REQUEST_QUEUED` — the reply channel will never carry
    /// anything more, so there is nothing left to wait on.
    Queued { inbox_id: Option<String> },
}

/// Where [`RequestOptions::on_signal`] delivery signals go.
pub type DeliverySignalSink = Arc<dyn Fn(DeliverySignal) + Send + Sync>;

/// Options for [`AgentMesh::request_with_options`].
#[derive(Clone, Default)]
pub struct RequestOptions {
    /// The §7.7 budget offer to attach. Validated before sending.
    pub budget: Option<Budget>,
    /// Response timeout ([`DEFAULT_REQUEST_TIMEOUT`] when unset). Reset by an
    /// accept (§6.4a); a §7.7 deadline is not.
    pub timeout: Option<Duration>,
    /// `config.accepted_output` (§6.4): the output media types this caller can
    /// take. Pre-flighted against the recipient's offering `output_modes` when a
    /// manifest is at hand (§6.4b).
    pub accepted_output: Option<Vec<String>>,
    /// The recipient's manifest, when the caller holds one (from `discover` or
    /// `get_manifest`). With it, the request is addressed to the manifest's
    /// **resolved** endpoint (§14.4 — the carried `endpoints.inbox` wins over
    /// subject construction) and pre-flighted against its **declared** limits
    /// (§6.4b — `limits.max_inbound_chars` and the offering's content modes).
    /// Without it, the SDK constructs the subject (it is the convention's
    /// legitimate constructor) and pre-flights against the §22.5 default cap;
    /// content-type checks need a manifest and are skipped.
    pub recipient: Option<Manifest>,
    /// Observer for §6.4a delivery signals (the accept, the queued ack). None
    /// of these resolve the request.
    pub on_signal: Option<DeliverySignalSink>,
    /// Override the §8.9 seal decision for this one request.
    ///
    /// Left `None`, the SDK seals when `recipient`'s manifest asks it to and
    /// that manifest carries a §8.3-verified key. `Some(true)` demands sealing
    /// and fails the request if it cannot be done, which is the right setting
    /// for a caller that knows it is sending a customer record whatever the
    /// recipient declared. `Some(false)` sends in the clear, and a recipient
    /// declaring `required` will refuse it.
    pub seal: Option<bool>,
}

/// The result of a `request`.
#[derive(Debug)]
pub struct RequestResult {
    /// Present in Task mode; `None` for a bare (single terminal reply) response.
    pub task_id: Option<String>,
    pub payload: Value,
    pub envelope: Envelope,
    /// Whether a §6.4a accept signal preceded the substantive respond.
    pub accepted: bool,
}

/// A single chunk of a streaming response (§11).
#[derive(Debug, Clone)]
pub struct StreamChunk {
    pub chunk_index: u64,
    pub data: Value,
    pub content_type: Option<String>,
    pub is_final: bool,
}

/// A live streaming response (§11.3): the verified opening envelope plus a
/// channel of chunks. The channel closes after the final chunk (or an error
/// item). §11.6 verification is applied per chunk: intermediate chunks may be
/// unsigned (unless `sign_chunks` was requested), a PRESENT signature must
/// verify, and the FINAL chunk must be signed and carry a `chunk_count` that
/// matches what actually arrived.
pub struct StreamResult {
    pub task_id: String,
    pub initial: Envelope,
    pub chunks: tokio::sync::mpsc::Receiver<Result<StreamChunk>>,
}

/// The producer side of a stream (§11.3, §11.6): publishes ordered chunks to
/// the task's stream subject. Intermediate chunks go unsigned unless the
/// requester asked for `sign_chunks`; `end()` publishes the signed FINAL chunk
/// (with `chunk_count`) plus the signed task-completion update.
///
/// Cheaply cloneable, and clones share the same chunk counter + closed flag
/// (via atomics), so the dispatcher can hand a writer to a handler and still
/// observe `is_closed()` / the correct `chunk_count` afterward to auto-end.
#[derive(Clone)]
pub struct StreamWriter {
    client: async_nats::Client,
    agent_id: String,
    agent_seed: String,
    requester: String,
    request_id: String,
    task_id: String,
    trace: crate::envelope::TraceContext,
    sign_chunks: bool,
    chunk_index: Arc<std::sync::atomic::AtomicU64>,
    closed: Arc<std::sync::atomic::AtomicBool>,
}

impl StreamWriter {
    fn chunk_env(&self, payload: Value) -> Envelope {
        let mut env = Envelope::new(PrimitiveType::Respond, &self.agent_id);
        env.to = Some(self.requester.clone());
        env.in_reply_to = Some(self.request_id.clone());
        env.task_id = Some(self.task_id.clone());
        env.trace = child_span(&self.trace);
        env.payload = Some(payload);
        env
    }

    fn sign(&self, env: &mut Envelope) {
        if let Ok(kp) = keypair_from_seed(&self.agent_seed) {
            let _ = sign_envelope(env, &kp);
        }
    }

    pub fn task_id(&self) -> &str {
        &self.task_id
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Publish one intermediate chunk.
    pub async fn write(&self, data: Value, content_type: Option<&str>) -> Result<()> {
        if self.is_closed() {
            return Err(MeshError::code(ErrorCode::Internal, "Cannot write to a closed stream"));
        }
        let idx = self.chunk_index.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut payload = json!({
            "status": "working",
            "chunk_index": idx,
            "final": false,
            "data": data,
        });
        if let Some(ct) = content_type {
            payload["content_type"] = json!(ct);
        }
        let mut env = self.chunk_env(payload);
        if self.sign_chunks {
            self.sign(&mut env);
        }
        self.client
            .publish(subjects::task_stream(&self.task_id), codec::encode(&env)?.into())
            .await
            .map_err(|e| MeshError::Transport(e.to_string()))
    }

    /// Publish the signed FINAL chunk (with chunk_count, §11.6) and the signed
    /// task-completion update (§11.3 step 6). Idempotent.
    pub async fn end(&self, data: Option<Value>) -> Result<()> {
        use std::sync::atomic::Ordering::SeqCst;
        if self.closed.swap(true, SeqCst) {
            return Ok(()); // already closed
        }
        let idx = self.chunk_index.fetch_add(1, SeqCst);
        let count = idx + 1;
        let output = data.unwrap_or(Value::Null);
        let payload = json!({
            "status": "completed",
            "chunk_index": idx,
            "final": true,
            "data": output.clone(),
            "chunk_count": count,
        });
        let mut env = self.chunk_env(payload);
        self.sign(&mut env);
        self.client
            .publish(subjects::task_stream(&self.task_id), codec::encode(&env)?.into())
            .await
            .map_err(|e| MeshError::Transport(e.to_string()))?;

        // §11.3 step 6: the completion update carries the final result as
        // `output` so the durable task record preserves the answer for
        // requesters that lost the stream (disconnect, restart).
        let mut update = self.chunk_env(json!({
            "status": "completed",
            "output": output,
        }));
        self.sign(&mut update);
        self.client
            .publish(subjects::task_update(&self.task_id), codec::encode(&update)?.into())
            .await
            .map_err(|e| MeshError::Transport(e.to_string()))
    }

    /// Publish a signed error envelope on the stream subject (stream failed).
    async fn fail(&self, message: String) -> Result<()> {
        use std::sync::atomic::Ordering::SeqCst;
        if self.closed.swap(true, SeqCst) {
            return Ok(());
        }
        let idx = self.chunk_index.load(SeqCst);
        let mut env = self.chunk_env(json!({
            "status": "failed",
            "chunk_index": idx,
            "final": true,
            "data": null,
        }));
        env.error = Some(ErrorObject {
            code: ErrorCode::Internal.as_str().to_string(),
            message,
            details: None,
            retryable: false,
            retry_after_ms: None,
        });
        self.sign(&mut env);
        self.client
            .publish(subjects::task_stream(&self.task_id), codec::encode(&env)?.into())
            .await
            .map_err(|e| MeshError::Transport(e.to_string()))
    }
}

type BoxFut = Pin<Box<dyn Future<Output = Result<Value>> + Send>>;
type Handler = Arc<dyn Fn(Value, RequestContext) -> BoxFut + Send + Sync>;
type StreamBoxFut = Pin<Box<dyn Future<Output = Result<()>> + Send>>;
type StreamHandler = Arc<dyn Fn(Value, StreamWriter, RequestContext) -> StreamBoxFut + Send + Sync>;
/// A per-offering §7.7 admission judgement ([`AgentMesh::on_admission`]): `Ok(())`
/// admits — the SDK then emits the §6.4a accept and runs the handler — and an
/// `Err` (typically [`crate::budget::budget_insufficient`] /
/// [`crate::budget::deadline_unmeetable`]) is the refusal of admission,
/// answered INSTEAD of an accept.
pub type AdmissionFn = Arc<dyn Fn(&Value, &RequestContext) -> Result<()> + Send + Sync>;
/// The host's incoming-cost estimator (EXT-8 §2,
/// [`AgentMesh::set_cost_estimator`]): the SDK cannot see the host's model
/// bill, so the host that can price a request better than the default
/// character heuristic says so here. Runs at admission, before the §6.4a
/// accept, for every inbound request while an allowance is armed.
pub type CostEstimatorFn = Arc<dyn Fn(&Value, &RequestContext) -> Usage + Send + Sync>;
/// The owner channel for `on_exhausted: "ask_owner"` (EXT-8 §2,
/// [`AgentMesh::on_allowance_question`]): the work is held unstarted while
/// this decides. `true` proceeds (the owner approved the spend); `false`
/// refuses with the same `BUDGET_INSUFFICIENT` shape a plain refusal answers.
pub type OwnerDecisionFn = Arc<dyn Fn(&AllowanceQuestion) -> bool + Send + Sync>;
/// The host's agreement lookup (§19.5, [`AgentMesh::on_agreement_lookup`]):
/// fetch a consumer OWNER's agreements on demand — the platform read. With
/// none registered, the SDK asks the platform itself at
/// `mesh.agreements.list`. An `Err` is NOT "no agreements": the caller treats
/// it as uncovered, so an outage refuses paid work rather than giving it away.
pub type AgreementLookupFn = Arc<dyn Fn(&str) -> Result<Vec<Value>> + Send + Sync>;

/// Options for [`AgentMesh::subscribe_durable`] (§18.6 Event Consumer). The
/// TypeScript SDK's `subscribe(pattern, handler, { durable, replay })` maps
/// here: calling `subscribe_durable` at all is `durable: true`, and `replay`
/// is this field.
#[derive(Debug, Clone, Copy, Default)]
pub struct DurableSubscribeOptions {
    /// Deliver the stream's retained history first (§18.6 "All for replay")
    /// instead of starting from new events. Only meaningful the first time a
    /// durable is created: an existing durable keeps its own cursor, and its
    /// deliver policy with it.
    pub replay: bool,
}

/// A running durable event subscription ([`AgentMesh::subscribe_durable`]).
pub struct DurableSubscription {
    durable: String,
    stop: tokio::task::AbortHandle,
}

impl DurableSubscription {
    /// The §18.6 durable consumer name this subscription is bound to.
    pub fn durable_name(&self) -> &str {
        &self.durable
    }

    /// Stop delivering. Aborts the delivery loop and NOTHING else: the durable
    /// consumer (its name, its cursor, its acks) stays on the server, which
    /// is what makes a later `subscribe_durable` with the same pattern resume
    /// where this one stopped instead of starting over. Deleting the durable
    /// is an operator act, not a side effect of hanging up.
    ///
    /// (`close()` on the agent ends the loop the same way; this exists so one
    /// subscription can end without closing the agent.)
    pub fn stop(&self) {
        self.stop.abort();
    }
}

/// Per-request context handed to `_ctx` offering handlers. `from` is the VERIFIED
/// caller: the envelope signature was checked against it at decode (§5.3).
#[derive(Debug, Clone)]
pub struct RequestContext {
    /// The caller's public nkey (signature-verified).
    pub from: String,
    /// The request envelope's id.
    pub request_id: String,
    /// The requester-assigned task id, when present.
    pub task_id: Option<String>,
    /// The inbound envelope's trace context (§13.1). Downstream calls made
    /// inside the handler inherit it automatically via the ambient task-local;
    /// this field is the explicit handle for code that outlives the handler.
    pub trace: crate::envelope::TraceContext,
    /// The requester's budget for this work (§7.7), verbatim from the request
    /// envelope. Read it BEFORE doing the work: accepting a request is a
    /// statement that the work fits inside it, and a handler that cannot
    /// finish inside it refuses at admission with
    /// [`crate::budget::budget_insufficient`] /
    /// [`crate::budget::deadline_unmeetable`] rather than accepting and
    /// failing mid-flight.
    pub budget: Option<Budget>,
}

/// Per-offering handler settings ([`AgentMesh::set_handler_options`]).
///
/// Like [`InboundOptions`], every default is the guarded one: the behavior
/// whose absence is invisible defaults ON, and opting out is explicit.
#[derive(Debug, Clone)]
pub struct HandlerOptions {
    /// Whether an inbound §10.8 cancel for a Task this handler is working is
    /// automatically forwarded to the handler's still-live delegates (the
    /// sub-requests it issued that have not reached a terminal state), with
    /// reason `upstream_cancelled` and the original reason carried in the
    /// note.
    ///
    /// **Default: true** — §10.8 says a performer MUST forward, and a
    /// stranded delegate burns the delegate's time on work nobody will read
    /// with nothing on the mesh able to see why. Set it to `false` only when
    /// this handler manages its delegates itself: it takes over deciding
    /// which sub-tasks to cancel, when, and with what note.
    pub propagate_cancel: bool,
    /// The §7.0 deferral threshold for this offering's bare handler. `None`
    /// (the default) keeps today's behaviour: the handler's return is the one
    /// terminal respond, however long it takes -- and a caller whose timeout
    /// is shorter simply never sees it. With a threshold set, a LIVE dispatch
    /// whose handler is still running when it elapses goes deferred instead:
    /// the dispatcher sends a non-terminal `{status: "working"}` respond
    /// carrying the dispatch task id (the same id delegation tracking and
    /// usage reporting already use), and when the handler eventually finishes
    /// it publishes the signed terminal update -- `completed` with the output,
    /// sealed exactly as a bare answer would have been, or `failed` -- on
    /// `mesh.task.{id}.update`, where the task manager records it durably
    /// (§7.4) and [`AgentMesh::await_task`] / [`AgentMesh::get_task`] recover
    /// it. Mailbox-drained dispatches never defer: their requester has no live
    /// wait to release, and the late terminal respond already reaches its
    /// inbox (§6.4). Pick a threshold under the callers' request timeout --
    /// the point is to answer before they stop listening.
    pub defer_after: Option<std::time::Duration>,
}

impl Default for HandlerOptions {
    fn default() -> Self {
        HandlerOptions { propagate_cancel: true, defer_after: None }
    }
}

/// One live sub-request (delegation) of a parent Task (§10.8 propagation).
struct SubDelegation {
    /// The agent the sub-request went to — where a propagated cancel is sent.
    delegate: String,
    /// The watcher on the sub-task's update subject, so propagation can end
    /// it when it removes the entry (the watcher's other exit is seeing the
    /// sub-task reach a terminal state itself). `None` only for the instant
    /// between recording the entry and spawning the watcher.
    watcher: Option<tokio::task::AbortHandle>,
}

/// The still-live delegations of one parent Task, plus which offering's handler
/// issued them — the key [`HandlerOptions`] are looked up by at propagation
/// time.
struct ParentDelegations {
    offering: String,
    subs: HashMap<String, SubDelegation>,
}

struct Inner {
    client: async_nats::Client,
    agent_id: String,
    node_id: String,
    agent_seed: String,
    node_seed: String,
    handlers: RwLock<HashMap<String, Handler>>,
    stream_handlers: RwLock<HashMap<String, StreamHandler>>,
    /// True when this agent is hosted by a MeshNode over a shared connection:
    /// it must not drain the connection on close, and the node's single
    /// heartbeat covers it (§9.6) so no per-agent heartbeat loop is started.
    hosted: bool,
    /// For hosted agents: the node's declared profile (§9.7), attached at
    /// register when the caller doesn't supply one.
    default_node_profile: Option<crate::manifest::NodeDeclaredProfile>,
    /// X25519 encryption secret (§4.3), if the agent declared one.
    encryption_seed: Option<String>,
    /// The mesh URL, retained so acl rooms can open a room-scoped second
    /// connection with a service-issued credential (§7.2).
    url: String,
    /// Background tasks (inbox listener, heartbeat) — aborted on close so a
    /// hosted agent detaches without touching the shared connection.
    tasks: std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
    /// §22 receiver-side settings. Behind a lock so a node-hosted agent (which
    /// does not go through `ConnectOptions`) can still configure them.
    inbound: RwLock<InboundOptions>,
    /// §22.2 duplicate memory for the live inbox (§14.1).
    seen_inbox: SeenEnvelopes,
    /// §22.2 duplicate memory for event subscriptions (§6.7). Separate from the
    /// inbox's so a flood of events cannot evict the inbox's memory — the gap
    /// §22.2 warns about opens for the traffic nobody was watching.
    seen_events: SeenEnvelopes,
    /// §6.4a reply correlation: request id → the channel its wait is
    /// listening on. A respond to a request, the bare answer and the §11.3
    /// step-2 opening alike, is published to the REQUESTER's inbox, never to
    /// the transport reply subject, so the inbox paths (live subscription and
    /// §16.4 drain) consult this map and forward a matching envelope to the
    /// wait instead of dispatching it. Registered before the request is
    /// published; removed when the wait ends, however it ends (RAII in
    /// [`PendingReply`]).
    pending_replies: std::sync::Mutex<HashMap<String, tokio::sync::mpsc::UnboundedSender<Envelope>>>,
    /// Which subject the LIVE inbox subscription is on (EXT-6 §7.1). `None`
    /// means there is no subscription yet; `Some(true)` means it is on the
    /// private `.guarded` subject, `Some(false)` the public inbox.
    ///
    /// Deliberately not a bare "am I guarded?" flag. An agent that is already
    /// listening is NOT re-pointed by a second `register`, so after a
    /// re-registration a `guarded` flag can say "yes" while the live
    /// subscription is still on the public inbox (or the reverse). Only this
    /// answers the question that matters — "can mail reach us on the subject
    /// anyone writes to?" — and that is the question a mesh-side guard entry has
    /// to agree with.
    inbox_subject_guarded: std::sync::Mutex<Option<bool>>,
    /// Whether the §16.4 mailbox drain LOOP has been started, so a second
    /// `register` nudges the running loop instead of starting a rival one.
    ///
    /// This used to be released when the drain finished, because the drain was a
    /// single pass; the loop does not finish, so the flag now stays raised for as
    /// long as the loop lives and `close` is what lowers it. It is a lifecycle
    /// flag, not a mutex — that job belongs to `drain_in_flight`.
    offline_drain_started: std::sync::atomic::AtomicBool,
    /// Whether one drain PASS is running. The mutex: `close` aborts the loop task
    /// without waiting for it, so a re-`register` can start a new loop while the
    /// old task is still suspended in a pull, and two passes over one durable
    /// consumer would each take their own bound and dispatch from the same cursor.
    /// Released by an RAII guard so an aborted pass releases it too.
    drain_in_flight: std::sync::atomic::AtomicBool,
    /// Fires on transport reconnect (and on a re-`register` nudge). See
    /// [`DrainTrigger`].
    drain_trigger: DrainTrigger,
    /// How often the §16.4 drain is re-run. See `ConnectOptions`.
    mailbox_drain_interval: Duration,
    /// Per-task budget state under latest-revision-wins (§7.7). Shared by both
    /// roles this agent may play: budgets it attaches as a requester, budgets
    /// it receives as a responder, and revisions surfaced by a task-update
    /// watch all land here, so `task_budget` is always the highest revision
    /// seen — the whole truth, per §7.7.
    task_budgets: TaskBudgets,
    /// §5.3: senders whose key the registry says is revoked, or who are
    /// paused, are refused before their request is handled
    /// ([`crate::revoked_senders`]). Consulted only while
    /// [`InboundOptions::refuse_revoked_senders`] is on.
    revoked_senders: RevokedSenders,
    /// §10.8 propagation basis: parent task id → the still-live sub-requests
    /// its handler issued. "Still live" IS presence in this map — an entry is
    /// recorded when a sub-request inside a dispatched handler comes back
    /// with a task id, and removed when the sub-task's update subject shows a
    /// terminal state or when propagation drains it.
    delegations: std::sync::Mutex<HashMap<String, ParentDelegations>>,
    /// Per-offering [`HandlerOptions`] ([`AgentMesh::set_handler_options`]). A
    /// offering with no entry gets the default, which is the guarded one
    /// (propagate).
    handler_options: RwLock<HashMap<String, HandlerOptions>>,
    /// Per-offering §7.7 admission judgements ([`AgentMesh::on_admission`]), run
    /// after the §22 protections and before the §6.4a accept. An offering with no
    /// entry is admitted once the SDK's own deterministic check (a budget
    /// deadline already past) passes.
    admissions: RwLock<HashMap<String, AdmissionFn>>,
    /// The EXT-8 allowance machine: the owner-signed spending policy (when
    /// armed), the spend ledger, metering and the admission judgement. Armed
    /// via [`AgentMesh::set_allowance`]; while armed (or fail-closed), every
    /// inbound request passes its judgement during the §7.7 admission phase,
    /// before the §6.4a accept.
    allowance: std::sync::Mutex<AllowanceMeter>,
    /// The §13.5 usage-receipt ledger: declared meter reports accumulated per
    /// task until the terminal respond attaches them as `payload.usage`.
    meter_usage: std::sync::Mutex<crate::metering::MeterLedger>,
    /// The host's incoming-cost estimator ([`AgentMesh::set_cost_estimator`]).
    /// `None` means the default [`estimate_tokens`] heuristic.
    cost_estimator: RwLock<Option<CostEstimatorFn>>,
    /// The `ask_owner` surface ([`AgentMesh::on_allowance_question`]). With no
    /// channel registered, an `ask_owner` exhaustion refuses: an owner channel
    /// that does not exist cannot approve spending the owner's money.
    owner_channel: RwLock<Option<OwnerDecisionFn>>,
    /// The `interaction` style this agent last registered under (§8.2/§8.3a).
    /// `Some("interactive")` suppresses the §6.4a accept: an attended agent
    /// cannot promise a handler is about to run — a person is in the loop —
    /// and §6.4a's MUST NOT for the attended case applies to it as much as to
    /// a node-held inbox. `None` (unregistered, or undeclared) and
    /// `Some("service")` emit accepts.
    interaction: std::sync::Mutex<Option<String>>,
    /// The §8.9 `sealing` posture this agent last registered under. Read by the
    /// dispatcher: `Some("required")` refuses a request that arrived in the
    /// clear. `None` (unregistered, or nothing declared) reads cleartext, which
    /// is what every agent did before the field existed.
    sealing: std::sync::Mutex<Option<String>>,
    /// §19 commerce state: the registered SKUs and their digests, the held
    /// agreements, and the caches the §19.5 admission check runs on.
    commerce: CommerceState,
    /// The [`RegisterOptions`] this agent last registered with — the input a
    /// §4.4 vouch renewal rebuilds the manifest from. `None` until `register`.
    register_opts: std::sync::Mutex<Option<RegisterOptions>>,
    /// The current vouch's window and the last renewal failure (§4.4). See
    /// [`AgentMesh::vouch`].
    vouch: std::sync::Mutex<VouchState>,
    /// Guard against overlapping in-flight renewals: the loop's tick and a
    /// manual `renew_vouch_if_due` may race, and two rebuild-and-re-register
    /// passes at once buy nothing.
    vouch_in_flight: std::sync::atomic::AtomicBool,
    /// The standalone renewal loop (§4.4). `None` for hosted agents — the
    /// node's ONE loop covers every agent it vouches for — and after
    /// deregister/close, so the timer never outlives the registration it
    /// maintains.
    vouch_task: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Lifetime to mint each vouch with, and the basis of the renewal cadence.
    vouch_ttl_ms: i64,
    /// Whether `vouch_ttl_ms` was set explicitly (it then overrides the §9.2
    /// declared-vs-ephemeral split).
    vouch_ttl_explicit: bool,
    /// The §4.8 credential lease loop, or `None` when the caller passed no
    /// `credential_renewal` (a guest credential, or a host that manages its own
    /// credential files). Separate from the vouch loop on purpose: the vouch is
    /// a claim ABOUT this agent that the registry enforces, the credential is
    /// what lets the connection exist at all, and they lapse independently.
    ///
    /// Always `None` for a hosted agent — the credential belongs to the node
    /// that holds the connection, and its [`MeshNode`](crate::MeshNode) runs the
    /// one loop that renews it.
    cred_renewer: std::sync::Mutex<Option<Arc<CredentialRenewer>>>,
    /// Set by `close`; a closed agent refuses `renew_vouch` and its loop stops.
    closed: std::sync::atomic::AtomicBool,
    /// The feeds this agent has declared (§6.6a), topic → kind. A BTreeMap so
    /// the manifest's `emits` list (§8.2) comes out sorted and a re-register
    /// is byte-stable. Declared via [`AgentMesh::declare_feed`]; read by
    /// `build_manifest`.
    declared_feeds: std::sync::Mutex<std::collections::BTreeMap<String, crate::feed::FeedKind>>,
    /// The §18.6 Feed Consumer's one pull loop and its handlers, shared by
    /// every durable feed subscription of this agent
    /// ([`AgentMesh::subscribe_feed_durable`]).
    feed_durable: Arc<crate::feed::FeedDurableShared>,
    /// The naming rule ([`crate::naming_gate`]): set when the agent connected
    /// with `require_named`, and then every send this agent originates asks it
    /// first.
    naming_gate: Option<Arc<crate::naming_gate::NamingGate>>,
}

/// The §4.4 renewal state one agent carries (mirrors the TS SDK's
/// `vouchExpiresAtIso`/`vouchRenewAtMs`/`lastVouchError` trio).
#[derive(Default)]
struct VouchState {
    /// RFC 3339 expiry of the current vouch, from its attestation.
    expires_at: Option<String>,
    /// Wall-clock instant (ms) at which the current vouch is due for renewal.
    /// Compared against the real clock on every tick, so a suspended host
    /// renews on the first tick after it wakes (see `crate::vouch`).
    renew_at_ms: Option<i64>,
    /// Why the last renewal attempt failed. Cleared by the next success.
    last_error: Option<String>,
}

/// The §19 commerce state one agent carries (mirrors the TS SDK's fields):
/// what it sells, at what digest, and which accounts have accepted.
#[derive(Default)]
struct CommerceState {
    /// The SKUs this agent registered (§19.1) — the coverage source the §19.5
    /// admission check runs [`sku_for`] over. `None`/empty means everything
    /// this agent offers is free.
    skus: std::sync::Mutex<Option<Vec<Sku>>>,
    /// sku id → its current digest (§19.1), computed once per registration.
    digests: std::sync::Mutex<HashMap<String, String>>,
    /// Where a human approves terms when the SKU names no `checkout_url`.
    approval_url: std::sync::Mutex<Option<String>>,
    /// §19.5 agreements this node holds, keyed by consumer owner. Verified on
    /// the way in; the platform is the store, this is the enforcing copy.
    agreements: std::sync::Mutex<HashMap<String, Vec<AgreementDocument>>>,
    /// agent id → (resolved at, owner key §8.6), cached [`AGREEMENT_TTL_MS`]:
    /// the account an agreement covers.
    owner_of: std::sync::Mutex<HashMap<String, (i64, Option<String>)>>,
    /// Optional host hook: fetch a consumer owner's agreements on demand (the
    /// platform read). [`AgreementLookupFn`].
    lookup: RwLock<Option<AgreementLookupFn>>,
}

impl Inner {
    fn agent_kp(&self) -> KeyPair {
        keypair_from_seed(&self.agent_seed).expect("valid agent seed")
    }
    fn node_kp(&self) -> KeyPair {
        keypair_from_seed(&self.node_seed).expect("valid node seed")
    }
    /// Sign an envelope with the agent key.
    fn sign(&self, env: &mut Envelope) {
        let kp = self.agent_kp();
        let _ = sign_envelope(env, &kp);
    }
    /// Publish one completed span, if this agent was told to (§13.1.1).
    ///
    /// Best-effort and deliberately swallowing: telemetry must never be able
    /// to fail the work it describes. A publish that fails because the
    /// connection is draining should cost a span, not a request.
    ///
    /// Not routed through `emit()`. Spans go to `mesh.trace.>` rather than the
    /// event bus, so nobody's `subscribe("trace.>")` handler receives them and
    /// they do not inherit event-bus semantics. The envelope is still signed
    /// the normal way, so a collector knows which agent claims each span.
    async fn publish_span(&self, input: crate::spans::SpanInput) {
        // Read and DROP before the await: a std RwLock guard is not Send, so
        // holding it across the publish would not compile and would be wrong
        // anyway.
        let enabled = self.inbound.read().map(|o| o.emit_spans).unwrap_or(false);
        if !enabled {
            return;
        }
        let mut env = Envelope::new(PrimitiveType::Emit, &self.agent_id);
        // The span describes THIS hop, so it carries the hop's own context
        // rather than opening a child: a span about a span is nobody's idea of
        // a useful trace.
        env.trace = input.trace.clone();
        env.payload = Some(crate::spans::span_payload(&input));
        self.sign(&mut env);
        if let Ok(bytes) = codec::encode(&env) {
            let _ = self
                .client
                .publish(crate::spans::trace_subject(&self.agent_id), bytes.into())
                .await;
        }
    }

    /// Record the renewal deadline implied by a manifest's vouch (§4.4).
    fn note_vouch(&self, manifest: &Manifest) {
        let mut v = self.vouch.lock().unwrap();
        v.expires_at = Some(manifest.node.attestation.expires_at.clone());
        v.renew_at_ms = vouch_renew_at(&manifest.node.attestation);
    }
    /// Build a bare `respond` for a completed request (task_id: None).
    /// `cost` is the §19.3 spend report — carried in the payload (and so
    /// covered by the signature) when the handler reported usage against an
    /// armed allowance.
    fn completed(
        &self,
        req: &Envelope,
        output: Value,
        cost: Option<CostCeiling>,
        usage: Option<Vec<crate::metering::UsageEntry>>,
    ) -> Envelope {
        let mut env = Envelope::new(PrimitiveType::Respond, &self.agent_id);
        env.to = Some(req.from.clone());
        env.in_reply_to = Some(req.id.clone());
        env.trace = child_span(&req.trace);
        env.payload = Some(completed_payload(output, cost, usage));
        self.sign(&mut env);
        env
    }

    /// The §19.3 spend report for a dispatch's terminal respond: what the
    /// host reported for this Task, priced by the armed allowance's currency.
    /// `None` when nothing was reported or no valid allowance is armed.
    fn reported_cost(&self, task_id: &str) -> Option<CostCeiling> {
        self.allowance.lock().unwrap().task_cost(task_id)
    }

    /// The §13.5 usage receipt for a dispatch's terminal respond: the declared
    /// meter entries the host reported for this Task, sorted by meter name.
    /// Attach-once — the ledger forgets the task as it hands these over.
    fn take_meters(&self, task_id: &str) -> Option<Vec<crate::metering::UsageEntry>> {
        self.meter_usage.lock().unwrap().take(task_id)
    }
    /// Raise a §22.7 local signal. A refusal that nobody can observe is
    /// indistinguishable from a crash on one side and from correct operation on
    /// the other, so every refusal comes through here — including the three that
    /// are deliberately silent to the sender.
    fn warn(&self, refusal: InboundRefusal, message: String, from: &str, subject: &str) {
        let sink = self.inbound.read().unwrap().on_security_warning.clone();
        if let Some(sink) = sink {
            sink(SecurityWarning {
                code: refusal.code().to_string(),
                message,
                subject: Some(subject.to_string()),
                from: Some(from.to_string()),
            });
        }
    }

    /// Build a bare error `respond` carrying a caller-built [`ErrorObject`]
    /// verbatim — the §7.7 refusal path, where `details` holds the estimate
    /// and flattening it would discard the counter-offer.
    fn refusal_resp(&self, req: &Envelope, error: ErrorObject) -> Envelope {
        let mut env = Envelope::new(PrimitiveType::Respond, &self.agent_id);
        env.to = Some(req.from.clone());
        env.in_reply_to = Some(req.id.clone());
        env.trace = child_span(&req.trace);
        env.payload = Some(json!({ "status": "failed" }));
        env.error = Some(error);
        self.sign(&mut env);
        env
    }

    /// Build a bare error `respond`.
    fn error_resp(&self, req: &Envelope, code: ErrorCode, message: String) -> Envelope {
        self.failed_resp(req, code, message, None)
    }

    /// Build a bare error `respond`, optionally carrying the §13.5 usage
    /// receipt: work that failed still consumed, and an honest receipt says so
    /// (rating decides what a failure costs). Attached BEFORE signing, so the
    /// envelope signature covers it — the receipt's entire design.
    fn failed_resp(
        &self,
        req: &Envelope,
        code: ErrorCode,
        message: String,
        usage: Option<Vec<crate::metering::UsageEntry>>,
    ) -> Envelope {
        let mut env = Envelope::new(PrimitiveType::Respond, &self.agent_id);
        env.to = Some(req.from.clone());
        env.in_reply_to = Some(req.id.clone());
        env.trace = child_span(&req.trace);
        let mut payload = json!({ "status": "failed" });
        if let Some(usage) = usage.filter(|u| !u.is_empty()) {
            payload["usage"] = json!(usage);
        }
        env.payload = Some(payload);
        env.error = Some(ErrorObject {
            code: code.as_str().to_string(),
            message,
            details: None,
            retryable: false,
            retry_after_ms: None,
        });
        self.sign(&mut env);
        env
    }
}

/// The terminal completed payload: `status` + `output`, plus the §19.3 spend
/// report as `payload.cost` (`{amount_micro, currency}`) when the handler
/// reported usage against an armed allowance. "The `cost` field of the
/// terminal `respond`" (§19.3) is the respond's PAYLOAD — where the platform's
/// task manager and the reference adapter already read it — never a new
/// envelope-level field. Absent stays omitted, never null.
fn completed_payload(
    output: Value,
    cost: Option<CostCeiling>,
    usage: Option<Vec<crate::metering::UsageEntry>>,
) -> Value {
    let mut payload = json!({ "status": "completed", "output": output });
    if let Some(cost) = cost {
        payload["cost"] = json!(cost);
    }
    // §13.5: the usage receipt — declared meter quantities — beside the spend
    // report, in the payload, where the envelope signature covers both.
    if let Some(usage) = usage.filter(|u| !u.is_empty()) {
        payload["usage"] = json!(usage);
    }
    payload
}

/// §7.2's terminal Task states, the set [`AgentMesh::await_task`] resolves on.
fn is_terminal_task_status(s: &str) -> bool {
    matches!(s, "completed" | "failed" | "canceled" | "exhausted" | "rejected")
}

/// The terminal payload out of a §7.4 task record, when the record is
/// terminal: the last history envelope whose `payload.status` matches the
/// record's state (the terminal update, which per §11.3 step 6 carries the
/// completion's `output`), else the state alone.
fn terminal_payload_of_record(record: &Value) -> Option<Value> {
    let state = record.get("state")?.as_str()?;
    if !is_terminal_task_status(state) {
        return None;
    }
    if let Some(history) = record.get("history").and_then(|h| h.as_array()) {
        for env in history.iter().rev() {
            if let Some(p) = env.get("payload") {
                if p.get("status").and_then(|s| s.as_str()) == Some(state) {
                    return Some(p.clone());
                }
            }
        }
    }
    Some(json!({ "status": state }))
}

/// An agent connected to the mesh.
#[derive(Clone)]
pub struct AgentMesh {
    inner: Arc<Inner>,
}

impl AgentMesh {
    /// Connect. The agent always has an Ed25519 keypair (its public nkey is the
    /// agent ID) and signs every envelope; a node key vouches for it (§4.4).
    pub async fn connect(url: &str, opts: ConnectOptions) -> Result<AgentMesh> {
        let agent_kp = match opts.agent_seed {
            Some(s) => keypair_from_seed(&s)?,
            None => KeyPair::new_user(),
        };
        let agent_seed = agent_kp.seed().map_err(|e| MeshError::Nkey(e.to_string()))?;
        let agent_id = agent_kp.public_key();
        let agent_id_for_gate = agent_id.clone();

        let (node_seed, node_id) = match opts.node_seed {
            Some(s) => {
                let kp = keypair_from_seed(&s)?;
                (s, kp.public_key())
            }
            None => (agent_seed.clone(), agent_id.clone()),
        };

        // The CONNECTION key signs the auth nonce: the node's when distinct
        // (§4.2), else the agent's own (self-hosting).
        // Retained for §4.8: the credential the renewer keeps alive is the one
        // this connection opened with, and `connect_client` consumes it.
        let jwt_in_hand = opts.jwt.clone();
        let (client, drain_trigger) = connect_client(url, opts.jwt, &node_seed).await?;

        let mesh = AgentMesh {
            inner: Arc::new(Inner {
                client,
                agent_id,
                node_id,
                agent_seed,
                node_seed,
                handlers: RwLock::new(HashMap::new()),
                stream_handlers: RwLock::new(HashMap::new()),
                hosted: false,
                default_node_profile: None,
                encryption_seed: opts.encryption_seed,
                url: url.to_string(),
                tasks: std::sync::Mutex::new(Vec::new()),
                inbound: RwLock::new(InboundOptions::default()),
                seen_inbox: SeenEnvelopes::new(),
                seen_events: SeenEnvelopes::new(),
                pending_replies: std::sync::Mutex::new(HashMap::new()),
                inbox_subject_guarded: std::sync::Mutex::new(None),
                offline_drain_started: std::sync::atomic::AtomicBool::new(false),
                drain_in_flight: std::sync::atomic::AtomicBool::new(false),
                drain_trigger,
                mailbox_drain_interval: clamp_drain_interval(opts.mailbox_drain_interval),
                task_budgets: TaskBudgets::new(),
                revoked_senders: RevokedSenders::new(),
                delegations: std::sync::Mutex::new(HashMap::new()),
                handler_options: RwLock::new(HashMap::new()),
                admissions: RwLock::new(HashMap::new()),
                allowance: std::sync::Mutex::new(AllowanceMeter::new()),
                meter_usage: std::sync::Mutex::new(crate::metering::MeterLedger::default()),
                cost_estimator: RwLock::new(None),
                owner_channel: RwLock::new(None),
                interaction: std::sync::Mutex::new(None),
                sealing: std::sync::Mutex::new(None),
                commerce: CommerceState::default(),
                register_opts: std::sync::Mutex::new(None),
                vouch: std::sync::Mutex::new(VouchState::default()),
                vouch_in_flight: std::sync::atomic::AtomicBool::new(false),
                vouch_task: std::sync::Mutex::new(None),
                vouch_ttl_ms: opts.vouch_ttl_ms.unwrap_or(DEFAULT_VOUCH_TTL_MS),
                vouch_ttl_explicit: opts.vouch_ttl_ms.is_some(),
                cred_renewer: std::sync::Mutex::new(None),
                closed: std::sync::atomic::AtomicBool::new(false),
                declared_feeds: std::sync::Mutex::new(std::collections::BTreeMap::new()),
                feed_durable: Arc::new(crate::feed::FeedDurableShared::default()),
                naming_gate: if opts.allow_unnamed {
                    None
                } else {
                    opts.require_named
                        .or_else(crate::naming_gate::RequireNamed::by_default)
                        .map(|cfg| Arc::new(crate::naming_gate::NamingGate::new(agent_id_for_gate.clone(), cfg)))
                },
            }),
        };

        // §4.8: armed here rather than at `register` — an agent that only sends
        // still needs a live credential, and an agent that never registers
        // still has one to keep alive. No JWT means an anonymous connection,
        // which holds no credential to renew.
        if let (Some(cfg), Some(jwt)) = (opts.credential_renewal, jwt_in_hand) {
            mesh.arm_credential_renewal(cfg, jwt);
        }
        // The naming rule: asked once now, so the first send has an answer.
        if let Some(gate) = mesh.inner.naming_gate.as_ref() {
            gate.check().await;
        }
        Ok(mesh)
    }

    /// Where this agent stands under the naming rule, as last checked. `None`
    /// when the agent did not connect with `require_named`, or before the
    /// first check.
    pub fn naming_status(&self) -> Option<crate::naming_gate::NamingStatus> {
        self.inner.naming_gate.as_ref().and_then(|g| g.current())
    }

    /// Ask the naming service again now, forgetting the cached answer: call it
    /// after naming the agent so it can send at once.
    pub async fn recheck_name(&self) -> Option<crate::naming_gate::NamingStatus> {
        let gate = self.inner.naming_gate.as_ref()?;
        gate.forget();
        Some(gate.check().await)
    }

    /// The naming rule's check, run first by every send this agent originates.
    pub(crate) async fn require_named(&self) -> Result<()> {
        match self.inner.naming_gate.as_ref() {
            Some(gate) => gate.require().await,
            None => Ok(()),
        }
    }

    /// Build and start the §4.8 renewal loop for this agent's own credential.
    ///
    /// The roster is the single agent this connection carries, consenting with
    /// its own seed — the degenerate case of the node shape, where node key and
    /// agent key may even be the same key.
    ///
    /// Failures go to whatever sink
    /// [`on_security_warning`](Self::on_security_warning) holds **at the time
    /// the failure happens**, not at connect: the sink is attached after
    /// `connect` returns, so capturing it here would capture nothing. The
    /// closure holds a WEAK handle, so the renewer never keeps a dropped agent
    /// alive to warn about it.
    fn arm_credential_renewal(&self, cfg: CredentialRenewal, jwt: String) {
        let sink = cfg.on_warning.clone().unwrap_or_else(|| {
            let weak = Arc::downgrade(&self.inner);
            Arc::new(move |w: SecurityWarning| {
                let Some(inner) = weak.upgrade() else { return };
                let sink = inner.inbound.read().unwrap().on_security_warning.clone();
                if let Some(sink) = sink {
                    sink(w);
                }
            })
        });
        let renewer = CredentialRenewer::new(CredentialRenewerOptions {
            api_base: cfg.api_base,
            jwt,
            // Defaults to this agent's own key, which is right whenever the
            // credential was minted against it; a bootstrap-minted credential
            // is bound to a separate key and names that key's seed.
            node_seed: cfg
                .credential_seed
                .unwrap_or_else(|| self.inner.agent_seed.clone()),
            agents: RenewalRoster::Fixed(vec![RenewalAgent::with_seed(
                self.inner.agent_id.clone(),
                self.inner.agent_seed.clone(),
            )]),
            transport: cfg.transport,
            on_renewed: cfg.on_renewed,
            on_warning: Some(sink),
        });
        renewer.start();
        *self.inner.cred_renewer.lock().unwrap() = Some(renewer);
    }

    /// Create an agent hosted by a `MeshNode` over its shared connection. The
    /// node key holds the connection; this agent gets its own keypair and is
    /// vouched by the node (§4.4). Used by `MeshNode::add_agent`.
    ///
    /// `drain_trigger` is the node's reconnect channel (§16.4): every agent on one
    /// connection shares it, so one reconnect re-drains every mailbox on the host.
    /// A node built over an embedder-supplied client has no such channel — nothing
    /// installed async-nats' event callback on that connection — and passes a
    /// channel nobody ever fires, leaving those agents with the periodic pass only.
    ///
    /// `encryption_seed` is per-agent, not per-node: `register` binds it to this
    /// agent's id with a §8.3 key claim, so two agents on one connection must
    /// not share one. `None` means this agent declares no `encryption_key` and
    /// participates in cleartext only (§4.3) — which is a choice, not a default
    /// to fall into. It used to be hardcoded here, which silently denied every
    /// node-hosted agent an encryption identity and locked them out of sealed
    /// rooms and EXT-7 alike.
    pub(crate) fn hosted_by(
        client: async_nats::Client,
        node_seed: String,
        node_id: String,
        // The node's mesh URL, or empty. Used only to dial an `acl` room's
        // scoped second connection — see MeshNode's `url` field.
        url: String,
        agent_seed: Option<String>,
        default_node_profile: Option<crate::manifest::NodeDeclaredProfile>,
        drain_trigger: DrainTrigger,
        mailbox_drain_interval: Option<Duration>,
        encryption_seed: Option<String>,
        // The node's explicit vouch TTL (§4.4), or `None` for the default:
        // hosted agents inherit the node's setting exactly as TS `addAgent`
        // passes `vouchTtlMs` only when it was set explicitly.
        vouch_ttl_ms: Option<i64>,
    ) -> Result<AgentMesh> {
        let agent_kp = match agent_seed {
            Some(s) => keypair_from_seed(&s)?,
            None => KeyPair::new_user(),
        };
        let agent_seed = agent_kp.seed().map_err(|e| MeshError::Nkey(e.to_string()))?;
        let agent_id = agent_kp.public_key();
        Ok(AgentMesh {
            inner: Arc::new(Inner {
                client,
                agent_id,
                node_id,
                agent_seed,
                node_seed,
                handlers: RwLock::new(HashMap::new()),
                stream_handlers: RwLock::new(HashMap::new()),
                hosted: true,
                default_node_profile,
                encryption_seed,
                // Hosted agents share the node's connection for everything on
                // `mesh.*`. This URL is dialled only for an acl room's scoped
                // second connection, which no shared connection can carry.
                url,
                tasks: std::sync::Mutex::new(Vec::new()),
                inbound: RwLock::new(InboundOptions::default()),
                seen_inbox: SeenEnvelopes::new(),
                seen_events: SeenEnvelopes::new(),
                pending_replies: std::sync::Mutex::new(HashMap::new()),
                inbox_subject_guarded: std::sync::Mutex::new(None),
                offline_drain_started: std::sync::atomic::AtomicBool::new(false),
                drain_in_flight: std::sync::atomic::AtomicBool::new(false),
                drain_trigger,
                mailbox_drain_interval: clamp_drain_interval(mailbox_drain_interval),
                task_budgets: TaskBudgets::new(),
                revoked_senders: RevokedSenders::new(),
                delegations: std::sync::Mutex::new(HashMap::new()),
                handler_options: RwLock::new(HashMap::new()),
                admissions: RwLock::new(HashMap::new()),
                allowance: std::sync::Mutex::new(AllowanceMeter::new()),
                meter_usage: std::sync::Mutex::new(crate::metering::MeterLedger::default()),
                cost_estimator: RwLock::new(None),
                owner_channel: RwLock::new(None),
                interaction: std::sync::Mutex::new(None),
                sealing: std::sync::Mutex::new(None),
                commerce: CommerceState::default(),
                register_opts: std::sync::Mutex::new(None),
                vouch: std::sync::Mutex::new(VouchState::default()),
                vouch_in_flight: std::sync::atomic::AtomicBool::new(false),
                vouch_task: std::sync::Mutex::new(None),
                vouch_ttl_ms: vouch_ttl_ms.unwrap_or(DEFAULT_VOUCH_TTL_MS),
                vouch_ttl_explicit: vouch_ttl_ms.is_some(),
                // §4.8: a hosted agent holds no credential — the node does, and
                // the node runs the one loop that renews it.
                cred_renewer: std::sync::Mutex::new(None),
                closed: std::sync::atomic::AtomicBool::new(false),
                declared_feeds: std::sync::Mutex::new(std::collections::BTreeMap::new()),
                feed_durable: Arc::new(crate::feed::FeedDurableShared::default()),
                // The naming rule is asked for at connect; a hosted agent is
                // built by its node, which does not carry the option (the TS
                // SDK's addAgent does not either).
                naming_gate: None,
            }),
        })
    }

    /// This agent's ID (its public nkey).
    pub fn id(&self) -> &str {
        &self.inner.agent_id
    }

    /// Replace this agent's §22 receiver-side settings. Defaults are the guarded
    /// ones (fence on, a 65,536-code-unit cap, no local warning sink), so this is
    /// only needed to widen or narrow them — or to attach the sink, which is how
    /// a refusal stops being invisible to the operator (§22.7).
    ///
    /// Call it before `register`/`listen_inbox`. Note what §22.3 does not allow:
    /// the freshness window has no off switch, because a bounded duplicate
    /// memory is only sufficient in its presence.
    pub fn set_inbound_options(&self, opts: InboundOptions) -> &Self {
        *self.inner.inbound.write().unwrap() = opts;
        self
    }

    /// This agent's current §22 settings.
    pub fn inbound_options(&self) -> InboundOptions {
        self.inner.inbound.read().unwrap().clone()
    }

    /// Set per-offering [`HandlerOptions`] (mirrors
    /// [`set_inbound_options`](Self::set_inbound_options)). An offering never set
    /// here uses [`HandlerOptions::default`] — notably `propagate_cancel:
    /// true`, so an inbound §10.8 cancel automatically forwards to the
    /// handler's still-live delegates. `propagate_cancel: false` means "this
    /// handler manages its delegates itself".
    pub fn set_handler_options(&self, offering: &str, opts: HandlerOptions) -> &Self {
        self.inner.handler_options.write().unwrap().insert(offering.to_string(), opts);
        self
    }

    /// Register a per-offering §7.7 **admission** judgement, run after the §22
    /// inbound protections and BEFORE the §6.4a accept signal — the last gate
    /// whose refusal is a refusal of admission.
    ///
    /// This is where refuse-with-estimate belongs: return `Ok(())` to admit
    /// (the SDK then emits `"accepted"` and invokes the handler), or an error
    /// — typically [`crate::budget::budget_insufficient`] /
    /// [`crate::budget::deadline_unmeetable`], estimate attached — to refuse.
    /// A refusal here is answered *instead of* an accept, which is the §6.4a
    /// ordering; a budget refusal returned from the request **handler** would
    /// arrive after the accept, and §6.4a forbids exactly that ("a failure of
    /// the work may follow an accept; a refusal of admission may not").
    ///
    /// The judgement sees the raw (unfenced) input and the
    /// [`RequestContext`] — including `budget`, verbatim from the envelope. It
    /// runs synchronously, before any work: read the budget, compare an
    /// estimate, decide. Independent of any hook, the SDK itself refuses
    /// `DEADLINE_UNMEETABLE` when the offered deadline has already passed at
    /// admission (under the §22.3 skew tolerance).
    pub fn on_admission<F>(&self, offering: &str, f: F) -> &Self
    where
        F: Fn(&Value, &RequestContext) -> Result<()> + Send + Sync + 'static,
    {
        self.inner.admissions.write().unwrap().insert(offering.to_string(), Arc::new(f));
        self
    }

    // ── EXT-8 owner allowance ──

    /// Arm this agent's node with an owner allowance (EXT-8 §1) — the signed,
    /// node-held spending policy the owner set on their own agent. Once armed,
    /// enforcement is SDK-automatic: every inbound request is judged against
    /// the ceilings during the §7.7 admission phase (before the §6.4a accept),
    /// and usage the host reports ([`report_usage`](Self::report_usage)) is
    /// metered by the document's declared cost model.
    ///
    /// A document that does not verify (or does not parse, or whose `agent`
    /// names a different agent than this one) leaves the agent **fail-closed,
    /// never unguarded**: the error returns, and until a valid document
    /// replaces it every ceiling reads as exhausted — refusing (or asking the
    /// owner, per the document's readable `on_exhausted`). Failing open here
    /// would be failing open on the owner's money (EXT-8 §1).
    /// [`allowance_status`](Self::allowance_status) makes the state
    /// observable either way.
    pub fn set_allowance(&self, doc: &Value) -> Result<()> {
        self.inner.allowance.lock().unwrap().arm_for(doc, &self.inner.agent_id)
    }

    /// [`set_allowance`](Self::set_allowance) from the document's JSON text —
    /// the shape it is held on disk in. Unparseable JSON fails closed exactly
    /// like an unverifiable document.
    pub fn set_allowance_json(&self, json: &str) -> Result<()> {
        match serde_json::from_str::<Value>(json) {
            Ok(doc) => self.set_allowance(&doc),
            Err(e) => {
                let err = MeshError::code(
                    ErrorCode::InvalidEnvelope,
                    format!("Allowance document is not JSON: {e}"),
                );
                self.set_allowance(&Value::Null).ok();
                Err(err)
            }
        }
    }

    /// Remove the allowance deliberately (the owner un-configuring their
    /// policy — distinct from a document failing to verify, which fails
    /// closed instead). The spend ledger is kept.
    pub fn clear_allowance(&self) -> &Self {
        self.inner.allowance.lock().unwrap().disarm();
        self
    }

    /// The armed policy, the fail-closed reason, or
    /// [`AllowanceStatus::Unarmed`].
    pub fn allowance_status(&self) -> AllowanceStatus {
        self.inner.allowance.lock().unwrap().status()
    }

    /// Register the host's incoming-cost estimator (EXT-8 §2). The SDK cannot
    /// see the host's model bill, so admission prices incoming work with this
    /// hook — [`Usage::Tokens`] converts by the armed cost model,
    /// [`Usage::CostMicro`] is taken as stated. Without one, the default is
    /// [`estimate_tokens`]: `ceil(sender-text chars / 4)` tokens, chars in
    /// UTF-16 code units (the §22.5 counting).
    pub fn set_cost_estimator<F>(&self, f: F) -> &Self
    where
        F: Fn(&Value, &RequestContext) -> Usage + Send + Sync + 'static,
    {
        *self.inner.cost_estimator.write().unwrap() = Some(Arc::new(f));
        self
    }

    /// Register the owner channel `on_exhausted: "ask_owner"` surfaces
    /// through (EXT-8 §2): work that would cross a ceiling is held unstarted
    /// while this callback puts the question to the owner. Return `true` to
    /// proceed (the owner approved the spend), `false` to refuse with the
    /// same `BUDGET_INSUFFICIENT` shape a plain refusal answers. Decide
    /// promptly — the judgement runs on the dispatch path, so a callback that
    /// waits on a person should hold the question elsewhere and decline.
    ///
    /// With no channel registered, `ask_owner` refuses: a channel that does
    /// not exist cannot approve spending the owner's money.
    pub fn on_allowance_question<F>(&self, f: F) -> &Self
    where
        F: Fn(&AllowanceQuestion) -> bool + Send + Sync + 'static,
    {
        *self.inner.owner_channel.write().unwrap() = Some(Arc::new(f));
        self
    }

    // ── §19.5 agreements ──

    /// Supply the host's own agreement lookup (§19.5): fetch a consumer
    /// OWNER's agreements for this seller. With none registered, the SDK asks
    /// the platform itself at `mesh.agreements.list`. Hits are cached per
    /// owner; a miss re-asks every time, deliberately — "approve, then send
    /// again" must work, and a cached miss reads as broken rather than as
    /// caching.
    pub fn on_agreement_lookup<F>(&self, f: F) -> &Self
    where
        F: Fn(&str) -> Result<Vec<Value>> + Send + Sync + 'static,
    {
        *self.inner.commerce.lookup.write().unwrap() = Some(Arc::new(f));
        self
    }

    /// Where a human approves terms when a SKU names no `provider.checkout_url`
    /// (§19.4). Without one, paid SKUs advertise but do not enforce — the
    /// §19.5 admission check admits rather than refuse toward a dead end.
    pub fn set_approval_url(&self, url: &str) -> &Self {
        *self.inner.commerce.approval_url.lock().unwrap() = Some(url.to_string());
        self
    }

    /// Report model usage for the request being handled (EXT-8 §2) — called
    /// from inside an offering handler, where the dispatch context is ambient.
    /// The SDK meters it against the armed allowance (`floor(tokens ×
    /// per_1k_tokens_micro / 1000)` for [`Usage::Tokens`]), accounts it to
    /// the Task, its `context_id` and the UTC day, and returns the micro-units
    /// recorded. The Task's total flows into the terminal respond's
    /// `payload.cost` (§19.3) automatically.
    ///
    /// Outside a handler, use
    /// [`report_task_usage`](Self::report_task_usage).
    pub fn report_usage(&self, usage: Usage) -> Result<u64> {
        let dispatch = crate::util::CURRENT_DISPATCH.try_with(|d| d.clone()).map_err(|_| {
            MeshError::code(
                ErrorCode::Internal,
                "report_usage called outside an offering handler — use report_task_usage with an \
                 explicit task id",
            )
        })?;
        self.report_task_usage(&dispatch.task_id, dispatch.context_id.as_deref(), usage)
    }

    /// Report model usage against an explicit Task (and optionally its
    /// context) — the host-side seam for work metered outside a dispatched
    /// handler. Accounted to the UTC day of the metering instant.
    pub fn report_task_usage(
        &self,
        task_id: &str,
        context_id: Option<&str>,
        usage: Usage,
    ) -> Result<u64> {
        self.inner.allowance.lock().unwrap().report(task_id, context_id, usage)
    }

    /// Report a declared meter quantity for the current dispatch's §13.5 usage
    /// receipt — `mesh.report_meter("tokens_out", 4210)` from inside an offering
    /// handler. Additive per (task, meter); the accumulated entries ride the
    /// terminal respond as `payload.usage`, covered by the envelope signature
    /// (a usage report is a signed receipt with no new signature). Quantity
    /// twin of [`report_usage`](Self::report_usage), which meters MONEY
    /// through the EXT-8 cost model — report both when both are known;
    /// neither implies the other.
    ///
    /// `INPUT_INVALID` on a malformed report: meter names are
    /// `[a-z0-9_]{1,64}` and never an observed meter's name
    /// ([`crate::metering::OBSERVED_METERS`]).
    pub fn report_meter(&self, meter: &str, quantity: u64) -> Result<()> {
        let dispatch = crate::util::CURRENT_DISPATCH.try_with(|d| d.clone()).map_err(|_| {
            MeshError::code(
                ErrorCode::Internal,
                "report_meter called outside an offering handler — use report_task_meter with an \
                 explicit task id",
            )
        })?;
        self.report_task_meter(&dispatch.task_id, meter, quantity)
    }

    /// Report a declared meter quantity against an explicit Task — the
    /// host-side seam for usage learned outside a dispatched handler.
    pub fn report_task_meter(&self, task_id: &str, meter: &str, quantity: u64) -> Result<()> {
        self.inner.meter_usage.lock().unwrap().report(task_id, meter, quantity)
    }

    /// A snapshot of the spend ledger: what this node has metered, keyed by
    /// Task, context and UTC day — the owner's queryable view of their own
    /// household's books.
    pub fn allowance_ledger(&self) -> SpendLedger {
        self.inner.allowance.lock().unwrap().ledger().clone()
    }

    /// Attach the §22.7 local-signal sink, leaving the other settings alone.
    pub fn on_security_warning<F>(&self, sink: F) -> &Self
    where
        F: Fn(SecurityWarning) + Send + Sync + 'static,
    {
        self.inner.inbound.write().unwrap().on_security_warning = Some(Arc::new(sink));
        self
    }

    /// Fetch a single agent's manifest by id (registry get, §9.2). Used by
    /// rooms to read a peer's published `encryption_key` before a sealed invite.
    pub async fn get_manifest(&self, agent_id: &str) -> Result<Manifest> {
        let mut env = Envelope::new(PrimitiveType::Discover, &self.inner.agent_id);
        env.payload = Some(json!({ "agent_id": agent_id }));
        self.inner.sign(&mut env);
        let resp = self
            .inner
            .client
            .request(subjects::registry_get(agent_id), codec::encode(&env)?.into())
            .await
            .map_err(|e| MeshError::Transport(e.to_string()))?;
        let resp_env = codec::decode(&resp.payload)?;
        if let Some(err) = &resp_env.error {
            return Err(MeshError::from_error_object(err));
        }
        Ok(serde_json::from_value(resp_env.payload.unwrap_or(Value::Null))?)
    }

    /// Another agent's published X25519 encryption key (§4.3), or `None` when it
    /// has none we are willing to use.
    ///
    /// This is the key secrets get sealed TO — a room key in an invite — so
    /// taking it from "whatever answered the registry call" was enough to have
    /// those secrets sealed to a stranger: forge the reply with your own X25519
    /// key and you decrypt everything in a room you were never admitted to, with
    /// no error on either side. Two conditions before the key is handed out, both
    /// cheap and both necessary:
    ///
    /// - the manifest's `trust.signature` verifies as the agent's own §8.3 claim
    ///   binding this `id` to this `encryption_key`, so the agent itself declared
    ///   the key; and
    /// - that `id` is the agent we asked about, so a signed manifest for B cannot
    ///   be served as the answer for A.
    ///
    /// A manifest carrying no such claim — registered by an older SDK, or by one
    /// that signed a different claim version — is refused here, and the agent
    /// fixes it by re-registering. That is the intended failure: sealing to a key
    /// nobody vouched for is the bug, so "cannot verify" must mean "will not
    /// seal".
    pub async fn encryption_key_for(&self, agent_id: &str) -> Option<String> {
        let manifest = self.get_manifest(agent_id).await.ok()?;
        if manifest.id != agent_id {
            return None;
        }
        if !crate::identity::verify_manifest_signature(&manifest) {
            return None;
        }
        manifest.encryption_key
    }

    /// The §4.3 key on a manifest ALREADY IN HAND, or `None` when there is
    /// nothing here safe to seal to. The same two conditions
    /// [`Self::encryption_key_for`] applies, without its registry round trip.
    fn verified_key_on(manifest: Option<&Manifest>, agent_id: &str) -> Option<String> {
        let m = manifest?;
        if m.id != agent_id {
            return None;
        }
        if !crate::identity::verify_manifest_signature(m) {
            return None;
        }
        m.encryption_key.clone()
    }

    /// §8.9: seal this outbound `input`, or do not, and say why not.
    ///
    /// The decision reads the manifest the caller **already handed us**
    /// (`RequestOptions::recipient`) and never fetches. That is the same rule
    /// §6.4b's sender pre-flight follows on the line above the call site, and
    /// it is deliberate: putting a registry round trip in front of every
    /// request would make a registry blip a messaging outage, which is a worse
    /// failure than the one sealing fixes. The cost of the choice is stated
    /// honestly in `docs/honesty-list.md`: a caller that never resolved the
    /// recipient sends its first request in the clear and is refused by a
    /// `required` agent.
    fn seal_outbound(
        &self,
        agent_id: &str,
        input: Value,
        recipient: Option<&Manifest>,
        explicit: Option<bool>,
    ) -> Result<Value> {
        if explicit == Some(false) {
            return Ok(input);
        }
        let posture = recipient
            .filter(|m| m.id == agent_id)
            .and_then(|m| m.sealing.as_deref());
        let required = posture == Some(crate::sealing::SEALING_REQUIRED);
        let wanted =
            explicit == Some(true) || required || posture == Some(crate::sealing::SEALING_PREFERRED);
        if !wanted {
            return Ok(input);
        }

        let Some(key) = Self::verified_key_on(recipient, agent_id) else {
            // Nothing verified to seal to. A `required` recipient will refuse
            // this anyway, so refuse here instead and keep the payload off the
            // wire — earning the refusal remotely would mean leaking the thing
            // first.
            if required || explicit == Some(true) {
                return Err(MeshError::Protocol {
                    code: ErrorCode::SealingRequired.as_str(),
                    message: format!(
                        "{agent_id} {}, and no verifiable encryption key for it is at hand. \
                         Pass RequestOptions.recipient from get_manifest(): sealing needs the \
                         agent's own §8.3 key claim, and this SDK will not seal to a key nobody \
                         signed for.",
                        if required {
                            "requires sealed requests (§8.9)"
                        } else {
                            "was asked for a sealed request"
                        }
                    ),
                });
            }
            // `preferred`: the agent reads cleartext, so sending is correct —
            // but silence here is how a confidentiality property becomes a
            // rumour.
            self.security_note(
                agent_id,
                format!(
                    "{agent_id} asks callers to seal (§8.9 preferred) and no verifiable \
                     encryption key for it is at hand, so this request went in cleartext. Pass \
                     RequestOptions.recipient before sending anything confidential."
                ),
            );
            return Ok(input);
        };

        // Our own key travels as `reply_key` so the answer comes back sealed.
        // With no encryption seed of our own there is nothing to name, and the
        // extension then permits a cleartext answer — worth saying out loud,
        // because the caller asked for confidentiality and is getting half.
        let reply_key = match self.inner.encryption_seed.as_deref() {
            Some(seed) => Some(crate::sealed::encryption_public_from_seed(seed)?),
            None => {
                self.security_note(
                    agent_id,
                    format!(
                        "This request to {agent_id} was sealed, but this agent published no \
                         encryption key of its own, so it named no reply_key and the ANSWER may \
                         come back in cleartext. Set ConnectOptions.encryption_seed to seal both \
                         directions."
                    ),
                );
                None
            }
        };
        Ok(serde_json::to_value(crate::sealed::seal_payload_to(
            &input,
            &key,
            reply_key.as_deref(),
        )?)?)
    }

    /// The §8.9 outbound signal on the local warning channel.
    fn security_note(&self, agent_id: &str, message: String) {
        let sink = self.inner.inbound.read().unwrap().on_security_warning.clone();
        if let Some(sink) = sink {
            sink(SecurityWarning {
                code: "sent_in_clear".to_string(),
                message,
                subject: Some(agent_id.to_string()),
                from: Some(self.inner.agent_id.clone()),
            });
        }
    }

    // ── internals shared with the rooms module (same crate) ──────────────

    pub(crate) fn nats(&self) -> &async_nats::Client {
        &self.inner.client
    }
    pub(crate) fn agent_kp(&self) -> KeyPair {
        self.inner.agent_kp()
    }
    pub(crate) fn agent_id_str(&self) -> &str {
        &self.inner.agent_id
    }
    pub(crate) fn encryption_seed(&self) -> Option<String> {
        self.inner.encryption_seed.clone()
    }
    /// Open a room-scoped second NATS connection with a service-issued acl
    /// credential (§7.2). The broker permits it only on this room's subjects.
    pub(crate) async fn open_scoped_connection(
        &self,
        jwt: String,
        seed: &str,
        inbox_prefix: Option<&str>,
    ) -> Result<async_nats::Client> {
        // Node-hosted agents reach this too: a node retains the URL it dialled
        // and hands it to each hosted agent, precisely so the Gateway is not
        // locked out of the one grade whose membership the broker enforces. Only
        // `MeshNode::with_client` still lands here — an embedder-supplied
        // connection carries no URL to redial.
        if self.inner.url.is_empty() {
            return Err(MeshError::code(
                ErrorCode::Internal,
                "acl rooms need a mesh URL to dial the room-scoped connection; \
                 this agent was built over a caller-supplied client that carries none",
            ));
        }
        // A room-scoped connection has no mailbox of its own, so its reconnect
        // channel is dropped here: nothing drains over it.
        connect_client_with(&self.inner.url, Some(jwt), seed, inbox_prefix).await.map(|(c, _)| c)
    }
    /// Build a signed `emit` envelope carrying a `context_id` (room traffic).
    pub(crate) fn signed_emit(&self, context_id: &str, payload: Value) -> Result<Vec<u8>> {
        let mut env = Envelope::new(PrimitiveType::Emit, &self.inner.agent_id);
        env.context_id = Some(context_id.to_string());
        env.payload = Some(payload);
        self.inner.sign(&mut env);
        codec::encode(&env)
    }
    pub(crate) fn track_task(&self, handle: tokio::task::JoinHandle<()>) {
        self.inner.tasks.lock().unwrap().push(handle);
    }
    /// Record a §6.6a feed declaration (see [`AgentMesh::declare_feed`], the
    /// validating public surface in `feed.rs`). Idempotent per topic.
    pub(crate) fn record_declared_feed(&self, topic: String, kind: crate::feed::FeedKind) {
        self.inner.declared_feeds.lock().unwrap().insert(topic, kind);
    }
    /// The declared feeds as manifest `emits` subjects (§8.2), sorted — the
    /// BTreeMap's topic order, which under one shared prefix is subject order.
    pub(crate) fn declared_feed_subjects(&self) -> Vec<String> {
        self.inner
            .declared_feeds
            .lock()
            .unwrap()
            .keys()
            .filter_map(|topic| subjects::feed(&self.inner.agent_id, topic).ok())
            .collect()
    }
    /// Signed request to a bare service subject (registry-style, not an agent
    /// inbox). Resolves with the response payload; errors on error envelopes.
    pub(crate) async fn service_request(&self, subject: &str, payload: Value) -> Result<Value> {
        let mut env = Envelope::new(PrimitiveType::Request, &self.inner.agent_id);
        env.payload = Some(payload);
        self.inner.sign(&mut env);
        let resp = tokio::time::timeout(
            Duration::from_secs(30),
            self.inner.client.request(subject.to_string(), codec::encode(&env)?.into()),
        )
        .await
        .map_err(|_| MeshError::code(ErrorCode::TransportTimeout, "rooms service did not respond"))?
        .map_err(|e| MeshError::Transport(e.to_string()))?;
        let resp_env = codec::decode(&resp.payload)?;
        if let Some(err) = &resp_env.error {
            return Err(MeshError::from_error_object(err));
        }
        Ok(resp_env.payload.unwrap_or(Value::Null))
    }

    /// Deregister this agent: remove its manifest from the registry (§9.2).
    /// The connection stays up; the agent can re-register later. The registry
    /// authenticates the removal by the envelope signature (only the agent
    /// itself can deregister itself).
    pub async fn deregister(&self) -> Result<()> {
        let mut env = Envelope::new(PrimitiveType::Register, &self.inner.agent_id);
        env.to = Some("mesh.service.registry".to_string());
        env.payload = Some(json!({ "agent_id": self.inner.agent_id }));
        self.inner.sign(&mut env);
        let resp = self
            .inner
            .client
            .request(subjects::REGISTRY_DEREGISTER, codec::encode(&env)?.into())
            .await
            .map_err(|e| MeshError::Transport(format!("deregister failed: {e}")))?;
        let resp_env = codec::decode(&resp.payload)?;
        if let Some(err) = &resp_env.error {
            return Err(MeshError::from_error_object(err));
        }
        // There is no longer a registration to keep alive (§4.4): stop
        // renewing, and clear the deadline so a hosting node's loop skips this
        // agent too. register() re-arms both if the agent comes back.
        self.stop_vouch_renewal();
        {
            let mut v = self.inner.vouch.lock().unwrap();
            v.expires_at = None;
            v.renew_at_ms = None;
        }
        Ok(())
    }

    /// Look up a task's durable record from the Task Manager
    /// (`mesh.task.get.{id}`). The record holds the current state and the
    /// update history — including, per §11.3 step 6, the completion update's
    /// `output` — so a requester that lost the stream can recover the result.
    /// Returns the raw task record; errors with `TASK_NOT_FOUND` if unknown
    /// (records expire, reference binding keeps them 7 days).
    pub async fn get_task(&self, task_id: &str) -> Result<Value> {
        let mut env = Envelope::new(PrimitiveType::Request, &self.inner.agent_id);
        env.payload = Some(json!({ "task_id": task_id }));
        self.inner.sign(&mut env);
        let resp = self
            .inner
            .client
            .request(subjects::task_get(task_id), codec::encode(&env)?.into())
            .await
            .map_err(|e| MeshError::Transport(format!("task lookup failed: {e}")))?;
        let resp_env = codec::decode(&resp.payload)?;
        if let Some(err) = &resp_env.error {
            return Err(MeshError::from_error_object(err));
        }
        Ok(resp_env.payload.unwrap_or(Value::Null))
    }

    /// Wait for a Task's terminal update (§7.3): subscribe to
    /// `mesh.task.{id}.update`, then read the durable record (subscription
    /// FIRST, so a terminal that lands between the two is caught either way),
    /// and resolve on the first signed update whose `payload.status` is
    /// terminal -- `completed`, `failed`, `canceled`, `exhausted` or
    /// `rejected`. Returns that payload: for a completion it carries the
    /// `output` (§11.3 step 6), the §19.3 `cost` and the §13.5 `usage` exactly
    /// as a bare terminal respond would have.
    ///
    /// This is the requester's half of §7.0 deferral
    /// ([`HandlerOptions::defer_after`]): a request that resolved with
    /// `status: "working"` and a `task_id` is work still running, and this is
    /// how to wait for it. Also usable for any other Task this agent may read
    /// (the task manager enforces §7.4 party access on the record; the update
    /// subject is broker-scoped the same way).
    ///
    /// On a mesh with no task manager the record lookup fails quietly and the
    /// live subscription alone decides -- fine for a wait that starts before
    /// the terminal, blind to one that already happened.
    pub async fn await_task(&self, task_id: &str, timeout: std::time::Duration) -> Result<Value> {
        let mut sub = self
            .inner
            .client
            .subscribe(subjects::task_update(task_id))
            .await
            .map_err(|e| MeshError::Transport(e.to_string()))?;
        if let Ok(record) = self.get_task(task_id).await {
            if let Some(payload) = terminal_payload_of_record(&record) {
                return Ok(payload);
            }
        }
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            match tokio::time::timeout_at(deadline, sub.next()).await {
                Err(_) => {
                    return Err(MeshError::code(
                        ErrorCode::TransportTimeout,
                        format!("task {task_id} reached no terminal state within the wait"),
                    ))
                }
                Ok(None) => {
                    return Err(MeshError::Transport(
                        "task update subscription closed".to_string(),
                    ))
                }
                Ok(Some(msg)) => {
                    // Signed updates only: `decode` verifies, and an update
                    // that does not is not a statement anyone made.
                    let Ok(update) = codec::decode(&msg.payload) else { continue };
                    let Some(payload) = update.payload else { continue };
                    let terminal = payload
                        .get("status")
                        .and_then(|s| s.as_str())
                        .is_some_and(is_terminal_task_status);
                    if terminal {
                        return Ok(payload);
                    }
                }
            }
        }
    }

    /// Register a synchronous handler for an offering.
    ///
    /// While the handler runs, the inbound trace (§13.1) and the dispatch
    /// context (§10.8) are ambient: sub-requests the handler awaits join the
    /// caller's trace and are tracked as delegations of the task being
    /// handled, so an inbound cancel for that task forwards to them
    /// automatically (see [`HandlerOptions`] to opt out). Honest limitation:
    /// a task-local is not inherited across `tokio::spawn`, so sub-requests
    /// issued from a task the handler spawned are neither traced nor
    /// auto-tracked.
    pub fn on_request<F, Fut>(&self, offering: &str, f: F)
    where
        F: Fn(Value) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Value>> + Send + 'static,
    {
        let handler: Handler = Arc::new(move |input, _ctx| Box::pin(f(input)));
        self.inner.handlers.write().unwrap().insert(offering.to_string(), handler);
    }

    /// Register a handler that also receives the [`RequestContext`] (the
    /// verified caller, request id, task id) — for inbound accounting,
    /// consent checks, and per-caller policy.
    pub fn on_request_ctx<F, Fut>(&self, offering: &str, f: F)
    where
        F: Fn(Value, RequestContext) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Value>> + Send + 'static,
    {
        let handler: Handler = Arc::new(move |input, ctx| Box::pin(f(input, ctx)));
        self.inner.handlers.write().unwrap().insert(offering.to_string(), handler);
    }

    /// Register a STREAMING offering handler (§11.3). Invoked when a request
    /// arrives with `config.stream: true`; the handler receives the input and a
    /// [`StreamWriter`]. If the handler returns without calling `end()`, the
    /// stream is ended automatically; if it errors, a signed error envelope is
    /// published on the stream subject.
    pub fn on_stream_request<F, Fut>(&self, offering: &str, f: F)
    where
        F: Fn(Value, StreamWriter) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        let handler: StreamHandler = Arc::new(move |input, writer, _ctx| Box::pin(f(input, writer)));
        self.inner
            .stream_handlers
            .write()
            .unwrap()
            .insert(offering.to_string(), handler);
    }

    /// Streaming variant of [`AgentMesh::on_request_ctx`]: the handler also
    /// receives the [`RequestContext`].
    pub fn on_stream_request_ctx<F, Fut>(&self, offering: &str, f: F)
    where
        F: Fn(Value, StreamWriter, RequestContext) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        let handler: StreamHandler = Arc::new(move |input, writer, ctx| Box::pin(f(input, writer, ctx)));
        self.inner.stream_handlers.write().unwrap().insert(offering.to_string(), handler);
    }

    /// Register this agent, start listening on its inbox, drain any offline
    /// mailbox, and begin heartbeats.
    ///
    /// Three things happen after the manifest goes out, in this order and for
    /// these reasons:
    ///
    /// 1. **The EXT-6 guard handshake**, when [`RegisterOptions::guarded`] is
    ///    set. Getting this wrong in the permissive direction costs filtering;
    ///    getting it wrong in the strict direction is silent and total, because a
    ///    guarded agent listens ONLY on the private `.guarded` subject and
    ///    nothing relays there unless the admission service is really guarding
    ///    it. An agent that wrongly believed itself guarded would register,
    ///    heartbeat, look healthy — and never receive another message. So only an
    ///    explicit ok moves the subscription (see `request_guard`), and when the
    ///    ask was refused this agent says so out loud (see `revoke_guard`) rather
    ///    than leaving the mesh acting on a guard entry no subscription backs.
    /// 2. **The inbox subscription**, on whichever subject step 1 settled.
    /// 3. **The §16.4 mailbox drain**, spawned rather than awaited: a mesh with
    ///    no JetStream answers the stream lookup with a timeout, and a
    ///    registration must not wait on a buffer that may not exist.
    pub async fn register(&self, opts: RegisterOptions) -> Result<Manifest> {
        let wants_guard = opts.guarded;
        let manifest = self.build_manifest(&opts)?;
        // §8.9: what this agent just told the mesh about its inbox is what its
        // dispatcher must now enforce. Recorded on every register, so a
        // re-register may change it — same rule as `interaction` below.
        *self.inner.sealing.lock().unwrap() = manifest.sealing.clone();
        self.send_register(&manifest).await?;
        // Copied, not aliased: a §4.4 renewal months from now re-registers what
        // the agent actually registered, not whatever the caller's value has
        // since become.
        *self.inner.register_opts.lock().unwrap() = Some(opts);
        self.inner.note_vouch(&manifest);

        // EXT-6 §7.1. `false` on anything short of an explicit ok, which keeps
        // this agent on the inbox everyone writes to.
        let guarded = if wants_guard { self.request_guard().await } else { false };
        self.listen_inbox(guarded).await?;
        // The other half of that handshake. The condition is the SUBSCRIPTION,
        // not the answer: `listen_inbox` leaves an already-listening agent where
        // it is, so a second `register` can get an ok from the service while this
        // process is still on the public inbox. Whichever way they disagree, the
        // subscription is the fact and the mesh-side entry is the claim.
        //
        // Left alone, that claim is acted on by two services at once: admission
        // relays this agent's mail to a private subject nobody is listening on,
        // and the registry points the offline mailbox at that same subject — while
        // every message arriving on the public inbox reaches the handler
        // unfiltered, because the filter the entry promises is not running. And
        // nothing else ever revokes an entry: the service is told by the agent,
        // the registry only reads the list, so one left behind by a previous run
        // outlives it silently.
        if wants_guard && !self.listening_on_guarded() {
            self.revoke_guard().await;
        }
        // §16.4 offline delivery: a registered agent may have a mailbox holding
        // messages sent while it was away. Silent no-op when there is none.
        self.start_offline_drain();
        // Node-hosted agents don't heartbeat individually — one heartbeat from
        // the node covers all its agents (§9.6); MeshNode owns that loop. Same
        // split for §4.4 vouch renewal: the node re-vouches every agent it
        // holds, so a hosted agent must not run its own renewal loop.
        if !self.inner.hosted {
            self.start_heartbeat();
            self.start_vouch_renewal();
        }
        Ok(manifest)
    }

    /// Build the manifest to register: a fresh node vouch (§4.4) and a fresh
    /// manifest key claim (§8.3) every time, so this is also exactly what a
    /// renewal sends (mirrors the TS SDK's `buildManifest`).
    fn build_manifest(&self, opts: &RegisterOptions) -> Result<Manifest> {
        // §19.1: refuse a malformed SKU at registration, where the operator
        // can see it — not at some later discovery read.
        if let Some(skus) = opts.skus.as_ref() {
            validate_skus(&serde_json::to_value(skus)?)?;
        }
        // §19.5: cache each SKU's current digest — the identity an agreement
        // binds to, recomputed only when a registration changes the terms.
        // New terms make every held agreement stale by definition, so drop
        // what we hold rather than carry acceptances of a price that no
        // longer exists.
        {
            let mut digests = self.inner.commerce.digests.lock().unwrap();
            digests.clear();
            self.inner.commerce.agreements.lock().unwrap().clear();
            for s in opts.skus.iter().flatten() {
                digests.insert(s.sku.clone(), sku_digest(s)?);
            }
        }
        // A paid SKU with nowhere to approve cannot be enforced: refusing a
        // buyer with a dead end is worse than taking the work. Say so rather
        // than silently doing one or the other.
        let approval_url_set = self.inner.commerce.approval_url.lock().unwrap().is_some();
        let unenforceable = opts
            .skus
            .iter()
            .flatten()
            .filter(|s| {
                s.price.model != SkuPriceModel::Free
                    && s.provider.checkout_url.is_none()
                    && !approval_url_set
            })
            .count();
        if unenforceable > 0 {
            eprintln!(
                "[agentmesh] {unenforceable} paid SKU(s) declare no approval route \
                 (provider.checkout_url, or set_approval_url) — their price is ADVERTISED but \
                 NOT enforced: a refusal a buyer cannot act on is a dead end (§19.5)"
            );
        }
        *self.inner.commerce.skus.lock().unwrap() = opts.skus.clone();
        // The §8.7 storefront, with §19.1's price advertisement: when SKUs
        // are declared, the public block carries each one's id, price, and
        // digest — price is pre-admission data by design. An explicit
        // `public.skus` wins: advertising less than you sell is a choice the
        // spec protects.
        let public = match (opts.skus.as_deref(), opts.public.clone()) {
            (Some(skus), public)
                if !skus.is_empty() && public.as_ref().is_none_or(|p| p.skus.is_none()) =>
            {
                let mut p = public.unwrap_or_default();
                p.skus = Some(skus.iter().map(public_sku_of).collect::<Result<Vec<_>>>()?);
                Some(p)
            }
            (_, public) => public,
        };
        // §6.4a × §8.3a: an agent registering as `interactive` is an attended
        // surface — its dispatcher must stop emitting accepts, because no
        // admission by a live handler is what an inbound request gets there.
        // Recorded on every register, so a re-register may change it.
        *self.inner.interaction.lock().unwrap() = opts.interaction.clone();
        // Ownership (§8.6): defaults to the node. An explicit owner seed groups
        // this agent under a person/org identity with an owner attestation.
        // SPEC 9.2 retention defaults: a declared availability_class earns
        // the full vouch; undeclared gets the short ephemeral lease. Declared
        // profile fields overlay the default profile so declaring a class
        // does not cost the platform/client attribution (EXT-1).
        let node_profile = match (opts.node_profile.clone(), self.inner.default_node_profile.clone()) {
            (Some(declared), Some(mut base)) => {
                if declared.availability_class.is_some() { base.availability_class = declared.availability_class; }
                if declared.reachability.is_some() { base.reachability = declared.reachability; }
                if declared.capacity.is_some() { base.capacity = declared.capacity; }
                if declared.platform.is_some() { base.platform = declared.platform; }
                if declared.client.is_some() { base.client = declared.client; }
                Some(base)
            }
            (declared, base) => declared.or(base),
        };
        // An explicit vouch TTL always wins over the declared-vs-ephemeral
        // split — mirroring the TS SDK's `vouchTtlMs`.
        let vouch_ttl_ms = if self.inner.vouch_ttl_explicit
            || node_profile.as_ref().and_then(|p| p.availability_class.as_ref()).is_some()
        {
            self.inner.vouch_ttl_ms
        } else {
            EPHEMERAL_VOUCH_TTL_MS
        };

        let (owner, owner_attestation) = match opts.owner_seed.as_deref() {
            Some(seed) => {
                let owner_kp = crate::identity::keypair_from_seed(seed)?;
                let owner_pub = owner_kp.public_key();
                if owner_pub != self.inner.node_id {
                    let att = create_attestation(&owner_kp, &self.inner.agent_id, vouch_ttl_ms)?;
                    (Some(owner_pub), Some(att))
                } else {
                    (Some(owner_pub), None)
                }
            }
            None => (None, None),
        };

        let inbox = subjects::agent_inbox(&self.inner.agent_id);
        let encryption_key = match self.inner.encryption_seed.as_deref() {
            Some(seed) => Some(crate::sealed::encryption_public_from_seed(seed)?),
            None => None,
        };
        let works_with = opts.works_with.clone().filter(|w| !w.is_empty());
        // §8.9: whether callers should seal what they send here. Derived from
        // what this agent already declared — an offering that asks for a
        // third-party sign-in earns `required`, a declared integration earns
        // `preferred` — so the vendor case is sealed without anybody
        // configuring encryption. Absent unless something says otherwise, which
        // is what every manifest written before this field existed says and
        // must keep saying.
        let sealing = crate::sealing::derived_sealing(
            encryption_key.as_deref(),
            works_with.as_deref(),
            &opts.offerings,
            opts.sealing,
        );
        let mut manifest = Manifest {
            id: self.inner.agent_id.clone(),
            name: opts.name.clone(),
            description: opts.description.clone(),
            version: opts.version.clone().unwrap_or_else(|| "0.1.0".to_string()),
            protocol_version: crate::envelope::PROTOCOL_VERSION.to_string(),
            encryption_key,
            sealing,
            // §8.10: the card-level data-use declaration, pass-through only.
            // The registry is the validator and drops an unreadable
            // declaration WHOLE on the way in; duplicating those rules here
            // would let the two drift and make this crate's verdict compete
            // with the authoritative one. Nothing here derives or invents one.
            data_use: opts.data_use.clone(),
            // §8.11: declaration-only in this SDK for now — an embedder that
            // wants compliance postures sets them on the manifest; nothing
            // here derives or invents one.
            compliance: None,
            // §8.12: audience, coverage, edge behaviour, whose interest it
            // serves, and where it came from. Declaration-only here for the
            // same reason as `compliance`: every one of them is a fact about
            // the operator's intent that this crate cannot observe, and a
            // default would be an invention. Absent means the agent has not
            // said, which is exactly what each field's third state means.
            audience: None,
            coverage: None,
            edge: None,
            serves: None,
            acts: None,
            parties: None,
            origin: None,
            endpoint: inbox.clone(),
            // §8.1/§14.4: the endpoint subjects, verbatim, so callers resolve
            // rather than construct. OPTIONAL on registration — a registry
            // stamps it when absent — but declared here so resolution is
            // available even on a mesh whose registry predates the field.
            endpoints: Some(crate::manifest::Endpoints {
                inbox: Some(inbox),
                other: Default::default(),
            }),
            // §8.1/§22.5: declare a nonstandard cap so senders pre-flight
            // against the value this agent will actually enforce (§6.4b). The
            // default cap is what absent already means, and 0 (no cap) has no
            // declared spelling — both stay undeclared.
            limits: {
                let cap = self.inner.inbound.read().unwrap().max_inbound_chars;
                if cap != crate::inbound::DEFAULT_MAX_INBOUND_CHARS && cap != 0 {
                    Some(crate::manifest::Limits { max_inbound_chars: Some(cap as u64) })
                } else {
                    None
                }
            },
            node: NodeRef {
                id: self.inner.node_id.clone(),
                attestation: create_attestation(&self.inner.node_kp(), &self.inner.agent_id, vouch_ttl_ms)?,
                profile: node_profile,
            },
            capabilities: opts.capabilities.clone(),
            offerings: opts.offerings.clone(),
            // §6.6a/§8.2: the feeds this agent declared, as their subjects,
            // sorted — what makes them discoverable through the registry.
            // Absent when none are declared: an empty list would read as
            // "declared no feeds", which is not the same as "did not say".
            emits: {
                let feed_subjects = self.declared_feed_subjects();
                if feed_subjects.is_empty() { None } else { Some(feed_subjects) }
            },
            // The `emits` twin (§8.2): nothing in this SDK derives it yet —
            // declaration-only wire parity with the TS manifest.
            accepts: None,
            // §8.8: carried only when it says something. An empty array would
            // read as "declared none", which is not the same as "did not say".
            works_with,
            public,
            skus: opts.skus.clone(),
            meta: None,
            trust: None,
            visibility: opts.visibility.clone(),
            interaction: opts.interaction.clone(),
            harness: opts.harness.clone(),
            harness_version: opts.harness_version.clone(),
            model: opts.model.clone(),
            availability: None,
            owner,
            owner_attestation,
        };

        // §8.3: sign the id→encryption_key binding with this agent's own key.
        // Without it, `encryption_key` is only as trustworthy as whatever answered
        // the registry call — which is how it became a way to have a room key
        // sealed to a stranger (see `encryption_key_for`). The claim covers the
        // id, the key and the instant, and deliberately nothing else: the registry
        // rewrites `owner`/`visibility`/`sandbox` right after this, so a wider
        // signature could not verify for anyone reading the manifest back.
        crate::identity::sign_manifest(&mut manifest, &self.inner.agent_kp())?;
        Ok(manifest)
    }

    /// Send a `register` for a built manifest. Shared by `register` and
    /// [`renew_vouch`](Self::renew_vouch).
    ///
    /// Honest difference from the TS SDK: TS *requests* the registration and
    /// surfaces the registry's refusal, falling back to a bare publish when no
    /// registry answers at all. This crate has always published fire-and-forget
    /// (which is what lets it work peer-to-peer with no registry), so the only
    /// failure a renewal can observe here is the transport's — a closed or
    /// failed connection. A registry-side refusal is invisible to this crate at
    /// register time and at renewal time alike.
    async fn send_register(&self, manifest: &Manifest) -> Result<()> {
        let mut env = Envelope::new(PrimitiveType::Register, &self.inner.agent_id);
        env.payload = Some(serde_json::to_value(manifest)?);
        self.inner.sign(&mut env);
        self.inner
            .client
            .publish(subjects::REGISTRY_REGISTER, codec::encode(&env)?.into())
            .await
            .map_err(|e| MeshError::Transport(e.to_string()))
    }

    // ─── Vouch renewal (§4.4) ──────────────────────────────────────────
    //
    // An agent's right to speak on the mesh is its node's vouch (§4.3), and a
    // vouch is a LEASE: the registry refuses an expired attestation (§9.7) and
    // its reaper reclaims a registration whose attestation has lapsed. So a
    // process that registers once and stays up outlives its own registration —
    // it keeps working, keeps heartbeating, and simply stops being discoverable
    // at the 30-day mark, with nothing in its logs to say why. Renewal is what
    // makes "long-lived" and "registered" compatible.
    //
    // A renewal is a re-registration with a freshly signed vouch, which is the
    // path §9.2 names ("re-registration with a fresh vouch is the legitimate
    // path back"). It deliberately does NOT redo register()'s other side
    // effects: the inbox subscription is already live, the mailbox consumer is
    // already bound, and re-running the EXT-6 guard handshake could have the
    // admission service refuse a guard this agent already holds (rate limit,
    // ceiling) and quietly move a healthy agent off the inbox anyone is
    // writing to.

    /// When the current vouch expires, when it is next due for renewal, and
    /// why the last renewal attempt failed (if it did). `None` values mean
    /// "not registered". Exposed so a host that attaches no
    /// [`on_security_warning`](Self::on_security_warning) sink can still see a
    /// lapsing vouch on its own health surface. Mirrors the TS SDK's `vouch`
    /// getter.
    pub fn vouch(&self) -> VouchStatus {
        let v = self.inner.vouch.lock().unwrap();
        VouchStatus {
            expires_at: v.expires_at.clone(),
            renew_at: v.renew_at_ms.and_then(crate::vouch::ms_to_rfc3339),
            last_error: v.last_error.clone(),
        }
    }

    /// Mint a fresh node vouch and re-register with it. Safe to call at any
    /// time — this is also what the renewal loop calls — but callers normally
    /// do not need to: an agent registered through this SDK renews itself.
    ///
    /// Errors if the agent has never registered (there is nothing to
    /// re-register), if it is closed, or if the transport refuses the publish
    /// (see [`send_register`](Self::send_register) for why a registry-side
    /// refusal is not observable in this crate).
    pub async fn renew_vouch(&self) -> Result<Manifest> {
        let opts = self.inner.register_opts.lock().unwrap().clone();
        let Some(opts) = opts else {
            return Err(MeshError::code(
                ErrorCode::Internal,
                "renew_vouch(): this agent has not registered — call register() first",
            ));
        };
        if self.inner.closed.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(MeshError::code(
                ErrorCode::Internal,
                "renew_vouch(): this agent is closed",
            ));
        }
        let manifest = self.build_manifest(&opts)?;
        self.send_register(&manifest).await?;
        self.inner.note_vouch(&manifest);
        self.inner.vouch.lock().unwrap().last_error = None;
        Ok(manifest)
    }

    /// Renew if the current vouch has reached its renewal deadline, judged
    /// against the wall clock. See
    /// [`renew_vouch_if_due_at`](Self::renew_vouch_if_due_at).
    pub async fn renew_vouch_if_due(&self) -> bool {
        self.renew_vouch_if_due_at(inbound::now_ms()).await
    }

    /// Renew if the current vouch has reached its renewal deadline as of
    /// `now_ms` (ms epoch). Returns `true` when a renewal was performed.
    ///
    /// Never errors: this runs on a timer with no caller to catch it. A failure
    /// records [`VouchStatus::last_error`], raises a §22.7 local signal with
    /// code `vouch_renewal_failed` on the
    /// [`on_security_warning`](Self::on_security_warning) sink, and leaves the
    /// deadline in place so the next tick retries — the renewal point is two
    /// thirds of the way through the TTL precisely so there is a third of it
    /// left to keep trying in. Overlapping calls are guarded: while one renewal
    /// is in flight, the rest return `false` without doing anything.
    ///
    /// Called by this agent's own loop when it is standalone, and by
    /// [`MeshNode`](crate::MeshNode)'s one loop for every agent that node
    /// vouches for. (In TS this is `renewVouchIfDue(now)` with a defaulted
    /// argument; Rust splits the defaulted form into
    /// [`renew_vouch_if_due`](Self::renew_vouch_if_due).)
    pub async fn renew_vouch_if_due_at(&self, now_ms: i64) -> bool {
        use std::sync::atomic::Ordering::SeqCst;
        if self.inner.closed.load(SeqCst) || self.inner.register_opts.lock().unwrap().is_none() {
            return false;
        }
        match self.inner.vouch.lock().unwrap().renew_at_ms {
            None => return false,
            Some(renew_at) if now_ms < renew_at => return false,
            Some(_) => {}
        }
        if self.inner.vouch_in_flight.swap(true, SeqCst) {
            return false; // a renewal is already in flight
        }
        // RAII so the guard is released even if this future is dropped
        // mid-await (the loop being aborted must not wedge a later manual
        // renewal) — the TS `finally`.
        struct InFlight<'a>(&'a std::sync::atomic::AtomicBool);
        impl Drop for InFlight<'_> {
            fn drop(&mut self) {
                self.0.store(false, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let _guard = InFlight(&self.inner.vouch_in_flight);
        match self.renew_vouch().await {
            Ok(_) => true,
            Err(err) => {
                let reason = err.to_string();
                let warning = {
                    let mut v = self.inner.vouch.lock().unwrap();
                    v.last_error = Some(reason.clone());
                    crate::vouch::renewal_failed_warning(
                        &self.inner.agent_id,
                        &reason,
                        v.expires_at.as_deref(),
                        now_ms,
                    )
                };
                let sink = self.inner.inbound.read().unwrap().on_security_warning.clone();
                if let Some(sink) = sink {
                    sink(warning);
                }
                false
            }
        }
    }

    /// Start this agent's own renewal loop. Standalone agents only — a hosted
    /// agent is covered by its node's single loop (§4.4).
    ///
    /// The loop compares the wall clock against the stored deadline on every
    /// tick rather than sleeping until the deadline, so a host that suspends
    /// renews on the first tick after it wakes. The task holds only a weak
    /// handle on the agent, so the loop never keeps an agent alive on its own
    /// (the analogue of the TS SDK's unref'd timer), and it is aborted on
    /// deregister/close so it never outlives the registration it maintains.
    fn start_vouch_renewal(&self) {
        self.stop_vouch_renewal();
        let weak = Arc::downgrade(&self.inner);
        let interval = vouch_check_interval(self.inner.vouch_ttl_ms);
        let handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            // Late ticks (a suspended host) must not burst-replay: each tick
            // reads the real clock, so one late tick already does the work.
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                // The first tick fires immediately; it compares wall clock
                // against the deadline, so an immediate not-yet-due tick is a
                // no-op.
                ticker.tick().await;
                let Some(inner) = weak.upgrade() else { break };
                AgentMesh { inner }.renew_vouch_if_due().await;
            }
        });
        *self.inner.vouch_task.lock().unwrap() = Some(handle);
    }

    /// Stop the renewal loop. Called from deregister/close so the timer never
    /// outlives the registration it maintains.
    fn stop_vouch_renewal(&self) {
        if let Some(handle) = self.inner.vouch_task.lock().unwrap().take() {
            handle.abort();
        }
    }

    // ─── Credential renewal (§4.8): the lease under the vouch ───────────
    //
    // Renewal is HTTPS and not a mesh call for one reason: it stays available
    // exactly when the credential does not. A node switched off through its
    // whole renewal window comes back with a dead credential, renews over
    // HTTPS, and connects — no operator, no re-bootstrap, no lost identity.

    /// When this agent's connection credential expires, when it is next due for
    /// renewal, whether it has already lapsed, and why the last attempt failed
    /// (§4.8). Mirrors the TS SDK's `credential` getter.
    ///
    /// All-`None`/`false` when no
    /// [`credential_renewal`](ConnectOptions::credential_renewal) was
    /// configured — that is "nothing here is watching", not a clean bill of
    /// health. An `expires_at` of `None` on a CONFIGURED renewer is the
    /// pre-§4.8 shape: a credential that never expires, which is a finding
    /// rather than good news, since nothing short of a broker restart can take
    /// it away.
    pub fn credential(&self) -> CredentialStatus {
        self.credential_at(inbound::now_ms())
    }

    /// [`credential`](Self::credential) judged against `now_ms` (ms epoch) —
    /// only `expired` depends on it. (In TS this is `credential` with a
    /// defaulted argument.)
    pub fn credential_at(&self, now_ms: i64) -> CredentialStatus {
        match self.inner.cred_renewer.lock().unwrap().as_ref() {
            Some(renewer) => renewer.status(now_ms),
            None => crate::credential::unwatched_credential_status(),
        }
    }

    /// Renew the connection credential now, regardless of schedule.
    ///
    /// Errors when no `credential_renewal` was configured, and when the mesh
    /// refuses — a refusal IS the revocation mechanism (§4.8), so treat it as a
    /// real answer rather than a transient fault.
    pub async fn renew_credential(&self) -> Result<()> {
        let renewer = self.inner.cred_renewer.lock().unwrap().clone();
        let Some(renewer) = renewer else {
            return Err(MeshError::code(
                ErrorCode::Internal,
                "renew_credential(): this agent was connected without credential_renewal",
            ));
        };
        renewer.renew().await.map(|_| ())
    }

    /// Renew the credential if its deadline has passed as of `now_ms`. Never
    /// errors; exposed so a host can drive the check on its own clock (tests, a
    /// supervisor loop) rather than only on the SDK's timer.
    pub async fn renew_credential_if_due(&self, now_ms: i64) -> bool {
        let renewer = self.inner.cred_renewer.lock().unwrap().clone();
        match renewer {
            Some(renewer) => renewer.renew_if_due(now_ms).await,
            None => false,
        }
    }

    /// Stop the credential loop. Called from close so the timer never outlives
    /// the connection it was keeping alive.
    fn stop_credential_renewal(&self) {
        if let Some(renewer) = self.inner.cred_renewer.lock().unwrap().take() {
            renewer.stop();
        }
    }

    /// Detached Ed25519 signature over `message` by this agent's key, standard
    /// base64. Mirrors the TS SDK's `AgentMesh.signDetached`.
    ///
    /// Exists for one caller: a [`MeshNode`](crate::MeshNode) assembling the
    /// per-agent consent lines of a node-credential request (§4.8). The node
    /// must prove every hosted agent agreed to be hosted, and the alternative —
    /// handing the node each agent's seed — would put key material somewhere it
    /// does not need to be.
    ///
    /// Not general-purpose signing: use [`sign_envelope`] or the tagged signers
    /// for anything protocol-shaped, which carry a domain tag and this
    /// deliberately does not.
    #[doc(hidden)]
    pub fn sign_detached(&self, message: &str) -> String {
        use base64::Engine as _;
        let sig = self
            .inner
            .agent_kp()
            .sign(message.as_bytes())
            .expect("a valid agent keypair signs");
        base64::engine::general_purpose::STANDARD.encode(sig)
    }

    /// Whether this agent has been closed — the seam a hosting node's renewal
    /// loop uses to prune agents that detached.
    pub(crate) fn is_closed(&self) -> bool {
        self.inner.closed.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Whether the LIVE inbox subscription is on the private `.guarded` subject
    /// (EXT-6 §7.1) — i.e. whether mail sent to this agent's public inbox can
    /// still reach it. `false` when there is no subscription at all.
    pub fn listening_on_guarded(&self) -> bool {
        *self.inner.inbox_subject_guarded.lock().unwrap() == Some(true)
    }

    /// Ask the admission service to guard this inbox (EXT-6 §7.1) and report
    /// whether it said yes. `true` is the ONLY answer that may move this agent
    /// off its public inbox.
    ///
    /// The refusal handling is the substance here, and it is deliberately strict.
    /// Setting "guarded" on any reply at all was a real defect with two ways in:
    ///
    /// - every service subject is wrapped in the platform's shared rate limiter,
    ///   which answers over the limit with a `RATE_LIMITED` **error** envelope.
    ///   An agent that had just been chatty — or one of many behind a busy node —
    ///   asked to be guarded, was refused, and unsubscribed itself from the only
    ///   inbox anybody was writing to;
    /// - any mesh participant that can publish into this connection's reply inbox
    ///   could answer first with anything at all, which made "make that agent
    ///   unreachable" a single unsigned message.
    ///
    /// So: decode (which verifies the signature, §5.3), bind the reply to this
    /// request (§6.2), refuse any `error`, and require the service's explicit ok.
    /// A timeout, no responders, an undecodable or unbound reply, an error, and
    /// the benign `{queued: true}` receipt the service gives a *sender* whose
    /// message was dropped are all NOT guarded. The service also refuses by
    /// saying nothing at all — it does that for an unregistered agent and at its
    /// guard ceiling — which is exactly why silence and error must land in the
    /// same place.
    async fn request_guard(&self) -> bool {
        // §7.1: empty payload. The service derives the inbox from the verified
        // `from`, so there is nothing to say and no way to guard another inbox.
        let mut env = Envelope::new(PrimitiveType::Request, &self.inner.agent_id);
        env.payload = Some(json!({}));
        self.inner.sign(&mut env);
        let Ok(bytes) = codec::encode(&env) else { return false };

        let resp = match tokio::time::timeout(
            GUARD_TIMEOUT,
            self.inner.client.request(subjects::ADMISSION_GUARD, bytes.into()),
        )
        .await
        {
            Ok(Ok(resp)) => resp,
            // Timed out, no responders, or the connection is gone: not guarded.
            _ => return false,
        };
        // Decoding is where the signature is verified (§5.3), so an unsigned or
        // forged reply never reaches the judgement below.
        let Ok(resp_env) = codec::decode(&resp.payload) else { return false };
        guard_reply_is_ok(&resp_env, &env.id, &self.inner.agent_id)
    }

    /// Tell the admission service to stop guarding this inbox (EXT-6 §7.1),
    /// because this process is not listening on the guarded subject.
    ///
    /// Best-effort reconciliation, not a precondition: a guard entry is a claim
    /// about a subscription this process holds, and this process is the only party
    /// that knows the subscription is not there.
    ///
    /// **Published, not requested.** There is nothing to learn from an answer —
    /// we stay on the public inbox either way — and a request would spend the
    /// timeout on every mesh with no admission service deployed. Signed and
    /// empty-payloaded exactly like the guard request, so there is no way to
    /// unguard anybody else's inbox. Never fails: leaving a stale entry is the
    /// state we started in, and it must not fail a registration that otherwise
    /// succeeded.
    async fn revoke_guard(&self) {
        let mut env = Envelope::new(PrimitiveType::Request, &self.inner.agent_id);
        env.payload = Some(json!({}));
        self.inner.sign(&mut env);
        if let Ok(bytes) = codec::encode(&env) {
            let _ = self
                .inner
                .client
                .publish(subjects::ADMISSION_UNGUARD, bytes.into())
                .await;
        }
    }

    /// Send a request and await the response (§6.4). A bare response yields
    /// `task_id: None`; a Task response yields the responder-assigned id.
    pub async fn request(&self, agent_id: &str, offering: &str, input: Value) -> Result<RequestResult> {
        self.request_with_options(agent_id, offering, input, RequestOptions::default()).await
    }

    /// Send a request carrying a budget (§7.7): the most this work may cost
    /// and the latest it may finish, as an offer the responder reads before
    /// doing any work. The budget attaches to the REQUEST, not to a Task,
    /// because the requester cannot know whether a Task will exist (§7.0): a
    /// bare answer makes it a static offer for that single round, a deferred
    /// one makes the Task inherit it — in which case it is recorded here under
    /// the responder-assigned task id and becomes live: revisable via
    /// [`AgentMesh::revise_budget`], readable via [`AgentMesh::task_budget`].
    ///
    /// A responder that cannot work within the budget refuses at admission:
    /// the error surfaces as [`MeshError::Refusal`] with `BUDGET_INSUFFICIENT`
    /// or `DEADLINE_UNMEETABLE`, whose `details.estimate` is the responder's
    /// counter-offer — resubmit with better terms, or pick another agent.
    ///
    /// The budget must validate (§7.7): `revision` 0 comes from the
    /// [`Budget`] constructors, and at least one axis must be present.
    pub async fn request_with_budget(
        &self,
        agent_id: &str,
        offering: &str,
        input: Value,
        budget: Budget,
    ) -> Result<RequestResult> {
        self.request_with_options(
            agent_id,
            offering,
            input,
            RequestOptions { budget: Some(budget), ..Default::default() },
        )
        .await
    }

    /// Send a request with the full option set: a §7.7 budget, a §6.4b
    /// pre-flight/§14.4 resolution manifest, an explicit response timeout, and
    /// an observer for the §6.4a delivery signals.
    ///
    /// The §6.4b pre-flight runs before anything is published: sender text
    /// against the recipient's declared cap (or the §22.5 default), content
    /// types against the manifest when one is at hand, and the serialized
    /// envelope against the transport's advertised `max_payload` (§18.9) — each
    /// refused locally with the same code the recipient would answer with, as
    /// a [`MeshError::Refusal`] whose `details` name the limit that fired.
    /// Nothing refused here was published, signed into the §22.2 memory, or
    /// retried.
    ///
    /// While waiting, a §6.4a accept resets the response timeout and never
    /// resolves the request; a queued node-ack never resolves it either — it
    /// fires [`RequestOptions::on_signal`] and then rejects promptly with the
    /// SDK-local `REQUEST_QUEUED` (ack fields and request id in
    /// `error.details`), because after a queued ack the reply channel will
    /// never carry anything more. The request completes on the first
    /// `respond` whose `payload.status` is not `"accepted"` (§7.0).
    pub async fn request_with_options(
        &self,
        agent_id: &str,
        offering: &str,
        input: Value,
        opts: RequestOptions,
    ) -> Result<RequestResult> {
        // The naming rule, before anything else is looked at: an unnamed agent
        // sends nothing, and is told why (crate::naming_gate).
        self.require_named().await?;
        if let Some(budget) = &opts.budget {
            budget.validate()?;
        }
        // §6.4b, the manifest-side checks (text cap, content types).
        crate::preflight::preflight_request(
            opts.recipient.as_ref(),
            offering,
            &input,
            opts.accepted_output.as_deref(),
        )?;

        // §8.9: seal the caller's material when the recipient asks to be sealed
        // to. AFTER the pre-flight above on purpose — the §22.5 text cap and
        // the content-type check are about what the recipient will read, which
        // is the plaintext, and measuring base64 ciphertext against a character
        // cap would refuse messages that are inside it.
        let input = self.seal_outbound(agent_id, input, opts.recipient.as_ref(), opts.seal)?;

        let mut payload = json!({ "offering": offering, "input": input });
        if let Some(accepted) = &opts.accepted_output {
            payload["config"] = json!({ "accepted_output": accepted });
        }
        let mut env = Envelope::new(PrimitiveType::Request, &self.inner.agent_id);
        env.to = Some(agent_id.to_string());
        env.payload = Some(payload);
        env.budget = opts.budget.clone();
        self.inner.sign(&mut env);
        let bytes = codec::encode(&env)?;

        // §6.4b: the serialized envelope against the transport's advertised
        // maximum payload (§18.9). Integer byte math; at the bound is legal.
        crate::preflight::preflight_envelope_size(
            bytes.len(),
            self.inner.client.server_info().max_payload,
        )?;

        // §14.4: a carried endpoint wins over subject construction; the SDK is
        // the convention's legitimate constructor when no manifest is at hand.
        let subject = opts
            .recipient
            .as_ref()
            .and_then(|m| m.resolved_inbox())
            .map(str::to_string)
            .unwrap_or_else(|| subjects::agent_inbox(agent_id));

        // The producer half of this hop (§13.1.1). Timed around the wire wait
        // only: what happens after the reply lands is this process unsealing
        // and bookkeeping, which is not the hop and would inflate every
        // duration.
        let span_start = chrono::Utc::now().timestamp_millis();
        let span_of = |outcome, error_code| crate::spans::SpanInput {
            trace: env.trace.clone(),
            kind: crate::spans::SpanKind::Producer,
            agent_id: self.inner.agent_id.clone(),
            operation: "request",
            peer: Some(agent_id.to_string()),
            offering: Some(offering.to_string()),
            task_id: None,
            context_id: env.context_id.clone(),
            outcome,
            error_code,
            started_at: span_start,
            ended_at: chrono::Utc::now().timestamp_millis(),
        };

        let awaited = self
            .publish_and_await_substantive(
                subject,
                bytes,
                &env.id,
                opts.timeout.unwrap_or(DEFAULT_REQUEST_TIMEOUT),
                opts.on_signal.as_ref(),
            )
            .await;
        let (accepted, resp_env) = match awaited {
            Ok(v) => v,
            Err(e) => {
                let (outcome, code) = crate::spans::outcome_of(&e);
                self.inner.publish_span(span_of(outcome, code)).await;
                return Err(e);
            }
        };
        if let Some(err) = &resp_env.error {
            let e = MeshError::from_error_object(err);
            let (outcome, code) = crate::spans::outcome_of(&e);
            self.inner.publish_span(span_of(outcome, code)).await;
            return Err(e);
        }
        // A reply arrived and carried no error, so both the hop and the work
        // succeeded.
        self.inner
            .publish_span(span_of(crate::spans::SpanOutcome::Ok, None))
            .await;
        let budget = opts.budget;
        // §7.7 scope: the responder went deferred, so the Task inherits the
        // request's budget and it becomes live. Recorded via latest-wins so a
        // revision that somehow arrived first is not clobbered by revision 0.
        if let (Some(task_id), Some(b)) = (resp_env.task_id.as_deref(), budget.as_ref()) {
            self.inner.task_budgets.apply(task_id, b);
        }
        // §10.8 propagation basis: a sub-request issued from inside a
        // dispatched handler, whose reply created a Task, is a delegation of
        // the task being handled — recorded so an inbound cancel for the
        // parent can be forwarded here. (Not inherited across `tokio::spawn`:
        // a sub-request issued from a task the handler spawned is invisible
        // to this, like §13.1 ambient tracing.)
        if let Some(sub_task_id) = resp_env.task_id.as_deref() {
            if let Ok(dispatch) = crate::util::CURRENT_DISPATCH.try_with(|d| d.clone()) {
                self.record_delegation(&dispatch.task_id, &dispatch.offering, sub_task_id, agent_id);
            }
        }
        // §8.9: a sealed answer, opened for the caller. The ENVELOPE is left
        // verbatim — its signature covers the ciphertext, so handing back a
        // record carrying the plaintext would hand back one that no longer
        // verifies. `payload` is the copy: the envelope is what arrived, the
        // payload is what it says.
        let mut payload = resp_env.payload.clone().unwrap_or(Value::Null);
        if let Some(seed) = self.inner.encryption_seed.as_deref() {
            if let Some(opened) = payload
                .get("output")
                .and_then(|o| crate::sealed::open_sealed_value(o, seed))
            {
                payload["output"] = opened.payload;
            }
        }
        Ok(RequestResult {
            task_id: resp_env.task_id.clone(),
            payload,
            envelope: resp_env,
            accepted,
        })
    }

    /// Publish a signed request and wait for its first **substantive** respond
    /// (§7.0): §6.4a accepts reset the timeout and are surfaced, never
    /// returned; queued node-acks are surfaced, never returned; replies are
    /// bound to the request (`in_reply_to`) and deduplicated on `(from, id)`
    /// (§22.2, D.2 #8). Returns `(accept_seen, substantive_envelope)`.
    ///
    /// The substantive respond arrives at this agent's OWN inbox, correlated by
    /// `in_reply_to` (§6.4a), and that holds for BOTH request modes: the bare
    /// answer and the §11.3 step-2 opening travel the same path. The transport
    /// reply subject the request still travels with is **liveness-only**: it
    /// exists so the broker's 503 no-responders status has somewhere to arrive,
    /// and so a node holding an attended inbox can answer its queued ack.
    /// Envelope data on it never resolves the wait. The inbox copy has already
    /// been through [`inbound::admit_envelope`] when it reaches this wait,
    /// which is the whole point of the routing: a reply gets the same §22
    /// protections as everything else this agent reads.
    async fn publish_and_await_substantive(
        &self,
        subject: String,
        bytes: Vec<u8>,
        request_id: &str,
        timeout: Duration,
        on_signal: Option<&DeliverySignalSink>,
    ) -> Result<(bool, Envelope)> {
        // The reply arrives at this agent's own inbox, so the inbox must be
        // listening, including for an agent that only sends and never
        // registers. Idempotent, and on the PUBLIC subject: an agent that will
        // later register guarded should register before it sends.
        self.listen_inbox(false).await?;
        let mut correlated = PendingReply::register(self.inner.clone(), request_id);

        let reply_inbox = self.inner.client.new_inbox();
        let mut sub = self
            .inner
            .client
            .subscribe(reply_inbox.clone())
            .await
            .map_err(|e| MeshError::Transport(e.to_string()))?;
        self.inner
            .client
            .publish_with_reply(subject.clone(), reply_inbox, bytes.into())
            .await
            .map_err(|e| MeshError::Transport(e.to_string()))?;

        // The response timeout. An accept RESETS it (§6.4a: the wait is no
        // longer blind; the caller's patience restarts) — it does not stack,
        // and it moves no §7.7 deadline.
        let mut deadline = tokio::time::Instant::now() + timeout;
        let mut accepted = false;
        let mut seen: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();

        // What one iteration of the wait received, from whichever channel.
        enum Arrival {
            Transport(Option<async_nats::Message>),
            Correlated(Option<Envelope>),
        }

        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(request_timeout_error(timeout, accepted));
            }
            let next = async {
                tokio::select! {
                    m = sub.next() => Arrival::Transport(m),
                    e = correlated.rx.recv() => Arrival::Correlated(e),
                }
            };
            let arrival = match tokio::time::timeout(remaining, next).await {
                Ok(a) => a,
                Err(_) => return Err(request_timeout_error(timeout, accepted)),
            };
            let (env, substantive_resolves) = match arrival {
                Arrival::Transport(None) => {
                    return Err(MeshError::Transport("reply subscription closed".to_string()))
                }
                Arrival::Correlated(None) => {
                    return Err(MeshError::Transport(
                        "agent closed while a request was outstanding".to_string(),
                    ))
                }
                Arrival::Transport(Some(msg)) => {
                    // Transport 503: undeliverable AND unbuffered, nothing
                    // subscribes to the subject and no mailbox stream captures
                    // it (§6.4). This is the liveness the reply subject exists
                    // to carry, and it is as fast as it ever was.
                    if msg.status == Some(async_nats::StatusCode::NO_RESPONDERS) {
                        return Err(MeshError::code(
                            ErrorCode::AgentUnavailable,
                            format!(
                                "No responders on {subject}: the agent is not accepting requests \
                                 and has no redelivery buffer (§6.4)"
                            ),
                        ));
                    }
                    // decode verifies the signature (§5.3); an unsigned or
                    // forged reply never reaches the judgement below.
                    let Ok(env) = codec::decode(&msg.payload) else { continue };
                    // This channel carries signals, never the answer: the
                    // substantive respond, bare or the §11.3 opening alike,
                    // resolves only through the inbox correlation.
                    (env, false)
                }
                // Already §22-admitted at the inbox before it was forwarded.
                Arrival::Correlated(Some(env)) => (env, true),
            };
            // §22.2 dedup on the pair (from, id), an accept "deduplicates like
            // any envelope", shared across both channels, so a respond that
            // somehow arrives on both is judged once.
            if !seen.insert((env.from.clone(), env.id.clone())) {
                continue;
            }
            match wait_step(&env, request_id, substantive_resolves) {
                WaitStep::Ignore => continue,
                WaitStep::AcceptSeen => {
                    accepted = true;
                    deadline = tokio::time::Instant::now() + timeout;
                    if let Some(sink) = on_signal {
                        sink(DeliverySignal::Accepted { envelope: env });
                    }
                    continue;
                }
                WaitStep::Queued(ack) => {
                    // The queued ack never resolves the request — and after it,
                    // nothing more is coming for THIS wait (the real reply
                    // arrives at this agent's own inbox after the attended
                    // session drains it, §6.4), so waiting on would wait on
                    // nothing. Signal first, then reject promptly with the
                    // SDK-local REQUEST_QUEUED.
                    if let Some(sink) = on_signal {
                        sink(DeliverySignal::Queued { inbox_id: ack.inbox_id.clone() });
                    }
                    return Err(request_queued_error(&ack, request_id));
                }
                WaitStep::Resolve => return Ok((accepted, env)),
            }
        }
    }

    // ── §7.7 live budget (Task-inherited) ────────────────────────────────

    /// The latest budget recorded for a task — the highest revision seen, per
    /// §7.7's latest-revision-wins. Fed by [`AgentMesh::request_with_budget`]
    /// (a Task inheriting the request's budget), by inbound requests carrying
    /// one, by [`AgentMesh::revise_budget`], and by
    /// [`AgentMesh::watch_task_budget`].
    pub fn task_budget(&self, task_id: &str) -> Option<Budget> {
        self.inner.task_budgets.get(task_id)
    }

    /// Send a budget revision for a task (§7.7): a task update **carrying only
    /// the budget block**. Revisions are absolute, never deltas — `budget`
    /// states the entire budget, and the highest revision is the whole truth
    /// (start from `self.task_budget(task_id)` and [`Budget::revised`]).
    ///
    /// Monotonicity is enforced locally before anything is published: a
    /// revision at or below the recorded one fails with
    /// `TASK_INVALID_TRANSITION`, the same refusal the task manager gives
    /// centrally. `to` names the counterparty when known (requester revising
    /// toward the responder, or the reverse); either party to a Task may
    /// revise.
    pub async fn revise_budget(&self, task_id: &str, to: Option<&str>, budget: Budget) -> Result<()> {
        budget.validate()?;
        self.inner.task_budgets.ensure_monotonic(task_id, budget.revision)?;
        let mut env = crate::budget::budget_revision_update(&self.inner.agent_id, task_id, to, &budget);
        self.inner.sign(&mut env);
        self.inner
            .client
            .publish(subjects::task_update(task_id), codec::encode(&env)?.into())
            .await
            .map_err(|e| MeshError::Transport(e.to_string()))?;
        self.inner.task_budgets.apply(task_id, &budget);
        Ok(())
    }

    /// Pause a task at the cost ceiling (§7.7 `BUDGET_EXHAUSTED`): publish the
    /// `input_required` task update reporting spend so far and an estimate to
    /// finish. A responder MUST stop BEFORE crossing the ceiling and send
    /// this rather than run past it — spend past the ceiling is on the
    /// responder's own account. The input required is money: the requester
    /// raises the budget by revision (which
    /// [`AgentMesh::watch_task_budget`] surfaces here) and work resumes, or
    /// cancels and keeps the partial artifacts.
    pub async fn pause_budget_exhausted(
        &self,
        task_id: &str,
        requester: Option<&str>,
        spent: &CostCeiling,
        estimate_to_finish: &CostCeiling,
        message: impl Into<String>,
    ) -> Result<()> {
        let mut env = crate::budget::budget_exhausted_update(
            &self.inner.agent_id,
            task_id,
            requester,
            spent,
            estimate_to_finish,
            message,
        );
        self.inner.sign(&mut env);
        self.inner
            .client
            .publish(subjects::task_update(task_id), codec::encode(&env)?.into())
            .await
            .map_err(|e| MeshError::Transport(e.to_string()))?;
        Ok(())
    }

    /// Watch a task's update subject for budget revisions (§7.7) and fold them
    /// into this agent's per-task budget state under latest-revision-wins —
    /// lower or equal revisions are ignored, so lost and reordered updates
    /// cost nothing. Read the current truth with [`AgentMesh::task_budget`].
    ///
    /// Every applied envelope is signature-verified at decode (§5.3): an
    /// unsigned or forged revision never reaches the store. Which PARTIES may
    /// revise (requester and responder only, `UNAUTHORIZED` otherwise) is the
    /// task manager's check — it holds the Task's parties centrally; this
    /// watch surfaces what the mesh delivered.
    ///
    /// The subscription lives until [`AgentMesh::close`]. Typical use: a
    /// responder paused in `BUDGET_EXHAUSTED` watches for the raise; a
    /// requester watches a long task for the responder's revisions.
    pub async fn watch_task_budget(&self, task_id: &str) -> Result<()> {
        let mut sub = self
            .inner
            .client
            .subscribe(subjects::task_update(task_id))
            .await
            .map_err(|e| MeshError::Transport(e.to_string()))?;
        let inner = self.inner.clone();
        let task_id = task_id.to_string();
        let handle = tokio::spawn(async move {
            while let Some(msg) = sub.next().await {
                let Ok(env) = codec::decode(&msg.payload) else { continue };
                if env.task_id.as_deref() != Some(task_id.as_str()) {
                    continue;
                }
                if let Some(budget) = &env.budget {
                    if budget.validate().is_ok() {
                        inner.task_budgets.apply(&task_id, budget);
                    }
                }
            }
        });
        self.inner.tasks.lock().unwrap().push(handle);
        Ok(())
    }

    // ── §10.8 cancel ─────────────────────────────────────────────────────

    /// Cancel a Task, with a stated reason (§10.8). The cancel travels twice:
    ///
    /// 1. the canceled TASK UPDATE — a signed `respond` on
    ///    `mesh.task.{task_id}.update` with `payload.status: "canceled"` and
    ///    the reason (+ note, omitted when absent) alongside it. This is what
    ///    the task manager records, and publishing it is what this method
    ///    awaits: **for the requester, cancellation is effective when sent**;
    /// 2. the `task.cancel` request to `agent_id`'s inbox — best-effort
    ///    notification, spawned rather than awaited, its reply and errors
    ///    ignored. The performer may be offline with the cancel sitting in
    ///    its mailbox (§16.4); that is the mesh working, not a failure.
    ///
    /// `reason` is REQUIRED and closed ([`CancelReason`]); `note` is optional
    /// free text for humans — the enum, not the note, is what the record
    /// carries as meaning. The Task's locally recorded budget is dropped:
    /// canceled is terminal.
    ///
    /// A performer receiving this cancel forwards it to its own still-live
    /// delegates automatically (reason `upstream_cancelled`, the original
    /// reason in the note) unless its handler opted out via
    /// [`HandlerOptions`]. Honest limitation of that tracking: a task-local
    /// is not inherited across `tokio::spawn`, so sub-requests a handler
    /// issues from a task it spawned are not auto-tracked (the same
    /// limitation §13.1 ambient tracing has).
    pub async fn cancel(
        &self,
        agent_id: &str,
        task_id: &str,
        reason: CancelReason,
        note: Option<String>,
    ) -> Result<()> {
        self.cancel_with(agent_id, task_id, reason, note, None).await
    }

    /// [`AgentMesh::cancel`], plus §10.8's qualifying fields: `unmet_need`
    /// (REQUIRED with [`CancelReason::NeedsNotFurnished`]) and `dependency`
    /// (optional with [`CancelReason::DependencyFailed`]). Refused as
    /// `INVALID_ENVELOPE` before anything is published when the qualifier does
    /// not match the reason.
    pub async fn cancel_with(
        &self,
        agent_id: &str,
        task_id: &str,
        reason: CancelReason,
        note: Option<String>,
        qualifier: Option<StopQualifier>,
    ) -> Result<()> {
        validate_stop_qualifier(Some(reason), qualifier.as_ref())?;
        // Leg 1: the canceled task update — the record (§10.8 flow step 2).
        let mut update = Envelope::new(PrimitiveType::Respond, &self.inner.agent_id);
        update.to = Some(agent_id.to_string());
        update.task_id = Some(task_id.to_string());
        update.payload =
            Some(canceled_update_payload(reason, note.as_deref(), qualifier.as_ref()));
        self.inner.sign(&mut update);
        self.inner
            .client
            .publish(subjects::task_update(task_id), codec::encode(&update)?.into())
            .await
            .map_err(|e| MeshError::Transport(e.to_string()))?;

        // Canceled is terminal: the recorded budget no longer describes live
        // work (§7.7).
        self.inner.task_budgets.forget(task_id);

        // Leg 2: best-effort notification to the performer's inbox (§10.8
        // flow step 1). Spawned; cancellation was effective at the publish
        // above, so nothing here can fail the cancel.
        let mut req = Envelope::new(PrimitiveType::Request, &self.inner.agent_id);
        req.to = Some(agent_id.to_string());
        req.payload =
            Some(cancel_request_payload(task_id, reason, note.as_deref(), qualifier.as_ref()));
        self.inner.sign(&mut req);
        let bytes = codec::encode(&req)?;
        let client = self.inner.client.clone();
        let inbox = subjects::agent_inbox(agent_id);
        let handle = tokio::spawn(async move {
            let _ = tokio::time::timeout(CANCEL_NOTIFY_TIMEOUT, client.request(inbox, bytes.into()))
                .await;
        });
        self.inner.tasks.lock().unwrap().push(handle);
        Ok(())
    }

    /// End a Task this agent is performing as `failed`, saying why (§10.8):
    /// publish a signed `respond` on `mesh.task.{task_id}.update` with
    /// `payload.status: "failed"` and the reason vocabulary alongside it.
    ///
    /// `reason` is OPTIONAL. A Task that simply did not work out is a complete
    /// statement and nobody is obliged to invent an excuse; what stating one
    /// buys is the distinction between three endings that otherwise look
    /// identical in the record — the performer did not deliver, the caller
    /// never furnished something the offering declared it needed
    /// ([`CancelReason::NeedsNotFurnished`], which MUST name the declared
    /// need), and an outside service the performer depends on broke
    /// ([`CancelReason::DependencyFailed`]).
    ///
    /// Whose failure it was is `attribution`, the platform computes it by
    /// checking the named need against this agent's own registered manifest,
    /// and it is deliberately not something a party puts on the wire (§10.8a).
    /// Naming a need that was never declared reads as a plain failure, so the
    /// way to be believed is to declare what you need before the work starts.
    pub async fn fail_task(
        &self,
        agent_id: &str,
        task_id: &str,
        reason: Option<CancelReason>,
        note: Option<String>,
        qualifier: Option<StopQualifier>,
    ) -> Result<()> {
        validate_stop_qualifier(reason, qualifier.as_ref())?;
        let mut update = Envelope::new(PrimitiveType::Respond, &self.inner.agent_id);
        update.to = Some(agent_id.to_string());
        update.task_id = Some(task_id.to_string());
        update.payload =
            Some(failed_update_payload(reason, note.as_deref(), qualifier.as_ref()));
        self.inner.sign(&mut update);
        self.inner
            .client
            .publish(subjects::task_update(task_id), codec::encode(&update)?.into())
            .await
            .map_err(|e| MeshError::Transport(e.to_string()))?;
        // Failed is terminal: the recorded budget no longer describes live
        // work (§7.7), exactly as on a cancel.
        self.inner.task_budgets.forget(task_id);
        Ok(())
    }

    /// Record that the handler currently being dispatched (parent task
    /// `parent_task_id`, running for `parent_offering`) delegated part of its
    /// work: sub-task `sub_task_id` at `delegate`. Spawns the liveness
    /// watcher on the sub-task's update subject; "still live" is presence in
    /// `Inner::delegations`, and the watcher is what removes the entry when
    /// the sub-task reaches a terminal state on its own.
    fn record_delegation(
        &self,
        parent_task_id: &str,
        parent_offering: &str,
        sub_task_id: &str,
        delegate: &str,
    ) {
        // The entry is recorded BEFORE the watcher spawns, so a terminal
        // update that races the spawn still finds something to remove.
        {
            let mut map = self.inner.delegations.lock().unwrap();
            let entry = map.entry(parent_task_id.to_string()).or_insert_with(|| {
                ParentDelegations { offering: parent_offering.to_string(), subs: HashMap::new() }
            });
            entry.subs.insert(
                sub_task_id.to_string(),
                SubDelegation { delegate: delegate.to_string(), watcher: None },
            );
        }
        let inner = self.inner.clone();
        let parent = parent_task_id.to_string();
        let sub_id = sub_task_id.to_string();
        let delegate = delegate.to_string();
        let handle = tokio::spawn(async move { watch_sub_task(inner, parent, sub_id, delegate).await });
        let abort = handle.abort_handle();
        self.inner.tasks.lock().unwrap().push(handle);
        let mut map = self.inner.delegations.lock().unwrap();
        if let Some(entry) = map.get_mut(parent_task_id) {
            if let Some(sub) = entry.subs.get_mut(sub_task_id) {
                sub.watcher = Some(abort);
            }
        }
        // Entry already gone: the watcher saw a terminal state (or propagation
        // drained it) in the gap, and has already ended itself.
    }

    /// Send a streaming request (§11.3). The task id is requester-generated and
    /// the chunk-stream subscription is established BEFORE the request is sent,
    /// so no chunk can be missed. Returns the verified signed opening (§11.6)
    /// plus a channel of chunks; the channel closes after the final chunk or an
    /// error item. Set `sign_chunks` to demand a signature on every chunk
    /// (strict mode, §11.6); by default streams are authenticated by their
    /// signed opening + signed final (with chunk_count).
    ///
    /// §6.4a on this path: when the responder is live, its accept signal
    /// arrives at this agent's inbox **before** the §11.3 step-2 `working`
    /// opening, which travels to the same inbox like every other respond. The
    /// accept resets the wait and establishes nothing: the opening is the
    /// first substantive respond, and it, not the accept, is what
    /// authenticates the stream (§11.6). The chunk-stream subscription is
    /// bound before the request is published, so nothing races the inbox
    /// round trip. The §6.4b text-cap and envelope-size pre-flights run here
    /// too (against the §22.5 default cap, since this signature carries no
    /// manifest).
    pub async fn request_stream(
        &self,
        agent_id: &str,
        offering: &str,
        input: Value,
        sign_chunks: bool,
    ) -> Result<StreamResult> {
        self.require_named().await?;
        // §6.4b, the checks that need no manifest.
        crate::preflight::preflight_sender_text(&input, None)?;

        let task_id = crate::util::uuid7();
        let mut sub = self
            .inner
            .client
            .subscribe(subjects::task_stream(&task_id))
            .await
            .map_err(|e| MeshError::Transport(e.to_string()))?;

        let mut env = Envelope::new(PrimitiveType::Request, &self.inner.agent_id);
        env.to = Some(agent_id.to_string());
        env.task_id = Some(task_id.clone());
        env.payload = Some(json!({
            "offering": offering,
            "input": input,
            "config": { "stream": true, "sign_chunks": sign_chunks },
        }));
        self.inner.sign(&mut env);
        let bytes = codec::encode(&env)?;
        crate::preflight::preflight_envelope_size(
            bytes.len(),
            self.inner.client.server_info().max_payload,
        )?;

        // The signed opening authenticates the responder for the stream
        // (§11.6); the accept, when one precedes it, authenticates only
        // delivery and is skipped here like any §6.4a signal.
        let (_accepted, initial) = self
            .publish_and_await_substantive(
                subjects::agent_inbox(agent_id),
                bytes,
                &env.id,
                DEFAULT_REQUEST_TIMEOUT,
                None,
            )
            .await?;
        if let Some(err) = &initial.error {
            return Err(MeshError::from_error_object(err));
        }
        // §10.8 propagation basis, requester-generated task id: a stream
        // opened from inside a dispatched handler is a delegation too.
        if let Ok(dispatch) = crate::util::CURRENT_DISPATCH.try_with(|d| d.clone()) {
            self.record_delegation(&dispatch.task_id, &dispatch.offering, &task_id, agent_id);
        }

        let (tx, rx) = tokio::sync::mpsc::channel(64);
        tokio::spawn(async move {
            let deadline = tokio::time::Instant::now() + STREAM_TIMEOUT;
            let mut received: u64 = 0;
            loop {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    let _ = tx
                        .send(Err(MeshError::code(ErrorCode::TransportTimeout, "Stream timed out")))
                        .await;
                    break;
                }
                let wait = remaining.min(CHUNK_TIMEOUT);
                let msg = match tokio::time::timeout(wait, sub.next()).await {
                    Ok(Some(m)) => m,
                    Ok(None) => break, // subscription closed
                    Err(_) => {
                        let _ = tx
                            .send(Err(MeshError::code(
                                ErrorCode::TransportTimeout,
                                format!("No chunk received within {}ms", wait.as_millis()),
                            )))
                            .await;
                        break;
                    }
                };
                received += 1;
                match validate_chunk(&msg.payload, sign_chunks, received) {
                    Ok(ChunkOutcome::Chunk(c)) => {
                        let is_final = c.is_final;
                        if tx.send(Ok(c)).await.is_err() {
                            break;
                        }
                        if is_final {
                            break;
                        }
                    }
                    Ok(ChunkOutcome::Error(e)) | Err(e) => {
                        let _ = tx.send(Err(e)).await;
                        break;
                    }
                }
            }
            // dropping `sub` unsubscribes from the chunk stream
        });

        Ok(StreamResult { task_id, initial, chunks: rx })
    }

    /// Discover agents on the mesh matching an optional query (§6.2). Returns
    /// the manifests the registry reports (availability joined from presence).
    pub async fn discover(&self, query: DiscoverQuery) -> Result<Vec<Manifest>> {
        // Parse per entry, skipping any that don't conform to the 0.2 manifest
        // (e.g. legacy pre-node-vouch registrations) — one bad manifest must
        // not fail the whole discovery result.
        Ok(self
            .discover_raw(query)
            .await?
            .into_iter()
            .filter_map(|v| serde_json::from_value::<Manifest>(v).ok())
            .collect())
    }

    /// Discover agents, returning each manifest as the registry's verbatim
    /// JSON document. This carries registry-joined fields the typed
    /// [`Manifest`] deliberately doesn't model — notably operator-attested
    /// node standing (`node.profile.trust_tier`, `role`, §9.7). For indexers
    /// and catalogs; agents calling other agents want [`discover`](Self::discover).
    pub async fn discover_raw(&self, query: DiscoverQuery) -> Result<Vec<Value>> {
        let mut env = Envelope::new(PrimitiveType::Discover, &self.inner.agent_id);
        env.payload = Some(serde_json::to_value(&query)?);
        self.inner.sign(&mut env);

        let resp = self
            .inner
            .client
            .request(subjects::REGISTRY_DISCOVER, codec::encode(&env)?.into())
            .await
            .map_err(|e| MeshError::Transport(e.to_string()))?;

        let resp_env = codec::decode(&resp.payload)?;
        if let Some(err) = &resp_env.error {
            return Err(MeshError::from_error_object(err));
        }
        Ok(resp_env
            .payload
            .as_ref()
            .and_then(|p| p.get("agents"))
            .and_then(|a| a.as_array())
            .cloned()
            .unwrap_or_default())
    }

    /// Emit a fire-and-forget event. `topic` is `{domain}.{event_type}`.
    pub async fn emit(&self, topic: &str, data: Value) -> Result<()> {
        self.require_named().await?;
        let mut parts = topic.splitn(2, '.');
        let domain = parts.next().unwrap_or(topic);
        let event_type = parts.next().unwrap_or(topic);
        let mut env = Envelope::new(PrimitiveType::Emit, &self.inner.agent_id);
        env.payload = Some(json!({ "domain": domain, "event_type": event_type, "data": data }));
        self.inner.sign(&mut env);
        // §18.8: the envelope id doubles as the JetStream Nats-Msg-Id, so any
        // stream capturing this subject (the per-room streams, MESH_METERING)
        // can drop a duplicate publish inside its duplicate window. Core NATS
        // ignores the header, so this costs nothing when no stream is
        // listening.
        // The typed name, not the string "Nats-Msg-Id": the server parses the
        // inbound header into the Standard variant, and a string-built name is
        // a Custom one that would not compare equal on lookup.
        let mut headers = async_nats::HeaderMap::new();
        headers.insert(async_nats::header::NATS_MESSAGE_ID, env.id.as_str());
        self.inner
            .client
            .publish_with_headers(subjects::event(topic), headers, codec::encode(&env)?.into())
            .await
            .map_err(|e| MeshError::Transport(e.to_string()))?;
        Ok(())
    }

    /// Subscribe to events matching a subject pattern (NATS wildcards).
    ///
    /// §22 applies here too, and §22.1 is explicit about why: "a protection
    /// present on one path and absent on another is worse than absent". An event
    /// body is untrusted text from a stranger exactly like a request body is, and
    /// it reaches the same model. The one difference is the refusal channel —
    /// there is no reply path on a fire-and-forget event, so an oversized one is
    /// reported to the RECIPIENT's warning sink only (§22.7).
    pub async fn subscribe<F>(&self, pattern: &str, handler: F) -> Result<()>
    where
        F: Fn(Value, Envelope) + Send + Sync + 'static,
    {
        let mut sub = self
            .inner
            .client
            .subscribe(subjects::event(pattern))
            .await
            .map_err(|e| MeshError::Transport(e.to_string()))?;
        let inner = self.inner.clone();
        let pattern = pattern.to_string();
        let handle = tokio::spawn(async move {
            while let Some(msg) = sub.next().await {
                let Ok(env) = codec::decode(&msg.payload) else { continue };
                // §22.2 → §22.4 → §22.3, over the event memory rather than the
                // inbox's, scoped to THIS subscription's pattern (§22.2 refuses
                // a repeat on one subscription, never a delivery to a second
                // one the app deliberately overlapped). An event carries no
                // `to`, so addressing is a no-op here; it costs nothing and is
                // not a special case to maintain.
                if let Some(refusal) = inbound::admit_envelope_scoped(
                    &env,
                    &inner.agent_id,
                    &inner.seen_events,
                    Some(&pattern),
                    InboundSource::Live,
                    inbound::now_ms(),
                ) {
                    inner.warn(
                        refusal,
                        format!("Event on {} refused: {}", msg.subject, refusal.code()),
                        &env.from,
                        &msg.subject,
                    );
                    continue;
                }
                let data = env
                    .payload
                    .as_ref()
                    .and_then(|p| p.get("data").cloned())
                    .unwrap_or(Value::Null);
                let (fence, max_chars) = {
                    let opts = inner.inbound.read().unwrap();
                    (opts.fence, opts.max_inbound_chars)
                };
                // §22.5 before anything reads the body.
                if let Some(size) = inbound::over_inbound_cap(&data, max_chars) {
                    let subject = &msg.subject;
                    inner.warn(
                        InboundRefusal::Oversize,
                        format!(
                            "Event on {subject} carries {size} characters of sender text, over \
                             this agent's {max_chars}-character cap \
                             (InboundOptions.max_inbound_chars)"
                        ),
                        &env.from,
                        subject,
                    );
                    continue;
                }
                // §22.6.
                let data = if fence {
                    inbound::fence_inbound_input(
                        &data,
                        &FrameProvenance {
                            from: &env.from,
                            trace_id: Some(&env.trace.trace_id),
                            ..Default::default()
                        },
                    )
                } else {
                    data
                };
                handler(data, env);
            }
        });
        // Tracked like every other background task: this handle used to be
        // discarded, so `close()` aborted the inbox listener and the heartbeat
        // but left every event loop, and its live subscription, running.
        self.inner.tasks.lock().unwrap().push(handle);
        Ok(())
    }

    /// The delivery loop behind [`AgentMesh::subscribe_feed`] (§6.6a) — here,
    /// next to [`AgentMesh::subscribe`], because it is that method's pipeline
    /// verbatim and must never drift from it: §22.2 → §22.4 → §22.3 over the
    /// same separate event memory (scoped to this subscription's subject), the
    /// §22.5 cap and §22.6 fence over the payload's `data`, refusals to the
    /// recipient's warning sink (§22.7 — a feed is fire-and-forget, so there
    /// is no reply channel), and the handle pushed where `close()` finds it.
    ///
    /// The ONE deliberate difference from `subscribe`: the handler is given
    /// the FULL `{topic, kind, data}` payload — with the protected `data` put
    /// back in place — because a feed carries its identity in-band and a
    /// wildcard subscriber needs the topic to know which feed spoke.
    pub(crate) async fn subscribe_feed_pipeline<F>(&self, subject: String, handler: F) -> Result<()>
    where
        F: Fn(Value, Envelope) + Send + Sync + 'static,
    {
        let mut sub = self
            .inner
            .client
            .subscribe(subject.clone())
            .await
            .map_err(|e| MeshError::Transport(e.to_string()))?;
        let inner = self.inner.clone();
        let handle = tokio::spawn(async move {
            while let Some(msg) = sub.next().await {
                let Ok(env) = codec::decode(&msg.payload) else { continue };
                let Some(payload) =
                    admit_feed_delivery(&inner, &env, &msg.subject, &subject, InboundSource::Live)
                else {
                    continue;
                };
                handler(payload, env);
            }
        });
        self.inner.tasks.lock().unwrap().push(handle);
        Ok(())
    }

    /// The binding behind [`AgentMesh::subscribe_feed_durable`] (§18.6 Feed
    /// Consumer): consumer info, then create or add this feed to its filters,
    /// then start the client's one pull loop if it is not running, all under
    /// the shared lock so two binds never race. See that method for the
    /// contract.
    pub(crate) async fn subscribe_feed_durable_pipeline(
        &self,
        pattern: String,
        handler: crate::feed::FeedHandler,
    ) -> Result<crate::feed::DurableFeedSubscription> {
        use async_nats::jetstream::consumer;
        use async_nats::jetstream::context::ConsumerInfoErrorKind;

        let stream_name = subjects::FEED_STREAM;
        let durable = subjects::feed_consumer(&self.inner.agent_id);
        let refused = |what: &str, e: &dyn std::fmt::Display| {
            MeshError::Transport(format!(
                "Durable feed subscription on {pattern} could not {what} this agent's feed \
                 consumer {durable} on {stream_name} (§18.6 Feed Consumer): {e}. It needs \
                 JetStream and the {stream_name} stream on this mesh, and a credential that \
                 grants this agent its own feed consumer; a credential minted before that \
                 grant existed is refused until it is renewed, which gives it the grant. Not \
                 falling back to a live subscription: durability was asked for."
            ))
        };

        let shared = self.inner.feed_durable.clone();
        let mut state = shared.state.lock().await;

        // No STREAM.INFO: the agent's credential grants only its own consumer's
        // subjects on MESH_FEED, so everything below is a consumer call.
        let js = async_nats::jetstream::new(self.inner.client.clone());
        let stream = js
            .get_stream_no_info(stream_name)
            .await
            .map_err(|e| refused("reach", &e))?;
        match stream.consumer_info(&durable).await {
            Ok(info) => {
                let existing = info.config;
                if let Some(filters) = crate::feed::feed_filters_with(
                    &existing.filter_subjects,
                    &existing.filter_subject,
                    &pattern,
                ) {
                    let updated = consumer::Config {
                        filter_subject: String::new(),
                        filter_subjects: filters,
                        ..existing
                    };
                    stream
                        .update_consumer(updated)
                        .await
                        .map_err(|e| refused("add this feed to", &e))?;
                }
            }
            Err(e) if matches!(e.kind(), ConsumerInfoErrorKind::NotFound) => {
                stream
                    .create_consumer(crate::feed::feed_consumer_config(&durable, &pattern))
                    .await
                    .map_err(|e| refused("create", &e))?;
            }
            Err(e) => return Err(refused("read", &e)),
        }

        // A loop that `close()` aborted is not running, whatever the state says.
        if state.as_ref().is_some_and(|running| running.task.is_finished()) {
            *state = None;
        }
        if state.is_none() {
            let pull: consumer::PullConsumer = stream
                .get_consumer(&durable)
                .await
                .map_err(|e| refused("bind", &e))?;
            let handlers: crate::feed::FeedHandlers = Default::default();
            let inner = self.inner.clone();
            let loop_handlers = handlers.clone();
            let handle = tokio::spawn(async move {
                loop {
                    // Rebuilt from the same durable when the pull stream breaks
                    // (a reconnect, a missed heartbeat); the server-side cursor
                    // is what makes that safe.
                    let Ok(mut messages) = pull.messages().await else {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    };
                    while let Some(item) = messages.next().await {
                        let Ok(msg) = item else { break };
                        handle_durable_feed_delivery(&inner, &loop_handlers, msg).await;
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            });
            let task = handle.abort_handle();
            // Tracked like every other background task, so `close()` ends it.
            self.inner.tasks.lock().unwrap().push(handle);
            *state = Some(crate::feed::FeedDurableLoop { handlers, task });
        }

        let id = shared
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let running = state.as_ref().expect("the loop was just ensured");
        running
            .handlers
            .write()
            .unwrap()
            .insert(pattern.clone(), (id, handler));
        drop(state);
        Ok(crate::feed::DurableFeedSubscription { durable, subject: pattern, id, shared })
    }

    /// Subscribe to events **durably** (§18.6 Event Consumer): bind a durable
    /// pull consumer named [`subjects::event_durable`] on the platform's
    /// `MESH_EVENTS` stream, filtered to `mesh.event.{pattern}`, so events
    /// emitted while this agent is away are delivered when it returns.
    ///
    /// This is the same operation the TypeScript SDK spells
    /// `subscribe(pattern, handler, { durable: true, replay })`; this crate
    /// gives the durable path its own method and options struct because the
    /// two paths return different things: a plain subscription has nothing to
    /// stop, this returns a [`DurableSubscription`] whose `stop()` ends
    /// delivery without touching the durable.
    ///
    /// **A missing stream is an error here**, loudly. That is the opposite of the
    /// §16.4 mailbox, whose absence is normal. An agent that asked for durable
    /// delivery and silently got an ephemeral subscription would lose exactly
    /// the events durability exists for, and nobody would know until they were
    /// gone.
    ///
    /// Deliveries run the same §22 pipeline as [`AgentMesh::subscribe`], over
    /// the same separate event memory, with one deliberate difference: the
    /// §22.3 window is the buffered one, because a replayed or caught-up event
    /// can be up to the stream's 24h retention old and the ten-minute live
    /// window would refuse the entire backlog. Each message is acked only
    /// after its handler ran, except undecodable bytes, which will not decode
    /// on redelivery either and are acked without dispatch.
    pub async fn subscribe_durable<F>(
        &self,
        pattern: &str,
        handler: F,
        opts: DurableSubscribeOptions,
    ) -> Result<DurableSubscription>
    where
        F: Fn(Value, Envelope) + Send + Sync + 'static,
    {
        let durable = subjects::event_durable(&self.inner.agent_id, pattern);
        let filter = subjects::event(pattern);
        let js = async_nats::jetstream::new(self.inner.client.clone());
        let stream = js.get_stream(subjects::EVENTS_STREAM).await.map_err(|e| {
            MeshError::Transport(format!(
                "Durable event subscription needs the {} stream (§18.6) and this connection \
                 could not reach it: {e}. Either this mesh has not provisioned {} or this \
                 credential has no JetStream access, sandbox credentials do not. Not falling \
                 back to an ephemeral subscription: that would silently lose the offline \
                 delivery being asked for.",
                subjects::EVENTS_STREAM,
                subjects::EVENTS_STREAM,
            ))
        })?;
        // Bind the EXISTING durable when there is one, resuming its cursor is
        // the whole point, and create it to the §18.6 pins when there is not.
        let consumer = stream
            .get_or_create_consumer(&durable, event_consumer_config(&durable, &filter, opts.replay))
            .await
            .map_err(|e| {
                MeshError::Transport(format!(
                    "Could not bind durable event consumer {durable} on {} (§18.6): {e}",
                    subjects::EVENTS_STREAM
                ))
            })?;

        let inner = self.inner.clone();
        let handler: Arc<dyn Fn(Value, Envelope) + Send + Sync> = Arc::new(handler);
        let pattern = pattern.to_string();
        let handle = tokio::spawn(async move {
            loop {
                // `messages` is the long-lived pull loop (the drain uses
                // `fetch` because it is bounded; this subscription is not).
                // A broken pull stream, a reconnect, a missed heartbeat, is
                // rebuilt from the same durable, whose server-side cursor is
                // exactly what makes that safe.
                let Ok(mut messages) = consumer.messages().await else {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                };
                while let Some(item) = messages.next().await {
                    let Ok(msg) = item else { break };
                    handle_durable_event(&inner, handler.as_ref(), &pattern, msg).await;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
        let stop = handle.abort_handle();
        // Tracked like every other background task, so `close()` ends it.
        self.inner.tasks.lock().unwrap().push(handle);
        Ok(DurableSubscription { durable, stop })
    }

    /// Send a single node-scoped heartbeat (§9.6).
    pub async fn send_heartbeat(&self) -> Result<()> {
        let mut env = Envelope::new(PrimitiveType::Emit, &self.inner.agent_id);
        env.payload = Some(json!({ "node": self.inner.node_id, "availability": "online" }));
        self.inner.sign(&mut env);
        let _ = self
            .inner
            .client
            .publish(subjects::heartbeat(&self.inner.node_id), codec::encode(&env)?.into())
            .await;
        Ok(())
    }

    fn start_heartbeat(&self) {
        let me = self.clone();
        let handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(HEARTBEAT_INTERVAL);
            loop {
                ticker.tick().await;
                if me.send_heartbeat().await.is_err() {
                    break;
                }
            }
        });
        self.inner.tasks.lock().unwrap().push(handle);
    }

    /// Subscribe the inbox, on the private `.guarded` subject when `guarded`
    /// (EXT-6 §7.1) and the public one otherwise.
    ///
    /// **Idempotent.** An agent that is already listening is left where it is: a
    /// second subscription would deliver every message twice, and re-pointing a
    /// healthy agent's only inbox on the strength of a second handshake is the
    /// silent-unreachability failure this whole path exists to avoid. The caller
    /// learns which subject won from [`listening_on_guarded`](Self::listening_on_guarded).
    async fn listen_inbox(&self, guarded: bool) -> Result<()> {
        let subject = {
            let mut state = self.inner.inbox_subject_guarded.lock().unwrap();
            if state.is_some() {
                return Ok(()); // already listening; not re-pointed
            }
            *state = Some(guarded);
            if guarded {
                subjects::agent_inbox_guarded(&self.inner.agent_id)
            } else {
                subjects::agent_inbox(&self.inner.agent_id)
            }
        };
        let mut sub = match self.inner.client.subscribe(subject).await {
            Ok(sub) => sub,
            Err(e) => {
                // The subscription is the fact `inbox_subject_guarded` records,
                // so a failure must not leave it claiming one exists.
                *self.inner.inbox_subject_guarded.lock().unwrap() = None;
                return Err(MeshError::Transport(e.to_string()));
            }
        };
        let inner = self.inner.clone();
        let handle = tokio::spawn(async move {
            while let Some(msg) = sub.next().await {
                // The signature check (§5.3) happens here, and it is a
                // precondition for everything downstream rather than one of the
                // five §22 protections: the §22.2 memory is keyed on `from`, so
                // running those over unverified envelopes would build a
                // forgeable memory rather than a protection.
                let Ok(env) = codec::decode(&msg.payload) else { continue };
                // Correlated replies are delivered INLINE, not spawned: the
                // §6.4a accept and the substantive respond for one request
                // arrive in subscription order only if nothing races them, and
                // a spawned pair can resolve the wait before the accept is
                // seen. Everything else is spawned as before, so one slow
                // handler never blocks the inbox.
                if pending_reply_target(&inner, &env) {
                    deliver_pending_reply(&inner, env, InboundSource::Live);
                    continue;
                }
                let inner = inner.clone();
                // The guarded-delivery fact is the SUBJECT the message arrived
                // on (EXT-6): only the admission relay writes there, and its
                // reply subject is how it forwards the answer onward.
                let guarded_delivery = msg.subject.ends_with(".inbox.guarded");
                let reply = msg.reply.map(|s| s.to_string());
                tokio::spawn(async move {
                    dispatch_inbound(inner, env, reply, InboundSource::Live, guarded_delivery)
                        .await
                });
            }
            // Task end drops `sub`, which unsubscribes the inbox.
        });
        self.inner.tasks.lock().unwrap().push(handle);
        Ok(())
    }

    /// Start the §16.4 mailbox drain loop, once. Spawned rather than awaited so a
    /// mesh without JetStream costs a registration nothing.
    ///
    /// A second `register` on an agent whose loop is already running does NOT start
    /// a second loop — two loops over one durable consumer would each take their
    /// own bound and dispatch from the same cursor. It nudges the running one
    /// instead, which takes a pass immediately.
    fn start_offline_drain(&self) {
        use std::sync::atomic::Ordering::SeqCst;
        if self.inner.offline_drain_started.swap(true, SeqCst) {
            let _ = self.inner.drain_trigger.send(());
            return;
        }
        let inner = self.inner.clone();
        let handle = tokio::spawn(async move { offline_drain(inner).await });
        self.inner.tasks.lock().unwrap().push(handle);
    }

    /// Close this agent. A standalone agent drains the connection; a node-hosted
    /// agent detaches (stops its inbox listener, which unsubscribes) but leaves
    /// the node's shared connection open (§4.1).
    pub async fn close(&self) {
        self.inner.closed.store(true, std::sync::atomic::Ordering::SeqCst);
        // §4.4: the renewal timer never outlives the registration it maintains.
        self.stop_vouch_renewal();
        // §4.8: nor does the credential loop outlive the connection it keeps
        // usable.
        self.stop_credential_renewal();
        for handle in self.inner.tasks.lock().unwrap().drain(..) {
            handle.abort();
        }
        // Aborting the listener unsubscribes, so there is no live subscription
        // left to describe; a re-`register` subscribes afresh. Same for the drain
        // loop, whose durable consumer keeps its cursor server-side.
        //
        // The abort is not synchronous, so a pass may still be suspended in a pull
        // when a re-`register` starts a fresh loop. `drain_in_flight` is what makes
        // that safe, and it is deliberately NOT cleared here: it belongs to the
        // running pass, which releases it when it (or its abort) drops the guard.
        *self.inner.inbox_subject_guarded.lock().unwrap() = None;
        // The feed pull loop was among the aborted tasks. Forget it so a later
        // durable feed subscription starts a fresh one; the consumer itself
        // stays on the server with its cursor.
        *self.inner.feed_durable.state.lock().await = None;
        self.inner
            .offline_drain_started
            .store(false, std::sync::atomic::Ordering::SeqCst);
        if !self.inner.hosted {
            let _ = self.inner.client.drain().await;
        }
    }
}

/// The SDK-local prompt rejection for a queued acknowledgement (§6.4a's
/// buffered path): after the queued ack, the reply channel will never carry
/// anything more — the real reply arrives at this agent's own inbox,
/// correlated by `in_reply_to` (§6.4) — so the wait rejects now rather than
/// running out a timeout on nothing. `details` carry the ack fields plus the
/// request id, which is the correlation handle for that late reply.
fn request_queued_error(ack: &QueuedAck, request_id: &str) -> MeshError {
    let inbox = ack.inbox_id.as_deref().unwrap_or("unknown");
    let mut details = json!({ "queued": true, "request_id": request_id });
    if let Some(inbox_id) = &ack.inbox_id {
        details["inbox_id"] = json!(inbox_id);
    }
    MeshError::Refusal(ErrorObject {
        code: ErrorCode::RequestQueued.as_str().to_string(),
        message: format!(
            "Queued at the recipient (inbox {inbox}): a live session will drain it, and the \
             reply will arrive at this agent's own inbox correlated by in_reply_to (§6.4a) — \
             nothing more arrives on this reply subject"
        ),
        details: Some(details),
        retryable: false,
        retry_after_ms: None,
    })
}

/// The error a `request` times out with — worded by what the wait had learned,
/// because the two silences mean different things to a caller (§6.4a): accept
/// seen means a handler was running and stalled; plain silence from a
/// registered agent is possibly buffered, not failed (§6.4, D.2 #9). (A
/// queued ack never reaches this path: it rejects promptly with
/// `REQUEST_QUEUED`.)
fn request_timeout_error(timeout: Duration, accepted: bool) -> MeshError {
    let secs = timeout.as_secs_f64();
    if accepted {
        return MeshError::code(
            ErrorCode::TransportTimeout,
            format!(
                "Accepted by the responder (§6.4a) but no substantive respond arrived within \
                 the reset {secs}s response timeout"
            ),
        );
    }
    MeshError::code(
        ErrorCode::TransportTimeout,
        format!(
            "No response within {secs}s. Silence from a registered agent is possibly queued, \
             not failed (§6.4): a late reply arrives at this agent's own inbox, correlated \
             by in_reply_to"
        ),
    )
}

// ─── §6.4a reply routing ────────────────────────────────────────────────────

/// One outstanding request wait, registered in [`Inner::pending_replies`]
/// under its request id.
///
/// RAII on purpose: the wait ends by resolving, by timing out, by a queued
/// rejection or by an error, and every one of those must deregister, a stale
/// entry would hold a dead channel that swallows a late reply which the drain
/// path could otherwise at least have observed. Registered BEFORE the request
/// is published, so a respond cannot outrun its own registration.
struct PendingReply {
    inner: Arc<Inner>,
    request_id: String,
    rx: tokio::sync::mpsc::UnboundedReceiver<Envelope>,
}

impl PendingReply {
    fn register(inner: Arc<Inner>, request_id: &str) -> PendingReply {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        inner.pending_replies.lock().unwrap().insert(request_id.to_string(), tx);
        PendingReply { inner, request_id: request_id.to_string(), rx }
    }
}

impl Drop for PendingReply {
    fn drop(&mut self) {
        self.inner.pending_replies.lock().unwrap().remove(&self.request_id);
    }
}

/// What the §6.4a wait does with one verified envelope, given whether the
/// channel it arrived on may carry the answer.
#[derive(Debug)]
enum WaitStep {
    /// Not bound to this request, or substantive data on the liveness-only
    /// transport reply subject, which the requester deliberately does not read.
    Ignore,
    /// The §6.4a accept: reset the response timeout, stay outstanding.
    AcceptSeen,
    /// The node's queued ack (§16.4 attended inbox): reject promptly with the
    /// SDK-local `REQUEST_QUEUED`.
    Queued(QueuedAck),
    /// The substantive respond: the request resolves with this envelope.
    Resolve,
}

/// The judgement [`WaitStep`] names, separated from the I/O so it can be pinned
/// on its own. `substantive_resolves` is false exactly for the transport reply
/// subject of a request, in either mode: the §6.4a signals (the accept and the queued
/// ack) are still honoured there, because they are statements about liveness and
/// delivery (and the queued ack is made by a NODE answering for an absent
/// agent, which has only that subject to answer on), but response DATA on it is
/// ignored: the answer a bare requester trusts is the one that came through its
/// own inbox and its §22 protections.
fn wait_step(env: &Envelope, request_id: &str, substantive_resolves: bool) -> WaitStep {
    // Bound to THIS request (§6.2's reply binding).
    if env.in_reply_to.as_deref() != Some(request_id) {
        return WaitStep::Ignore;
    }
    if is_accept_signal(env) {
        return WaitStep::AcceptSeen;
    }
    if env.error.is_none() {
        if let Some(ack) = queued_ack_of(env.payload.as_ref()) {
            return WaitStep::Queued(ack);
        }
    }
    if substantive_resolves {
        WaitStep::Resolve
    } else {
        WaitStep::Ignore
    }
}

/// Whether an inbound envelope is a reply some request wait on this agent is
/// listening for: a `respond`, or an inbox-mode answer, the fresh `request`
/// with `in_reply_to` an adapter session sends when it works through drained
/// mail, whose `in_reply_to` names a registered wait. Correlation is the
/// request envelope's id in both shapes, which is what keeps them one contract.
fn pending_reply_target(inner: &Arc<Inner>, env: &Envelope) -> bool {
    if env.kind != PrimitiveType::Respond && env.kind != PrimitiveType::Request {
        return false;
    }
    let Some(request_id) = env.in_reply_to.as_deref() else {
        return false;
    };
    inner.pending_replies.lock().unwrap().contains_key(request_id)
}

/// Run one correlated reply through the §22 protections and forward it to the
/// wait it belongs to.
///
/// The same [`inbound::admit_envelope`] the request dispatch runs, over the same
/// `seen_inbox` memory and the same per-path §22.3 window, so a replayed,
/// stale or misaddressed respond cannot resolve a wait, and the copy of a
/// respond the mailbox captured cannot be delivered a second time by the drain
/// after the live path already forwarded it. Delivered INLINE from the inbox
/// loop rather than through a spawned task, because the §6.4a accept and the
/// substantive respond arrive in order only if nothing races them.
fn deliver_pending_reply(inner: &Arc<Inner>, env: Envelope, source: InboundSource) {
    if let Some(refusal) = inbound::admit_envelope(
        &env,
        &inner.agent_id,
        &inner.seen_inbox,
        source,
        inbound::now_ms(),
    ) {
        inner.warn(
            refusal,
            format!("Inbound reply {} refused by {} (§22)", env.id, refusal.code()),
            &env.from,
            &inner.agent_id,
        );
        return;
    }
    let Some(request_id) = env.in_reply_to.as_deref() else { return };
    let tx = inner.pending_replies.lock().unwrap().get(request_id).cloned();
    if let Some(tx) = tx {
        // A wait that ended between the lookup and the send just drops it,
        // which is what would have happened to a late reply anyway.
        let _ = tx.send(env);
    }
}

/// Whether a decoded reply to `mesh.admission.guard` is the service's explicit
/// ok (EXT-6 §7.1) — the one answer that may move an agent off its public inbox.
///
/// Separate from the I/O so the judgement can be read and tested on its own,
/// because every clause is a way the old "guarded on any reply" was wrong:
///
/// - `in_reply_to` must be this request's id (§6.2). Without it, any mesh
///   participant that can publish into this connection's reply inbox answers
///   first with anything at all, and "make that agent unreachable" is one
///   unsigned message.
/// - `to`, when stated, must be us: a reply captured from somebody else's
///   exchange cannot be re-aimed here. Absent is legitimate.
/// - an `error` is a refusal. The platform's shared rate limiter answers over the
///   limit with `RATE_LIMITED`, so a chatty agent used to be refused and then
///   unsubscribe itself from the only inbox anybody was writing to.
/// - `output.ok` must be literally `true`. The benign `{queued: true}` receipt
///   the service gives a *sender* whose message was dropped is not an ok.
/// - `output.guarded: false` is a refusal wearing an ok; absent is fine, because
///   that is what the service actually sends when it agreed.
fn guard_reply_is_ok(resp: &Envelope, request_id: &str, me: &str) -> bool {
    if resp.in_reply_to.as_deref() != Some(request_id) {
        return false;
    }
    if resp.to.as_deref().is_some_and(|to| to != me) {
        return false;
    }
    if resp.error.is_some() {
        return false;
    }
    let out = resp.payload.as_ref().and_then(|p| p.get("output"));
    let ok = out.and_then(|o| o.get("ok")) == Some(&Value::Bool(true));
    let not_denied = out.and_then(|o| o.get("guarded")) != Some(&Value::Bool(false));
    ok && not_denied
}

// ─── §16.4 offline mailbox drain ────────────────────────────────────────────

/// The §22.3 window a drained message is judged under (§22.3, §16.4).
///
/// Named rather than inlined so a test can pin it, because either mistake here is
/// quiet. Passing [`InboundSource::Live`] would refuse an entire mailbox as stale
/// — a buffered envelope is minutes-to-days old by construction — and every
/// message an agent missed would be dropped with only a local warning to say so.
/// Widening the live path to this window instead would make a week-old signed
/// envelope replayable into a live inbox.
const MAILBOX_SOURCE: InboundSource = InboundSource::Mailbox;

/// The mailbox consumer configuration §18.6 pins.
///
/// Every value is the spec's, not a preference: `Explicit` acks because the ack
/// is the §16.4 handoff and this SDK controls when it happens, `All` so the drain
/// starts from the oldest message still held rather than from now (a `New` policy
/// would bind the consumer and skip the very backlog it exists to deliver), and
/// the ack-wait/max-deliver pair from [`MAILBOX_ACK_WAIT`] and
/// [`MAILBOX_MAX_DELIVER`].
fn mailbox_consumer_config(durable: &str) -> async_nats::jetstream::consumer::pull::Config {
    use async_nats::jetstream::consumer::{pull, AckPolicy, DeliverPolicy};
    pull::Config {
        durable_name: Some(durable.to_string()),
        ack_policy: AckPolicy::Explicit,
        deliver_policy: DeliverPolicy::All,
        ack_wait: MAILBOX_ACK_WAIT,
        max_deliver: MAILBOX_MAX_DELIVER,
        ..Default::default()
    }
}

/// The §18.6 Event Consumer configuration, every value the spec's:
/// `Explicit` acks because the ack happens after the handler ran and this SDK
/// decides when; `New` so a fresh durable starts from now, with `All` only when the
/// subscriber asked for replay, because replaying up to 24h of events into an
/// agent that wanted "from now on" is a flood nobody asked for; the
/// [`EVENT_ACK_WAIT`]/[`EVENT_MAX_DELIVER`] pair; and the filter narrowing the
/// shared stream to this subscription's `mesh.event.{pattern}`.
fn event_consumer_config(
    durable: &str,
    filter_subject: &str,
    replay: bool,
) -> async_nats::jetstream::consumer::pull::Config {
    use async_nats::jetstream::consumer::{pull, AckPolicy, DeliverPolicy};
    pull::Config {
        durable_name: Some(durable.to_string()),
        ack_policy: AckPolicy::Explicit,
        deliver_policy: if replay { DeliverPolicy::All } else { DeliverPolicy::New },
        ack_wait: EVENT_ACK_WAIT,
        max_deliver: EVENT_MAX_DELIVER,
        filter_subject: filter_subject.to_string(),
        ..Default::default()
    }
}

/// One delivered durable event: the [`AgentMesh::subscribe`] §22 pipeline, on
/// the buffered §22.3 window, with the JetStream ack LAST.
///
/// The window is [`InboundSource::Mailbox`] for the same reason the drain's is
/// (§22.3): a replayed event, or one that waited out an agent's absence, is
/// old by construction, up to the stream's 24h retention, and the live
/// ten-minute window would refuse the whole backlog with only a local warning
/// to say so. The memory is `seen_events`, the SAME one the live event path
/// writes, scoped to the subscription pattern both paths share, so an event
/// both paths saw is dispatched once — while a second subscription the app
/// deliberately overlapped with this one still gets its own delivery.
///
/// Every exit acks. A handled event is done; an undecodable one will not
/// decode on redelivery either; and a §22-refused one (a duplicate the live
/// path already dispatched, a stale replay) will be refused identically all
/// [`EVENT_MAX_DELIVER`] times, so redelivering it buys five refusals for the
/// price of one. The one ack that waits is the handled case's, which happens
/// after the handler so a crash mid-handling earns a redelivery.
async fn handle_durable_event(
    inner: &Arc<Inner>,
    handler: &(dyn Fn(Value, Envelope) + Send + Sync),
    pattern: &str,
    msg: async_nats::jetstream::Message,
) {
    let Ok(env) = codec::decode(&msg.payload) else {
        let _ = msg.ack().await;
        return;
    };
    if let Some(refusal) = inbound::admit_envelope_scoped(
        &env,
        &inner.agent_id,
        &inner.seen_events,
        Some(pattern),
        InboundSource::Mailbox,
        inbound::now_ms(),
    ) {
        inner.warn(
            refusal,
            format!("Durable event on {} refused: {}", msg.subject, refusal.code()),
            &env.from,
            &msg.subject,
        );
        let _ = msg.ack().await;
        return;
    }
    let data = env
        .payload
        .as_ref()
        .and_then(|p| p.get("data").cloned())
        .unwrap_or(Value::Null);
    let (fence, max_chars) = {
        let opts = inner.inbound.read().unwrap();
        (opts.fence, opts.max_inbound_chars)
    };
    // §22.5 before anything reads the body; recipient-local signal only, like
    // every event refusal, there is no reply path on an event (§22.7).
    if let Some(size) = inbound::over_inbound_cap(&data, max_chars) {
        let subject = &msg.subject;
        inner.warn(
            InboundRefusal::Oversize,
            format!(
                "Durable event on {subject} carries {size} characters of sender text, over \
                 this agent's {max_chars}-character cap (InboundOptions.max_inbound_chars)"
            ),
            &env.from,
            subject,
        );
        let _ = msg.ack().await;
        return;
    }
    // §22.6.
    let data = if fence {
        inbound::fence_inbound_input(
            &data,
            &FrameProvenance {
                from: &env.from,
                trace_id: Some(&env.trace.trace_id),
                ..Default::default()
            },
        )
    } else {
        data
    };
    handler(data, env);
    let _ = msg.ack().await;
}

/// The §22 pipeline for one feed delivery, shared by the live
/// ([`AgentMesh::subscribe_feed`]) and durable
/// ([`AgentMesh::subscribe_feed_durable`]) paths so they cannot drift:
/// §22.2 → §22.4 → §22.3 over the event memory, scoped to the subscription
/// pattern `scope`, on the window `source` picks; the §22.5 cap and §22.6
/// fence over the payload's `data`; refusals to the warning sink (§22.7).
/// Returns the full `{topic, kind, data}` payload with the protected `data`
/// put back in place, or `None` when the delivery was refused.
fn admit_feed_delivery(
    inner: &Inner,
    env: &Envelope,
    delivered_on: &str,
    scope: &str,
    source: InboundSource,
) -> Option<Value> {
    let label = match source {
        InboundSource::Live => "Feed event",
        _ => "Durable feed event",
    };
    if let Some(refusal) = inbound::admit_envelope_scoped(
        env,
        &inner.agent_id,
        &inner.seen_events,
        Some(scope),
        source,
        inbound::now_ms(),
    ) {
        inner.warn(
            refusal,
            format!("{label} on {delivered_on} refused: {}", refusal.code()),
            &env.from,
            delivered_on,
        );
        return None;
    }
    let data = env
        .payload
        .as_ref()
        .and_then(|p| p.get("data").cloned())
        .unwrap_or(Value::Null);
    let (fence, max_chars) = {
        let opts = inner.inbound.read().unwrap();
        (opts.fence, opts.max_inbound_chars)
    };
    // §22.5 before anything reads the body.
    if let Some(size) = inbound::over_inbound_cap(&data, max_chars) {
        inner.warn(
            InboundRefusal::Oversize,
            format!(
                "{label} on {delivered_on} carries {size} characters of sender text, over \
                 this agent's {max_chars}-character cap (InboundOptions.max_inbound_chars)"
            ),
            &env.from,
            delivered_on,
        );
        return None;
    }
    // §22.6.
    let data = if fence {
        inbound::fence_inbound_input(
            &data,
            &FrameProvenance {
                from: &env.from,
                trace_id: Some(&env.trace.trace_id),
                ..Default::default()
            },
        )
    } else {
        data
    };
    // Reassemble the full feed payload around the protected data.
    let mut payload = match &env.payload {
        Some(Value::Object(map)) => Value::Object(map.clone()),
        _ => json!({}),
    };
    if let Value::Object(map) = &mut payload {
        map.insert("data".to_string(), data);
    }
    Some(payload)
}

/// One delivery on the §18.6 Feed Consumer. Undecodable bytes are acked and
/// dropped (they will not decode on redelivery either). A delivery no handler
/// here follows is handed back after [`crate::feed::FEED_UNCLAIMED_NAK`].
/// Otherwise every handler whose pattern matches gets it through
/// [`admit_feed_delivery`] on the buffered window, and the ack comes after
/// they all return; a handler that panics leaves it unacked, so the server
/// redelivers after the ack wait (up to max_deliver).
async fn handle_durable_feed_delivery(
    inner: &Arc<Inner>,
    handlers: &crate::feed::FeedHandlers,
    msg: async_nats::jetstream::Message,
) {
    use async_nats::jetstream::AckKind;
    let Ok(env) = codec::decode(&msg.payload) else {
        let _ = msg.ack().await;
        return;
    };
    let subject = msg.subject.to_string();
    let claimed: Vec<(String, crate::feed::FeedHandler)> = handlers
        .read()
        .unwrap()
        .iter()
        .filter(|(pattern, _)| crate::feed::feed_subject_matches(pattern, &subject))
        .map(|(pattern, (_, h))| (pattern.clone(), h.clone()))
        .collect();
    if claimed.is_empty() {
        // Nobody here follows this feed (yet): hand it back for later.
        let _ = msg.ack_with(AckKind::Nak(Some(crate::feed::FEED_UNCLAIMED_NAK))).await;
        return;
    }
    let mut failed = false;
    for (pattern, handler) in claimed {
        let Some(payload) =
            admit_feed_delivery(inner, &env, &subject, &pattern, InboundSource::Mailbox)
        else {
            continue;
        };
        let env = env.clone();
        let ran = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handler(payload, env)));
        if ran.is_err() {
            failed = true;
        }
    }
    if !failed {
        // After every handler returned: the ack means "durably handled".
        let _ = msg.ack().await;
    }
}

/// What the bounded drain does with one delivered mailbox message, given the
/// bound it took when it bound the consumer.
///
/// A named decision rather than two inline comparisons, because it is the whole
/// fix and each arm is a different mistake if it goes wrong: dispatching past the
/// bound re-opens the race, stopping before it leaves genuinely buffered mail
/// undelivered, and acking the message that stopped the drain would have this
/// path claim one it never handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DrainStep {
    /// Inside the backlog: dispatch it, ack it, keep going.
    Dispatch,
    /// The last message of the backlog: dispatch it, ack it, then stop.
    DispatchAndStop,
    /// Added to the stream after the bind: the live subscription owns it, so
    /// stop without dispatching and without acking.
    Stop,
}

/// Judge one message against the drain's bound.
///
/// `stream_sequence` is the message's position in the STREAM
/// ([`async_nats::jetstream::message::Info::stream_sequence`]), never the
/// consumer's own `consumer_sequence`, which counts deliveries to one consumer
/// and is a different number entirely.
fn drain_step(stream_sequence: u64, bound: u64) -> DrainStep {
    match stream_sequence.cmp(&bound) {
        std::cmp::Ordering::Greater => DrainStep::Stop,
        std::cmp::Ordering::Equal => DrainStep::DispatchAndStop,
        std::cmp::Ordering::Less => DrainStep::Dispatch,
    }
}

/// §16.4 offline delivery, receiving half: bind a durable consumer on this
/// agent's mailbox and run **the backlog it was holding at that moment** through
/// the ordinary inbox dispatch.
///
/// **Why the drain is bounded.** The mailbox stream captures the very subject
/// live messages arrive on, so a drain that keeps consuming competes with the
/// live subscription for every live message. §22.2 dedup then decides which of
/// the two dispatches runs — and the two answer DIFFERENT destinations: the live
/// path answers the requester's transport-minted `_INBOX.` reply subject, this
/// path answers the sender's inbox because a drained requester is assumed to be
/// long gone. So without a bound, the reply destination is a race, and a
/// requester that is still waiting times out while its answer sits in its inbox.
/// The bound is the stream's last sequence when this binds; `register` has
/// already established the live subscription by then, so nothing falls between
/// the two paths, and everything above the bound belongs to the live one.
///
/// **Absence is a no-op, not a failure**, and there are two ways to have no
/// mailbox. The stream may not exist — sandbox agents are given none and older
/// deployments have none at all — and the credential may not reach the JetStream
/// API at all, which is the ordinary case for a guest credential. Neither is an
/// error to report or retry: this agent simply operates live-only, and a
/// registration that failed on either would break startup for the majority of
/// agents on the mesh. A drain that stops partway through for the same reasons is
/// a degraded start, not a dead agent: the live subscription is up regardless.
///
/// **The ack is deliberately last.** It is the node's "durably accepted" signal,
/// and from then on nobody else holds the message — so it happens after a handler
/// has been dispatched, never before. A crash mid-handling therefore redelivers
/// (up to [`MAILBOX_MAX_DELIVER`]) rather than losing the message. The one thing
/// acked *without* being handled is undecodable bytes: they will not decode on
/// the next attempt either, so retrying them is an infinite loop over one
/// message.
///
/// **And the bounded pass REPEATS**, on every reconnect and on
/// [`Inner::mailbox_drain_interval`] otherwise, because a bound on its own trades
/// one bug for a worse one. The pass stops at the bind-time bound, so everything
/// the mailbox captures afterwards stays on the durable consumer undelivered and
/// unacked: the cursor stops where the pass left it and the tail grows for the life
/// of the process, capped only by the stream's 7-day retention. Then the next
/// restart binds, sees the whole tail as backlog, and dispatches it — handlers
/// re-run, answers go to senders' inboxes, and the fresh process's §22.2 memory
/// cannot suppress any of it, because that memory does not survive a restart. The
/// old unbounded drain never had that, because it acked every live copy as it went.
///
/// Re-running the pass keeps the cursor at the head, and does not weaken the bound:
/// every pass reads a fresh `state.last_sequence` and stops there. What the live
/// path already handled in this process is caught by the §22.2 memory and merely
/// acked; what the live subscription MISSED — a reconnect gap, which is exactly
/// what the reconnect trigger is for — is dispatched now instead of at the next
/// restart.
async fn offline_drain(inner: Arc<Inner>) {
    // Subscribed before the first pass, so a reconnect during it is not lost.
    let mut trigger = inner.drain_trigger.subscribe();
    let interval = inner.mailbox_drain_interval;
    loop {
        drain_pass(&inner).await;
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            signal = trigger.recv() => {
                use tokio::sync::broadcast::error::RecvError;
                match signal {
                    // A reconnect, a re-register nudge, or a signal we were too
                    // slow to read — all "look again now".
                    Ok(()) | Err(RecvError::Lagged(_)) => {}
                    // Every sender is gone, so `recv` would return instantly
                    // forever. Fall back to the periodic pass rather than spin.
                    Err(RecvError::Closed) => tokio::time::sleep(interval).await,
                }
            }
        }
    }
}

/// The "one drain pass at a time" claim, released on drop.
///
/// Drop rather than an explicit reset, because `close` aborts the loop task without
/// waiting for it: a flag left raised by an aborted pass would silence every future
/// pass of a re-registered agent, which is a leak shaped exactly like the bug this
/// whole change fixes. Dropping a suspended future runs its destructors, so an
/// aborted pass releases the slot too.
struct DrainSlot<'a>(&'a std::sync::atomic::AtomicBool);

impl<'a> DrainSlot<'a> {
    /// Take the slot, or `None` when a pass is already running.
    fn claim(flag: &'a std::sync::atomic::AtomicBool) -> Option<DrainSlot<'a>> {
        use std::sync::atomic::Ordering::SeqCst;
        flag.compare_exchange(false, true, SeqCst, SeqCst)
            .ok()
            .map(|_| DrainSlot(flag))
    }
}

impl Drop for DrainSlot<'_> {
    fn drop(&mut self) {
        self.0.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

/// One bounded pass, at most one at a time.
///
/// The claim happens before the first `.await`, so two triggers landing together —
/// a reconnect during a re-register, or a new loop started by a re-`register` while
/// `close`'s abort of the old one has not landed yet — produce one pass, not two.
/// Two passes over one durable consumer would each take their own bound and each
/// dispatch from the same cursor. The loser returns immediately; the next tick finds
/// whatever it would have found.
async fn drain_pass(inner: &Arc<Inner>) {
    let Some(_slot) = DrainSlot::claim(&inner.drain_in_flight) else {
        return;
    };
    drain_mailbox_backlog(inner).await;
}

/// ONE pass of [`offline_drain`]: bind, take the bound, deliver everything up to
/// it, then return. Split out so every exit is a plain `return` and the in-flight
/// flag is released in exactly one place ([`drain_pass`]).
async fn drain_mailbox_backlog(inner: &Arc<Inner>) {
    let stream_name = subjects::mailbox_stream(&inner.agent_id);
    let durable = subjects::mailbox_durable(&inner.agent_id);
    let js = async_nats::jetstream::new(inner.client.clone());

    // No mailbox on this mesh, or no JetStream permission on this credential.
    // Both land here, and both are silent.
    let Ok(stream) = js.get_stream(&stream_name).await else {
        return;
    };
    // The bound. `state.last_sequence` is the highest sequence the STREAM has
    // assigned, and `get_stream` already fetched it with the STREAM.INFO request
    // that just proved the mailbox exists — so this is read at bind time and
    // costs no extra round trip.
    let bound = stream.cached_info().state.last_sequence;

    // Bind the EXISTING durable if there is one, and only create it when there is
    // not. A fresh consumer under a different name — or a `New` deliver policy on
    // this one — would replay everything this agent has already handled.
    let Ok(consumer) = stream
        .get_or_create_consumer(&durable, mailbox_consumer_config(&durable))
        .await
    else {
        return;
    };

    // `fetch` rather than `messages`: it is a no-wait pull, so a mailbox with
    // nothing left below the bound ends its batch immediately instead of waiting
    // for a message that is never coming. An empty backlog is therefore a clean
    // stop on the first batch, and a caught-up durable never blocks at all.
    loop {
        let Ok(mut batch) = consumer
            .fetch()
            .max_messages(MAILBOX_DRAIN_BATCH)
            .messages()
            .await
        else {
            return;
        };
        let mut received = 0usize;
        while let Some(item) = batch.next().await {
            // A recoverable item error (a failed pull, a broken heartbeat) is not
            // the end of the mailbox; the next batch re-asks for the same
            // messages, because nothing was acked for them.
            let Ok(msg) = item else { continue };
            received += 1;

            // Without a stream sequence there is no way to tell a buffered
            // message from a live one, and guessing in either direction is the
            // bug this bound exists to close. Stop instead.
            let Ok(seq) = msg.info().map(|i| i.stream_sequence) else {
                return;
            };
            let step = drain_step(seq, bound);
            if step == DrainStep::Stop {
                // Arrived after the bind: the live subscription owns it, so it is
                // neither dispatched nor acked here.
                return;
            }

            let Ok(env) = codec::decode(&msg.payload) else {
                // Undecodable or unverifiable buffered bytes: ack and drop.
                let _ = msg.ack().await;
                if step == DrainStep::DispatchAndStop {
                    return;
                }
                continue;
            };

            // No transport reply subject travels with a buffered message, and
            // none is needed: the dispatcher answers a bare request on the
            // SENDER's inbox whichever path it arrived by (§6.4a), correlated
            // by `in_reply_to`, the same destination for drained and live, so
            // there is no reply-destination race between the two paths. The
            // answer is itself buffered if the sender has meanwhile gone
            // offline too.
            //
            // Awaited, not spawned: the ack must not overtake the dispatch, or a
            // crash mid-handling would have already told the node the message was
            // accepted.
            //
            // A handler slower than MAILBOX_ACK_WAIT therefore earns a redelivery
            // while it is still working, and that copy is caught by the §22.2
            // memory `dispatch_inbound` consults — which is one more reason the
            // memory is written before the freshness judgement rather than after
            // it.
            // `guarded_delivery: false` even when this mailbox captured the
            // guarded subject: no live relay is waiting, and the guard already
            // admitted what reached the stream, see `dispatch_inbound`.
            dispatch_inbound(inner.clone(), env, None, MAILBOX_SOURCE, false).await;
            let _ = msg.ack().await;

            if step == DrainStep::DispatchAndStop {
                // The backlog present at bind time is fully drained.
                return;
            }
        }
        if received == 0 {
            // The pull came back empty: nothing of the bind-time backlog is left,
            // whatever the stream's last sequence said.
            return;
        }
    }
}

/// The EXT-8 §2 allowance judgement for one inbound request — SDK-automatic
/// while an allowance is armed (or fail-closed), and a no-op otherwise. Runs
/// inside the §7.7 admission phase, which puts it BEFORE the §6.4a accept: a
/// refusal here is answered *instead of* an accept, never after one.
///
/// The sequence: price the work (the host's estimator hook, else the default
/// `ceil(sender-text chars / 4)`-token heuristic, converted by the armed cost
/// model's floor arithmetic), judge it against every applicable ceiling
/// (smallest remaining binds), and on exhaustion follow the document's
/// `on_exhausted` — refuse `BUDGET_INSUFFICIENT` with `details.estimate` as
/// the price, or hold the work while the owner channel decides. On the wire
/// the refusal is deliberately indistinguishable from a budget-broke one.
fn allowance_admission(
    inner: &Arc<Inner>,
    env: &Envelope,
    input: &Value,
    ctx: &RequestContext,
    offering: &str,
) -> Option<MeshError> {
    // Fast path, and a lock-ordering guarantee: the estimator hook is host
    // code and must never run under the meter's lock.
    if !inner.allowance.lock().unwrap().enforcing() {
        return None;
    }
    let usage = match inner.cost_estimator.read().unwrap().clone() {
        Some(estimator) => estimator(input, ctx),
        None => Usage::Tokens(estimate_tokens(input)),
    };
    let decision = {
        let meter = inner.allowance.lock().unwrap();
        // In the fail-closed state tokens have no trusted conversion; the
        // estimate is moot there — every ceiling already reads exhausted.
        let estimate_micro = meter.usage_micro(usage).unwrap_or(0);
        meter.check_admission(
            WorkScope { task_id: env.task_id.as_deref(), context_id: env.context_id.as_deref() },
            estimate_micro,
        )
    };
    match decision {
        AllowanceDecision::Unenforced | AllowanceDecision::Admit { .. } => None,
        AllowanceDecision::Exhausted { on_exhausted, binding, estimate } => match on_exhausted {
            OnExhausted::Refuse => Some(allowance_insufficient(estimate)),
            OnExhausted::AskOwner => {
                let ask = inner.owner_channel.read().unwrap().clone();
                let question = AllowanceQuestion {
                    from: env.from.clone(),
                    offering: offering.to_string(),
                    task_id: env.task_id.clone(),
                    context_id: env.context_id.clone(),
                    estimate: estimate.clone(),
                    binding,
                };
                match ask {
                    // The owner raised the ceiling / approved: the work
                    // proceeds, and what it actually burns is metered as usual.
                    Some(decide) if decide(&question) => None,
                    // Declined — or no owner channel exists to approve: the
                    // same refusal shape as `refuse`, per the fixture.
                    _ => Some(allowance_insufficient(estimate)),
                }
            }
        },
    }
}

/// The §19.5 agreement check — SDK-automatic whenever a paid SKU covers the
/// requested offering, run in the same admission slot as the allowance and
/// BEFORE any work. `None` admits; `Some` is the `AGREEMENT_REQUIRED` refusal
/// of admission, answered instead of an accept.
///
/// Free is the default and the fast path: an offering covered by no SKU, or by
/// a `free` one, never reaches a lookup. Only a priced offering pays for the
/// owner resolution, and only once per owner per TTL.
async fn agreement_admission(inner: &Arc<Inner>, env: &Envelope, offering: &str) -> Option<MeshError> {
    let sku = {
        let skus = inner.commerce.skus.lock().unwrap();
        sku_for(skus.as_deref(), offering).cloned()
    };
    let sku = sku?; // §19.1: uncovered is free
    if sku.price.model == SkuPriceModel::Free {
        return None;
    }
    // Warned at registration; a dead-end refusal helps nobody.
    let approval_url = sku
        .provider
        .checkout_url
        .clone()
        .or_else(|| inner.commerce.approval_url.lock().unwrap().clone())?;
    // No digest computed: cannot state what to accept.
    let digest = inner.commerce.digests.lock().unwrap().get(&sku.sku).cloned()?;

    let owner = consumer_owner(inner, &env.from).await;

    // Same owner on both sides is not a sale, and must not be dressed up as
    // one. Without this an operator's own agents refuse each other until the
    // operator has formally accepted their own terms — a signature they give
    // themselves, recording a promise to pay themselves, checked against their
    // own price. Nothing about that ceremony protects anybody: the agreement
    // exists so a stranger cannot be charged a price they never saw, and there
    // is no stranger here.
    //
    // Resolved through the SAME lookup as the consumer rather than from a
    // field captured at registration, for two reasons: the registry rewrites
    // `owner` server-side (§8.3), so a locally-remembered value can be wrong;
    // and using one resolution path means the two sides cannot disagree about
    // what an owner IS. Cached per owner per TTL like any other, and only ever
    // reached on the priced path.
    if let Some(owner) = owner.as_deref() {
        if consumer_owner(inner, &inner.agent_id).await.as_deref() == Some(owner) {
            return None;
        }
    }

    let mut covered = false;
    if let Some(owner) = owner.as_deref() {
        let want = AgreementWant {
            consumer_owner: owner,
            seller_agent: &inner.agent_id,
            sku: &sku.sku,
            sku_digest: &digest,
            now_ms: None,
        };
        // The armed set first; the platform lookup only when what we hold
        // does not answer.
        covered = inner
            .commerce
            .agreements
            .lock()
            .unwrap()
            .get(owner)
            .is_some_and(|held| held.iter().any(|d| agreement_covers(d, &want)));
        if !covered {
            // Reaching here means what we hold does NOT answer the question,
            // so ASK — every time, with no cache in front of it. Two attempts
            // at one went wrong live on 2026-08-02: caching the MISS made
            // "approve, then send again" keep refusing, and caching the HIT
            // kept serving an acceptance of the OLD terms after a re-price.
            // Both read as broken rather than as caching, and both were
            // suppressing exactly the call that would have fixed them — the
            // tell that the cache never belonged on this path. The lookup is
            // one KV read, on a path that does no work, already bounded by
            // the inbound rate limiter.
            let hook = inner.commerce.lookup.read().unwrap().clone();
            let fetched = match hook {
                Some(hook) => hook(owner),
                None => lookup_agreements_on_mesh(inner, owner).await,
            };
            match fetched {
                Ok(list) => {
                    let mut verified: Vec<AgreementDocument> = Vec::new();
                    for raw in &list {
                        // An unverifiable agreement authorises nothing.
                        if let Ok(doc) = crate::agreement::load_agreement(raw) {
                            if doc.seller_agent == inner.agent_id {
                                verified.push(doc);
                            }
                        }
                    }
                    covered = verified.iter().any(|d| agreement_covers(d, &want));
                    // Replace rather than merge: the platform's answer is the
                    // whole truth for this (owner, seller) pair, so a revoked
                    // agreement disappears here instead of lingering.
                    inner.commerce.agreements.lock().unwrap().insert(owner.to_string(), verified);
                }
                // A platform outage refuses paid work, never gives it away.
                Err(_) => covered = false,
            }
        }
    }
    if covered {
        return None;
    }
    Some(agreement_required(
        AgreementRequiredDetails { sku: sku.sku, sku_digest: digest, approval_url },
        None,
    ))
}

/// The owner key that groups an agent's account (§8.6), cached per
/// [`AGREEMENT_TTL_MS`]. `None` when the agent is unregistered or the registry
/// cannot be reached — in which case no agreement can be matched, and paid
/// work is refused.
async fn consumer_owner(inner: &Arc<Inner>, agent_id: &str) -> Option<String> {
    let now = inbound::now_ms();
    if let Some((at, owner)) = inner.commerce.owner_of.lock().unwrap().get(agent_id) {
        if now - at < AGREEMENT_TTL_MS {
            return owner.clone();
        }
    }
    let owner = fetch_manifest_owner(inner, agent_id).await;
    inner.commerce.owner_of.lock().unwrap().insert(agent_id.to_string(), (now, owner.clone()));
    owner
}

/// One registry `get` (§9.2), read for its `owner` field alone.
async fn fetch_manifest_owner(inner: &Arc<Inner>, agent_id: &str) -> Option<String> {
    let mut env = Envelope::new(PrimitiveType::Discover, &inner.agent_id);
    env.payload = Some(json!({ "agent_id": agent_id }));
    inner.sign(&mut env);
    let bytes = codec::encode(&env).ok()?;
    let resp = tokio::time::timeout(
        DEFAULT_REQUEST_TIMEOUT,
        inner.client.request(subjects::registry_get(agent_id), bytes.into()),
    )
    .await
    .ok()?
    .ok()?;
    let resp_env = codec::decode(&resp.payload).ok()?;
    if resp_env.error.is_some() {
        return None;
    }
    resp_env.payload.as_ref()?.get("owner").and_then(Value::as_str).map(str::to_string)
}

/// Ask the registry whether `key` is a revoked agent key, or a paused agent
/// (§5.3, §4.12). A registry `get` answers a revoked key with `UNAUTHORIZED`,
/// `details.reason: agent_key_revoked`, and a paused agent with its manifest
/// carrying `status: "paused"`; any other answer, a manifest or not-found
/// included, means not revoked. Anything that is not a signed answer from the
/// registry to this question is `Unknown`, which the memo treats as "let it
/// through". The memo applies its own timeout.
async fn registry_revocation(inner: Arc<Inner>, key: String) -> RevocationAnswer {
    let mut env = Envelope::new(PrimitiveType::Discover, &inner.agent_id);
    env.payload = Some(json!({ "agent_id": key }));
    inner.sign(&mut env);
    let Ok(bytes) = codec::encode(&env) else {
        return RevocationAnswer::Unknown;
    };
    let Ok(resp) = inner.client.request(subjects::registry_get(&key), bytes.into()).await else {
        return RevocationAnswer::Unknown;
    };
    let Ok(resp_env) = codec::decode(&resp.payload) else {
        return RevocationAnswer::Unknown;
    };
    // Bound to this question: an answer to some other request is no answer.
    if resp_env.in_reply_to.as_deref().is_some_and(|id| id != env.id) {
        return RevocationAnswer::Unknown;
    }
    if let Some(err) = &resp_env.error {
        let details = err.details.as_ref();
        let reason = details.and_then(|d| d.get("reason")).and_then(Value::as_str);
        if err.code == ErrorCode::Unauthorized.as_str() && reason == Some("agent_key_revoked") {
            let text = |k: &str| details.and_then(|d| d.get(k)).and_then(Value::as_str).map(str::to_string);
            return RevocationAnswer::Revoked {
                revoked_at: text("revoked_at"),
                replaced_by: text("replaced_by"),
            };
        }
        return RevocationAnswer::NotRevoked { paused: false, since: None };
    }
    // The kill switch (§9 registry status): a paused agent's manifest says
    // so, and a receiver refuses what it sends until it is resumed.
    let payload = resp_env.payload.as_ref();
    if payload.and_then(|p| p.get("status")).and_then(Value::as_str) == Some("paused") {
        let since = payload
            .and_then(|p| p.get("status_since"))
            .and_then(Value::as_str)
            .map(str::to_string);
        return RevocationAnswer::NotRevoked { paused: true, since };
    }
    RevocationAnswer::NotRevoked { paused: false, since: None }
}

/// The platform's agreement record for one consumer account, filtered to THIS
/// seller by the service (§19.5). The default lookup: a deployment that runs
/// the platform gets enforcement with nothing to wire, and one that does not
/// supplies its own through [`AgentMesh::on_agreement_lookup`].
///
/// A refusal or a timeout here is NOT "no agreements" by accident — it is an
/// `Err`, and the caller treats an `Err` as uncovered, so an outage refuses
/// paid work rather than giving it away.
async fn lookup_agreements_on_mesh(inner: &Arc<Inner>, consumer_owner: &str) -> Result<Vec<Value>> {
    let mut env = Envelope::new(PrimitiveType::Request, &inner.agent_id);
    env.payload = Some(json!({ "consumer_owner": consumer_owner }));
    inner.sign(&mut env);
    let resp = tokio::time::timeout(
        DEFAULT_REQUEST_TIMEOUT,
        inner.client.request(AGREEMENT_LOOKUP_SUBJECT, codec::encode(&env)?.into()),
    )
    .await
    .map_err(|_| MeshError::Transport("agreement lookup timed out (§19.5)".into()))?
    .map_err(|e| MeshError::Transport(e.to_string()))?;
    let resp_env = codec::decode(&resp.payload)?;
    if let Some(err) = &resp_env.error {
        return Err(MeshError::from_error_object(err));
    }
    Ok(resp_env
        .payload
        .as_ref()
        .and_then(|p| p.get("agreements"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default())
}

/// Where a respond to one inbound request is published (§6.4a).
///
/// The rule is one line: an answer goes to the SENDER's inbox, whatever path
/// the request arrived by, whichever mode it asked for (the bare answer and
/// the §11.3 step-2 opening alike, per §11.3 and the Appendix C diagrams), and
/// whether or not a transport reply subject came with it. The collapse is
/// deliberate: the live path and the §16.4 drain used to answer DIFFERENT
/// destinations, which made the reply destination a race whenever both paths
/// saw a message, and it is what lets the requester run every reply through
/// its own inbox and the §22 protections there, instead of trusting whatever
/// lands on an unprotected `_INBOX.` subscription.
///
/// Exactly two exceptions keep the transport reply subject, and both are
/// `None` when none was carried:
/// - [`REGISTRY_PROBE_OFFERING`], the reaper's liveness probe, whose cheap
///   same-subject answer is the point;
/// - a request DELIVERED on the guarded subject (`.inbox.guarded`, EXT-6):
///   the requester of record there is the admission guard relay, a platform
///   service with no inbox of its own that forwards the reply data to the true
///   sender itself, answering the sender's inbox directly would route the
///   reply around the guard's forwarding role. The distinguishing fact is the
///   DELIVERY SUBJECT, never anything in the payload: a sender cannot claim
///   the guarded shape, only arrive by it.
fn respond_destination(
    offering: &str,
    guarded_delivery: bool,
    sender: &str,
    transport_reply: Option<&str>,
) -> Option<String> {
    if guarded_delivery || offering == REGISTRY_PROBE_OFFERING {
        return transport_reply.map(str::to_string);
    }
    Some(subjects::agent_inbox(sender))
}

/// Answer a request from a revoked or paused sender (§5.3) with
/// `UNAUTHORIZED`, and raise the local signal. The handler never runs.
async fn refuse_revoked_sender(
    inner: &Arc<Inner>,
    env: &Envelope,
    respond_to: Option<&str>,
    r: &crate::revoked_senders::RevokedSender,
) {
    let (error, code, warning) = if r.paused {
        // The kill switch (§4.12): a paused sender's node may still be able
        // to publish, so the receiver refusing is what makes the pause hold.
        let mut details = json!({ "reason": "agent_paused" });
        if let Some(since) = &r.since {
            details["stopped_at"] = json!(since);
        }
        (
            ErrorObject {
                code: ErrorCode::Unauthorized.as_str().to_string(),
                message: "The agent that sent this is paused by its owner or by AgentMesh, so its \
                          messages are refused until it is resumed (§5.3)."
                    .to_string(),
                details: Some(details),
                retryable: false,
                retry_after_ms: None,
            },
            "stopped_sender",
            "refused a request from an agent that is paused by the kill switch".to_string(),
        )
    } else {
        let mut details = json!({ "reason": "agent_key_revoked" });
        if let Some(at) = &r.revoked_at {
            details["revoked_at"] = json!(at);
        }
        if let Some(to) = &r.replaced_by {
            details["replaced_by"] = json!(to);
        }
        let moved = r
            .replaced_by
            .as_ref()
            .map(|to| format!("; the agent moved to {to}"))
            .unwrap_or_default();
        (
            ErrorObject {
                code: ErrorCode::Unauthorized.as_str().to_string(),
                message: "The key that signed this message has been revoked, so it is refused (§5.3)."
                    .to_string(),
                details: Some(details),
                retryable: false,
                retry_after_ms: None,
            },
            "revoked_sender",
            format!("refused a request signed by a revoked key{moved}"),
        )
    };
    if let Some(reply) = respond_to {
        let resp = inner.refusal_resp(env, error);
        if let Ok(bytes) = codec::encode(&resp) {
            let _ = inner.client.publish(reply.to_string(), bytes.clone().into()).await;
            // Tap: the refusal is observable to the operator surfaces, like
            // every other response this agent makes.
            let _ = inner
                .client
                .publish(subjects::agent_outbox(&inner.agent_id), bytes.into())
                .await;
        }
    }
    let sink = inner.inbound.read().unwrap().on_security_warning.clone();
    if let Some(sink) = sink {
        sink(SecurityWarning {
            code: code.to_string(),
            message: warning,
            subject: Some(inner.agent_id.clone()),
            from: Some(env.from.clone()),
        });
    }
}

/// Dispatch one verified inbound `request`, whatever path it arrived on.
///
/// **One function for both paths on purpose.** §22.1 is blunt about it: "a
/// protection present on one path and absent on another is worse than absent".
/// The live subscription and the §16.4 mailbox drain differ in exactly two
/// respects, and both are parameters here rather than branches inside:
///
/// - `source` selects the §22.3 `max_age` bound — ten minutes live, seven days
///   for a buffered message that is old by construction. Everything else about
///   admission, including the duplicate memory, is identical and SHARED, so the
///   copy the mailbox captured cannot slip past a rejection the live path just
///   made (`inner.seen_inbox` is the same memory for both).
/// - `reply` is the transport reply subject the message travelled with, when it
///   travelled with one. It is NOT where an answer goes, that is the sender's
///   own inbox on every path and in every mode (§6.4a, §11.3), decided by
///   [`respond_destination`], it is what the two exceptions answer on: the
///   registry probe, and a guarded delivery's relay.
async fn dispatch_inbound(
    inner: Arc<Inner>,
    env: Envelope,
    reply: Option<String>,
    source: InboundSource,
    // Whether the message was DELIVERED on the `.inbox.guarded` subject
    // (EXT-6), read off the subscription's subject, never the payload. Always
    // false for the drain: a guarded agent's mailbox stream captures the
    // guarded subject, but a drained message has no live relay waiting on a
    // reply subject, and the guard already admitted whatever reached the
    // stream, so a drained answer goes to the sender's inbox like any other.
    guarded_delivery: bool,
) {
    // ── §6.4a replies ──
    // A respond addressed to a wait this agent has outstanding, or an
    // inbox-mode answer wearing a fresh request, resolves that wait instead of
    // being dispatched. The live loop usually catches these first (inline, to
    // keep signal order); this is the same judgement for the §16.4 drain, where
    // a reply that was buffered while this agent's requester side was waiting
    // still finds its wait.
    if pending_reply_target(&inner, &env) {
        deliver_pending_reply(&inner, env, source);
        return;
    }
    if env.kind != PrimitiveType::Request {
        // A respond nobody is waiting for (a late reply into a restarted
        // process, or one the app will correlate itself from its own records)
        // is dropped here exactly as it always was.
        return;
    }

    // ── §22.2 → §22.4 → §22.3 ──
    // Silent to the sender, all three (§22.7): the party who would receive the
    // answer is not the party who made the mistake. A duplicate is normal
    // transport behaviour and the first copy was already answered; a stale or
    // misaddressed envelope was, if anything, replayed, and an error envelope
    // would tell a replayer which of its held copies are still inside the window
    // and would put this agent's signature on a reply to a message it was never
    // sent. Local signal only.
    if let Some(refusal) = inbound::admit_envelope(
        &env,
        &inner.agent_id,
        &inner.seen_inbox,
        source,
        inbound::now_ms(),
    ) {
        let path = match source {
            InboundSource::Live => "Inbound",
            InboundSource::Mailbox => "Mailbox-drained",
        };
        inner.warn(
            refusal,
            format!("{path} request {} refused by {} (§22)", env.id, refusal.code()),
            &env.from,
            &inner.agent_id,
        );
        return;
    }

    let payload = env.payload.clone().unwrap_or(Value::Null);
    // Deprecation window (§8.5): senders on pre-rename SDKs say `skill`.
    // Normalized once here; everything this SDK emits uses only the new name.
    let offering = payload
        .get("offering")
        .or_else(|| payload.get("skill"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let mut input = payload.get("input").cloned().unwrap_or(Value::Null);
    let config = payload.get("config");
    let is_stream = config.and_then(|c| c.get("stream")).and_then(|v| v.as_bool()).unwrap_or(false);
    let sign_chunks = config.and_then(|c| c.get("sign_chunks")).and_then(|v| v.as_bool()).unwrap_or(false);

    // ── §6.4a where answers go ──
    // One destination for every respond this dispatch makes, the accept, a
    // refusal, the terminal answer, decided once, before the first thing that
    // could answer. See [`respond_destination`].
    let respond_to =
        respond_destination(&offering, guarded_delivery, &env.from, reply.as_deref());

    let (fence, max_chars, refuse_revoked) = {
        let opts = inner.inbound.read().unwrap();
        (opts.fence, opts.max_inbound_chars, opts.refuse_revoked_senders)
    };

    // ── §5.3 revoked or paused sender ──
    // "Receivers MUST refuse a message signed by a revoked agent key." The
    // signature (checked at decode) proves which key signed; this asks
    // whether that key is still its owner's. After the cheap §22 checks, so a
    // malformed or replayed envelope costs no registry question, and before
    // anything is handled or answered as though the sender were who it says.
    if refuse_revoked {
        let lookup_inner = inner.clone();
        let refused = inner
            .revoked_senders
            .check(&env.from, move |key| registry_revocation(lookup_inner, key))
            .await;
        if let Some(r) = refused {
            refuse_revoked_sender(&inner, &env, respond_to.as_deref(), &r).await;
            return;
        }
    }

    // §7.7 scope: a request arriving WITH a task id and a budget is work whose
    // Task inherits that budget — record it (latest-wins) so revisions have a
    // baseline and `task_budget` answers for the responder side too. A
    // malformed budget block is not recorded; it still reaches the handler
    // verbatim via the context, whose admission judgement it is.
    if let (Some(task_id), Some(budget)) = (env.task_id.as_deref(), env.budget.as_ref()) {
        if budget.validate().is_ok() {
            inner.task_budgets.apply(task_id, budget);
        }
    }

    // ── §22.5 inbound size cap ──
    // Before the handler is resolved and before the stream branch, because
    // `payload.config.stream` selects a different handler and never a different
    // set of protections (§22.1). The local signal is raised whether or not
    // there is a respond destination (§22.7 MUST); the error envelope goes out
    // only where one exists, which for a bare request is always, now that the
    // destination is the sender's inbox.
    if let Some(size) = inbound::over_inbound_cap(&input, max_chars) {
        let message = format!(
            "Inbound message carries {size} characters of sender text, over this agent's \
             {max_chars}-character cap (InboundOptions.max_inbound_chars)"
        );
        inner.warn(InboundRefusal::Oversize, message.clone(), &env.from, &inner.agent_id);
        if let Some(reply) = respond_to.as_ref() {
            let resp = inner.error_resp(&env, ErrorCode::ContextTooLarge, message);
            if let Ok(bytes) = codec::encode(&resp) {
                let _ = inner.client.publish(reply.clone(), bytes.clone().into()).await;
                // Tap: the refusal is observable to the operator surfaces, like
                // every other response this agent makes.
                let _ = inner
                    .client
                    .publish(subjects::agent_outbox(&inner.agent_id), bytes.into())
                    .await;
            }
        }
        return;
    }

    // ── §8.9 open the box ──
    // After the size cap, which is a DoS measure and belongs on the bytes that
    // actually arrived; before everything else, so the cancel parser, the
    // admission hooks, the fence and the handler all see one shape and no part
    // of the pipeline has to know about ciphertext.
    //
    // Only when this agent holds an encryption seed AND the box opens. A seed
    // we do not have, or a box that is not ours, leaves the payload exactly as
    // it arrived: an embedder that opens sealed payloads in its own handler
    // keeps working unchanged.
    let mut sealed_in = false;
    let mut claimed_reply_key: Option<String> = None;
    if let Some(seed) = inner.encryption_seed.as_deref() {
        if let Some(opened) = crate::sealed::open_sealed_value(&input, seed) {
            input = opened.payload;
            sealed_in = true;
            claimed_reply_key = opened.reply_key;
        }
    }

    // ── §10.8 task.cancel interception ──
    // After the size cap (a note is sender text and falls under §22.5) and
    // BEFORE fencing, which would rewrite the input and mangle the exact
    // reason bytes the closed enum is judged on. Inside dispatch_inbound so
    // it runs identically on the live path and the §16.4 mailbox drain
    // (§22.1: a protection present on one path and absent on another is
    // worse than absent); §22.2 above already dropped a duplicate cancel.
    if offering == CANCEL_OFFERING {
        handle_task_cancel(inner, env, respond_to, &input).await;
        return;
    }

    // ── §8.9 `required`: this inbox does not read cleartext ──
    // A refusal of admission, so it lands here: after the §22 checks, before
    // the accept, and after the cancel interception on purpose. A cancel is a
    // protocol operation carrying a task id and a closed-enum reason, not the
    // caller's material, and an agent that stopped honouring cancels because
    // they were not encrypted would be protecting nothing at the cost of the
    // one message that ends work already running.
    if !sealed_in
        && inner.sealing.lock().unwrap().as_deref() == Some(crate::sealing::SEALING_REQUIRED)
    {
        if let Some(reply) = respond_to.as_ref() {
            let resp = inner.error_resp(
                &env,
                ErrorCode::SealingRequired,
                "This agent declares sealing: \"required\" (§8.9) and this request arrived in \
                 the clear, so its content was not read. Resolve this agent's manifest, seal to \
                 the encryption_key its §8.3 claim covers, and send again."
                    .to_string(),
            );
            if let Ok(bytes) = codec::encode(&resp) {
                let _ = inner.client.publish(reply.clone(), bytes.clone().into()).await;
                let _ = inner
                    .client
                    .publish(subjects::agent_outbox(&inner.agent_id), bytes.into())
                    .await;
            }
        }
        return;
    }

    // ── §7.7 budget admission ──
    // The last gate whose refusal is a refusal of ADMISSION: everything from
    // here on is the work's own outcome. §6.4a's ordering rule is exactly
    // this line — a refusal here is answered INSTEAD of an accept, never
    // after one.
    //
    // Three judgements. First the SDK's own deterministic one: an offered
    // deadline already past (under the §22.3 skew tolerance) cannot be met by
    // any handler, so no hook is needed to refuse it. Then the EXT-8
    // allowance — SDK-automatic whenever one is armed, since the owner's
    // policy is the node's to enforce, not the handler's to remember. Last
    // the offering's registered admission judgement (`on_admission`), which is
    // where budget-side refuse-with-estimate lives — it holds the estimate,
    // the SDK does not.
    let ctx = RequestContext {
        from: env.from.clone(),
        request_id: env.id.clone(),
        task_id: env.task_id.clone(),
        trace: env.trace.clone(),
        budget: env.budget.clone(),
    };
    let mut admission_refusal: Option<MeshError> = {
        let deadline_past = env
            .budget
            .as_ref()
            .is_some_and(|b| b.validate().is_ok() && b.past_deadline(inbound::now_ms()));
        if deadline_past {
            let deadline = env
                .budget
                .as_ref()
                .and_then(|b| b.deadline.clone())
                .unwrap_or_default();
            Some(crate::budget::deadline_unmeetable(
                None,
                format!("Budget deadline {deadline} had already passed at admission (§7.7)"),
            ))
        } else {
            allowance_admission(&inner, &env, &input, &ctx, &offering)
        }
    };
    // 1b. The §19.5 agreement — has this consumer's ACCOUNT accepted the
    //     terms of the paid SKU covering this offering? Free offerings never
    //     reach it, and its refusal is a refusal of admission like the rest.
    if admission_refusal.is_none() {
        admission_refusal = agreement_admission(&inner, &env, &offering).await;
    }
    if admission_refusal.is_none() {
        let admit = inner.admissions.read().unwrap().get(&offering).cloned();
        if let Some(admit) = admit {
            admission_refusal = admit(&input, &ctx).err();
        }
    }
    if let Some(refusal) = admission_refusal {
        if let Some(reply) = respond_to.clone() {
            let resp = match refusal {
                // The §7.7 refusals travel with their estimate intact.
                MeshError::Refusal(eo) => inner.refusal_resp(&env, eo),
                other => inner.error_resp(&env, ErrorCode::Internal, other.to_string()),
            };
            if let Ok(bytes) = codec::encode(&resp) {
                let _ = inner.client.publish(reply, bytes.clone().into()).await;
                // Tap: refusals are observable like every other respond.
                let _ = inner
                    .client
                    .publish(subjects::agent_outbox(&inner.agent_id), bytes.into())
                    .await;
            }
        }
        return;
    }

    // ── §6.4a the accept signal ──
    // Admission is complete: the §22 checks and §7.7 admission passed, and a
    // live handler is about to run. Emitted BEFORE the handler is even
    // resolved — which is why OFFERING_NOT_FOUND / INPUT_INVALID discovered at
    // dispatch legally FOLLOW an accept: they are failures of the work, not
    // refusals of admission.
    //
    // Live path only. A §16.4 mailbox-drained request has no wait left to
    // un-blind: its requester was told promptly (REQUEST_QUEUED) or timed out
    // long ago, and §6.4's offline-targets rule already told it to expect the
    // late reply at its own inbox, the only thing an accept would add is a
    // non-substantive envelope in that inbox with nothing correlating it. The
    // node-held-inbox path (§16.4 attended sessions) answers the queued ack
    // instead and never reaches this dispatcher at all.
    //
    // And never for an agent registered `interaction: "interactive"` (§8.3a):
    // attended means a person is in the loop, so "a handler will run now" is
    // not a promise this dispatcher can make — §6.4a's MUST NOT for the
    // attended case covers an SDK-hosted interactive agent as much as a
    // node-held inbox.
    let attended = inner.interaction.lock().unwrap().as_deref() == Some("interactive");
    if source == InboundSource::Live && !attended {
        if let Some(reply) = respond_to.as_deref() {
            let mut acc = accept_envelope(&inner.agent_id, &env);
            inner.sign(&mut acc);
            if let Ok(bytes) = codec::encode(&acc) {
                let _ = inner.client.publish(reply.to_string(), bytes.clone().into()).await;
                // Tap: the accept is a respond this agent made; operator
                // surfaces see it like any other.
                let _ = inner
                    .client
                    .publish(subjects::agent_outbox(&inner.agent_id), bytes.into())
                    .await;
            }
        }
    }

    // ── §22.6 sender-text fencing ──
    // Untrusted text, framed and fenced before any handler sees it, unless the
    // host opted out because it frames inbound text itself. The ENVELOPE is left
    // verbatim: `codec::decode` must still verify it, and a handler that wants
    // the raw text can read it there.
    let input = if fence {
        inbound::fence_inbound_input(
            &input,
            &FrameProvenance {
                from: &env.from,
                trace_id: Some(&env.trace.trace_id),
                ..Default::default()
            },
        )
    } else {
        input
    };

    // Bare and stream mode always have a destination (the sender's inbox); the
    // two reply-subject exceptions (registry probe, guarded delivery) have one
    // only when a transport reply subject was carried, so this is the point a
    // probe without one goes quiet. The transport reply subject is kept
    // alongside for the §6.4a queued-ack carve-out below, which is decided by
    // the handler's RESULT and so cannot be part of respond_destination's
    // up-front call.
    let transport_reply = reply.clone();
    let Some(reply) = respond_to else { return };

    // ── Streaming request (§11.3) ──
    if is_stream {
        let handler = inner.stream_handlers.read().unwrap().get(&offering).cloned();
        let Some(h) = handler else {
            let resp = inner.error_resp(&env, ErrorCode::OfferingNotFound, format!("No stream handler for offering '{offering}'"));
            if let Ok(b) = codec::encode(&resp) {
                let _ = inner.client.publish(reply, b.into()).await;
            }
            return;
        };
        // Step 1: signed "working" opening to the requester's inbox, like
        // every other respond (§11.3 step 2). It authenticates the responder
        // for the whole stream (§11.6); the chunks that follow are
        // subject-addressed on the task's stream subject.
        let task_id = env.task_id.clone().unwrap_or_else(crate::util::uuid7);
        let mut opening = Envelope::new(PrimitiveType::Respond, &inner.agent_id);
        opening.to = Some(env.from.clone());
        opening.in_reply_to = Some(env.id.clone());
        opening.task_id = Some(task_id.clone());
        opening.trace = child_span(&env.trace);
        opening.payload = Some(json!({ "status": "working" }));
        inner.sign(&mut opening);
        if let Ok(b) = codec::encode(&opening) {
            let _ = inner.client.publish(reply, b.clone().into()).await;
            // Tap: a copy of the opening respond for activity observation.
            let _ = inner.client.publish(subjects::agent_outbox(&inner.agent_id), b.into()).await;
        }
        // Step 2: run the handler with a writer; auto-end / fail on error.
        // The writer clone the handler gets shares this one's counter + closed
        // flag (atomics), so `is_closed()`/`chunk_count` stay correct here.
        let writer = StreamWriter {
            client: inner.client.clone(),
            agent_id: inner.agent_id.clone(),
            agent_seed: inner.agent_seed.clone(),
            requester: env.from.clone(),
            request_id: env.id.clone(),
            task_id,
            trace: env.trace.clone(),
            sign_chunks,
            chunk_index: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            closed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        let ctx = RequestContext {
            from: env.from.clone(),
            request_id: env.id.clone(),
            task_id: env.task_id.clone(),
            trace: env.trace.clone(),
            budget: env.budget.clone(),
        };
        // §10.8: the dispatch context is ambient while the handler runs, so
        // sub-requests it issues are recorded as delegations of this task.
        // CURRENT_DISPATCH outside, CURRENT_TRACE inside — same nesting as
        // the bare path below.
        let dispatch = crate::util::DispatchContext {
            task_id: writer.task_id().to_string(),
            context_id: env.context_id.clone(),
            offering: offering.clone(),
        };
        match crate::util::CURRENT_DISPATCH
            .scope(
                dispatch,
                crate::util::CURRENT_TRACE.scope(env.trace.clone(), h(input, writer.clone(), ctx)),
            )
            .await
        {
            Ok(()) => {
                if !writer.is_closed() {
                    let _ = writer.end(None).await;
                }
            }
            Err(e) => {
                if !writer.is_closed() {
                    let _ = writer.fail(e.to_string()).await;
                }
            }
        }
        return;
    }

    // ── Bare request/respond ──
    let handler = inner.handlers.read().unwrap().get(&offering).cloned();
    let ctx = RequestContext {
        from: env.from.clone(),
        request_id: env.id.clone(),
        task_id: env.task_id.clone(),
        trace: env.trace.clone(),
        budget: env.budget.clone(),
    };
    let resp = match handler {
        None => inner.error_resp(&env, ErrorCode::OfferingNotFound, format!("No handler registered for offering '{offering}'")),
        // §13.1: the inbound trace is ambient while the handler runs, so any
        // request/emit the handler makes joins the same trace automatically.
        // §10.8: so is the dispatch context (the task being handled + the
        // offering), which is how a sub-request the handler issues gets recorded
        // as a delegation. The dispatch task id is the inbound `task_id` when
        // present, else fresh — the same rule RequestContext/streams use.
        // CURRENT_DISPATCH outside, CURRENT_TRACE inside, as in the stream
        // path above.
        Some(h) => {
            let dispatch_task_id = env.task_id.clone().unwrap_or_else(crate::util::uuid7);
            let dispatch = crate::util::DispatchContext {
                task_id: dispatch_task_id.clone(),
                context_id: env.context_id.clone(),
                offering: offering.clone(),
            };
            // The consumer half of the hop (§13.1.1), parented under the
            // sender's span by carrying the inbound envelope's own trace.
            // Timed around the handler, which is the part this agent is
            // answerable for.
            let span_start = chrono::Utc::now().timestamp_millis();
            let span_of = |outcome, error_code| crate::spans::SpanInput {
                trace: env.trace.clone(),
                kind: crate::spans::SpanKind::Consumer,
                agent_id: inner.agent_id.clone(),
                operation: "request",
                peer: Some(env.from.clone()),
                offering: Some(offering.clone()),
                task_id: Some(dispatch_task_id.clone()),
                context_id: env.context_id.clone(),
                outcome,
                error_code,
                started_at: span_start,
                ended_at: chrono::Utc::now().timestamp_millis(),
            };

            // §7.0 deferral: with a threshold configured for this offering,
            // a LIVE dispatch races the handler against it. Drained requests
            // never defer -- there is no live wait to release, and the late
            // terminal respond already reaches the requester's inbox (§6.4).
            let defer_after = inner
                .handler_options
                .read()
                .unwrap()
                .get(&offering)
                .and_then(|o| o.defer_after)
                .filter(|_| source == InboundSource::Live);
            let fut = crate::util::CURRENT_DISPATCH
                .scope(dispatch, crate::util::CURRENT_TRACE.scope(env.trace.clone(), h(input, ctx)));
            let mut deferred = false;
            let handled = match defer_after {
                None => fut.await,
                Some(threshold) => {
                    tokio::pin!(fut);
                    match tokio::time::timeout(threshold, &mut fut).await {
                        Ok(handled) => handled,
                        Err(_) => {
                            deferred = true;
                            // The non-terminal respond (§7.0): same shape and
                            // destination as the §11.3 streaming opening, and
                            // the task id is the dispatch task id delegation
                            // tracking and usage reporting already key off.
                            let mut opening = Envelope::new(PrimitiveType::Respond, &inner.agent_id);
                            opening.to = Some(env.from.clone());
                            opening.in_reply_to = Some(env.id.clone());
                            opening.task_id = Some(dispatch_task_id.clone());
                            opening.trace = child_span(&env.trace);
                            opening.payload = Some(json!({ "status": "working" }));
                            inner.sign(&mut opening);
                            if let Ok(b) = codec::encode(&opening) {
                                let _ = inner.client.publish(reply.clone(), b.clone().into()).await;
                                // Tap: observable like every other respond.
                                let _ = inner
                                    .client
                                    .publish(subjects::agent_outbox(&inner.agent_id), b.into())
                                    .await;
                            }
                            fut.await
                        }
                    }
                }
            };
            match &handled {
                Ok(_) => {
                    inner
                        .publish_span(span_of(crate::spans::SpanOutcome::Ok, None))
                        .await
                }
                // A refusal is not a failure, and the span says so: "this
                // agent declined" and "this agent broke" are different facts,
                // and conflating them sends somebody debugging the wrong thing.
                Err(e @ MeshError::Refusal(_)) => {
                    let (_, code) = crate::spans::outcome_of(e);
                    inner
                        .publish_span(span_of(crate::spans::SpanOutcome::Refused, code))
                        .await
                }
                Err(e) => {
                    let (outcome, code) = crate::spans::outcome_of(e);
                    inner.publish_span(span_of(outcome, code)).await
                }
            }

            // §7.0 deferred completion: the caller was told `working`, so
            // the terminal statement travels the task update channel -- the
            // same subject `StreamWriter::end` and `fail_task` publish on,
            // which the task manager records durably (§7.4) and
            // [`AgentMesh::await_task`] / [`AgentMesh::get_task`] read back.
            // Sealing, the §19.3 spend report and the §13.5 usage receipt are
            // exactly what the bare terminal respond would have carried.
            if deferred {
                let payload = match handled {
                    Ok(output) => {
                        let cost = inner.reported_cost(&dispatch_task_id);
                        let usage = inner.take_meters(&dispatch_task_id);
                        match seal_reply_output(&inner, &env, output, sealed_in, claimed_reply_key)
                            .await
                        {
                            Ok(output) => completed_payload(output, cost, usage),
                            Err(message) => failed_update_payload(None, Some(&message), None),
                        }
                    }
                    Err(e) => failed_update_payload(None, Some(&e.to_string()), None),
                };
                let mut update = Envelope::new(PrimitiveType::Respond, &inner.agent_id);
                update.to = Some(env.from.clone());
                update.in_reply_to = Some(env.id.clone());
                update.task_id = Some(dispatch_task_id.clone());
                update.trace = child_span(&env.trace);
                update.payload = Some(payload);
                inner.sign(&mut update);
                if let Ok(b) = codec::encode(&update) {
                    let _ = inner
                        .client
                        .publish(subjects::task_update(&dispatch_task_id), b.clone().into())
                        .await;
                    // Tap: the deferred terminal is a respond this agent made.
                    let _ = inner
                        .client
                        .publish(subjects::agent_outbox(&inner.agent_id), b.into())
                        .await;
                }
                return;
            }

            match handled {
                // §19.3: usage the handler reported rides out as the terminal
                // respond's `payload.cost` — the informative spend report.
                Ok(output) => {
                    let cost = inner.reported_cost(&dispatch_task_id);
                    let usage = inner.take_meters(&dispatch_task_id);
                    // ── §8.9 the deliverable goes back the way it came ──
                    // A sealed ask that named a reply_key asked for a sealed
                    // answer, and this is the one place in the exchange where
                    // the deliverable exists — so answering in the clear here
                    // would undo the whole thing at the worst possible moment.
                    // `output` is what gets sealed; `status`, cost and the
                    // usage receipt stay readable, because a mesh that cannot
                    // see whether work completed cannot be operated.
                    //
                    // A sealed ask that named NO reply_key asked for nothing
                    // back and is answered in the clear, which the extension
                    // permits and which is what a sender holding no encryption
                    // key of its own has chosen.
                    match seal_reply_output(&inner, &env, output, sealed_in, claimed_reply_key)
                        .await
                    {
                        Ok(output) => inner.completed(&env, output, cost, usage),
                        Err(message) => {
                            inner.failed_resp(&env, ErrorCode::SealingRequired, message, usage)
                        }
                    }
                }
                // A structured refusal keeps its wire error object — the §7.7
                // admission refusals travel this way, estimate and all. No
                // usage receipt: an admission refusal precedes the work.
                Err(MeshError::Refusal(eo)) => inner.refusal_resp(&env, eo),
                Err(e) => {
                    let usage = inner.take_meters(&dispatch_task_id);
                    inner.failed_resp(&env, ErrorCode::Internal, e.to_string(), usage)
                }
            }
        }
    };
    // §6.4a third carve-out beside the probe and the guarded relay: an
    // attended agent's queued ack "rides the transport reply channel, the one
    // channel §18.7 reserves for delivery-status signals" — the node speaking
    // about delivery, not the agent answering, releasing the caller's live
    // wait on the reply subject. Gated on the DECLARED interaction, not the
    // result shape alone, so a service handler that happens to return
    // `{queued, inbox_id}` still answers at the sender's inbox. A drained or
    // reply-less delivery carries no transport subject and sends nothing:
    // the queued ack is a live-delivery signal, exactly like the accept.
    // (`inbox_id` required, as the fixture pins it and the TypeScript SDK's
    // routing gate does — recognition alone tolerates its absence.)
    let queued_ack = attended
        && resp.error.is_none()
        && queued_ack_of(resp.payload.as_ref()).is_some_and(|a| a.inbox_id.is_some());
    if let Ok(bytes) = codec::encode(&resp) {
        if queued_ack {
            if let Some(t) = transport_reply {
                let _ = inner.client.publish(t, bytes.clone().into()).await;
            }
        } else {
            let _ = inner.client.publish(reply, bytes.clone().into()).await;
        }
        // Tap: publish a copy of every respond (success, error, offering-not-found)
        // for activity observation — mirrors the TypeScript SDK.
        let _ = inner.client.publish(subjects::agent_outbox(&inner.agent_id), bytes.into()).await;
    }
}


// ─── §10.8 cancel: interception, propagation, delegation liveness ───────────

/// The delegation-liveness watcher: one small subscription on a sub-task's
/// update subject, removing the delegation entry when the sub-task reaches a
/// terminal state (§7.3) — after which there is nothing left to propagate a
/// cancel to. Ends itself when the entry it exists for is gone, however it
/// went (its own removal, or propagation draining the parent — which also
/// aborts this task via the recorded handle).
async fn watch_sub_task(inner: Arc<Inner>, parent_task_id: String, sub_task_id: String, delegate: String) {
    let Ok(mut sub) = inner.client.subscribe(subjects::task_update(&sub_task_id)).await else {
        return;
    };
    while let Some(msg) = sub.next().await {
        // decode verifies the signature (§5.3); only the delegate itself or
        // this agent (having canceled the sub-task) can end the tracking.
        let Ok(env) = codec::decode(&msg.payload) else { continue };
        if env.kind != PrimitiveType::Respond
            || env.task_id.as_deref() != Some(sub_task_id.as_str())
            || (env.from != delegate && env.from != inner.agent_id)
        {
            continue;
        }
        let terminal = env
            .payload
            .as_ref()
            .and_then(|p| p.get("status"))
            .and_then(Value::as_str)
            .is_some_and(is_terminal_task_state);
        let mut map = inner.delegations.lock().unwrap();
        let Some(entry) = map.get_mut(&parent_task_id) else {
            return; // propagation drained the parent; this watcher's job is done
        };
        if terminal {
            entry.subs.remove(&sub_task_id);
            if entry.subs.is_empty() {
                map.remove(&parent_task_id);
            }
            return;
        }
    }
}

/// §8.9: the terminal respond's `output`, sealed back to the requester when it
/// asked for that. `Err(message)` means the answer must NOT go out in the
/// clear, and carries what to say instead.
///
/// The claimed `reply_key` is resolved against the requester's own published,
/// §8.3-verified key before anything is encrypted to it. `reply_key` rides
/// outside the box, and although the envelope signature covers it, that only
/// proves the sender chose it — it does not tie it to the sender's identity.
/// `resolve_reply_key` re-ties the two, and refuses a claim that disagrees.
async fn seal_reply_output(
    inner: &Arc<Inner>,
    env: &Envelope,
    output: Value,
    sealed_in: bool,
    claimed_reply_key: Option<String>,
) -> std::result::Result<Value, String> {
    if !sealed_in || claimed_reply_key.is_none() {
        return Ok(output);
    }
    let mesh = AgentMesh { inner: inner.clone() };
    let declared = mesh.encryption_key_for(&env.from).await;
    let Some(key) =
        crate::sealed::resolve_reply_key(claimed_reply_key.as_deref(), declared.as_deref())
    else {
        return Err(
            "This request was sealed and asked for a sealed answer, but its reply_key could not \
             be resolved against the sender's own published encryption key (§8.3, §8.9) — either \
             the sender declared none, or it named a different key. The work ran; the answer is \
             NOT being sent in the clear."
                .to_string(),
        );
    };
    let reply_key = inner
        .encryption_seed
        .as_deref()
        .and_then(|s| crate::sealed::encryption_public_from_seed(s).ok());
    match crate::sealed::seal_payload_to(&output, &key, reply_key.as_deref()) {
        Ok(sealed) => Ok(serde_json::to_value(sealed).unwrap_or(Value::Null)),
        Err(e) => Err(format!(
            "This request was sealed and asked for a sealed answer, which could not be produced \
             ({e}). The work ran; the answer is NOT being sent in the clear."
        )),
    }
}

/// An inbound `task.cancel` request (§10.8), intercepted before any offering
/// handler: validate at the door, propagate to still-live delegates unless
/// the parent task's handler opted out, and answer with the canceled Task
/// state.
///
/// On invalid input the answer is an `INVALID_ENVELOPE` error envelope where
/// a reply is permitted, and silence otherwise — nothing recorded, nothing
/// propagated (the fixture's `invalid` doctrine).
async fn handle_task_cancel(inner: Arc<Inner>, env: Envelope, reply: Option<String>, input: &Value) {
    let parsed = match validate_cancel_input(input) {
        Ok(parsed) => parsed,
        Err(e) => {
            if let Some(reply) = reply {
                let message = match &e {
                    MeshError::Protocol { message, .. } => message.clone(),
                    other => other.to_string(),
                };
                let resp = inner.error_resp(&env, ErrorCode::InvalidEnvelope, message);
                if let Ok(bytes) = codec::encode(&resp) {
                    let _ = inner.client.publish(reply, bytes.clone().into()).await;
                    let _ = inner
                        .client
                        .publish(subjects::agent_outbox(&inner.agent_id), bytes.into())
                        .await;
                }
            }
            return;
        }
    };

    // (a) §10.8 propagation, before the acknowledgement: a delegate should
    // not keep working while the canceler already holds our answer.
    propagate_cancel(&inner, &parsed).await;

    // (b) Answer with the updated Task state — `Inner::completed`'s shape
    // with status `canceled`, carrying the canceled task's id.
    if let Some(reply) = reply {
        let mut resp = Envelope::new(PrimitiveType::Respond, &inner.agent_id);
        resp.to = Some(env.from.clone());
        resp.in_reply_to = Some(env.id.clone());
        resp.trace = child_span(&env.trace);
        resp.task_id = Some(parsed.task_id.clone());
        resp.payload = Some(json!({ "status": "canceled" }));
        inner.sign(&mut resp);
        if let Ok(bytes) = codec::encode(&resp) {
            let _ = inner.client.publish(reply, bytes.clone().into()).await;
            // Tap: like every other respond this agent makes.
            let _ = inner
                .client
                .publish(subjects::agent_outbox(&inner.agent_id), bytes.into())
                .await;
        }
    }
}

/// Forward an inbound cancel for parent task `cancel.task_id` to each of its
/// still-live delegates (§10.8): reason `upstream_cancelled`, the ORIGINAL
/// reason carried in the note ([`propagated_cancel_note`] — the pinned
/// format, which composes across hops). The parent's entry is drained from
/// the delegations map and each sub's watcher ended; each forwarded cancel is
/// best-effort, like any cancel.
///
/// A parent whose handler set `propagate_cancel: false` is left alone —
/// entry, watchers and all: that handler manages its delegates itself, and
/// the watchers still retire entries as the delegates finish.
async fn propagate_cancel(inner: &Arc<Inner>, cancel: &CancelInput) {
    let drained = {
        let mut map = inner.delegations.lock().unwrap();
        let Some(entry) = map.get(&cancel.task_id) else { return };
        let propagate = inner
            .handler_options
            .read()
            .unwrap()
            .get(&entry.offering)
            .map(|o| o.propagate_cancel)
            .unwrap_or(true);
        if !propagate {
            return;
        }
        map.remove(&cancel.task_id)
    };
    let Some(entry) = drained else { return };
    let note = propagated_cancel_note(cancel.reason, cancel.note.as_deref());
    let me = AgentMesh { inner: inner.clone() };
    for (sub_task_id, sub) in entry.subs {
        if let Some(watcher) = sub.watcher {
            watcher.abort();
        }
        let _ = me
            .cancel(&sub.delegate, &sub_task_id, CancelReason::UpstreamCancelled, Some(note.clone()))
            .await;
    }
}

// ─── Stream chunk validation (§11.6) ────────────────────────────────────────

/// The outcome of validating one stream-subject envelope.
#[derive(Debug)]
pub enum ChunkOutcome {
    Chunk(StreamChunk),
    /// A well-formed error envelope from the responder (stream failed).
    Error(MeshError),
}

/// Validate a stream chunk over the RECEIVED bytes (§11.6):
/// - a PRESENT signature must verify (over the received JSON, §5.3);
/// - an ABSENT signature is accepted for intermediate chunks unless the
///   requester demanded `sign_chunks`;
/// - the FINAL chunk must be signed and its `chunk_count` must equal the
///   number of chunks actually received (truncation/injection detection).
pub fn validate_chunk(data: &[u8], sign_chunks: bool, received: u64) -> Result<ChunkOutcome> {
    let raw: Value = serde_json::from_slice(data)?;
    let from = raw.get("from").and_then(|v| v.as_str()).unwrap_or_default().to_string();
    let sig = raw
        .get("sig")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    match &sig {
        Some(s) => {
            let mut r = raw.clone();
            if !codec::verify_json_sig(&mut r, &from, s) {
                return Err(MeshError::code(
                    ErrorCode::IdentityMismatch,
                    format!("Chunk signature does not verify against 'from' ({from})"),
                ));
            }
        }
        None if sign_chunks => {
            return Err(MeshError::code(
                ErrorCode::IdentityMismatch,
                "Stream was requested with sign_chunks but a chunk arrived unsigned",
            ));
        }
        None => {}
    }

    if let Some(err) = raw.get("error").filter(|e| !e.is_null()) {
        let eo: ErrorObject = serde_json::from_value(err.clone())?;
        return Ok(ChunkOutcome::Error(MeshError::from_error_object(&eo)));
    }

    let p = raw.get("payload").cloned().unwrap_or(Value::Null);
    let chunk_index = p.get("chunk_index").and_then(|v| v.as_u64()).unwrap_or(0);
    let is_final = p.get("final").and_then(|v| v.as_bool()).unwrap_or(false);

    if is_final {
        if sig.is_none() {
            return Err(MeshError::code(
                ErrorCode::IdentityMismatch,
                "Final stream chunk is unsigned",
            ));
        }
        let declared = p.get("chunk_count").and_then(|v| v.as_u64());
        if declared != Some(received) {
            return Err(MeshError::code(
                ErrorCode::InvalidEnvelope,
                format!(
                    "Stream is incomplete or tampered: final declares {declared:?} chunk(s), received {received}"
                ),
            ));
        }
    }

    Ok(ChunkOutcome::Chunk(StreamChunk {
        chunk_index,
        data: p.get("data").cloned().unwrap_or(Value::Null),
        content_type: p.get("content_type").and_then(|v| v.as_str()).map(String::from),
        is_final,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inbound::{fresh_enough, SeenEnvelopes};

    /// A key-shaped id, so the names read like the ones the mesh actually uses.
    const ID: &str = "UAGENT7SAMPLEKEYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    #[test]
    fn the_spend_report_rides_in_payload_cost_and_absent_stays_omitted() {
        // §19.3: "the cost field of the terminal respond" is the respond's
        // PAYLOAD — where the platform's task manager reads reported spend —
        // never an envelope-level field.
        let with = completed_payload(json!({ "answer": 42 }), Some(CostCeiling::new(17000, "USD")), None);
        assert_eq!(with["status"], "completed");
        assert_eq!(with["output"], json!({ "answer": 42 }));
        assert_eq!(with["cost"], json!({ "amount_micro": 17000, "currency": "USD" }));

        let without = completed_payload(json!("ok"), None, None);
        assert_eq!(without, json!({ "status": "completed", "output": "ok" }));
        assert!(without.get("cost").is_none(), "no report: the key is ABSENT, never null");
    }

    #[test]
    fn the_usage_receipt_rides_in_payload_usage_and_empty_stays_omitted() {
        // §13.5: the receipt beside the spend report, both in the payload,
        // both covered by the envelope signature.
        let entries = vec![
            crate::metering::UsageEntry { meter: "tokens_out".into(), quantity: 4210 },
            crate::metering::UsageEntry { meter: "tool_calls".into(), quantity: 3 },
        ];
        let with = completed_payload(json!("ok"), None, Some(entries));
        assert_eq!(
            with["usage"],
            json!([
                { "meter": "tokens_out", "quantity": 4210 },
                { "meter": "tool_calls", "quantity": 3 }
            ])
        );

        let empty = completed_payload(json!("ok"), None, Some(vec![]));
        assert!(empty.get("usage").is_none(), "empty receipt: the key is ABSENT, never []");
    }

    #[test]
    fn the_mailbox_stream_and_durable_are_the_names_the_registry_wrote() {
        // §18.6's table, and `sdk-typescript/src/mesh.ts` startOfflineDrain. A
        // different stream name finds no mailbox; a different DURABLE name is
        // worse — it is a second consumer whose cursor starts at the beginning,
        // so every message this agent already handled is delivered again.
        assert_eq!(subjects::mailbox_stream(ID), format!("MESH_INBOX_{ID}"));
        assert_eq!(subjects::mailbox_durable(ID), format!("inbox_{ID}"));
    }

    #[test]
    fn the_mailbox_consumer_carries_the_settings_18_6_pins() {
        use async_nats::jetstream::consumer::{AckPolicy, DeliverPolicy};
        let durable = subjects::mailbox_durable(ID);
        let c = mailbox_consumer_config(&durable);
        assert_eq!(c.durable_name.as_deref(), Some(durable.as_str()));
        // Explicit: the ack is the §16.4 handoff and this SDK decides when it
        // happens. Anything else acks on delivery, which loses a message to a
        // crash mid-handling.
        assert_eq!(c.ack_policy, AckPolicy::Explicit);
        // All, not New: a consumer bound with New skips the very backlog the
        // mailbox exists to deliver, and does it silently.
        assert_eq!(c.deliver_policy, DeliverPolicy::All);
        assert_eq!(c.ack_wait, Duration::from_secs(30));
        assert_eq!(c.max_deliver, 5);
    }

    #[test]
    fn the_event_durable_name_is_the_18_6_derivation() {
        // §18.6: `mesh_event_{agent_id}_{subscription_hash}`, where the hash is
        // the first 16 lowercase hex characters of SHA-256 over the UTF-8
        // pattern. The hex literal is the cross-implementation fixture: the TS
        // SDK must derive the identical string for "billing.invoice_ready", or
        // an agent that switches SDKs binds a second consumer whose cursor
        // starts over.
        assert_eq!(subjects::subscription_hash("billing.invoice_ready"), "99397ba4a29eec30");
        assert_eq!(
            subjects::event_durable(ID, "billing.invoice_ready"),
            format!("mesh_event_{ID}_99397ba4a29eec30")
        );
        // Distinct patterns hash apart, and the hash is pattern-sensitive at
        // the byte level (a wildcard is part of the identity).
        assert_ne!(
            subjects::subscription_hash("billing.invoice_ready"),
            subjects::subscription_hash("billing.>")
        );
    }

    #[test]
    fn the_event_consumer_carries_the_settings_18_6_pins() {
        use async_nats::jetstream::consumer::{AckPolicy, DeliverPolicy};
        let durable = subjects::event_durable(ID, "billing.invoice_ready");
        let filter = subjects::event("billing.invoice_ready");
        let c = event_consumer_config(&durable, &filter, false);
        assert_eq!(c.durable_name.as_deref(), Some(durable.as_str()));
        assert_eq!(c.ack_policy, AckPolicy::Explicit);
        // New by default: a fresh durable starts from now, not from 24h of
        // retained history nobody asked for.
        assert_eq!(c.deliver_policy, DeliverPolicy::New);
        assert_eq!(c.ack_wait, Duration::from_secs(30));
        assert_eq!(c.max_deliver, 5);
        assert_eq!(c.filter_subject, "mesh.event.billing.invoice_ready");
        // …and All exactly when the subscriber asked for replay.
        let replayed = event_consumer_config(&durable, &filter, true);
        assert_eq!(replayed.deliver_policy, DeliverPolicy::All);
    }

    // ── §6.4a reply destination ─────────────────────────────────────────────

    #[test]
    fn an_answer_goes_to_the_senders_inbox_on_every_path() {
        // The collapse: live and drained share one destination, so the reply
        // destination can never again be a race between the two paths. The
        // transport reply subject being present changes nothing, and the mode
        // changes nothing either: the destination is decided before the
        // bare-vs-stream branch, so the §11.3 step-2 opening travels to the
        // requester's inbox exactly like a bare answer (§11.3, Appendix C).
        let inbox = format!("mesh.agent.{ID}.inbox");
        assert_eq!(
            respond_destination("echo", false, ID, Some("_INBOX.abc")),
            Some(inbox.clone())
        );
        assert_eq!(respond_destination("echo", false, ID, None), Some(inbox));
    }

    #[test]
    fn the_registry_probe_keeps_the_transport_reply_subject() {
        // The reaper's cheap liveness answer: same subject, no inbox round
        // trip, and quiet when no reply subject was carried, because there is
        // nowhere cheap left to say "alive" to.
        assert_eq!(
            respond_destination("__registry_probe__", false, ID, Some("_INBOX.abc")),
            Some("_INBOX.abc".to_string())
        );
        assert_eq!(respond_destination("__registry_probe__", false, ID, None), None);
    }

    #[test]
    fn a_guarded_delivery_answers_the_relay_on_the_reply_subject() {
        // EXT-6: on the `.inbox.guarded` subject, the requester of record is
        // the admission relay, which forwards the reply data to the true
        // sender itself, so the answer goes back on the transport reply
        // subject, never around the guard to the sender's inbox. With the
        // probe above, this is the WHOLE reply-subject exception list.
        assert_eq!(
            respond_destination("echo", true, ID, Some("_INBOX.relay")),
            Some("_INBOX.relay".to_string())
        );
        assert_eq!(respond_destination("echo", true, ID, None), None);
    }

    // ── §6.4a what the wait reads from each channel ─────────────────────────

    /// A respond correlated to `request_id`, with the given payload.
    fn reply_env(request_id: &str, payload: Value) -> Envelope {
        let mut env = Envelope::new(PrimitiveType::Respond, ID);
        env.in_reply_to = Some(request_id.to_string());
        env.payload = Some(payload);
        env
    }

    #[test]
    fn substantive_data_on_the_liveness_channel_is_ignored() {
        // The transport reply subject of a request is liveness-only: a
        // full answer arriving there (a pre-cutover responder, or a spoofer
        // who learned the `_INBOX.` subject) never resolves the request.
        let env = reply_env("req-1", json!({ "status": "completed", "output": 42 }));
        assert!(matches!(wait_step(&env, "req-1", false), WaitStep::Ignore));
        // The same envelope through the inbox path resolves.
        assert!(matches!(wait_step(&env, "req-1", true), WaitStep::Resolve));
    }

    #[test]
    fn delivery_signals_are_honoured_on_both_channels() {
        // The accept and the queued ack are statements about liveness and
        // delivery, not response data, and the queued ack is made by a node
        // answering for an absent agent, which has only the reply subject to
        // answer on. Both are read wherever they arrive.
        let acc = reply_env("req-1", json!({ "status": "accepted" }));
        assert!(matches!(wait_step(&acc, "req-1", false), WaitStep::AcceptSeen));
        assert!(matches!(wait_step(&acc, "req-1", true), WaitStep::AcceptSeen));
        let queued = reply_env("req-1", json!({ "queued": true, "inbox_id": "held-1" }));
        assert!(matches!(wait_step(&queued, "req-1", false), WaitStep::Queued(_)));
        assert!(matches!(wait_step(&queued, "req-1", true), WaitStep::Queued(_)));
    }

    #[test]
    fn a_reply_bound_to_a_different_request_is_ignored_everywhere() {
        let env = reply_env("req-OTHER", json!({ "status": "completed" }));
        assert!(matches!(wait_step(&env, "req-1", true), WaitStep::Ignore));
        assert!(matches!(wait_step(&env, "req-1", false), WaitStep::Ignore));
    }

    #[test]
    fn a_drained_message_is_answered_on_the_senders_inbox() {
        // No live reply subject travels with a buffered message, and none is
        // needed: §6.4a answers a bare request on the sender's own inbox on
        // every path, which is itself buffered if the sender has meanwhile
        // gone offline too.
        assert_eq!(subjects::agent_inbox(ID), format!("mesh.agent.{ID}.inbox"));
    }

    #[test]
    fn the_drain_stops_at_the_backlog_that_existed_when_it_bound() {
        // The fix, stated as a test. The mailbox captures the same subject live
        // messages arrive on, so a drain that keeps consuming dispatches live
        // traffic too — and answers it on the SENDER's inbox while the requester
        // waits on its `_INBOX.` reply subject until it times out. §22.2 dedup
        // does not save this: it decides which of the two paths dispatches, and
        // the two answer different destinations, so unbounded it is the reply
        // destination that becomes the race.
        //
        // `bound` here is the stream's last sequence at bind time.
        let bound = 7;
        // Inside the backlog: this is mail the agent really did miss.
        assert_eq!(drain_step(1, bound), DrainStep::Dispatch);
        assert_eq!(drain_step(6, bound), DrainStep::Dispatch);
        // The backlog's last message: handled, then the drain is done.
        assert_eq!(drain_step(7, bound), DrainStep::DispatchAndStop);
        // Added to the stream after the bind. THIS is the case that was broken:
        // the live subscription owns it, so the drain neither dispatches it nor
        // acks it.
        assert_eq!(drain_step(8, bound), DrainStep::Stop);
        assert_eq!(drain_step(9_999, bound), DrainStep::Stop);
        // A mailbox that never captured anything has bound 0, so the first live
        // message to reach it is already past the bound — an empty backlog can
        // never dispatch anything, whatever arrives while the drain is binding.
        assert_eq!(drain_step(1, 0), DrainStep::Stop);
    }

    // ── §16.4: the bounded pass repeats ────────────────────────────────────

    #[test]
    fn every_pass_takes_a_fresh_bound_and_stops_at_that_one() {
        // Repeating the drain must not weaken the bound. Pass 1 bound at 1; pass 2
        // re-reads `state.last_sequence` and binds at 3. The same sequence is judged
        // differently by the two, and that is the whole point: seq 2 belonged to the
        // live subscription during pass 1 and is drainable backlog by pass 2 — which
        // is how a message the live path missed in a reconnect gap gets recovered
        // instead of waiting for the next restart.
        assert_eq!(drain_step(2, 1), DrainStep::Stop);
        assert_eq!(drain_step(2, 3), DrainStep::Dispatch);
        assert_eq!(drain_step(3, 3), DrainStep::DispatchAndStop);
        // …and pass 2 stops at ITS bound, not at "whatever is there now". A message
        // that landed while pass 2 was working is still the live path's.
        assert_eq!(drain_step(4, 3), DrainStep::Stop);
    }

    #[test]
    fn a_reconnect_is_a_connect_that_follows_a_disconnect() {
        use async_nats::Event;
        let seen = std::sync::atomic::AtomicBool::new(false);
        // The first connection is not a reconnect: firing here would cost every
        // process a redundant pass at startup, right after the one `register`
        // already takes.
        assert!(!is_reconnect(&Event::Connected, &seen));
        // A disconnect on its own is not the moment either — the mailbox cannot be
        // read while the transport is away.
        assert!(!is_reconnect(&Event::Disconnected, &seen));
        // Coming back IS: this is the gap in which the live subscription missed
        // messages the mailbox captured.
        assert!(is_reconnect(&Event::Connected, &seen));
        // …and it is consumed, so a later `Connected` with no gap before it does
        // not fire again.
        assert!(!is_reconnect(&Event::Connected, &seen));
        // Noise on the same channel is not a reconnect.
        assert!(!is_reconnect(&Event::SlowConsumer(1), &seen));
        assert!(!is_reconnect(&Event::LameDuckMode, &seen));
    }

    #[test]
    fn two_triggers_do_not_run_two_passes() {
        // A reconnect landing during a re-register, or a fresh loop started by a
        // re-`register` before `close`'s abort of the old one has landed. Two passes
        // over one durable consumer would each take their own bound and each dispatch
        // from the same cursor.
        let flag = std::sync::atomic::AtomicBool::new(false);
        let first = DrainSlot::claim(&flag).expect("the first trigger runs");
        assert!(DrainSlot::claim(&flag).is_none(), "the second must not");
        assert!(DrainSlot::claim(&flag).is_none(), "nor the third");
        drop(first);
        // Released with the pass, not left held: the next trigger runs. Dropping is
        // also what an ABORTED pass does, which is why the release is on Drop.
        assert!(DrainSlot::claim(&flag).is_some(), "the next trigger runs");
    }

    #[test]
    fn the_re_drain_interval_is_clamped_and_defaults_to_sixty_seconds() {
        // 60s is chosen against §22.2's 5,000-pair memory: a re-drain re-delivers
        // everything the live path already handled, and the memory is what turns that
        // into an ack instead of a second dispatch. 5,000 messages in 60s is 83 a
        // second, sustained, on one agent.
        assert_eq!(clamp_drain_interval(None), Duration::from_secs(60));
        assert_eq!(DEFAULT_MAILBOX_DRAIN_INTERVAL, Duration::from_secs(60));
        assert_eq!(crate::MAX_SEEN_INBOX_IDS, 5_000);
        // A caller may go faster, but not to zero: a pass is two JetStream requests
        // plus a pull, and zero is a busy loop against the broker.
        assert_eq!(
            clamp_drain_interval(Some(Duration::ZERO)),
            MIN_MAILBOX_DRAIN_INTERVAL
        );
        assert_eq!(
            clamp_drain_interval(Some(Duration::from_millis(1))),
            MIN_MAILBOX_DRAIN_INTERVAL
        );
        assert_eq!(
            clamp_drain_interval(Some(Duration::from_secs(300))),
            Duration::from_secs(300)
        );
    }

    #[test]
    fn the_drain_judges_freshness_on_the_mailbox_window_not_the_live_one() {
        // §22.3. A buffered envelope is old by construction: this is the
        // difference between draining a mailbox and refusing all of it as stale.
        assert_eq!(MAILBOX_SOURCE, InboundSource::Mailbox);
        let a_day_ago = "2027-01-14T00:00:00Z";
        let now = crate::inbound::parse_instant_ms(a_day_ago).unwrap() + 24 * 60 * 60 * 1000;
        assert!(!fresh_enough(a_day_ago, now, InboundSource::Live));
        assert!(fresh_enough(a_day_ago, now, MAILBOX_SOURCE));
        // …and the mailbox window is not unbounded: past the buffer's own
        // retention, a copy is a replay and nothing distinguishes it.
        let over = now + crate::inbound::MAX_MAILBOX_AGE_MS;
        assert!(!fresh_enough(a_day_ago, over, MAILBOX_SOURCE));
    }

    // ── EXT-6 §7.1: the guard refusal conditions ───────────────────────────

    /// A signed-shaped reply to a guard request. The signature is checked by
    /// `codec::decode` before this judgement ever runs, so these cases are about
    /// the judgement alone.
    fn guard_reply(request_id: &str, to: Option<&str>, payload: Value) -> Envelope {
        let mut env = Envelope::new(PrimitiveType::Respond, "USERVICE");
        env.in_reply_to = Some(request_id.to_string());
        env.to = to.map(str::to_string);
        env.payload = Some(payload);
        env
    }

    #[test]
    fn an_explicit_ok_is_the_only_answer_that_guards() {
        let ok_bare = guard_reply("req-1", Some(ID), json!({ "output": { "ok": true } }));
        assert!(guard_reply_is_ok(&ok_bare, "req-1", ID));
        // `guarded: true` alongside it is the same answer.
        let ok_explicit =
            guard_reply("req-1", Some(ID), json!({ "output": { "ok": true, "guarded": true } }));
        assert!(guard_reply_is_ok(&ok_explicit, "req-1", ID));
        // An absent `to` is legitimate — service replies omit it (§22.4).
        let ok_no_to = guard_reply("req-1", None, json!({ "output": { "ok": true } }));
        assert!(guard_reply_is_ok(&ok_no_to, "req-1", ID));
    }

    #[test]
    fn a_benign_queued_receipt_is_not_an_ok() {
        // What the admission service sends a SENDER whose message was dropped.
        // Believing it made the agent unsubscribe from its only inbox.
        let receipt = guard_reply("req-1", Some(ID), json!({ "output": { "queued": true } }));
        assert!(!guard_reply_is_ok(&receipt, "req-1", ID));
        // Truthy-but-not-true is not an ok either.
        let stringly = guard_reply("req-1", Some(ID), json!({ "output": { "ok": "yes" } }));
        assert!(!guard_reply_is_ok(&stringly, "req-1", ID));
        // No payload at all.
        let empty = guard_reply("req-1", Some(ID), Value::Null);
        assert!(!guard_reply_is_ok(&empty, "req-1", ID));
    }

    #[test]
    fn a_rate_limited_refusal_leaves_the_agent_unguarded() {
        // Every service subject is wrapped in the platform's shared rate limiter,
        // which answers over the limit with an ERROR envelope. A chatty agent — or
        // one of many behind a busy node — must not read that as a guard.
        let mut refused = guard_reply("req-1", Some(ID), json!({ "output": { "ok": true } }));
        refused.error = Some(ErrorObject {
            code: "RATE_LIMITED".to_string(),
            message: "too many requests".to_string(),
            details: None,
            retryable: true,
            retry_after_ms: Some(1_000),
        });
        assert!(!guard_reply_is_ok(&refused, "req-1", ID));
        // And an explicit denial dressed as an ok.
        let denied =
            guard_reply("req-1", Some(ID), json!({ "output": { "ok": true, "guarded": false } }));
        assert!(!guard_reply_is_ok(&denied, "req-1", ID));
    }

    #[test]
    fn an_unbound_or_re_aimed_reply_is_refused() {
        // §6.2. Racing a reply blind is defeated by `in_reply_to` alone, which is
        // why it holds even where the service's key is unknowable in advance.
        let raced = guard_reply("someone-elses-request", Some(ID), json!({ "output": { "ok": true } }));
        assert!(!guard_reply_is_ok(&raced, "req-1", ID));
        let unbound = {
            let mut e = guard_reply("req-1", Some(ID), json!({ "output": { "ok": true } }));
            e.in_reply_to = None;
            e
        };
        assert!(!guard_reply_is_ok(&unbound, "req-1", ID));
        // A reply captured from another agent's exchange cannot be re-aimed here.
        let for_someone_else =
            guard_reply("req-1", Some("UOTHERAGENT"), json!({ "output": { "ok": true } }));
        assert!(!guard_reply_is_ok(&for_someone_else, "req-1", ID));
    }

    #[test]
    fn the_guarded_subject_is_private_and_distinct_from_the_public_inbox() {
        // Nothing relays here unless the admission service is really guarding the
        // agent, which is why believing a refused guard succeeded is silent and
        // total rather than merely unfiltered.
        assert_eq!(
            subjects::agent_inbox_guarded(ID),
            format!("mesh.agent.{ID}.inbox.guarded")
        );
        assert_ne!(subjects::agent_inbox_guarded(ID), subjects::agent_inbox(ID));
        assert_eq!(subjects::ADMISSION_GUARD, "mesh.admission.guard");
        assert_eq!(subjects::ADMISSION_UNGUARD, "mesh.admission.unguard");
    }

    // ── §8.2 interaction style ─────────────────────────────────────────────

    #[test]
    fn interaction_rides_the_wire_under_its_own_name_and_is_never_invented() {
        let mut m = crate::manifest::Manifest {
            id: ID.to_string(),
            name: "probe".to_string(),
            description: String::new(),
            version: "0.1.0".to_string(),
            protocol_version: crate::envelope::PROTOCOL_VERSION.to_string(),
            encryption_key: None,
            endpoint: subjects::agent_inbox(ID),
            endpoints: None,
            limits: None,
            node: NodeRef {
                id: ID.to_string(),
                attestation: crate::manifest::AgentAttestation {
                    node: ID.to_string(),
                    agent: ID.to_string(),
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
            meta: None,
            trust: None,
            visibility: None,
            interaction: None,
            harness: None,
            harness_version: None,
            model: None,
            availability: None,
            owner: None,
            owner_attestation: None,
        };
        // Undeclared stays ABSENT on the wire. "unknown" and "service" mean very
        // different things to a caller (§8.3a), so the field must not appear as
        // null and must not be defaulted.
        let wire = serde_json::to_value(&m).unwrap();
        assert!(wire.get("interaction").is_none());

        for declared in ["service", "interactive"] {
            m.interaction = Some(declared.to_string());
            let wire = serde_json::to_value(&m).unwrap();
            assert_eq!(wire["interaction"], json!(declared));
            // …and reads back, which is what a discovering caller filters on.
            let back: crate::manifest::Manifest = serde_json::from_value(wire).unwrap();
            assert_eq!(back.interaction.as_deref(), Some(declared));
        }
    }

    // ── §8.8 works_with / §8.5.1 the credential need ───────────────────────

    #[test]
    fn the_third_party_declarations_ride_the_wire_under_their_own_names() {
        // Both say something about a service the agent does not own, and both
        // are read pre-admission, so the field names are the contract: a TS
        // registrant and a Rust one must produce the same bytes.
        let need = crate::manifest::NeedEntry {
            credential: Some("Colorado DMV".to_string()),
            scope: Some("read your registration record".to_string()),
            ..Default::default()
        };
        let wire = serde_json::to_value(&need).unwrap();
        assert_eq!(wire["credential"], json!("Colorado DMV"));
        assert_eq!(wire["scope"], json!("read your registration record"));
        // The other kinds stay absent rather than null: a `resource: null` on a
        // credential need would read as a fifth, malformed kind.
        assert!(wire.get("resource").is_none());
        assert!(wire.get("file").is_none());
        assert!(wire.get("text").is_none());

        let back: crate::manifest::NeedEntry = serde_json::from_value(wire).unwrap();
        assert_eq!(back.credential.as_deref(), Some("Colorado DMV"));

        let w = crate::manifest::WorksWith {
            service: "Colorado DMV".to_string(),
            domain: Some("dmv.colorado.gov".to_string()),
            description: None,
        };
        let wire = serde_json::to_value(&w).unwrap();
        assert_eq!(wire["service"], json!("Colorado DMV"));
        assert_eq!(wire["domain"], json!("dmv.colorado.gov"));
        assert!(wire.get("description").is_none());
    }

    #[test]
    fn an_agent_that_declares_no_integrations_says_nothing_about_them() {
        // Absent means "did not say". An empty array would read as "declared
        // none", which is a different claim and not one the SDK may invent.
        let opts = RegisterOptions { works_with: Some(vec![]), ..Default::default() };
        assert!(opts.works_with.clone().filter(|w| !w.is_empty()).is_none());
    }

    // ── §10.8 cancel ───────────────────────────────────────────────────────

    #[test]
    fn handler_options_default_to_propagating_cancels() {
        // The guarded default, in the InboundOptions::fence pattern: the
        // behavior whose absence is invisible (a stranded delegate burning
        // time on work nobody will read) defaults ON, and `propagate_cancel:
        // false` — "this handler manages its delegates itself" — is an
        // explicit opt-out per offering.
        assert!(HandlerOptions::default().propagate_cancel);
    }

    #[test]
    fn the_drain_shares_the_live_inboxs_duplicate_memory() {
        // §22.1's hole, stated as a test: the drain and the live subscription can
        // both deliver the same envelope, and the drain's window is 1000x wider.
        // If the drain kept its own memory, an envelope the live path had just
        // refused as stale would sail through on the buffered copy. One memory,
        // and `remember` runs before the freshness judgement, is what closes it.
        let seen = SeenEnvelopes::new();
        assert!(seen.remember(ID, "envelope-1"), "live delivery is first sight");
        assert!(
            !seen.remember(ID, "envelope-1"),
            "the buffered copy of the same envelope is a duplicate"
        );
    }
}
