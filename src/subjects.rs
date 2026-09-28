//! NATS subject namespace (AgentMesh 0.2 §14). Mirrors the TS SDK's Subjects.

pub const REGISTRY_REGISTER: &str = "mesh.registry.register";
pub const REGISTRY_DEREGISTER: &str = "mesh.registry.deregister";
pub const REGISTRY_DISCOVER: &str = "mesh.registry.discover";

/// Registry single-manifest lookup by agent id (request-reply).
pub fn registry_get(agent_id: &str) -> String {
    format!("mesh.registry.get.{agent_id}")
}

/// Rooms service (mesh://extensions/rooms/v1, durable side). Bare subjects.
pub mod rooms {
    pub const PROVISION: &str = "mesh.rooms.provision";
    pub const REPLAY: &str = "mesh.rooms.replay";
    pub const ATTACH: &str = "mesh.rooms.attach";
    pub const FETCH: &str = "mesh.rooms.fetch";
    pub const STATUS: &str = "mesh.rooms.status";
    pub const RECLAIM: &str = "mesh.rooms.reclaim";
    /// Operator-level durable-room usage vs quota (diagnostics).
    pub const USAGE: &str = "mesh.rooms.usage";
    /// Rooms the caller can reach: acl rooms it is admitted to, plus any room it
    /// created. NOT capability/sealed rooms it merely holds a descriptor for —
    /// the service never learns of those (EXT-5 §6).
    pub const MINE: &str = "mesh.rooms.mine";
    /// The caller's read position in a room's record. Monotonic.
    pub const CURSOR: &str = "mesh.rooms.cursor";
    // acl grade (broker-enforced membership):
    pub const ADMIT: &str = "mesh.rooms.admit";
    pub const CREDENTIAL: &str = "mesh.rooms.credential";
    pub const EXPEL: &str = "mesh.rooms.expel";
    /// Attach an attributed note to a file already on the drive, keyed by its
    /// digest (EXT-5 §8.4).
    pub const NOTE: &str = "mesh.rooms.note";
    /// Read the notes on one digest, or on every noted file in the room.
    pub const NOTES: &str = "mesh.rooms.notes";
}

/// The work board (EXT-5 §10): a room's optional whiteboard of claimable work
/// items, answered by the rooms service. Every verb presents the room's
/// descriptor and is admitted by the same membership rule as the record and
/// the drive — the board adds no access model of its own.
pub mod board {
    pub const POST: &str = "mesh.board.post";
    pub const LIST: &str = "mesh.board.list";
    pub const CLAIM: &str = "mesh.board.claim";
    pub const COMPLETE: &str = "mesh.board.complete";
    pub const ABANDON: &str = "mesh.board.abandon";
    pub const WITHDRAW: &str = "mesh.board.withdraw";
}

/// EXT-6 admission service (`mesh://extensions/admission/v1`, §7.1). `guard`
/// asks the service to filter this agent's inbox; `unguard` withdraws that ask.
/// Both derive the inbox from the request's VERIFIED `from`, so neither carries
/// an agent id and neither can be aimed at somebody else's inbox.
pub const ADMISSION_GUARD: &str = "mesh.admission.guard";
/// See [`ADMISSION_GUARD`].
pub const ADMISSION_UNGUARD: &str = "mesh.admission.unguard";

/// Presence snapshot lookup (§9.6 `get_presence`, request-reply). Consumers
/// tracking liveness MUST subscribe to the transition stream (the heartbeat
/// subjects below, or the deployment's `mesh.event.presence.*` events) BEFORE
/// reading this snapshot — see `AgentMesh::track_presence`.
pub const PRESENCE_GET: &str = "mesh.presence.get";

pub fn agent_inbox(agent_id: &str) -> String {
    format!("mesh.agent.{agent_id}.inbox")
}
/// The PRIVATE subject a guarded agent listens on instead of its public inbox
/// (EXT-6 §7.1). Nothing relays here unless the admission service is actually
/// guarding the agent, which is why believing a refused guard succeeded makes an
/// agent silently unreachable (see `AgentMesh::register`).
pub fn agent_inbox_guarded(agent_id: &str) -> String {
    format!("mesh.agent.{agent_id}.inbox.guarded")
}
pub fn agent_outbox(agent_id: &str) -> String {
    format!("mesh.agent.{agent_id}.outbox")
}
pub fn task_update(task_id: &str) -> String {
    format!("mesh.task.{task_id}.update")
}
pub fn task_stream(task_id: &str) -> String {
    format!("mesh.task.{task_id}.stream")
}
/// Task Manager lookup (request-reply): the durable task record by id.
pub fn task_get(task_id: &str) -> String {
    format!("mesh.task.get.{task_id}")
}
/// Domain event subject. `topic` is `{domain}.{event_type}` (or a wildcard).
pub fn event(topic: &str) -> String {
    format!("mesh.event.{topic}")
}

/// `^U[A-Z2-7]{55}$` — a user nkey, the shape the owner slot of a feed
/// subject must hold (§6.6a; same grammar as `agreement.rs`).
fn is_user_nkey(s: &str) -> bool {
    s.len() == 56
        && s.starts_with('U')
        && s.bytes().skip(1).all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b))
}

/// `^[A-Za-z0-9_-]{1,128}$` — ONE subject token naming a feed channel
/// (§6.6a). A dot would smuggle a fifth token, so it is not a topic character;
/// neither is a wildcard, a space, or anything else NATS gives meaning to.
fn is_feed_topic(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Feed subject (§6.6a): `mesh.feed.{agent_id}.{topic}` — the owner-rooted
/// event channel, exactly four tokens. REFUSES rather than emits a subject the
/// transport grant (`mesh.feed.<own key>.*`) would reject or that would
/// smuggle extra tokens: a dotted, empty, wildcard, spaced or oversized topic
/// is an error here, never split or passed through
/// (`conformance/feeds.json` build_cases).
pub fn feed(agent_id: &str, topic: &str) -> crate::error::Result<String> {
    if !is_user_nkey(agent_id) {
        return Err(crate::error::MeshError::code(
            crate::error::ErrorCode::InputInvalid,
            format!("feed owner must be a user nkey (^U[A-Z2-7]{{55}}$), got {agent_id:?}"),
        ));
    }
    if !is_feed_topic(topic) {
        return Err(crate::error::MeshError::code(
            crate::error::ErrorCode::InputInvalid,
            format!("feed topic must be one [A-Za-z0-9_-]{{1,128}} token, got {topic:?}"),
        ));
    }
    Ok(format!("mesh.feed.{agent_id}.{topic}"))
}

/// The subscription form of [`feed`]: identical grammar, plus the one wildcard
/// §6.6a names — `topic == "*"` matches all of one agent's feeds. Still never
/// a publish subject; [`feed`] is what a publish validates against.
pub fn feed_pattern(agent_id: &str, topic: &str) -> crate::error::Result<String> {
    if topic == "*" {
        if !is_user_nkey(agent_id) {
            return Err(crate::error::MeshError::code(
                crate::error::ErrorCode::InputInvalid,
                format!("feed owner must be a user nkey (^U[A-Z2-7]{{55}}$), got {agent_id:?}"),
            ));
        }
        return Ok(format!("mesh.feed.{agent_id}.*"));
    }
    feed(agent_id, topic)
}

/// Parse a subject as a feed (§6.6a): exactly four tokens, the `mesh.feed`
/// prefix, a user nkey in the owner slot and one valid topic token —
/// `Some((agent_id, topic))`, else `None`. `mesh.feed.get` has three tokens
/// and is therefore never a feed (`conformance/feeds.json` parse_cases).
pub fn parse_feed_subject(subject: &str) -> Option<(String, String)> {
    let tokens: Vec<&str> = subject.split('.').collect();
    if tokens.len() != 4 || tokens[0] != "mesh" || tokens[1] != "feed" {
        return None;
    }
    if !is_user_nkey(tokens[2]) || !is_feed_topic(tokens[3]) {
        return None;
    }
    Some((tokens[2].to_string(), tokens[3].to_string()))
}
/// Node-scoped heartbeat (§9.6).
pub fn heartbeat(node_id: &str) -> String {
    format!("mesh.heartbeat.{node_id}")
}

// ─── §16.4 offline mailbox (§18.6 stream/consumer table) ────────────────────
//
// These two are NOT subjects — they are the JetStream stream and durable
// consumer NAMES, and they live here because they are the same kind of thing:
// wire identifiers the registry, the TypeScript SDK and this crate must all
// spell identically. The registry creates the stream at registration and the
// agent binds the consumer; a name that differs by one character means the
// agent finds no mailbox and never learns it had one.

/// The per-agent offline redelivery buffer (§16.4, §18.6). Captures messages
/// sent while the agent was not live; the agent drains it on register.
///
/// **Absence is normal.** Sandbox agents get no mailbox and older deployments
/// have none at all, so a missing stream is a no-op and never an error.
pub fn mailbox_stream(agent_id: &str) -> String {
    format!("MESH_INBOX_{agent_id}")
}

/// The durable pull consumer this agent binds on its own mailbox (§18.6).
///
/// Per-agent and STABLE across restarts, which is the whole point of a durable:
/// the server remembers what this agent has acked. Deriving a different name —
/// a uuid, a hostname, a process id — creates a second consumer whose cursor
/// starts at the beginning, so every message the agent has already handled is
/// delivered again.
pub fn mailbox_durable(agent_id: &str) -> String {
    format!("inbox_{agent_id}")
}

/// The shared event stream durable subscriptions bind on (§18.6 Event
/// Consumer). One stream for the whole mesh, capturing `mesh.event.>`;
/// per-subscription consumers filter inside it. Provisioned by the platform,
/// never by this SDK, a missing stream is an error the subscriber must hear
/// about, unlike the per-agent mailbox whose absence is normal.
pub const EVENTS_STREAM: &str = "MESH_EVENTS";

/// State-feed current-value lookup (§18.3, request-reply): `{agent, topic}`
/// in, `{found, envelope}` out. Three tokens, so never itself a feed subject.
pub const FEED_GET: &str = "mesh.feed.get";

/// The optional stream-feed history stream (§18.3): the ONE stream bound to
/// `mesh.feed.>` — a slice needing its own retention sources from it, the same
/// one-owner rule as `MESH_EVENTS`. Provisioned by the platform, never by this
/// SDK.
pub const FEED_STREAM: &str = "MESH_FEED";

/// The §18.6 subscription hash: the first 16 lowercase hex characters of the
/// SHA-256 of the UTF-8 pattern.
///
/// The hash exists because the pattern itself cannot be in the durable name
/// (NATS consumer names cannot carry `.` or `>`), and the TRUNCATION is part of
/// the wire contract, not a style choice: both SDKs must derive the same
/// durable for the same pattern or an agent that switches SDKs binds a second
/// consumer whose cursor starts over. Pinned by the `billing.invoice_ready`
/// fixture in `client.rs`'s tests and cross-checked in `tests/cross_impl.rs`.
pub fn subscription_hash(pattern: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(pattern.as_bytes());
    // 16 hex characters = the first 8 digest bytes.
    digest[..8].iter().map(|b| format!("{b:02x}")).collect()
}

/// The durable pull consumer one agent binds for one durable event
/// subscription (§18.6): `mesh_event_{agent_id}_{subscription_hash}`.
///
/// Keyed on the PAIR, the same agent may hold many durable subscriptions, and
/// two agents subscribing the same pattern must not share a cursor. Like the
/// mailbox durable above, stability across restarts is the point: the server
/// remembers what this agent has acked for this pattern, which is what makes
/// stopping and rebinding resume instead of replay.
pub fn event_durable(agent_id: &str, pattern: &str) -> String {
    format!("mesh_event_{agent_id}_{}", subscription_hash(pattern))
}

/// An agent's durable feed consumer on [`FEED_STREAM`] (§18.6 Feed Consumer):
/// ONE per agent, `mesh_feed_{agent_id}`, whose filter subjects are the feeds
/// it follows durably. Named for the agent and not the feed because a
/// credential can grant a consumer only by its whole name, and the agent's key
/// is the one name known when the credential is minted. Cross-SDK contract:
/// the TypeScript SDK's `Subjects.feedConsumer` spells it identically.
pub fn feed_consumer(agent_id: &str) -> String {
    format!("mesh_feed_{agent_id}")
}
