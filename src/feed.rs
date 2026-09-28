//! Feeds (SPEC.md §6.6a): the owner-rooted event channel. Where §6.6's
//! `mesh.event.{domain}.{event_type}` space is a shared commons — the subject
//! names a domain, not an owner — a feed belongs to exactly one agent and says
//! so in its subject: `mesh.feed.{agent_id}.{topic}`. A feed publish is an
//! ordinary `emit` (no new envelope fields, no new signature) whose payload is
//! `{topic, kind, data}` — NEVER the `{domain, event_type, data}` split of a
//! domain emit, because a feed topic is a single token and is never split on
//! dots. The wire shapes here are pinned byte-for-byte by
//! `conformance/feeds.json`.
//!
//! A feed is one of two kinds, chosen by its owner: a **stream** is an ordered
//! history, replayed like any durable event subscription (§18.6); a **state**
//! is a current value — each publish replaces the last, the platform keeps the
//! latest emit envelope per feed (§18.3), and a late subscriber reads it over
//! `mesh.feed.get` without replaying history. Reading that snapshot while also
//! tracking changes obeys §9.6's subscribe-before-snapshot rule for exactly
//! the reason presence does (see [`crate::presence`]): a transition that fires
//! between a snapshot read and a later subscription lands in the gap and is
//! simply never seen.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::client::AgentMesh;
use crate::codec;
use crate::envelope::{Envelope, PrimitiveType};
use crate::error::{ErrorCode, MeshError, Result};
use crate::identity::sign_envelope;
use crate::subjects;

/// How long the §18.3 current-value read waits for a feed-state service. A
/// mesh without one answers no-responders immediately; this bounds the silent
/// case (same bound as the presence snapshot, `presence.rs`).
const FEED_GET_TIMEOUT: Duration = Duration::from_secs(5);

/// A feed's kind (§6.6a), chosen by its owner and carried in-band in every
/// publish so the platform and subscribers learn it from traffic without a
/// manifest read. `stream` is an ordered history; `state` is a current value
/// each publish of which replaces the last. These two are the whole vocabulary —
/// anything else fails to parse (`conformance/feeds.json` kind_cases).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FeedKind {
    State,
    Stream,
}

/// The §6.6a feed emit payload, exactly as the wire carries it:
/// `{topic, kind, data}` (`conformance/feeds.json` shape_cases). NOT the
/// `{domain, event_type, data}` of a domain emit — a feed topic is a single
/// token and is never split on dots.
pub fn feed_payload(topic: &str, kind: FeedKind, data: Value) -> Value {
    json!({ "topic": topic, "kind": kind, "data": data })
}

/// The `mesh.feed.get` request payload (§18.3): the feed's name, nothing else
/// (`conformance/feeds.json` lookup_request_cases).
pub fn feed_lookup_payload(agent_id: &str, topic: &str) -> Value {
    json!({ "agent": agent_id, "topic": topic })
}

// ─── §18.6 Feed Consumer: durable feed subscriptions ────────────────────────

/// §18.6 Feed Consumer: how long a delivery may sit unacked before the server
/// redelivers it. Pinned by SPEC, the same figure as the Event Consumer's.
pub(crate) const FEED_ACK_WAIT: Duration = Duration::from_secs(30);
/// §18.6 Feed Consumer: how many times one delivery is attempted.
pub(crate) const FEED_MAX_DELIVER: i64 = 5;
/// A delivery on the feed consumer whose feed no subscription in this process
/// follows (yet) is handed back after this long, so a process that subscribes
/// its feeds one after another does not lose a delivery for one it has not
/// reached; max_deliver bounds how often. Same figure as the TypeScript SDK's
/// `FEED_UNCLAIMED_NAK_MS`.
pub(crate) const FEED_UNCLAIMED_NAK: Duration = Duration::from_secs(5);

/// Whether a feed delivery subject matches a feed subscription pattern:
/// `mesh.feed.{agent}.{topic}` exactly, or `mesh.feed.{agent}.*` for every
/// topic of one agent. The only two pattern shapes [`subjects::feed_pattern`]
/// builds, so the only two this needs to understand.
pub(crate) fn feed_subject_matches(pattern: &str, subject: &str) -> bool {
    if pattern == subject {
        return true;
    }
    let p: Vec<&str> = pattern.split('.').collect();
    let s: Vec<&str> = subject.split('.').collect();
    p.len() == 4 && s.len() == 4 && p[3] == "*" && p[0] == s[0] && p[1] == s[1] && p[2] == s[2]
}

/// The consumer config a first durable feed subscription creates (§18.6 Feed
/// Consumer): explicit ack, deliver new, 30s ack wait, 5 deliveries, and this
/// one feed as the only filter subject.
pub(crate) fn feed_consumer_config(
    durable: &str,
    pattern: &str,
) -> async_nats::jetstream::consumer::pull::Config {
    use async_nats::jetstream::consumer::{pull, AckPolicy, DeliverPolicy};
    pull::Config {
        durable_name: Some(durable.to_string()),
        ack_policy: AckPolicy::Explicit,
        deliver_policy: DeliverPolicy::New,
        ack_wait: FEED_ACK_WAIT,
        max_deliver: FEED_MAX_DELIVER,
        filter_subjects: vec![pattern.to_string()],
        ..Default::default()
    }
}

/// The filter subjects an existing feed consumer should have once `pattern`
/// is added, or `None` when it already filters on it. The existing filters are
/// `filter_subjects`, or the single `filter_subject` when that is what the
/// consumer was made with. Nothing is ever removed.
pub(crate) fn feed_filters_with(
    filter_subjects: &[String],
    filter_subject: &str,
    pattern: &str,
) -> Option<Vec<String>> {
    let mut filters: Vec<String> = if !filter_subjects.is_empty() {
        filter_subjects.to_vec()
    } else if !filter_subject.is_empty() {
        vec![filter_subject.to_string()]
    } else {
        Vec::new()
    };
    if filters.iter().any(|f| f == pattern) {
        return None;
    }
    filters.push(pattern.to_string());
    Some(filters)
}

/// One durable feed handler as the shared pull loop calls it.
pub(crate) type FeedHandler = std::sync::Arc<dyn Fn(Value, Envelope) + Send + Sync>;
/// Feed pattern to (subscription id, handler). The id tells a stale `stop()`
/// apart from the subscription that replaced it on the same pattern.
pub(crate) type FeedHandlers =
    std::sync::Arc<std::sync::RwLock<std::collections::HashMap<String, (u64, FeedHandler)>>>;

/// The client's one running feed pull loop and the handlers it dispatches to.
pub(crate) struct FeedDurableLoop {
    pub(crate) handlers: FeedHandlers,
    pub(crate) task: tokio::task::AbortHandle,
}

/// Per-client state behind durable feed subscriptions. The mutex is held for
/// the whole of a bind, which is what serializes two concurrent
/// `subscribe_feed_durable` calls so they cannot race an update of the
/// consumer's filters.
#[derive(Default)]
pub(crate) struct FeedDurableShared {
    pub(crate) state: tokio::sync::Mutex<Option<FeedDurableLoop>>,
    pub(crate) next_id: std::sync::atomic::AtomicU64,
}

/// A running durable feed subscription ([`AgentMesh::subscribe_feed_durable`],
/// SPEC §18.6 Feed Consumer).
///
/// `stop()` removes this subscription's handler and, when it was the last
/// one, ends the client's pull loop. It never deletes the consumer and never
/// removes a filter subject: the consumer is the server-side cursor, and the
/// next start of this agent picks up what arrived while it was away.
pub struct DurableFeedSubscription {
    pub(crate) durable: String,
    pub(crate) subject: String,
    pub(crate) id: u64,
    pub(crate) shared: std::sync::Arc<FeedDurableShared>,
}

impl DurableFeedSubscription {
    /// The agent's one feed consumer on `MESH_FEED`, `mesh_feed_{agent_id}`.
    pub fn durable(&self) -> &str {
        &self.durable
    }

    /// The feed subject (or `mesh.feed.{agent}.*` pattern) this follows.
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Stop this subscription. See the type docs for what is kept.
    pub async fn stop(&self) {
        let mut state = self.shared.state.lock().await;
        let Some(running) = state.as_ref() else { return };
        let now_empty = {
            let mut handlers = running.handlers.write().unwrap();
            match handlers.get(&self.subject) {
                Some((id, _)) if *id == self.id => {
                    handlers.remove(&self.subject);
                }
                // Replaced by a later subscription on the same feed, or
                // already stopped: nothing of ours to remove.
                _ => return,
            }
            handlers.is_empty()
        };
        if now_empty {
            running.task.abort();
            *state = None;
        }
    }
}

impl AgentMesh {
    /// Publish onto one of this agent's own feeds (§6.6a): an ordinary `emit`
    /// on `mesh.feed.{own key}.{topic}` carrying the pinned
    /// `{topic, kind, data}` payload. Fire-and-forget like every emit; the
    /// subject grammar is validated here ([`subjects::feed`]) so a dotted or
    /// otherwise invalid topic is refused locally rather than smuggled onto
    /// the wire. Only the owner publishes — the transport grant
    /// (`mesh.feed.<own key>.>`) enforces that; this method can only ever aim
    /// at this agent's own space.
    pub async fn publish_feed(&self, topic: &str, data: Value, kind: FeedKind) -> Result<()> {
        self.require_named().await?;
        let subject = subjects::feed(self.agent_id_str(), topic)?;
        let mut env = Envelope::new(PrimitiveType::Emit, self.agent_id_str());
        env.payload = Some(feed_payload(topic, kind, data));
        let _ = sign_envelope(&mut env, &self.agent_kp());
        // §18.8: the envelope id doubles as the JetStream Nats-Msg-Id, so a
        // stream capturing this subject (`MESH_FEED`, a state-feed writer) can
        // drop a duplicate publish inside its duplicate window. Core NATS
        // ignores the header, so this costs nothing when no stream listens.
        // The typed name, not the string "Nats-Msg-Id": the server parses the
        // inbound header into the Standard variant, and a string-built name is
        // a Custom one that would not compare equal on lookup (see `emit`).
        let mut headers = async_nats::HeaderMap::new();
        headers.insert(async_nats::header::NATS_MESSAGE_ID, env.id.as_str());
        self.nats()
            .publish_with_headers(subject, headers, codec::encode(&env)?.into())
            .await
            .map_err(|e| MeshError::Transport(e.to_string()))?;
        Ok(())
    }

    /// Subscribe to one agent's feed (§6.6a) — or to all of them with
    /// `topic == "*"` (§6.7 unchanged). Deliveries are AMBIENT: they run the
    /// same §22 pipeline as [`AgentMesh::subscribe`] and reach the handler,
    /// never the mail path.
    ///
    /// One deliberate difference from [`AgentMesh::subscribe`]: the handler
    /// receives the FULL `{topic, kind, data}` payload, not `payload.data` —
    /// a feed carries its identity in-band, and a wildcard subscriber needs
    /// the topic to know which feed spoke. The §22.5 size cap and §22.6
    /// fencing still apply to the `data` member, exactly where `subscribe`
    /// applies them.
    pub async fn subscribe_feed<F>(&self, agent_id: &str, topic: &str, handler: F) -> Result<()>
    where
        F: Fn(Value, Envelope) + Send + Sync + 'static,
    {
        let subject = subjects::feed_pattern(agent_id, topic)?;
        self.subscribe_feed_pipeline(subject, handler).await
    }

    /// Subscribe to one agent's feed (or all of them, `topic == "*"`)
    /// **durably**: SPEC §18.6 Feed Consumer. What was published while this
    /// agent was offline is delivered when it comes back, and a delivery its
    /// handler panicked on is redelivered. The TypeScript SDK spells this
    /// `subscribeFeed(owner, topic, handler, { durable: true })`.
    ///
    /// The feed is added to this agent's ONE durable pull consumer on
    /// `MESH_FEED`, named [`subjects::feed_consumer`] (`mesh_feed_{agent_id}`),
    /// whose filter subjects are every feed it follows durably. When the
    /// consumer is missing it is created (explicit ack, deliver new, 30s ack
    /// wait, 5 deliveries); when it stands without this feed its filters are
    /// updated to add it. Bindings are serialized, so two concurrent calls
    /// cannot race that update. Filters are never removed.
    ///
    /// One pull loop per client serves every durable feed subscription,
    /// because a pull consumer divides its deliveries among whoever pulls.
    /// Each delivery runs the same §22 pipeline as
    /// [`AgentMesh::subscribe_feed`] (full `{topic, kind, data}` payload to the
    /// handler), on the buffered §22.3 window and deduplicated per pattern,
    /// for every handler whose pattern matches, and is acked after they all
    /// return. Undecodable bytes are acked and dropped. A delivery no handler
    /// in this process follows yet is handed back with a 5 second delay.
    ///
    /// A missing `MESH_FEED` stream or a refused JetStream call is an error,
    /// never a silent live subscription: a caller who asked for durability
    /// must not get the weaker thing. A credential minted before the
    /// feed-consumer grant existed is refused here until it is renewed.
    pub async fn subscribe_feed_durable<F>(
        &self,
        agent_id: &str,
        topic: &str,
        handler: F,
    ) -> Result<DurableFeedSubscription>
    where
        F: Fn(Value, Envelope) + Send + Sync + 'static,
    {
        let pattern = subjects::feed_pattern(agent_id, topic)?;
        self.subscribe_feed_durable_pipeline(pattern, std::sync::Arc::new(handler)).await
    }

    /// Read a state feed's current value (§18.3, request-reply on
    /// `mesh.feed.get`): `Some(envelope)` — the latest emit envelope the
    /// platform stored for `{agent_id}.{topic}` — or `None` when the feed has
    /// never published. Transport failures are errors, exactly as
    /// [`AgentMesh::get_presence`] treats its snapshot read: a timeout is
    /// `TRANSPORT_TIMEOUT`, never a silent `None` that would read as "never
    /// published".
    ///
    /// A consumer **tracking** a feed MUST NOT call this first and subscribe
    /// after: use [`AgentMesh::track_feed`], which owns the §9.6
    /// subscribe-before-snapshot ordering (§18.3 binds feeds to it).
    pub async fn feed_value(&self, agent_id: &str, topic: &str) -> Result<Option<Envelope>> {
        // The same grammar the builder enforces: a wildcard or dotted "topic"
        // names no single feed and has no current value to look up.
        subjects::feed(agent_id, topic)?;
        let mut env = Envelope::new(PrimitiveType::Request, self.agent_id_str());
        env.payload = Some(feed_lookup_payload(agent_id, topic));
        let _ = sign_envelope(&mut env, &self.agent_kp());
        let resp = tokio::time::timeout(
            FEED_GET_TIMEOUT,
            self.nats().request(subjects::FEED_GET, codec::encode(&env)?.into()),
        )
        .await
        .map_err(|_| MeshError::code(ErrorCode::TransportTimeout, "feed-state service did not respond"))?
        .map_err(|e| MeshError::Transport(e.to_string()))?;
        let resp_env = codec::decode(&resp.payload)?;
        if let Some(err) = &resp_env.error {
            return Err(MeshError::from_error_object(err));
        }
        let payload = resp_env.payload.unwrap_or(Value::Null);
        if payload.get("found").and_then(Value::as_bool) != Some(true) {
            return Ok(None);
        }
        match payload.get("envelope") {
            Some(v) if !v.is_null() => Ok(Some(serde_json::from_value(v.clone())?)),
            _ => Ok(None),
        }
    }

    /// Track one state feed (§18.3), in the order §9.6 makes normative:
    /// **subscribe to the feed subject first**, **then** read the current
    /// value. The subscription is established on this connection before the
    /// snapshot request departs, so a publish firing in the gap is delivered
    /// rather than lost; the worst case is a value seen twice, which a state
    /// feed absorbs by nature — each publish replaces the last.
    ///
    /// Returns the snapshot: the latest stored emit envelope, or `None` when
    /// the feed has never published — or when no feed-state service answered,
    /// because the snapshot is optional infrastructure and the stream is not
    /// (the same degradation [`AgentMesh::track_presence`] applies to its
    /// snapshot). `handler` then fires on every subsequent publish, through
    /// the same §22 pipeline as [`AgentMesh::subscribe_feed`]. The
    /// subscription lives until [`AgentMesh::close`].
    pub async fn track_feed<F>(&self, agent_id: &str, topic: &str, handler: F) -> Result<Option<Envelope>>
    where
        F: Fn(Value, Envelope) + Send + Sync + 'static,
    {
        // §9.6 MUST: the subscription first…
        self.subscribe_feed(agent_id, topic, handler).await?;
        // …then the snapshot. A mesh with no feed-state service leaves the
        // snapshot unknown and the stream authoritative.
        Ok(self.feed_value(agent_id, topic).await.ok().flatten())
    }

    /// Declare one of this agent's feeds (§6.6a), ahead of `register`: the
    /// next manifest this agent registers carries every declared feed's
    /// subject in its `emits` field (§8.2), which is what makes feeds
    /// discoverable through the registry like any other manifest fact. The
    /// topic is validated against the feed grammar here, where the operator
    /// can see the refusal. Declaring is advisory — publishing does not
    /// require it — and idempotent per topic (a re-declaration updates the
    /// kind).
    pub fn declare_feed(&self, topic: &str, kind: FeedKind) -> Result<()> {
        subjects::feed(self.agent_id_str(), topic)?;
        self.record_declared_feed(topic.to_string(), kind);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fixture's published owner key (`conformance/feeds.json`).
    const OWNER: &str = "UD3IZ2TLL7SK4WO7QRHMZS3IEUBPSN5XDCQOFB2XR2HG2PCMQBW2PDVF";

    #[test]
    fn feed_payload_is_topic_kind_data_and_never_the_domain_split() {
        let p = feed_payload("status", FeedKind::State, json!({ "level": "ok" }));
        assert_eq!(p, json!({ "topic": "status", "kind": "state", "data": { "level": "ok" } }));
        // The one member set, exactly — no domain/event_type smuggled in.
        assert_eq!(p.as_object().unwrap().len(), 3);
        assert!(p.get("domain").is_none());
        assert!(p.get("event_type").is_none());
    }

    #[test]
    fn declared_feed_validation_is_the_subject_grammar() {
        // `declare_feed` validates by building the subject
        // (`subjects::feed(own_key, topic)`), so the refusal set is exactly
        // the builder's: dotted, empty, wildcard, spaced, oversized.
        assert!(subjects::feed(OWNER, "status").is_ok());
        for bad in ["a.b", "", "*", "bad topic", &"a".repeat(129)] {
            assert!(subjects::feed(OWNER, bad).is_err(), "topic {bad:?} must refuse");
        }
        // The pattern form admits the single §6.7 wildcard and nothing else.
        assert_eq!(subjects::feed_pattern(OWNER, "*").unwrap(), format!("mesh.feed.{OWNER}.*"));
        assert!(subjects::feed_pattern(OWNER, "a.b").is_err());
    }

    #[test]
    fn a_built_subject_round_trips_through_parse() {
        let subject = subjects::feed(OWNER, "open-calls_v1").unwrap();
        let (agent, topic) = subjects::parse_feed_subject(&subject).unwrap();
        assert_eq!(agent, OWNER);
        assert_eq!(topic, "open-calls_v1");
        // The lookup subject has three tokens and is never a feed.
        assert_eq!(subjects::parse_feed_subject(subjects::FEED_GET), None);
    }

    #[test]
    fn the_feed_consumer_is_named_for_the_agent() {
        assert_eq!(subjects::feed_consumer(OWNER), format!("mesh_feed_{OWNER}"));
        // One consumer per agent: the name does not depend on any feed.
        assert!(!subjects::feed_consumer(OWNER).contains('.'));
    }

    #[test]
    fn feed_patterns_match_exactly_or_by_the_one_wildcard() {
        let status = subjects::feed(OWNER, "status").unwrap();
        let rounds = subjects::feed(OWNER, "rounds").unwrap();
        let all = subjects::feed_pattern(OWNER, "*").unwrap();
        assert!(feed_subject_matches(&status, &status));
        assert!(!feed_subject_matches(&status, &rounds));
        assert!(feed_subject_matches(&all, &status));
        assert!(feed_subject_matches(&all, &rounds));
        // Another owner's feed, a deeper subject, or a different prefix.
        let other = "UAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert!(!feed_subject_matches(&all, &format!("mesh.feed.{other}.status")));
        assert!(!feed_subject_matches(&all, &format!("mesh.feed.{OWNER}.status.x")));
        assert!(!feed_subject_matches(&all, &format!("mesh.event.{OWNER}.status")));
        // A wildcard is only a pattern, never a subject that matches one.
        assert!(!feed_subject_matches(&status, &all));
    }

    #[test]
    fn the_first_bind_creates_the_consumer_to_the_spec_pins() {
        use async_nats::jetstream::consumer::{AckPolicy, DeliverPolicy};
        let durable = subjects::feed_consumer(OWNER);
        let pattern = subjects::feed(OWNER, "status").unwrap();
        let c = feed_consumer_config(&durable, &pattern);
        assert_eq!(c.durable_name.as_deref(), Some(durable.as_str()));
        assert_eq!(c.ack_policy, AckPolicy::Explicit);
        assert_eq!(c.deliver_policy, DeliverPolicy::New);
        assert_eq!(c.ack_wait, Duration::from_secs(30));
        assert_eq!(c.max_deliver, 5);
        assert_eq!(c.filter_subjects, vec![pattern]);
        assert!(c.filter_subject.is_empty());
        assert_eq!(FEED_UNCLAIMED_NAK, Duration::from_secs(5));
    }

    #[test]
    fn a_later_bind_adds_its_filter_and_never_removes_one() {
        let a = "mesh.feed.X.a".to_string();
        let b = "mesh.feed.X.b".to_string();
        // Already there: no update.
        assert_eq!(feed_filters_with(std::slice::from_ref(&a), "", &a), None);
        assert_eq!(feed_filters_with(&[], &a, &a), None);
        // Added after the existing ones, which are kept in order.
        assert_eq!(feed_filters_with(std::slice::from_ref(&a), "", &b), Some(vec![a.clone(), b.clone()]));
        // A consumer made with the single filter_subject is carried over.
        assert_eq!(feed_filters_with(&[], &a, &b), Some(vec![a.clone(), b.clone()]));
        // A consumer with no filter at all gets exactly this one.
        assert_eq!(feed_filters_with(&[], "", &b), Some(vec![b]));
    }

    #[tokio::test]
    async fn stop_removes_only_its_own_handler_and_the_last_one_ends_the_loop() {
        let shared = std::sync::Arc::new(FeedDurableShared::default());
        let handlers: FeedHandlers = Default::default();
        let task = tokio::spawn(std::future::pending::<()>());
        *shared.state.lock().await =
            Some(FeedDurableLoop { handlers: handlers.clone(), task: task.abort_handle() });
        let h: FeedHandler = std::sync::Arc::new(|_, _| {});
        let sub = |subject: &str, id: u64| DurableFeedSubscription {
            durable: subjects::feed_consumer(OWNER),
            subject: subject.to_string(),
            id,
            shared: shared.clone(),
        };
        handlers.write().unwrap().insert("s.a".into(), (1, h.clone()));
        handlers.write().unwrap().insert("s.b".into(), (2, h.clone()));
        let a = sub("s.a", 1);
        assert_eq!(a.durable(), subjects::feed_consumer(OWNER));
        assert_eq!(a.subject(), "s.a");

        // A stale subscription (replaced on the same feed) removes nothing.
        sub("s.a", 99).stop().await;
        assert_eq!(handlers.read().unwrap().len(), 2);

        a.stop().await;
        assert_eq!(handlers.read().unwrap().len(), 1);
        assert!(shared.state.lock().await.is_some(), "one handler left, the loop runs on");

        sub("s.b", 2).stop().await;
        assert!(shared.state.lock().await.is_none(), "the last stop ends the loop");
        let ended = task.await;
        assert!(ended.unwrap_err().is_cancelled());
        // Stopping again after the loop is gone is harmless.
        a.stop().await;
    }

    #[test]
    fn feed_kind_speaks_lowercase_and_only_the_two_words() {
        assert_eq!(serde_json::to_value(FeedKind::State).unwrap(), json!("state"));
        assert_eq!(serde_json::to_value(FeedKind::Stream).unwrap(), json!("stream"));
        assert!(serde_json::from_value::<FeedKind>(json!("latest")).is_err());
        assert!(serde_json::from_value::<FeedKind>(json!("")).is_err());
    }
}
