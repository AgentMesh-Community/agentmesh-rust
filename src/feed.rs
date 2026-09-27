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
    fn feed_kind_speaks_lowercase_and_only_the_two_words() {
        assert_eq!(serde_json::to_value(FeedKind::State).unwrap(), json!("state"));
        assert_eq!(serde_json::to_value(FeedKind::Stream).unwrap(), json!("stream"));
        assert!(serde_json::from_value::<FeedKind>(json!("latest")).is_err());
        assert!(serde_json::from_value::<FeedKind>(json!("")).is_err());
    }
}
