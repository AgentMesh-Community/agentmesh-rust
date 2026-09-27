//! The presence surface (SPEC.md §9.6): the `get_presence` snapshot and a
//! liveness tracker that obeys the section's one ordering MUST —
//! **subscribe before snapshot**.
//!
//! A transition that fires between a snapshot read and a later subscription
//! lands in the gap and is simply never seen: the consumer's stale entry looks
//! exactly like a quiet healthy one. [`AgentMesh::track_presence`] therefore
//! subscribes to the transition stream — the heartbeat subject (§10.10) and
//! the deployment's presence-change events (`mesh.event.presence.*`) —
//! **before** it reads the snapshot (`mesh.presence.get`), on the same
//! connection, whose command ordering makes the subscriptions live server-side
//! before the snapshot request departs. The worst case is then a transition
//! seen twice, which [`PresenceTracker`] absorbs by applying state
//! idempotently.

use std::sync::Mutex;
use std::time::Duration;

use futures::StreamExt;
use serde_json::{json, Value};

use crate::client::AgentMesh;
use crate::codec;
use crate::envelope::{Envelope, PrimitiveType};
use crate::error::{ErrorCode, MeshError, Result};
use crate::identity::sign_envelope;
use crate::manifest::Availability;
use crate::subjects;

/// How long the §9.6 snapshot read waits for a presence service. A mesh
/// without one answers no-responders immediately; this bounds the silent case.
const PRESENCE_GET_TIMEOUT: Duration = Duration::from_secs(5);

/// Milliseconds without a heartbeat before a tracked node is read as offline:
/// `2 * heartbeat_interval` (§9.6), the same threshold the reference presence
/// service sweeps on.
pub const PRESENCE_STALE_AFTER_MS: i64 = 60_000;

/// One node's liveness as presence reports it (§9.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodePresence {
    pub node: String,
    pub status: Availability,
    /// Milliseconds since the Unix epoch of the last heartbeat presence saw,
    /// when reported.
    pub last_seen: Option<i64>,
}

/// The idempotent state fold of §9.6's subscribe-before-snapshot pattern.
///
/// Two rules, each one half of the race the ordering MUST closes:
///
/// - a **transition** (a heartbeat, or a presence-change event) always
///   applies, but reports a change only when the status actually moved — so
///   the "worst case, seen twice" transition is absorbed silently;
/// - the **snapshot** applies only while no transition has been seen. The
///   subscription predates the snapshot read, so any transition already
///   observed is at least as fresh as the snapshot — a stale snapshot arriving
///   after a live transition must not roll the state back.
pub struct PresenceTracker {
    state: Mutex<TrackerState>,
}

struct TrackerState {
    status: Option<Availability>,
    transition_seen: bool,
}

impl PresenceTracker {
    pub fn new() -> PresenceTracker {
        PresenceTracker { state: Mutex::new(TrackerState { status: None, transition_seen: false }) }
    }

    /// Apply a live transition. `Some(status)` when the state moved (notify);
    /// `None` when it was already known — the twice-seen transition, absorbed.
    pub fn apply_transition(&self, status: Availability) -> Option<Availability> {
        let mut s = self.state.lock().unwrap();
        s.transition_seen = true;
        if s.status == Some(status) {
            return None;
        }
        s.status = Some(status);
        Some(status)
    }

    /// Apply the snapshot read. `Some(status)` when it establishes the state;
    /// `None` when a transition already did — the subscription is older than
    /// the snapshot, so what it delivered wins.
    pub fn apply_snapshot(&self, status: Availability) -> Option<Availability> {
        let mut s = self.state.lock().unwrap();
        if s.transition_seen || s.status == Some(status) {
            return None;
        }
        s.status = Some(status);
        Some(status)
    }

    /// The current folded status, if any source has reported one yet.
    pub fn status(&self) -> Option<Availability> {
        self.state.lock().unwrap().status
    }
}

impl Default for PresenceTracker {
    fn default() -> Self {
        PresenceTracker::new()
    }
}

/// Parse a §9.6 status string; unknown strings are `None` (never invented).
fn availability_of(v: Option<&Value>) -> Option<Availability> {
    serde_json::from_value(v?.clone()).ok()
}

impl AgentMesh {
    /// Read the §9.6 presence snapshot for a node (`get_presence`,
    /// request-reply on `mesh.presence.get`). An unknown node is `offline` —
    /// the same reading the reference store gives one.
    ///
    /// A consumer **tracking** liveness MUST NOT call this first and subscribe
    /// after: use [`AgentMesh::track_presence`], which owns the §9.6
    /// subscribe-before-snapshot ordering.
    pub async fn get_presence(&self, node: &str) -> Result<NodePresence> {
        let mut env = Envelope::new(PrimitiveType::Request, self.agent_id_str());
        env.payload = Some(json!({ "node": node }));
        let _ = sign_envelope(&mut env, &self.agent_kp());
        let resp = tokio::time::timeout(
            PRESENCE_GET_TIMEOUT,
            self.nats().request(subjects::PRESENCE_GET, codec::encode(&env)?.into()),
        )
        .await
        .map_err(|_| MeshError::code(ErrorCode::TransportTimeout, "presence service did not respond"))?
        .map_err(|e| MeshError::Transport(e.to_string()))?;
        let resp_env = codec::decode(&resp.payload)?;
        if let Some(err) = &resp_env.error {
            return Err(MeshError::from_error_object(err));
        }
        let payload = resp_env.payload.unwrap_or(Value::Null);
        let status = availability_of(payload.get("status"))
            .or_else(|| availability_of(payload.get("availability")))
            .unwrap_or(Availability::Offline);
        Ok(NodePresence {
            node: payload.get("node").and_then(Value::as_str).unwrap_or(node).to_string(),
            status,
            last_seen: payload.get("last_seen").and_then(Value::as_i64),
        })
    }

    /// Track a node's liveness (§9.6), in the order the section makes
    /// normative: **subscribe to the transition stream first** — the node's
    /// heartbeat subject (§10.10) and the presence-change events — **then**
    /// read the snapshot. Both subscriptions are established on this
    /// connection before the snapshot request is sent, so a transition firing
    /// in the gap is delivered rather than lost; the worst case is a
    /// transition seen twice, which the [`PresenceTracker`] fold absorbs.
    ///
    /// `on_transition` fires once with the initial state (from the snapshot,
    /// or from the first transition when no presence service answers — the
    /// snapshot is optional infrastructure, the stream is not) and then on
    /// every status change, including a local staleness verdict: a tracked
    /// node silent for [`PRESENCE_STALE_AFTER_MS`] is reported `offline`, the
    /// same `2 * heartbeat_interval` reading the presence service applies.
    ///
    /// Heartbeats are believed only from the node's own verified key
    /// (`env.from == node`, §10.10); a vouched agent heartbeating for its node
    /// is accepted by the presence *service*, which holds the vouch records
    /// this SDK does not, and reaches this tracker through the service's
    /// presence-change events instead. The subscriptions live until
    /// [`AgentMesh::close`].
    pub async fn track_presence<F>(&self, node: &str, on_transition: F) -> Result<()>
    where
        F: Fn(NodePresence) + Send + Sync + 'static,
    {
        // §9.6 MUST: the transition stream first…
        let mut heartbeats = self
            .nats()
            .subscribe(subjects::heartbeat(node))
            .await
            .map_err(|e| MeshError::Transport(e.to_string()))?;
        let mut events = self
            .nats()
            .subscribe(subjects::event("presence.*"))
            .await
            .map_err(|e| MeshError::Transport(e.to_string()))?;

        // …then the snapshot. A mesh with no presence service leaves the
        // snapshot unknown and the stream authoritative.
        let tracker = PresenceTracker::new();
        let snapshot = self.get_presence(node).await.ok();
        if let Some(snap) = &snapshot {
            if let Some(status) = tracker.apply_snapshot(snap.status) {
                on_transition(NodePresence { node: node.to_string(), status, last_seen: snap.last_seen });
            }
        }

        let node = node.to_string();
        let handle = tokio::spawn(async move {
            let mut last_heartbeat_at: Option<tokio::time::Instant> = None;
            let mut stale_check = tokio::time::interval(Duration::from_millis(
                (PRESENCE_STALE_AFTER_MS as u64) / 4,
            ));
            stale_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                let observed: Option<Availability> = tokio::select! {
                    msg = heartbeats.next() => {
                        let Some(msg) = msg else { break };
                        match codec::decode(&msg.payload) {
                            // §10.10: the heartbeat is believed for the node its
                            // VERIFIED sender is; the payload's `node` claim is not.
                            Ok(env) if env.from == node => {
                                last_heartbeat_at = Some(tokio::time::Instant::now());
                                Some(
                                    availability_of(
                                        env.payload.as_ref().and_then(|p| p.get("availability")),
                                    )
                                    .unwrap_or(Availability::Online),
                                )
                            }
                            _ => None,
                        }
                    }
                    msg = events.next() => {
                        let Some(msg) = msg else { break };
                        match codec::decode(&msg.payload) {
                            Ok(env) => presence_event_status(&env, &node),
                            Err(_) => None,
                        }
                    }
                    _ = stale_check.tick() => {
                        // §9.6: no heartbeat within 2 * heartbeat_interval means
                        // offline. Only judged from heartbeats this tracker saw.
                        match last_heartbeat_at {
                            Some(at)
                                if at.elapsed()
                                    >= Duration::from_millis(PRESENCE_STALE_AFTER_MS as u64) =>
                            {
                                Some(Availability::Offline)
                            }
                            _ => None,
                        }
                    }
                };
                if let Some(status) = observed {
                    if let Some(changed) = tracker.apply_transition(status) {
                        on_transition(NodePresence {
                            node: node.clone(),
                            status: changed,
                            last_seen: None,
                        });
                    }
                }
            }
        });
        self.track_task(handle);
        Ok(())
    }
}

/// What a `mesh.event.presence.*` envelope says about `node`'s status, if
/// anything: `node_online` / `node_offline` events carrying `data.node ==
/// node`. Anything else — another node's transition, another domain, a shape
/// this SDK does not know — is `None`.
fn presence_event_status(env: &Envelope, node: &str) -> Option<Availability> {
    let payload = env.payload.as_ref()?;
    if payload.get("domain").and_then(Value::as_str) != Some("presence") {
        return None;
    }
    if payload.get("data")?.get("node").and_then(Value::as_str) != Some(node) {
        return None;
    }
    match payload.get("event_type").and_then(Value::as_str)? {
        "node_online" => Some(Availability::Online),
        "node_offline" => Some(Availability::Offline),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_transition_seen_twice_is_absorbed() {
        // §9.6's stated worst case for subscribe-before-snapshot, absorbed by
        // applying state idempotently.
        let t = PresenceTracker::new();
        assert_eq!(t.apply_transition(Availability::Online), Some(Availability::Online));
        assert_eq!(t.apply_transition(Availability::Online), None, "the second sight is silent");
        assert_eq!(t.apply_transition(Availability::Offline), Some(Availability::Offline));
        assert_eq!(t.status(), Some(Availability::Offline));
    }

    #[test]
    fn a_stale_snapshot_cannot_roll_back_a_live_transition() {
        // The subscription predates the snapshot read, so a transition already
        // seen is at least as fresh as the snapshot: the snapshot must not win.
        let t = PresenceTracker::new();
        assert_eq!(t.apply_transition(Availability::Online), Some(Availability::Online));
        assert_eq!(t.apply_snapshot(Availability::Offline), None, "the stale snapshot is ignored");
        assert_eq!(t.status(), Some(Availability::Online));
    }

    #[test]
    fn the_snapshot_establishes_the_state_when_nothing_else_has() {
        let t = PresenceTracker::new();
        assert_eq!(t.apply_snapshot(Availability::Online), Some(Availability::Online));
        // A second identical snapshot (a re-read) is idempotent too.
        assert_eq!(t.apply_snapshot(Availability::Online), None);
        // …and a later real transition still moves it.
        assert_eq!(t.apply_transition(Availability::Offline), Some(Availability::Offline));
    }

    #[test]
    fn presence_events_speak_only_for_their_own_node_and_domain() {
        let mk = |payload: Value| {
            let mut env = Envelope::new(PrimitiveType::Emit, "USERVICE");
            env.payload = Some(payload);
            env
        };
        let online = mk(json!({ "domain": "presence", "event_type": "node_online", "data": { "node": "UNODE" } }));
        assert_eq!(presence_event_status(&online, "UNODE"), Some(Availability::Online));
        let offline = mk(json!({ "domain": "presence", "event_type": "node_offline", "data": { "node": "UNODE", "reason": "heartbeat_timeout" } }));
        assert_eq!(presence_event_status(&offline, "UNODE"), Some(Availability::Offline));
        // Another node's transition says nothing about ours.
        assert_eq!(presence_event_status(&online, "UOTHER"), None);
        // Another domain, or an unknown event type, is not a presence verdict.
        let other = mk(json!({ "domain": "scraping", "event_type": "node_online", "data": { "node": "UNODE" } }));
        assert_eq!(presence_event_status(&other, "UNODE"), None);
        let unknown = mk(json!({ "domain": "presence", "event_type": "node_flaky", "data": { "node": "UNODE" } }));
        assert_eq!(presence_event_status(&unknown, "UNODE"), None);
    }
}
