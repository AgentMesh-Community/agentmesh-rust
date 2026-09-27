//! The message envelope (AgentMesh 0.2 §5) — the wire format for every
//! primitive. Includes the 0.2 `sig` field (per-agent signature, §4.5).

use serde::{Deserialize, Serialize};

use crate::error::ErrorObject;

/// The protocol version every envelope this SDK mints is stamped with (`v`).
/// Receivers compare the MAJOR component only (`codec::decode`), so 0.3 peers
/// interoperate across minor/patch drift; 0.3.0 is the flag day that also
/// closed the untagged-signature window (§5.3).
pub const PROTOCOL_VERSION: &str = "0.3.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PrimitiveType {
    Register,
    Discover,
    Request,
    Respond,
    Emit,
    Subscribe,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceContext {
    pub trace_id: String,
    pub span_id: String,
    /// Serialized as `null` when absent (NOT omitted) to match the TS SDK's
    /// trace context exactly — the canonical-JSON signing must byte-match, and
    /// TS emits `parent_span_id: null`. Do not add skip_serializing_if here.
    #[serde(default)]
    pub parent_span_id: Option<String>,
    /// W3C `tracestate`, carried verbatim (§13.1). OMITTED when absent — the
    /// TS SDK leaves the key out entirely, and signing must byte-match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tracestate: Option<String>,
}

/// The standard envelope. Optional fields are omitted from the wire when unset
/// (matching the TS SDK), which is also what canonical signing relies on.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub v: String,
    pub id: String,
    #[serde(rename = "type")]
    pub kind: PrimitiveType,
    pub ts: String,
    pub from: String,
    pub trace: TraceContext,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_reply_to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    /// The sender's budget for the work this message initiates or revises
    /// (§5.2, §7.7): an absolute deadline, a monotonic revision counter, and
    /// (with the Economics extension, §19.3) a cost ceiling. Meaningful on
    /// `request` and on budget revisions; ignored elsewhere. OMITTED when
    /// absent, like every optional field here — the canonical signing base
    /// (§5.3) must never see a `null` the TS SDK leaves out.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget: Option<crate::budget::Budget>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorObject>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifacts: Option<Vec<serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<serde_json::Value>,
    /// Ed25519 signature over the canonical envelope (all fields except `sig`)
    /// by the `from` agent's key (§4.5). Required on the wire in 0.2.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
}

impl Envelope {
    /// A new unsigned envelope with `v`/`id`/`ts`/`trace` auto-filled. Set any
    /// optional fields, then sign it (see `identity::sign_envelope`).
    pub fn new(kind: PrimitiveType, from: impl Into<String>) -> Self {
        Envelope {
            v: PROTOCOL_VERSION.to_string(),
            id: crate::util::uuid7(),
            kind,
            ts: crate::util::now_iso(),
            from: from.into(),
            trace: crate::util::ambient_child_or_new(),
            to: None,
            task_id: None,
            in_reply_to: None,
            context_id: None,
            budget: None,
            error: None,
            payload: None,
            artifacts: None,
            meta: None,
            sig: None,
        }
    }
}
