//! The accept signal (SPEC.md §6.4a) — the non-terminal `respond` a
//! responder's SDK emits the moment a live handler **admits** a request, and
//! the caller-side recognition of it and of the node-level **queued
//! acknowledgement** it must never be confused with.
//!
//! The two signals certify different things, and the distinction is the whole
//! module:
//!
//!  - **`"accepted"`** means a handler will run *now*: the §22 inbound checks
//!    and §7.7 budget admission passed, and the responder's SDK says so before
//!    invoking the handler — so a caller facing a cold agent's multi-second
//!    first token is no longer waiting blind. It resets the caller's response
//!    timeout and resolves nothing: the request stays outstanding until the
//!    first `respond` whose `payload.status` is not `"accepted"` (§7.0's
//!    first-substantive-respond rule).
//!  - **`queued`** means a mailbox holds the message (§16.4): no handler ran,
//!    nothing was admitted — the reference adapter answers the identical shape
//!    whether the message was queued, held for review, or refused — and the
//!    real reply arrives later at the sender's own inbox, correlated by
//!    `in_reply_to`.
//!
//! Wire shape pinned by `conformance/accept-signal.json`, which is the
//! authority on §22.8's terms: when this module and the fixture disagree, this
//! module is what changes.

use serde_json::{json, Value};

use crate::envelope::{Envelope, PrimitiveType};
use crate::util::child_span;

/// The `payload.status` value of an accept signal (§6.4a). Not a Task state
/// (§7.2): it never appears in a Task record.
pub const ACCEPTED_STATUS: &str = "accepted";

/// Build the (unsigned) accept signal for an admitted request (§6.4a):
/// a non-terminal `respond` with `payload.status: "accepted"`, `in_reply_to`
/// the admitted request's id, and `task_id` `None` — absent on the wire per
/// §5.3's absent-members rule; the accept never creates a Task.
///
/// The caller signs it and publishes it on the request's reply subject
/// **before** invoking the handler. Refusals of admission are sent *instead
/// of* this envelope, never after it.
pub fn accept_envelope(agent_id: &str, request: &Envelope) -> Envelope {
    let mut env = Envelope::new(PrimitiveType::Respond, agent_id);
    env.to = Some(request.from.clone());
    env.in_reply_to = Some(request.id.clone());
    env.trace = child_span(&request.trace);
    env.payload = Some(json!({ "status": ACCEPTED_STATUS }));
    env
}

/// Whether a decoded reply envelope is the §6.4a accept signal.
///
/// True only for a `respond` with `payload.status: "accepted"` and no
/// `error`. A requester's SDK MUST NOT treat such an envelope as the
/// substantive reply: the request completes on the first `respond` whose
/// `payload.status` is **not** `"accepted"` — which is also why anything that
/// fails this predicate is, to the waiting caller, substantive.
pub fn is_accept_signal(env: &Envelope) -> bool {
    env.kind == PrimitiveType::Respond
        && env.error.is_none()
        && env
            .payload
            .as_ref()
            .and_then(|p| p.get("status"))
            .and_then(Value::as_str)
            == Some(ACCEPTED_STATUS)
}

/// The node-level queued acknowledgement (§6.4a, §16.4), as recognized in a
/// reply's payload: a mailbox holds the message for an attended session to
/// drain, and the real reply will arrive at the sender's own inbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedAck {
    /// The held message's inbox id, when the ack carried one (the fixture pins
    /// it present and non-empty; recognition tolerates its absence).
    pub inbox_id: Option<String>,
}

/// Recognize the queued ack in a reply payload (§6.4a's buffered-path
/// convention). `queued` must be boolean `true` — never a string — either at
/// the payload's top level or under `output`, which is where a node built on
/// an SDK request handler carries it (the handler's return value becomes
/// `payload.output`).
///
/// Like the accept, a queued ack never resolves the request: it certifies
/// delivery to a held mailbox only — deliberately not admission.
pub fn queued_ack_of(payload: Option<&Value>) -> Option<QueuedAck> {
    let payload = payload?;
    let spot = if payload.get("queued") == Some(&Value::Bool(true)) {
        payload
    } else {
        let output = payload.get("output")?;
        if output.get("queued") == Some(&Value::Bool(true)) { output } else { return None }
    };
    let inbox_id = spot
        .get("inbox_id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    Some(QueuedAck { inbox_id })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn respond_with(payload: Value) -> Envelope {
        let mut env = Envelope::new(PrimitiveType::Respond, "URESPONDER");
        env.payload = Some(payload);
        env
    }

    #[test]
    fn the_accept_is_shaped_exactly_as_6_4a_requires() {
        let mut req = Envelope::new(PrimitiveType::Request, "UREQUESTER");
        req.to = Some("URESPONDER".to_string());
        let acc = accept_envelope("URESPONDER", &req);
        assert_eq!(acc.kind, PrimitiveType::Respond);
        assert_eq!(acc.to.as_deref(), Some("UREQUESTER"));
        assert_eq!(acc.in_reply_to.as_deref(), Some(req.id.as_str()));
        // task_id: null at the API, absent on the wire (§5.3) — the accept
        // never creates a Task.
        assert!(acc.task_id.is_none());
        let wire = serde_json::to_value(&acc).unwrap();
        assert!(wire.get("task_id").is_none(), "task_id must be ABSENT on the wire");
        assert_eq!(wire["payload"], json!({ "status": "accepted" }));
        assert!(is_accept_signal(&acc));
    }

    #[test]
    fn only_a_clean_accepted_respond_is_an_accept() {
        assert!(is_accept_signal(&respond_with(json!({ "status": "accepted" }))));
        // Substantive statuses are not accepts — they complete the request.
        for status in ["completed", "failed", "working", "submitted", "input_required"] {
            assert!(!is_accept_signal(&respond_with(json!({ "status": status }))));
        }
        // An error envelope is a substantive reply whatever its status says.
        let mut err = respond_with(json!({ "status": "accepted" }));
        err.error = Some(crate::error::ErrorObject {
            code: "INTERNAL_ERROR".into(),
            message: "boom".into(),
            details: None,
            retryable: false,
            retry_after_ms: None,
        });
        assert!(!is_accept_signal(&err));
        // A request is never an accept, whatever its payload claims.
        let mut req = Envelope::new(PrimitiveType::Request, "U");
        req.payload = Some(json!({ "status": "accepted" }));
        assert!(!is_accept_signal(&req));
    }

    #[test]
    fn the_queued_ack_is_boolean_true_never_a_string() {
        // The fixture's pinned points: `queued` is boolean true, `inbox_id`
        // present and non-empty, `text` informative only.
        let ack = queued_ack_of(Some(&json!({
            "queued": true, "inbox_id": "inb-1", "text": "held for the operator"
        })))
        .expect("recognized");
        assert_eq!(ack.inbox_id.as_deref(), Some("inb-1"));
        // A node built on a request handler answers it under `output`.
        let wrapped = queued_ack_of(Some(&json!({
            "status": "completed", "output": { "queued": true, "inbox_id": "inb-2" }
        })))
        .expect("recognized under output");
        assert_eq!(wrapped.inbox_id.as_deref(), Some("inb-2"));
        // Truthy-but-not-true is not a queued ack.
        assert!(queued_ack_of(Some(&json!({ "queued": "true", "inbox_id": "x" }))).is_none());
        assert!(queued_ack_of(Some(&json!({ "queued": 1 }))).is_none());
        assert!(queued_ack_of(Some(&json!({ "status": "completed" }))).is_none());
        assert!(queued_ack_of(None).is_none());
        // An empty inbox_id is tolerated as recognition but not reported as an id.
        let empty = queued_ack_of(Some(&json!({ "queued": true, "inbox_id": "" }))).unwrap();
        assert_eq!(empty.inbox_id, None);
    }
}
