//! Small helpers: time-ordered IDs and trace contexts.

use chrono::Utc;
use uuid::Uuid;

use crate::envelope::TraceContext;

/// UUID v7 (time-ordered), matching the TS SDK's id scheme.
pub fn uuid7() -> String {
    Uuid::now_v7().to_string()
}

/// Current time as an RFC 3339 / ISO-8601 UTC string.
pub fn now_iso() -> String {
    Utc::now().to_rfc3339()
}

/// Random lowercase-hex id of `bytes` bytes (W3C Trace Context format, §13.1).
/// W3C forbids the all-zero id; a re-roll is astronomically rare.
fn rand_hex(bytes: usize) -> String {
    use rand::RngCore;
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    if buf.iter().all(|b| *b == 0) {
        return rand_hex(bytes);
    }
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

/// A fresh root trace context. Ids are W3C Trace Context format: 32 hex chars
/// for trace_id, 16 for span_id — the fields of a `traceparent` header.
pub fn new_trace() -> TraceContext {
    TraceContext {
        trace_id: rand_hex(16),
        span_id: rand_hex(8),
        parent_span_id: None,
        tracestate: None,
    }
}

/// W3C caps `tracestate` at 512 chars; longer is a header no HTTP hop would
/// carry, so it is either a mistake or someone padding our envelopes.
const MAX_TRACESTATE_LEN: usize = 512;

/// Whether a context is a well-formed W3C Trace Context (§13.1): 32/16
/// lowercase hex chars, neither all-zero (W3C forbids both), a
/// `parent_span_id` that is absent or itself a span id, and a `tracestate`
/// short enough to be real.
///
/// Inbound envelopes are deliberately NOT rejected over this. The trace is
/// bookkeeping rather than content, and a message is still worth delivering
/// with a broken one. What must not happen is COPYING it, which is what
/// [`child_span`] uses this for.
pub fn is_valid_trace_context(t: &TraceContext) -> bool {
    fn hex(s: &str, len: usize) -> bool {
        s.len() == len
            && s.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            && s.bytes().any(|b| b != b'0')
    }
    let parent_ok = match t.parent_span_id.as_deref() {
        None => true,
        Some(p) => hex(p, 16),
    };
    let tracestate_ok = match t.tracestate.as_deref() {
        None => true,
        Some(s) => s.len() <= MAX_TRACESTATE_LEN,
    };
    hex(&t.trace_id, 32) && hex(&t.span_id, 16) && parent_ok && tracestate_ok
}

/// A child span that preserves the trace (and tracestate) and links to the
/// parent span.
///
/// A parent that is not a valid context gets a FRESH ROOT rather than being
/// copied. Every propagation site reaches the wire through here, so this is
/// the one place that has to hold: a sender who supplies another party's
/// `trace_id` (or a megabyte of `tracestate`) would otherwise have it stamped
/// verbatim onto everything the receiving agent says next, merging its traffic
/// into someone else's trace in the history record. Losing the link on a
/// malformed trace is the correct failure; the alternative is a trace that
/// lies. Matches `childSpan` in the TypeScript SDK.
pub fn child_span(parent: &TraceContext) -> TraceContext {
    if !is_valid_trace_context(parent) {
        return new_trace();
    }
    TraceContext {
        trace_id: parent.trace_id.clone(),
        span_id: rand_hex(8),
        parent_span_id: Some(parent.span_id.clone()),
        tracestate: parent.tracestate.clone(),
    }
}

/// Render a context as a version-00 W3C `traceparent` header value.
pub fn to_traceparent(t: &TraceContext) -> String {
    format!("00-{}-{}-01", t.trace_id, t.span_id)
}

/// Build a mesh trace context from an inbound `traceparent` header: the
/// header's span becomes the parent, and the mesh operation gets a fresh span
/// in the same trace. Returns None if the header does not parse.
pub fn from_traceparent(traceparent: &str, tracestate: Option<&str>) -> Option<TraceContext> {
    let mut parts = traceparent.trim().splitn(4, '-');
    let (version, trace_id, span_id, flags) =
        (parts.next()?, parts.next()?, parts.next()?, parts.next()?);
    let is_hex = |s: &str, len: usize| s.len() == len && s.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase());
    if version != "00" || !is_hex(trace_id, 32) || !is_hex(span_id, 16) || !is_hex(flags, 2) {
        return None;
    }
    Some(TraceContext {
        trace_id: trace_id.to_string(),
        span_id: rand_hex(8),
        parent_span_id: Some(span_id.to_string()),
        tracestate: tracestate.map(str::to_string),
    })
}

/// The inbound dispatch an offering handler is running for — the basis of §10.8
/// cancel propagation. `task_id` is the inbound envelope's `task_id` when
/// present, else a fresh [`uuid7`] (the same rule the dispatcher uses for a
/// stream's task id); `offering` is the handler's registered offering name, which is
/// what per-handler [`HandlerOptions`](crate::client::HandlerOptions) are
/// looked up by at propagation time.
#[derive(Debug, Clone)]
pub(crate) struct DispatchContext {
    pub task_id: String,
    /// The inbound envelope's `context_id`, so usage the handler reports
    /// ([`crate::AgentMesh::report_usage`]) is accounted to the work's
    /// context (EXT-8 §2) without the handler naming it.
    pub context_id: Option<String>,
    pub offering: String,
    /// An admitted trial (Common Agent 7.7): usage the handler reports is
    /// metered as trial spend.
    pub trial: bool,
}

tokio::task_local! {
    /// The inbound envelope's trace, ambient while an offering handler runs
    /// (§13.1 automatic propagation).
    pub(crate) static CURRENT_TRACE: TraceContext;

    /// The inbound dispatch, ambient while an offering handler runs, so a
    /// sub-request the handler issues can be recorded as a delegation of the
    /// task being handled (§10.8 propagation).
    ///
    /// Same honest limitation as [`CURRENT_TRACE`]: a task-local is not
    /// inherited across `tokio::spawn`, so sub-requests issued from a task the
    /// handler spawned are not auto-tracked.
    pub(crate) static CURRENT_DISPATCH: DispatchContext;
}

/// A child of the ambient trace when a handler is running, else a fresh root.
pub(crate) fn ambient_child_or_new() -> TraceContext {
    CURRENT_TRACE.try_with(child_span).unwrap_or_else(|_| new_trace())
}

#[cfg(test)]
mod trace_tests {
    use super::*;

    fn is_hex(s: &str, len: usize) -> bool {
        s.len() == len && s.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    }

    #[test]
    fn w3c_id_formats() {
        let t = new_trace();
        assert!(is_hex(&t.trace_id, 32));
        assert!(is_hex(&t.span_id, 16));
        assert!(t.parent_span_id.is_none() && t.tracestate.is_none());
        let c = child_span(&t);
        assert_eq!(c.trace_id, t.trace_id);
        assert_eq!(c.parent_span_id.as_deref(), Some(t.span_id.as_str()));
        assert!(is_hex(&c.span_id, 16));
    }

    #[test]
    fn tracestate_carries_through_child_and_serialization_omits_when_absent() {
        let mut t = new_trace();
        t.tracestate = Some("vendor=abc".into());
        assert_eq!(child_span(&t).tracestate.as_deref(), Some("vendor=abc"));
        let plain = serde_json::to_string(&new_trace()).unwrap();
        assert!(!plain.contains("tracestate"));
        assert!(plain.contains("\"parent_span_id\":null"));
    }

    #[test]
    fn traceparent_round_trip() {
        let t = new_trace();
        let header = to_traceparent(&t);
        assert_eq!(header, format!("00-{}-{}-01", t.trace_id, t.span_id));
        let back = from_traceparent(&header, Some("vendor=abc")).unwrap();
        assert_eq!(back.trace_id, t.trace_id);
        assert_eq!(back.parent_span_id.as_deref(), Some(t.span_id.as_str()));
        assert_eq!(back.tracestate.as_deref(), Some("vendor=abc"));
        assert!(from_traceparent("garbage", None).is_none());
        assert!(from_traceparent("00-short-span-01", None).is_none());
    }

    /// The gate `childSpan` has had in TypeScript from the start: a parent
    /// nobody validated must not be copied onto this agent's own traffic.
    #[test]
    fn a_malformed_parent_yields_a_fresh_root_not_a_copy() {
        let good = new_trace();

        // Someone else's trace, or a hand-typed one, or a padded tracestate.
        let bad = [
            TraceContext { trace_id: "not-hex".into(), ..good.clone() },
            TraceContext { trace_id: "0".repeat(32), ..good.clone() },   // W3C forbids all-zero
            TraceContext { span_id: "0".repeat(16), ..good.clone() },
            TraceContext { trace_id: good.trace_id.to_uppercase(), ..good.clone() },
            TraceContext { trace_id: "a".repeat(31), ..good.clone() },
            TraceContext { parent_span_id: Some("nope".into()), ..good.clone() },
            TraceContext { tracestate: Some("x".repeat(MAX_TRACESTATE_LEN + 1)), ..good.clone() },
        ];
        for parent in &bad {
            assert!(!is_valid_trace_context(parent), "should be invalid: {parent:?}");
            let c = child_span(parent);
            assert_ne!(c.trace_id, parent.trace_id, "a bad trace_id must not be copied");
            assert!(c.parent_span_id.is_none(), "a fresh root has no parent");
            assert!(c.tracestate.is_none(), "a bad context's tracestate must not travel");
            assert!(is_hex(&c.trace_id, 32) && is_hex(&c.span_id, 16));
        }

        // The valid case still links, and a tracestate at the cap still rides.
        assert!(is_valid_trace_context(&good));
        assert_eq!(child_span(&good).trace_id, good.trace_id);
        let at_cap = TraceContext { tracestate: Some("x".repeat(MAX_TRACESTATE_LEN)), ..good.clone() };
        assert!(is_valid_trace_context(&at_cap));
        assert_eq!(child_span(&at_cap).tracestate, at_cap.tracestate);
    }

    #[tokio::test]
    async fn ambient_scope_makes_children_and_survives_await() {
        let inbound = new_trace();
        let inbound2 = inbound.clone();
        let env = CURRENT_TRACE
            .scope(inbound.clone(), async move {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                let e = crate::envelope::Envelope::new(
                    crate::envelope::PrimitiveType::Request,
                    "UAGENT",
                );
                assert_eq!(e.trace.trace_id, inbound2.trace_id);
                assert_eq!(e.trace.parent_span_id.as_deref(), Some(inbound2.span_id.as_str()));
                e
            })
            .await;
        assert_ne!(env.trace.span_id, inbound.span_id);
        // Outside the scope: fresh root.
        let root = crate::envelope::Envelope::new(crate::envelope::PrimitiveType::Request, "UAGENT");
        assert_ne!(root.trace.trace_id, inbound.trace_id);
        assert!(root.trace.parent_span_id.is_none());
    }
}
