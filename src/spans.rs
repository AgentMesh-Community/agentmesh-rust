//! Span completion events (SPEC.md §13.1.1). Parity with the TypeScript SDK's
//! `internal/spans.ts`.
//!
//! A mesh hop is one span. The sender closes a `producer` span when it has an
//! answer or a failure; the receiver closes a `consumer` span when it has
//! finished handling. Both carry the same `trace_id`, and the consumer is
//! parented under the producer, which is what makes a chain of agents read as
//! one trace instead of a pile of unrelated work.
//!
//! Two properties this module exists to hold:
//!
//! **Nothing about content can leak.** [`span_data`] builds its output field by
//! field from a typed input. There is no serialization of an envelope, no
//! pass-through of a payload, and nowhere to put a string somebody sent us.
//! Leaking a payload into a span would take a deliberate edit here.
//!
//! **No amounts.** Price, quoted totals and settled amounts are excluded even
//! though they are genuinely useful for debugging spend, because a span is
//! routinely exported into third-party tooling the counterparty never agreed
//! to. Commercial terms live in the agreement, the meter report and the
//! settlement record, all of which are addressed to the parties.
//!
//! Emission is off unless an operator turns it on. Propagation (§13.1) is
//! always on and costs nothing; producing a record of who you talked to is a
//! different act and wants a decision.

use serde_json::{json, Map, Value};

use crate::envelope::TraceContext;
use crate::error::MeshError;

/// Spans publish to their own subject tree, NOT the event bus: they are
/// telemetry about the mesh rather than application events, and a
/// `subscribe("trace.>")` consumer has no business receiving them. Matches the
/// `MESH_TRACE` stream's `mesh.trace.>` filter in §14.
pub fn trace_subject(agent_id: &str) -> String {
    format!("mesh.trace.{agent_id}")
}

/// Which side of the hop this span describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpanKind {
    Producer,
    Consumer,
}

impl SpanKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SpanKind::Producer => "producer",
            SpanKind::Consumer => "consumer",
        }
    }
}

/// How the operation ended. A closed set, so a collector can group on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpanOutcome {
    Ok,
    Error,
    Refused,
    Timeout,
    Canceled,
}

impl SpanOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            SpanOutcome::Ok => "ok",
            SpanOutcome::Error => "error",
            SpanOutcome::Refused => "refused",
            SpanOutcome::Timeout => "timeout",
            SpanOutcome::Canceled => "canceled",
        }
    }
}

/// Everything a span is allowed to know.
#[derive(Debug, Clone)]
pub struct SpanInput {
    pub trace: TraceContext,
    pub kind: SpanKind,
    pub agent_id: String,
    /// Which primitive this span covers (§3).
    pub operation: &'static str,
    /// The counterparty's handle or key. None for a broadcast.
    pub peer: Option<String>,
    /// The offering NAMED, never its input.
    pub offering: Option<String>,
    pub task_id: Option<String>,
    pub context_id: Option<String>,
    pub outcome: SpanOutcome,
    /// The closed-enum error code only. Never a remote party's free text.
    pub error_code: Option<String>,
    /// Epoch milliseconds.
    pub started_at: i64,
    pub ended_at: i64,
}

fn iso(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms)
        .unwrap_or_else(chrono::Utc::now)
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// The `data` of a `span_completed` event, built field by field.
///
/// Optional fields are OMITTED rather than set to null, so a span carries no
/// evidence of what it declined to say. A reader seeing `"offering": null`
/// learns there was a slot this hop refused to fill; absence says less, which
/// is the point.
pub fn span_data(s: &SpanInput) -> Value {
    let mut out = Map::new();
    out.insert("trace_id".into(), json!(s.trace.trace_id));
    out.insert("span_id".into(), json!(s.trace.span_id));
    out.insert("parent_span_id".into(), json!(s.trace.parent_span_id));
    out.insert("agent_id".into(), json!(s.agent_id));
    out.insert("kind".into(), json!(s.kind.as_str()));
    out.insert("operation".into(), json!(s.operation));
    out.insert("started_at".into(), json!(iso(s.started_at)));
    out.insert("ended_at".into(), json!(iso(s.ended_at)));
    out.insert("duration_ms".into(), json!((s.ended_at - s.started_at).max(0)));
    out.insert("status".into(), json!(s.outcome.as_str()));
    if let Some(o) = &s.offering {
        out.insert("offering".into(), json!(o));
    }
    if let Some(c) = &s.error_code {
        out.insert("error_code".into(), json!(c));
    }

    let mut tags = Map::new();
    if let Some(p) = &s.peer {
        tags.insert("peer".into(), json!(p));
    }
    if let Some(t) = &s.task_id {
        tags.insert("task_id".into(), json!(t));
    }
    if let Some(c) = &s.context_id {
        tags.insert("context_id".into(), json!(c));
    }
    if !tags.is_empty() {
        out.insert("tags".into(), Value::Object(tags));
    }

    Value::Object(out)
}

/// The emit payload wrapping a completed span.
pub fn span_payload(s: &SpanInput) -> Value {
    json!({ "domain": "trace", "event_type": "span_completed", "data": span_data(s) })
}

/// Map an error to the closed outcome set plus its code.
///
/// The variant is ours and travels; any message inside it may be text a
/// stranger wrote and never leaves this function.
pub fn outcome_of(err: &MeshError) -> (SpanOutcome, Option<String>) {
    // Only the variants that CARRY a code have one. A transport or json error
    // is an error with no closed-enum name, and inventing one for the span
    // would put a Rust type name in somebody's observability platform.
    let code: Option<&str> = match err {
        MeshError::Protocol { code, .. } => Some(code),
        MeshError::Refusal(obj) => Some(obj.code.as_str()),
        _ => None,
    };
    match code {
        Some(c @ ("TRANSPORT_TIMEOUT" | "TASK_TIMEOUT")) => (SpanOutcome::Timeout, Some(c.to_string())),
        Some(c @ ("TASK_CANCELED" | "CANCELED")) => (SpanOutcome::Canceled, Some(c.to_string())),
        Some(c @ ("REFUSED" | "ADMISSION_REFUSED" | "BUDGET_EXHAUSTED")) => {
            (SpanOutcome::Refused, Some(c.to_string()))
        }
        Some(c) => (SpanOutcome::Error, Some(c.to_string())),
        None => (SpanOutcome::Error, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::new_trace;

    fn input() -> SpanInput {
        SpanInput {
            trace: new_trace(),
            kind: SpanKind::Producer,
            agent_id: "UME".into(),
            operation: "request",
            peer: Some("UTHEM".into()),
            offering: Some("quote".into()),
            task_id: None,
            context_id: None,
            outcome: SpanOutcome::Ok,
            error_code: None,
            started_at: 1_700_000_000_000,
            ended_at: 1_700_000_000_250,
        }
    }

    #[test]
    fn carries_the_ids_the_parties_and_the_outcome() {
        let d = span_data(&input());
        assert_eq!(d["duration_ms"], 250);
        assert_eq!(d["status"], "ok");
        assert_eq!(d["kind"], "producer");
        assert_eq!(d["offering"], "quote");
        assert_eq!(d["tags"]["peer"], "UTHEM");
        assert_eq!(d["started_at"], "2023-11-14T22:13:20.000Z");
    }

    #[test]
    fn omits_what_it_has_nothing_to_say_about() {
        let mut i = input();
        i.offering = None;
        i.peer = None;
        let d = span_data(&i);
        assert!(d.get("offering").is_none());
        assert!(d.get("tags").is_none());
    }

    #[test]
    fn never_reports_a_negative_duration() {
        let mut i = input();
        i.started_at = 500;
        i.ended_at = 100;
        assert_eq!(span_data(&i)["duration_ms"], 0);
    }

    /// The refusals of §13.1.1, as a test that breaks if somebody adds a field.
    #[test]
    fn has_nowhere_to_put_content_or_money() {
        let s = span_data(&input()).to_string().to_lowercase();
        for content in ["input", "output", "payload", "artifact", "message", "\"text\"", "content"] {
            assert!(!s.contains(content), "a span must not carry {content}");
        }
        for money in ["price", "cost", "amount", "total", "currency", "xcr"] {
            assert!(!s.contains(money), "a span must not carry {money}");
        }
    }

    #[test]
    fn a_span_lives_off_the_event_bus() {
        assert_eq!(trace_subject("UME"), "mesh.trace.UME");
        assert!(!trace_subject("UME").contains("mesh.event"));
    }

    #[test]
    fn the_payload_names_itself() {
        let p = span_payload(&input());
        assert_eq!(p["domain"], "trace");
        assert_eq!(p["event_type"], "span_completed");
    }
}
