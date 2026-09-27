//! Cancel (SPEC.md §10.8) — reasoned cancellation and upstream propagation.
//!
//! A cancel travels **twice**, and both shapes are pinned byte-for-byte in
//! `conformance/cancel.json`:
//!
//!  1. the `task.cancel` REQUEST to the performer's inbox, whose
//!     `payload.input` carries `task_id` + `reason` + optional `note`
//!     ([`cancel_request_payload`]); and
//!  2. the canceled TASK UPDATE — a `respond` on `mesh.task.{task_id}.update`
//!     with `payload.status: "canceled"` and the same `reason` + optional
//!     `note` alongside it ([`canceled_update_payload`]).
//!
//! For the requester, cancellation is **effective when sent**: the update
//! publish is the record, and the inbox request is best-effort notification —
//! the performer may be offline with the cancel sitting in its mailbox, and
//! that is the mesh working, not a violation (§10.8 deliberately bounds no
//! acknowledgement).
//!
//! What lives here:
//!
//!  - [`CancelReason`] — the CLOSED eight-value enum. `reason` is REQUIRED on
//!    a cancel, the strings are exact wire bytes, and a cancel whose reason is
//!    missing or unknown is rejected as `INVALID_ENVELOPE` — never recorded,
//!    never case-folded.
//!  - [`StopQualifier`] — §10.8's two fields that qualify a reason:
//!    `unmet_need` (REQUIRED with `needs_not_furnished`, refused with anything
//!    else) and `dependency` (optional with `dependency_failed`, refused with
//!    anything else).
//!  - [`failed_update_payload`] — the same vocabulary ending a `failed` Task,
//!    where the reason is OPTIONAL: a Task that simply did not work out is a
//!    complete statement, and a responder is never forced to invent an excuse.
//!  - [`validate_cancel_input`] — the accept-or-say-why door judgement for an
//!    inbound `task.cancel` input, in the style of
//!    [`Budget::validate`](crate::budget::Budget::validate).
//!  - [`propagated_cancel_note`] — the pinned note format for forwarding a
//!    cancel to a delegate: reason `upstream_cancelled`, with the ORIGINAL
//!    reason carried in the note.
//!  - [`TERMINAL_TASK_STATES`] / [`is_terminal_task_state`] — which §7.3
//!    states end a Task. A cancel may reach a Task in any non-terminal state
//!    (the §7.7 pauses included); a terminal state that arrived first stands
//!    (`TASK_NOT_CANCELABLE`).
//!
//! The `note` is OPTIONAL free text and is OMITTED when absent, never `null`
//! — the enum, not the note, is what the record carries as meaning.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::error::{ErrorCode, MeshError, Result};

/// The offering name a cancel request travels under (§10.8):
/// `payload.offering: "task.cancel"`.
pub const CANCEL_OFFERING: &str = "task.cancel";

/// The §7.3 states a Task cannot leave. A cancel arriving for a Task already
/// in one of these is refused with `TASK_NOT_CANCELABLE` — the state that
/// arrived first stands; every other state (the §7.7 pauses included) may
/// cancel. Pinned against `conformance/cancel.json` `transitions`.
///
/// `exhausted` comes from Agent SoW §5.5.5 (<https://agentsow.com>): under a
/// time and materials arrangement, a task in flight when the engagement's
/// not-to-exceed cap is reached ends `exhausted`, with whatever artifacts exist
/// attached, billed no further than the cap. It is terminal and it is NOT a
/// failure — a runtime MUST NOT record an exhausted task as failed.
pub const TERMINAL_TASK_STATES: [&str; 5] =
    ["completed", "failed", "canceled", "rejected", "exhausted"];

/// Whether a task `status` string is one of the [`TERMINAL_TASK_STATES`].
pub fn is_terminal_task_state(status: &str) -> bool {
    TERMINAL_TASK_STATES.contains(&status)
}

/// The §10.8 reason. REQUIRED on every cancel and OPTIONAL on a failure, from
/// this CLOSED enum: the eight strings are exact wire bytes
/// (`conformance/cancel.json`), there is no case folding, and a receiver
/// rejects anything else as `INVALID_ENVELOPE`. `deadline_exceeded` and
/// `budget_exhausted` deliberately reuse the §12.2 vocabulary so a cancel
/// after an overdue mark or a budget pause reads consistently with the budget
/// lifecycle (§7.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CancelReason {
    /// A human, or the requesting agent's own logic, decided the work is no
    /// longer wanted.
    UserRequested,
    /// A newer request replaces this one; the answer would be discarded even
    /// if delivered.
    Superseded,
    /// The budget's deadline (§7.7) passed and the requester chose to stop
    /// rather than keep listening.
    DeadlineExceeded,
    /// The cost ceiling was reached (§7.7 pause) and the requester chose to
    /// cancel rather than raise the budget.
    BudgetExhausted,
    /// The canceling agent's own Task was canceled and it is forwarding the
    /// cancellation to a delegate ([`propagated_cancel_note`]).
    ///
    /// British spelling on the wire — `upstream_cancelled`, two l's — which
    /// the variant name produces under `rename_all = "snake_case"` and a unit
    /// test pins.
    UpstreamCancelled,
    /// An operator or policy layer terminated the work on content,
    /// permission, or tenancy grounds.
    Policy,
    /// The caller did not furnish something the offering declared under
    /// `needs` (§8.5.1): the resource never granted, the file never attached,
    /// the sign-in never given or no longer valid. REQUIRES
    /// [`StopQualifier::unmet_need`], because a claim about the caller that
    /// names nothing is an assertion and not evidence (§10.8a).
    NeedsNotFurnished,
    /// An outside service the responder depends on, and SHOULD have declared
    /// under `works_with` (§8.8), stopped working. Still the PROVIDER's
    /// failure (§10.8a): the provider chose the dependency. The separate
    /// reason buys legibility, not absolution.
    DependencyFailed,
}

impl CancelReason {
    /// The exact wire string.
    pub fn as_str(self) -> &'static str {
        match self {
            CancelReason::UserRequested => "user_requested",
            CancelReason::Superseded => "superseded",
            CancelReason::DeadlineExceeded => "deadline_exceeded",
            CancelReason::BudgetExhausted => "budget_exhausted",
            CancelReason::UpstreamCancelled => "upstream_cancelled",
            CancelReason::Policy => "policy",
            CancelReason::NeedsNotFurnished => "needs_not_furnished",
            CancelReason::DependencyFailed => "dependency_failed",
        }
    }

    /// Parse an exact wire string; `None` for anything outside the closed
    /// enum, including a case variant — the strings are bytes, not words.
    pub fn from_wire(s: &str) -> Option<CancelReason> {
        match s {
            "user_requested" => Some(CancelReason::UserRequested),
            "superseded" => Some(CancelReason::Superseded),
            "deadline_exceeded" => Some(CancelReason::DeadlineExceeded),
            "budget_exhausted" => Some(CancelReason::BudgetExhausted),
            "upstream_cancelled" => Some(CancelReason::UpstreamCancelled),
            "policy" => Some(CancelReason::Policy),
            "needs_not_furnished" => Some(CancelReason::NeedsNotFurnished),
            "dependency_failed" => Some(CancelReason::DependencyFailed),
            _ => None,
        }
    }
}

/// The §8.5.1 need kinds, which are also the prefixes of an `unmet_need`
/// reference.
pub const NEED_KINDS: [&str; 4] = ["resource", "file", "credential", "text"];

/// Split a valid `unmet_need` reference (§10.8) into its kind and value, or
/// `None` when it is malformed. The format is `"<kind>:<value>"` with kind
/// from [`NEED_KINDS`] — `"credential:Salesforce"`, `"resource:git-repo"`,
/// `"file:application/pdf"`. Split at the FIRST colon only: a value may
/// contain colons of its own.
pub fn parse_unmet_need_ref(value: &str) -> Option<(&str, &str)> {
    let at = value.find(':')?;
    if at == 0 || at + 1 >= value.len() {
        return None;
    }
    let (kind, rest) = value.split_at(at);
    if !NEED_KINDS.contains(&kind) {
        return None;
    }
    Some((kind, &rest[1..]))
}

/// Whether a string is a well-formed `unmet_need` reference (§10.8).
pub fn is_unmet_need_ref(value: &str) -> bool {
    parse_unmet_need_ref(value).is_some()
}

/// The `unmet_need` reference a §8.5.1 need entry answers to, or `None` for an
/// entry naming no kind this vocabulary knows. The value is taken verbatim, so
/// the comparison a platform makes is between two strings the manifest and the
/// failing agent both wrote.
pub fn need_ref_of(need: &Value) -> Option<String> {
    let obj = need.as_object()?;
    for kind in NEED_KINDS {
        if let Some(value) = obj.get(kind).and_then(Value::as_str) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return Some(format!("{kind}:{trimmed}"));
            }
        }
    }
    None
}

/// §10.8's two fields that qualify a reason. Each is meaningful with exactly
/// one reason and refused with every other: `unmet_need` is REQUIRED with
/// [`CancelReason::NeedsNotFurnished`], `dependency` is optional with
/// [`CancelReason::DependencyFailed`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StopQualifier {
    /// Which declared need (§8.5.1) the caller did not furnish, as
    /// `"<kind>:<value>"`. Whether the need was really declared is the
    /// PLATFORM's question, not the sender's (§10.8a).
    pub unmet_need: Option<String>,
    /// The outside service that stopped working, named the way §8.8 names it.
    pub dependency: Option<String>,
}

impl StopQualifier {
    /// A qualifier naming the declared need the caller did not furnish.
    pub fn unmet_need(need: impl Into<String>) -> StopQualifier {
        StopQualifier { unmet_need: Some(need.into()), dependency: None }
    }

    /// A qualifier naming the outside service that broke.
    pub fn dependency(service: impl Into<String>) -> StopQualifier {
        StopQualifier { unmet_need: None, dependency: Some(service.into()) }
    }

    fn is_empty(&self) -> bool {
        self.unmet_need.is_none() && self.dependency.is_none()
    }
}

/// Check a reason against its qualifier (§10.8), the accept-or-say-why door
/// every producer of a canceled or failed update goes through. `None` for
/// `reason` is a bare failure, which may carry neither qualifier.
pub fn validate_stop_qualifier(
    reason: Option<CancelReason>,
    qualifier: Option<&StopQualifier>,
) -> Result<()> {
    let empty = StopQualifier::default();
    let q = qualifier.unwrap_or(&empty);
    match reason {
        Some(CancelReason::NeedsNotFurnished) => {
            let Some(need) = q.unmet_need.as_deref() else {
                return Err(MeshError::code(
                    ErrorCode::InvalidEnvelope,
                    "needs_not_furnished requires unmet_need — a claim about the caller that \
                     names nothing is an assertion, not evidence (§10.8a)",
                ));
            };
            if !is_unmet_need_ref(need) {
                return Err(MeshError::code(
                    ErrorCode::InvalidEnvelope,
                    format!(
                        "unmet_need must be '<kind>:<value>' with kind one of {} (§8.5.1), \
                         not '{need}'",
                        NEED_KINDS.join(", ")
                    ),
                ));
            }
        }
        _ if q.unmet_need.is_some() => {
            return Err(MeshError::code(
                ErrorCode::InvalidEnvelope,
                "unmet_need is meaningful only with needs_not_furnished (§10.8)",
            ))
        }
        _ => {}
    }
    match reason {
        Some(CancelReason::DependencyFailed) => {
            if let Some(service) = q.dependency.as_deref() {
                if service.trim().is_empty() {
                    return Err(MeshError::code(
                        ErrorCode::InvalidEnvelope,
                        "dependency, when present, is a non-empty string naming the service",
                    ));
                }
            }
        }
        _ if q.dependency.is_some() => {
            return Err(MeshError::code(
                ErrorCode::InvalidEnvelope,
                "dependency is meaningful only with dependency_failed (§10.8)",
            ))
        }
        _ => {}
    }
    Ok(())
}

impl std::str::FromStr for CancelReason {
    type Err = MeshError;
    fn from_str(s: &str) -> Result<CancelReason> {
        CancelReason::from_wire(s).ok_or_else(|| {
            MeshError::code(
                ErrorCode::InvalidEnvelope,
                format!("'{s}' is not a cancel reason — the §10.8 enum is closed"),
            )
        })
    }
}

/// The pinned note a PROPAGATED cancel carries (§10.8, fixture
/// `propagation.cases`): forwarding a cancel to a delegate uses reason
/// [`CancelReason::UpstreamCancelled`] and puts the ORIGINAL reason in the
/// note — the original reason string alone when the original cancel had no
/// note, else the original reason, `: ` (colon space), then the original
/// note. Both SDKs must produce these exact bytes.
///
/// Propagation composes: a two-hop chain nests
/// (`"upstream_cancelled: user_requested"`), and the reason stays
/// `upstream_cancelled` at every hop.
pub fn propagated_cancel_note(reason: CancelReason, note: Option<&str>) -> String {
    match note {
        Some(note) => format!("{}: {note}", reason.as_str()),
        None => reason.as_str().to_string(),
    }
}

/// A validated inbound `task.cancel` input (§10.8): the fields of
/// `payload.input`, typed. Produced only by [`validate_cancel_input`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancelInput {
    /// The Task being canceled.
    pub task_id: String,
    /// Why — from the closed enum, exact bytes.
    pub reason: CancelReason,
    /// OPTIONAL free text for humans; the enum, not the note, carries the
    /// meaning. Omitted on the wire when absent, never `null`.
    pub note: Option<String>,
    /// §10.8's qualifying fields, validated against the reason.
    pub qualifier: StopQualifier,
}

/// Validate the input of an inbound `task.cancel` request (§10.8), in the
/// accept-or-say-why style of [`Budget::validate`](crate::budget::Budget::validate):
/// `task_id` (a non-empty string) + `reason` (from the CLOSED enum) +
/// optional `note` (a string when present — never `null`, never a number).
/// Every refusal is `INVALID_ENVELOPE`, judged at the door before any state
/// is touched; the reject cases are pinned in `conformance/cancel.json`
/// `invalid.cases`.
pub fn validate_cancel_input(input: &Value) -> Result<CancelInput> {
    let Some(obj) = input.as_object() else {
        return Err(MeshError::code(
            ErrorCode::InvalidEnvelope,
            "A task.cancel input must be an object carrying task_id + reason (§10.8)",
        ));
    };
    let task_id = match obj.get("task_id").and_then(Value::as_str) {
        Some(t) if !t.is_empty() => t.to_string(),
        _ => {
            return Err(MeshError::code(
                ErrorCode::InvalidEnvelope,
                "A task.cancel input must name the task: task_id is a required string (§10.8)",
            ))
        }
    };
    let reason = match obj.get("reason") {
        None | Some(Value::Null) => {
            return Err(MeshError::code(
                ErrorCode::InvalidEnvelope,
                "reason is REQUIRED on every cancel — absent is omitted, never null (§10.8)",
            ))
        }
        Some(Value::String(s)) => CancelReason::from_wire(s).ok_or_else(|| {
            MeshError::code(
                ErrorCode::InvalidEnvelope,
                format!(
                    "'{s}' is not a cancel reason — the §10.8 enum is closed and the strings \
                     are exact bytes"
                ),
            )
        })?,
        Some(other) => {
            return Err(MeshError::code(
                ErrorCode::InvalidEnvelope,
                format!("reason must be one of the six §10.8 strings, not {other}"),
            ))
        }
    };
    let note = match obj.get("note") {
        None => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(other) => {
            return Err(MeshError::code(
                ErrorCode::InvalidEnvelope,
                format!("note, when present, is a string (§10.8), not {other}"),
            ))
        }
    };
    let qualifier = StopQualifier {
        unmet_need: string_field(obj.get("unmet_need"), "unmet_need")?,
        dependency: string_field(obj.get("dependency"), "dependency")?,
    };
    validate_stop_qualifier(Some(reason), Some(&qualifier))?;
    Ok(CancelInput { task_id, reason, note, qualifier })
}

fn string_field(value: Option<&Value>, field: &str) -> Result<Option<String>> {
    match value {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(other) => Err(MeshError::code(
            ErrorCode::InvalidEnvelope,
            format!("{field}, when present, is a string (§10.8), not {other}"),
        )),
    }
}

/// Fold a reason's qualifying fields into a payload object, omitting each
/// when absent (never `null`).
fn apply_qualifier(target: &mut Value, qualifier: Option<&StopQualifier>) {
    let Some(q) = qualifier.filter(|q| !q.is_empty()) else { return };
    if let Some(need) = &q.unmet_need {
        target["unmet_need"] = json!(need);
    }
    if let Some(service) = &q.dependency {
        target["dependency"] = json!(service);
    }
}

/// The `task.cancel` REQUEST payload (§10.8 leg 1, fixture
/// `shapes.cancel_request_payload`): `offering` + `input.task_id` +
/// `input.reason` + optional `input.note`, which is OMITTED when absent —
/// never `null`. `qualifier` adds §10.8's `unmet_need` / `dependency` when the
/// reason takes one.
pub fn cancel_request_payload(
    task_id: &str,
    reason: CancelReason,
    note: Option<&str>,
    qualifier: Option<&StopQualifier>,
) -> Value {
    let mut input = json!({ "task_id": task_id, "reason": reason.as_str() });
    if let Some(note) = note {
        input["note"] = json!(note);
    }
    apply_qualifier(&mut input, qualifier);
    json!({ "offering": CANCEL_OFFERING, "input": input })
}

/// The canceled TASK UPDATE payload (§10.8 leg 2, fixture
/// `shapes.canceled_update_payload`): a `respond` on
/// `mesh.task.{task_id}.update` whose payload is `status: "canceled"` with
/// the same `reason` + optional `note` alongside it — the note OMITTED when
/// absent, never `null`. This is what the task manager records.
pub fn canceled_update_payload(
    reason: CancelReason,
    note: Option<&str>,
    qualifier: Option<&StopQualifier>,
) -> Value {
    let mut payload = json!({ "status": "canceled", "reason": reason.as_str() });
    if let Some(note) = note {
        payload["note"] = json!(note);
    }
    apply_qualifier(&mut payload, qualifier);
    payload
}

/// The failed TASK UPDATE payload (§10.8, fixture
/// `shapes.failed_update_payload`): a `respond` on
/// `mesh.task.{task_id}.update` whose payload is `status: "failed"`, with the
/// same reason vocabulary alongside it.
///
/// `reason` is OPTIONAL here and that is the point: a Task that simply did not
/// work out is a complete statement, and a responder is never forced to invent
/// an excuse. What stating one buys is the §10.8a distinction between a
/// performer that did not deliver, a caller that never furnished a declared
/// need, and an outside service that broke. Whose failure it was is
/// `attribution`, which the PLATFORM computes and no party puts on the wire.
pub fn failed_update_payload(
    reason: Option<CancelReason>,
    note: Option<&str>,
    qualifier: Option<&StopQualifier>,
) -> Value {
    let mut payload = json!({ "status": "failed" });
    if let Some(reason) = reason {
        payload["reason"] = json!(reason.as_str());
    }
    if let Some(note) = note {
        payload["note"] = json!(note);
    }
    apply_qualifier(&mut payload, qualifier);
    payload
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorObject;

    #[test]
    fn the_british_spelling_of_upstream_cancelled_is_pinned_on_the_wire() {
        // `rename_all = "snake_case"` on `UpstreamCancelled` must produce the
        // two-l wire string, and keep producing it.
        assert_eq!(
            serde_json::to_string(&CancelReason::UpstreamCancelled).unwrap(),
            "\"upstream_cancelled\""
        );
        assert_eq!(
            serde_json::from_str::<CancelReason>("\"upstream_cancelled\"").unwrap(),
            CancelReason::UpstreamCancelled
        );
        assert_eq!(CancelReason::UpstreamCancelled.as_str(), "upstream_cancelled");
    }

    #[test]
    fn a_propagated_note_is_the_bare_reason_when_the_original_had_no_note() {
        assert_eq!(
            propagated_cancel_note(CancelReason::UserRequested, None),
            "user_requested"
        );
    }

    #[test]
    fn a_propagated_note_joins_reason_and_note_with_colon_space() {
        assert_eq!(
            propagated_cancel_note(CancelReason::DeadlineExceeded, Some("overdue since 16:00Z")),
            "deadline_exceeded: overdue since 16:00Z"
        );
    }

    #[test]
    fn propagation_composes_across_hops_and_the_reason_stays_upstream_cancelled() {
        // Hop 1: the original cancel had no note.
        let hop1 = propagated_cancel_note(CancelReason::UserRequested, None);
        // Hop 2 forwards hop 1's cancel — reason upstream_cancelled, note hop1.
        let hop2 = propagated_cancel_note(CancelReason::UpstreamCancelled, Some(&hop1));
        assert_eq!(hop2, "upstream_cancelled: user_requested");
        // Hop 3 nests again, colons and all.
        let hop3 = propagated_cancel_note(CancelReason::UpstreamCancelled, Some(&hop2));
        assert_eq!(hop3, "upstream_cancelled: upstream_cancelled: user_requested");
    }

    #[test]
    fn an_empty_note_is_still_a_present_note() {
        // Present-but-empty is a note the sender chose to send; the format
        // does not collapse it into absence.
        assert_eq!(propagated_cancel_note(CancelReason::Policy, Some("")), "policy: ");
    }

    #[test]
    fn a_cancel_input_without_a_task_id_is_refused_at_the_door() {
        for input in [
            serde_json::json!({ "reason": "policy" }),
            serde_json::json!({ "task_id": "", "reason": "policy" }),
            serde_json::json!({ "task_id": 7, "reason": "policy" }),
            serde_json::json!("not an object"),
        ] {
            let err = validate_cancel_input(&input).unwrap_err();
            assert!(
                err.to_string().contains("INVALID_ENVELOPE"),
                "expected INVALID_ENVELOPE, got: {err}"
            );
        }
    }

    #[test]
    fn task_not_cancelable_is_a_code_a_peer_may_send_and_keeps_its_name() {
        // §10.8 errors: a terminal state that arrived first stands. The code
        // must survive the wire round trip through `static_code` rather than
        // arriving as INTERNAL_ERROR.
        assert_eq!(ErrorCode::TaskNotCancelable.as_str(), "TASK_NOT_CANCELABLE");
        let err = MeshError::from_error_object(&ErrorObject {
            code: "TASK_NOT_CANCELABLE".to_string(),
            message: "task already completed".to_string(),
            details: None,
            retryable: false,
            retry_after_ms: None,
        });
        assert!(err.to_string().contains("TASK_NOT_CANCELABLE"), "got: {err}");
    }
}
