//! Budget (SPEC.md §7.7, §19.3, §12.2) — the requester's statement of the most
//! a piece of work may cost and the latest it may finish.
//!
//! A budget is an **offer, and acceptance means something**: a responder reads
//! it before doing any work, and accepting the request is a statement that it
//! believes the work fits inside it. Only money and time appear, deliberately —
//! tokens are the responder's private units, so the responder owns the
//! conversion (§7.7).
//!
//! What lives here:
//!
//!  - [`Budget`] / [`CostCeiling`] — the wire block. `deadline` is core;
//!    `cost_ceiling` is the Economics extension's money axis (§19.3), integer
//!    micro-units only, so no floating point ever touches money.
//!  - Admission refusal — [`budget_insufficient`] / [`deadline_unmeetable`],
//!    the §7.7 refuse-with-estimate mechanism. Returned from a request handler,
//!    they become the error envelope the dispatcher answers with; the estimate
//!    rides in `error.details.estimate`, and resubmitting with better terms is
//!    the counter-offer. Accepting work the budget never covered and then
//!    failing is the one outcome §7.7 treats as the responder's fault.
//!  - The §7.7 ceiling pause — [`budget_exhausted_update`], the
//!    `input_required` task update carrying spend so far and an estimate to
//!    finish. The input required is money: the requester raises the budget by
//!    revision, or cancels and keeps the partial artifacts.
//!  - Revisions — [`budget_revision_update`] plus [`TaskBudgets`], the
//!    latest-revision-wins store. Revisions are **absolute, never deltas**:
//!    each states the entire budget, so the highest `revision` is simply the
//!    whole truth and a lost or reordered revision corrupts nobody's
//!    arithmetic.
//!  - The deadline predicate — [`Budget::past_deadline`], compared under the
//!    §22.3 clock-skew tolerance and at second granularity, because below one
//!    second a deadline measures network jitter, not the work.
//!
//! The budget rides the envelope as a top-level OPTIONAL field (§5.2), which
//! means it is covered by the envelope signature (§5.3). Absent stays absent on
//! the wire — canonical signing must never see a `null` the TypeScript SDK
//! leaves out.

use std::collections::HashMap;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::envelope::{Envelope, PrimitiveType};
use crate::error::{ErrorCode, ErrorObject, MeshError, Result};
use crate::inbound::{parse_instant_ms, MAX_CLOCK_SKEW_AHEAD_MS};

/// Micro-units per currency unit (§19.3): 1,000,000 micro-units = one unit.
pub const MICROS_PER_UNIT: u64 = 1_000_000;

/// The clock-skew tolerance [`Budget::past_deadline`] judges under.
///
/// §7.7: "Deadlines are compared under the clock-skew tolerance of Section
/// 22.3" — the SAME constant the §22.3 freshness window uses for a clock that
/// runs fast, not a new number. A deadline is only declared past once `now`
/// exceeds it by MORE than this, so an out-of-sync local clock cannot declare
/// work overdue that the task manager's central clock would not.
pub const DEADLINE_SKEW_TOLERANCE_MS: i64 = MAX_CLOCK_SKEW_AHEAD_MS;

/// The money axis of a budget (§19.3, Economics extension). Core treats it as
/// opaque; this SDK types it because integer arithmetic near money is the whole
/// point of the encoding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CostCeiling {
    /// Integer micro-units of the currency ([`MICROS_PER_UNIT`] = one unit).
    /// Never a float: `4000000` is four dollars, exactly.
    pub amount_micro: u64,
    /// ISO 4217 currency code (e.g. `"USD"`).
    pub currency: String,
}

impl CostCeiling {
    pub fn new(amount_micro: u64, currency: impl Into<String>) -> CostCeiling {
        CostCeiling { amount_micro, currency: currency.into() }
    }
}

/// The §7.7 budget block, attached to a `request` envelope (and to budget
/// revisions) as the top-level `budget` field.
///
/// `revision` is REQUIRED: `0` on the initiating request, incremented by one on
/// each revision. At least one of `deadline` / `cost_ceiling` MUST be present —
/// [`Budget::validate`] enforces both rules, and deserialization already fails
/// on a missing `revision`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Budget {
    /// Absolute RFC 3339 UTC deadline (core, OPTIONAL). The moment the
    /// requester's obligation to wait ends and the responder's authorization to
    /// spend ends — not a kill switch, and not retroactive (§7.7). SHOULD NOT
    /// be finer than one second.
    ///
    /// OMITTED from the wire when absent — never `null` (canonical signing,
    /// §5.3). An EXPLICIT `null` is refused at deserialization
    /// (`conformance/budget.json` `null_axis`): absent-is-omitted is the wire
    /// rule, so a null here is a malformed block, not an empty axis.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present_means_not_null"
    )]
    pub deadline: Option<String>,
    /// Monotonic revision counter. `0` on the initiating request; each revision
    /// states the ENTIRE budget and the highest revision is the whole truth.
    pub revision: u64,
    /// The most the requester can be asked to pay for the work (§19.3,
    /// Economics extension, OPTIONAL). OMITTED when absent — never `null`
    /// (same rule and same fixture case as `deadline`).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present_means_not_null"
    )]
    pub cost_ceiling: Option<CostCeiling>,
}

/// Deserialize an optional field whose PRESENCE requires a real value.
///
/// With `#[serde(default)]` alongside, an ABSENT key still becomes `None` —
/// this function only runs when the key is present, and then `null` is an
/// error rather than a second spelling of absence. The wire rule (§5.3 and
/// the TS SDK) is that absent fields are omitted; a `null` axis is therefore
/// a malformed block, and accepting it would let two encodings of one budget
/// exist — exactly what canonical signing cannot tolerate.
fn present_means_not_null<'de, D, T>(deserializer: D) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

impl Budget {
    /// A revision-0 budget with only the time axis.
    pub fn with_deadline(deadline: impl Into<String>) -> Budget {
        Budget { deadline: Some(deadline.into()), revision: 0, cost_ceiling: None }
    }

    /// A revision-0 budget with only the money axis.
    pub fn with_ceiling(ceiling: CostCeiling) -> Budget {
        Budget { deadline: None, revision: 0, cost_ceiling: Some(ceiling) }
    }

    /// Add/replace the time axis (builder-style).
    pub fn and_deadline(mut self, deadline: impl Into<String>) -> Budget {
        self.deadline = Some(deadline.into());
        self
    }

    /// Add/replace the money axis (builder-style).
    pub fn and_ceiling(mut self, ceiling: CostCeiling) -> Budget {
        self.cost_ceiling = Some(ceiling);
        self
    }

    /// This budget restated at the next revision. Revisions are absolute
    /// (§7.7): the caller edits the axes on the clone and sends the whole
    /// thing, never a delta.
    pub fn revised(mut self) -> Budget {
        self.revision += 1;
        self
    }

    /// Validate the §7.7 shape rules: at least one axis present, and a
    /// `deadline` (when present) that parses as an RFC 3339 instant — any RFC
    /// 3339 form, including a numeric UTC offset (§22.3 rule 1 applies to
    /// deadlines the same way it applies to `ts`).
    ///
    /// `revision` needs no runtime check here: the field is non-optional, so a
    /// budget missing it never deserializes in the first place.
    pub fn validate(&self) -> Result<()> {
        if self.deadline.is_none() && self.cost_ceiling.is_none() {
            return Err(MeshError::code(
                ErrorCode::InvalidEnvelope,
                "A budget must state at least one of deadline / cost_ceiling (§7.7)",
            ));
        }
        if let Some(deadline) = self.deadline.as_deref() {
            if parse_instant_ms(deadline).is_none() {
                return Err(MeshError::code(
                    ErrorCode::InvalidEnvelope,
                    format!("Budget deadline '{deadline}' is not an RFC 3339 instant (§7.7)"),
                ));
            }
        }
        Ok(())
    }

    /// Whether the deadline has passed, judged at `now_ms` (milliseconds since
    /// the Unix epoch, [`crate::inbound::now_ms`]).
    ///
    /// Two deliberate softenings, both from §7.7:
    ///
    ///  - **second granularity** — both instants are floored to whole seconds
    ///    before comparing, because below one second a deadline measures
    ///    network jitter, not the work;
    ///  - **skew tolerance** — the deadline is only past once `now` exceeds it
    ///    by more than [`DEADLINE_SKEW_TOLERANCE_MS`] (the §22.3 constant), so
    ///    a locally fast clock cannot declare work overdue early. Exactly at
    ///    the tolerance is NOT past — inclusive bounds, like §22.3's.
    ///
    /// A budget with no deadline is never past one, and an unparseable
    /// deadline answers `false` here — [`Budget::validate`] is where a
    /// malformed deadline is refused; this predicate never invents an overdue
    /// mark from a string it cannot read.
    pub fn past_deadline(&self, now_ms: i64) -> bool {
        let Some(deadline) = self.deadline.as_deref() else { return false };
        let Some(deadline_ms) = parse_instant_ms(deadline) else { return false };
        let drift_s = now_ms.div_euclid(1000) - deadline_ms.div_euclid(1000);
        drift_s > DEADLINE_SKEW_TOLERANCE_MS / 1000
    }
}

// ─── §7.7 admission refusal (refuse-with-estimate) ──────────────────────────

/// The refusal a request handler returns when the offered **cost ceiling**
/// cannot cover the work (§7.7, §12.2 `BUDGET_INSUFFICIENT`). MUST happen at
/// admission — before the work — never accept-then-fail.
///
/// `estimate` is the responder's price, and it SHOULD be given: the
/// refuse-with-estimate loop is the negotiation mechanism (it replaced the
/// retired `negotiate` operation), and a refusal without a price gives the
/// requester nothing to counter with. It rides in `error.details.estimate` as
/// a `{amount_micro, currency}` object.
///
/// Returned as an error from an `on_request` handler, the dispatcher answers
/// the requester with this exact error object in a signed `respond`.
pub fn budget_insufficient(estimate: Option<CostCeiling>, message: impl Into<String>) -> MeshError {
    MeshError::Refusal(ErrorObject {
        code: ErrorCode::BudgetInsufficient.as_str().to_string(),
        message: message.into(),
        details: estimate.map(|e| json!({ "estimate": e })),
        retryable: false,
        retry_after_ms: None,
    })
}

/// The refusal a request handler returns when the offered **deadline** cannot
/// be met (§7.7, §12.2 `DEADLINE_UNMEETABLE`). Same admission rule and same
/// negotiation loop as [`budget_insufficient`].
///
/// `earliest_completion` is the responder's earliest realistic completion
/// (RFC 3339), riding in `error.details.earliest_completion` — NOT
/// `details.estimate`. The two refusals carry differently-typed estimates
/// under different names so a reader never type-sniffs
/// (`conformance/budget.json` pins both).
pub fn deadline_unmeetable(
    earliest_completion: Option<String>,
    message: impl Into<String>,
) -> MeshError {
    MeshError::Refusal(ErrorObject {
        code: ErrorCode::DeadlineUnmeetable.as_str().to_string(),
        message: message.into(),
        details: earliest_completion.map(|e| json!({ "earliest_completion": e })),
        retryable: false,
        retry_after_ms: None,
    })
}

// ─── §7.7 ceiling pause and revisions (the update envelopes) ────────────────

/// The UNSIGNED `input_required` task update a responder publishes when it
/// reaches the cost ceiling mid-work (§7.7 `BUDGET_EXHAUSTED`): stop BEFORE
/// crossing the ceiling, report spend so far and an estimate to finish, and
/// wait. The input required is money — a budget revision resumes the work, a
/// cancellation keeps the partial artifacts with the requester.
///
/// The caller signs and publishes it to `mesh.task.{task_id}.update`
/// ([`crate::subjects::task_update`]); connected agents use
/// [`crate::AgentMesh::pause_budget_exhausted`], which does both.
///
/// `BUDGET_EXHAUSTED` is not retryable (§12.2): it is resolved by a revision
/// or a cancellation, and the same request costs the same the second time.
pub fn budget_exhausted_update(
    agent_id: &str,
    task_id: &str,
    requester: Option<&str>,
    spent: &CostCeiling,
    estimate_to_finish: &CostCeiling,
    message: impl Into<String>,
) -> Envelope {
    let mut env = Envelope::new(PrimitiveType::Respond, agent_id);
    env.to = requester.map(str::to_string);
    env.task_id = Some(task_id.to_string());
    env.payload = Some(json!({ "status": "input_required" }));
    env.error = Some(ErrorObject {
        code: ErrorCode::BudgetExhausted.as_str().to_string(),
        message: message.into(),
        details: Some(json!({
            "spent": spent,
            "estimate_to_finish": estimate_to_finish,
        })),
        retryable: false,
        retry_after_ms: None,
    });
    env
}

/// The UNSIGNED budget-revision task update (§7.7): a task update **carrying
/// only the `budget` block** — no payload, no error. Either party to a Task
/// may send one; the revision states the entire budget, absolutely.
///
/// The caller signs and publishes it to `mesh.task.{task_id}.update`;
/// connected agents use [`crate::AgentMesh::revise_budget`], which also
/// enforces revision monotonicity locally.
pub fn budget_revision_update(
    agent_id: &str,
    task_id: &str,
    to: Option<&str>,
    budget: &Budget,
) -> Envelope {
    let mut env = Envelope::new(PrimitiveType::Respond, agent_id);
    env.to = to.map(str::to_string);
    env.task_id = Some(task_id.to_string());
    env.budget = Some(budget.clone());
    env
}

// ─── latest-revision-wins (the live budget) ─────────────────────────────────

/// Per-task budget state under latest-revision-wins (§7.7).
///
/// Because revisions are absolute, this store never merges: it holds the
/// highest-revision budget seen per task and ignores anything at or below it —
/// a lost or reordered revision therefore costs nothing, the next one is the
/// whole truth again. Shared by both sides: the requester's outgoing revisions
/// and the incoming ones a task-update watch surfaces land in the same place,
/// so [`TaskBudgets::get`] is always "the budget as currently agreed".
#[derive(Debug, Default)]
pub struct TaskBudgets {
    inner: Mutex<HashMap<String, Budget>>,
}

impl TaskBudgets {
    pub fn new() -> TaskBudgets {
        TaskBudgets::default()
    }

    /// Apply a budget under latest-revision-wins: recorded if this task has no
    /// budget yet or `budget.revision` is STRICTLY greater than the recorded
    /// one; ignored (returning `false`) otherwise. Equal is ignored too — the
    /// same revision restated adds nothing, and applying it would let a replay
    /// masquerade as news.
    pub fn apply(&self, task_id: &str, budget: &Budget) -> bool {
        let mut map = self.inner.lock().unwrap();
        match map.get(task_id) {
            Some(current) if budget.revision <= current.revision => false,
            _ => {
                map.insert(task_id.to_string(), budget.clone());
                true
            }
        }
    }

    /// The latest budget recorded for a task, if any.
    pub fn get(&self, task_id: &str) -> Option<Budget> {
        self.inner.lock().unwrap().get(task_id).cloned()
    }

    /// The local monotonicity gate for an OUTGOING revision: errors with
    /// `TASK_INVALID_TRANSITION` unless `revision` is strictly greater than
    /// the recorded one (§7.7 — the task manager applies the same rule
    /// centrally; failing here saves publishing a revision the mesh would
    /// refuse). A task with no recorded budget passes: this side may be
    /// joining the conversation late, and latest-wins makes that safe.
    pub fn ensure_monotonic(&self, task_id: &str, revision: u64) -> Result<()> {
        let map = self.inner.lock().unwrap();
        if let Some(current) = map.get(task_id) {
            if revision <= current.revision {
                return Err(MeshError::code(
                    ErrorCode::TaskInvalidTransition,
                    format!(
                        "Budget revision {revision} does not supersede the recorded revision {} \
                         for task {task_id} (§7.7: revisions are monotonic)",
                        current.revision
                    ),
                ));
            }
        }
        Ok(())
    }

    /// Drop a task's recorded budget (the task reached a terminal state).
    pub fn forget(&self, task_id: &str) {
        self.inner.lock().unwrap().remove(task_id);
    }
}
