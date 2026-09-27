//! The three job doors (SPEC.md §5.7), from the asking side.
//!
//! A node that runs an agent serves three request doors about one unit of
//! work, and until now no SDK could open any of them: a caller had to build
//! the request by hand and read the answer by guess.
//!
//!  - `job.manifest` answers with the signed manifest of a task's delivery.
//!  - `job.quote` answers with what redoing named steps of a task would cost
//!    now, under the agent's declared revisions policy.
//!  - `job.record` answers with what the node wrote down about one task while
//!    it happened: whether a job folder was made, what was collected, dropped
//!    or skipped, what the harness did, whether a reply went out. It exists so
//!    that an agent running on somebody else's compute can be diagnosed by the
//!    customer, who has no shell on that host.
//!
//! THREE RULES SHAPE THIS MODULE.
//!
//! **A refusal is a value, not an error.** Every one of the three doors
//! answers an unentitled asker and an unknown task with ONE sentence, and that
//! is deliberate: a stranger holding a task id must not be able to learn
//! whether it exists. A client that turned that sentence into a `MeshError`
//! "not found" would report a fact the door refused to state. So the sentence
//! comes back as the answer it is, with `unknown_or_not_yours` set, and the
//! caller is told plainly that the two cases are not distinguishable from out
//! here.
//!
//! **A transport failure is an `Err`.** `request` fails on a timeout, on no
//! responders, on a refusal at admission. Nothing here swallows those, so "the
//! door said no" and "nobody answered" can never be confused: one is an `Ok`
//! carrying a refusal, the other is an `Err`.
//!
//! **A malformed answer is refused whole.** The parsers check every member
//! before handing anything back, and a document that fails comes back as a
//! fault naming the member, never as a half-populated record. The fault type
//! is the job manifest's, because the vocabulary already fits: a document that
//! names itself something other than `job-quote-v1` or `job-record-v1` is
//! `wrong_format`, and everything else these parsers can find is `malformed`.
//!
//! The parsers are pure and public on their own, so a caller holding an answer
//! from anywhere (a recorded envelope, a test fixture) reads it the same way a
//! live ask does.
//!
//! Mirrors `sdk-typescript/src/job-doors.ts`: same door names, same sentences,
//! same shapes, same three outcomes.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::client::{AgentMesh, RequestOptions};
use crate::error::{ErrorCode, MeshError, Result};
use crate::job_manifest::{
    as_count, is_rfc3339_utc, non_empty_str, verify_job_manifest, JobManifest, JobManifestFault,
    JobManifestReason,
};

// ─── the doors, and the sentences they answer with ──────────────────────────

/// The offering name of the manifest door.
pub const JOB_MANIFEST_DOOR: &str = "job.manifest";
/// The offering name of the quote door.
pub const JOB_QUOTE_DOOR: &str = "job.quote";
/// The offering name of the record door.
pub const JOB_RECORD_DOOR: &str = "job.record";

/// The one value a quote answer's `quote` member may hold.
pub const JOB_QUOTE_FORMAT: &str = "job-quote-v1";
/// The one value a record answer's `record` member may hold.
pub const JOB_RECORD_FORMAT: &str = "job-record-v1";

/// The manifest door's one answer for a task it does not know AND for a caller
/// that is not that task's requester. The two are deliberately
/// indistinguishable.
pub const NO_JOB_MANIFEST_REASON: &str = "no job manifest for that task at this agent";
/// The quote and record doors' one answer for the same pair of cases.
pub const NO_JOB_REASON: &str = "no job for that task at this agent";
/// The manifest door's other refusal: it knows the job and could not read what
/// it filed. Distinguishable from the pair above, and worth telling an operator
/// about, since it says a file went missing on that host.
pub const MANIFEST_UNREADABLE_REASON: &str = "the record of that task could not be read";
/// The quote door's other refusal: the job is yours and the agent declares no
/// revisions for that offering, so there is nothing to price.
pub const NO_REVISIONS_REASON: &str = "this agent declares no revisions for that offering";

/// How long a job door is given to answer. These doors read files the node
/// already wrote and never wake a model, so a slow answer means the host is in
/// trouble rather than thinking.
pub const DEFAULT_JOB_DOOR_TIMEOUT: Duration = Duration::from_secs(20);

// ─── what comes back ────────────────────────────────────────────────────────

/// A door's refusal, as the door said it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobDoorRefusal {
    /// The door's sentence, verbatim.
    pub reason: String,
    /// True when `reason` is the sentence the door gives BOTH for a task it has
    /// no record of and for a caller that is not that task's requester. When it
    /// is true, which of the two happened is not knowable from here, and a
    /// caller must not report it as either one.
    pub unknown_or_not_yours: bool,
}

/// What the `job.manifest` door answered.
#[derive(Debug, Clone, PartialEq)]
pub enum JobManifestAnswer {
    Answered {
        manifest: Box<JobManifest>,
        manifest_ref: String,
    },
    Refused(JobDoorRefusal),
    Malformed(JobManifestFault),
}

/// An amount in micro-units of a currency, the way the node prices a revision:
/// `amount_micro` whole and never negative.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobQuotePrice {
    pub amount_micro: u64,
    pub currency: String,
}

/// One step named in the ask, and what it costs on its own. `price` is `None`
/// when the agent declares no price for that step, which is the ordinary case
/// under a flat revision price. Required on the wire, nullable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobQuoteStep {
    pub id: String,
    pub price: Option<JobQuotePrice>,
}

/// The `job-quote-v1` document: what redoing the named steps costs now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobQuote {
    /// Always [`JOB_QUOTE_FORMAT`].
    pub quote: String,
    /// The offering whose revisions policy was quoted under.
    pub offering: String,
    /// The steps that were asked about, in the order they were asked.
    pub steps: Vec<JobQuoteStep>,
    /// What the whole revision costs. Zero while an included revision remains
    /// inside the window, which is why `included_remaining` travels beside it.
    pub price: JobQuotePrice,
    /// How many included revisions are left inside the window.
    pub included_remaining: u64,
    /// When the included window closes, `None` when the agent declares no
    /// window. Required on the wire, nullable.
    pub window_ends_at: Option<String>,
    /// Steps that were asked about and that the offering does not declare.
    /// Absent when every named step was known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unknown_steps: Option<Vec<String>>,
    /// Every step the offering declares, so a caller can ask again with a name
    /// the agent knows.
    pub all_steps: Vec<String>,
    /// When the quote was made (RFC 3339, UTC).
    pub at: String,
}

/// What the `job.quote` door answered.
#[derive(Debug, Clone, PartialEq)]
pub enum JobQuoteAnswer {
    Answered(Box<JobQuote>),
    Refused(JobDoorRefusal),
    Malformed(JobManifestFault),
}

/// Whether a job folder is on that host now, and when the node recorded making
/// one. The pair matters: "never made" and "made and since gone" are different
/// faults, and `made_at` `None` with `present` true means the task is older
/// than the node's records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobRecordFolder {
    pub present: bool,
    pub made_at: Option<String>,
}

/// Whether the harness left a `pieces.json`, and where. `where_at` is `None`
/// when none was found. Any host path in it has been folded by the node before
/// it left that machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobRecordPiecesJson {
    pub found: bool,
    /// The wire member is `where`, which is a Rust keyword.
    #[serde(rename = "where")]
    pub where_at: Option<String>,
    pub at: Option<String>,
}

/// What was collected. `count` is the whole count and `names` is capped by the
/// node, so a very large delivery has more collected than named here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobRecordCollected {
    pub count: u64,
    pub names: Vec<String>,
}

/// A piece that did not make it onto the delivery, and why. `size_bytes` is
/// present only where the node recorded a size.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobRecordPieceOutcome {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
    pub why: String,
}

/// Whether a signed job manifest was filed for this task, and which one. When
/// `filed` is true the manifest door will hand it to the same caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobRecordManifest {
    pub filed: bool,
    pub r#ref: Option<String>,
    pub version: Option<u64>,
}

/// Whether a reply went out. `sent` `None` means the node has NO RECORD of a
/// reply, which is not the same statement as "no reply was sent" and must never
/// be reported as one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobRecordReply {
    pub sent: Option<bool>,
    pub at: Option<String>,
    pub delivery: Option<String>,
}

/// The refusal the reply carried, when it was one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobRecordRefusal {
    pub code: String,
    pub message: String,
}

/// What the harness did. `fault` is present when it did not answer;
/// `output_chars` when it did. The stderr tail the node also holds is
/// deliberately not here: it is the operator's to read, because a harness can
/// echo anything on its way out, including a key.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct JobRecordHarness {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fault: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_chars: Option<u64>,
}

/// The `job-record-v1` document: what the node wrote down about one task, while
/// it was happening. Anything the node did not write down is `None` and is
/// named in `unknown`; silence never resolves to the flattering value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobRecord {
    /// Always [`JOB_RECORD_FORMAT`].
    pub record: String,
    pub task_id: String,
    /// When the answer was assembled (RFC 3339, UTC).
    pub at: String,
    pub offering: Option<String>,
    pub received_at: Option<String>,
    pub folder: JobRecordFolder,
    pub pieces_json: Option<JobRecordPiecesJson>,
    pub collected: Option<JobRecordCollected>,
    pub dropped: Option<Vec<JobRecordPieceOutcome>>,
    pub skipped: Option<Vec<JobRecordPieceOutcome>>,
    pub manifest: JobRecordManifest,
    pub reply: JobRecordReply,
    pub refusal: Option<JobRecordRefusal>,
    pub harness: Option<JobRecordHarness>,
    /// What this node cannot say about this task, in words.
    pub unknown: Vec<String>,
    /// The whole record as sentences, so a person does not have to assemble it
    /// from the members above.
    pub summary: String,
}

/// What the `job.record` door answered.
#[derive(Debug, Clone, PartialEq)]
pub enum JobRecordAnswer {
    Answered(Box<JobRecord>),
    Refused(JobDoorRefusal),
    Malformed(JobManifestFault),
}

// ─── reading an answer ──────────────────────────────────────────────────────

fn fault(
    reason: JobManifestReason,
    member: impl Into<String>,
    message: impl Into<String>,
) -> JobManifestFault {
    JobManifestFault {
        reason,
        member: member.into(),
        message: message.into(),
    }
}
fn malformed(member: impl Into<String>, message: impl Into<String>) -> JobManifestFault {
    fault(JobManifestReason::Malformed, member, message)
}

/// The door said null and gave a sentence. `identical` is the sentence THAT
/// door uses for both the unknown task and the caller who is not the requester,
/// which is what `unknown_or_not_yours` reports.
fn refusal_of(reason: &str, identical: &str) -> JobDoorRefusal {
    JobDoorRefusal {
        reason: reason.to_string(),
        unknown_or_not_yours: reason == identical,
    }
}

/// A member that is present and is either a string or null.
fn null_or_str(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::Null) | Some(Value::String(_)))
}

fn is_price(v: Option<&Value>) -> bool {
    match v.and_then(Value::as_object) {
        Some(p) => {
            as_count(p.get("amount_micro")).is_some() && non_empty_str(p.get("currency")).is_some()
        }
        None => false,
    }
}

fn all_strings(v: Option<&Value>) -> bool {
    matches!(v.and_then(Value::as_array), Some(xs) if xs.iter().all(Value::is_string))
}

fn all_non_empty_strings(v: Option<&Value>) -> bool {
    matches!(v.and_then(Value::as_array), Some(xs) if xs.iter().all(|x| non_empty_str(Some(x)).is_some()))
}

/// The answer read as an object, or the fault for a caller that was handed
/// something else.
fn answer_object<'a>(answer: &'a Value, door: &str) -> std::result::Result<&'a serde_json::Map<String, Value>, JobManifestFault> {
    answer
        .as_object()
        .ok_or_else(|| malformed("answer", format!("a {door} answer is an object")))
}

/// Every piece outcome in a record answer, or the fault for the first bad one.
/// `why` may be empty: the node writes down the reason it had, and an empty one
/// is still the reason it had.
fn check_piece_outcomes(v: Option<&Value>, member: &str) -> std::result::Result<(), JobManifestFault> {
    match v {
        Some(Value::Null) => Ok(()),
        Some(Value::Array(xs)) => {
            for (i, entry) in xs.iter().enumerate() {
                let at = format!("{member}[{i}]");
                let Some(e) = entry.as_object() else {
                    return Err(malformed(at, "each entry is an object"));
                };
                if non_empty_str(e.get("name")).is_none() {
                    return Err(malformed(format!("{at}.name"), "name is required"));
                }
                if !matches!(e.get("why"), Some(Value::String(_))) {
                    return Err(malformed(format!("{at}.why"), "why is a sentence"));
                }
                if e.contains_key("size_bytes") && as_count(e.get("size_bytes")).is_none() {
                    return Err(malformed(
                        format!("{at}.size_bytes"),
                        "size_bytes, when present, is a whole number of bytes",
                    ));
                }
            }
            Ok(())
        }
        _ => Err(malformed(
            member.to_string(),
            format!("{member}, when present, is an array or null"),
        )),
    }
}

/// A document that passed its shape check and still will not deserialize is a
/// fault in this SDK, not in the answer, so it is reported as one rather than
/// swallowed.
fn typed<T: serde::de::DeserializeOwned>(
    doc: &Value,
    member: &str,
) -> std::result::Result<T, JobManifestFault> {
    serde_json::from_value(doc.clone())
        .map_err(|e| malformed(member.to_string(), format!("the answer does not read as its own shape: {e}")))
}

/// Read a `job.manifest` answer.
///
/// `expected_agent` is passed through to [`verify_job_manifest`]: give it the
/// agent you asked when you want the manifest held to that key, and leave it
/// `None` when the agent may legitimately hand over a manifest another key
/// signed.
///
/// The signature is checked here rather than left to the caller, because a
/// manifest that does not verify is not a weaker answer, it is a different
/// document from the one the agent signed.
pub fn parse_job_manifest_answer(answer: &Value, expected_agent: Option<&str>) -> JobManifestAnswer {
    let a = match answer_object(answer, JOB_MANIFEST_DOOR) {
        Ok(a) => a,
        Err(f) => return JobManifestAnswer::Malformed(f),
    };
    let Some(doc) = a.get("manifest") else {
        return JobManifestAnswer::Malformed(malformed(
            "manifest",
            "an answer carries a manifest or null",
        ));
    };
    if doc.is_null() {
        return match non_empty_str(a.get("reason")) {
            Some(reason) => JobManifestAnswer::Refused(refusal_of(reason, NO_JOB_MANIFEST_REASON)),
            None => {
                JobManifestAnswer::Malformed(malformed("reason", "a refused manifest says why"))
            }
        };
    }
    if let Err(f) = verify_job_manifest(doc, expected_agent) {
        // The member is reported as a path into the ANSWER, so a reader who has
        // the answer in front of them can find the member the fault is about.
        return JobManifestAnswer::Malformed(JobManifestFault {
            reason: f.reason,
            member: format!("manifest.{}", f.member),
            message: f.message,
        });
    }
    let Some(manifest_ref) = non_empty_str(a.get("manifest_ref")) else {
        return JobManifestAnswer::Malformed(malformed(
            "manifest_ref",
            "manifest_ref says where the filed manifest lives",
        ));
    };
    match typed::<JobManifest>(doc, "manifest") {
        Ok(manifest) => JobManifestAnswer::Answered {
            manifest: Box::new(manifest),
            manifest_ref: manifest_ref.to_string(),
        },
        Err(f) => JobManifestAnswer::Malformed(f),
    }
}

/// Read a `job.quote` answer. The answered document IS the answer object: the
/// door puts the quote's members at the top level rather than nesting them.
pub fn parse_job_quote_answer(answer: &Value) -> JobQuoteAnswer {
    let a = match answer_object(answer, JOB_QUOTE_DOOR) {
        Ok(a) => a,
        Err(f) => return JobQuoteAnswer::Malformed(f),
    };
    let Some(format) = a.get("quote") else {
        return JobQuoteAnswer::Malformed(malformed("quote", "an answer carries a quote or null"));
    };
    if format.is_null() {
        return match non_empty_str(a.get("reason")) {
            Some(reason) => JobQuoteAnswer::Refused(refusal_of(reason, NO_JOB_REASON)),
            None => JobQuoteAnswer::Malformed(malformed("reason", "a refused quote says why")),
        };
    }
    if format.as_str() != Some(JOB_QUOTE_FORMAT) {
        return JobQuoteAnswer::Malformed(fault(
            JobManifestReason::WrongFormat,
            "quote",
            format!("quote must be \"{JOB_QUOTE_FORMAT}\""),
        ));
    }
    if non_empty_str(a.get("offering")).is_none() {
        return JobQuoteAnswer::Malformed(malformed("offering", "offering names what was quoted"));
    }
    let Some(steps) = a.get("steps").and_then(Value::as_array) else {
        return JobQuoteAnswer::Malformed(malformed(
            "steps",
            "steps is an array, empty when none were named",
        ));
    };
    for (i, step) in steps.iter().enumerate() {
        let at = format!("steps[{i}]");
        let Some(s) = step.as_object() else {
            return JobQuoteAnswer::Malformed(malformed(at, "each step is an object"));
        };
        if non_empty_str(s.get("id")).is_none() {
            return JobQuoteAnswer::Malformed(malformed(format!("{at}.id"), "id names the step"));
        }
        let price = s.get("price");
        if !matches!(price, Some(Value::Null)) && !is_price(price) {
            return JobQuoteAnswer::Malformed(malformed(
                format!("{at}.price"),
                "price is { amount_micro, currency } or null",
            ));
        }
    }
    if !is_price(a.get("price")) {
        return JobQuoteAnswer::Malformed(malformed(
            "price",
            "price is { amount_micro, currency }",
        ));
    }
    if as_count(a.get("included_remaining")).is_none() {
        return JobQuoteAnswer::Malformed(malformed(
            "included_remaining",
            "included_remaining is a count of revisions still included",
        ));
    }
    if !matches!(a.get("window_ends_at"), Some(Value::Null))
        && non_empty_str(a.get("window_ends_at")).is_none()
    {
        return JobQuoteAnswer::Malformed(malformed(
            "window_ends_at",
            "window_ends_at is an instant or null",
        ));
    }
    if a.contains_key("unknown_steps") && !all_non_empty_strings(a.get("unknown_steps")) {
        return JobQuoteAnswer::Malformed(malformed(
            "unknown_steps",
            "unknown_steps, when present, is an array of step names",
        ));
    }
    if !all_non_empty_strings(a.get("all_steps")) {
        return JobQuoteAnswer::Malformed(malformed(
            "all_steps",
            "all_steps is the offering's declared steps",
        ));
    }
    // `at` is stamped by the answering node as it answers, so it is held to the
    // format. The instants COPIED from an older record are not: the node does
    // not police what it wrote down months ago, and neither does this.
    if !non_empty_str(a.get("at")).is_some_and(is_rfc3339_utc) {
        return JobQuoteAnswer::Malformed(malformed("at", "at is an RFC 3339 instant in UTC"));
    }
    match typed::<JobQuote>(answer, "quote") {
        Ok(quote) => JobQuoteAnswer::Answered(Box::new(quote)),
        Err(f) => JobQuoteAnswer::Malformed(f),
    }
}

/// Read a `job.record` answer. Like the quote, the answered document IS the
/// answer object.
pub fn parse_job_record_answer(answer: &Value) -> JobRecordAnswer {
    let a = match answer_object(answer, JOB_RECORD_DOOR) {
        Ok(a) => a,
        Err(f) => return JobRecordAnswer::Malformed(f),
    };
    let Some(format) = a.get("record") else {
        return JobRecordAnswer::Malformed(malformed(
            "record",
            "an answer carries a record or null",
        ));
    };
    if format.is_null() {
        return match non_empty_str(a.get("reason")) {
            Some(reason) => JobRecordAnswer::Refused(refusal_of(reason, NO_JOB_REASON)),
            None => JobRecordAnswer::Malformed(malformed("reason", "a refused record says why")),
        };
    }
    if format.as_str() != Some(JOB_RECORD_FORMAT) {
        return JobRecordAnswer::Malformed(fault(
            JobManifestReason::WrongFormat,
            "record",
            format!("record must be \"{JOB_RECORD_FORMAT}\""),
        ));
    }
    if non_empty_str(a.get("task_id")).is_none() {
        return JobRecordAnswer::Malformed(malformed(
            "task_id",
            "task_id names the task answered about",
        ));
    }
    if !non_empty_str(a.get("at")).is_some_and(is_rfc3339_utc) {
        return JobRecordAnswer::Malformed(malformed("at", "at is an RFC 3339 instant in UTC"));
    }
    if !null_or_str(a.get("offering")) {
        return JobRecordAnswer::Malformed(malformed("offering", "offering is a string or null"));
    }
    if !null_or_str(a.get("received_at")) {
        return JobRecordAnswer::Malformed(malformed(
            "received_at",
            "received_at is an instant or null",
        ));
    }
    match a.get("folder").and_then(Value::as_object) {
        Some(f) if f.get("present").and_then(Value::as_bool).is_some() && null_or_str(f.get("made_at")) => {}
        _ => {
            return JobRecordAnswer::Malformed(malformed(
                "folder",
                "folder is { present, made_at }",
            ))
        }
    }
    if !matches!(a.get("pieces_json"), Some(Value::Null)) {
        let ok = match a.get("pieces_json").and_then(Value::as_object) {
            Some(p) => {
                p.get("found").and_then(Value::as_bool).is_some()
                    && null_or_str(p.get("where"))
                    && null_or_str(p.get("at"))
            }
            None => false,
        };
        if !ok {
            return JobRecordAnswer::Malformed(malformed(
                "pieces_json",
                "pieces_json is { found, where, at } or null",
            ));
        }
    }
    if !matches!(a.get("collected"), Some(Value::Null)) {
        // `count` is the whole count and `names` is capped by the node, so a
        // delivery larger than the cap names fewer than it counts. Held to
        // "count is at least what is named" rather than to equality.
        let ok = match a.get("collected").and_then(Value::as_object) {
            Some(c) => match (as_count(c.get("count")), c.get("names").and_then(Value::as_array)) {
                (Some(count), Some(names)) => {
                    names.iter().all(Value::is_string) && count >= names.len() as u64
                }
                _ => false,
            },
            None => false,
        };
        if !ok {
            return JobRecordAnswer::Malformed(malformed(
                "collected",
                "collected is { count, names } or null, and count is at least what it names",
            ));
        }
    }
    if let Err(f) = check_piece_outcomes(a.get("dropped"), "dropped") {
        return JobRecordAnswer::Malformed(f);
    }
    if let Err(f) = check_piece_outcomes(a.get("skipped"), "skipped") {
        return JobRecordAnswer::Malformed(f);
    }
    let manifest_ok = match a.get("manifest").and_then(Value::as_object) {
        Some(m) => {
            m.get("filed").and_then(Value::as_bool).is_some()
                && null_or_str(m.get("ref"))
                && (matches!(m.get("version"), Some(Value::Null))
                    || as_count(m.get("version")).is_some())
        }
        None => false,
    };
    if !manifest_ok {
        return JobRecordAnswer::Malformed(malformed(
            "manifest",
            "manifest is { filed, ref, version }",
        ));
    }
    let reply_ok = match a.get("reply").and_then(Value::as_object) {
        Some(r) => {
            matches!(r.get("sent"), Some(Value::Null) | Some(Value::Bool(_)))
                && null_or_str(r.get("at"))
                && null_or_str(r.get("delivery"))
        }
        None => false,
    };
    if !reply_ok {
        return JobRecordAnswer::Malformed(malformed("reply", "reply is { sent, at, delivery }"));
    }
    if !matches!(a.get("refusal"), Some(Value::Null)) {
        let ok = match a.get("refusal").and_then(Value::as_object) {
            Some(r) => {
                matches!(r.get("code"), Some(Value::String(_)))
                    && matches!(r.get("message"), Some(Value::String(_)))
            }
            None => false,
        };
        if !ok {
            return JobRecordAnswer::Malformed(malformed(
                "refusal",
                "refusal is { code, message } or null",
            ));
        }
    }
    if !matches!(a.get("harness"), Some(Value::Null)) {
        let ok = match a.get("harness").and_then(Value::as_object) {
            Some(h) => {
                (!h.contains_key("fault") || matches!(h.get("fault"), Some(Value::String(_))))
                    && (!h.contains_key("output_chars") || as_count(h.get("output_chars")).is_some())
            }
            None => false,
        };
        if !ok {
            return JobRecordAnswer::Malformed(malformed(
                "harness",
                "harness is { fault?, output_chars? } or null",
            ));
        }
    }
    if !all_strings(a.get("unknown")) {
        return JobRecordAnswer::Malformed(malformed(
            "unknown",
            "unknown lists what this node cannot say, in words",
        ));
    }
    if !matches!(a.get("summary"), Some(Value::String(_))) {
        return JobRecordAnswer::Malformed(malformed(
            "summary",
            "summary is the record as sentences",
        ));
    }
    match typed::<JobRecord>(answer, "record") {
        Ok(record) => JobRecordAnswer::Answered(Box::new(record)),
        Err(f) => JobRecordAnswer::Malformed(f),
    }
}

// ─── asking ─────────────────────────────────────────────────────────────────

/// Options common to all three asks.
#[derive(Debug, Clone, Default)]
pub struct JobDoorOptions {
    /// How long to wait ([`DEFAULT_JOB_DOOR_TIMEOUT`] when unset).
    pub timeout: Option<Duration>,
    /// Hold the manifest to this key. Only the manifest door reads it.
    pub expect_agent: Option<String>,
}

/// What the quote door is asked.
#[derive(Debug, Clone, Default)]
pub struct JobQuoteAsk {
    /// The task being revised. The door calls it `revises`, because a quote is
    /// priced against the completion it would replace.
    pub revises: String,
    /// The steps to redo. Leaving it out asks what the offering's flat revision
    /// price is, where one is declared.
    pub steps: Option<Vec<String>>,
    /// Which offering's revisions policy to quote under. Left out, the node
    /// uses the offering it recorded for that job.
    pub offering: Option<String>,
}

fn require_task_id(task_id: &str, member: &str) -> Result<()> {
    // Refused here rather than sent. An empty id would come back as the door's
    // "unknown task or not yours" sentence, and a caller cannot tell its own
    // empty string from a real refusal once it has been through that door.
    if task_id.is_empty() {
        return Err(MeshError::code(
            ErrorCode::InputInvalid,
            format!("a job door needs a {member} to answer about"),
        ));
    }
    Ok(())
}

/// The door's answer inside the respond payload (§6.4). The bare-payload
/// fallback is for a responder that answers with the document itself.
fn door_output(payload: &Value) -> Value {
    match payload.get("output") {
        Some(v) if !v.is_null() => v.clone(),
        _ if !payload.is_null() => payload.clone(),
        _ => json!({}),
    }
}

async fn ask_door(
    client: &AgentMesh,
    agent_id: &str,
    door: &str,
    input: Value,
    opts: &JobDoorOptions,
) -> Result<Value> {
    let result = client
        .request_with_options(
            agent_id,
            door,
            input,
            RequestOptions {
                timeout: Some(opts.timeout.unwrap_or(DEFAULT_JOB_DOOR_TIMEOUT)),
                ..Default::default()
            },
        )
        .await?;
    Ok(door_output(&result.payload))
}

/// Ask an agent for the signed manifest of one task (§5.7).
///
/// Answered only to that task's requester. A caller who is not, and a task the
/// agent has no manifest for, get the same sentence back, surfaced as a refusal
/// with `unknown_or_not_yours` true.
///
/// `Err` on a transport failure, never on a refusal.
pub async fn ask_job_manifest(
    client: &AgentMesh,
    agent_id: &str,
    task_id: &str,
    opts: JobDoorOptions,
) -> Result<JobManifestAnswer> {
    require_task_id(task_id, "task_id")?;
    let answer = ask_door(
        client,
        agent_id,
        JOB_MANIFEST_DOOR,
        json!({ "task_id": task_id }),
        &opts,
    )
    .await?;
    Ok(parse_job_manifest_answer(&answer, opts.expect_agent.as_deref()))
}

/// Ask an agent what redoing named steps of one task would cost now (§5.7),
/// under its declared revisions policy. Answered only to that task's requester,
/// with the same identical refusal as the other two doors.
///
/// `Err` on a transport failure, never on a refusal.
pub async fn ask_job_quote(
    client: &AgentMesh,
    agent_id: &str,
    ask: &JobQuoteAsk,
    opts: JobDoorOptions,
) -> Result<JobQuoteAnswer> {
    require_task_id(&ask.revises, "revises")?;
    let mut input = json!({ "revises": ask.revises });
    if let Some(steps) = &ask.steps {
        input["steps"] = json!(steps);
    }
    if let Some(offering) = &ask.offering {
        input["offering"] = json!(offering);
    }
    let answer = ask_door(client, agent_id, JOB_QUOTE_DOOR, input, &opts).await?;
    Ok(parse_job_quote_answer(&answer))
}

/// Ask an agent what its node wrote down about one task (§5.7): whether a job
/// folder was made, what was collected, dropped or skipped, what the harness
/// did, whether a reply went out.
///
/// This is the door for diagnosing an agent that runs on somebody else's
/// compute, where there is no shell to open. Answered only to that task's
/// requester, with the same identical refusal as the other two doors.
///
/// `Err` on a transport failure, never on a refusal.
pub async fn ask_job_record(
    client: &AgentMesh,
    agent_id: &str,
    task_id: &str,
    opts: JobDoorOptions,
) -> Result<JobRecordAnswer> {
    require_task_id(task_id, "task_id")?;
    let answer = ask_door(
        client,
        agent_id,
        JOB_RECORD_DOOR,
        json!({ "task_id": task_id }),
        &opts,
    )
    .await?;
    Ok(parse_job_record_answer(&answer))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_output_member_carries_the_answer() {
        let payload = json!({ "status": "completed", "output": { "record": null, "reason": NO_JOB_REASON } });
        assert_eq!(door_output(&payload)["reason"], json!(NO_JOB_REASON));
    }

    #[test]
    fn a_payload_that_is_the_document_itself_is_taken_as_one() {
        let payload = json!({ "record": null, "reason": NO_JOB_REASON });
        assert_eq!(door_output(&payload)["reason"], json!(NO_JOB_REASON));
    }

    #[test]
    fn an_empty_task_id_never_reaches_the_door() {
        let err = require_task_id("", "task_id").unwrap_err();
        assert!(err.to_string().contains("task_id"), "{err}");
    }
}
