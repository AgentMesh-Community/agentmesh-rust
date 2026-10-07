//! Error model (AgentMesh 0.2 §12) — mirrors the TS SDK's ErrorCode/MeshError.

use serde::{Deserialize, Serialize};

/// Protocol error codes (§12.2). String-valued to match the wire format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    TransportTimeout,
    TransportNoResponders,
    TransportPermissionDenied,
    /// SDK-local (never on the wire): the recipient's node answered the §6.4a
    /// queued acknowledgement — a mailbox holds the message for an attended
    /// session, and the reply channel will never carry anything more, so the
    /// wait rejects promptly instead of running out its timeout. The real
    /// reply arrives later at this agent's own inbox, correlated by
    /// `in_reply_to` (§6.4). Carried as a [`MeshError::Refusal`] whose
    /// `details` hold the ack fields (`queued`, `inbox_id`) plus the
    /// `request_id` to correlate that late reply with.
    RequestQueued,
    InvalidEnvelope,
    InvalidVersion,
    IdentityMismatch,
    InvalidManifest,
    InvalidQuery,
    TaskNotFound,
    TaskInvalidTransition,
    /// §10.8/§12.2: the Task a cancel named is already in a terminal state —
    /// the state that arrived first stands. Cancellation is best-effort on
    /// the work by design, so this is an answer, not a fault.
    TaskNotCancelable,
    AgentUnavailable,
    OfferingNotFound,
    InputInvalid,
    Unauthorized,
    /// §7.7/§12.2: refused at admission — the work cannot be done within the
    /// offered cost ceiling. SHOULD carry the responder's estimate (its price)
    /// in `details.estimate`; see [`crate::budget::budget_insufficient`].
    BudgetInsufficient,
    /// §7.7/§12.2: refused at admission — the work cannot be completed by the
    /// offered deadline. SHOULD carry the earliest realistic completion in
    /// `details.estimate`; see [`crate::budget::deadline_unmeetable`].
    DeadlineUnmeetable,
    /// §7.7/§12.2: the cost ceiling was reached mid-work; the Task is paused in
    /// `input_required` with spend so far and an estimate to finish. Resolved
    /// by a budget revision or cancellation, never by retry.
    BudgetExhausted,
    /// §7.7/§12.2: recorded on a completion that arrived after the deadline
    /// (completed late). A marker, not a failure — the requester decides what
    /// a late answer is worth.
    DeadlineExceeded,
    /// §19.5/§12.2: refused at admission — the requested work is covered by a
    /// paid SKU and the consumer's account holds no agreement at its current
    /// digest. `details` names the `sku`, the `sku_digest`, and the
    /// `approval_url` where a human accepts the terms; see
    /// [`crate::agreement::agreement_required`].
    AgreementRequired,
    /// Common Agent 7.7: refused at admission, a request marked `trial: true`
    /// that the trial declaration does not allow. `details` carries `reason`
    /// (budget, not_offered, not_eligible, input, requester_day, day,
    /// requester_ever, funds), `limit` and `resets_at` where they apply, and
    /// `quote`, what the same work costs as an ordinary request; see
    /// [`crate::trial::trial_refused`]. Never retryable as sent: waiting
    /// helps only where `resets_at` says so.
    TrialRefused,
    Internal,
    /// The accumulated context exceeds the agent's capacity. The §22.5 inbound
    /// size cap is the one §22 protection that MUST answer the sender, because
    /// it is the only one whose trigger an honest caller can act on: it sent too
    /// much, and it can send less. Never retryable — the same bytes will be too
    /// big next time. Also the code a §6.4b sender pre-flight refuses with
    /// locally — same code as the remote refusal, so the caller's error
    /// handling never has to know which side refused.
    ContextTooLarge,
    /// §6.4/§12.2: the requested output modes (or the input's type) are not
    /// supported by the target offering. Answered remotely by the responder and
    /// refused locally by the §6.4b sender pre-flight under the same code.
    ContentTypeNotSupported,
    /// §8.9/§12.2: the recipient declares `sealing: "required"` and the request
    /// arrived in the clear, so its content was not read. Also raised LOCALLY
    /// by a sender that is about to send to such an agent and cannot seal to it
    /// — refusing at home rather than leaking the payload onto the wire to earn
    /// the same refusal remotely. Not retryable as sent: resolve the
    /// recipient's manifest, seal to the key its §8.3 claim covers, send again.
    SealingRequired,
    /// EXT-5 §10.1: a board claim (or withdraw) lost — the item is already
    /// claimed and its lease live, or otherwise not takeable. The refusal a
    /// losing claimant gets; recover by listing again, not by hammering claim.
    BoardItemTaken,
    RateLimited,
    /// SDK-local, raised before anything is published: this agent has no handle
    /// in the global naming standard (its name, a dot, its owner's email), so it
    /// sends nothing. Only when the agent connected with `require_named`; see
    /// [`crate::naming_gate`]. Not retryable as is: name the agent, then send.
    NotNamed,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::TransportTimeout => "TRANSPORT_TIMEOUT",
            ErrorCode::TransportNoResponders => "TRANSPORT_NO_RESPONDERS",
            ErrorCode::TransportPermissionDenied => "TRANSPORT_PERMISSION_DENIED",
            ErrorCode::RequestQueued => "REQUEST_QUEUED",
            ErrorCode::InvalidEnvelope => "INVALID_ENVELOPE",
            ErrorCode::InvalidVersion => "INVALID_VERSION",
            ErrorCode::IdentityMismatch => "IDENTITY_MISMATCH",
            ErrorCode::InvalidManifest => "INVALID_MANIFEST",
            ErrorCode::InvalidQuery => "INVALID_QUERY",
            ErrorCode::TaskNotFound => "TASK_NOT_FOUND",
            ErrorCode::TaskInvalidTransition => "TASK_INVALID_TRANSITION",
            ErrorCode::TaskNotCancelable => "TASK_NOT_CANCELABLE",
            ErrorCode::AgentUnavailable => "AGENT_UNAVAILABLE",
            ErrorCode::OfferingNotFound => "OFFERING_NOT_FOUND",
            ErrorCode::InputInvalid => "INPUT_INVALID",
            ErrorCode::Unauthorized => "UNAUTHORIZED",
            ErrorCode::BudgetInsufficient => "BUDGET_INSUFFICIENT",
            ErrorCode::DeadlineUnmeetable => "DEADLINE_UNMEETABLE",
            ErrorCode::BudgetExhausted => "BUDGET_EXHAUSTED",
            ErrorCode::DeadlineExceeded => "DEADLINE_EXCEEDED",
            ErrorCode::AgreementRequired => "AGREEMENT_REQUIRED",
            ErrorCode::TrialRefused => "TRIAL_REFUSED",
            ErrorCode::Internal => "INTERNAL_ERROR",
            ErrorCode::ContextTooLarge => "CONTEXT_TOO_LARGE",
            ErrorCode::ContentTypeNotSupported => "CONTENT_TYPE_NOT_SUPPORTED",
            ErrorCode::SealingRequired => "SEALING_REQUIRED",
            ErrorCode::BoardItemTaken => "BOARD_ITEM_TAKEN",
            ErrorCode::RateLimited => "RATE_LIMITED",
            ErrorCode::NotNamed => "NOT_NAMED",
        }
    }
}

/// The structured error object carried in an envelope's `error` field (§12.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorObject {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
    pub retryable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

/// SDK error type.
#[derive(Debug, thiserror::Error)]
pub enum MeshError {
    #[error("[{code}] {message}")]
    Protocol { code: &'static str, message: String },
    /// A structured refusal carrying the full wire [`ErrorObject`] — details
    /// included. This is how the §7.7 refuse-with-estimate mechanism keeps its
    /// estimate: a `BUDGET_INSUFFICIENT` flattened to a code and a message has
    /// lost the price, which is the one thing the requester needed for the
    /// counter-offer. Returned from a request handler, the dispatcher answers
    /// with this exact error object (see [`crate::budget`]); received from a
    /// peer, [`MeshError::error_object`] reads the details back.
    #[error("[{}] {}", .0.code, .0.message)]
    Refusal(ErrorObject),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("nkey: {0}")]
    Nkey(String),
    #[error("transport: {0}")]
    Transport(String),
}

impl MeshError {
    /// Convert an envelope's error object into a MeshError (for propagating a
    /// remote agent's error to the caller).
    ///
    /// The three §7.7 budget refusals keep their whole [`ErrorObject`]: their
    /// `details` carry the responder's estimate (the price, or the earliest
    /// realistic completion), and that estimate IS the negotiation mechanism —
    /// flattening it to a code and message would discard the one thing the
    /// refusal exists to say. The two §6.4b pre-flight codes
    /// (`CONTEXT_TOO_LARGE`, `CONTENT_TYPE_NOT_SUPPORTED`) keep theirs too, for
    /// the mirror §6.4b demands: a local pre-flight refusal is built as a
    /// [`MeshError::Refusal`] carrying `error.details` that name the limit that
    /// fired, so the remote refusal must surface as the same variant — a caller
    /// matching on the variant or reading `error_object()` sees one shape
    /// wherever the refusal happened. Everything else keeps the older
    /// code+message shape.
    pub fn from_error_object(e: &ErrorObject) -> Self {
        const STRUCTURED_REFUSALS: [ErrorCode; 7] = [
            ErrorCode::BudgetInsufficient,
            ErrorCode::DeadlineUnmeetable,
            ErrorCode::BudgetExhausted,
            ErrorCode::ContextTooLarge,
            ErrorCode::ContentTypeNotSupported,
            // §19.5: the refusal's details carry the sku, its digest and the
            // approval_url — the one thing a refused buyer needed to act.
            ErrorCode::AgreementRequired,
            // Common Agent 7.7: the details carry the reason, limit,
            // resets_at and the quote for the ordinary request.
            ErrorCode::TrialRefused,
        ];
        if STRUCTURED_REFUSALS.iter().any(|c| c.as_str() == e.code) {
            return MeshError::Refusal(e.clone());
        }
        MeshError::Protocol {
            code: static_code(&e.code),
            message: e.message.clone(),
        }
    }

    /// Whether this is a protocol error whose wire code the protocol's list
    /// did not name, so it was read as `INTERNAL_ERROR`.
    pub(crate) fn is_unknown_code(&self) -> bool {
        matches!(self, MeshError::Protocol { code: "INTERNAL_ERROR", .. })
    }

    /// The error's code as a string: the protocol's, the refusal's, or
    /// `TRANSPORT` when nothing answered. Empty for the rest.
    pub fn code_str(&self) -> &str {
        match self {
            MeshError::Protocol { code, .. } => code,
            MeshError::Refusal(e) => &e.code,
            MeshError::Transport(_) => "TRANSPORT",
            _ => "",
        }
    }

    /// The full wire error object, when this error carries one (a §7.7
    /// refusal). This is where a refused requester reads the estimate:
    /// `err.error_object().and_then(|e| e.details.as_ref())`.
    pub fn error_object(&self) -> Option<&ErrorObject> {
        match self {
            MeshError::Refusal(e) => Some(e),
            _ => None,
        }
    }
}

/// Best-effort map a wire error-code string to a static str for MeshError.
///
/// The list is hand-maintained, so a code missing from it is reported to the
/// caller as `INTERNAL_ERROR` — which is how a §22.5 refusal reached the sender
/// looking like the responder had crashed rather than like the sender had sent
/// too much. That is the whole reason the size cap answers at all, so
/// `CONTEXT_TOO_LARGE` has to be here. Anything added to [`ErrorCode`] that a
/// peer may send belongs here too.
fn static_code(code: &str) -> &'static str {
    for c in [
        ErrorCode::OfferingNotFound, ErrorCode::AgentUnavailable, ErrorCode::Unauthorized,
        ErrorCode::InputInvalid, ErrorCode::InvalidEnvelope, ErrorCode::IdentityMismatch,
        ErrorCode::TaskNotFound, ErrorCode::TaskInvalidTransition, ErrorCode::TaskNotCancelable,
        ErrorCode::RateLimited, ErrorCode::ContentTypeNotSupported,
        ErrorCode::SealingRequired, ErrorCode::BoardItemTaken,
        ErrorCode::Internal, ErrorCode::ContextTooLarge, ErrorCode::BudgetInsufficient,
        ErrorCode::DeadlineUnmeetable, ErrorCode::BudgetExhausted, ErrorCode::DeadlineExceeded,
        ErrorCode::AgreementRequired, ErrorCode::TrialRefused,
    ] {
        if c.as_str() == code {
            return c.as_str();
        }
    }
    "INTERNAL_ERROR"
}

impl MeshError {
    pub fn code(code: ErrorCode, message: impl Into<String>) -> Self {
        MeshError::Protocol { code: code.as_str(), message: message.into() }
    }
}

pub type Result<T> = std::result::Result<T, MeshError>;
