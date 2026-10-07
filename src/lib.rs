//! AgentMesh 0.2 client SDK (Rust).
//!
//! A2A-semantics agent-to-agent messaging over NATS JetStream. This crate is
//! the Rust reference/client mirroring `sdk-typescript`; the Egg Gateway is its
//! first consumer (behind an anti-corruption boundary — no Egg types leak here).
//!
//! Implemented: the wire foundation — envelope (§5), identity + always-sign
//! signatures and node vouching (§4), the codec — and the async-nats client:
//! connect, register, discover, request/respond (bare-vs-task), streaming with
//! chunk verification, events, heartbeats, node hosting, and manifest-by-ID
//! lookup. Full **Rooms** (mesh://extensions/rooms/v1): ephemeral, durable
//! (record + drive via the rooms service), sealed (end-to-end X25519 +
//! XSalsa20-Poly1305), and acl (broker-enforced membership via a room-scoped
//! second connection) — see [`rooms`] and [`sealed`]. Envelope signatures,
//! room-descriptor signatures, the §8.3 manifest key claim, and sealed-key
//! exchange are cross-verified against sdk-typescript byte for byte (a TS agent
//! and a Rust agent share a sealed room, and each will seal to an agent the other
//! registered). All five **inbound protections** (§22) are implemented on the
//! live inbox, the §16.4 mailbox drain and the event paths, and asserted against
//! `conformance/inbound-protections.json` — see [`inbound`]. The **§7.7 budget**
//! is implemented end to end: attach on request, Task inheritance,
//! refuse-with-estimate admission, absolute revisions under
//! latest-revision-wins, and the `BUDGET_EXHAUSTED` pause — see [`budget`].
//! The **EXT-8 owner allowance** is implemented end to end: the owner-signed
//! document (tag `agentmesh-allowance-v1`, fail-closed on a bad signature),
//! host-reported usage metered by the declared cost model (floor arithmetic,
//! accounted to Task/context/UTC-day), smallest-remaining-wins admission
//! enforcement before the §6.4a accept, the `ask_owner` channel, and the
//! §19.3 `payload.cost` spend report on the terminal respond — see
//! [`allowance`].
//! **§10.8 cancel** is implemented end to end: the closed reason enum, both
//! wire legs (`AgentMesh::cancel` publishes the canceled task update and
//! best-effort-notifies the performer's inbox), door validation of inbound
//! `task.cancel`, and automatic upstream propagation to still-live delegates
//! with the pinned note format — see [`cancel`].
//! The **§16.4 offline mailbox drain** and **EXT-6 guarded registration** are
//! wired into `register`;
//! an agent declares its `interaction` style (§8.2) there too.
//! The **§6.4a accept signal** is implemented on both sides: a live handler's
//! admission emits the non-terminal `"accepted"` respond before the handler
//! runs (refusals of admission — §22, §7.7 via [`client::AgentMesh::on_admission`] —
//! happen instead, never after), and a waiting requester treats an accept as
//! delivery + admission: response timeout reset, request still outstanding
//! until the first substantive respond, the queued node-ack equally
//! non-resolving, see [`accept`]. The **§6.4a reply path** routes every
//! respond, the bare answer and the §11.3 step-2 opening alike, to the
//! REQUESTER's inbox, correlated by `in_reply_to`, with the transport reply
//! subject kept liveness-only (no-responders, the queued ack); the registry
//! probe and EXT-6 guarded deliveries are the only two reply-subject
//! exceptions. **§18.6 durable event
//! subscriptions** bind the `mesh_event_{agent}_{hash}` pull consumer on
//! `MESH_EVENTS`, see [`client::AgentMesh::subscribe_durable`].
//! The **§6.4b sender pre-flight** refuses
//! locally, before publishing, with the recipient's own codes — see
//! [`preflight`]. The **§9.6 presence surface** subscribes to transitions
//! before it reads the snapshot — see [`presence`].
//! **§6.6a feeds** — the owner-rooted event channel — are implemented end to
//! end: the four-token subject grammar (built refusing, parsed strictly,
//! pinned by `conformance/feeds.json`), publish as an ordinary emit carrying
//! the `{topic, kind, data}` payload, ambient subscription through the same
//! §22 pipeline as events (handing the handler the full payload — a feed's
//! identity travels in-band), the §18.3 current-value read on
//! `mesh.feed.get`, subscribe-before-snapshot tracking (§9.6), and the
//! manifest `emits` declaration at register, see [`feed`]. **Durable feed
//! subscriptions** (§18.6 Feed Consumer) add a followed feed to the agent's one
//! `mesh_feed_{agent}` pull consumer on `MESH_FEED`, so what was published
//! while it was offline arrives when it returns, see
//! [`client::AgentMesh::subscribe_feed_durable`]. Callers holding a
//! manifest address its carried `endpoints` verbatim rather than constructing
//! subjects (§14.4).
//! **§19.1 SKUs and §19.5 agreements** are implemented end to end: SKUs
//! declared at `register` are validated there (where the operator can see a
//! refusal), each one's tagged digest — byte-identical to the TS SDK's, pinned
//! by `conformance/commerce.json` — is cached as the identity an agreement
//! binds to, the §8.7 `public.skus` price advertisement is derived unless an
//! explicit one wins, and the `AGREEMENT_REQUIRED` admission check runs in the
//! §7.7 admission slot before the §6.4a accept — see [`sku`] and
//! [`agreement`].
//! **§4.4 vouch renewal** is implemented end to end: a registration is a
//! lease, and the SDK re-registers with a freshly minted vouch at two thirds
//! of the attestation's own window (checks at window/4, capped hourly, judged
//! against the wall clock so a suspended host renews on first wake) — a
//! standalone agent runs its own loop from `register`, a [`MeshNode`] runs ONE
//! loop for every agent it vouches for, a failure raises a
//! `vouch_renewal_failed` security warning and retries, and the state is readable
//! via [`client::AgentMesh::vouch`] — see [`vouch`].
//! **§4.8 node-credential renewal** is the same lease one layer down: the
//! connection credential is re-minted at two thirds of its OWN lifetime (read
//! off the JWT's `iat`/`exp`) through `POST {api_base}/v1/node-credential`,
//! authorized by proof-of-possession of the node key and every hosted agent
//! key — so it works with no live connection and on a credential that has
//! already lapsed. A standalone agent and a [`MeshNode`] each run one loop, a
//! host that cannot persist the fresh credential is treated as a failed
//! renewal, and the state is readable via
//! [`client::AgentMesh::credential`] — see [`credential`]. The POST is made by
//! a built-in HTTP transport compiled in with the default `http` feature, so
//! renewal works out of the box; `default-features = false` drops the HTTP
//! dependency and the host supplies a [`credential::CredentialTransport`]
//! instead. Not yet ported:
//! local task tracking, and the §6.2 response-binding pin
//! machinery, which exists only as the two inline checks the EXT-6 guard
//! handshake makes for itself.

pub mod accept;
pub mod agreement;
pub mod allowance;
pub mod budget;
pub mod cancel;
pub mod client;
pub mod codec;
pub mod credential;
mod env_generated;
pub mod envelope;
pub mod error;
pub mod feed;
pub mod identity;
pub mod inbound;
pub mod interview;
pub mod job_doors;
pub mod job_manifest;
pub mod manifest;
pub mod metering;
pub mod naming_gate;
pub mod node;
pub mod pact;
pub mod preflight;
pub mod presence;
pub mod rests_on;
pub mod revoked_senders;
pub mod rooms;
pub mod sealed;
pub mod services;
mod services_generated;
mod mesh_doors;
pub mod sealing;
pub mod sku;
pub mod sow;
pub mod spans;
pub mod subjects;
pub mod trial;
pub mod util;
pub mod vouch;

pub use accept::{accept_envelope, is_accept_signal, queued_ack_of, QueuedAck, ACCEPTED_STATUS};
pub use agreement::{
    agreement_covers, agreement_required, canonical_agreement_bytes, load_agreement,
    sign_agreement, validate_agreement, verify_agreement_signature, AgreementDocument,
    AgreementEvidence, AgreementRequiredDetails, AgreementWant, AGREEMENT_SIG_PREFIX,
};
pub use allowance::{
    allowance_insufficient, canonical_allowance_bytes, estimate_tokens, load_allowance,
    meter_cost_micro, sign_allowance, today_utc, validate_allowance_value,
    verify_allowance_signature, Allowance, AllowanceCeiling, AllowanceCostModel,
    AllowanceDecision, AllowanceMeter, AllowanceQuestion, AllowanceStatus, BindingCeiling,
    CeilingScope, OnExhausted, SpendLedger, Usage, WorkScope, ALLOWANCE_SIG_PREFIX,
    ESTIMATE_CHARS_PER_TOKEN,
};
pub use budget::{
    budget_exhausted_update, budget_insufficient, budget_revision_update, deadline_unmeetable,
    Budget, CostCeiling, TaskBudgets, DEADLINE_SKEW_TOLERANCE_MS, MICROS_PER_UNIT,
};
pub use cancel::{
    cancel_request_payload, canceled_update_payload, failed_update_payload, is_terminal_task_state,
    is_unmet_need_ref, need_ref_of, parse_unmet_need_ref, propagated_cancel_note,
    validate_cancel_input, validate_stop_qualifier, CancelInput, CancelReason, StopQualifier,
    CANCEL_OFFERING, NEED_KINDS, TERMINAL_TASK_STATES,
};
pub use client::{AgentMesh, AdmissionFn, AgreementLookupFn, ChunkOutcome, ConnectOptions, CostEstimatorFn, DeliverySignal, DeliverySignalSink, DiscoverQuery, DurableSubscribeOptions, DurableSubscription, HandlerOptions, OwnerDecisionFn, RegisterOptions, RequestOptions, RequestResult, StreamChunk, StreamResult, StreamWriter, validate_chunk, RequestContext, DEFAULT_MAILBOX_DRAIN_INTERVAL, DEFAULT_REQUEST_TIMEOUT, MIN_MAILBOX_DRAIN_INTERVAL};
pub use codec::{decode, decode_unverified, encode};
// §4.8 node-credential renewal: the credential is a lease like the vouch under
// it, renewed at the same two thirds of its own lifetime. The signing contract
// (`mesh-node-cred-v1` / `mesh-node-agent-v1`) is byte-identical to the TS
// SDK's, and so is the 15s request timeout and the no-retry-inside-the-call
// rule. The HTTP call is made by the built-in transport (default `http`
// feature) or by one the host supplies; see the [`credential`] module docs.
pub use credential::{
    agent_consent_line, build_credential_request, credential_check_interval, credential_endpoint,
    credential_renew_at, decode_credential_claims, node_credential_line,
    parse_credential_response, renew_node_credential, renew_node_credential_at, BoxFuture,
    CredentialClaims, CredentialHttpResponse, CredentialRenewal, CredentialRenewer,
    CredentialRenewerOptions, CredentialRequest, CredentialRequestAgent, CredentialStatus,
    CredentialTransport, DetachedSigner, OnRenewedFn, RenewalAgent, RenewalRoster,
    RenewedCredential, ASSUMED_CREDENTIAL_LIFETIME_MS, CREDENTIAL_REQUEST_TIMEOUT_MS,
    NODE_AGENT_CONSENT_SIG_PREFIX, NODE_CREDENTIAL_SIG_PREFIX,
};
pub use credential::default_credential_transport;
#[cfg(feature = "http")]
pub use credential::HttpCredentialTransport;
pub use envelope::{Envelope, PrimitiveType, TraceContext, PROTOCOL_VERSION};
pub use error::{ErrorCode, ErrorObject, MeshError, Result};
pub use feed::{feed_lookup_payload, feed_payload, DurableFeedSubscription, FeedKind};
pub use inbound::{
    addressed_to_me, admit_envelope, fence_inbound_input, fence_sender_text, frame_message,
    fresh_enough, inbound_text_length, is_sealed_payload, now_ms, over_inbound_cap, parse_instant_ms,
    sender_text_of, utf16_len, FrameProvenance, InboundOptions, InboundRefusal, InboundSource,
    SecurityWarning, SecurityWarningSink, SeenEnvelopes, SenderText, SenderTextField,
    BEGIN_SENDER_MESSAGE, DEFAULT_MAX_INBOUND_CHARS, END_SENDER_MESSAGE, MAX_CLOCK_SKEW_AHEAD_MS,
    MAX_CLOCK_SKEW_BEHIND_MS, MAX_MAILBOX_AGE_MS, MAX_SEEN_INBOX_IDS,
};
pub use identity::{
    canonical_json, create_agent_identity, create_attestation, keypair_from_seed,
    manifest_key_claim_bytes, sign_envelope, sign_manifest, sign_manifest_at, signed_envelope_bytes,
    verify_attestation, verify_envelope_sig, verify_manifest_signature, ENVELOPE_SIG_PREFIX,
    MANIFEST_KEY_CLAIM_TYPE, VOUCH_SIG_PREFIX,
};
pub use interview::{
    describe_document_of, diff_answers, interview, project_five_questions, AnswerMismatch,
    FiveAnswers, FIVE_QUESTIONS, REFUSAL_STATEMENT,
};
// Job manifests (job-manifest-v1): the delivering agent's signed record of a
// completion's pieces — tagged agentmesh-job-manifest-v1 signing, verification
// with a typed reason (which refuses any other format before reading a byte
// of signature), the shape check, and the reuse computation between a prior
// manifest and its revision. Byte-identical to the TypeScript SDK's;
// conformance/job-manifest.json pins that.
// The three job doors (§5.7), from the asking side: the signed manifest of one
// task, what redoing named steps of it would cost now, and what the answering
// node wrote down about it while it happened (the door a customer diagnoses an
// agent through when the agent runs on somebody else's compute and there is no
// shell to open). Each door answers an unentitled asker and an unknown task
// with ONE sentence, so a stranger holding a task id learns nothing; these
// clients hand that sentence back as a refusal with `unknown_or_not_yours` set
// rather than turning it into an error. A transport failure is still an `Err`.
// The TypeScript SDK has the same three, with the same shapes.
pub use job_doors::{
    ask_job_manifest, ask_job_quote, ask_job_record, parse_job_manifest_answer,
    parse_job_quote_answer, parse_job_record_answer, JobDoorOptions, JobDoorRefusal,
    JobManifestAnswer, JobQuote, JobQuoteAnswer, JobQuoteAsk, JobQuotePrice, JobQuoteStep,
    JobRecord, JobRecordAnswer, JobRecordCollected, JobRecordFolder, JobRecordHarness,
    JobRecordManifest, JobRecordPieceOutcome, JobRecordPiecesJson, JobRecordRefusal,
    JobRecordReply, DEFAULT_JOB_DOOR_TIMEOUT, JOB_MANIFEST_DOOR, JOB_QUOTE_DOOR,
    JOB_QUOTE_FORMAT, JOB_RECORD_DOOR, JOB_RECORD_FORMAT, MANIFEST_UNREADABLE_REASON,
    NO_JOB_MANIFEST_REASON, NO_JOB_REASON, NO_REVISIONS_REASON,
};
pub use job_manifest::{
    canonical_job_manifest_bytes, job_manifest_reuse, job_manifest_reuse_claim_holds,
    sign_job_manifest, validate_job_manifest, verify_job_manifest, JobManifest,
    JobManifestFault, JobManifestPiece, JobManifestReason, JobManifestReused,
    JobManifestVerdict, JOB_MANIFEST_FORMAT, JOB_MANIFEST_SIG_PREFIX,
};
pub use manifest::{AgentAttestation, AgentComplianceAttestation, AgentComplianceEntry, AgentDataUse, AgentDataUsePromises, AgentDataUseRetention, Availability, Delivers, Endpoints, Limits, Manifest, NeedEntry, NodeDeclaredProfile, NodeRef, Offering, OfferingReporting, PublicBlock, ResourceEntry, Trust, WorksWith, with_detected_device, SDK_CLIENT};
pub use metering::{validate_meter_name, UsageEntry, OBSERVED_METERS};
pub use naming_gate::{
    is_standard_handle, judge_resolve_answer, not_named_error, propose_handle, NameCheck, NameLookup, NamingGate,
    NamingStatus, ProposedHandle, RequireNamed, NAMED_TTL_MS, NAMING_STANDARD_WORDS, NOT_NAMED, UNNAMED_TTL_MS,
};
#[cfg(feature = "http")]
pub use naming_gate::RegistrarNameLookup;
pub use node::{AddAgentOptions, MeshNode, NodeConnectOptions};
pub use preflight::{
    input_media_type, preflight_content_types, preflight_envelope_size, preflight_request,
    preflight_sender_text,
};
pub use presence::{NodePresence, PresenceTracker, PRESENCE_STALE_AFTER_MS};
pub use rooms::{
    descriptor_from_token, descriptor_to_token, normalize_playbook, sign_descriptor,
    verify_descriptor, AttachOptions, AttachResult, BoardItem, BoardItemClaim, BoardList, FetchedArtifact,
    JoinRoomOptions, LinkOptions, LinkResult, MyRoom, RoomFile, NoteSource, NoteVerdict, OpenRoomOptions, PostWorkInput, RecordEntry, Room,
    RoomDescriptor, RoomInput, RoomMessage, RoomNote, RoomPhase, RoomPlaybook, MAX_ROOM_AGENDA,
    ROOM_DESCRIPTOR_SIG_PREFIX,
};
pub use sealed::{
    create_encryption_identity, encryption_public_from_seed, open_sealed_key, open_sealed_payload,
    open_sealed_value, resolve_reply_key, room_key_fingerprint, seal_key_to, seal_payload_to,
    OpenedPayload, SealedKey, SealedPayload, SEALED_PAYLOAD_V1,
};
pub use sealing::{
    declares_credential_need, derived_sealing, SealingChoice, SEALING_PREFERRED, SEALING_REQUIRED,
};
pub use sku::{
    public_sku_of, sku_digest, sku_digest_value, sku_for, validate_sku, validate_sku_price,
    validate_skus, PublicSku, Sku, SkuCovers, SkuIncluded, SkuPeriod, SkuPrice, SkuPriceModel,
    SkuProvider, SkuTier, SKU_DIGEST_PREFIX,
};
// Agent SoW pricing arrangements (<https://agentsow.com> §5.5): the fixed-fee,
// time-and-materials and no-charge clauses, the mandatory not-to-exceed cap and
// its reservation window, rating that stops at the cap, pass-through lines
// billed at cost against an upstream receipt, the §5.5.8 operator fee disclosed
// in the quote and again in the settlement record, the §5.5.7 rule that nothing
// settles under a no-charge engagement, the §7.1 document states including
// `exhausted`, and the §6.2 organizational-authority fields. Canonicalization
// and signing use the agent-sow-v1 domain tag and are byte-identical to the
// TypeScript SDK's — `conformance/sow-pricing.json` pins that.
pub use sow::{
    admit_settlement, arbiter_verdict_signed_bytes, canonical_sow_json, check_operator_fee,
    check_settlement, committed_price,
    confidentiality_of, confidentiality_shortfall,
    directed_offer_refusal, disputes_of, is_directed_proposal, liability_of,
    qualification_grade_ceiling,
    qualification_refusal, qualifications_of, required_assertions, service_floors_of,
    sign_arbiter_verdict, validate_arbiter_verdict, verify_arbiter_verdict_signature,
    load_sow_price, mandate_verified, max_rated_total_under_cap, meets_reporting_level,
    operator_fee, operator_fee_amount,
    operator_fee_grade,
    pass_through_lines, provider_net, quote_with_operator_fee, rate_usage,
    rate_usage_with_operator_fee, refuse_further_work_under_operator,
    reporting_cadence_warning, reporting_every_ms, reporting_of, reporting_shortfall,
    reservation_release_at, reservation_within_term, settlement_total,
    settlement_with_operator_fee, settles, sign_sow, sow_agreed, sow_signed_bytes,
    subcontract_conformance, subcontract_conformance_with, subcontracting_of, SubcontractOpts,
    validate_operator_fee, validate_schedule_against_meters, validate_settlement_line,
    validate_sow_approval, validate_sow_confidentiality, validate_sow_disputes,
    validate_sow_liability,
    validate_sow_offered_to,
    validate_sow_party, validate_sow_price,
    validate_sow_qualification, validate_sow_qualifications, validate_sow_reporting,
    validate_sow_service_floors, validate_sow_subcontracting,
    verify_sow_signature,
    ApprovalAuthority, ArbiterVerdictExpectation, PricingArrangement, SowApprovalAct,
    SowApprovalRecord, SowArbiterBasis, SowArbiterBinding, SowArbiterDisputed,
    SowArbiterExclusion, SowArbiterFee, SowArbiterHeard, SowArbiterSplit, SowArbiterVerdict,
    SowArbiterVerdictSignature, SowCap, SowCeiling,
    SowConfidentiality, SowConfidentialityPromise, SowConfidentialityPromises,
    SowConfidentialityRequirement, SowConfidentialityRetention, SowConfidentialityTransport,
    SowDisputeReason, SowDisputedSettlement, SowDisputes, SowDisputesPosture, SowDocumentState,
    SowFixedFeeRate,
    SowGrade, SowIndemnification, SowLiability, SowLiabilityCap, SowMeteredCount, SowOfferedTo,
    SowOperatorFee, SowOperatorFeeBasis, SowParty,
    SowPeriod, SowPrice, SowProcessor, SowQualification, SowQualificationFacts,
    SowQuote, SowRating, SowReporting, SowReportingLevel, SowReservation, SowScheduleLine,
    SowServiceFloor, SowServiceFloors, SowServiceFloorsBreach,
    SowSettlementLine, SowSettlementRecord,
    SowSettlementVerdict, SowSignature, SowSubcontracting, SowSubcontractingPosture,
    SowSubcontractorEntry, APPROVAL_AUTHORITIES, ARBITER_VERDICT_SIG_PREFIX,
    CHECKABLE_QUALIFICATION_KINDS,
    DEFAULT_AMENDMENT_AUTHORITY,
    DEFAULT_FORMATION_AUTHORITY, DEFAULT_REPORTING_LEVEL, OPERATOR_FEE_BASIS_GRADE,
    PRICING_ARRANGEMENTS, ROLE_ARBITER, SOW_ARBITER_FEES, SOW_CONFIDENTIALITY_PROMISES,
    SOW_DISPUTES_POSTURES, SOW_END_STATES, SOW_FLOOR_REMEDIES,
    SOW_QUALIFICATION_KINDS, SOW_REPORTING_GRADE, SOW_REPORTING_LEVELS,
    SOW_SIG_PREFIX, SOW_SUBCONTRACTING_POSTURES,
};
pub use trial::{
    input_over_limit, is_trial_request, money_words, next_utc_midnight, quote_from_price,
    trial_admission, trial_day_of, trial_declaration_of, trial_of, trial_refusal,
    trial_refusal_words, trial_refused, trial_requester_of, validate_descriptor_trials,
    validate_trial, work_caps, InputOver, MemoryTrialLedger, TrialAdmissionArgs, TrialContext,
    TrialCounts, TrialDeclaration, TrialFunds, TrialInputLimit, TrialInputLimitValue, TrialLedger,
    TrialLimits, TrialQuote, TrialReason, TrialRefusal, TrialRefusalDetails, TrialRequester,
    TrialRequesterKind, TrialShape, TrialWho, WorkCap, ADMISSION_LIMIT_KEYS, TRIAL_LIMIT_KEYS,
    TRIAL_REASONS, TRIAL_WHO,
};
pub use vouch::{
    vouch_check_interval, vouch_renew_at, VouchStatus, DEFAULT_VOUCH_TTL_MS,
    EPHEMERAL_VOUCH_TTL_MS, MAX_VOUCH_CHECK_INTERVAL_MS, VOUCH_RENEWAL_FRACTION,
};
pub use nkeys::KeyPair;
