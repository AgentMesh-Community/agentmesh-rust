//! Sender pre-flight (SPEC.md §6.4b) — the sender-side mirror of the §22
//! receiver obligations: the same checks, run where they are cheapest, refused
//! locally with the **same error codes the recipient would answer with**, so a
//! pre-flight refusal and a remote refusal are indistinguishable to the
//! caller's error handling.
//!
//! Three checks, in the spec's order:
//!
//!  - **Sender text** against the recipient's declared cap
//!    (`limits.max_inbound_chars`, §8.1) or the §22.5 default when undeclared —
//!    measured *exactly* as the recipient measures it: the §22.5 extraction
//!    ladder ([`crate::inbound::sender_text_of`], the very function the
//!    receiving dispatcher runs, so the mirror holds by construction), counted
//!    in UTF-16 code units, refused only when strictly greater than the cap.
//!    Code: `CONTEXT_TOO_LARGE`, `retryable: false`.
//!  - **Envelope size** against the transport's advertised maximum payload
//!    (§18.9), integer byte math. The one check with no remote mirror — an
//!    oversized publish never reaches the recipient at all — so the pre-flight
//!    turns a raw transport error into a protocol-legible refusal under the
//!    same code, with `error.details` naming the limit that fired.
//!  - **Content type** against the recipient's manifest (§8.1): a
//!    `config.accepted_output` no output mode of the target offering can satisfy,
//!    or input in a type the offering's `input_modes` exclude. Code:
//!    `CONTENT_TYPE_NOT_SUPPORTED`.
//!
//! A pre-flight refusal is **local**: nothing was published, so nothing was
//! signed, deduplicated, or retried. Decisions pinned by
//! `conformance/sender-preflight.json`, the authority on §22.8's terms.

use serde_json::{json, Value};

use crate::error::{ErrorCode, ErrorObject, MeshError, Result};
use crate::inbound::{inbound_text_length, DEFAULT_MAX_INBOUND_CHARS};
use crate::manifest::Manifest;

/// A §6.4b local refusal: the exact wire [`ErrorObject`] the recipient would
/// have answered with, raised as [`MeshError::Refusal`] so `details` (which
/// MAY name the limit that fired) survive to the caller.
fn refuse(code: ErrorCode, message: String, details: Value) -> MeshError {
    MeshError::Refusal(ErrorObject {
        code: code.as_str().to_string(),
        message,
        details: Some(details),
        retryable: false,
        retry_after_ms: None,
    })
}

/// §6.4b sender-text pre-flight: the request's `input`, measured by the §22.5
/// extraction ladder in UTF-16 code units, against `declared_cap`
/// (the recipient's `limits.max_inbound_chars`, §8.1) or the §22.5 default
/// (65,536) when the recipient declared none.
///
/// The comparison is strictly greater-than — a message **at** the cap is legal
/// and MUST be published. Refusal: `CONTEXT_TOO_LARGE`, `retryable: false`,
/// the code §22.5 answers with remotely. A declared cap of `0` is §22.5's
/// explicit "no cap" and refuses nothing — the same convention the receiving
/// side's `InboundOptions.max_inbound_chars` uses.
pub fn preflight_sender_text(input: &Value, declared_cap: Option<u64>) -> Result<()> {
    if declared_cap == Some(0) {
        return Ok(());
    }
    let cap = declared_cap.unwrap_or(DEFAULT_MAX_INBOUND_CHARS as u64);
    let len = inbound_text_length(input) as u64;
    if len > cap {
        let source = if declared_cap.is_some() { "declared" } else { "default" };
        return Err(refuse(
            ErrorCode::ContextTooLarge,
            format!(
                "Sender text is {len} UTF-16 code units, over the recipient's {source} \
                 max_inbound_chars cap of {cap} (§6.4b pre-flight; nothing was published)"
            ),
            json!({ "limit": "max_inbound_chars", "cap": cap, "length": len }),
        ));
    }
    Ok(())
}

/// §6.4b envelope-size pre-flight: the serialized envelope against the
/// transport's advertised maximum payload (§18.9), integer byte math, at the
/// bound legal. An envelope over it MUST NOT be published — §18.9's remedy, an
/// Object Store `ref` part, is the correct path for the content.
///
/// `error.details` names the limit (`transport_max_payload`) so an operator
/// can tell this refusal from the text cap's; the CODE is the same so a
/// caller's error handling never has to.
pub fn preflight_envelope_size(envelope_bytes: usize, max_payload_bytes: usize) -> Result<()> {
    if envelope_bytes > max_payload_bytes {
        return Err(refuse(
            ErrorCode::ContextTooLarge,
            format!(
                "Serialized envelope is {envelope_bytes} bytes, over the transport's \
                 max_payload of {max_payload_bytes} (§18.9); move the content to an \
                 Object Store ref part (nothing was published)"
            ),
            json!({
                "limit": "transport_max_payload",
                "max_payload_bytes": max_payload_bytes,
                "envelope_bytes": envelope_bytes,
            }),
        ));
    }
    Ok(())
}

/// The media type the §6.4b input-mode check reads a request `input` as: a
/// JSON string is prose (`text/plain`); anything else rides as structured JSON
/// (`application/json`). An inference, stated once so both sides of a Rust
/// pair infer identically.
pub fn input_media_type(input: &Value) -> &'static str {
    if input.is_string() { "text/plain" } else { "application/json" }
}

/// §6.4b content-type pre-flight against the recipient's manifest (§8.1):
///
/// - a `config.accepted_output` that **no** output mode of the target offering
///   can satisfy refuses `CONTENT_TYPE_NOT_SUPPORTED` — the code §6.4 answers
///   with;
/// - input whose type the offering's declared `input_modes` exclude refuses the
///   same way ([`input_media_type`] states the inference).
///
/// An offering the manifest does not declare, or one that declares no modes,
/// refuses nothing here: pre-flight enforces published limits, and an
/// unpublished limit resolves remotely (the fixture's `not_covered` doctrine).
pub fn preflight_content_types(
    manifest: &Manifest,
    offering_id: &str,
    accepted_output: Option<&[String]>,
    input: &Value,
) -> Result<()> {
    let Some(offering) = manifest.offering(offering_id) else { return Ok(()) };

    if let (Some(accepted), Some(produced)) = (accepted_output, offering.output_modes.as_deref()) {
        if !accepted.is_empty() && !accepted.iter().any(|a| produced.contains(a)) {
            return Err(refuse(
                ErrorCode::ContentTypeNotSupported,
                format!(
                    "No requested output mode ({accepted:?}) is one offering '{offering_id}' \
                     produces ({produced:?}) (§6.4b pre-flight; nothing was published)"
                ),
                json!({ "limit": "output_modes", "accepted_output": accepted, "output_modes": produced }),
            ));
        }
    }

    if let Some(input_modes) = offering.input_modes.as_deref() {
        let media = input_media_type(input);
        if !input_modes.is_empty() && !input_modes.iter().any(|m| m == media) {
            return Err(refuse(
                ErrorCode::ContentTypeNotSupported,
                format!(
                    "Input rides as {media}, which offering '{offering_id}'s input_modes \
                     ({input_modes:?}) exclude (§6.4b pre-flight; nothing was published)"
                ),
                json!({ "limit": "input_modes", "input_media_type": media, "input_modes": input_modes }),
            ));
        }
    }
    Ok(())
}

/// The full §6.4b pre-flight for one request, minus the envelope-size check
/// (which needs the serialized bytes and runs after signing): sender text
/// against the declared-or-default cap, then content types when a manifest is
/// at hand.
///
/// `recipient: None` is the manifest-not-at-hand case: the §22.5 **default**
/// still governs the text cap — a sender that fetched nothing may still not
/// publish what no default-configured recipient could accept — while the
/// content-type checks, which cannot run without a manifest, are skipped and
/// any divergence resolves remotely (which is the round trip §8.1's `limits`
/// block exists to spare).
pub fn preflight_request(
    recipient: Option<&Manifest>,
    offering_id: &str,
    input: &Value,
    accepted_output: Option<&[String]>,
) -> Result<()> {
    let declared_cap = recipient.and_then(|m| m.declared_max_inbound_chars());
    preflight_sender_text(input, declared_cap)?;
    if let Some(manifest) = recipient {
        preflight_content_types(manifest, offering_id, accepted_output, input)?;
    }
    Ok(())
}
