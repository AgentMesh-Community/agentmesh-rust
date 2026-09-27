//! Job manifests (`job-manifest-v1`) — the signed record of what an agent
//! delivered.
//!
//! A completion is an answer plus pieces: the files the work produced, each
//! named, tied to the step that made it, and pinned by ref and digest. The
//! manifest is the agent's own signed statement of that set. A first delivery
//! is version 1 and opens a job; a revision is a new completion (a new task)
//! that names the completion it revises, carries the same `job`, and counts
//! how many pieces it carried forward unchanged.
//!
//! Three properties carry the design:
//!
//!  - **The deliverer signs.** `agent` is the key that did the work, and
//!    `sig` is that key's signature over the tagged canonical document. A
//!    reader holding a manifest holds the agent's word for what it delivered,
//!    not the platform's.
//!  - **Reuse is computed, never trusted.** The `reused` member is a claim.
//!    The truth is the pair (prior manifest, this manifest): a piece is reused
//!    when the prior manifest has a piece of the same name and step with the
//!    same ref AND the same digest. [`job_manifest_reuse`] computes it and
//!    [`job_manifest_reuse_claim_holds`] checks the claim against it.
//!  - **The format is a member, and verification refuses any other.** A
//!    signature over some other document shape must never verify as a
//!    manifest, so [`verify_job_manifest`] checks `format` before it checks
//!    bytes.
//!
//! Mirrors `sdk-typescript/src/job-manifest.ts`. Shapes, the canonical bytes,
//! a real signature, the reason for each invalid case and the reuse count for
//! a prior/revision pair are pinned by `conformance/job-manifest.json`
//! (`tests/job_manifest_conformance.rs`).

use std::collections::HashSet;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{ErrorCode, MeshError, Result};
use crate::identity::{b64url, canonical_json, tagged_sig_bytes, unb64url, verify_tagged};
use nkeys::KeyPair;

/// The one value `format` may hold. A verifier refuses every other.
pub const JOB_MANIFEST_FORMAT: &str = "job-manifest-v1";

/// The domain tag inside a job manifest's signed bytes: `sig` covers this
/// prefix + the canonical JSON of the document excluding `sig`. The prefix
/// exists only inside the signed bytes — it never appears in the document
/// itself. Pinned by `conformance/job-manifest.json`.
pub const JOB_MANIFEST_SIG_PREFIX: &str = "agentmesh-job-manifest-v1\n";

/// One delivered piece. `name` and `step` together name it across revisions;
/// `ref` and `digest` say which bytes it is this time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobManifestPiece {
    pub name: String,
    /// The delivery step that produced it.
    pub step: String,
    pub media_type: String,
    /// Where the bytes live (`mesh:artifacts:...`).
    pub r#ref: String,
    /// Size in bytes.
    pub size: u64,
    /// `sha256:` + 64 lowercase hex.
    pub digest: String,
    /// OPTIONAL. Names of the inputs this piece was produced from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub produced_from: Option<Vec<String>>,
    /// OPTIONAL. The piece's place within the delivery: a relative path with
    /// forward slashes, no leading slash and no `..` segment
    /// (`explainer.html`, `clips/beat-02.mp3`), so a reader can lay the
    /// pieces out as the agent did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// OPTIONAL. `"file"` or `"link"`. A link piece's bytes are one URL
    /// (http or https), and a reader shows it as an address rather than a
    /// download. Absent means file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Carried forward unchanged from the prior manifest (same ref, same
    /// digest). Always false on a first delivery.
    pub reused: bool,
}

/// How many of this manifest's pieces carry the same ref and digest as the
/// prior manifest's piece of the same name and step. `of` is this manifest's
/// piece count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobManifestReused {
    pub pieces: u64,
    pub of: u64,
}

/// The `job-manifest-v1` document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobManifest {
    /// Always [`JOB_MANIFEST_FORMAT`].
    pub format: String,
    /// The task id of the job's first delivery; stable across revisions.
    pub job: String,
    /// This completion's task id.
    pub task_id: String,
    /// Required on the wire, nullable: serialized as `null` when `None`.
    pub context_id: Option<String>,
    /// The task id of the completion this one revises; `null` on a first
    /// delivery. Required on the wire, nullable.
    pub revises: Option<String>,
    /// 1 for the first delivery, +1 per revision.
    pub version: u64,
    /// The delivering agent's public key — the signer.
    pub agent: String,
    pub offering: String,
    /// RFC 3339, UTC (`Z`).
    pub produced_at: String,
    pub pieces: Vec<JobManifestPiece>,
    pub reused: JobManifestReused,
    /// base64url Ed25519 over [`JOB_MANIFEST_SIG_PREFIX`] + the canonical
    /// document excluding `sig`, by `agent`. Empty until signed.
    #[serde(default)]
    pub sig: String,
}

/// Why a manifest was refused. The `snake_case` strings are the cross-SDK
/// vocabulary: `conformance/job-manifest.json` names the reason each
/// implementation must give for each invalid case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobManifestReason {
    /// `format` is not `job-manifest-v1`. Checked before anything else.
    WrongFormat,
    /// A member has the wrong shape; the fault's `member` names it.
    Malformed,
    /// `sig` does not verify against `agent` over the tagged canonical bytes.
    BadSignature,
    /// The verifier expected a particular agent and `agent` is a different key.
    AgentMismatch,
}

impl JobManifestReason {
    /// The fixture's spelling of the reason.
    pub fn as_str(&self) -> &'static str {
        match self {
            JobManifestReason::WrongFormat => "wrong_format",
            JobManifestReason::Malformed => "malformed",
            JobManifestReason::BadSignature => "bad_signature",
            JobManifestReason::AgentMismatch => "agent_mismatch",
        }
    }
}

/// A refusal: the reason, the member it is about (as a path — `version`,
/// `pieces[0].digest`, `reused.of`), and a sentence for a person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobManifestFault {
    pub reason: JobManifestReason,
    pub member: String,
    pub message: String,
}

impl fmt::Display for JobManifestFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "job manifest: {} ({}): {}",
            self.member,
            self.reason.as_str(),
            self.message
        )
    }
}

impl std::error::Error for JobManifestFault {}

impl From<JobManifestFault> for MeshError {
    fn from(fault: JobManifestFault) -> Self {
        let code = match fault.reason {
            JobManifestReason::WrongFormat | JobManifestReason::Malformed => {
                ErrorCode::InvalidEnvelope
            }
            JobManifestReason::BadSignature | JobManifestReason::AgentMismatch => {
                ErrorCode::IdentityMismatch
            }
        };
        MeshError::code(code, fault.to_string())
    }
}

/// The outcome of [`validate_job_manifest`] and [`verify_job_manifest`]:
/// `Ok(())`, or the fault.
pub type JobManifestVerdict = std::result::Result<(), JobManifestFault>;

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

/// `^U[A-Z2-7]{55}$` — a user nkey (an agent public key).
fn is_user_nkey(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 56
        && b[0] == b'U'
        && b[1..]
            .iter()
            .all(|c| c.is_ascii_uppercase() || (b'2'..=b'7').contains(c))
}

/// `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$` — RFC 3339 in UTC, the
/// `Z` designator only, matched without a regex engine. Shared with the job
/// doors, which hold a node-stamped instant to the same shape.
pub(crate) fn is_rfc3339_utc(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() < 20 {
        return false;
    }
    let d = |i: usize| b[i].is_ascii_digit();
    if !(d(0) && d(1) && d(2) && d(3) && b[4] == b'-' && d(5) && d(6) && b[7] == b'-')
        || !(d(8) && d(9) && b[10] == b'T' && d(11) && d(12) && b[13] == b':')
        || !(d(14) && d(15) && b[16] == b':' && d(17) && d(18))
    {
        return false;
    }
    let mut i = 19;
    if b[i] == b'.' {
        i += 1;
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i == start {
            return false;
        }
    }
    b.get(i) == Some(&b'Z') && i + 1 == b.len()
}

/// `^sha256:[0-9a-f]{64}$`.
fn is_sha256_digest(s: &str) -> bool {
    match s.strip_prefix("sha256:") {
        Some(hex) => {
            hex.len() == 64
                && hex
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        }
        None => false,
    }
}

/// A piece's place within the delivery: forward slashes, no leading slash,
/// no backslash, no empty segment, no `..` segment.
fn is_delivery_path(s: &str) -> bool {
    !s.is_empty()
        && !s.contains('\\')
        && s.split('/').all(|segment| !segment.is_empty() && segment != "..")
}

pub(crate) fn non_empty_str(v: Option<&Value>) -> Option<&str> {
    v.and_then(Value::as_str).filter(|s| !s.is_empty())
}

/// A JSON number that is a whole number, read the way JavaScript reads it:
/// `1` and `1.0` are the same value, and anything past 2^53 is not exact.
fn as_whole(v: Option<&Value>) -> Option<i64> {
    let x = v?.as_f64()?;
    if x.is_finite() && x.fract() == 0.0 && x.abs() < 9007199254740992.0 {
        Some(x as i64)
    } else {
        None
    }
}

/// A non-negative whole number.
pub(crate) fn as_count(v: Option<&Value>) -> Option<u64> {
    as_whole(v).filter(|n| *n >= 0).map(|n| n as u64)
}

/// Shape check of every member over the raw JSON, with a typed reason.
/// Signature is [`verify_job_manifest`]'s job; this is the shape alone. The
/// rules beyond "each member has its type":
///
///  - version 1 revises nothing and its `job` is its own `task_id`; any later
///    version names the task it revises, which is not itself;
///  - a name and step names one piece — no two pieces share both;
///  - `reused.of` is the piece count and `reused.pieces` is the number of
///    pieces flagged `reused`, so the summary cannot disagree with the list it
///    summarizes. Whether the flags are TRUE is
///    [`job_manifest_reuse_claim_holds`]'s question, which needs the prior
///    manifest.
pub fn validate_job_manifest(doc: &Value) -> JobManifestVerdict {
    let Some(d) = doc.as_object() else {
        return Err(malformed("document", "a job manifest is an object"));
    };
    if d.get("format").and_then(Value::as_str) != Some(JOB_MANIFEST_FORMAT) {
        return Err(fault(
            JobManifestReason::WrongFormat,
            "format",
            format!("format must be \"{JOB_MANIFEST_FORMAT}\""),
        ));
    }
    let Some(job) = non_empty_str(d.get("job")) else {
        return Err(malformed(
            "job",
            "job is the task id of the job's first delivery",
        ));
    };
    let Some(task_id) = non_empty_str(d.get("task_id")) else {
        return Err(malformed("task_id", "task_id is this completion's task id"));
    };
    match d.get("context_id") {
        Some(Value::Null) => {}
        Some(v) if non_empty_str(Some(v)).is_some() => {}
        _ => return Err(malformed("context_id", "context_id is a string or null")),
    }
    let revises = match d.get("revises") {
        Some(Value::Null) => None,
        Some(v) => match non_empty_str(Some(v)) {
            Some(s) => Some(s),
            None => {
                return Err(malformed(
                    "revises",
                    "revises is the prior completion's task id or null",
                ))
            }
        },
        None => {
            return Err(malformed(
                "revises",
                "revises is the prior completion's task id or null",
            ))
        }
    };
    let version = match as_whole(d.get("version")) {
        Some(n) if n >= 1 => n,
        _ => {
            return Err(malformed(
                "version",
                "version is an integer, 1 for the first delivery",
            ))
        }
    };
    if version == 1 {
        if revises.is_some() {
            return Err(malformed(
                "revises",
                "the first delivery (version 1) revises nothing",
            ));
        }
        if job != task_id {
            return Err(malformed(
                "job",
                "the first delivery's job is its own task id",
            ));
        }
    } else {
        match revises {
            None => {
                return Err(malformed(
                    "revises",
                    "a revision names the task id it revises",
                ))
            }
            Some(r) if r == task_id => {
                return Err(malformed("revises", "a completion cannot revise itself"))
            }
            Some(_) => {}
        }
    }
    match non_empty_str(d.get("agent")) {
        Some(k) if is_user_nkey(k) => {}
        _ => {
            return Err(malformed(
                "agent",
                "agent is the delivering agent's public key (an agent nkey)",
            ))
        }
    }
    if non_empty_str(d.get("offering")).is_none() {
        return Err(malformed("offering", "offering is required"));
    }
    match non_empty_str(d.get("produced_at")) {
        Some(t) if is_rfc3339_utc(t) => {}
        _ => {
            return Err(malformed(
                "produced_at",
                "produced_at is an RFC 3339 instant in UTC",
            ))
        }
    }
    let pieces = match d.get("pieces").and_then(Value::as_array) {
        Some(p) if !p.is_empty() => p,
        _ => {
            return Err(malformed(
                "pieces",
                "pieces is a non-empty array — a delivery of nothing has no manifest",
            ))
        }
    };
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut flagged: u64 = 0;
    for (i, p) in pieces.iter().enumerate() {
        let at = format!("pieces[{i}]");
        let Some(p) = p.as_object() else {
            return Err(malformed(at, "each piece is an object"));
        };
        let Some(name) = non_empty_str(p.get("name")) else {
            return Err(malformed(format!("{at}.name"), "name is required"));
        };
        let Some(step) = non_empty_str(p.get("step")) else {
            return Err(malformed(
                format!("{at}.step"),
                "step names the delivery step that produced it",
            ));
        };
        if non_empty_str(p.get("media_type")).is_none() {
            return Err(malformed(
                format!("{at}.media_type"),
                "media_type is required",
            ));
        }
        if non_empty_str(p.get("ref")).is_none() {
            return Err(malformed(
                format!("{at}.ref"),
                "ref says where the bytes live",
            ));
        }
        if as_count(p.get("size")).is_none() {
            return Err(malformed(
                format!("{at}.size"),
                "size is a whole number of bytes",
            ));
        }
        match non_empty_str(p.get("digest")) {
            Some(dg) if is_sha256_digest(dg) => {}
            _ => {
                return Err(malformed(
                    format!("{at}.digest"),
                    "digest is \"sha256:\" followed by 64 lowercase hex digits",
                ))
            }
        }
        if let Some(pf) = p.get("produced_from") {
            let ok = pf
                .as_array()
                .is_some_and(|a| a.iter().all(|x| non_empty_str(Some(x)).is_some()));
            if !ok {
                return Err(malformed(
                    format!("{at}.produced_from"),
                    "produced_from, when present, is an array of input names",
                ));
            }
        }
        if let Some(path) = p.get("path") {
            if !path.as_str().is_some_and(is_delivery_path) {
                return Err(malformed(
                    format!("{at}.path"),
                    "path, when present, is a relative path with forward slashes and no .. segment",
                ));
            }
        }
        if let Some(kind) = p.get("kind") {
            if !matches!(kind.as_str(), Some("file") | Some("link")) {
                return Err(malformed(
                    format!("{at}.kind"),
                    "kind, when present, is \"file\" or \"link\"",
                ));
            }
        }
        let Some(reused) = p.get("reused").and_then(Value::as_bool) else {
            return Err(malformed(format!("{at}.reused"), "reused is a boolean"));
        };
        if !seen.insert((name.to_string(), step.to_string())) {
            return Err(malformed(
                at,
                "a name and step names one piece; this one repeats an earlier piece",
            ));
        }
        if reused {
            flagged += 1;
        }
    }
    let Some(reused) = d.get("reused").and_then(Value::as_object) else {
        return Err(malformed("reused", "reused is { pieces, of }"));
    };
    let Some(claimed) = as_count(reused.get("pieces")) else {
        return Err(malformed("reused.pieces", "reused.pieces is a count"));
    };
    let Some(of) = as_count(reused.get("of")) else {
        return Err(malformed("reused.of", "reused.of is a count"));
    };
    if of != pieces.len() as u64 {
        return Err(malformed(
            "reused.of",
            "reused.of counts this manifest's pieces",
        ));
    }
    if claimed != flagged {
        return Err(malformed(
            "reused.pieces",
            "reused.pieces counts the pieces flagged reused",
        ));
    }
    let Some(sig) = non_empty_str(d.get("sig")) else {
        return Err(malformed("sig", "sig is required"));
    };
    match unb64url(sig) {
        Ok(bytes) if bytes.len() == 64 => {}
        Ok(_) => return Err(malformed("sig", "sig is a 64-byte Ed25519 signature")),
        Err(_) => return Err(malformed("sig", "sig is base64url")),
    }
    Ok(())
}

/// The canonical bytes a manifest's `sig` covers, before tagging: the
/// canonical JSON (§5.3) of the document excluding `sig`.
pub fn canonical_job_manifest_bytes(doc: &Value) -> Result<Vec<u8>> {
    let mut v = doc.clone();
    let Some(map) = v.as_object_mut() else {
        return Err(malformed("document", "a job manifest is an object").into());
    };
    map.remove("sig");
    Ok(canonical_json(&v).into_bytes())
}

/// Verify a signed manifest: shape, then (when asked) that `agent` is the
/// expected key, then the signature against `agent`. Refuses any document
/// whose `format` is not `job-manifest-v1` before looking at the signature.
/// Returns the fault rather than a bare `false` so a reader can act on the
/// reason.
pub fn verify_job_manifest(doc: &Value, expected_agent: Option<&str>) -> JobManifestVerdict {
    validate_job_manifest(doc)?;
    // Validated above: agent and sig are non-empty strings.
    let agent = doc["agent"].as_str().unwrap_or_default();
    if let Some(expected) = expected_agent {
        if agent != expected {
            return Err(fault(
                JobManifestReason::AgentMismatch,
                "agent",
                format!("signed by {agent}, not the expected {expected}"),
            ));
        }
    }
    // Validated above: sig is base64url and 64 bytes long.
    let Ok(sig) = unb64url(doc["sig"].as_str().unwrap_or_default()) else {
        return Err(malformed("sig", "sig is base64url"));
    };
    let Ok(canonical) = canonical_job_manifest_bytes(doc) else {
        return Err(malformed("document", "a job manifest is an object"));
    };
    let verified = match KeyPair::from_public_key(agent) {
        Ok(vpub) => verify_tagged(&vpub, JOB_MANIFEST_SIG_PREFIX, &canonical, &sig),
        Err(_) => false,
    };
    if !verified {
        return Err(fault(
            JobManifestReason::BadSignature,
            "sig",
            "sig does not verify against agent over the tagged canonical document",
        ));
    }
    Ok(())
}

/// Sign a manifest in place as the delivering agent (`keypair_from_seed` turns
/// a persisted seed into the keypair). Fills `agent` from the key; when the
/// document already names an `agent`, it must be that key (a manifest signed
/// by one key and attributed to another is refused here rather than
/// discovered later by a verifier). `IDENTITY_MISMATCH` on that,
/// `INVALID_ENVELOPE` when the result fails [`validate_job_manifest`].
pub fn sign_job_manifest(doc: &mut JobManifest, agent_kp: &KeyPair) -> Result<()> {
    let public_key = agent_kp.public_key();
    if !doc.agent.is_empty() && doc.agent != public_key {
        return Err(MeshError::code(
            ErrorCode::IdentityMismatch,
            format!(
                "job manifest: agent {} is not the signing key {public_key}",
                doc.agent
            ),
        ));
    }
    doc.agent = public_key;
    let mut v = serde_json::to_value(&*doc)?;
    if let Some(map) = v.as_object_mut() {
        map.remove("sig");
    }
    let bytes = tagged_sig_bytes(JOB_MANIFEST_SIG_PREFIX, canonical_json(&v).as_bytes());
    let sig = agent_kp
        .sign(&bytes)
        .map_err(|e| MeshError::Nkey(e.to_string()))?;
    doc.sig = b64url(&sig);
    validate_job_manifest(&serde_json::to_value(&*doc)?)?;
    Ok(())
}

/// Per piece of `next`, whether it is reused from `prior` (see
/// [`job_manifest_reuse`]).
fn reused_flags(prior: Option<&JobManifest>, next: &JobManifest) -> Vec<bool> {
    next.pieces
        .iter()
        .map(|p| {
            let Some(prior) = prior else { return false };
            prior
                .pieces
                .iter()
                .find(|q| q.name == p.name && q.step == p.step)
                .is_some_and(|before| before.r#ref == p.r#ref && before.digest == p.digest)
        })
        .collect()
}

/// How many of `next`'s pieces are carried forward from `prior`: a piece is
/// reused when `prior` has a piece of the same `name` and `step` whose `ref`
/// AND `digest` both equal it. `of` is `next`'s piece count. With no prior
/// manifest (a first delivery) nothing is reused.
pub fn job_manifest_reuse(prior: Option<&JobManifest>, next: &JobManifest) -> JobManifestReused {
    JobManifestReused {
        pieces: reused_flags(prior, next).iter().filter(|r| **r).count() as u64,
        of: next.pieces.len() as u64,
    }
}

/// Does `next`'s own `reused` member match what [`job_manifest_reuse`]
/// computes? Each piece's `reused` flag is held to the computation too, so a
/// manifest whose count is right but whose flags are on the wrong pieces does
/// not pass. Pass `None` for a first delivery: the claim then holds only when
/// nothing is flagged.
pub fn job_manifest_reuse_claim_holds(prior: Option<&JobManifest>, next: &JobManifest) -> bool {
    if next.reused != job_manifest_reuse(prior, next) {
        return false;
    }
    next.pieces
        .iter()
        .zip(reused_flags(prior, next))
        .all(|(p, flag)| p.reused == flag)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_utc_shapes() {
        for ok in [
            "2026-09-08T09:00:00Z",
            "2026-09-08T09:00:00.000Z",
            "2026-09-08T09:00:00.5Z",
        ] {
            assert!(is_rfc3339_utc(ok), "{ok}");
        }
        for nope in [
            "2026-09-08",
            "2026-09-08T09:00:00",
            "2026-09-08T09:00:00.Z",
            "2026-09-08T09:00:00+00:00",
            "2026-09-08T09:00:00-07:00",
            "2026-09-08 09:00:00Z",
            "2026-09-08T09:00:00Zx",
        ] {
            assert!(!is_rfc3339_utc(nope), "{nope}");
        }
    }

    #[test]
    fn digest_shapes() {
        assert!(is_sha256_digest(&format!("sha256:{}", "a1".repeat(32))));
        assert!(
            !is_sha256_digest(&format!("sha256:{}", "A1".repeat(32))),
            "uppercase hex"
        );
        assert!(
            !is_sha256_digest(&format!("sha256:{}", "a1".repeat(31))),
            "too short"
        );
        assert!(
            !is_sha256_digest(&format!("sha512:{}", "a1".repeat(32))),
            "wrong algorithm"
        );
        assert!(!is_sha256_digest("sha256:notahash"));
    }

    #[test]
    fn delivery_path_shapes() {
        for ok in ["explainer.html", "clips/beat-02.mp3", "a/b/c.txt"] {
            assert!(is_delivery_path(ok), "{ok}");
        }
        for nope in [
            "",
            "/explainer.html",
            "clips/",
            "clips//beat-02.mp3",
            "../beats.txt",
            "clips/../beats.txt",
            "clips\\beat-02.mp3",
        ] {
            assert!(!is_delivery_path(nope), "{nope}");
        }
    }

    #[test]
    fn whole_numbers_read_like_javascript() {
        assert_eq!(as_whole(Some(&serde_json::json!(1))), Some(1));
        assert_eq!(as_whole(Some(&serde_json::json!(1.0))), Some(1));
        assert_eq!(as_whole(Some(&serde_json::json!(1.5))), None);
        assert_eq!(as_whole(Some(&serde_json::json!("1"))), None);
        assert_eq!(as_count(Some(&serde_json::json!(-1))), None);
    }

    fn first_delivery(agent: &str) -> JobManifest {
        JobManifest {
            format: JOB_MANIFEST_FORMAT.into(),
            job: "t1".into(),
            task_id: "t1".into(),
            context_id: None,
            revises: None,
            version: 1,
            agent: agent.into(),
            offering: "story-package".into(),
            produced_at: "2026-09-08T09:00:00.000Z".into(),
            pieces: vec![JobManifestPiece {
                name: "beat script".into(),
                step: "write-the-story".into(),
                media_type: "text/plain".into(),
                r#ref: "mesh:artifacts:01J".into(),
                size: 12,
                digest: format!("sha256:{}", "ab".repeat(32)),
                produced_from: Some(vec!["brief".into()]),
                path: None,
                kind: None,
                reused: false,
            }],
            reused: JobManifestReused { pieces: 0, of: 1 },
            sig: String::new(),
        }
    }

    #[test]
    fn sign_fills_agent_and_verifies() {
        let kp = KeyPair::new_user();
        let mut doc = first_delivery("");
        sign_job_manifest(&mut doc, &kp).unwrap();
        assert_eq!(doc.agent, kp.public_key());
        let v = serde_json::to_value(&doc).unwrap();
        assert_eq!(verify_job_manifest(&v, None), Ok(()));
        assert_eq!(verify_job_manifest(&v, Some(&kp.public_key())), Ok(()));
        // context_id and revises travel as explicit nulls.
        assert!(v["context_id"].is_null() && v["revises"].is_null());
        assert!(v.as_object().unwrap().contains_key("context_id"));
    }

    #[test]
    fn sign_refuses_to_attribute_to_another_key() {
        let kp = KeyPair::new_user();
        let other = KeyPair::new_user().public_key();
        let mut doc = first_delivery(&other);
        let err = sign_job_manifest(&mut doc, &kp).unwrap_err();
        assert!(err.to_string().contains("IDENTITY_MISMATCH"), "{err}");
    }

    #[test]
    fn sign_refuses_a_malformed_result() {
        let kp = KeyPair::new_user();
        let mut doc = first_delivery("");
        doc.pieces[0].digest = "sha256:notahash".into();
        let err = sign_job_manifest(&mut doc, &kp).unwrap_err();
        assert!(err.to_string().contains("INVALID_ENVELOPE"), "{err}");
        assert!(err.to_string().contains("pieces[0].digest"), "{err}");
    }

    #[test]
    fn fault_converts_to_the_matching_code() {
        let m: MeshError = malformed("version", "x").into();
        assert!(m.to_string().starts_with("[INVALID_ENVELOPE]"));
        let b: MeshError = fault(JobManifestReason::BadSignature, "sig", "x").into();
        assert!(b.to_string().starts_with("[IDENTITY_MISMATCH]"));
    }
}
