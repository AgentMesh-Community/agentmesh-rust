//! The five questions (SPEC.md §3.3.1), as a library.
//!
//! Every agent answers five questions about itself — who are you, what do you
//! do, how are you used, on what terms, what do you refuse — and every answer
//! already lives in operator-declared, signed bytes: the describe document
//! (§10.14), built on the public block (§8.7). This module is the projection
//! from that document to the five answers, and the diff that §3.3.1's
//! consistency rule makes possible: an agent's statements about itself,
//! wherever spoken, are subordinate to its signed declarations, so a stale or
//! inflated self-description stops being an operational nuisance and becomes
//! a checkable defect. Ask, then diff.
//!
//! A LIBRARY, deliberately: describe is served by the platform from declared
//! bytes (§10.14 — a document, not a conversation), so nothing here serves
//! anything. These are pure functions any party uses to project and to
//! compare — a conformance harness, an adapter, a buyer's surface, an
//! interviewer. Nothing here invokes a model, and nothing here invents a
//! fact: every value in a projection is copied or derived from the input
//! bytes, an absent input projects to an absent answer member (absence states
//! nothing), and a question none of whose inputs were declared projects to an
//! EMPTY answer object — explicitly present, stating nothing.
//!
//! The one synthesized sentence is the refusals statement, and it is
//! synthesized precisely because §3.3.1 says refusal is answered mechanically,
//! not by the model: the closure of the declared offerings IS the refusal
//! answer, whoever computes it.
//!
//! Mirrors `sdk-typescript/src/interview.ts`; projection and diff shapes are
//! pinned by `conformance/five-questions.json`, and both SDKs produce
//! byte-identical results over the same fixture.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::client::AgentMesh;
use crate::error::{ErrorCode, MeshError, Result};
use crate::identity::canonical_json;
use crate::manifest::Manifest;

/// The set, in the order §3.3.1 names it — also the order the diff reports
/// mismatches in.
pub const FIVE_QUESTIONS: [&str; 5] =
    ["identity", "capabilities", "usage", "terms", "refusals"];

/// The mechanical refusal sentence (§3.3.1, question 5). Pinned by the
/// fixture: both SDKs emit these exact bytes.
pub const REFUSAL_STATEMENT: &str = "Requests outside the declared offerings are refused.";

/// The members of an advertised offering that answer "how are you used" —
/// the interface slice of a §8.7 `offering_details` entry.
const USAGE_MEMBERS: [&str; 9] = [
    "input_modes",
    "output_modes",
    "input_schema",
    "output_schema",
    "streaming",
    "estimated_duration_ms",
    "needs",
    "delivers",
    "reporting",
];

/// The five answers. Each member is an object whose members were copied or
/// derived from the describe document — see [`project_five_questions`] for
/// which input answers which question. An empty object is an answer too: the
/// agent declared nothing on that question, stated explicitly rather than
/// filled in.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FiveAnswers {
    /// Who are you? `agent_id`, `name`, `owner`, and the registrar-signed
    /// `card` verbatim (SPEC-NAMING §5.3) when the document carried one.
    pub identity: Map<String, Value>,
    /// What do you do? The storefront `description`, the advertised offering
    /// ids (`offerings`), and the registry-materialized `offering_details`
    /// verbatim (§8.7).
    pub capabilities: Map<String, Value>,
    /// How are you used? Schemas, modes, needs/delivers and reporting per
    /// advertised offering, the card-level default modes, and the interaction
    /// style (§8.5.1, §8.5.2, §8.3a).
    pub usage: Map<String, Value>,
    /// On what terms? `skus` (§19.1), `data_use` (§8.10), `compliance`
    /// (§8.11), `sealing` (§8.9), and the `admission` text (§8.7).
    pub terms: Map<String, Value>,
    /// What do you refuse? The closure, computed mechanically: the advertised
    /// offering ids as `boundary`, the `admission` stance when present, and
    /// the standard `statement`.
    pub refusals: Map<String, Value>,
}

impl FiveAnswers {
    /// The answer for a question, by §3.3.1 name.
    fn answer(&self, question: &str) -> Option<&Map<String, Value>> {
        match question {
            "identity" => Some(&self.identity),
            "capabilities" => Some(&self.capabilities),
            "usage" => Some(&self.usage),
            "terms" => Some(&self.terms),
            "refusals" => Some(&self.refusals),
            _ => None,
        }
    }
}

/// One conflict between what an agent declared and what it said elsewhere.
/// `declared` is `Value::Null` when the declaration has no such member —
/// claiming what was never declared is a mismatch, because the signed bytes
/// do not back it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnswerMismatch {
    pub question: String,
    /// `<question>.<member>`, or the bare question when the claim was not
    /// even an answer object.
    pub path: String,
    pub declared: Value,
    pub claimed: Value,
}

fn as_object(v: &Value) -> Option<&Map<String, Value>> {
    v.as_object()
}

/// Project a describe document (§10.14: `agent_id`, the signed `card`, the
/// `public` block verbatim, plus the fields that travel with the storefront —
/// `name`, `sealing`, `data_use`, `compliance`, and `interaction` where the
/// source carried it) to the five answers.
///
/// Copies and derivations only. Unknown members inside verbatim-copied
/// subtrees (the card, a SKU entry, an offering descriptor) ride through
/// untouched; unknown top-level members answer no question and are ignored.
/// Pinned by `conformance/five-questions.json`.
pub fn project_five_questions(doc: &Value) -> Result<FiveAnswers> {
    let Some(doc) = as_object(doc) else {
        return Err(MeshError::code(
            ErrorCode::InputInvalid,
            "a describe document is a JSON object (§10.14)",
        ));
    };
    let public = doc.get("public").and_then(as_object);

    // 1. Who are you? (§3.3.1 row 1: the agent ID, the registrar-signed
    // card, the owner.)
    let mut identity = Map::new();
    for member in ["agent_id", "name", "owner"] {
        if let Some(s) = doc.get(member).and_then(Value::as_str) {
            identity.insert(member.to_string(), Value::String(s.to_string()));
        }
    }
    if let Some(card) = doc.get("card") {
        identity.insert("card".to_string(), card.clone());
    }

    // 2. What do you do? (Row 2: the advertised offerings and their
    // registry-materialized details.)
    let mut capabilities = Map::new();
    if let Some(s) = public.and_then(|p| p.get("description")).and_then(Value::as_str) {
        capabilities.insert("description".to_string(), Value::String(s.to_string()));
    }
    for member in ["offerings", "offering_details"] {
        if let Some(v) = public.and_then(|p| p.get(member)) {
            if v.is_array() {
                capabilities.insert(member.to_string(), v.clone());
            }
        }
    }

    // 3. How are you used? (Row 3: schemas and modes, needs and delivers,
    // interaction style.) The interface slice of each advertised offering;
    // an entry with nothing but its id still names itself, stating nothing
    // more.
    let mut usage = Map::new();
    if let Some(details) = public.and_then(|p| p.get("offering_details")).and_then(Value::as_array) {
        let mut entries: Vec<Value> = Vec::new();
        for detail in details {
            let Some(detail) = as_object(detail) else { continue };
            let Some(id) = detail.get("id").and_then(Value::as_str) else { continue };
            let mut entry = Map::new();
            entry.insert("id".to_string(), Value::String(id.to_string()));
            for member in USAGE_MEMBERS {
                if let Some(v) = detail.get(member) {
                    entry.insert(member.to_string(), v.clone());
                }
            }
            entries.push(Value::Object(entry));
        }
        if !entries.is_empty() {
            usage.insert("offerings".to_string(), Value::Array(entries));
        }
    }
    for member in ["default_input_modes", "default_output_modes"] {
        if let Some(v) = public.and_then(|p| p.get(member)) {
            if v.is_array() {
                usage.insert(member.to_string(), v.clone());
            }
        }
    }
    if let Some(s) = doc.get("interaction").and_then(Value::as_str) {
        usage.insert("interaction".to_string(), Value::String(s.to_string()));
    }

    // 4. On what terms? (Row 4: skus, data_use, compliance, sealing, the
    // admission text, the access block.)
    let mut terms = Map::new();
    if let Some(v) = public.and_then(|p| p.get("skus")) {
        if v.is_array() {
            terms.insert("skus".to_string(), v.clone());
        }
    }
    if let Some(v) = doc.get("data_use") {
        if v.is_object() {
            terms.insert("data_use".to_string(), v.clone());
        }
    }
    if let Some(v) = doc.get("compliance") {
        if v.is_array() {
            terms.insert("compliance".to_string(), v.clone());
        }
    }
    if let Some(s) = doc.get("sealing").and_then(Value::as_str) {
        terms.insert("sealing".to_string(), Value::String(s.to_string()));
    }
    let admission = public.and_then(|p| p.get("admission")).and_then(Value::as_str);
    if let Some(s) = admission {
        terms.insert("admission".to_string(), Value::String(s.to_string()));
    }
    let access = public.and_then(|p| p.get("access")).filter(|v| v.is_object());
    if let Some(v) = access {
        terms.insert("access".to_string(), v.clone());
    }

    // 5. What do you refuse? (Row 5: the closure of the above, answered
    // mechanically.) The advertised ids are the declared boundary; everything
    // outside it is refused, and the admission stance travels with that.
    let mut boundary: Vec<String> = Vec::new();
    let advertised: Vec<Option<&str>> = match public.and_then(|p| p.get("offerings")).and_then(Value::as_array) {
        Some(ids) => ids.iter().map(Value::as_str).collect(),
        None => public
            .and_then(|p| p.get("offering_details"))
            .and_then(Value::as_array)
            .map(|details| {
                details
                    .iter()
                    .map(|d| as_object(d).and_then(|o| o.get("id")).and_then(Value::as_str))
                    .collect()
            })
            .unwrap_or_default(),
    };
    for id in advertised.into_iter().flatten() {
        if !id.is_empty() && !boundary.iter().any(|b| b == id) {
            boundary.push(id.to_string());
        }
    }
    let mut refusals = Map::new();
    refusals.insert(
        "boundary".to_string(),
        Value::Array(boundary.into_iter().map(Value::String).collect()),
    );
    if let Some(s) = admission {
        refusals.insert("admission".to_string(), Value::String(s.to_string()));
    }
    if let Some(v) = access {
        refusals.insert("access".to_string(), v.clone());
    }
    refusals.insert("statement".to_string(), Value::String(REFUSAL_STATEMENT.to_string()));

    Ok(FiveAnswers { identity, capabilities, usage, terms, refusals })
}

/// Diff a claimed set of answers — what an agent said about itself elsewhere,
/// in the same five-question shape — against its declared projection, per
/// §3.3.1's consistency rule: the signed bytes govern.
///
/// Only claimed members are compared: silence claims nothing, and a declared
/// member nobody repeated is no conflict. Comparison is byte-exact after
/// RFC 8785 canonicalization. Mismatches come back in a fixed order —
/// questions as §3.3.1 names them, members lexicographic within a question —
/// so two implementations report the same conflicts in the same sequence.
/// Pinned by `conformance/five-questions.json`.
pub fn diff_answers(declared: &FiveAnswers, claimed: &Value) -> Result<Vec<AnswerMismatch>> {
    let Some(claimed) = as_object(claimed) else {
        return Err(MeshError::code(
            ErrorCode::InputInvalid,
            "a claimed answer set is a JSON object keyed by question (§3.3.1)",
        ));
    };
    let mut mismatches = Vec::new();
    for question in FIVE_QUESTIONS {
        let Some(claimed_answer) = claimed.get(question) else { continue };
        let declared_answer = declared
            .answer(question)
            .expect("FIVE_QUESTIONS names only the five members");
        let Some(claimed_answer) = as_object(claimed_answer) else {
            // Not even the right shape: the mismatch is the question itself,
            // with the whole declared answer beside the prose that replaced
            // it.
            mismatches.push(AnswerMismatch {
                question: question.to_string(),
                path: question.to_string(),
                declared: Value::Object(declared_answer.clone()),
                claimed: claimed.get(question).cloned().unwrap_or(Value::Null),
            });
            continue;
        };
        let mut members: Vec<&String> = claimed_answer.keys().collect();
        members.sort();
        for member in members {
            let claimed_value = &claimed_answer[member];
            match declared_answer.get(member) {
                Some(declared_value)
                    if canonical_json(declared_value) == canonical_json(claimed_value) => {}
                declared_value => mismatches.push(AnswerMismatch {
                    question: question.to_string(),
                    path: format!("{question}.{member}"),
                    declared: declared_value.cloned().unwrap_or(Value::Null),
                    claimed: claimed_value.clone(),
                }),
            }
        }
    }
    Ok(mismatches)
}

/// The describe-shaped document derivable from a registry manifest: what the
/// platform's `describe` answer carries, built from the same declared bytes.
/// The registrar-signed card is deliberately absent — the registry get (§9.2)
/// does not carry it, and inventing one would be synthesis. A caller holding
/// the real §10.14 response projects that instead.
pub fn describe_document_of(manifest: &Manifest) -> Result<Value> {
    let m = serde_json::to_value(manifest)?;
    let Some(m) = m.as_object() else {
        return Err(MeshError::code(
            ErrorCode::InvalidManifest,
            "a manifest serializes to a JSON object (§8)",
        ));
    };
    let mut doc = Map::new();
    if let Some(id) = m.get("id") {
        doc.insert("agent_id".to_string(), id.clone());
    }
    for member in ["name", "owner", "interaction", "sealing", "data_use", "compliance", "public"] {
        if let Some(v) = m.get(member) {
            doc.insert(member.to_string(), v.clone());
        }
    }
    Ok(Value::Object(doc))
}

/// The interviewer convenience (§3.3.1, "the interview"): fetch the agent's
/// declared bytes over the connected client — the §9.2 registry get, the
/// SDK's pre-admission read path — project the five answers, hand them back.
/// Testable by code that holds no model — pair with [`diff_answers`] to check
/// a spoken self-description against these.
pub async fn interview(client: &AgentMesh, agent_id: &str) -> Result<FiveAnswers> {
    let manifest = client.get_manifest(agent_id).await?;
    project_five_questions(&describe_document_of(&manifest)?)
}
