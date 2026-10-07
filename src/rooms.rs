//! Rooms (mesh://extensions/rooms/v1) — shared conversations for N agents.
//!
//! Full parity with the TS SDK's `rooms.ts`: ephemeral (fan-out), durable
//! (record + drive via the rooms service), and sealed (end-to-end encrypted)
//! rooms, all built from ordinary signed envelopes. A room message is an
//! `emit` whose `context_id` is the `room_id`; authorship is per-message and
//! verified on receipt. Descriptors are creator-signed and cross-verify with
//! TS byte for byte.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD};
use base64::Engine;
use futures::StreamExt;
use nkeys::KeyPair;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::client::AgentMesh;
use crate::envelope::Envelope;
use crate::error::{ErrorCode, MeshError, Result};
use crate::identity::{self, canonical_json};
use crate::{sealed, subjects};

// ── objects ─────────────────────────────────────────────────────────────────

/// The room's identity and, at the capability/sealed grades, the membership
/// token itself. Signed by the creator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomDescriptor {
    pub rooms: String,
    pub room_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub channels: Vec<String>,
    /// The room's plan: where it opens, what it means to work through, and
    /// who facilitates (EXT-5 §8.5). Absent means the creator did not say,
    /// which is not "no rules": it means the room's way of working lives
    /// outside anything a joiner can read.
    ///
    /// Where the room is NOW is [`Room::phase`], read off the record, never
    /// from here. A descriptor is signed once and cannot move; a meeting does.
    ///
    /// DECLARED, NOT ENFORCED — nothing here makes a member wait its turn.
    /// It rides in the signed descriptor so a late joiner reads the
    /// creator's own word rather than inferring rules from the traffic, and
    /// `skip_serializing_if` keeps a descriptor without one byte-identical
    /// to descriptors written before the field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub playbook: Option<RoomPlaybook>,
    /// `"ephemeral"`, or a binding-typed ref (`mesh:rooms:<id>`) for durable.
    pub record: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drive: Option<Vec<String>>,
    pub policy: Value,
    pub privacy: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_fingerprint: Option<String>,
    pub creator: String,
    pub created_at: String,
    #[serde(default)]
    pub sig: String,
}

/// The room's PLAN: how it means to work, named rather than described
/// (EXT-5 §8.5).
///
/// Governance is not the rooms extension's job: who may speak when, how a
/// draft is judged, who holds the pen. What a room CAN do is say which
/// published pattern it is running, so every member reads the same word for
/// it instead of inferring the rules from the traffic. The vocabulary is
/// Agent Collab's (<https://agentcollab.dev>); `standard` names where the
/// pattern is defined so a reader can go and look rather than guess. Free-form
/// strings on purpose: a mesh must carry a pattern this SDK has never heard of
/// rather than dropping it from a signed descriptor.
///
/// THE PLAN, NOT THE STATE. This is the room's opening declaration and its
/// intended shape: where it starts, what it means to work through, and who
/// facilitates. Where the room actually IS lives in the record, as `phase`
/// messages the facilitator signs, because a meeting moves and a signed
/// descriptor cannot. Read the current phase from [`Room::phase`], never from
/// here.
///
/// (This shipped as a single fixed `pattern` for the room's whole life, which
/// modelled a room's opening stance as if it were its biography. The
/// descriptor holds what cannot change; the record holds what happened.
/// `pattern` survives as the phase the room OPENS in.)
///
/// DECLARED, NOT ENFORCED. Nothing in this SDK or the rooms service makes a
/// member wait its turn: the declaration is a contract the members honor, in
/// exactly the way an agent's storefront is its own word. A room that says
/// `floor` and then talks over itself has broken a promise, not a rule, and a
/// surface must not render this as a guarantee. The one pattern with teeth
/// today is `work-board`, and its teeth come from that machinery (EXT-5 §10),
/// not from this field.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RoomPlaybook {
    /// The pattern the room OPENS in, named in its standard, e.g.
    /// `"roll-call"`, `"critique-circle"`, `"work-board"`. Empty (and
    /// omitted on the wire) since 0.18: a plan may state a goal without
    /// committing to a working shape — the shape then emerges in the room,
    /// usually as its facilitator's proposal. A playbook carries a pattern,
    /// a goal, or both.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub pattern: String,
    /// What done looks like, in one sentence. The ask the room exists to
    /// answer; what actually got produced lives in the record, as
    /// `output`-marked artifacts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub goal: Option<String>,
    /// Named things the work starts from. `from` optionally names the member
    /// expected to bring one, so prep is a checklist rather than a hope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inputs: Option<Vec<RoomInput>>,
    /// Named deliverables the room promises, fulfilled by `output`-marked
    /// artifacts in the record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outputs: Option<Vec<String>>,
    /// The patterns the room means to work through, in order, `pattern`
    /// first. A plan, not a schedule and not a track: nothing advances it, and
    /// a facilitator may call a phase that is not on it. Absent means the
    /// creator declared a starting pattern and no further intent.
    ///
    /// Bounded by [`MAX_ROOM_AGENDA`] when a writer honors it: this is signed
    /// into a descriptor every joiner verifies, and no surface should have to
    /// defend against a novel of a pattern name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agenda: Option<Vec<String>>,
    /// The member who may call a phase change. Absent means the creator, who
    /// is the one member every descriptor already names. Declared like
    /// everything else here: it says whose phase calls the members agreed to
    /// follow, and nothing refuses anyone else's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub facilitator: Option<String>,
    /// Where the pattern is defined. Absent means Agent Collab.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub standard: Option<String>,
    /// Roles the creator assigned: agent id → role name. Declared, unenforced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roles: Option<std::collections::BTreeMap<String, String>>,
    /// One line about how this room runs, beside the pattern rather than
    /// instead of it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// One named input the work starts from (EXT-5 §8.5): what it is, and who is
/// expected to bring it. A brought-in artifact with a matching name fulfills
/// it, visibly, in the record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoomInput {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
}

/// Where the room IS right now: the last phase its facilitator called, or the
/// descriptor's opening pattern before anybody has called one.
///
/// Derived, never stored on the wire as a whole. It is a fold over the
/// record's `phase` messages, which is why a late joiner replaying history
/// arrives at the same answer as a member present throughout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoomPhase {
    pub pattern: String,
    pub standard: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Who called it, or `None` while this is still the descriptor's opening
    /// declaration and nobody has moved the room yet. Serialized as `null` in
    /// that case, matching the TS SDK's `by: string | null`.
    pub by: Option<String>,
}

/// Where a pattern is defined when neither the phase message nor the playbook
/// says. The vocabulary's home (EXT-5 §8.5).
const DEFAULT_PATTERN_STANDARD: &str = "https://agentcollab.dev";

/// An empty string is absent, not a value. TypeScript falls through both with
/// one `||`; Rust needs saying, and a phase whose standard is `""` would
/// otherwise render as a link to nowhere.
fn non_empty(s: Option<String>) -> Option<String> {
    s.filter(|v| !v.is_empty())
}

/// An envelope timestamp in milliseconds, or `None` when it does not parse.
/// The live path falls back to now (the frame is here, so it is now-ish); the
/// replay path falls back to 0, which is the oldest thing there is and so can
/// never displace a phase already held.
fn ts_millis(ts: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(ts).ok().map(|dt| dt.timestamp_millis())
}

// ── the phase rules (EXT-5 §8.5) ────────────────────────────────────────────
//
// A live `Room` holds a connection, so the rules that decide where a room IS
// are extracted here as pure functions over the descriptor, exactly as the
// receive rules and the board payloads are. These are what must not quietly
// regress, and they are what the tests below assert.

/// The member whose phase calls move a room: the declared `facilitator`, or
/// the creator when none is declared. `None` only for a room that declared no
/// playbook at all.
pub(crate) fn facilitator_of(d: &RoomDescriptor) -> Option<&str> {
    let pb = d.playbook.as_ref()?;
    Some(pb.facilitator.as_deref().unwrap_or(d.creator.as_str()))
}

/// The phase a descriptor opens in, before anybody has called one. `by` is
/// `None`: nobody has moved this room yet. `None` also for a goal-only plan:
/// the room knows WHAT done looks like but not yet HOW it works, and the
/// first phase call is what gives it a shape.
pub(crate) fn opening_phase(d: &RoomDescriptor) -> Option<RoomPhase> {
    let pb = d.playbook.as_ref()?;
    if pb.pattern.is_empty() {
        return None;
    }
    Some(RoomPhase {
        pattern: pb.pattern.clone(),
        standard: non_empty(pb.standard.clone())
            .unwrap_or_else(|| DEFAULT_PATTERN_STANDARD.to_string()),
        note: non_empty(pb.note.clone()),
        by: None,
    })
}

/// Fold one `phase` message into the phase a room holds.
///
/// Two rules and no others. AUTHORITY: only the facilitator's call moves the
/// room; anybody else's is left where it is, delivered and recorded but
/// inert. FRESHNESS: a call older than the one already held is dropped, so
/// replaying an old batch after the live tail has moved on cannot walk the
/// room backwards.
pub(crate) fn fold_phase(
    d: &RoomDescriptor,
    held: &mut Option<(RoomPhase, i64)>,
    msg: &RoomMessage,
    from: &str,
    ts: i64,
) {
    let RoomMessage::Phase { pattern, standard, note } = msg else { return };
    if facilitator_of(d) != Some(from) {
        return;
    }
    if ts < held.as_ref().map(|(_, at)| *at).unwrap_or(0) {
        return;
    }
    let standard = non_empty(standard.clone())
        .or_else(|| d.playbook.as_ref().and_then(|p| non_empty(p.standard.clone())))
        .unwrap_or_else(|| DEFAULT_PATTERN_STANDARD.to_string());
    *held = Some((
        RoomPhase {
            pattern: pattern.clone(),
            standard,
            note: non_empty(note.clone()),
            by: Some(from.to_string()),
        },
        ts,
    ));
}

/// What is left on the agenda after `here`. Empty when the room declared no
/// agenda or has moved off it. The agenda is a plan, and a room that left it
/// is not lost.
pub(crate) fn remaining_agenda_after(d: &RoomDescriptor, here: Option<&str>) -> Vec<String> {
    let Some(agenda) = d.playbook.as_ref().and_then(|p| p.agenda.as_ref()) else {
        return Vec::new();
    };
    let Some(here) = here else { return Vec::new() };
    match agenda.iter().position(|x| x == here) {
        // Bounded on the way out. Our own writer normalizes the agenda, but
        // this descriptor may be somebody else's, signed, and a signed
        // document cannot be trimmed on the way in — so the ceiling is
        // applied where the value leaves.
        Some(at) => agenda.iter().skip(at + 1).take(MAX_ROOM_AGENDA).cloned().collect(),
        None => Vec::new(),
    }
}

/// The room's account of itself for `me`, sentence by sentence. See
/// [`Room::brief`] for why it exists and why it ends the way it does.
pub(crate) fn brief_text(d: &RoomDescriptor, phase: Option<&RoomPhase>, me: &str) -> String {
    let pb = d.playbook.as_ref();
    if pb.is_none() && phase.is_none() {
        return String::new();
    }
    let name = match d.name.as_deref() {
        Some(n) if !n.is_empty() => format!("This room (\"{n}\")"),
        _ => "This room".to_string(),
    };
    let mut parts: Vec<String> = Vec::new();
    // The WHAT before the HOW, exactly as the TypeScript brief() words it.
    let goal = pb.and_then(|p| p.goal.as_deref()).filter(|g| !g.is_empty());
    if let Some(g) = goal {
        parts.push(format!("{name} exists to produce: {g}"));
    }
    let subject = if goal.is_some() { "It".to_string() } else { name.clone() };
    if let Some(phase) = phase {
        parts.push(format!(
            "{subject} is in its {} phase, a pattern defined at {}.",
            phase.pattern, phase.standard
        ));
    } else if pb.is_some() {
        parts.push(format!("{subject} has not opened in a pattern yet; the facilitator gives it one."));
    }
    let next = remaining_agenda_after(d, phase.map(|p| p.pattern.as_str()));
    if !next.is_empty() {
        parts.push(format!("After it, the room plans: {}.", next.join(", ")));
    }
    if let Some(inputs) = pb.and_then(|p| p.inputs.as_ref()).filter(|i| !i.is_empty()) {
        parts.push(format!(
            "The work starts from: {}.",
            inputs.iter().map(|i| i.name.as_str()).collect::<Vec<_>>().join(", ")
        ));
        let mine: Vec<&str> = inputs
            .iter()
            .filter(|i| i.from.as_deref() == Some(me))
            .map(|i| i.name.as_str())
            .collect();
        if !mine.is_empty() {
            parts.push(format!("You bring: {}.", mine.join(", ")));
        }
    }
    if let Some(outputs) = pb.and_then(|p| p.outputs.as_ref()).filter(|o| !o.is_empty()) {
        parts.push(format!("It promises: {}.", outputs.join(", ")));
    }
    if let Some(note) = phase.and_then(|p| p.note.as_deref()) {
        parts.push(format!("The facilitator's note on this phase: {note}"));
    }
    let mine = d.playbook.as_ref().and_then(|p| p.roles.as_ref()).and_then(|r| r.get(me));
    if let Some(role) = mine {
        parts.push(format!("Your role in this room is {role}."));
    }
    let facilitator = facilitator_of(d);
    parts.push(if facilitator == Some(me) {
        "You facilitate: you are the member whose phase calls move this room.".to_string()
    } else {
        let who = if facilitator == Some(d.creator.as_str()) {
            "the room's creator"
        } else {
            "the room's facilitator"
        };
        format!("Phase calls come from {who}; a phase called by anyone else does not move the room.")
    });
    parts.push(
        "The pattern is what this room says it does. Nothing on the mesh enforces it, so following it is your choice and departing from it is visible in the record."
            .to_string(),
    );
    parts.join(" ")
}

/// The domain tag inside a descriptor's signed bytes (EXT-5 §2): the
/// signature covers this prefix + the canonical descriptor JSON (`sig`
/// excluded). The prefix never appears in the descriptor itself and the
/// encoding of `sig` is unchanged — same scheme as the envelope's
/// `ENVELOPE_SIG_PREFIX` (§5.3).
pub const ROOM_DESCRIPTOR_SIG_PREFIX: &str = "agentmesh-room-descriptor-v1\n";

fn canonical_descriptor_bytes(d: &RoomDescriptor) -> Result<Vec<u8>> {
    let mut v = serde_json::to_value(d)?;
    if let Value::Object(ref mut m) = v {
        m.remove("sig");
    }
    Ok(canonical_json(&v).into_bytes())
}

/// Sign a descriptor with the creator's keypair, setting `sig`. Signs the
/// tagged form: `ROOM_DESCRIPTOR_SIG_PREFIX` + the canonical descriptor JSON.
pub fn sign_descriptor(mut d: RoomDescriptor, kp: &KeyPair) -> Result<RoomDescriptor> {
    d.sig = String::new();
    let bytes = identity::tagged_sig_bytes(ROOM_DESCRIPTOR_SIG_PREFIX, &canonical_descriptor_bytes(&d)?);
    let sig = kp.sign(&bytes).map_err(|e| MeshError::Nkey(e.to_string()))?;
    d.sig = URL_SAFE_NO_PAD.encode(sig);
    Ok(d)
}

/// Verify a descriptor's creator signature. Tagged form only: the 0.2 draft
/// window's dual-accept closed at protocol 0.3, so a legacy untagged
/// descriptor signature is refused.
pub fn verify_descriptor(d: &RoomDescriptor) -> bool {
    if d.rooms != "v1" || d.room_id.is_empty() || d.creator.is_empty() || d.sig.is_empty() {
        return false;
    }
    let Ok(bytes) = canonical_descriptor_bytes(d) else { return false };
    let Ok(sig) = URL_SAFE_NO_PAD.decode(d.sig.as_bytes()) else { return false };
    match KeyPair::from_public_key(&d.creator) {
        Ok(k) => identity::verify_tagged(&k, ROOM_DESCRIPTOR_SIG_PREFIX, &bytes, &sig),
        Err(_) => false,
    }
}

/// The pasteable membership token (the descriptor as base64url JSON).
pub fn descriptor_to_token(d: &RoomDescriptor) -> Result<String> {
    Ok(URL_SAFE_NO_PAD.encode(serde_json::to_vec(d)?))
}

pub fn descriptor_from_token(token: &str) -> Result<RoomDescriptor> {
    let bytes = URL_SAFE_NO_PAD
        .decode(token.trim().as_bytes())
        .map_err(|e| MeshError::code(ErrorCode::InvalidEnvelope, format!("token: {e}")))?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// A typed room message (the envelope payload). Tag = `type`.
/// Why a member was expelled (EXT-5 §8.1). A closed set, signed with the
/// message. Receivers treat anything else as `conduct` — the enum is small so
/// that nodes can react mechanically, and an unknown value must not become an
/// unhandled case.
pub const EXPEL_SEVERITIES: [&str; 3] = ["timeout", "conduct", "safety"];

/// The roster is a fold over messages from the network, so it needs a ceiling:
/// without one, `join` floods with fresh member strings grow it without bound.
/// Matches the TypeScript SDK's MAX_ROOM_ROSTER.
const MAX_ROOM_ROSTER: usize = 1_000;

/// Cap on a room's declared agenda (EXT-5 §8.5). It is signed into the
/// descriptor every joiner verifies, and a meeting with more than a dozen
/// planned phases has not been planned. Matches the TypeScript SDK's
/// MAX_ROOM_AGENDA.
///
/// Public because a caller assembling a plan by hand should be able to read
/// the ceiling [`normalize_playbook`] will apply.
pub const MAX_ROOM_AGENDA: usize = 12;

/// A plan as it should ride the wire: trimmed, bounded, and absent when it
/// says nothing.
///
/// The mirror of the TypeScript SDK's `normalizePlaybook`, and it has to be a
/// mirror rather than merely a similar idea. Both SDKs sign descriptors that
/// the other verifies, and both feed the same conformance fixtures; two
/// normalizers that disagreed about what a plan looks like would put the same
/// creator's intent on the wire as two different documents.
///
/// Three of the rules matter beyond tidiness. A caller who supplied only an
/// agenda meant to open in its first entry, so `pattern` is derived rather
/// than left empty. `standard` is defaulted, so a reader never has to guess
/// whose vocabulary a pattern name belongs to. And a facilitator written into
/// `roles`, which was the only place it could go before the field existed, is
/// promoted, so "who may call a phase" has exactly one answer.
pub fn normalize_playbook(p: Option<RoomPlaybook>) -> Option<RoomPlaybook> {
    let p = p?;
    let cut = |s: &str, n: usize| s.trim().chars().take(n).collect::<String>();
    let agenda: Vec<String> = p
        .agenda
        .unwrap_or_default()
        .iter()
        .map(|x| cut(x, 64))
        .filter(|x| !x.is_empty())
        .take(MAX_ROOM_AGENDA)
        .collect();
    let pattern = match cut(&p.pattern, 64) {
        x if !x.is_empty() => x,
        _ => agenda.first().cloned().unwrap_or_default(),
    };
    // The plan's WHAT: goal, named inputs, promised outputs. Independent of
    // the working shape — a plan may state any of these with no pattern at
    // all, and the shape then emerges in the room.
    let goal = p.goal.as_deref().map(|g| cut(g, 200)).filter(|g| !g.is_empty());
    let inputs: Vec<RoomInput> = p
        .inputs
        .unwrap_or_default()
        .into_iter()
        .map(|i| RoomInput {
            name: cut(&i.name, 64),
            from: i.from.as_deref().map(|f| cut(f, 120)).filter(|f| !f.is_empty()),
        })
        .filter(|i| !i.name.is_empty())
        .take(12)
        .collect();
    let outputs: Vec<String> = {
        let mut seen = std::collections::HashSet::new();
        p.outputs
            .unwrap_or_default()
            .iter()
            .map(|o| cut(o, 64))
            .filter(|o| !o.is_empty())
            .filter(|o| seen.insert(o.clone()))
            .take(12)
            .collect()
    };
    // A playbook exists when it says SOMETHING: a working shape, or a goal.
    // Inputs/outputs alone are not enough — deliverables with no stated ask
    // and no shape is a list nobody can read a meeting out of.
    if pattern.is_empty() && goal.is_none() {
        return None;
    }
    let roles = p.roles.map(|r| {
        r.into_iter()
            .take(32)
            .map(|(k, v)| (k, cut(&v, 40)))
            .collect::<std::collections::BTreeMap<String, String>>()
    });
    let facilitator = p
        .facilitator
        .map(|f| f.trim().to_string())
        .filter(|f| !f.is_empty())
        .or_else(|| {
            roles
                .as_ref()
                .and_then(|r| r.iter().find(|(_, v)| v.eq_ignore_ascii_case("facilitator")))
                .map(|(k, _)| k.clone())
        });
    // `pattern` first and no duplicates anywhere: an agenda is the order the
    // room means to work through, and one that does not begin where the room
    // begins describes a different room. Fully deduped (not just against the
    // opening pattern) because the current phase is found in it by first
    // position — a repeated entry would make "what remains" walk backwards.
    // A room that genuinely revisits a pattern expresses that with phase
    // calls; the plan is a set in order.
    let agenda = if agenda.is_empty() {
        None
    } else {
        let mut seen = std::collections::HashSet::new();
        let mut ordered: Vec<String> = std::iter::once(pattern.clone())
            .chain(agenda)
            .filter(|x| seen.insert(x.clone()))
            .collect();
        ordered.truncate(MAX_ROOM_AGENDA);
        Some(ordered)
    };
    Some(RoomPlaybook {
        pattern,
        goal,
        inputs: if inputs.is_empty() { None } else { Some(inputs) },
        outputs: if outputs.is_empty() { None } else { Some(outputs) },
        agenda,
        facilitator,
        standard: Some(match p.standard.as_deref().map(str::trim) {
            Some(s) if !s.is_empty() => cut(s, 200),
            _ => "https://agentcollab.dev".to_string(),
        }),
        roles: roles.filter(|r| !r.is_empty()),
        note: p.note.map(|n| cut(&n, 280)).filter(|n| !n.is_empty()),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum RoomMessage {
    Genesis {
        descriptor: RoomDescriptor,
    },
    Join {
        member: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        handle: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        operator: Option<String>,
    },
    Say {
        channel: String,
        in_reply_to: Option<String>,
        body: String,
    },
    Artifact {
        name: String,
        version: String,
        #[serde(rename = "ref")]
        ref_: String,
        digest: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        media_type: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        size: Option<u64>,
        /// `default` matters: without it, an implementation that omits a FALSE
        /// boolean — a perfectly ordinary thing to do, and what the TypeScript
        /// SDK's own optional `sealed?: boolean` type permits a caller to
        /// construct — makes this whole artifact message fail to deserialize, so
        /// the entry degrades to `unknown` and the artifact vanishes from the
        /// transcript. Absent means not sealed, which is the only sane reading.
        #[serde(default)]
        sealed: bool,
        /// Where the bytes came from BEFORE this room, when they came from
        /// anywhere (EXT-5 §5.1). A member contributing material it already
        /// held is making a claim about history the room cannot see, and the
        /// claim rides in that member's own signed announcement so it is
        /// attributable. Absent means the bytes originated here.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        origin: Option<String>,
        /// Set when the room holds no bytes at all: they live at this location
        /// and `digest` is the announcer's CLAIM about them (EXT-5 §5.2).
        ///
        /// Not decoration. A client that ignores this renders a linked artifact
        /// exactly like a stored one, sends its user to fetch bytes the drive
        /// never had, and reports the refusal as an error — when the honest
        /// rendering is "held elsewhere, here is where, here is what it should
        /// hash to."
        #[serde(default, skip_serializing_if = "Option::is_none")]
        external: Option<String>,
        /// What this file IS to the meeting: `"input"` (raw material),
        /// `"interim"` (scaffolding), or `"output"` (the thing the room
        /// exists to produce). Declared by the announcing member — intent is
        /// never inferred. Free-form on the wire like every declared
        /// vocabulary here: an unknown value is carried as written. Absent
        /// means undeclared; hand-over delivers only what was explicitly
        /// marked `output`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        role: Option<String>,
    },
    Leave {
        member: String,
    },
    /// The creator removes a member (EXT-5 §8.1). Advisory at the capability
    /// grade — a node folds it out of its roster — and enforced at `acl`, where
    /// the service also refuses the member's credential renewal.
    Expel {
        member: String,
        severity: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        note: Option<String>,
    },
    /// The room moves to another pattern (EXT-5 §8.5). Posted by the
    /// facilitator, meaning the descriptor's `playbook.facilitator`, or the
    /// creator when none is named.
    ///
    /// A phase from anybody else is carried in the record and delivered to
    /// handlers like any other signed statement, and does NOT move the room.
    /// It is deliberately not in [`is_creator_only`]: dropping it would hide
    /// something a member actually said, while obeying it would make the
    /// declared facilitator meaningless.
    Phase {
        pattern: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        standard: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        note: Option<String>,
    },
    Close {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
}

/// Is this message allowed to name the member it names?
///
/// Membership is FIRST-PERSON: an agent joins and leaves for itself. Taking
/// `member` on trust let any agent that learned a room id post a signed
/// `{type:"leave", member: <someone else>}` and erase that member from every
/// other member's roster — the signature verifies, it just does not say what the
/// roster assumed. `expel` is the deliberate exception: it names somebody else by
/// design, which is why it carries the creator gate in [`is_creator_only`].
pub(crate) fn names_only_itself(msg: &RoomMessage, from: &str) -> bool {
    match msg {
        RoomMessage::Join { member, .. } | RoomMessage::Leave { member } => member == from,
        _ => true,
    }
}

/// Lifecycle authority is the creator's alone (EXT-5): genesis, close, and
/// expel. Expel is here because it is the one message that legitimately names
/// another member.
pub(crate) fn is_creator_only(msg: &RoomMessage) -> bool {
    matches!(
        msg,
        RoomMessage::Genesis { .. } | RoomMessage::Close { .. } | RoomMessage::Expel { .. }
    )
}

/// Receivers MUST read an unknown expel severity as `conduct` (§8.1), so a value
/// added later cannot arrive as an unhandled case.
pub(crate) fn normalize_severity(msg: RoomMessage) -> RoomMessage {
    match msg {
        RoomMessage::Expel { member, severity, note }
            if !EXPEL_SEVERITIES.contains(&severity.as_str()) =>
        {
            RoomMessage::Expel { member, severity: "conduct".to_string(), note }
        }
        other => other,
    }
}

/// One entry of a durable room's record.
#[derive(Debug, Clone)]
pub struct RecordEntry {
    pub seq: u64,
    /// The decoded message (say bodies decrypted for sealed rooms), or `None`
    /// if the entry wasn't a recognized room message.
    pub message: Option<RoomMessage>,
    /// The raw record envelope (say body is ciphertext for sealed rooms).
    pub envelope: Value,
}

#[derive(Debug, Clone)]
pub struct AttachResult {
    pub ref_: String,
    pub digest: String,
    pub size: u64,
    pub media_type: Option<String>,
}

#[derive(Debug, Clone)]
pub struct FetchedArtifact {
    pub ref_: String,
    pub name: String,
    pub version: String,
    pub digest: String,
    pub media_type: Option<String>,
    pub size: u64,
    /// Where the bytes came from before this room, when the attacher said (EXT-5 §5.1).
    pub origin: Option<String>,
    pub data: Vec<u8>,
}

/// What [`Room::attach_with`] says about a file beside its bytes.
#[derive(Debug, Clone, Default)]
pub struct AttachOptions {
    /// The file's version. "1" when left out.
    pub version: Option<String>,
    pub media_type: Option<String>,
    /// Where the bytes came from before this room (EXT-5 §5.1).
    pub origin: Option<String>,
    /// What the file is to the meeting: "input", "interim" or "output".
    pub role: Option<String>,
    /// The channel to announce it on. The room's first when left out.
    pub channel: Option<String>,
}

/// What [`Room::link`] announces about a file the room does not hold.
#[derive(Debug, Clone, Default)]
pub struct LinkOptions {
    /// Where the bytes are.
    pub location: String,
    /// What they should hash to: `sha256:` and 64 hex digits.
    pub digest: String,
    pub size: Option<u64>,
    pub version: Option<String>,
    pub media_type: Option<String>,
    pub origin: Option<String>,
    pub role: Option<String>,
    pub channel: Option<String>,
}

/// What [`Room::link`] answers: the file's ref on the drive's index, the
/// digest as claimed, and where the bytes are.
#[derive(Debug, Clone)]
pub struct LinkResult {
    pub ref_: String,
    pub digest: String,
    pub size: Option<u64>,
    pub external: String,
}

/// One file on a room's drive, as the rooms service records it: who attached
/// it, when, and where it came from, which the transcript does not carry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomFile {
    #[serde(rename = "ref")]
    pub ref_: String,
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub digest: String,
    #[serde(default)]
    pub media_type: Option<String>,
    #[serde(default)]
    pub size: Option<u64>,
    #[serde(default)]
    pub attached_by: String,
    #[serde(default)]
    pub attached_at: String,
    #[serde(default)]
    pub origin: Option<String>,
    /// Where the bytes are when the drive does not hold them; the digest is
    /// then the attaching member's claim.
    #[serde(default)]
    pub external: Option<String>,
}

// ── notes on a file (EXT-5 §8.4) ────────────────────────────────────────────

/// What a note says about the bytes it names (EXT-5 §8.4).
///
/// Three values and no more. A note is read mechanically, so the set is closed
/// for the same reason §8.1 closes expel severities — and it is a real enum
/// rather than a `&str` so a caller cannot invent a fourth: a verdict nobody
/// recognizes reads as "not pass" everywhere it lands, which is a decision no
/// typo should get to make.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NoteVerdict {
    Pass,
    Flag,
    Hold,
}

impl NoteVerdict {
    pub const fn as_str(self) -> &'static str {
        match self {
            NoteVerdict::Pass => "pass",
            NoteVerdict::Flag => "flag",
            NoteVerdict::Hold => "hold",
        }
    }

    /// Read a stored note's verdict. `None` for anything outside the three —
    /// a caller deciding on a note MUST NOT treat that as a pass.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "pass" => Some(NoteVerdict::Pass),
            "flag" => Some(NoteVerdict::Flag),
            "hold" => Some(NoteVerdict::Hold),
            _ => None,
        }
    }
}

impl std::fmt::Display for NoteVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for NoteVerdict {
    type Err = MeshError;
    fn from_str(s: &str) -> Result<Self> {
        NoteVerdict::parse(s).ok_or_else(|| {
            MeshError::code(ErrorCode::InvalidEnvelope, "verdict must be one of pass, flag, hold")
        })
    }
}

/// Who judged, as the writing member names them: a detector or service id, the
/// policy it ran, and that policy's version. Opaque to the mesh — nothing here
/// is verified and nothing here confers standing. A note's weight comes from
/// `by`, the member who signed it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NoteSource {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// A note on a file's exact bytes (EXT-5 §8.4).
///
/// It exists because a room multiplies work that only needs doing once: ten
/// members each screening the same attachment is ten paid reads of one
/// document, and none of them can see the others' answer.
///
/// **Keyed by digest**, so it is a statement about those bytes permanently —
/// nobody can have a harmless version noted and then serve a different one.
/// **Additive**: it adds a row beside the file and edits, hides or removes
/// nothing; the room's record is unchanged by it. A reader's own screening
/// still runs — this is prior information they MAY act on and MAY ignore.
/// **Attributed, not privileged**: any member may write one, there is no
/// screener role to grant, and a reader trusts a note because of who signed it.
/// Surfaces MUST show the author and MUST NOT present a note as the room's own
/// verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomNote {
    /// The note's kind. `"screening/v1"` is the one §8.4 defines; a later kind
    /// is a different string, which is why this is not an enum.
    #[serde(default)]
    pub note: String,
    pub digest: String,
    /// `"pass" | "flag" | "hold"`. A string on the way in, like
    /// [`BoardItem::state`], so one note the service versions differently does
    /// not make the whole read fail; put it through [`NoteVerdict::parse`] to
    /// act on it. Writing takes the enum — see [`Room::note`].
    pub verdict: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The member who wrote it, set by the service from the VERIFIED envelope.
    /// Clients never send this, and this type gives them no way to.
    pub by: String,
    /// When the service recorded it, from its own clock. Also never sent.
    pub at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<NoteSource>,
}

/// The write payload (EXT-5 §8.4). Pure, so the one thing that must never
/// appear on it — `by` — is assertable without a broker.
pub(crate) fn note_payload(
    descriptor: &RoomDescriptor,
    digest: &str,
    verdict: NoteVerdict,
    reason: Option<&str>,
    source: Option<&NoteSource>,
) -> Result<Value> {
    let mut m = serde_json::Map::new();
    m.insert("descriptor".to_string(), serde_json::to_value(descriptor)?);
    m.insert("digest".to_string(), json!(digest));
    m.insert("verdict".to_string(), json!(verdict.as_str()));
    if let Some(r) = reason {
        m.insert("reason".to_string(), json!(r));
    }
    if let Some(s) = source {
        m.insert("source".to_string(), serde_json::to_value(s)?);
    }
    Ok(Value::Object(m))
}

/// The read payload. An absent digest is OMITTED, not null: that is what asks
/// for every noted digest in the room.
pub(crate) fn notes_payload(descriptor: &RoomDescriptor, digest: Option<&str>) -> Result<Value> {
    let mut m = serde_json::Map::new();
    m.insert("descriptor".to_string(), serde_json::to_value(descriptor)?);
    if let Some(d) = digest {
        m.insert("digest".to_string(), json!(d));
    }
    Ok(Value::Object(m))
}

// ── the work board (EXT-5 §10) ──────────────────────────────────────────────

/// One past claim on a board item, as the item's history records it (EXT-5
/// §10.1). `outcome` is `"expired" | "abandoned" | "done"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoardItemClaim {
    pub by: String,
    pub at: String,
    pub outcome: String,
}

/// One item on a room's work board (EXT-5 §10.1): a stateful record, not a
/// message — posted open, taken by whichever member claims first.
///
/// Lease expiry is derived on read: an item whose claim lapsed comes back as
/// `open` (with `lease_lapsed` set) whether or not any sweep has run, and the
/// lapsed claim lands on `claims` when somebody re-claims. `result_note` and
/// `artifacts` are the completer's claims — the board records them and never
/// adjudicates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoardItem {
    pub item_id: String,
    pub room_id: String,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Hint: what kind of agent should take this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offering: Option<String>,
    pub posted_by: String,
    pub posted_at: String,
    pub lease_ms: u64,
    /// `"open" | "claimed" | "done" | "withdrawn"`. A string like
    /// `RoomDescriptor.privacy`, so a state added later still parses instead
    /// of making the whole item vanish.
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claimed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claimed_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_expires_at: Option<String>,
    /// Minted per claim (§10.2). The claimer opens the real Task under it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub done_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifacts: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<Vec<BoardItemClaim>>,
    /// Present (true) when the service is presenting an expired claim as an
    /// open item — the lease ran out and nobody has re-claimed yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_lapsed: Option<bool>,
}

/// The board's list reply: the room's items (lease expiry applied, oldest
/// first) with per-state counts.
#[derive(Debug, Clone, Deserialize)]
pub struct BoardList {
    pub items: Vec<BoardItem>,
    #[serde(default)]
    pub open: u64,
    #[serde(default)]
    pub claimed: u64,
    #[serde(default)]
    pub done: u64,
}

/// What [`Room::post_work`] sends (EXT-5 §10.3 `post`). Optional fields are
/// omitted from the wire, never sent as null — same bytes as the TS SDK.
#[derive(Debug, Clone, Default, Serialize)]
pub struct PostWorkInput {
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Hint: what kind of agent should take this.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offering: Option<String>,
    /// Bounds a future claimant's lease (operator-clamped, default 1 hour).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_ms: Option<u64>,
}

/// Every board verb's request is its own fields plus the room's descriptor —
/// membership is decided from the presented descriptor, same as
/// status/cursor. Pure, so the wire shape is testable without a broker.
pub(crate) fn board_payload(descriptor: &RoomDescriptor, fields: Value) -> Result<Value> {
    let mut m = match fields {
        Value::Object(m) => m,
        _ => serde_json::Map::new(),
    };
    m.insert("descriptor".to_string(), serde_json::to_value(descriptor)?);
    Ok(Value::Object(m))
}

/// The write verbs all answer `{item}`; a reply without one is malformed.
fn parse_board_item(resp: Value) -> Result<BoardItem> {
    let item = resp
        .get("item")
        .cloned()
        .ok_or_else(|| MeshError::code(ErrorCode::InvalidEnvelope, "board reply carried no item"))?;
    Ok(serde_json::from_value(item)?)
}

// ── options ─────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct OpenRoomOptions {
    pub name: Option<String>,
    pub channels: Option<Vec<String>>,
    pub policy: Option<Value>,
    /// The room's plan (EXT-5 §8.5): the pattern it opens in, the agenda it
    /// means to work through, and who facilitates. Rides in the signed
    /// descriptor; declared, never enforced.
    pub playbook: Option<RoomPlaybook>,
    /// Provision a durable record + drive via the rooms service.
    pub durable: bool,
    /// Sealed grade: end-to-end encryption (composes with `durable`).
    pub sealed: bool,
    /// acl grade (§7.2): broker-enforced membership. Always durable; the
    /// member carries room traffic on a room-scoped second connection.
    pub acl: bool,
    /// Deliver this member's own messages to its handler too.
    pub include_self: bool,
}

#[derive(Default)]
pub struct JoinRoomOptions {
    pub handle: Option<String>,
    pub operator: Option<String>,
    pub include_self: bool,
    /// Sealed room: the sealed key from the invite.
    pub sealed_key: Option<sealed::SealedKey>,
    /// Sealed room: the raw room key, base64url (e.g. persisted from
    /// [`Room::room_key_b64`]).
    pub room_key: Option<String>,
}

// ── the room ────────────────────────────────────────────────────────────────

type RoomHandler = Arc<dyn Fn(RoomMessage, Envelope) + Send + Sync>;

struct RoomInner {
    mesh: AgentMesh,
    descriptor: RoomDescriptor,
    room_key: Option<[u8; 32]>,
    include_self: bool,
    roster: RwLock<HashSet<String>>,
    handler: RwLock<Option<RoomHandler>>,
    closed: AtomicBool,
    /// The last phase the facilitator called, with the envelope timestamp
    /// (milliseconds) it was called at. `None` while the room is still in the
    /// pattern its descriptor opened with.
    ///
    /// One lock rather than two: the freshness comparison and the write are a
    /// single decision, so replaying an old batch after the live tail has
    /// already moved the room cannot walk it backwards. Timestamps rather
    /// than sequence numbers, because live frames carry no sequence and the
    /// freshness window already bounds how far a clock may lie.
    called_phase: RwLock<Option<(RoomPhase, i64)>>,
    /// acl grade: the room-scoped second connection (§7.2). When present, the
    /// room's live traffic pub/subs here on the broker-enforced namespace.
    acl_conn: Option<async_nats::Client>,
}

/// A room the agent has opened or joined.
#[derive(Clone)]
pub struct Room {
    inner: Arc<RoomInner>,
}

impl Room {
    pub fn id(&self) -> &str {
        &self.inner.descriptor.room_id
    }
    pub fn descriptor(&self) -> &RoomDescriptor {
        &self.inner.descriptor
    }
    pub fn token(&self) -> Result<String> {
        descriptor_to_token(&self.inner.descriptor)
    }
    pub fn sealed(&self) -> bool {
        self.inner.descriptor.privacy == "sealed"
    }
    /// Whether this room is broker-enforced (acl grade).
    pub fn acl(&self) -> bool {
        self.inner.descriptor.privacy == "acl"
    }
    pub fn durable(&self) -> bool {
        self.inner.descriptor.record.starts_with("mesh:rooms:")
    }
    pub fn closed(&self) -> bool {
        self.inner.closed.load(Ordering::SeqCst)
    }
    /// Members observed so far (creator + joins − leaves). A live view.
    pub fn members(&self) -> Vec<String> {
        self.inner.roster.read().unwrap().iter().cloned().collect()
    }
    /// The room key as base64url, for hosts that persist membership. Store it
    /// with the same care as the agent seed; rejoin via `JoinRoomOptions.room_key`.
    pub fn room_key_b64(&self) -> Option<String> {
        self.inner.room_key.as_ref().map(|k| URL_SAFE_NO_PAD.encode(k))
    }

    // ── the phase (EXT-5 §8.5) ──────────────────────────────────────────

    /// The member whose phase calls move this room: the descriptor's declared
    /// `facilitator`, or the creator when it declared none.
    ///
    /// Never `None` for a room that declares a playbook at all, because the
    /// creator is the one member every descriptor already names. That matters:
    /// "nobody is facilitating" and "the creator is facilitating by default"
    /// are different rooms, and only the second one can be moved.
    pub fn facilitator(&self) -> Option<&str> {
        self.inner.facilitator()
    }

    /// Whether THIS member may call a phase. False in a room with no declared
    /// playbook: there is no phase to move.
    pub fn may_call_phase(&self) -> bool {
        matches!(self.facilitator(), Some(f) if f == self.inner.mesh.agent_id_str())
    }

    /// Where the room is now: the last phase its facilitator called, or the
    /// pattern the descriptor opened with.
    ///
    /// `None` only when the room declared no playbook, which means its way of
    /// working lives somewhere a member cannot read, not that it has none.
    pub fn phase(&self) -> Option<RoomPhase> {
        if let Some((held, _)) = self.inner.called_phase.read().unwrap().as_ref() {
            return Some(held.clone());
        }
        opening_phase(&self.inner.descriptor)
    }

    /// What the room still means to work through, after the phase it is in.
    /// Empty when the creator declared no agenda, or when the room has moved
    /// off it. The agenda is a plan, and a room that left it is not lost.
    pub fn remaining_agenda(&self) -> Vec<String> {
        let here = self.phase();
        remaining_agenda_after(&self.inner.descriptor, here.as_ref().map(|p| p.pattern.as_str()))
    }

    /// The room's own account of itself, in a sentence or three, for handing
    /// to a model.
    ///
    /// This is the delivery half of §8.5 and the reason the declaration is
    /// worth anything: a pattern nobody reads changes no behaviour. A host
    /// carrying this room to an agent puts this in front of it when the agent
    /// joins and again whenever the phase changes: the current phase and the
    /// agent's own position in it, not the standard's whole catalogue, which
    /// is a menu rather than an instruction.
    ///
    /// It says plainly that nothing enforces this, because a model told "you
    /// are in a critique circle" will otherwise reasonably assume something
    /// does. Word for word the TS SDK's `brief()`, so the two SDKs cannot
    /// brief the same agent differently.
    pub fn brief(&self) -> String {
        brief_text(
            &self.inner.descriptor,
            self.phase().as_ref(),
            self.inner.mesh.agent_id_str(),
        )
    }

    /// Move the room to another pattern. Facilitator only.
    ///
    /// A phase change is a MESSAGE, not an edit: it lands in the record
    /// signed, timestamped and attributable, so who moved the room and when is
    /// as checkable as anything anybody said in it. That is the whole reason
    /// it does not live in the descriptor: a descriptor cannot change without
    /// becoming a different room, and a meeting that cannot change its shape
    /// is not a meeting.
    ///
    /// The guard here stops an accident, not an attacker: any member can post
    /// whatever it likes, and every receiver applies the same rule on the way
    /// in. It refuses rather than warns because a facilitator who thinks they
    /// moved the room and did not is worse off than one who got an error.
    pub async fn call_phase(&self, pattern: &str, note: Option<&str>) -> Result<()> {
        let name: String = pattern.trim().chars().take(64).collect();
        if name.is_empty() {
            return Err(MeshError::code(ErrorCode::InvalidEnvelope, "a phase needs a pattern name"));
        }
        let Some(pb) = self.inner.descriptor.playbook.as_ref() else {
            return Err(MeshError::code(
                ErrorCode::InvalidEnvelope,
                "this room declared no playbook, so it has no phases to move between — open a room with one to use this",
            ));
        };
        if !self.may_call_phase() {
            let short: String =
                self.facilitator().unwrap_or_default().chars().take(12).collect();
            return Err(MeshError::code(
                ErrorCode::Unauthorized,
                format!("only this room's facilitator ({short}…) may call a phase"),
            ));
        }
        let msg = RoomMessage::Phase {
            pattern: name,
            standard: pb.standard.clone(),
            note: note.map(|n| n.trim().chars().take(280).collect::<String>()).filter(|n| !n.is_empty()),
        };
        self.inner.post(msg.clone(), None).await?;
        // Own messages are not delivered back unless include_self, so fold it
        // in here too: a facilitator asking `phase()` straight after calling
        // one must not be told the room is still where it was.
        let me = self.inner.mesh.agent_id_str().to_string();
        self.inner.apply_phase(&msg, &me, chrono::Utc::now().timestamp_millis());
        Ok(())
    }

    /// Set the message handler. Signature-verified; own messages skipped unless
    /// opened/joined with `include_self`.
    pub fn on_message<F>(&self, f: F)
    where
        F: Fn(RoomMessage, Envelope) + Send + Sync + 'static,
    {
        *self.inner.handler.write().unwrap() = Some(Arc::new(f));
    }

    fn require_room_key(&self) -> Result<[u8; 32]> {
        self.inner
            .room_key
            .ok_or_else(|| MeshError::code(ErrorCode::Internal, "sealed room, but this member holds no room key"))
    }
    fn require_durable(&self) -> Result<()> {
        if self.durable() {
            Ok(())
        } else {
            Err(MeshError::code(ErrorCode::InvalidEnvelope, "this room is ephemeral: it has no record or drive"))
        }
    }

    /// Say something on a channel. Encrypted under the room key in a sealed room.
    pub async fn say(&self, body: &str, channel: Option<&str>, in_reply_to: Option<&str>) -> Result<()> {
        let ch = channel.map(String::from).unwrap_or_else(|| self.inner.default_channel().to_string());
        let wire = if self.sealed() {
            sealed::seal_body(body, &self.require_room_key()?)?
        } else {
            body.to_string()
        };
        self.inner
            .post(
                RoomMessage::Say { channel: ch.clone(), in_reply_to: in_reply_to.map(String::from), body: wire },
                Some(&ch),
            )
            .await
    }

    /// Invite another agent (pairwise `rooms.invite`). Sealed rooms seal the
    /// room key to the invitee's published encryption key; an agent with no
    /// encryption key cannot be invited.
    pub async fn invite(&self, agent_id: &str, note: Option<&str>) -> Result<Value> {
        let sealed_key = if self.sealed() {
            let key = self.require_room_key()?;
            // Not `get_manifest(...).encryption_key`: that took the key from
            // whatever answered the registry call, so a forged reply got the room
            // key sealed to the forger (assessment 2026-07-25, finding 6.5).
            // `encryption_key_for` hands back a key only when the agent's own §8.3
            // claim vouches for it.
            let peer = self
                .inner
                .mesh
                .encryption_key_for(agent_id)
                .await
                .ok_or_else(|| {
                    let short = &agent_id[..agent_id.len().min(12)];
                    MeshError::code(ErrorCode::InvalidEnvelope, format!("cannot invite {short}… to a sealed room: it has published no verifiable encryption key — either it declared none, or its manifest carries no §8.3 key claim we could check it against, which an agent fixes by re-registering"))
                })?;
            Some(sealed::seal_key_to(&key, &peer)?)
        } else {
            None
        };
        if self.acl() {
            // Admit before delivering: the invitee can only get a scoped
            // credential once the service has them on the admit list.
            self.inner
                .mesh
                .service_request(subjects::rooms::ADMIT, json!({ "descriptor": self.inner.descriptor, "agent_id": agent_id }))
                .await?;
        }
        let payload = json!({
            "rooms": "v1",
            "descriptor": self.inner.descriptor,
            "token": self.token()?,
            "sealed_key": sealed_key,
            "note": note,
        });
        match self.inner.mesh.request(agent_id, "rooms.invite", payload).await {
            Ok(res) => Ok(res.payload),
            // An attended invitee's node answers the §6.4a queued ack and the
            // request layer rejects promptly with the SDK-local REQUEST_QUEUED.
            // For an INVITATION, queued delivery IS success: the operator's
            // session decides later, and the decision arrives as its own
            // message — so the ack fields become the resolved payload, the
            // same `{queued: true, inbox_id}` shape the adapter used to answer
            // inline.
            Err(MeshError::Refusal(eo))
                if eo.code == ErrorCode::RequestQueued.as_str() =>
            {
                Ok(eo.details.unwrap_or_else(|| serde_json::json!({ "queued": true })))
            }
            Err(e) => Err(e),
        }
    }

    /// Post a signed `leave` and stop listening.
    /// Creator only: remove a member (EXT-5 §8.1). `severity` is one of
    /// `timeout` | `conduct` | `safety`; anything else is rejected here rather
    /// than sent, since receivers would silently read it as `conduct`.
    ///
    /// At the `acl` grade this also tells the service, which drops the member
    /// from the admit list and refuses credential renewal — so the member's room
    /// connection lapses within the credential TTL. Re-admission stays possible:
    /// an expel is not forever unless the creator never invites again.
    pub async fn expel(&self, member: &str, severity: &str, note: Option<&str>) -> Result<()> {
        let me = self.inner.mesh.agent_id_str().to_string();
        if me != self.inner.descriptor.creator {
            return Err(MeshError::code(
                ErrorCode::Unauthorized,
                "only the room's creator can expel",
            ));
        }
        if !EXPEL_SEVERITIES.contains(&severity) {
            return Err(MeshError::code(
                ErrorCode::InvalidEnvelope,
                format!("severity must be one of {:?}", EXPEL_SEVERITIES),
            ));
        }
        self.inner
            .post(
                RoomMessage::Expel {
                    member: member.to_string(),
                    severity: severity.to_string(),
                    note: note.map(String::from),
                },
                None,
            )
            .await?;
        if self.acl() {
            self.inner
                .mesh
                .service_request(
                    subjects::rooms::EXPEL,
                    json!({
                        "descriptor": self.inner.descriptor,
                        "member": member,
                        "severity": severity,
                    }),
                )
                .await?;
        }
        Ok(())
    }

    pub async fn leave(&self) -> Result<()> {
        if self.closed() {
            return Ok(());
        }
        let me = self.inner.mesh.agent_id_str().to_string();
        self.inner.post(RoomMessage::Leave { member: me }, None).await?;
        self.inner.closed.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Creator only: post `close`.
    pub async fn close(&self, reason: Option<&str>) -> Result<()> {
        if self.closed() {
            return Ok(());
        }
        if self.inner.mesh.agent_id_str() != self.inner.descriptor.creator {
            return Err(MeshError::code(ErrorCode::Unauthorized, "only the room's creator may close it"));
        }
        self.inner.post(RoomMessage::Close { reason: reason.map(String::from) }, None).await?;
        self.inner.closed.store(true, Ordering::SeqCst);
        Ok(())
    }

    // ── durable operations ──────────────────────────────────────────────

    /// One batch of the record from `from_seq` (default 1). Returns
    /// `(entries, next_seq, done)`.
    pub async fn history(&self, from_seq: Option<u64>, limit: Option<u64>) -> Result<(Vec<RecordEntry>, u64, bool)> {
        self.require_durable()?;
        let resp = self
            .inner
            .mesh
            .service_request(
                subjects::rooms::REPLAY,
                json!({ "descriptor": self.inner.descriptor, "from_seq": from_seq, "limit": limit }),
            )
            .await?;
        let next_seq = resp.get("next_seq").and_then(|v| v.as_u64()).unwrap_or(0);
        let done = resp.get("done").and_then(|v| v.as_bool()).unwrap_or(true);
        let mut entries = Vec::new();
        if let Some(msgs) = resp.get("messages").and_then(|v| v.as_array()) {
            for m in msgs {
                let seq = m.get("seq").and_then(|v| v.as_u64()).unwrap_or(0);
                let env = m.get("envelope").cloned().unwrap_or(Value::Null);
                let parsed = env
                    .get("payload")
                    .cloned()
                    .and_then(|p| serde_json::from_value::<RoomMessage>(p).ok());
                // Replay carries the phase too, which is what makes a late
                // joiner's answer to "what is this room doing" the same as
                // everyone else's. Timestamp-ordered, so replaying an old batch
                // after the live tail has moved the room cannot walk it back.
                if let Some(msg @ RoomMessage::Phase { .. }) = parsed.as_ref() {
                    let from = env.get("from").and_then(|v| v.as_str()).unwrap_or_default();
                    let ts = env
                        .get("ts")
                        .and_then(|v| v.as_str())
                        .and_then(ts_millis)
                        .unwrap_or(0);
                    self.inner.apply_phase(msg, from, ts);
                }
                let message = parsed.map(|msg| self.inner.unseal(msg));
                entries.push(RecordEntry { seq, message, envelope: env });
            }
        }
        Ok((entries, next_seq, done))
    }

    /// The full record, batched under the hood.
    /// This member's read position in the room's record.
    pub async fn cursor(&self) -> Result<u64> {
        self.require_durable()?;
        let res = self
            .inner
            .mesh
            .service_request(subjects::rooms::CURSOR, json!({ "descriptor": self.inner.descriptor }))
            .await?;
        Ok(res.get("seq").and_then(|v| v.as_u64()).unwrap_or(0))
    }

    /// Advance this member's read position. Monotonic: a lower `seq` than the
    /// stored one is ignored rather than rewinding, so a second slower client
    /// cannot make the room look unread again.
    pub async fn mark_read(&self, seq: u64) -> Result<u64> {
        self.require_durable()?;
        let res = self
            .inner
            .mesh
            .service_request(
                subjects::rooms::CURSOR,
                json!({ "descriptor": self.inner.descriptor, "seq": seq }),
            )
            .await?;
        Ok(res.get("seq").and_then(|v| v.as_u64()).unwrap_or(seq))
    }

    pub async fn full_history(&self) -> Result<Vec<RecordEntry>> {
        self.require_durable()?;
        let mut all = Vec::new();
        let mut from = 1u64;
        loop {
            let (entries, next, done) = self.history(Some(from), None).await?;
            all.extend(entries);
            if done || next <= from {
                return Ok(all);
            }
            from = next;
        }
    }

    /// Put a blob on the drive, saying more about it than its media type: its
    /// version, where the bytes came from before this room (EXT-5 §5.1), what
    /// it is to the meeting, and the channel to announce it on. The TypeScript
    /// SDK's `room.attach(name, data, opts)`.
    pub async fn attach_with(&self, name: &str, data: &[u8], opts: AttachOptions) -> Result<AttachResult> {
        self.require_durable()?;
        let stored = if self.sealed() {
            sealed::seal_bytes(data, &self.require_room_key()?)?
        } else {
            data.to_vec()
        };
        let mut req = serde_json::Map::new();
        req.insert("descriptor".into(), serde_json::to_value(&self.inner.descriptor)?);
        req.insert("name".into(), json!(name));
        if let Some(v) = &opts.version {
            req.insert("version".into(), json!(v));
        }
        if let Some(v) = &opts.media_type {
            req.insert("media_type".into(), json!(v));
        }
        if let Some(v) = &opts.origin {
            req.insert("origin".into(), json!(v));
        }
        req.insert("data_b64".into(), json!(B64.encode(&stored)));
        let resp = self.inner.mesh.service_request(subjects::rooms::ATTACH, Value::Object(req)).await?;
        let result = AttachResult {
            ref_: resp.get("ref").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
            digest: resp.get("digest").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
            size: resp.get("size").and_then(|v| v.as_u64()).unwrap_or(0),
            media_type: resp.get("media_type").and_then(|v| v.as_str()).map(String::from),
        };
        self.inner
            .post(
                RoomMessage::Artifact {
                    name: name.to_string(),
                    version: opts.version.clone().unwrap_or_else(|| "1".to_string()),
                    ref_: result.ref_.clone(),
                    digest: result.digest.clone(),
                    media_type: opts.media_type.clone(),
                    size: Some(result.size),
                    sealed: self.sealed(),
                    origin: opts.origin.clone(),
                    external: None,
                    role: opts.role.clone(),
                },
                opts.channel.as_deref(),
            )
            .await?;
        Ok(result)
    }

    /// Announce a file the room does not hold: where it lives and what it
    /// should hash to (EXT-5 §5.2). The drive takes at most 512 KB a file, so
    /// a video or a dataset is linked, never stored. The digest is required: a
    /// pointer with no digest says nothing about what you will get when you
    /// follow it. Nothing on the mesh fetches the location. The TypeScript
    /// SDK's `room.link(name, opts)`.
    pub async fn link(&self, name: &str, opts: LinkOptions) -> Result<LinkResult> {
        self.require_durable()?;
        let mut req = serde_json::Map::new();
        req.insert("descriptor".into(), serde_json::to_value(&self.inner.descriptor)?);
        req.insert("name".into(), json!(name));
        if let Some(v) = &opts.version {
            req.insert("version".into(), json!(v));
        }
        if let Some(v) = &opts.media_type {
            req.insert("media_type".into(), json!(v));
        }
        if let Some(v) = &opts.origin {
            req.insert("origin".into(), json!(v));
        }
        req.insert("location".into(), json!(opts.location));
        req.insert("digest".into(), json!(opts.digest));
        if let Some(v) = opts.size {
            req.insert("size".into(), json!(v));
        }
        let resp = self.inner.mesh.service_request(subjects::rooms::ATTACH, Value::Object(req)).await?;
        let result = LinkResult {
            ref_: resp.get("ref").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
            digest: resp.get("digest").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
            size: resp.get("size").and_then(|v| v.as_u64()),
            external: resp.get("external").and_then(|v| v.as_str()).unwrap_or(&opts.location).to_string(),
        };
        self.inner
            .post(
                RoomMessage::Artifact {
                    name: name.to_string(),
                    version: opts.version.clone().unwrap_or_else(|| "1".to_string()),
                    ref_: result.ref_.clone(),
                    digest: result.digest.clone(),
                    media_type: opts.media_type.clone(),
                    size: result.size,
                    // Never sealed: the room holds no bytes to seal.
                    sealed: false,
                    origin: opts.origin.clone(),
                    external: Some(result.external.clone()),
                    role: opts.role.clone(),
                },
                opts.channel.as_deref(),
            )
            .await?;
        Ok(result)
    }

    /// The room's drive index: every file, newest last. Not the transcript:
    /// the record says a file was announced, this says what is stored and
    /// still fetchable. The TypeScript SDK's `room.files()`.
    pub async fn files(&self) -> Result<Vec<RoomFile>> {
        let s = self.status().await?;
        let list = s.get("drive").and_then(|d| d.get("artifacts")).cloned().unwrap_or(Value::Array(vec![]));
        Ok(serde_json::from_value(list)?)
    }

    /// Put a blob on the drive (encrypted in a sealed room) and post the signed
    /// `artifact` announcement.
    pub async fn attach(&self, name: &str, data: &[u8], media_type: Option<&str>) -> Result<AttachResult> {
        self.require_durable()?;
        let stored = if self.sealed() {
            sealed::seal_bytes(data, &self.require_room_key()?)?
        } else {
            data.to_vec()
        };
        let resp = self
            .inner
            .mesh
            .service_request(
                subjects::rooms::ATTACH,
                json!({
                    "descriptor": self.inner.descriptor,
                    "name": name,
                    "media_type": media_type,
                    "data_b64": B64.encode(&stored),
                }),
            )
            .await?;
        let result = AttachResult {
            ref_: resp.get("ref").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
            digest: resp.get("digest").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
            size: resp.get("size").and_then(|v| v.as_u64()).unwrap_or(0),
            media_type: resp.get("media_type").and_then(|v| v.as_str()).map(String::from),
        };
        self.inner
            .post(
                RoomMessage::Artifact {
                    name: name.to_string(),
                    version: "1".to_string(),
                    ref_: result.ref_.clone(),
                    digest: result.digest.clone(),
                    media_type: media_type.map(String::from),
                    size: Some(result.size),
                    sealed: self.sealed(),
                    // `attach` uploads bytes, so both are None by construction:
                    // nothing came from anywhere else, and the room holds it.
                    // Announcing provenance or linking bytes held elsewhere are
                    // separate calls (EXT-5 §5.1, §5.2), still to be added here.
                    origin: None,
                    external: None,
                    // Undeclared here: marking a file's meeting role (input /
                    // interim / output) is an explicit act via attach_with,
                    // still to be added on this signature.
                    role: None,
                },
                None,
            )
            .await?;
        Ok(result)
    }

    /// Fetch an artifact's bytes by ref (decrypted in a sealed room).
    pub async fn fetch_artifact(&self, ref_: &str) -> Result<FetchedArtifact> {
        self.require_durable()?;
        let resp = self
            .inner
            .mesh
            .service_request(subjects::rooms::FETCH, json!({ "descriptor": self.inner.descriptor, "ref": ref_ }))
            .await?;
        let b64 = resp.get("data_b64").and_then(|v| v.as_str()).unwrap_or_default();
        let mut data = B64
            .decode(b64)
            .map_err(|e| MeshError::code(ErrorCode::Internal, format!("artifact base64: {e}")))?;
        if self.sealed() {
            data = sealed::open_bytes(&data, &self.require_room_key()?)
                .ok_or_else(|| MeshError::code(ErrorCode::Internal, "artifact did not decrypt with this room's key"))?;
        }
        Ok(FetchedArtifact {
            ref_: resp.get("ref").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
            name: resp.get("name").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
            version: resp.get("version").and_then(|v| v.as_str()).unwrap_or("1").to_string(),
            digest: resp.get("digest").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
            media_type: resp.get("media_type").and_then(|v| v.as_str()).map(String::from),
            size: resp.get("size").and_then(|v| v.as_u64()).unwrap_or(0),
            origin: resp.get("origin").and_then(|v| v.as_str()).map(String::from),
            data,
        })
    }

    // ── notes on a file (EXT-5 §8.4) ────────────────────────────────────

    /// Attach a note to a file already on this room's drive, keyed by its
    /// digest.
    ///
    /// A note is a short attributed statement about those exact bytes —
    /// somebody already looked, and here is what they said. It adds a row
    /// beside the file: nothing is edited, hidden or removed, no room message
    /// is posted, and the record is unchanged. Whoever fetches the bytes still
    /// screens them if that is their policy; this is prior information, not a
    /// substitute for it.
    ///
    /// Any member may write one — there is no screener role to grant or
    /// revoke, because conferring one is exactly the invisible setting §8.4 is
    /// trying not to have. `by` and `at` are the SERVICE's to set, from the
    /// verified envelope and its own clock: a client that sends them is
    /// claiming an authorship it cannot prove, which is why this method has no
    /// way to.
    pub async fn note(
        &self,
        digest: &str,
        verdict: NoteVerdict,
        reason: Option<&str>,
        source: Option<NoteSource>,
    ) -> Result<RoomNote> {
        self.require_durable()?;
        if digest.is_empty() {
            return Err(MeshError::code(
                ErrorCode::InvalidEnvelope,
                "a note is keyed by the file's digest, and none was given",
            ));
        }
        let payload = note_payload(&self.inner.descriptor, digest, verdict, reason, source.as_ref())?;
        let resp = self.inner.mesh.service_request(subjects::rooms::NOTE, payload).await?;
        // The service answers `{noted, digest, note, notes_on_file}`; a bare
        // record is accepted too, since a note is unambiguous either way.
        let record = resp.get("note").cloned().unwrap_or(resp);
        Ok(serde_json::from_value(record)?)
    }

    /// The notes on one digest, or — with `None` — every noted file in the
    /// room.
    ///
    /// Notes are ordered as the service returns them and are never merged: two
    /// members who disagree about the same bytes both appear, each with its
    /// author. Show the author. A note is never the room's verdict.
    pub async fn notes(&self, digest: Option<&str>) -> Result<Vec<RoomNote>> {
        self.require_durable()?;
        let payload = notes_payload(&self.inner.descriptor, digest)?;
        let resp = self.inner.mesh.service_request(subjects::rooms::NOTES, payload).await?;
        // A room with no notes is an ordinary answer, not a failure.
        match resp.get("notes").cloned() {
            Some(v) => Ok(serde_json::from_value(v)?),
            None => Ok(Vec::new()),
        }
    }

    /// Record/drive usage and limits, from the rooms service.
    pub async fn status(&self) -> Result<Value> {
        self.require_durable()?;
        self.inner
            .mesh
            .service_request(subjects::rooms::STATUS, json!({ "descriptor": self.inner.descriptor }))
            .await
    }

    // ── the work board (EXT-5 §10) ──────────────────────────────────────

    /// Post a work item on the room's board: one line of what is wanted, open
    /// to whichever member claims it first. The board is implicit — it exists
    /// the moment the first item is posted — but it lives with the rooms
    /// service, so like the record and the drive it needs a durable room.
    pub async fn post_work(&self, input: PostWorkInput) -> Result<BoardItem> {
        self.require_durable()?;
        let payload = board_payload(&self.inner.descriptor, serde_json::to_value(&input)?)?;
        let resp = self.inner.mesh.service_request(subjects::board::POST, payload).await?;
        parse_board_item(resp)
    }

    /// The room's board: every item oldest first, with lease expiry already
    /// applied — an item whose claim lapsed reads as `open` (and carries
    /// `lease_lapsed`) whether or not any sweep has run. The counts summarize
    /// by state, so "anything for me?" is one call.
    pub async fn board_items(&self) -> Result<BoardList> {
        self.require_durable()?;
        let payload = board_payload(&self.inner.descriptor, json!({}))?;
        let resp = self.inner.mesh.service_request(subjects::board::LIST, payload).await?;
        Ok(serde_json::from_value(resp)?)
    }

    /// Claim one open item. Atomic: exactly one claimant wins a contested item
    /// and every other is refused with `BOARD_ITEM_TAKEN` naming the holder
    /// and the lease's end — recover by listing again, not by re-claiming in
    /// a loop. The claim mints a `task_id`: open the real Task under it via
    /// the ordinary deferred-task path, naming the poster as requester
    /// (§10.2) — the board coordinates who does the work; the Task machinery
    /// carries it.
    pub async fn claim_work(&self, item_id: &str, lease_ms: Option<u64>) -> Result<BoardItem> {
        self.require_durable()?;
        let mut fields = json!({ "item_id": item_id });
        if let Some(lease) = lease_ms {
            fields["lease_ms"] = json!(lease);
        }
        let payload = board_payload(&self.inner.descriptor, fields)?;
        let resp = self.inner.mesh.service_request(subjects::board::CLAIM, payload).await?;
        parse_board_item(resp)
    }

    /// Current claimer only: end the item `done`, with an optional result
    /// note and artifact refs — both claims the board records and never
    /// adjudicates. A completion after the lease lapsed is accepted so long
    /// as nobody re-claimed: work that finished is work that finished.
    pub async fn complete_work(
        &self,
        item_id: &str,
        note: Option<&str>,
        artifacts: Option<Vec<String>>,
    ) -> Result<BoardItem> {
        self.require_durable()?;
        let mut fields = json!({ "item_id": item_id });
        if let Some(n) = note {
            fields["note"] = json!(n);
        }
        if let Some(a) = artifacts {
            fields["artifacts"] = json!(a);
        }
        let payload = board_payload(&self.inner.descriptor, fields)?;
        let resp = self.inner.mesh.service_request(subjects::board::COMPLETE, payload).await?;
        parse_board_item(resp)
    }

    /// Current claimer only: put the item back — `claimed → open`, the
    /// abandoned claim recorded on its history. Honest surrender beats a
    /// lease quietly running out: the item is claimable again now, not at
    /// expiry.
    pub async fn abandon_work(&self, item_id: &str) -> Result<BoardItem> {
        self.require_durable()?;
        let payload = board_payload(&self.inner.descriptor, json!({ "item_id": item_id }))?;
        let resp = self.inner.mesh.service_request(subjects::board::ABANDON, payload).await?;
        parse_board_item(resp)
    }

    /// Poster only: remove an UNCLAIMED item. A live claim is never pulled
    /// out from under its worker — refused with `BOARD_ITEM_TAKEN` — so a
    /// poster who wants an item gone waits out the lease.
    pub async fn withdraw_work(&self, item_id: &str) -> Result<BoardItem> {
        self.require_durable()?;
        let payload = board_payload(&self.inner.descriptor, json!({ "item_id": item_id }))?;
        let resp = self.inner.mesh.service_request(subjects::board::WITHDRAW, payload).await?;
        parse_board_item(resp)
    }

    /// Creator only: delete the durable room's record and drive, freeing quota.
    pub async fn reclaim(&self) -> Result<()> {
        self.require_durable()?;
        if self.inner.mesh.agent_id_str() != self.inner.descriptor.creator {
            return Err(MeshError::code(ErrorCode::Unauthorized, "only the room's creator may reclaim it"));
        }
        self.inner
            .mesh
            .service_request(subjects::rooms::RECLAIM, json!({ "descriptor": self.inner.descriptor }))
            .await
            .map(|_| ())
    }
}

impl RoomInner {
    fn default_channel(&self) -> &str {
        self.descriptor.channels.first().map(String::as_str).unwrap_or("main")
    }

    /// The declared facilitator, or the creator by default. `None` only for a
    /// room that declared no playbook at all.
    fn facilitator(&self) -> Option<&str> {
        facilitator_of(&self.descriptor)
    }

    /// Fold one `phase` message in, if it is the facilitator's and not older
    /// than the phase already held. Called from BOTH the live path and history
    /// replay, so a late joiner lands on the same answer as a member who has
    /// been present all along.
    ///
    /// A phase from anybody else leaves the room where it was. It is still
    /// delivered and still sits in the record: it is a signed statement
    /// somebody made, and the record's job is to keep it.
    fn apply_phase(&self, msg: &RoomMessage, from: &str, ts: i64) {
        let mut held = self.called_phase.write().unwrap();
        fold_phase(&self.descriptor, &mut held, msg, from, ts);
    }

    /// The room's live-traffic subject prefix. acl rooms use the broker-enforced
    /// `mesh.aclroom.<id>` namespace; other grades use the open event namespace.
    fn subject_base(&self) -> String {
        if self.descriptor.privacy == "acl" {
            format!("mesh.aclroom.{}", self.descriptor.room_id)
        } else {
            subjects::event(&format!("room.{}", self.descriptor.room_id))
        }
    }

    async fn post(&self, msg: RoomMessage, channel: Option<&str>) -> Result<()> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(MeshError::code(ErrorCode::Internal, "room is closed"));
        }
        let ch = channel.map(String::from).unwrap_or_else(|| self.default_channel().to_string());
        let payload = serde_json::to_value(&msg)?;
        let bytes = self.mesh.signed_emit(&self.descriptor.room_id, payload)?;
        let subject = format!("{}.{}", self.subject_base(), ch);
        // acl rooms publish on the room-scoped connection; others on the main one.
        let conn = self.acl_conn.as_ref().unwrap_or_else(|| self.mesh.nats());
        conn.publish(subject, bytes.into())
            .await
            .map_err(|e| MeshError::Transport(e.to_string()))
    }

    /// Decrypt a say body for delivery when the room key is held. A body that
    /// fails to open is passed through unchanged (visibly sealed).
    fn unseal(&self, msg: RoomMessage) -> RoomMessage {
        if let (RoomMessage::Say { channel, in_reply_to, body }, Some(key)) = (&msg, self.room_key.as_ref()) {
            if sealed::is_sealed_body(body) {
                if let Some(plain) = sealed::open_body(body, key) {
                    return RoomMessage::Say { channel: channel.clone(), in_reply_to: in_reply_to.clone(), body: plain };
                }
            }
        }
        msg
    }
}

/// One entry from [`AgentMesh::my_rooms`]. `last_seq` is the record's newest
/// sequence and `cursor` this agent's read position, so `last_seq - cursor` is
/// the unread count without a second round trip.
#[derive(Debug, Clone, Deserialize)]
pub struct MyRoom {
    pub room_id: String,
    #[serde(default)]
    pub name: Option<String>,
    pub privacy: String,
    pub created_at: String,
    /// "creator" | "member".
    pub role: String,
    #[serde(default)]
    pub last_seq: Option<u64>,
    #[serde(default)]
    pub cursor: u64,
    /// The room's signed descriptor, to rejoin it by.
    #[serde(default)]
    pub descriptor: Option<RoomDescriptor>,
}

// ── construction on the client ──────────────────────────────────────────────

impl AgentMesh {
    /// Rooms this agent can reach, from the rooms service: acl rooms it has been
    /// admitted to, plus any room it created — each with the record's `last_seq`
    /// and this agent's `cursor`, so unread counts cost one round trip.
    ///
    /// Capability and sealed rooms it merely holds a descriptor for are NOT here
    /// and cannot be: at those grades membership is possession of the descriptor
    /// and the service never learns of it (EXT-5 §6). A client that wants those
    /// listed has to remember its own descriptors.
    pub async fn my_rooms(&self) -> Result<Vec<MyRoom>> {
        let res = self.service_request(subjects::rooms::MINE, json!({})).await?;
        let rooms = res.get("rooms").cloned().unwrap_or(Value::Array(vec![]));
        Ok(serde_json::from_value(rooms).unwrap_or_default())
    }

    /// Open a new ephemeral room (or sealed with `opts.sealed`). The returned
    /// `Room.token()` is the pasteable membership credential.
    pub async fn open_room(&self, opts: OpenRoomOptions) -> Result<Room> {
        self.require_named().await?;
        if opts.acl {
            return self.open_room_acl(opts).await;
        }
        if opts.durable {
            return self.open_room_durable(opts).await;
        }
        let room_key = if opts.sealed { Some(sealed::new_room_key()) } else { None };
        let descriptor = self.build_descriptor(&opts, false, room_key.as_ref())?;
        let room = self.spawn_room(descriptor.clone(), room_key, opts.include_self, None).await?;
        room.inner.post(RoomMessage::Genesis { descriptor }, None).await?;
        Ok(room)
    }

    /// Open a durable room: the rooms service provisions the record and drive
    /// before genesis is posted. Errors if the service refuses (no PAN
    /// operator, quota, unreachable).
    pub async fn open_room_durable(&self, opts: OpenRoomOptions) -> Result<Room> {
        self.require_named().await?;
        let room_key = if opts.sealed { Some(sealed::new_room_key()) } else { None };
        let descriptor = self.build_descriptor(&opts, true, room_key.as_ref())?;
        self.service_request(subjects::rooms::PROVISION, json!({ "descriptor": descriptor })).await?;
        let room = self.spawn_room(descriptor.clone(), room_key, opts.include_self, None).await?;
        room.inner.post(RoomMessage::Genesis { descriptor }, None).await?;
        Ok(room)
    }

    /// Fetch a service-issued scoped credential for an acl room and open the
    /// room-scoped second connection. The caller must already be admitted.
    async fn open_acl_conn(&self, descriptor: &RoomDescriptor) -> Result<async_nats::Client> {
        let cred = self
            .service_request(subjects::rooms::CREDENTIAL, json!({ "descriptor": descriptor }))
            .await?;
        let jwt = cred.get("jwt").and_then(|v| v.as_str())
            .ok_or_else(|| MeshError::code(ErrorCode::Internal, "credential response had no jwt"))?.to_string();
        // The reply space this credential is scoped to. Applying it is what keeps
        // the connection's own inbox subscription from being denied.
        let inbox_prefix = cred.get("inbox_prefix").and_then(|v| v.as_str()).map(|s| s.to_string());
        let seed = cred.get("seed").and_then(|v| v.as_str())
            .ok_or_else(|| MeshError::code(ErrorCode::Internal, "credential response had no seed"))?;
        self.open_scoped_connection(jwt, seed, inbox_prefix.as_deref()).await
    }

    /// Open an acl room (always durable): provision, get the creator's scoped
    /// credential and room-scoped connection, then post genesis.
    pub async fn open_room_acl(&self, opts: OpenRoomOptions) -> Result<Room> {
        self.require_named().await?;
        let mut descriptor = self.build_descriptor(&opts, true, None)?;
        // Re-sign with privacy = acl.
        descriptor.privacy = "acl".to_string();
        let descriptor = sign_descriptor(descriptor, &self.agent_kp())?;
        self.service_request(subjects::rooms::PROVISION, json!({ "descriptor": descriptor })).await?;
        let acl_conn = self.open_acl_conn(&descriptor).await?; // creator admitted at provision
        let room = self.spawn_room(descriptor.clone(), None, opts.include_self, Some(acl_conn)).await?;
        room.inner.post(RoomMessage::Genesis { descriptor }, None).await?;
        Ok(room)
    }

    /// Join a room from its descriptor token. Verifies the creator signature;
    /// for a sealed room, opens/checks the room key; for an acl room, fetches a
    /// scoped credential and opens the room-scoped connection.
    pub async fn join_room(&self, token: &str, opts: JoinRoomOptions) -> Result<Room> {
        // A join announces this agent to every member, so it is a send.
        self.require_named().await?;
        let descriptor = descriptor_from_token(token)?;
        if !verify_descriptor(&descriptor) {
            return Err(MeshError::code(ErrorCode::InvalidEnvelope, "room descriptor failed verification"));
        }
        if descriptor.privacy == "acl" {
            // The service refuses a credential unless this agent was admitted.
            let acl_conn = self.open_acl_conn(&descriptor).await?;
            let room = self.spawn_room(descriptor, None, opts.include_self, Some(acl_conn)).await?;
            room.inner.roster.write().unwrap().insert(self.agent_id_str().to_string());
            room.inner
                .post(RoomMessage::Join { member: self.agent_id_str().to_string(), handle: opts.handle, operator: opts.operator }, None)
                .await?;
            return Ok(room);
        }
        let room_key = if descriptor.privacy == "sealed" {
            let key: [u8; 32] = if let Some(raw) = opts.room_key.as_deref() {
                URL_SAFE_NO_PAD
                    .decode(raw.as_bytes())
                    .map_err(|e| MeshError::code(ErrorCode::InvalidEnvelope, format!("room_key: {e}")))?
                    .try_into()
                    .map_err(|_| MeshError::code(ErrorCode::InvalidEnvelope, "room_key not 32 bytes"))?
            } else if let Some(sk) = opts.sealed_key.as_ref() {
                let seed = self
                    .encryption_seed()
                    .ok_or_else(|| MeshError::code(ErrorCode::Internal, "sealed invite, but this agent has no encryption key to open it"))?;
                sealed::open_sealed_key(sk, &seed)?
            } else {
                return Err(MeshError::code(ErrorCode::InvalidEnvelope, "this room is sealed: joining requires the room key from an invite"));
            };
            if sealed::room_key_fingerprint(&key) != descriptor.key_fingerprint.clone().unwrap_or_default() {
                return Err(MeshError::code(ErrorCode::InvalidEnvelope, "room key does not match the descriptor's key_fingerprint"));
            }
            Some(key)
        } else {
            None
        };
        let room = self.spawn_room(descriptor, room_key, opts.include_self, None).await?;
        room.inner.roster.write().unwrap().insert(self.agent_id_str().to_string());
        room.inner
            .post(
                RoomMessage::Join { member: self.agent_id_str().to_string(), handle: opts.handle, operator: opts.operator },
                None,
            )
            .await?;
        Ok(room)
    }

    fn build_descriptor(&self, opts: &OpenRoomOptions, durable: bool, room_key: Option<&[u8; 32]>) -> Result<RoomDescriptor> {
        use rand::RngCore;
        let mut id = [0u8; 18];
        rand::thread_rng().fill_bytes(&mut id);
        let room_id = URL_SAFE_NO_PAD.encode(id);
        let record = if durable { format!("mesh:rooms:{room_id}") } else { "ephemeral".to_string() };
        let d = RoomDescriptor {
            rooms: "v1".to_string(),
            room_id,
            name: opts.name.clone(),
            channels: opts.channels.clone().unwrap_or_else(|| vec!["main".to_string()]),
            playbook: normalize_playbook(opts.playbook.clone()),
            record,
            drive: None,
            policy: opts.policy.clone().unwrap_or_else(|| json!({})),
            privacy: if room_key.is_some() { "sealed".to_string() } else { "capability".to_string() },
            key_fingerprint: room_key.map(|k| sealed::room_key_fingerprint(k)),
            creator: self.agent_id_str().to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
            sig: String::new(),
        };
        sign_descriptor(d, &self.agent_kp())
    }

    async fn spawn_room(
        &self,
        descriptor: RoomDescriptor,
        room_key: Option<[u8; 32]>,
        include_self: bool,
        acl_conn: Option<async_nats::Client>,
    ) -> Result<Room> {
        let mut roster = HashSet::new();
        roster.insert(descriptor.creator.clone());
        let inner = Arc::new(RoomInner {
            mesh: self.clone(),
            descriptor: descriptor.clone(),
            room_key,
            include_self,
            roster: RwLock::new(roster),
            handler: RwLock::new(None),
            closed: AtomicBool::new(false),
            // The room opens in its descriptor's pattern; nothing has been
            // called yet.
            called_phase: RwLock::new(None),
            acl_conn: acl_conn.clone(),
        });

        // acl rooms listen on the room-scoped connection and enforced namespace.
        let subject = format!("{}.*", inner.subject_base());
        let listen_conn = acl_conn.unwrap_or_else(|| self.nats().clone());
        let mut sub = listen_conn.subscribe(subject).await.map_err(|e| MeshError::Transport(e.to_string()))?;

        let listen = inner.clone();
        let handle = tokio::spawn(async move {
            let room_id = listen.descriptor.room_id.clone();
            let creator = listen.descriptor.creator.clone();
            let me = listen.mesh.agent_id_str().to_string();
            while let Some(msg) = sub.next().await {
                let Ok(env) = crate::codec::decode(&msg.payload) else { continue };
                if env.context_id.as_deref() != Some(room_id.as_str()) {
                    continue;
                }
                let Some(payload) = env.payload.clone() else { continue };
                let Ok(room_msg) = serde_json::from_value::<RoomMessage>(payload) else { continue };
                if is_creator_only(&room_msg) && env.from != creator {
                    continue;
                }
                if !names_only_itself(&room_msg, &env.from) {
                    continue;
                }
                match &room_msg {
                    RoomMessage::Join { member, .. } => {
                        let mut roster = listen.roster.write().unwrap();
                        // Bounded: a join flood must not grow this without end.
                        if roster.len() < MAX_ROOM_ROSTER {
                            roster.insert(member.clone());
                        }
                    }
                    // An expelled member leaves the fold exactly like a leave.
                    RoomMessage::Leave { member } | RoomMessage::Expel { member, .. } => {
                        listen.roster.write().unwrap().remove(member);
                    }
                    // A phase from anyone but the facilitator is DELIVERED and
                    // does not move the room (§8.5). Dropping it would hide a
                    // signed statement a member made; obeying it would make the
                    // declared facilitator meaningless.
                    RoomMessage::Phase { .. } => {
                        let ts = ts_millis(&env.ts)
                            .unwrap_or_else(|| chrono::Utc::now().timestamp_millis());
                        listen.apply_phase(&room_msg, &env.from, ts);
                    }
                    _ => {}
                }
                let is_close = matches!(room_msg, RoomMessage::Close { .. });
                let delivered = listen.unseal(normalize_severity(room_msg));
                if env.from != me || listen.include_self {
                    let handler = listen.handler.read().unwrap().clone();
                    if let Some(h) = handler {
                        h(delivered, env);
                    }
                }
                if is_close {
                    listen.closed.store(true, Ordering::SeqCst);
                    break;
                }
            }
        });
        self.track_task(handle);
        Ok(Room { inner })
    }
}

#[cfg(test)]
mod note_wire {
    //! The note client's wire shape (EXT-5 §8.4). The methods need a live
    //! connection, so the payloads are pure functions ([`note_payload`],
    //! [`notes_payload`]) asserted here — including the field that must never
    //! appear on one.
    use super::*;

    fn descriptor() -> RoomDescriptor {
        let kp = KeyPair::new_user();
        let d = RoomDescriptor {
            rooms: "v1".to_string(),
            room_id: "noted-room-0123456789".to_string(),
            name: Some("noted".to_string()),
            playbook: None,
            channels: vec!["main".to_string()],
            record: "mesh:rooms:noted-room-0123456789".to_string(),
            drive: None,
            policy: serde_json::json!({}),
            privacy: "capability".to_string(),
            key_fingerprint: None,
            creator: kp.public_key(),
            created_at: "2026-08-13T00:00:00Z".to_string(),
            sig: String::new(),
        };
        sign_descriptor(d, &kp).expect("sign")
    }

    const DIGEST: &str = "sha256:1a2b3c4d5e6f";

    #[test]
    fn the_two_subjects_are_spelled_as_the_service_answers_them() {
        assert_eq!(subjects::rooms::NOTE, "mesh.rooms.note");
        assert_eq!(subjects::rooms::NOTES, "mesh.rooms.notes");
    }

    #[test]
    fn the_write_carries_the_digest_and_the_verdict_and_never_the_author() {
        let d = descriptor();
        let p = note_payload(
            &d,
            DIGEST,
            NoteVerdict::Flag,
            Some("Instruction-shaped content in the footer."),
            Some(&NoteSource {
                id: Some("model-armor".into()),
                policy: Some("proj_7d2f".into()),
                version: Some("2026-08-01".into()),
            }),
        )
        .expect("payload");

        // Membership is decided from the presented descriptor, same rule as the
        // record and the drive.
        assert_eq!(p["descriptor"], serde_json::to_value(&d).unwrap());
        assert_eq!(p["digest"], DIGEST);
        assert_eq!(p["verdict"], "flag");
        assert_eq!(p["reason"], "Instruction-shaped content in the footer.");
        assert_eq!(p["source"]["policy"], "proj_7d2f");

        // THE BUG §8.4 WARNS ABOUT: a client that names the author is claiming
        // an authorship it cannot prove. The service takes both from the
        // verified envelope and its own clock.
        assert!(p.get("by").is_none(), "a client must never send `by`");
        assert!(p.get("at").is_none(), "nor `at`");
    }

    #[test]
    fn absent_reason_and_source_are_omitted_rather_than_sent_as_null() {
        // Same bytes as the TS SDK, whose JSON.stringify drops undefined.
        let p = note_payload(&descriptor(), DIGEST, NoteVerdict::Pass, None, None).expect("payload");
        assert_eq!(p["verdict"], "pass");
        assert!(p.get("reason").is_none());
        assert!(p.get("source").is_none());
    }

    #[test]
    fn omitting_the_digest_asks_for_every_noted_file_in_the_room() {
        let d = descriptor();
        let one = notes_payload(&d, Some(DIGEST)).expect("payload");
        assert_eq!(one["digest"], DIGEST);

        let all = notes_payload(&d, None).expect("payload");
        assert_eq!(all["descriptor"], serde_json::to_value(&d).unwrap());
        assert!(
            all.get("digest").is_none(),
            "absent means every noted digest — omitted, not null"
        );
    }

    #[test]
    fn the_verdict_is_a_closed_set_of_three() {
        for (v, s) in [
            (NoteVerdict::Pass, "pass"),
            (NoteVerdict::Flag, "flag"),
            (NoteVerdict::Hold, "hold"),
        ] {
            assert_eq!(v.as_str(), s);
            assert_eq!(serde_json::to_value(v).unwrap(), json!(s));
            assert_eq!(NoteVerdict::parse(s), Some(v));
            assert_eq!(s.parse::<NoteVerdict>().unwrap(), v);
        }

        // A fourth value cannot be constructed and cannot be read back as one
        // of the three. A caller deciding on a note must not read this as pass.
        assert_eq!(NoteVerdict::parse("looks-fine"), None);
        assert!("looks-fine".parse::<NoteVerdict>().is_err());
        assert!(serde_json::from_value::<NoteVerdict>(json!("PASS")).is_err());
    }

    #[test]
    fn a_stored_note_keeps_its_author_and_its_unversioned_verdict() {
        // The record as the service shapes it, `by`/`at` set from the verified
        // envelope.
        let n: RoomNote = serde_json::from_value(json!({
            "note": "screening/v1",
            "digest": DIGEST,
            "verdict": "hold",
            "reason": "could not read it",
            "by": "UGUARD",
            "at": "2026-08-13T14:10:00Z",
            "source": { "id": "model-armor", "policy": "proj_7d2f", "version": "2026-08-01" }
        }))
        .expect("parse a service-shaped note");
        assert_eq!(n.by, "UGUARD", "implementations MUST expose the author");
        assert_eq!(NoteVerdict::parse(&n.verdict), Some(NoteVerdict::Hold));
        assert_eq!(n.source.and_then(|s| s.id).as_deref(), Some("model-armor"));

        // A verdict this SDK does not know keeps the note readable — the author
        // and the digest still say something — but never parses as one of the
        // three, so nothing can mistake it for a pass.
        let future: RoomNote = serde_json::from_value(json!({
            "note": "screening/v2",
            "digest": DIGEST,
            "verdict": "quarantined",
            "by": "UGUARD",
            "at": "2026-08-13T14:10:00Z"
        }))
        .expect("a newer service's note must not make the whole read fail");
        assert_eq!(NoteVerdict::parse(&future.verdict), None);
    }
}

#[cfg(test)]
mod board_wire {
    //! The board client's wire shape (EXT-5 §10.4): the subjects it addresses
    //! and the payload every verb sends. The methods themselves need a live
    //! connection, so the payload construction is a pure function
    //! ([`board_payload`]) asserted here — the same extraction the receive
    //! rules below use.
    use super::*;

    fn signed_descriptor() -> RoomDescriptor {
        let kp = KeyPair::new_user();
        let d = RoomDescriptor {
            rooms: "v1".to_string(),
            room_id: "board-room-0123456789".to_string(),
            name: Some("board".to_string()),
            playbook: None,
            channels: vec!["main".to_string()],
            record: "mesh:rooms:board-room-0123456789".to_string(),
            drive: None,
            policy: serde_json::json!({}),
            privacy: "capability".to_string(),
            key_fingerprint: None,
            creator: kp.public_key(),
            created_at: "2026-08-12T00:00:00Z".to_string(),
            sig: String::new(),
        };
        sign_descriptor(d, &kp).expect("sign")
    }

    #[test]
    fn the_six_subjects_are_spelled_as_the_service_answers_them() {
        assert_eq!(subjects::board::POST, "mesh.board.post");
        assert_eq!(subjects::board::LIST, "mesh.board.list");
        assert_eq!(subjects::board::CLAIM, "mesh.board.claim");
        assert_eq!(subjects::board::COMPLETE, "mesh.board.complete");
        assert_eq!(subjects::board::ABANDON, "mesh.board.abandon");
        assert_eq!(subjects::board::WITHDRAW, "mesh.board.withdraw");
    }

    #[test]
    fn every_verbs_payload_carries_the_descriptor() {
        // Membership is decided from the presented descriptor (same rule as
        // status/cursor), so the descriptor must ride on EVERY verb's payload.
        let d = signed_descriptor();
        let expected = serde_json::to_value(&d).expect("descriptor to value");

        for fields in [
            serde_json::to_value(PostWorkInput { title: "summarize".into(), ..Default::default() }).unwrap(),
            json!({}),
            json!({ "item_id": "item-1", "lease_ms": 120_000 }),
            json!({ "item_id": "item-1", "note": "done", "artifacts": ["mesh:rooms:r/drive/a"] }),
            json!({ "item_id": "item-1" }),
        ] {
            let p = board_payload(&d, fields.clone()).expect("payload");
            assert_eq!(p["descriptor"], expected, "descriptor must ride along");
            if let Value::Object(m) = &fields {
                for (k, v) in m {
                    assert_eq!(&p[k], v, "verb field {k} must survive");
                }
            }
        }
    }

    #[test]
    fn post_input_omits_absent_optionals_rather_than_sending_null() {
        // The TS SDK's JSON.stringify drops undefined fields; these are the
        // same bytes. A null lease_ms happens to be tolerated by the reference
        // service, but omission is the contract.
        let v = serde_json::to_value(PostWorkInput {
            title: "summarize the meeting".into(),
            ..Default::default()
        })
        .expect("serialize");
        assert_eq!(v["title"], "summarize the meeting");
        assert!(v.get("detail").is_none(), "absent detail must be absent, not null");
        assert!(v.get("offering").is_none());
        assert!(v.get("lease_ms").is_none());
    }

    #[test]
    fn a_claimed_item_reply_parses_with_its_minted_task_id() {
        // The claim reply as the rooms service shapes it — including the
        // §10.2 graft: the task_id the claimer opens the real Task under.
        let resp = json!({
            "item": {
                "item_id": "item-1",
                "room_id": "board-room-0123456789",
                "title": "summarize the meeting",
                "posted_by": "UPOSTER",
                "posted_at": "2026-08-12T00:00:00Z",
                "lease_ms": 3_600_000,
                "state": "claimed",
                "claimed_by": "UWORKER",
                "claimed_at": "2026-08-12T00:01:00Z",
                "lease_expires_at": "2026-08-12T01:01:00Z",
                "task_id": "task-abc",
                "claims": [{ "by": "UEARLIER", "at": "2026-08-11T23:00:00Z", "outcome": "expired" }]
            }
        });
        let item = parse_board_item(resp).expect("parse");
        assert_eq!(item.state, "claimed");
        assert_eq!(item.task_id.as_deref(), Some("task-abc"));
        assert_eq!(item.claimed_by.as_deref(), Some("UWORKER"));
        let claims = item.claims.expect("claims history");
        assert_eq!(claims[0].outcome, "expired");

        // A reply without an item is malformed, not a default item.
        assert!(parse_board_item(json!({})).is_err());
    }

    #[test]
    fn the_list_reply_parses_items_and_counts() {
        let list: BoardList = serde_json::from_value(json!({
            "items": [{
                "item_id": "item-1",
                "room_id": "r",
                "title": "open one",
                "posted_by": "UPOSTER",
                "posted_at": "2026-08-12T00:00:00Z",
                "lease_ms": 3_600_000,
                "state": "open",
                "lease_lapsed": true
            }],
            "open": 1, "claimed": 0, "done": 0
        }))
        .expect("parse list");
        assert_eq!(list.items.len(), 1);
        assert_eq!(list.open, 1);
        assert_eq!(list.claimed, 0);
        assert_eq!(list.done, 0);
        // An expired claim presented as open says so.
        assert_eq!(list.items[0].lease_lapsed, Some(true));
    }

    #[test]
    fn the_losing_claimants_refusal_is_distinguishable() {
        // The wire refusal a contested claim answers with (EXT-5 §10.1),
        // mapped through the same path every service error takes.
        let err = MeshError::from_error_object(&crate::error::ErrorObject {
            code: "BOARD_ITEM_TAKEN".to_string(),
            message: "this item cannot be claimed — it is claimed by UWORKER… until later".to_string(),
            details: None,
            retryable: false,
            retry_after_ms: None,
        });
        match err {
            MeshError::Protocol { code, .. } => {
                assert_eq!(code, ErrorCode::BoardItemTaken.as_str());
            }
            other => panic!("expected a Protocol error, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod receive_rules {
    //! The three rules the subscription loop applies before a room message is
    //! allowed to change the roster or reach a handler. They live in the loop,
    //! which needs a live connection, so they are extracted and asserted here —
    //! these are exactly the checks that must not quietly regress.
    use super::*;

    fn kp() -> KeyPair {
        KeyPair::new_user()
    }

    fn descriptor(creator: &str) -> RoomDescriptor {
        RoomDescriptor {
            rooms: "v1".to_string(),
            room_id: "test-room-0123456789ab".to_string(),
            name: Some("test".to_string()),
            playbook: None,
            channels: vec!["main".to_string()],
            record: "ephemeral".to_string(),
            drive: None,
            policy: serde_json::json!({}),
            privacy: "capability".to_string(),
            key_fingerprint: None,
            creator: creator.to_string(),
            created_at: "2026-07-30T00:00:00Z".to_string(),
            sig: String::new(),
        }
    }

#[test]
fn membership_is_first_person() {
    let alice = "UALICE";
    let bob = "UBOB";

    // Joining and leaving for yourself is fine.
    let join_self = RoomMessage::Join { member: alice.to_string(), handle: None, operator: None };
    assert!(names_only_itself(&join_self, alice));
    let leave_self = RoomMessage::Leave { member: alice.to_string() };
    assert!(names_only_itself(&leave_self, alice));

    // THE ATTACK: a signed `leave` naming somebody else. The signature verifies
    // against bob; it just does not make bob an authority on alice's membership.
    // Accepting it erased alice from every other member's roster.
    let leave_other = RoomMessage::Leave { member: alice.to_string() };
    assert!(
        !names_only_itself(&leave_other, bob),
        "bob must not be able to remove alice by naming her in a leave"
    );
    let join_other = RoomMessage::Join { member: alice.to_string(), handle: None, operator: None };
    assert!(
        !names_only_itself(&join_other, bob),
        "bob must not be able to add arbitrary members"
    );

    // Expel is the deliberate exception: it names another member by design, and
    // is gated on the creator instead.
    let expel = RoomMessage::Expel {
        member: alice.to_string(),
        severity: "conduct".to_string(),
        note: None,
    };
    assert!(names_only_itself(&expel, bob), "expel names someone else by design");
    assert!(is_creator_only(&expel), "so it must be creator-gated");
}

#[test]
fn lifecycle_messages_are_the_creators_alone() {
    let creator = kp();
    let signed = sign_descriptor(descriptor(&creator.public_key()), &creator).expect("sign");

    for msg in [
        RoomMessage::Genesis { descriptor: signed.clone() },
        RoomMessage::Close { reason: None },
        RoomMessage::Expel {
            member: "UALICE".to_string(),
            severity: "safety".to_string(),
            note: None,
        },
    ] {
        assert!(is_creator_only(&msg), "{msg:?} must be creator-only");
    }

    // Ordinary traffic is not gated: anybody in the room may speak.
    let say = RoomMessage::Say {
        channel: "main".to_string(),
        in_reply_to: None,
        body: "hello".to_string(),
    };
    assert!(!is_creator_only(&say));
}

#[test]
fn an_unknown_expel_severity_reads_as_conduct() {
    // §8.1 closes the enum so nodes can react mechanically. A value added later
    // must arrive as `conduct`, not as an unhandled case.
    let odd = RoomMessage::Expel {
        member: "UALICE".to_string(),
        severity: "banished-forever".to_string(),
        note: Some("from a newer peer".to_string()),
    };
    match normalize_severity(odd) {
        RoomMessage::Expel { severity, note, member } => {
            assert_eq!(severity, "conduct");
            assert_eq!(member, "UALICE");
            assert_eq!(note.as_deref(), Some("from a newer peer"), "the note survives");
        }
        other => panic!("expected an expel, got {other:?}"),
    }

    // Every declared severity passes through untouched.
    for s in EXPEL_SEVERITIES {
        let msg = RoomMessage::Expel {
            member: "UALICE".to_string(),
            severity: s.to_string(),
            note: None,
        };
        match normalize_severity(msg) {
            RoomMessage::Expel { severity, .. } => assert_eq!(severity, s),
            other => panic!("expected an expel, got {other:?}"),
        }
    }
}
}

#[cfg(test)]
mod phase_rules {
    //! Where a room IS, and who gets to move it (EXT-5 §8.5).
    //!
    //! A live `Room` holds a connection, so the parts that matter are asserted
    //! through the pure functions the room delegates to: the fold
    //! ([`fold_phase`]) that both the live path and history replay run, and the
    //! derivations a host reads ([`opening_phase`], [`remaining_agenda_after`],
    //! [`brief_text`]). The descriptor's own bytes are asserted too, because a
    //! new optional field that ever serializes while absent breaks every
    //! signature written before it existed.
    use super::*;
    use std::collections::BTreeMap;

    const CREATOR: &str = "UCREATOR";

    /// A descriptor as it was written before the plan fields existed. Keys are
    /// in JCS order already, so the canonical form is this minus `sig`.
    const LEGACY_DESCRIPTOR_JSON: &str = concat!(
        r#"{"channels":["main"],"created_at":"2026-08-24T00:00:00Z","creator":"UCREATOR","#,
        r#""name":"legacy","policy":{},"privacy":"capability","record":"ephemeral","#,
        r#""room_id":"legacy-room-0123456789","rooms":"v1","sig":""}"#
    );

    const LEGACY_CANONICAL: &str = concat!(
        r#"{"channels":["main"],"created_at":"2026-08-24T00:00:00Z","creator":"UCREATOR","#,
        r#""name":"legacy","policy":{},"privacy":"capability","record":"ephemeral","#,
        r#""room_id":"legacy-room-0123456789","rooms":"v1"}"#
    );

    /// The normalizer is the half that decides what gets SIGNED, so its rules
    /// have to match the TypeScript SDK's exactly: two normalizers that
    /// disagreed would put the same creator's intent on the wire as two
    /// different documents. Mirrors `normalizePlaybook`'s own tests.
    #[test]
    fn the_plan_is_trimmed_bounded_and_absent_when_it_says_nothing() {
        assert!(normalize_playbook(None).is_none());
        // A pattern of nothing but spaces is not a pattern.
        assert!(normalize_playbook(Some(playbook_of("   "))).is_none());

        let out = normalize_playbook(Some(RoomPlaybook {
            pattern: "  relay  ".to_string(),
            note: Some("x".repeat(400)),
            roles: Some(BTreeMap::from([("UAAA".to_string(), " facilitator ".to_string())])),
            ..playbook_of("relay")
        }))
        .unwrap();
        assert_eq!(out.pattern, "relay");
        assert_eq!(out.standard.as_deref(), Some("https://agentcollab.dev"));
        assert_eq!(out.note.unwrap().chars().count(), 280);
        // A facilitator written into roles is promoted, so "who may call a
        // phase" has one answer rather than two places to look.
        assert_eq!(out.facilitator.as_deref(), Some("UAAA"));
    }

    #[test]
    fn a_plan_opens_where_its_agenda_begins_and_the_agenda_begins_there_once() {
        let only_agenda = normalize_playbook(Some(RoomPlaybook {
            pattern: String::new(),
            agenda: Some(vec!["roll-call".to_string(), "critique-circle".to_string()]),
            ..playbook_of("")
        }))
        .unwrap();
        assert_eq!(only_agenda.pattern, "roll-call");
        assert_eq!(only_agenda.agenda.unwrap(), vec!["roll-call", "critique-circle"]);

        let reordered = normalize_playbook(Some(RoomPlaybook {
            agenda: Some(vec![
                "roll-call".to_string(),
                "critique-circle".to_string(),
                "spec-then-build".to_string(),
            ]),
            ..playbook_of("critique-circle")
        }))
        .unwrap();
        assert_eq!(
            reordered.agenda.unwrap(),
            vec!["critique-circle", "roll-call", "spec-then-build"]
        );

        // An explicit facilitator wins over one inferred from roles.
        let explicit = normalize_playbook(Some(RoomPlaybook {
            facilitator: Some("UCCC".to_string()),
            roles: Some(BTreeMap::from([("UAAA".to_string(), "facilitator".to_string())])),
            ..playbook_of("relay")
        }))
        .unwrap();
        assert_eq!(explicit.facilitator.as_deref(), Some("UCCC"));

        // Every agenda entry once: the phase is found in it by first position,
        // so a repeated entry would make "what remains" walk backwards the
        // second time the room reached it. Revisiting a pattern is what phase
        // calls are for; the plan is a set in order.
        let repeated = normalize_playbook(Some(RoomPlaybook {
            agenda: Some(vec![
                "sketch".to_string(),
                "critique-circle".to_string(),
                "revise".to_string(),
                "critique-circle".to_string(),
            ]),
            ..playbook_of("sketch")
        }))
        .unwrap();
        assert_eq!(repeated.agenda.unwrap(), vec!["sketch", "critique-circle", "revise"]);
    }

    #[test]
    fn the_plan_carries_what_done_looks_like_and_a_goal_alone_is_a_plan() {
        // Mirror of the TypeScript normalizer: goal trimmed and bounded,
        // inputs named with owners, outputs deduped; a goal with no pattern
        // survives (the shape emerges in the room), deliverables alone do not.
        let out = normalize_playbook(Some(RoomPlaybook {
            goal: Some("  a drafted HR handbook  ".to_string()),
            inputs: Some(vec![
                RoomInput { name: " current policies ".to_string(), from: Some("UHRR".to_string()) },
                RoomInput { name: "style guide".to_string(), from: None },
                RoomInput { name: "  ".to_string(), from: None },
            ]),
            outputs: Some(vec![" handbook draft ".to_string(), "handbook draft".to_string(), String::new()]),
            ..playbook_of("critique-circle")
        }))
        .unwrap();
        assert_eq!(out.goal.as_deref(), Some("a drafted HR handbook"));
        assert_eq!(
            out.inputs.unwrap(),
            vec![
                RoomInput { name: "current policies".to_string(), from: Some("UHRR".to_string()) },
                RoomInput { name: "style guide".to_string(), from: None },
            ]
        );
        assert_eq!(out.outputs.unwrap(), vec!["handbook draft"]);

        let goal_only = normalize_playbook(Some(RoomPlaybook {
            goal: Some("a drafted HR handbook".to_string()),
            ..playbook_of("")
        }))
        .unwrap();
        assert!(goal_only.pattern.is_empty());
        // And a goal-only plan opens in NO phase: the first call gives it one.
        assert!(opening_phase(&descriptor(Some(goal_only))).is_none());

        assert!(normalize_playbook(Some(RoomPlaybook {
            outputs: Some(vec!["handbook draft".to_string()]),
            ..playbook_of("")
        }))
        .is_none());
    }

    #[test]
    fn the_brief_speaks_the_goal_before_the_phase() {
        let pb = normalize_playbook(Some(RoomPlaybook {
            goal: Some("a drafted HR handbook".to_string()),
            outputs: Some(vec!["handbook draft".to_string()]),
            ..playbook_of("")
        }))
        .unwrap();
        let d = descriptor(Some(pb));
        let brief = brief_text(&d, None, "UBOB");
        assert!(brief.contains("exists to produce: a drafted HR handbook"));
        assert!(brief.contains("It promises: handbook draft."));
        assert!(brief.contains("has not opened in a pattern yet"));
    }

    fn playbook_of(pattern: &str) -> RoomPlaybook {
        RoomPlaybook {
            pattern: pattern.to_string(),
            goal: None,
            inputs: None,
            outputs: None,
            agenda: None,
            facilitator: None,
            standard: None,
            roles: None,
            note: None,
        }
    }

    fn descriptor(playbook: Option<RoomPlaybook>) -> RoomDescriptor {
        RoomDescriptor {
            rooms: "v1".to_string(),
            room_id: "phase-room-0123456789".to_string(),
            name: Some("design review".to_string()),
            playbook,
            channels: vec!["main".to_string()],
            record: "ephemeral".to_string(),
            drive: None,
            policy: json!({}),
            privacy: "capability".to_string(),
            key_fingerprint: None,
            creator: CREATOR.to_string(),
            created_at: "2026-08-24T00:00:00Z".to_string(),
            sig: String::new(),
        }
    }

    /// A three-phase plan the creator facilitates by default.
    fn planned() -> RoomPlaybook {
        RoomPlaybook {
            pattern: "roll-call".to_string(),
            goal: None,
            inputs: None,
            outputs: None,
            agenda: Some(vec![
                "roll-call".to_string(),
                "critique-circle".to_string(),
                "decide".to_string(),
            ]),
            facilitator: None,
            standard: None,
            roles: Some(BTreeMap::from([("UBOB".to_string(), "critic".to_string())])),
            note: None,
        }
    }

    fn phase_msg(pattern: &str, note: Option<&str>) -> RoomMessage {
        RoomMessage::Phase {
            pattern: pattern.to_string(),
            standard: None,
            note: note.map(String::from),
        }
    }

    #[test]
    fn a_descriptor_with_no_plan_signs_exactly_as_it_did_before_the_plan_existed() {
        // THE PROPERTY: three optional fields were added to a structure whose
        // signature covers every key present. A descriptor written before they
        // existed has to produce the same canonical bytes today, or every
        // signature over one stops verifying.
        let d: RoomDescriptor = serde_json::from_str(LEGACY_DESCRIPTOR_JSON)
            .expect("a pre-plan descriptor still parses");
        assert!(d.playbook.is_none());
        let canonical =
            String::from_utf8(canonical_descriptor_bytes(&d).expect("canonical")).expect("utf-8");
        assert_eq!(
            canonical, LEGACY_CANONICAL,
            "an absent plan is absent from the signed bytes, never present as null"
        );

        // And the same one level down: a playbook naming only its opening
        // pattern carries only that key.
        let bare = RoomPlaybook {
            pattern: "roll-call".to_string(),
            goal: None,
            inputs: None,
            outputs: None,
            agenda: None,
            facilitator: None,
            standard: None,
            roles: None,
            note: None,
        };
        assert_eq!(serde_json::to_string(&bare).unwrap(), r#"{"pattern":"roll-call"}"#);
    }

    #[test]
    fn a_plan_with_an_agenda_and_a_facilitator_round_trips() {
        let mut pb = planned();
        pb.facilitator = Some("UFACILITATOR".to_string());
        pb.standard = Some("https://agentcollab.dev".to_string());
        pb.note = Some("keep it short".to_string());

        let wire = serde_json::to_value(&pb).expect("serialize");
        assert_eq!(wire["pattern"], "roll-call");
        assert_eq!(wire["agenda"], json!(["roll-call", "critique-circle", "decide"]));
        assert_eq!(wire["facilitator"], "UFACILITATOR");
        assert_eq!(wire["roles"]["UBOB"], "critic");
        assert_eq!(wire["note"], "keep it short");

        let back: RoomPlaybook = serde_json::from_value(wire).expect("deserialize");
        assert_eq!(back, pb, "the plan survives the wire unchanged");

        // A phase message is a `phase`, spelled the way the TS SDK spells it.
        let msg = serde_json::to_value(phase_msg("critique-circle", Some("ten minutes"))).unwrap();
        assert_eq!(msg["type"], "phase");
        assert_eq!(msg["pattern"], "critique-circle");
        assert_eq!(msg["note"], "ten minutes");
        assert!(msg.get("standard").is_none(), "an absent standard is omitted, not null");

        assert_eq!(MAX_ROOM_AGENDA, 12, "the same ceiling as the TypeScript SDK");
    }

    #[test]
    fn the_phase_falls_back_to_the_pattern_the_descriptor_opened_in() {
        let d = descriptor(Some(planned()));
        let opening = opening_phase(&d).expect("a room with a plan has a phase");
        assert_eq!(opening.pattern, "roll-call");
        assert_eq!(
            opening.standard, DEFAULT_PATTERN_STANDARD,
            "an undeclared standard means Agent Collab"
        );
        assert_eq!(opening.by, None, "nobody has moved this room yet");

        // A declared standard is the one a reader gets sent to.
        let mut pb = planned();
        pb.standard = Some("https://example.test/patterns".to_string());
        assert_eq!(
            opening_phase(&descriptor(Some(pb))).unwrap().standard,
            "https://example.test/patterns"
        );

        // No plan is not a phase with an empty name: it is a room whose way of
        // working lives somewhere a member cannot read.
        assert_eq!(opening_phase(&descriptor(None)), None);
        assert_eq!(facilitator_of(&descriptor(None)), None);

        // An absent facilitator means the creator, the one member every
        // descriptor already names.
        assert_eq!(facilitator_of(&descriptor(Some(planned()))), Some(CREATOR));
    }

    #[test]
    fn the_facilitators_phase_moves_the_room() {
        let d = descriptor(Some(planned()));
        let mut held = None;
        fold_phase(
            &d,
            &mut held,
            &phase_msg("critique-circle", Some("ten minutes")),
            CREATOR,
            1_000,
        );

        let (now, at) = held.clone().expect("the facilitator moved the room");
        assert_eq!(now.pattern, "critique-circle");
        assert_eq!(now.by.as_deref(), Some(CREATOR), "who moved it is part of the answer");
        assert_eq!(now.note.as_deref(), Some("ten minutes"));
        assert_eq!(now.standard, DEFAULT_PATTERN_STANDARD);
        assert_eq!(at, 1_000);

        // A call older than the one held cannot walk the room backwards. That
        // rule is what makes replaying an old batch safe after the live tail
        // has already moved on.
        fold_phase(&d, &mut held, &phase_msg("roll-call", None), CREATOR, 500);
        assert_eq!(held.as_ref().unwrap().0.pattern, "critique-circle");
        fold_phase(&d, &mut held, &phase_msg("decide", None), CREATOR, 2_000);
        assert_eq!(held.as_ref().unwrap().0.pattern, "decide");
    }

    #[test]
    fn a_phase_from_anyone_else_is_carried_but_does_not_move_the_room() {
        let d = descriptor(Some(planned()));
        let mut held = None;
        let interloper = phase_msg("decide", None);
        fold_phase(&d, &mut held, &interloper, "UBOB", 9_000);
        assert_eq!(held, None, "only the facilitator's call moves the room");

        // AND IT IS STILL DELIVERED. A phase is not creator-gated the way
        // genesis, expel and close are: dropping it would hide a signed
        // statement a member actually made. It sits in the record, attributed,
        // and moves nothing.
        assert!(!is_creator_only(&interloper), "a phase reaches handlers whoever sent it");
        assert!(names_only_itself(&interloper, "UBOB"), "a phase names no member");

        // A named facilitator displaces the creator: now the creator's own
        // call is the one that does nothing.
        let mut pb = planned();
        pb.facilitator = Some("UBOB".to_string());
        let d = descriptor(Some(pb));
        let mut held = None;
        fold_phase(&d, &mut held, &phase_msg("decide", None), CREATOR, 9_000);
        assert_eq!(held, None, "the creator stops being the facilitator once one is named");
        fold_phase(&d, &mut held, &phase_msg("decide", None), "UBOB", 9_000);
        assert_eq!(held.expect("the named facilitator moves it").0.pattern, "decide");
    }

    #[test]
    fn the_remaining_agenda_is_what_is_left_after_the_phase_the_room_is_in() {
        let d = descriptor(Some(planned()));
        assert_eq!(
            remaining_agenda_after(&d, Some("roll-call")),
            vec!["critique-circle".to_string(), "decide".to_string()]
        );

        // After a move, only what follows it.
        let mut held = None;
        fold_phase(&d, &mut held, &phase_msg("critique-circle", None), CREATOR, 1_000);
        let here = held.as_ref().map(|(p, _)| p.pattern.as_str());
        assert_eq!(remaining_agenda_after(&d, here), vec!["decide".to_string()]);

        // The last entry leaves nothing, and a pattern that was never on the
        // agenda leaves nothing either: the agenda is a plan, and a room that
        // departed from it is not lost.
        assert!(remaining_agenda_after(&d, Some("decide")).is_empty());
        assert!(remaining_agenda_after(&d, Some("post-mortem")).is_empty());

        // No agenda at all: a starting pattern and no further intent.
        let mut pb = planned();
        pb.agenda = None;
        assert!(remaining_agenda_after(&descriptor(Some(pb)), Some("roll-call")).is_empty());

        // A descriptor somebody else signed arrives verbatim, so an oversized
        // agenda is bounded on the way out (both SDKs apply this ceiling).
        let mut wide = planned();
        wide.agenda = Some((0..31).map(|i| format!("p{i}")).collect());
        let out = remaining_agenda_after(&descriptor(Some(wide)), Some("p0"));
        assert_eq!(out.len(), MAX_ROOM_AGENDA);
        assert_eq!(out[0], "p1");
    }

    #[test]
    fn the_brief_says_where_the_room_is_and_that_nothing_enforces_it() {
        // Word for word the TS SDK's brief(), so two SDKs cannot brief the same
        // agent differently.
        let d = descriptor(Some(planned()));
        let phase = opening_phase(&d);

        assert_eq!(
            brief_text(&d, phase.as_ref(), "UBOB"),
            "This room (\"design review\") is in its roll-call phase, a pattern defined at \
https://agentcollab.dev. After it, the room plans: critique-circle, decide. Your role in this \
room is critic. Phase calls come from the room's creator; a phase called by anyone else does not \
move the room. The pattern is what this room says it does. Nothing on the mesh enforces it, so \
following it is your choice and departing from it is visible in the record."
        );

        assert_eq!(
            brief_text(&d, phase.as_ref(), CREATOR),
            "This room (\"design review\") is in its roll-call phase, a pattern defined at \
https://agentcollab.dev. After it, the room plans: critique-circle, decide. You facilitate: you \
are the member whose phase calls move this room. The pattern is what this room says it does. \
Nothing on the mesh enforces it, so following it is your choice and departing from it is visible \
in the record."
        );

        // A room that declared no plan briefs nothing. There is nothing to say,
        // and inventing a pattern would be worse than silence.
        assert_eq!(brief_text(&descriptor(None), None, CREATOR), "");
    }
}
