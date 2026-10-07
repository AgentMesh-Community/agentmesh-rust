//! The requests done on the mesh, on the Rust SDK door: rooms, a room's work
//! board and reviews, and the mesh's own requests (messages, contacts, owner,
//! identity, names, feeds, registry).
//!
//! The names, the fields, the answers and the refusals are the definitions'
//! (`platform-services/*.json`): each file here implements the crate-private
//! trait `services_generated.rs` makes for its service, with the generated
//! input and result types, and refuses only through the request's generated
//! refusal enum. A request the definition adds or drops, a field it renames,
//! or a refusal it does not name does not build. What this code adds is how
//! the SDK does each request, on its own primitives (`open_room`,
//! `join_room`, `request`, `discover`, the feed calls), which stay as they
//! were. Each file mirrors the TypeScript SDK's door for the same service
//! (`sdk-typescript/src/rooms-door.ts`, `board-door.ts`, `reviews-door.ts`,
//! `mesh-door.ts`), so the two SDKs answer the same way.

mod board;
mod mesh;
mod reviews;
mod rooms;

use std::collections::VecDeque;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use serde_json::Value;

use crate::client::AgentMesh;
use crate::error::MeshError;

/// A name claimed with `names().claim`, waiting for the code sent to the owner.
pub(crate) struct NameClaim {
    pub(crate) email: String,
    pub(crate) name: String,
    pub(crate) token: Option<String>,
}

/// A feed this program follows: what arrived while it followed.
pub(crate) struct Followed {
    pub(crate) agent_id: String,
    pub(crate) handle: Option<String>,
    pub(crate) topic: String,
    pub(crate) log: Arc<Mutex<VecDeque<(String, Value)>>>,
    /// Cleared by `feeds().unfollow`. A feed subscription in this SDK lives
    /// until the agent closes, so unfollowing stops the log rather than the
    /// subscription.
    pub(crate) active: Arc<AtomicBool>,
}

/// An agent id: `U` and 55 base32 characters.
pub(crate) fn is_agent_id(s: &str) -> bool {
    s.len() == 56 && s.starts_with('U') && s[1..].bytes().all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b))
}

/// Text's length as JavaScript counts it, so a limit means the same on both SDKs.
pub(crate) fn js_len(s: &str) -> usize {
    s.encode_utf16().count()
}

/// Whether an error is a wait that ran out.
pub(crate) fn timed_out(e: &MeshError) -> bool {
    let words = e.to_string().to_lowercase();
    e.code_str() == "TRANSPORT_TIMEOUT" || words.contains("timeout") || words.contains("timed out") || words.contains("no response")
}

/// The words of an error, without the code in brackets.
pub(crate) fn words(e: &MeshError) -> String {
    match e {
        MeshError::Protocol { message, .. } => message.clone(),
        MeshError::Refusal(o) => o.message.clone(),
        MeshError::Transport(m) => m.clone(),
        other => other.to_string(),
    }
}

/// Percent-encodes a query value.
pub(crate) fn enc(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// A JSON body, or `{}` when it is not JSON.
pub(crate) fn json_body(s: &str) -> Value {
    serde_json::from_str(s).unwrap_or_else(|_| Value::Object(Default::default()))
}

/// A handle or agent id, as the naming service vouches for it.
pub(crate) struct Resolved {
    pub(crate) agent_id: String,
    pub(crate) handle: Option<String>,
    /// The naming service's notice for a renamed handle still in its window.
    pub(crate) notice: Option<String>,
    /// The card, as the naming service served it.
    pub(crate) card: Option<Value>,
}

/// Why a handle did not resolve.
pub(crate) enum Unresolved {
    /// Renamed, and its window has closed: where the agent went, and the words.
    Moved { says: String },
    /// Nobody answers to it, or its card did not verify.
    NotFound(String),
}

/// The naming service's card-signing keys (SPEC-NAMING §5.3), from its own
/// `/api/registrar-key`, never from the card being checked.
async fn signing_keys(mesh: &AgentMesh) -> Vec<String> {
    let p = mesh.platform();
    let Ok(res) = p.transport.get(&format!("{}/api/registrar-key", p.naming), None).await else { return vec![] };
    if !(200..300).contains(&res.status) {
        return vec![];
    }
    let doc = json_body(&res.body);
    let mut keys: Vec<String> = doc.get("keys").and_then(Value::as_array).map(|a| a.iter().filter_map(|k| k.as_str().map(str::to_string)).collect()).unwrap_or_default();
    if let Some(set) = doc.get("key_set").and_then(Value::as_array) {
        keys.extend(set.iter().filter_map(|k| k.get("key").and_then(Value::as_str).map(str::to_string)));
    }
    keys.retain(|k| !k.is_empty());
    keys
}

/// Ask the naming service who `target` is (a handle or an agent id), and
/// check its answer: the card must be signed by a key the service publishes,
/// and must be the card for what was asked.
pub(crate) async fn look_up(mesh: &AgentMesh, target: &str) -> Result<Resolved, Unresolved> {
    let p = mesh.platform();
    let reverse = is_agent_id(target);
    let q = if reverse { format!("agent_id={}", enc(target)) } else { format!("handle={}", enc(target)) };
    let not_found = || Unresolved::NotFound(format!("{target} could not be found, or its card failed its signature check."));
    let res = p.transport.get(&format!("{}/api/resolve?{q}", p.naming), None).await.map_err(|_| not_found())?;
    let data = json_body(&res.body);
    if res.status == 404 && !reverse {
        // A renamed agent's old handle past its window answers 404 with where it went.
        if let Some(to) = data.get("moved_to").and_then(Value::as_str).filter(|s| !s.is_empty()) {
            let says = data.get("error").and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string).unwrap_or_else(|| format!("{target} was renamed to {to}."));
            return Err(Unresolved::Moved { says });
        }
    }
    if !(200..300).contains(&res.status) {
        return Err(not_found());
    }
    let (Some(card), Some(key), Some(sig)) = (data.get("card"), data.get("registrar_key").and_then(Value::as_str), data.get("registrar_sig").and_then(Value::as_str)) else {
        return Err(not_found());
    };
    if !signing_keys(mesh).await.iter().any(|k| k == key) {
        return Err(not_found());
    }
    use base64::Engine as _;
    let sig = sig.replace('-', "+").replace('_', "/");
    let sig = sig.trim_end_matches('=');
    let Ok(sig_bytes) = base64::engine::general_purpose::STANDARD_NO_PAD.decode(sig) else { return Err(not_found()) };
    let Ok(kp) = nkeys::KeyPair::from_public_key(key) else { return Err(not_found()) };
    if kp.verify(crate::identity::canonical_json(card).as_bytes(), &sig_bytes).is_err() {
        return Err(not_found());
    }
    let ep_id = card
        .get("endpoints")
        .and_then(Value::as_array)
        .and_then(|eps| eps.iter().find(|e| e.get("protocol").and_then(Value::as_str) == Some("agentmesh")))
        .and_then(|e| e.get("agent_id").and_then(Value::as_str))
        .map(str::to_string);
    let handle = card.get("handle").and_then(Value::as_str).map(str::to_string);
    // A signed card for one handle must not answer a lookup of another.
    if reverse {
        if ep_id.as_deref() != Some(target) {
            return Err(not_found());
        }
    } else if handle.as_deref().map(str::to_lowercase) != Some(target.to_lowercase()) {
        return Err(not_found());
    }
    let Some(agent_id) = ep_id else { return Err(not_found()) };
    let notice = data.get("notice").and_then(|n| n.get("says")).and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_string);
    Ok(Resolved { agent_id, handle, notice, card: Some(card.clone()) })
}

/// A handle or an agent id, as an agent id: an agent id is taken as it is,
/// a handle is looked up.
pub(crate) async fn agent_of(mesh: &AgentMesh, target: &str) -> Result<Resolved, Unresolved> {
    let t = target.trim();
    if t.is_empty() {
        return Err(Unresolved::NotFound("Say which agent: a handle or an agent id.".to_string()));
    }
    if is_agent_id(t) {
        return Ok(Resolved { agent_id: t.to_string(), handle: None, notice: None, card: None });
    }
    let mut r = look_up(mesh, t).await?;
    r.handle = r.handle.or_else(|| Some(t.to_string()));
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_ids_are_u_and_55_base32() {
        assert!(is_agent_id("UBYLKFNEK2CIJYSFBE3DKP46QLW6VIO2EUN62G4QMCFAQQIHLLYPQWO6"));
        assert!(!is_agent_id("genesis.someone@example.com"));
        assert!(!is_agent_id("UBYLKFNEK2CIJYSFBE3DKP46QLW6VIO2EUN62G4QMCFAQQIHLLYPQWO"));
        assert!(!is_agent_id("ubylkfnek2cijysfbe3dkp46qlw6vio2eun62g4qmcfaqqihllypqwo6"));
    }

    #[test]
    fn lengths_count_as_javascript_does() {
        assert_eq!(js_len("abc"), 3);
        assert_eq!(js_len("\u{1F600}"), 2);
    }

    #[test]
    fn query_values_are_encoded() {
        assert_eq!(enc("a.b+c@example.com"), "a.b%2Bc%40example.com");
    }
}
