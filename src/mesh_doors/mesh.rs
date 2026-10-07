//! The mesh's own requests on the Rust SDK (platform-services/*.json with
//! `"part": "mesh"`): `mesh.messages()`, `mesh.contacts()`, `mesh.owner()`,
//! `mesh.identity()`, `mesh.names()`, `mesh.feeds()` and `mesh.registry()`,
//! with the same names, fields, answers and refusals as the MCP tools
//! (`messages_send`, `feeds_read`, ...) and the command line
//! (`agentmesh messages send`, ...). The TypeScript SDK's `mesh-door.ts`.
//!
//! They are built on the SDK's own primitives, which stay as they were:
//! `request`, `discover`, `declare_feed`, `publish_feed`, `track_feed`,
//! `feed_value`. What a program can only do with those (be called on each
//! message as it arrives, on each new feed value) it still does with them;
//! these requests answer the questions every door answers.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Map, Value};

use crate::client::{AgentMesh, DiscoverQuery, RequestOptions};
use crate::error::MeshError;
use crate::feed::FeedKind;
use crate::services::*;

use super::{agent_of, enc, is_agent_id, js_len, json_body, look_up, timed_out, words, Followed, NameClaim, Unresolved};

/// The most a message's text may be, in characters: the mesh's own cap on one
/// inbound message. Over it, refused; never cut.
pub(crate) const MESH_TEXT_MAX: usize = 64 * 1024;
/// What a knock may ask to be allowed to do.
const KNOCK_GRANTS: [&str; 4] = ["messages", "scheduling", "share", "errands"];
/// How many values a followed feed keeps in memory, as the adapter's log does.
pub(crate) const FEED_LOG_MAX: usize = 200;

fn feed_topic_ok(t: &str) -> bool {
    !t.is_empty() && t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn email_ok(e: &str) -> bool {
    let Some((local, domain)) = e.split_once('@') else { return false };
    !local.is_empty() && !e.chars().any(char::is_whitespace) && domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.') && !domain.contains('@')
}

/// A name as the naming service takes it: lower case, runs of anything but
/// letters, digits, `-` and `_` made one `-`, no `-` at either end.
pub(crate) fn clean_name(s: &str) -> String {
    let mut out = String::new();
    for c in s.trim().to_lowercase().chars() {
        if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-' {
            if !(c == '-' && out.ends_with('-')) {
                out.push(c);
            }
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    out.trim_matches('-').to_string()
}

/// The details a refusal from the mesh carries.
fn details(e: &MeshError) -> Value {
    e.error_object().and_then(|o| o.details.clone()).unwrap_or(Value::Null)
}

/// What a respond carried: its `output`, or the payload itself.
fn output_of(payload: &Value) -> Value {
    payload.get("output").cloned().unwrap_or_else(|| payload.clone())
}

// ── messages ────────────────────────────────────────────────────────────────

impl MessagesRequests for MessagesService<'_> {
    async fn send(&self, input: MessagesSendInput) -> Result<MessagesSendResult, ServiceError> {
        if input.text.trim().is_empty() {
            return Err(MessagesSendRefusal::InputInvalid.refuse("Say the message: text is empty."));
        }
        let n = js_len(&input.text);
        if n > MESH_TEXT_MAX {
            return Err(MessagesSendRefusal::TooBig.refuse(format!("That message is {n} characters; a message takes at most {MESH_TEXT_MAX}. Send it as a file instead.")));
        }
        let to = match agent_of(self.mesh, &input.to).await {
            Ok(r) => r,
            Err(Unresolved::Moved { says }) => return Err(MessagesSendRefusal::Renamed.refuse(says)),
            Err(Unresolved::NotFound(w)) => return Err(MessagesSendRefusal::NotFound.refuse(w)),
        };
        let mut body = Map::new();
        body.insert("text".into(), json!(input.text));
        if let Some(r) = input.resources.as_ref().filter(|r| !r.is_empty()) {
            body.insert("resources".into(), serde_json::to_value(r).unwrap_or(Value::Null));
        }
        let opts = RequestOptions { timeout: Some(Duration::from_secs(60)), context_id: input.context.clone(), ..Default::default() };
        match self.mesh.request_with_options(&to.agent_id, "chat", Value::Object(body), opts).await {
            Ok(r) => {
                let p = output_of(&r.payload);
                let reply = if p.is_string() { p } else { p.get("text").cloned().unwrap_or(p) };
                Ok(MessagesSendResult { delivered: true, reply: Some(reply), request_id: r.envelope.in_reply_to.clone(), note: None, notice: to.notice })
            }
            Err(e) => {
                let d = details(&e);
                let request_id = d.get("request_id").and_then(Value::as_str).map(str::to_string);
                if e.code_str() == "REQUEST_QUEUED" || d.get("queued").and_then(Value::as_bool) == Some(true) {
                    return Ok(MessagesSendResult {
                        delivered: false,
                        reply: None,
                        request_id,
                        note: Some("Sent. The agent's mailbox holds it; any reply arrives later as a message to this agent.".into()),
                        notice: to.notice,
                    });
                }
                if timed_out(&e) {
                    return Ok(MessagesSendResult {
                        delivered: false,
                        reply: None,
                        request_id,
                        note: Some("Sent. The agent did not answer within a minute; if it is offline the mesh holds the message, and any reply arrives later as a message to this agent.".into()),
                        notice: to.notice,
                    });
                }
                match e {
                    _ if e.code_str() == "NOT_NAMED" => Err(MessagesSendRefusal::NotNamed.refuse(words(&e))),
                    MeshError::Protocol { .. } | MeshError::Refusal(_) => Err(MessagesSendRefusal::Refused.refuse(words(&e))),
                    other => Err(other.into()),
                }
            }
        }
    }
}

// ── contacts ────────────────────────────────────────────────────────────────

impl ContactsRequests for ContactsService<'_> {
    async fn knock(&self, input: ContactsKnockInput) -> Result<ContactsKnockResult, ServiceError> {
        let grants = input.grants.clone().unwrap_or_default();
        if grants.iter().any(|g| !KNOCK_GRANTS.contains(&g.as_str())) {
            return Err(ContactsKnockRefusal::InputInvalid.refuse(format!("grants are names from this list only: {}", KNOCK_GRANTS.join(", "))));
        }
        let via = input.via.as_deref().unwrap_or("").trim().to_string();
        if js_len(&via) > 80 {
            return Err(ContactsKnockRefusal::InputInvalid.refuse(format!("via is at most 80 characters; that is {}.", js_len(&via))));
        }
        let to = match agent_of(self.mesh, &input.to).await {
            Ok(r) => r,
            Err(Unresolved::Moved { says }) | Err(Unresolved::NotFound(says)) => return Err(ContactsKnockRefusal::NotFound.refuse(says)),
        };
        let mut body = Map::new();
        if !via.is_empty() {
            body.insert("via".into(), json!(via));
        }
        if !grants.is_empty() {
            body.insert("grants".into(), json!(grants));
        }
        let opts = RequestOptions { timeout: Some(Duration::from_secs(30)), ..Default::default() };
        match self.mesh.request_with_options(&to.agent_id, "knock", Value::Object(body), opts).await {
            Ok(r) => {
                let p = output_of(&r.payload);
                if p.get("refused").and_then(Value::as_bool) == Some(true) {
                    let code = p.get("code").and_then(Value::as_str).unwrap_or("REFUSED");
                    let why = p.get("error").and_then(Value::as_str).unwrap_or("no reason given");
                    return Err(ContactsKnockRefusal::Refused.refuse(format!("{} turned the knock away ({code}): {why}", input.to)));
                }
            }
            // A knock that times out still knocked: the other side records it before anything answers.
            Err(e) if timed_out(&e) => {}
            Err(e) if e.code_str() == "NOT_NAMED" => return Err(ContactsKnockRefusal::NotNamed.refuse(words(&e))),
            Err(e @ (MeshError::Protocol { .. } | MeshError::Refusal(_))) => return Err(ContactsKnockRefusal::Refused.refuse(words(&e))),
            Err(e) => return Err(e.into()),
        }
        Ok(ContactsKnockResult {
            to: to.agent_id,
            note: Some("Knocked. Its owner decides; once they let you in, your messages go through. Nothing comes back to say no.".into()),
            notice: to.notice,
        })
    }

    async fn presence(&self, input: ContactsPresenceInput) -> Result<ContactsPresenceResult, ServiceError> {
        let who: Vec<String> = input.who.unwrap_or_default().into_iter().map(|w| w.trim().to_string()).filter(|w| !w.is_empty()).collect();
        if who.is_empty() {
            return Ok(ContactsPresenceResult { contacts: vec![] });
        }
        // id (or "?name" when nobody answers to it) -> the name asked for.
        let mut named: Vec<(String, String)> = Vec::new();
        for w in &who {
            if is_agent_id(w) {
                named.push((w.clone(), w.clone()));
                continue;
            }
            let id = look_up(self.mesh, w).await.map(|r| r.agent_id).unwrap_or_else(|_| format!("?{w}"));
            named.push((id, w.clone()));
        }
        let ids: Vec<String> = named.iter().map(|(id, _)| id.clone()).filter(|id| is_agent_id(id)).collect();
        let found = self
            .mesh
            .discover_raw(DiscoverQuery { agent_ids: ids, ..Default::default() })
            .await
            .map_err(|e| ContactsPresenceRefusal::Unavailable.refuse(format!("Presence could not be read: {}", words(&e))))?;
        let by_id: HashMap<String, &Value> = found
            .iter()
            .filter_map(|m| m.get("id").or_else(|| m.get("agent_id")).and_then(Value::as_str).map(|id| (id.to_string(), m)))
            .collect();
        let rank = |s: &str| match s {
            "online" => 0,
            "busy" => 1,
            "degraded" => 2,
            _ => 3,
        };
        let mut contacts: Vec<ContactsPresenceResultContact> = named
            .into_iter()
            .map(|(id, name)| {
                let m = if is_agent_id(&id) { by_id.get(&id).copied() } else { None };
                let raw = m.and_then(|m| m.get("availability")).and_then(Value::as_str).map(str::to_lowercase).unwrap_or_else(|| if m.is_some() { "online".into() } else { "quiet".into() });
                let state = match raw.as_str() {
                    "live" => "online",
                    "online" | "busy" | "degraded" => raw.as_str(),
                    _ => "quiet",
                }
                .to_string();
                let desc = m.and_then(|m| m.get("description")).and_then(Value::as_str).unwrap_or("");
                let attended = if desc.contains("(a live session answers)") {
                    Some(true)
                } else if desc.contains("(unattended)") {
                    Some(false)
                } else {
                    None
                };
                let line = match state.as_str() {
                    "online" => format!(
                        "online{}",
                        match attended {
                            Some(true) => " · a live session may answer",
                            Some(false) => " · unattended, answers on its own",
                            None => "",
                        }
                    ),
                    "quiet" => "quiet · messages wait for it".to_string(),
                    other => other.to_string(),
                };
                ContactsPresenceResultContact { name, agent_id: is_agent_id(&id).then_some(id), state, attended, line }
            })
            .collect();
        contacts.sort_by(|a, b| rank(&a.state).cmp(&rank(&b.state)).then_with(|| a.name.cmp(&b.name)));
        Ok(ContactsPresenceResult { contacts })
    }
}

// ── owner ───────────────────────────────────────────────────────────────────

const NOT_LINKED: &str = "This agent is not linked to its owner's AgentMesh account, so there is nobody to ask.";

impl OwnerRequests for OwnerService<'_> {
    async fn ask(&self, input: OwnerAskInput) -> Result<OwnerAskResult, ServiceError> {
        let text = input.text.as_deref().unwrap_or("").trim().to_string();
        let settles = input.settles.clone().filter(|s| !s.is_empty());
        if settles.is_none() && text.is_empty() {
            return Err(OwnerAskRefusal::InputInvalid.refuse("Say the question, or give settles."));
        }
        if js_len(&text) > MESH_TEXT_MAX {
            return Err(OwnerAskRefusal::InputInvalid.refuse(format!("That question is {} characters; a message takes at most {MESH_TEXT_MAX}.", js_len(&text))));
        }
        let mesh = self.mesh;
        let p = mesh.platform();
        let ts = now_js();
        let body = json!({ "agent_id": mesh.id(), "ts": ts, "sig": mesh.sign_detached(&format!("owner-agent-v1:{}:{ts}", mesh.id())) });
        let res = p
            .transport
            .post_json(&format!("{}/v1/agent/owner", p.api), None, body.to_string())
            .await
            .map_err(|w| OwnerAskRefusal::Unavailable.refuse(format!("AgentMesh could not be reached to find the owner: {w}")))?;
        if res.status == 404 {
            return Err(OwnerAskRefusal::NotLinked.refuse(NOT_LINKED));
        }
        let out = json_body(&res.body);
        let hosted = out.get("hosted");
        let Some(agent_id) = hosted.and_then(|h| h.get("agent_id")).and_then(Value::as_str).filter(|_| (200..300).contains(&res.status)).map(str::to_string) else {
            let why = out.get("error").and_then(Value::as_str).map(str::to_string).unwrap_or_else(|| format!("HTTP {}", res.status));
            return Err(OwnerAskRefusal::Unavailable.refuse(format!("AgentMesh could not say which agent is the owner's: {why}")));
        };
        let who = hosted.and_then(|h| h.get("handle")).and_then(Value::as_str).map(str::to_string).unwrap_or_else(|| agent_id.clone());
        let choices: Vec<String> = input.choices.clone().unwrap_or_default().into_iter().map(|c| c.trim().to_string()).filter(|c| !c.is_empty()).collect();
        let payload = match &settles {
            Some(s) => json!({ "text": if text.is_empty() { "Settled." } else { &text }, "ask": { "settles": s } }),
            None => {
                let mut ask = json!({ "kind": "question" });
                if !choices.is_empty() {
                    ask["choices"] = json!(choices);
                }
                json!({ "text": text, "ask": ask })
            }
        };
        let opts = RequestOptions { timeout: Some(Duration::from_secs(10)), ..Default::default() };
        match mesh.request_with_options(&agent_id, "chat", payload, opts).await {
            Ok(r) => Ok(match settles {
                Some(s) => OwnerAskResult { to: who, settled: Some(s), ..Default::default() },
                None => OwnerAskResult { to: who, held: Some(false), request_id: r.envelope.in_reply_to.clone(), ..Default::default() },
            }),
            Err(e) => {
                let d = details(&e);
                let flag = |k: &str| d.get(k).and_then(Value::as_bool) == Some(true);
                if matches!(e.code_str(), "REQUEST_QUEUED" | "AGENT_UNAVAILABLE") || flag("queued") || flag("captured") || timed_out(&e) {
                    let request_id = d.get("request_id").and_then(Value::as_str).map(str::to_string);
                    return Ok(OwnerAskResult {
                        to: who,
                        held: Some(true),
                        request_id: if settles.is_some() { None } else { request_id },
                        settled: settles,
                    });
                }
                if e.code_str() == "NOT_NAMED" {
                    return Err(OwnerAskRefusal::NotNamed.refuse(words(&e)));
                }
                Err(e.into())
            }
        }
    }
}

// ── identity ────────────────────────────────────────────────────────────────

impl IdentityRequests for IdentityService<'_> {
    async fn me(&self, _input: IdentityMeInput) -> Result<IdentityMeResult, ServiceError> {
        // The definition's refusals are for the other doors: this SDK is the agent.
        let mesh = self.mesh;
        let status = match mesh.naming_status() {
            Some(s) => Some(s),
            None => mesh.recheck_name().await,
        };
        let mut handle = status.as_ref().and_then(|s| s.handle.clone());
        if status.is_none() {
            // No naming check on this agent (allow_unnamed): asked here instead.
            let p = mesh.platform();
            if let Ok(res) = p.transport.get(&format!("{}/api/resolve?agent_id={}", p.naming, enc(mesh.id())), None).await {
                if (200..300).contains(&res.status) {
                    handle = json_body(&res.body).get("card").and_then(|c| c.get("handle")).and_then(Value::as_str).map(str::to_string);
                }
            }
        }
        let can_send = match &status {
            Some(s) => s.named || s.unchecked,
            None => handle.is_some(),
        };
        Ok(IdentityMeResult {
            agent_id: Some(mesh.id().to_string()),
            name: handle.as_ref().map(|h| h.split('.').next().unwrap_or("").to_string()),
            handle,
            can_send: Some(can_send),
            why_not: (!can_send).then(|| "AgentMesh uses one global standard for agent names: the agent's name, a dot, and its owner's email. This agent does not have one yet, so it cannot send.".to_string()),
            get_a_name: (!can_send).then(|| "Ask the person for their email and the name they want, call names().claim() with both, then names().confirm() with the code they are emailed.".to_string()),
            ..Default::default()
        })
    }
}

// ── names ───────────────────────────────────────────────────────────────────

/// A POST to the naming service: its answer, or the code to refuse with and
/// the words. `refused` is the code for a refusal the service gave.
async fn naming_post(mesh: &AgentMesh, path: &str, body: Value, token: Option<&str>, refused: &'static str) -> Result<Value, (&'static str, String)> {
    let p = mesh.platform();
    let res = p
        .transport
        .post_json(&format!("{}{path}", p.naming), token, body.to_string())
        .await
        .map_err(|w| ("UNAVAILABLE", format!("The naming service did not answer: {w}")))?;
    let data = json_body(&res.body);
    if (200..300).contains(&res.status) {
        return Ok(data);
    }
    let words = data.get("error").and_then(Value::as_str).map(str::to_string).unwrap_or_else(|| format!("the naming service answered {}", res.status));
    Err((if res.status >= 500 { "UNAVAILABLE" } else { refused }, words))
}

impl NamesRequests for NamesService<'_> {
    async fn resolve(&self, input: NamesResolveInput) -> Result<NamesResolveResult, ServiceError> {
        let t = input.target.trim().to_string();
        if t.is_empty() {
            return Err(NamesResolveRefusal::InputInvalid.refuse("Say which agent: a handle or an agent id."));
        }
        match look_up(self.mesh, &t).await {
            Ok(r) => Ok(NamesResolveResult {
                agent_id: r.agent_id,
                handle: r.handle.or_else(|| (!is_agent_id(&t)).then(|| t.clone())),
                card: r.card.and_then(|c| c.as_object().cloned()),
                notice: r.notice,
            }),
            Err(Unresolved::Moved { says }) => Err(NamesResolveRefusal::Renamed.refuse(says)),
            Err(Unresolved::NotFound(_)) if is_agent_id(&t) => Ok(NamesResolveResult { agent_id: t, ..Default::default() }),
            Err(Unresolved::NotFound(w)) => Err(NamesResolveRefusal::NotFound.refuse(w)),
        }
    }

    async fn claim(&self, input: NamesClaimInput) -> Result<NamesClaimResult, ServiceError> {
        if let Some(s) = self.mesh.naming_status().filter(|s| s.named) {
            let h = s.handle.map(|h| format!(", {h}")).unwrap_or_default();
            return Err(NamesClaimRefusal::AlreadyNamed.refuse(format!("This agent already has its name{h}. Renaming happens on its page in the app.")));
        }
        let email = input.email.as_deref().unwrap_or("").trim().to_lowercase();
        if !email_ok(&email) {
            return Err(NamesClaimRefusal::InputInvalid.refuse("Give the owner's email: the code goes there. Ask the person for it; never guess."));
        }
        let name = clean_name(&input.name);
        if name.is_empty() {
            return Err(NamesClaimRefusal::InputInvalid.refuse("That name has no letters or numbers to use. Offer a short name, like little-buddy."));
        }
        naming_post(self.mesh, "/api/handles/start", json!({ "email": email }), None, "INPUT_INVALID")
            .await
            .map_err(|(c, w)| NamesClaimRefusal::from_code(c).unwrap_or(NamesClaimRefusal::Unavailable).refuse(w))?;
        *self.mesh.platform().name_claim.lock().unwrap() = Some(NameClaim { email: email.clone(), name: name.clone(), token: None });
        Ok(NamesClaimResult { handle: format!("{name}.{email}"), name, code_sent_to: Some(email) })
    }

    async fn confirm(&self, input: NamesConfirmInput) -> Result<NamesConfirmResult, ServiceError> {
        let no = |(c, w): (&'static str, String)| NamesConfirmRefusal::from_code(c).unwrap_or(NamesConfirmRefusal::Unavailable).refuse(w);
        let code = input.code.trim().to_string();
        if code.is_empty() {
            return Err(NamesConfirmRefusal::InputInvalid.refuse("Give the code from the email."));
        }
        let mesh = self.mesh;
        let naming = mesh.platform().naming.clone();
        let check_at = |h: &str| Some(format!("{naming}/api/resolve?handle={}", enc(h)));
        let bind = |pair: String| async move {
            let signature = mesh.sign_detached(&format!("pan-pair-v1:{}:{}", pair.to_uppercase(), mesh.id()));
            let done = naming_post(mesh, "/api/pair/complete", json!({ "code": pair, "agent_id": mesh.id(), "signature": signature }), None, "CODE_WRONG").await?;
            let _ = mesh.recheck_name().await;
            Ok::<Option<String>, (&'static str, String)>(done.get("handle").and_then(Value::as_str).map(str::to_string))
        };
        let asked = input.name.as_deref().unwrap_or("").trim().to_string();
        let pending = mesh.platform().name_claim.lock().unwrap().take();
        // A name the owner claimed in the app: the full handle and the pairing code shown there.
        if pending.is_none() && asked.contains('@') {
            let handle = bind(code).await.map_err(no)?.unwrap_or(asked);
            return Ok(NamesConfirmResult { check_at: check_at(&handle), handle, agent_id: mesh.id().to_string() });
        }
        let Some(mut pending) = pending else {
            return Err(NamesConfirmRefusal::NoClaim.refuse(NamesConfirmRefusal::NoClaim.says()));
        };
        // Put the claim back if this attempt fails, so a wrong code can be tried again.
        let keep = |p: NameClaim| *mesh.platform().name_claim.lock().unwrap() = Some(p);
        if pending.token.is_none() {
            match naming_post(mesh, "/api/handles/verify", json!({ "email": pending.email, "code": code }), None, "CODE_WRONG").await {
                Ok(v) => pending.token = v.get("token").and_then(Value::as_str).map(str::to_string),
                Err(e) => {
                    keep(pending);
                    return Err(no(e));
                }
            }
        }
        let token = pending.token.clone().unwrap_or_default();
        let mut operator = input.display_name.as_deref().unwrap_or("").trim().to_string();
        if operator.is_empty() {
            let p = mesh.platform();
            if let Ok(res) = p.transport.get(&format!("{}/api/operator", p.naming), Some(&token)).await {
                operator = json_body(&res.body).get("name").and_then(Value::as_str).unwrap_or("").to_string();
            }
            if operator.is_empty() {
                keep(pending);
                return Err(NamesConfirmRefusal::NeedsDisplayName.refuse(NamesConfirmRefusal::NeedsDisplayName.says()));
            }
        }
        let name = if asked.is_empty() { pending.name.clone() } else { clean_name(&asked) };
        let claimed = match naming_post(mesh, "/api/handles/claim", json!({ "name": name, "operator_name": operator }), Some(&token), "NAME_TAKEN").await {
            Ok(c) => c,
            Err(e) => {
                keep(pending);
                return Err(no(e));
            }
        };
        let claimed_handle = claimed.get("handle").and_then(Value::as_str).unwrap_or("").to_string();
        let pair = naming_post(mesh, "/api/pair/start", json!({ "handle": claimed_handle }), Some(&token), "INPUT_INVALID").await.map_err(no)?;
        let pair_code = match pair.get("code") {
            Some(Value::String(s)) => s.clone(),
            Some(other) => other.to_string(),
            None => String::new(),
        };
        let handle = bind(pair_code).await.map_err(no)?.unwrap_or(claimed_handle);
        Ok(NamesConfirmResult { check_at: check_at(&handle), handle, agent_id: mesh.id().to_string() })
    }
}

// ── feeds ───────────────────────────────────────────────────────────────────

fn kind_word(k: FeedKind) -> &'static str {
    match k {
        FeedKind::State => "state",
        FeedKind::Stream => "stream",
    }
}

fn topic_refusal(topic: &str) -> String {
    format!("A feed's name is letters, digits, - and _ only, like build-status. {} is not.", json!(topic))
}

impl FeedsRequests for FeedsService<'_> {
    async fn declare(&self, input: FeedsDeclareInput) -> Result<FeedsDeclareResult, ServiceError> {
        if !feed_topic_ok(&input.topic) {
            return Err(FeedsDeclareRefusal::InputInvalid.refuse(topic_refusal(&input.topic)));
        }
        let kind = match input.kind.as_deref().unwrap_or("state") {
            "state" => FeedKind::State,
            "stream" => FeedKind::Stream,
            other => return Err(FeedsDeclareRefusal::InputInvalid.refuse(format!("A feed's kind is state or stream, not {}.", json!(other)))),
        };
        self.mesh.declare_feed(&input.topic, kind).map_err(|e| FeedsDeclareRefusal::InputInvalid.refuse(words(&e)))?;
        Ok(FeedsDeclareResult {
            topic: input.topic,
            kind: kind_word(kind).to_string(),
            note: Some(if self.mesh.has_registered() {
                "Public to the whole mesh. It is published with this agent's next registration.".to_string()
            } else {
                "Public to the whole mesh. It is published when this agent registers.".to_string()
            }),
        })
    }

    async fn publish(&self, input: FeedsPublishInput) -> Result<FeedsPublishResult, ServiceError> {
        if !feed_topic_ok(&input.topic) {
            return Err(FeedsPublishRefusal::InputInvalid.refuse(topic_refusal(&input.topic)));
        }
        let declared = self.mesh.declared_feeds().into_iter().find(|(t, _)| *t == input.topic).map(|(_, k)| k);
        let kind = declared.unwrap_or(FeedKind::State);
        let data = match input.data {
            Value::String(s) => serde_json::from_str(&s).unwrap_or_else(|_| json!({ "text": s })),
            other => other,
        };
        if let Err(e) = self.mesh.publish_feed(&input.topic, data, kind).await {
            if e.code_str() == "NOT_NAMED" {
                return Err(FeedsPublishRefusal::NotNamed.refuse(words(&e)));
            }
            return Err(e.into());
        }
        Ok(FeedsPublishResult {
            note: declared.is_none().then(|| format!("{} is not declared, so readers cannot find it. feeds().declare() fixes that.", input.topic)),
            topic: input.topic,
            kind: kind_word(kind).to_string(),
        })
    }

    async fn follow(&self, input: FeedsFollowInput) -> Result<FeedsFollowResult, ServiceError> {
        if !feed_topic_ok(&input.topic) {
            return Err(FeedsFollowRefusal::InputInvalid.refuse(topic_refusal(&input.topic)));
        }
        let owner = match agent_of(self.mesh, &input.target).await {
            Ok(r) => r,
            Err(Unresolved::Moved { says }) | Err(Unresolved::NotFound(says)) => return Err(FeedsFollowRefusal::NotFound.refuse(says)),
        };
        let key = format!("{}/{}", owner.agent_id, input.topic);
        let already = self.mesh.platform().following.lock().unwrap().contains_key(&key);
        if !already {
            let log: Arc<Mutex<VecDeque<(String, Value)>>> = Arc::new(Mutex::new(VecDeque::new()));
            let active = Arc::new(AtomicBool::new(true));
            let (l, a) = (log.clone(), active.clone());
            self.mesh
                .track_feed(&owner.agent_id, &input.topic, move |payload, _env| {
                    if !a.load(Ordering::SeqCst) {
                        return;
                    }
                    let mut l = l.lock().unwrap();
                    l.push_back((now_js(), payload.get("data").cloned().unwrap_or(Value::Null)));
                    while l.len() > FEED_LOG_MAX {
                        l.pop_front();
                    }
                })
                .await?;
            let entry = Followed { agent_id: owner.agent_id.clone(), handle: owner.handle.clone(), topic: input.topic.clone(), log, active };
            self.mesh.platform().following.lock().unwrap().insert(key, entry);
        }
        Ok(FeedsFollowResult {
            agent_id: owner.agent_id,
            topic: input.topic,
            note: Some(format!("Followed while this program runs. The most recent {FEED_LOG_MAX} values are kept; feeds().read() shows them. Nothing arrives as a message.")),
        })
    }

    async fn unfollow(&self, input: FeedsUnfollowInput) -> Result<FeedsUnfollowResult, ServiceError> {
        let owner = match agent_of(self.mesh, &input.target).await {
            Ok(r) => r,
            Err(Unresolved::Moved { says }) | Err(Unresolved::NotFound(says)) => return Err(FeedsUnfollowRefusal::NotFound.refuse(says)),
        };
        let key = format!("{}/{}", owner.agent_id, input.topic);
        let Some(entry) = self.mesh.platform().following.lock().unwrap().remove(&key) else {
            return Err(FeedsUnfollowRefusal::NotFollowed.refuse(format!("This program does not follow {} from {}.", input.topic, input.target)));
        };
        entry.active.store(false, Ordering::SeqCst);
        Ok(FeedsUnfollowResult { agent_id: owner.agent_id, topic: input.topic })
    }

    async fn read(&self, input: FeedsReadInput) -> Result<FeedsReadResult, ServiceError> {
        let topic = input.topic.clone();
        if !feed_topic_ok(&topic) {
            return Err(FeedsReadRefusal::InputInvalid.refuse(topic_refusal(&topic)));
        }
        let agent_id = if input.target.trim().eq_ignore_ascii_case("agentmesh") {
            // AgentMesh's own channels have no handle: the platform says which key signs each topic.
            let p = self.mesh.platform();
            let channels: Vec<Value> = match p.transport.get(&format!("{}/v1/platform-channels", p.api), None).await {
                Ok(res) => json_body(&res.body).get("channels").and_then(Value::as_array).cloned().unwrap_or_default(),
                Err(_) => vec![],
            };
            let usable: Vec<(&str, &str)> = channels.iter().filter_map(|c| Some((c.get("topic")?.as_str()?, c.get("agent")?.as_str()?))).collect();
            match usable.iter().find(|(t, _)| *t == topic) {
                Some((_, agent)) => agent.to_string(),
                None => {
                    let list = usable.iter().map(|(t, _)| *t).collect::<Vec<_>>().join(", ");
                    return Err(FeedsReadRefusal::NotFound.refuse(format!("AgentMesh has no channel {}. Its channels: {}.", json!(topic), if list.is_empty() { "none could be read just now".to_string() } else { list })));
                }
            }
        } else {
            match agent_of(self.mesh, &input.target).await {
                Ok(r) => r.agent_id,
                Err(Unresolved::Moved { says }) | Err(Unresolved::NotFound(says)) => return Err(FeedsReadRefusal::NotFound.refuse(says)),
            }
        };
        let (env, unavailable) = match self.mesh.feed_value(&agent_id, &topic).await {
            Ok(e) => (e, false),
            Err(_) => (None, true),
        };
        let followed = self.mesh.platform().following.lock().unwrap().get(&format!("{agent_id}/{topic}")).map(|f| f.log.clone());
        let n = input.limit.unwrap_or(20).clamp(1, FEED_LOG_MAX as i64) as usize;
        let log: Vec<FeedsReadResultLog> = match &followed {
            Some(l) => {
                let l = l.lock().unwrap();
                // The definition's limit, asked for by the caller.
                l.iter().skip(l.len().saturating_sub(n)).map(|(at, data)| FeedsReadResultLog { at: at.clone(), data: Some(data.clone()) }).collect()
            }
            None => vec![],
        };
        let p = env.as_ref().and_then(|e| e.payload.clone()).unwrap_or(Value::Null);
        let note = if unavailable {
            Some("The current value could not be read just now.")
        } else if env.is_none() {
            Some("This feed has never published, or nothing on this mesh keeps its value.")
        } else if followed.is_none() {
            Some("No log: feeds().follow() keeps one while this program runs.")
        } else {
            None
        };
        Ok(FeedsReadResult {
            agent_id,
            topic,
            current: env.as_ref().map(|_| p.get("data").cloned().unwrap_or(Value::Null)),
            as_of: env.as_ref().map(|e| e.ts.clone()),
            kind: env.as_ref().and_then(|_| p.get("kind").and_then(Value::as_str).map(str::to_string)),
            log: Some(log),
            note: note.map(str::to_string),
        })
    }

    async fn list(&self, _input: FeedsListInput) -> Result<FeedsListResult, ServiceError> {
        let mesh = self.mesh;
        let value_of = |agent: String, topic: String| async move {
            match mesh.feed_value(&agent, &topic).await {
                Ok(Some(env)) => Some(env.payload.and_then(|p| p.get("data").cloned()).unwrap_or(Value::Null)),
                _ => None,
            }
        };
        let mut declared = Vec::new();
        for (topic, kind) in mesh.declared_feeds() {
            let current = value_of(mesh.id().to_string(), topic.clone()).await;
            declared.push(FeedsListResultDeclared { topic, kind: kind_word(kind).to_string(), current });
        }
        let follows: Vec<(String, Option<String>, String)> = mesh.platform().following.lock().unwrap().values().map(|f| (f.agent_id.clone(), f.handle.clone(), f.topic.clone())).collect();
        let mut following = Vec::new();
        for (agent_id, handle, topic) in follows {
            let current = value_of(agent_id.clone(), topic.clone()).await;
            following.push(FeedsListResultFollowing { agent_id, handle, topic, current });
        }
        Ok(FeedsListResult { declared, following })
    }

    async fn retire(&self, input: FeedsRetireInput) -> Result<FeedsRetireResult, ServiceError> {
        if !self.mesh.forget_declared_feed(&input.topic) {
            return Err(FeedsRetireRefusal::NotDeclared.refuse(format!("This agent declares no feed called {}. feeds().declare() declares one.", json!(input.topic))));
        }
        Ok(FeedsRetireResult { topic: input.topic, note: Some("It leaves this agent's registration the next time it registers. What was published stays public.".to_string()) })
    }
}

// ── registry ────────────────────────────────────────────────────────────────

impl RegistryRequests for RegistryService<'_> {
    async fn list(&self, input: RegistryListInput) -> Result<RegistryListResult, ServiceError> {
        let query = DiscoverQuery {
            capabilities: input.capability.into_iter().filter(|c| !c.is_empty()).collect(),
            offering_id: input.offering.filter(|o| !o.is_empty()),
            tags: input.tags.unwrap_or_default(),
            ..Default::default()
        };
        let found = self.mesh.discover_raw(query).await.map_err(|e| RegistryListRefusal::Unavailable.refuse(format!("The registry did not answer: {}", words(&e))))?;
        let s = |m: &Value, k: &str| m.get(k).and_then(Value::as_str).filter(|v| !v.is_empty()).map(str::to_string);
        let agents: Vec<RegistryListResultAgent> = found
            .iter()
            .filter_map(|m| {
                let agent_id = s(m, "id").or_else(|| s(m, "agent_id"))?;
                let offerings = m
                    .get("offerings")
                    .or_else(|| m.get("skills"))
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(|o| s(o, "id").or_else(|| s(o, "name"))).collect())
                    .unwrap_or_default();
                Some(RegistryListResultAgent { agent_id, name: s(m, "name"), description: s(m, "description"), offerings: Some(offerings) })
            })
            .collect();
        Ok(RegistryListResult { total: agents.len() as i64, agents })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_cleaned_as_the_naming_service_takes_them() {
        assert_eq!(clean_name("Little Buddy!"), "little-buddy");
        assert_eq!(clean_name("  --a  b--  "), "a-b");
        assert_eq!(clean_name("!!!"), "");
    }

    #[test]
    fn emails_and_topics_are_checked_before_anything_is_sent() {
        assert!(email_ok("test-rig+claude@agentmesh.ai"));
        assert!(!email_ok("nobody"));
        assert!(!email_ok("a b@example.com"));
        assert!(feed_topic_ok("build-status_2"));
        assert!(!feed_topic_ok("a.b"));
        assert!(!feed_topic_ok(""));
    }
}
