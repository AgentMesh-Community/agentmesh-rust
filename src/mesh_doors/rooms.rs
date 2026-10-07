//! `mesh.rooms()`: the rooms service's requests (platform-services/rooms.json),
//! done on the live rooms this agent opens and joins with `open_room` and
//! `join_room`, which stay the SDK's way to listen to a room and come back as
//! `room`. The TypeScript SDK's `rooms-door.ts`.
//!
//! A room is named by its id or its name. Rooms this door opened or joined
//! are held on the agent; any other room the rooms service lists for this
//! agent (acl and durable rooms it created or was admitted to) is joined on
//! first use. A sealed room is reachable only once held, since its key
//! travels in the invite.

use serde_json::Value;

use crate::client::AgentMesh;
use crate::rooms::{descriptor_from_token, descriptor_to_token, AttachOptions, JoinRoomOptions, LinkOptions, OpenRoomOptions, Room, RoomMessage, RoomPlaybook};
use crate::services::*;

use super::{agent_of, is_agent_id, js_len, words};

/// The rooms service's limit on one file (EXT-5 §4).
pub(crate) const ROOM_FILE_MAX_BYTES: usize = 512 * 1024;
/// The longest message a room takes, as the app's room page does.
pub(crate) const ROOM_POST_MAX_CHARS: usize = 16_000;

/// The phase as the definition carries it.
fn phase_of(room: &Room) -> Option<(String, Option<String>, Option<String>)> {
    room.phase().map(|p| (p.pattern, p.note, p.by))
}

fn brief_of(room: &Room) -> Option<String> {
    Some(room.brief()).filter(|b| !b.is_empty())
}

impl AgentMesh {
    /// Keep a live room this door made or joined, so later requests reach it.
    pub(crate) fn keep_room(&self, room: &Room) {
        self.platform().rooms.lock().unwrap().insert(room.id().to_string(), room.clone());
    }

    /// A room by id or name: held here, or listed for this agent by the rooms
    /// service and joined now. The words of the refusal when it is neither.
    /// The board door reaches rooms through this too, so the two share them.
    pub(crate) async fn room_of(&self, reference: &str) -> Result<Room, String> {
        let want = reference.trim();
        if want.is_empty() {
            return Err("Say which room: its id or its name.".to_string());
        }
        {
            let held = self.platform().rooms.lock().unwrap();
            if let Some(r) = held.get(want).filter(|r| !r.closed()) {
                return Ok(r.clone());
            }
            if let Some(r) = held.values().find(|r| !r.closed() && r.descriptor().name.as_deref() == Some(want)) {
                return Ok(r.clone());
            }
        }
        // The rooms service away: answered as not in the room, below.
        let mine = self.my_rooms().await.unwrap_or_default();
        let found = mine.iter().find(|m| m.room_id == want).or_else(|| mine.iter().find(|m| m.name.as_deref() == Some(want)));
        if let Some(d) = found.and_then(|m| m.descriptor.clone()).filter(|d| d.privacy != "sealed") {
            let token = descriptor_to_token(&d).map_err(|e| format!("This agent could not rejoin that room: {}", words(&e)))?;
            return match self.join_room(&token, JoinRoomOptions::default()).await {
                Ok(room) => {
                    self.keep_room(&room);
                    Ok(room)
                }
                Err(e) => Err(format!("This agent could not rejoin that room: {}", words(&e))),
            };
        }
        Err("You are not in that room. rooms().list() shows the rooms you are in.".to_string())
    }
}

/// A handle or an agent id, as the agent id.
async fn agent_id_of(mesh: &AgentMesh, target: &str) -> Result<String, String> {
    let t = target.trim();
    if is_agent_id(t) {
        return Ok(t.to_string());
    }
    agent_of(mesh, t).await.map(|r| r.agent_id).map_err(|_| format!("No agent answers to {t}."))
}

fn base_name(name: &str) -> String {
    name.rsplit(['/', '\\']).next().unwrap_or("").to_string()
}

impl RoomsRequests for RoomsService<'_> {
    async fn open(&self, input: RoomsOpenInput) -> Result<RoomsOpenResult, ServiceError> {
        let no = |r: RoomsOpenRefusal, w: String| Err(r.refuse(w));
        let sealed = input.sealed.unwrap_or(false);
        let acl = input.acl.unwrap_or(false);
        if sealed && acl {
            return no(RoomsOpenRefusal::InputInvalid, "A room is either sealed or keeps a member list, not both.".into());
        }
        let agenda: Vec<String> = input.agenda.unwrap_or_default().into_iter().filter(|x| !x.trim().is_empty()).collect();
        let mut facilitator = input.facilitator.map(|f| f.trim().to_string()).filter(|f| !f.is_empty());
        if let Some(f) = facilitator.clone().filter(|f| !is_agent_id(f)) {
            match agent_id_of(self.mesh, &f).await {
                Ok(id) => facilitator = Some(id),
                Err(w) => return no(RoomsOpenRefusal::InputInvalid, w),
            }
        }
        let playbook = if input.playbook.is_some() || !agenda.is_empty() {
            Some(RoomPlaybook {
                pattern: input.playbook.unwrap_or_default(),
                goal: None,
                inputs: None,
                outputs: None,
                agenda: if agenda.is_empty() { None } else { Some(agenda) },
                facilitator,
                standard: None,
                roles: None,
                note: input.playbook_note.filter(|n| !n.is_empty()),
            })
        } else {
            None
        };
        let opts = OpenRoomOptions {
            name: input.name.map(|n| n.trim().to_string()).filter(|n| !n.is_empty()),
            playbook,
            durable: input.durable.unwrap_or(false),
            sealed,
            acl,
            ..Default::default()
        };
        let room = match self.mesh.open_room(opts).await {
            Ok(r) => r,
            Err(e) => {
                return match e.code_str() {
                    "NOT_NAMED" => no(RoomsOpenRefusal::NotNamed, words(&e)),
                    "QUOTA_EXCEEDED" => no(RoomsOpenRefusal::QuotaExceeded, words(&e)),
                    "TRANSPORT_TIMEOUT" | "TRANSPORT_NO_RESPONDERS" | "TRANSPORT" => no(RoomsOpenRefusal::Unavailable, words(&e)),
                    "INPUT_INVALID" | "INVALID_ENVELOPE" => no(RoomsOpenRefusal::InputInvalid, words(&e)),
                    _ => Err(e.into()),
                }
            }
        };
        self.mesh.keep_room(&room);
        Ok(RoomsOpenResult {
            room_id: room.id().to_string(),
            name: room.descriptor().name.clone(),
            durable: room.durable(),
            sealed: room.sealed(),
            acl: room.acl(),
            token: room.token().ok(),
            phase: phase_of(&room).map(|(pattern, note, by)| RoomsOpenResultPhase { pattern, note, by }),
            brief: brief_of(&room),
            room: Some(room),
        })
    }

    async fn join(&self, input: RoomsJoinInput) -> Result<RoomsJoinResult, ServiceError> {
        let token = input.invite_or_token.trim().to_string();
        if descriptor_from_token(&token).is_err() {
            return Err(RoomsJoinRefusal::InputInvalid.refuse("That is not a room token. The SDK joins by token; an invite reaches your program as a rooms.invite request carrying it."));
        }
        let room = match self.mesh.join_room(&token, JoinRoomOptions::default()).await {
            Ok(r) => r,
            Err(e) => {
                let w = words(&e);
                return if e.code_str() == "NOT_NAMED" {
                    Err(RoomsJoinRefusal::NotNamed.refuse(w))
                } else if e.code_str() == "UNAUTHORIZED" || w.to_lowercase().contains("not admitted") || w.to_lowercase().contains("expelled") {
                    Err(RoomsJoinRefusal::NotAdmitted.refuse(w))
                } else {
                    Err(e.into())
                };
            }
        };
        self.mesh.keep_room(&room);
        Ok(RoomsJoinResult {
            room_id: room.id().to_string(),
            name: room.descriptor().name.clone(),
            members: Some(room.members()),
            phase: phase_of(&room).map(|(pattern, note, by)| RoomsJoinResultPhase { pattern, note, by }),
            brief: brief_of(&room),
            room: Some(room),
        })
    }

    async fn invite(&self, input: RoomsInviteInput) -> Result<RoomsInviteResult, ServiceError> {
        let room = self.mesh.room_of(&input.room).await.map_err(|w| RoomsInviteRefusal::NotInRoom.refuse(w))?;
        let to = agent_id_of(self.mesh, &input.target).await.map_err(|w| RoomsInviteRefusal::NotFound.refuse(w))?;
        match room.invite(&to, input.note.as_deref()).await {
            Ok(_) => Ok(RoomsInviteResult { room_id: room.id().to_string(), to, delivered: true, delivery: None }),
            Err(e) => {
                let w = words(&e);
                if e.code_str() == "NOT_NAMED" {
                    return Err(RoomsInviteRefusal::NotNamed.refuse(w));
                }
                if e.code_str() == "UNAUTHORIZED" || w.to_lowercase().contains("only the room's creator") {
                    return Err(RoomsInviteRefusal::NotPermitted.refuse(w));
                }
                Ok(RoomsInviteResult {
                    room_id: room.id().to_string(),
                    to,
                    delivered: false,
                    delivery: Some(format!("Invite sent with no answer ({w}). They may be offline, or their owner may be holding first contact for approval.")),
                })
            }
        }
    }

    async fn post(&self, input: RoomsPostInput) -> Result<RoomsPostResult, ServiceError> {
        let n = js_len(&input.text);
        if n > ROOM_POST_MAX_CHARS {
            return Err(RoomsPostRefusal::TooBig.refuse(format!("That message is {n} characters; a room takes at most {ROOM_POST_MAX_CHARS}. In a durable room, put it on the drive with rooms().attach() and quote its ref.")));
        }
        let room = self.mesh.room_of(&input.room).await.map_err(|w| RoomsPostRefusal::NotInRoom.refuse(w))?;
        if let Err(e) = room.say(&input.text, None, None).await {
            if e.code_str() == "NOT_NAMED" {
                return Err(RoomsPostRefusal::NotNamed.refuse(words(&e)));
            }
            return Err(e.into());
        }
        Ok(RoomsPostResult { room_id: room.id().to_string() })
    }

    async fn history(&self, input: RoomsHistoryInput) -> Result<RoomsHistoryResult, ServiceError> {
        let room = self.mesh.room_of(&input.room).await.map_err(|w| RoomsHistoryRefusal::NotInRoom.refuse(w))?;
        if !room.durable() {
            return Err(RoomsHistoryRefusal::NotDurable.refuse("That room keeps no record."));
        }
        let entries = room.full_history().await?;
        let s = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
        Ok(RoomsHistoryResult {
            room_id: room.id().to_string(),
            entries: entries
                .iter()
                .map(|e| {
                    let mut out = RoomsHistoryResultEntry {
                        seq: e.seq as i64,
                        from: s(&e.envelope, "from").unwrap_or_default(),
                        at: s(&e.envelope, "ts"),
                        r#type: "unknown".to_string(),
                        ..Default::default()
                    };
                    match &e.message {
                        Some(RoomMessage::Say { body, .. }) => {
                            out.r#type = "say".into();
                            out.body = Some(body.clone());
                        }
                        Some(RoomMessage::Artifact { name, version, ref_, digest, media_type, size, origin, .. }) => {
                            out.r#type = "artifact".into();
                            out.name = Some(name.clone());
                            out.r#ref = Some(ref_.clone());
                            out.version = Some(version.clone());
                            out.digest = Some(digest.clone());
                            out.media_type = media_type.clone();
                            out.size = size.map(|n| n as i64);
                            out.origin = origin.clone();
                        }
                        Some(RoomMessage::Join { member, .. }) => {
                            out.r#type = "join".into();
                            out.member = Some(member.clone());
                        }
                        Some(RoomMessage::Leave { member }) => {
                            out.r#type = "leave".into();
                            out.member = Some(member.clone());
                        }
                        Some(RoomMessage::Expel { member, .. }) => {
                            out.r#type = "expel".into();
                            out.member = Some(member.clone());
                        }
                        Some(RoomMessage::Genesis { .. }) => out.r#type = "genesis".into(),
                        Some(RoomMessage::Phase { .. }) => out.r#type = "phase".into(),
                        Some(RoomMessage::Close { .. }) => out.r#type = "close".into(),
                        None => {}
                    }
                    out
                })
                .collect(),
        })
    }

    async fn phase(&self, input: RoomsPhaseInput) -> Result<RoomsPhaseResult, ServiceError> {
        let room = self.mesh.room_of(&input.room).await.map_err(|w| RoomsPhaseRefusal::NotInRoom.refuse(w))?;
        if let Err(e) = room.call_phase(&input.pattern, input.note.as_deref()).await {
            if e.code_str() == "NOT_NAMED" {
                return Err(RoomsPhaseRefusal::NotNamed.refuse(words(&e)));
            }
            return Err(RoomsPhaseRefusal::NotFacilitator.refuse(words(&e)));
        }
        let phase = phase_of(&room)
            .map(|(pattern, note, by)| RoomsPhaseResultPhase { pattern, note, by })
            .unwrap_or_else(|| RoomsPhaseResultPhase { pattern: input.pattern.clone(), ..Default::default() });
        Ok(RoomsPhaseResult { room_id: room.id().to_string(), phase, brief: brief_of(&room) })
    }

    async fn list(&self, _input: RoomsListInput) -> Result<RoomsListResult, ServiceError> {
        let held: Vec<Room> = self.mesh.platform().rooms.lock().unwrap().values().cloned().collect();
        let mine = match self.mesh.my_rooms().await {
            Ok(m) => m,
            // Rooms held here are still known; the service's list is not.
            Err(e) if held.is_empty() => return Err(RoomsListRefusal::Unavailable.refuse(words(&e))),
            Err(_) => vec![],
        };
        let mut rooms = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for m in &mine {
            seen.insert(m.room_id.clone());
            let live = held.iter().find(|r| r.id() == m.room_id);
            rooms.push(RoomsListResultRoom {
                room_id: m.room_id.clone(),
                name: m.name.clone(),
                creator: m.descriptor.as_ref().map(|d| d.creator.clone()),
                role: Some(m.role.clone()),
                privacy: Some(m.privacy.clone()),
                members: live.map(|r| r.members()),
                unread: m.last_seq.map(|last| last.saturating_sub(m.cursor) as i64),
            });
        }
        for r in held.iter().filter(|r| !r.closed() && !seen.contains(r.id())) {
            let d = r.descriptor();
            rooms.push(RoomsListResultRoom {
                room_id: r.id().to_string(),
                name: d.name.clone(),
                creator: Some(d.creator.clone()),
                role: Some(if d.creator == self.mesh.id() { "creator" } else { "member" }.to_string()),
                privacy: Some(d.privacy.clone()),
                members: Some(r.members()),
                unread: None,
            });
        }
        // The service never learns of a room held only by its token (EXT-5 §6).
        Ok(RoomsListResult { rooms, complete: false })
    }

    async fn attach(&self, input: RoomsAttachInput) -> Result<RoomsAttachResult, ServiceError> {
        let room = self.mesh.room_of(&input.room).await.map_err(|w| RoomsAttachRefusal::NotInRoom.refuse(w))?;
        if !room.durable() {
            return Err(RoomsAttachRefusal::NotDurable.refuse("That room has no drive."));
        }
        let name = base_name(&input.name);
        if name.is_empty() || name == "." || name == ".." {
            return Err(RoomsAttachRefusal::InputInvalid.refuse("name must be a plain file name."));
        }
        let bytes = input.content.as_bytes();
        if bytes.len() > ROOM_FILE_MAX_BYTES {
            return Err(RoomsAttachRefusal::TooBig.refuse(format!("That file is {} bytes; a room's drive takes at most {ROOM_FILE_MAX_BYTES}. rooms().link() announces bytes held somewhere else.", bytes.len())));
        }
        let r = room
            .attach_with(
                &name,
                bytes,
                AttachOptions {
                    version: input.version,
                    media_type: Some(input.media_type.unwrap_or_else(|| "text/plain".to_string())),
                    origin: input.origin,
                    ..Default::default()
                },
            )
            .await?;
        Ok(RoomsAttachResult { r#ref: r.ref_, digest: r.digest, size: r.size as i64 })
    }

    async fn fetch(&self, input: RoomsFetchInput) -> Result<RoomsFetchResult, ServiceError> {
        let room = self.mesh.room_of(&input.room).await.map_err(|w| RoomsFetchRefusal::NotInRoom.refuse(w))?;
        if !room.durable() {
            return Err(RoomsFetchRefusal::NotDurable.refuse("That room has no drive."));
        }
        let mut reference = input.r#ref.trim().to_string();
        if !reference.starts_with("mesh:rooms:") {
            let files = room.files().await?;
            match files.iter().rev().find(|f| f.name == reference) {
                Some(f) => reference = f.ref_.clone(),
                None => return Err(RoomsFetchRefusal::NotFound.refuse("No file with that ref or name on this room's drive.")),
            }
        }
        let a = match room.fetch_artifact(&reference).await {
            Ok(a) => a,
            Err(e) if matches!(e.code_str(), "NOT_FOUND" | "ARTIFACT_GONE") => return Err(RoomsFetchRefusal::NotFound.refuse(words(&e))),
            Err(e) => return Err(e.into()),
        };
        let text = String::from_utf8(a.data.clone()).ok();
        Ok(RoomsFetchResult {
            r#ref: a.ref_,
            name: a.name,
            version: a.version,
            size: a.size as i64,
            digest: a.digest,
            media_type: a.media_type,
            origin: a.origin,
            binary: if text.is_some() { None } else { Some(true) },
            text,
            data: Some(a.data),
        })
    }

    async fn link(&self, input: RoomsLinkInput) -> Result<RoomsLinkResult, ServiceError> {
        let room = self.mesh.room_of(&input.room).await.map_err(|w| RoomsLinkRefusal::NotInRoom.refuse(w))?;
        if !room.durable() {
            return Err(RoomsLinkRefusal::NotDurable.refuse("That room has no drive."));
        }
        let d = &input.digest;
        if !(d.len() == 71 && d.starts_with("sha256:") && d[7..].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))) {
            return Err(RoomsLinkRefusal::InputInvalid.refuse("digest must be sha256: followed by the 64 hex digits of the bytes."));
        }
        let opts = LinkOptions {
            location: input.location.clone(),
            digest: input.digest.clone(),
            size: input.size.map(|n| n.max(0) as u64),
            version: input.version,
            media_type: input.media_type,
            origin: input.origin,
            ..Default::default()
        };
        match room.link(&base_name(&input.name), opts).await {
            Ok(r) => Ok(RoomsLinkResult { r#ref: r.ref_, digest: r.digest, external: r.external }),
            Err(e) if matches!(e.code_str(), "INPUT_INVALID" | "INVALID_ENVELOPE") => Err(RoomsLinkRefusal::InputInvalid.refuse(words(&e))),
            Err(e) => Err(e.into()),
        }
    }

    async fn files(&self, input: RoomsFilesInput) -> Result<RoomsFilesResult, ServiceError> {
        let room = self.mesh.room_of(&input.room).await.map_err(|w| RoomsFilesRefusal::NotInRoom.refuse(w))?;
        if !room.durable() {
            return Err(RoomsFilesRefusal::NotDurable.refuse("That room has no drive."));
        }
        let files = room.files().await?;
        Ok(RoomsFilesResult {
            room_id: room.id().to_string(),
            files: files
                .into_iter()
                .map(|f| RoomsFilesResultFile {
                    r#ref: f.ref_,
                    name: f.name,
                    version: f.version,
                    size: f.size.map(|n| n as i64),
                    digest: f.digest,
                    media_type: f.media_type,
                    attached_by: f.attached_by,
                    attached_at: f.attached_at,
                    origin: f.origin,
                    external: f.external,
                })
                .collect(),
        })
    }
}
