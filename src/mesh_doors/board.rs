//! `mesh.board()`: a durable room's work board (platform-services/board.json),
//! done on the live rooms the rooms door holds, with the room's own board
//! calls (`post_work`, `claim_work` and the rest), which stay on `Room`
//! unchanged. The TypeScript SDK's `board-door.ts`.

use crate::error::MeshError;
use crate::rooms;
use crate::services::*;

use super::words;

/// A board item as the definition carries it.
pub(crate) fn item_out(i: rooms::BoardItem) -> BoardItem {
    BoardItem {
        item_id: i.item_id,
        room_id: i.room_id,
        title: i.title,
        detail: i.detail,
        offering: i.offering,
        posted_by: i.posted_by,
        posted_at: i.posted_at,
        lease_ms: i.lease_ms as i64,
        state: i.state,
        claimed_by: i.claimed_by,
        claimed_at: i.claimed_at,
        lease_expires_at: i.lease_expires_at,
        task_id: i.task_id,
        done_at: i.done_at,
        result_note: i.result_note,
        artifacts: i.artifacts.filter(|a| !a.is_empty()),
        claims: i.claims.filter(|c| !c.is_empty()).map(|c| c.into_iter().map(|c| BoardItemClaim { by: c.by, at: c.at, outcome: c.outcome }).collect()),
        lease_lapsed: i.lease_lapsed.filter(|l| *l),
    }
}

/// The rooms service's board codes, as the definition's words for them. A
/// code the request does not name is not renamed: it goes back as it came.
pub(crate) fn board_code(e: &MeshError) -> Option<&'static str> {
    match e.code_str() {
        "BOARD_ITEM_TAKEN" => Some("TAKEN"),
        "IDENTITY_MISMATCH" => Some("NOT_YOURS"),
        "NOT_FOUND" => Some("NOT_FOUND"),
        "QUOTA_EXCEEDED" => Some("QUOTA_EXCEEDED"),
        "INVALID_ENVELOPE" | "INPUT_INVALID" => Some("INPUT_INVALID"),
        "NOT_NAMED" => Some("NOT_NAMED"),
        _ => None,
    }
}

/// One board act's answer, or its refusal under the request's own codes.
macro_rules! act {
    ($refusal:ty, $result:ident, $call:expr) => {
        match $call.await {
            Ok(item) => Ok($result { item: item_out(item) }),
            Err(e) => match board_code(&e).and_then(<$refusal>::from_code) {
                Some(r) => Err(r.refuse(words(&e))),
                None => Err(e.into()),
            },
        }
    };
}

const NOT_DURABLE: &str = "That room is not durable, so it has no work board.";

impl BoardRequests for BoardService<'_> {
    async fn list(&self, input: BoardListInput) -> Result<BoardListResult, ServiceError> {
        let room = self.mesh.room_of(&input.room).await.map_err(|w| BoardListRefusal::NotInRoom.refuse(w))?;
        if !room.durable() {
            return Err(BoardListRefusal::NotDurable.refuse(NOT_DURABLE));
        }
        let b = match room.board_items().await {
            Ok(b) => b,
            Err(e) => {
                return Err(match board_code(&e).and_then(BoardListRefusal::from_code) {
                    Some(r) => r.refuse(words(&e)),
                    None => e.into(),
                })
            }
        };
        Ok(BoardListResult {
            room_id: room.id().to_string(),
            items: b.items.into_iter().map(item_out).collect(),
            open: b.open as i64,
            claimed: b.claimed as i64,
            done: b.done as i64,
        })
    }

    async fn post(&self, input: BoardPostInput) -> Result<BoardPostResult, ServiceError> {
        let room = self.mesh.room_of(&input.room).await.map_err(|w| BoardPostRefusal::NotInRoom.refuse(w))?;
        if !room.durable() {
            return Err(BoardPostRefusal::NotDurable.refuse(NOT_DURABLE));
        }
        let work = rooms::PostWorkInput { title: input.title, detail: input.detail, offering: input.offering, lease_ms: input.lease_ms.map(|n| n.max(0) as u64) };
        act!(BoardPostRefusal, BoardPostResult, room.post_work(work))
    }

    async fn claim(&self, input: BoardClaimInput) -> Result<BoardClaimResult, ServiceError> {
        let room = self.mesh.room_of(&input.room).await.map_err(|w| BoardClaimRefusal::NotInRoom.refuse(w))?;
        if !room.durable() {
            return Err(BoardClaimRefusal::NotDurable.refuse(NOT_DURABLE));
        }
        act!(BoardClaimRefusal, BoardClaimResult, room.claim_work(&input.item_id, input.lease_ms.map(|n| n.max(0) as u64)))
    }

    async fn done(&self, input: BoardDoneInput) -> Result<BoardDoneResult, ServiceError> {
        let room = self.mesh.room_of(&input.room).await.map_err(|w| BoardDoneRefusal::NotInRoom.refuse(w))?;
        if !room.durable() {
            return Err(BoardDoneRefusal::NotDurable.refuse(NOT_DURABLE));
        }
        act!(BoardDoneRefusal, BoardDoneResult, room.complete_work(&input.item_id, input.note.as_deref(), input.artifacts.clone()))
    }

    async fn abandon(&self, input: BoardAbandonInput) -> Result<BoardAbandonResult, ServiceError> {
        let room = self.mesh.room_of(&input.room).await.map_err(|w| BoardAbandonRefusal::NotInRoom.refuse(w))?;
        if !room.durable() {
            return Err(BoardAbandonRefusal::NotDurable.refuse(NOT_DURABLE));
        }
        act!(BoardAbandonRefusal, BoardAbandonResult, room.abandon_work(&input.item_id))
    }

    async fn withdraw(&self, input: BoardWithdrawInput) -> Result<BoardWithdrawResult, ServiceError> {
        let room = self.mesh.room_of(&input.room).await.map_err(|w| BoardWithdrawRefusal::NotInRoom.refuse(w))?;
        if !room.durable() {
            return Err(BoardWithdrawRefusal::NotDurable.refuse(NOT_DURABLE));
        }
        act!(BoardWithdrawRefusal, BoardWithdrawResult, room.withdraw_work(&input.item_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorObject;

    #[test]
    fn the_services_codes_become_the_definitions() {
        let refusal = |code: &str| MeshError::Refusal(ErrorObject { code: code.into(), message: "m".into(), details: None, retryable: false, retry_after_ms: None });
        assert_eq!(board_code(&refusal("BOARD_ITEM_TAKEN")), Some("TAKEN"));
        assert_eq!(board_code(&refusal("QUOTA_EXCEEDED")), Some("QUOTA_EXCEEDED"));
        assert_eq!(board_code(&MeshError::code(crate::ErrorCode::IdentityMismatch, "not yours")), Some("NOT_YOURS"));
        assert_eq!(board_code(&refusal("SOMETHING_ELSE")), None);
        // A code the request does not name stays as it came.
        assert_eq!(board_code(&refusal("QUOTA_EXCEEDED")).and_then(BoardClaimRefusal::from_code), None);
        assert_eq!(board_code(&refusal("BOARD_ITEM_TAKEN")).and_then(BoardClaimRefusal::from_code), Some(BoardClaimRefusal::Taken));
    }

    #[test]
    fn a_request_the_service_finds_forged_is_not_yours_on_every_board_request() {
        // Debt 359: the rooms service acts only as the agent that signed the
        // envelope, and answers IDENTITY_MISMATCH to one whose signature does
        // not verify against the sender it names, and to a done, give-back or
        // withdraw by anyone but the holder or poster. Read the way
        // service_request reads a reply, every board request, the list among
        // them, gives that back as the definition's NOT_YOURS.
        let forged = MeshError::from_error_object(&ErrorObject {
            code: "IDENTITY_MISMATCH".into(),
            message: "Envelope signature does not verify against 'from'".into(),
            details: None,
            retryable: false,
            retry_after_ms: None,
        });
        let code = board_code(&forged);
        assert_eq!(code, Some("NOT_YOURS"));
        assert_eq!(code.and_then(BoardListRefusal::from_code), Some(BoardListRefusal::NotYours));
        assert_eq!(code.and_then(BoardPostRefusal::from_code), Some(BoardPostRefusal::NotYours));
        assert_eq!(code.and_then(BoardClaimRefusal::from_code), Some(BoardClaimRefusal::NotYours));
        assert_eq!(code.and_then(BoardDoneRefusal::from_code), Some(BoardDoneRefusal::NotYours));
        assert_eq!(code.and_then(BoardAbandonRefusal::from_code), Some(BoardAbandonRefusal::NotYours));
        assert_eq!(code.and_then(BoardWithdrawRefusal::from_code), Some(BoardWithdrawRefusal::NotYours));
    }

    #[test]
    fn a_from_in_the_input_names_nobody() {
        // An input that names another agent, as JSON from a caller would,
        // keeps none of it: what is sent is the request's own fields, and who
        // sends it is the key that signs the envelope (service_request).
        let other = "UOTHERAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let named = serde_json::json!({ "room": "launch", "item_id": "itm_1", "title": "x", "from": other, "posted_by": other, "claimed_by": other });
        let post: BoardPostInput = serde_json::from_value(named.clone()).unwrap();
        let claim: BoardClaimInput = serde_json::from_value(named.clone()).unwrap();
        let done: BoardDoneInput = serde_json::from_value(named.clone()).unwrap();
        let withdraw: BoardWithdrawInput = serde_json::from_value(named).unwrap();
        for sent in [
            serde_json::to_value(&post).unwrap(),
            serde_json::to_value(&claim).unwrap(),
            serde_json::to_value(&done).unwrap(),
            serde_json::to_value(&withdraw).unwrap(),
        ] {
            assert!(!sent.to_string().contains(other), "{sent}");
        }
    }
}
