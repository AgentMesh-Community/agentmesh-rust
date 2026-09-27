//! Rooms (EXT-5) in the Rust SDK.
//!
//! There was no rooms test file here at all, which is how the SDK went several
//! releases with no `expel` — no message variant, no `Room::expel` — while the
//! TypeScript SDK had it and EXT-5 §8.1 specified it. These cover the descriptor's
//! signature (it IS the membership credential at the capability grade) and the
//! expel wire shape, both cross-SDK contracts.
//!
//! The three receive-side rules — first-person membership, creator-only
//! lifecycle, unknown-severity normalization — are unit-tested inside
//! `src/rooms.rs`, because they are `pub(crate)` and widening the public API just
//! to reach them from here would be the wrong trade.

use agentmesh::rooms::{
    descriptor_from_token, descriptor_to_token, sign_descriptor, verify_descriptor,
    RoomDescriptor, RoomMessage,
};
use agentmesh::KeyPair;

fn kp() -> KeyPair {
    KeyPair::new_user()
}

fn descriptor(creator: &str) -> RoomDescriptor {
    RoomDescriptor {
        rooms: "v1".to_string(),
        room_id: "test-room-0123456789ab".to_string(),
        name: Some("test".to_string()),
        channels: vec!["main".to_string()],
        playbook: None,
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
fn descriptor_signs_verifies_and_rejects_tampering() {
    let creator = kp();
    let signed = sign_descriptor(descriptor(&creator.public_key()), &creator).expect("sign");
    assert!(verify_descriptor(&signed));

    // The descriptor IS the membership credential at the capability grade, so a
    // forged one must not verify.
    let mut tampered = signed.clone();
    tampered.name = Some("somebody else's room".to_string());
    assert!(!verify_descriptor(&tampered), "a tampered descriptor must not verify");

    // A different key's signature does not stand in for the creator's.
    let stranger = kp();
    let restamped = sign_descriptor(signed.clone(), &stranger).expect("re-sign");
    assert!(
        restamped.creator != stranger.public_key(),
        "creator field is not rewritten by signing"
    );
    assert!(!verify_descriptor(&restamped));
}

#[test]
fn descriptor_round_trips_through_its_token_form() {
    let creator = kp();
    let signed = sign_descriptor(descriptor(&creator.public_key()), &creator).expect("sign");
    let token = descriptor_to_token(&signed).expect("to token");
    let back = descriptor_from_token(&token).expect("from token");
    assert_eq!(back.room_id, signed.room_id);
    assert_eq!(back.sig, signed.sig);
    assert!(verify_descriptor(&back), "the token form still verifies");
}

#[test]
fn expel_serializes_to_the_wire_shape_the_spec_names() {
    let msg = RoomMessage::Expel {
        member: "UALICE".to_string(),
        severity: "timeout".to_string(),
        note: None,
    };
    let v = serde_json::to_value(&msg).expect("serialize");
    assert_eq!(v["type"], "expel");
    assert_eq!(v["member"], "UALICE");
    assert_eq!(v["severity"], "timeout");
    // An absent note is absent, not null — the TypeScript SDK omits it too, and
    // a canonical-JSON signature is computed over exactly these bytes.
    assert!(v.get("note").is_none(), "an omitted note must not serialize as null");

    // And it parses back from the same shape a TypeScript member would send.
    let from_ts: RoomMessage = serde_json::from_value(serde_json::json!({
        "type": "expel", "member": "UBOB", "severity": "safety", "note": "spam"
    }))
    .expect("parse a TS-shaped expel");
    match from_ts {
        RoomMessage::Expel { member, severity, note } => {
            assert_eq!(member, "UBOB");
            assert_eq!(severity, "safety");
            assert_eq!(note.as_deref(), Some("spam"));
        }
        other => panic!("expected an expel, got {other:?}"),
    }
}

// ── the work board (EXT-5 §10) ────────────────────────────────────────────
//
// The payload every verb sends (descriptor riding along, optionals omitted)
// is unit-tested inside `src/rooms.rs` next to the builder, like the receive
// rules. What belongs here is the public surface: the item record a TS
// service replies with must parse through the exported types, task_id — the
// §10.2 graft — included.

#[test]
fn a_board_item_from_the_service_parses_through_the_public_types() {
    let item: agentmesh::rooms::BoardItem = serde_json::from_value(serde_json::json!({
        "item_id": "item-1",
        "room_id": "board-room-0123456789",
        "title": "summarize the meeting",
        "detail": "the whole meeting, one page",
        "offering": "summarizer",
        "posted_by": "UPOSTER",
        "posted_at": "2026-08-12T00:00:00Z",
        "lease_ms": 3_600_000,
        "state": "claimed",
        "claimed_by": "UWORKER",
        "claimed_at": "2026-08-12T00:01:00Z",
        "lease_expires_at": "2026-08-12T01:01:00Z",
        "task_id": "task-abc"
    }))
    .expect("parse a service-shaped item");
    assert_eq!(item.state, "claimed");
    assert_eq!(
        item.task_id.as_deref(),
        Some("task-abc"),
        "the claim's minted task_id must survive the parse — the claimer opens the real Task under it"
    );

    // And a minimal open item — every optional field absent — parses too.
    let open: agentmesh::rooms::BoardItem = serde_json::from_value(serde_json::json!({
        "item_id": "item-2",
        "room_id": "board-room-0123456789",
        "title": "translate the notes",
        "posted_by": "UPOSTER",
        "posted_at": "2026-08-12T00:00:00Z",
        "lease_ms": 3_600_000,
        "state": "open"
    }))
    .expect("parse a minimal open item");
    assert!(open.task_id.is_none());
    assert!(open.claims.is_none());
}

// ── notes on a file (EXT-5 §8.4) ──────────────────────────────────────────
//
// The payloads the two verbs send — descriptor riding along, `by` absent,
// optionals omitted — are unit-tested inside `src/rooms.rs` next to the
// builders, like the board's. What belongs here is the public surface: the
// record a TS service replies with must parse through the exported types, and
// the verdict a caller passes must come from the exported enum.

#[test]
fn a_stored_note_from_the_service_parses_through_the_public_types() {
    let note: agentmesh::rooms::RoomNote = serde_json::from_value(serde_json::json!({
        "note": "screening/v1",
        "digest": "sha256:1a2b3c4d5e6f",
        "verdict": "pass",
        "reason": "No instruction-shaped content found.",
        "by": "UGUARD",
        "at": "2026-08-13T14:10:00Z",
        "source": { "id": "model-armor", "policy": "proj_7d2f", "version": "2026-08-01" }
    }))
    .expect("parse a service-shaped note");

    // Keyed by digest, never by name or ref: the note is about those exact
    // bytes, permanently.
    assert_eq!(note.digest, "sha256:1a2b3c4d5e6f");
    // Attributed, and the author is the service's to set — surfaces MUST show
    // it, and MUST NOT present the note as the room's own verdict.
    assert_eq!(note.by, "UGUARD");
    assert_eq!(
        agentmesh::rooms::NoteVerdict::parse(&note.verdict),
        Some(agentmesh::rooms::NoteVerdict::Pass)
    );
    assert_eq!(note.source.expect("source").id.as_deref(), Some("model-armor"));

    // The minimum a note can be: a digest, a verdict, and who said it.
    let bare: agentmesh::rooms::RoomNote = serde_json::from_value(serde_json::json!({
        "note": "screening/v1",
        "digest": "sha256:ffff",
        "verdict": "flag",
        "by": "UGUARD",
        "at": "2026-08-13T14:10:00Z"
    }))
    .expect("parse a minimal note");
    assert!(bare.reason.is_none());
    assert!(bare.source.is_none());
}

#[test]
fn the_verdict_a_caller_writes_comes_from_the_closed_enum() {
    use agentmesh::rooms::NoteVerdict;
    // Three values and no more — the same closed set the TypeScript SDK's
    // ROOM_NOTE_VERDICTS spells, in the same order.
    assert_eq!(
        [NoteVerdict::Pass, NoteVerdict::Flag, NoteVerdict::Hold].map(|v| v.as_str()),
        ["pass", "flag", "hold"]
    );
    // There is no fourth to pass, and a free string does not become one.
    assert!("looks-fine".parse::<NoteVerdict>().is_err());
}

// ── node-hosted agents and the acl grade ─────────────────────────────────
//
// Until 2026-07-30 a hosted agent carried no mesh URL — `hosted_by` set
// `url: String::new()` — so `open_scoped_connection` refused every acl room
// with "acl rooms require a standalone agent". That locked the Egg Gateway, the
// reference node, out of the one grade whose membership the broker actually
// enforces: it could open capability and sealed rooms all day and never join an
// acl one. A node now retains the URL it dialled and hands it to each hosted
// agent, for this single purpose.
//
// Why a second connection is unavoidable, and why sharing the node's is not an
// option: acl traffic rides `mesh.aclroom.<id>.>`, which the broker permits only
// on the short-lived credential the rooms service mints per member per room.
// `cred-template.ts` keeps `mesh.aclroom.>` in its NEVER deny list for exactly
// this reason — that separation IS the grade.

/// Live: needs an operator-mode broker with a rooms service (see
/// `services/tools/local-acl-mesh.mjs`). Set ACL_MESH_URL to run it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_node_hosted_agent_can_open_an_acl_room() {
    let Ok(url) = std::env::var("ACL_MESH_URL") else {
        eprintln!("skipping: set ACL_MESH_URL to a broker with a rooms service");
        return;
    };
    let jwt = std::env::var("ACL_MESH_NODE_JWT").ok();
    let node_seed = std::env::var("ACL_MESH_NODE_SEED").ok();

    let node = match agentmesh::MeshNode::connect(
        &url,
        agentmesh::NodeConnectOptions { jwt, node_seed, ..Default::default() },
    )
    .await
    {
        Ok(n) => n,
        Err(e) => {
            eprintln!("skipping: could not connect as a node: {e}");
            return;
        }
    };

    let agent = node.add_agent(None).expect("add hosted agent");
    let room = agent
        .open_room_acl(agentmesh::rooms::OpenRoomOptions {
            name: Some("hosted-acl".into()),
            acl: true,
            ..Default::default()
        })
        .await
        .expect("a node-hosted agent must be able to open an acl room");

    assert!(room.acl(), "the room must be at the acl grade");
    // Posting proves the scoped connection is live: `say` publishes on the
    // room-scoped connection at this grade, not the node's.
    room.say("hello from a hosted agent", None, None)
        .await
        .expect("say over the scoped connection");
}

/// A node built over a caller-supplied client keeps the old refusal, because
/// there is genuinely no URL to redial. Deterministic — no broker needed.
#[test]
fn a_with_client_node_still_refuses_acl_for_want_of_a_url() {
    // Documented behaviour rather than a live probe: `with_client` takes an
    // `async_nats::Client` the caller opened, and async-nats exposes no dialled
    // URL on one, so an acl room cannot open its second connection. The refusal
    // now says that instead of blaming the node model.
    let msg = "acl rooms need a mesh URL to dial the room-scoped connection";
    assert!(
        include_str!("../src/client.rs").contains(msg),
        "the with_client refusal must explain the missing URL, not claim acl needs a standalone agent",
    );
}
