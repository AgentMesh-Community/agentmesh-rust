//! The three job doors (§5.7) from the asking side: `job.manifest`,
//! `job.quote`, `job.record`.
//!
//! Three things are being held here, and the middle one is the point:
//!
//!  1. a good answer parses into the declared shape and nothing else;
//!  2. the sentence every door gives BOTH to an unentitled asker and about a
//!     task it does not know comes back as a refusal, never as an `Err` and
//!     never flattened into "no such task". A stranger holding a task id must
//!     learn nothing from that door, and a client that guessed on the caller's
//!     behalf would undo it;
//!  3. an answer that does not parse is refused whole, with the member named.
//!
//! The manifest the door hands over is the one pinned by
//! `conformance/job-manifest.json`, so this test and the TypeScript SDK's read
//! the same signed bytes. The sentences are pinned against the adapter's own
//! source at the bottom of this file: the doors are served there, so that file
//! is the authority for what they say.

use agentmesh::{
    ask_job_manifest, ask_job_record, parse_job_manifest_answer, parse_job_quote_answer,
    parse_job_record_answer, AgentMesh, ConnectOptions, JobDoorOptions, JobManifestAnswer,
    JobManifestReason, JobQuoteAnswer, JobRecordAnswer, RegisterOptions, JOB_QUOTE_FORMAT,
    JOB_RECORD_FORMAT, MANIFEST_UNREADABLE_REASON, NO_JOB_MANIFEST_REASON, NO_JOB_REASON,
    NO_REVISIONS_REASON,
};
use serde_json::{json, Value};

static FIXTURE_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/conformance/job-manifest.json"
));

const MANIFEST_REF: &str = "mesh:artifacts:f2c1a0de";
const AGENT: &str = "UAGENTAGENTAGENTAGENTAGENTAGENTAGENTAGENTAGENTAGENTAGENT";

/// The signed first delivery the fixture pins. Both SDKs read this document.
fn signed() -> Value {
    let f: Value = serde_json::from_str(FIXTURE_JSON).expect("conformance/job-manifest.json parses");
    f["job_manifest"]["signed"].clone()
}

/// A quote the way the door builds one: the named steps with their prices, the
/// total, what is still included, and the offering's whole step list.
fn quote() -> Value {
    json!({
        "quote": JOB_QUOTE_FORMAT,
        "offering": "explainer",
        "steps": [
            { "id": "script", "price": { "amount_micro": 2_000_000, "currency": "USD" } },
            { "id": "voice", "price": null }
        ],
        "price": { "amount_micro": 2_000_000, "currency": "USD" },
        "included_remaining": 0,
        "window_ends_at": "2026-09-24T09:00:00.000Z",
        "unknown_steps": ["storyboard"],
        "all_steps": ["script", "voice", "render"],
        "at": "2026-09-10T12:00:00.000Z"
    })
}

/// A record the way the door builds one, with the three faults it was written
/// for represented: a folder that is gone, pieces that could not be stored, and
/// a harness that did not answer.
fn record() -> Value {
    json!({
        "record": JOB_RECORD_FORMAT,
        "task_id": "t-77",
        "at": "2026-09-10T12:00:00.000Z",
        "offering": "explainer",
        "received_at": "2026-09-10T11:02:00.000Z",
        "folder": { "present": false, "made_at": "2026-09-10T11:02:01.000Z" },
        "pieces_json": { "found": true, "where": "the job folder", "at": "2026-09-10T11:40:00.000Z" },
        "collected": { "count": 3, "names": ["explainer.html", "beat-01.mp3", "beat-02.mp3"] },
        "dropped": [{ "name": "render.mp4", "size_bytes": 91_000_000, "why": "over the store's size cap" }],
        "skipped": [{ "name": "notes.txt", "why": "" }],
        "manifest": { "filed": true, "ref": MANIFEST_REF, "version": 2 },
        "reply": { "sent": true, "at": "2026-09-10T11:41:00.000Z", "delivery": "3 pieces" },
        "refusal": null,
        "harness": { "fault": "the harness ended with no output", "output_chars": 0 },
        "unknown": ["whether a reply was sent"],
        "summary": "The job folder was made at 2026-09-10T11:02:01.000Z and is no longer on this host."
    })
}

/// The fault of a malformed answer, whichever door it came from.
fn manifest_fault(answer: &JobManifestAnswer) -> &agentmesh::JobManifestFault {
    match answer {
        JobManifestAnswer::Malformed(f) => f,
        other => panic!("expected a malformed answer, got {other:?}"),
    }
}
fn quote_fault(answer: &JobQuoteAnswer) -> &agentmesh::JobManifestFault {
    match answer {
        JobQuoteAnswer::Malformed(f) => f,
        other => panic!("expected a malformed answer, got {other:?}"),
    }
}
fn record_fault(answer: &JobRecordAnswer) -> &agentmesh::JobManifestFault {
    match answer {
        JobRecordAnswer::Malformed(f) => f,
        other => panic!("expected a malformed answer, got {other:?}"),
    }
}

// ─── job.manifest ───────────────────────────────────────────────────────────

#[test]
fn the_pinned_signed_manifest_parses_with_its_ref() {
    let answer = parse_job_manifest_answer(
        &json!({ "manifest": signed(), "manifest_ref": MANIFEST_REF }),
        None,
    );
    match answer {
        JobManifestAnswer::Answered {
            manifest,
            manifest_ref,
        } => {
            assert_eq!(serde_json::to_value(&*manifest).unwrap(), signed());
            assert_eq!(manifest_ref, MANIFEST_REF);
        }
        other => panic!("expected an answered manifest, got {other:?}"),
    }
}

#[test]
fn the_one_sentence_for_unknown_and_not_yours_is_a_refusal() {
    let answer =
        parse_job_manifest_answer(&json!({ "manifest": null, "reason": NO_JOB_MANIFEST_REASON }), None);
    match answer {
        JobManifestAnswer::Refused(r) => {
            assert_eq!(r.reason, NO_JOB_MANIFEST_REASON);
            assert!(r.unknown_or_not_yours, "the two cases are not distinguishable");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn the_unreadable_record_refusal_is_marked_as_the_different_thing_it_is() {
    let answer = parse_job_manifest_answer(
        &json!({ "manifest": null, "reason": MANIFEST_UNREADABLE_REASON }),
        None,
    );
    match answer {
        JobManifestAnswer::Refused(r) => assert!(!r.unknown_or_not_yours),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_refusal_that_says_nothing_is_malformed() {
    let answer = parse_job_manifest_answer(&json!({ "manifest": null }), None);
    assert_eq!(manifest_fault(&answer).member, "reason");
}

#[test]
fn a_malformed_manifest_is_refused_rather_than_half_parsed() {
    let mut doc = signed();
    doc["pieces"][0]["digest"] = json!("sha256:nope");
    let answer = parse_job_manifest_answer(&json!({ "manifest": doc, "manifest_ref": MANIFEST_REF }), None);
    let f = manifest_fault(&answer);
    assert_eq!(f.reason, JobManifestReason::Malformed);
    assert_eq!(f.member, "manifest.pieces[0].digest");
}

#[test]
fn a_manifest_whose_signature_does_not_verify_is_refused() {
    let mut doc = signed();
    doc["offering"] = json!("something-else");
    let answer = parse_job_manifest_answer(&json!({ "manifest": doc, "manifest_ref": MANIFEST_REF }), None);
    let f = manifest_fault(&answer);
    assert_eq!(f.reason, JobManifestReason::BadSignature);
    assert_eq!(f.member, "manifest.sig");
}

#[test]
fn a_manifest_signed_by_an_unexpected_key_is_refused() {
    let answer = parse_job_manifest_answer(
        &json!({ "manifest": signed(), "manifest_ref": MANIFEST_REF }),
        Some(AGENT),
    );
    assert_eq!(manifest_fault(&answer).reason, JobManifestReason::AgentMismatch);
}

#[test]
fn a_manifest_with_no_ref_is_refused() {
    let answer = parse_job_manifest_answer(&json!({ "manifest": signed() }), None);
    assert_eq!(manifest_fault(&answer).member, "manifest_ref");
}

// ─── job.quote ──────────────────────────────────────────────────────────────

#[test]
fn a_quote_parses_into_the_declared_shape() {
    match parse_job_quote_answer(&quote()) {
        JobQuoteAnswer::Answered(q) => {
            assert_eq!(q.offering, "explainer");
            assert!(q.steps[1].price.is_none(), "a step with no price of its own");
            assert_eq!(q.price.amount_micro, 2_000_000);
            assert_eq!(q.unknown_steps.as_deref(), Some(&["storyboard".to_string()][..]));
        }
        other => panic!("expected an answered quote, got {other:?}"),
    }
}

#[test]
fn a_quote_with_no_window_and_nothing_unknown_parses() {
    let mut q = quote();
    q["window_ends_at"] = Value::Null;
    q.as_object_mut().unwrap().remove("unknown_steps");
    match parse_job_quote_answer(&q) {
        JobQuoteAnswer::Answered(q) => {
            assert!(q.window_ends_at.is_none());
            assert!(q.unknown_steps.is_none());
        }
        other => panic!("expected an answered quote, got {other:?}"),
    }
}

#[test]
fn the_quote_doors_identical_refusal_is_a_refusal() {
    match parse_job_quote_answer(&json!({ "quote": null, "reason": NO_JOB_REASON })) {
        JobQuoteAnswer::Refused(r) => {
            assert_eq!(r.reason, NO_JOB_REASON);
            assert!(r.unknown_or_not_yours);
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn the_no_revisions_refusal_is_marked_as_the_different_thing_it_is() {
    match parse_job_quote_answer(&json!({ "quote": null, "reason": NO_REVISIONS_REASON })) {
        JobQuoteAnswer::Refused(r) => assert!(!r.unknown_or_not_yours),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_quote_that_names_itself_something_else_is_refused() {
    let mut q = quote();
    q["quote"] = json!("job-quote-v2");
    let answer = parse_job_quote_answer(&q);
    let f = quote_fault(&answer);
    assert_eq!(f.reason, JobManifestReason::WrongFormat);
    assert_eq!(f.member, "quote");
}

#[test]
fn a_price_that_is_not_one_and_a_step_that_is_not_one_are_refused() {
    let mut no_currency = quote();
    no_currency["price"] = json!({ "amount_micro": 5 });
    assert_eq!(quote_fault(&parse_job_quote_answer(&no_currency)).member, "price");

    let mut bad_step = quote();
    bad_step["steps"] = json!([{ "id": "script", "price": { "amount_micro": -1, "currency": "USD" } }]);
    assert_eq!(quote_fault(&parse_job_quote_answer(&bad_step)).member, "steps[0].price");
}

#[test]
fn an_at_that_is_not_an_instant_in_utc_is_refused() {
    let mut q = quote();
    q["at"] = json!("2026-09-10T12:00:00+02:00");
    assert_eq!(quote_fault(&parse_job_quote_answer(&q)).member, "at");
}

// ─── job.record ─────────────────────────────────────────────────────────────

#[test]
fn a_record_parses_into_the_declared_shape() {
    match parse_job_record_answer(&record()) {
        JobRecordAnswer::Answered(r) => {
            assert!(!r.folder.present);
            assert_eq!(r.folder.made_at.as_deref(), Some("2026-09-10T11:02:01.000Z"));
            assert_eq!(r.collected.as_ref().unwrap().count, 3);
            assert_eq!(r.dropped.as_ref().unwrap()[0].size_bytes, Some(91_000_000));
            assert_eq!(r.manifest.r#ref.as_deref(), Some(MANIFEST_REF));
            assert_eq!(r.unknown, vec!["whether a reply was sent".to_string()]);
        }
        other => panic!("expected an answered record, got {other:?}"),
    }
}

#[test]
fn an_unrecorded_reply_stays_unrecorded_rather_than_not_sent() {
    let mut doc = record();
    doc["reply"] = json!({ "sent": null, "at": null, "delivery": null });
    match parse_job_record_answer(&doc) {
        JobRecordAnswer::Answered(r) => assert!(r.reply.sent.is_none()),
        other => panic!("expected an answered record, got {other:?}"),
    }
}

#[test]
fn a_task_the_node_wrote_nothing_down_about_still_parses() {
    let mut doc = record();
    for member in ["offering", "received_at", "pieces_json", "collected", "dropped", "skipped", "refusal", "harness"] {
        doc[member] = Value::Null;
    }
    doc["manifest"] = json!({ "filed": false, "ref": null, "version": null });
    assert!(matches!(parse_job_record_answer(&doc), JobRecordAnswer::Answered(_)));
}

#[test]
fn a_collection_may_count_more_than_it_names() {
    // The node caps the names it lists and does not cap the count, so a very
    // large delivery names fewer pieces than it counted.
    let mut doc = record();
    doc["collected"] = json!({ "count": 200, "names": ["explainer.html"] });
    assert!(matches!(parse_job_record_answer(&doc), JobRecordAnswer::Answered(_)));
}

#[test]
fn the_record_doors_identical_refusal_is_a_refusal() {
    match parse_job_record_answer(&json!({ "record": null, "reason": NO_JOB_REASON })) {
        JobRecordAnswer::Refused(r) => {
            assert_eq!(r.reason, NO_JOB_REASON);
            assert!(r.unknown_or_not_yours);
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_record_that_names_itself_something_else_is_refused() {
    let mut doc = record();
    doc["record"] = json!("job-record-v2");
    assert_eq!(record_fault(&parse_job_record_answer(&doc)).reason, JobManifestReason::WrongFormat);
}

#[test]
fn a_folder_a_reply_and_a_dropped_piece_that_are_not_the_shape_are_refused() {
    let mut folder = record();
    folder["folder"] = json!({ "present": "no", "made_at": null });
    assert_eq!(record_fault(&parse_job_record_answer(&folder)).member, "folder");

    let mut reply = record();
    reply["reply"] = json!({ "sent": "yes", "at": null, "delivery": null });
    assert_eq!(record_fault(&parse_job_record_answer(&reply)).member, "reply");

    let mut dropped = record();
    dropped["dropped"] = json!([{ "name": "render.mp4" }]);
    assert_eq!(record_fault(&parse_job_record_answer(&dropped)).member, "dropped[0].why");
}

#[test]
fn an_answer_that_is_not_an_object_is_refused() {
    let answer = parse_job_record_answer(&json!("no job for that task at this agent"));
    assert_eq!(record_fault(&answer).member, "answer");
}

// ─── the node's own source ──────────────────────────────────────────────────

/// The doors are served by the reference node, so its source is the authority
/// for their names and for the sentences they refuse with. Skipped rather than
/// failed when the crate is checked out on its own, which is the same bargain
/// the broker-dependent suites make.
#[test]
fn the_node_serves_the_same_door_names_and_sentences() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../mesh-adapter/mesh-adapter.mjs");
    let Ok(source) = std::fs::read_to_string(path) else {
        eprintln!("skipping: no mesh-adapter beside this crate");
        return;
    };
    for door in [
        agentmesh::JOB_MANIFEST_DOOR,
        agentmesh::JOB_QUOTE_DOOR,
        agentmesh::JOB_RECORD_DOOR,
    ] {
        assert!(source.contains(&format!("\"{door}\"")), "the node serves {door}");
    }
    for reason in [
        NO_JOB_MANIFEST_REASON,
        NO_JOB_REASON,
        MANIFEST_UNREADABLE_REASON,
        NO_REVISIONS_REASON,
    ] {
        assert!(source.contains(reason), "the node refuses with: {reason}");
    }
    assert!(source.contains(JOB_QUOTE_FORMAT));
    assert!(source.contains(JOB_RECORD_FORMAT));
}

// ─── the wire ───────────────────────────────────────────────────────────────

/// The asking half, against a live broker: the door is asked by name, the
/// refusal comes back as a refusal, and an empty task id never leaves here.
/// Requires nats-server on 127.0.0.1:4222 (skips gracefully if absent), the
/// same bargain tests/e2e.rs makes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_doors_are_asked_by_name_and_a_refusal_comes_back_as_one() {
    const URL: &str = "nats://127.0.0.1:4222";
    let responder = match AgentMesh::connect(URL, ConnectOptions { allow_unnamed: true, ..Default::default() }).await {
        Ok(a) => a,
        Err(_) => {
            eprintln!("skipping job-door wire test: no NATS server at {URL}");
            return;
        }
    };
    let responder_id = responder.id().to_string();
    // What the node answers a caller who is not that task's requester, and
    // about a task it has no record of: one sentence for both.
    responder.on_request("job.record", |input| async move {
        assert_eq!(input["task_id"], json!("t-77"), "the door reads task_id");
        Ok(json!({ "record": null, "reason": NO_JOB_REASON }))
    });
    responder.on_request("job.manifest", |_input| async move {
        Ok(json!({ "manifest": null, "reason": NO_JOB_MANIFEST_REASON }))
    });
    responder
        .register(RegisterOptions {
            name: "job-door responder".into(),
            capabilities: vec!["job.record".into(), "job.manifest".into()],
            ..Default::default()
        })
        .await
        .expect("register");

    let requester = AgentMesh::connect(URL, ConnectOptions { allow_unnamed: true, ..Default::default() }).await.expect("connect requester");
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    match ask_job_record(&requester, &responder_id, "t-77", JobDoorOptions::default()).await {
        Ok(JobRecordAnswer::Refused(r)) => {
            assert_eq!(r.reason, NO_JOB_REASON);
            assert!(r.unknown_or_not_yours);
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    match ask_job_manifest(&requester, &responder_id, "t-77", JobDoorOptions::default()).await {
        Ok(JobManifestAnswer::Refused(r)) => assert!(r.unknown_or_not_yours),
        other => panic!("expected a refusal, got {other:?}"),
    }
    // An empty id is refused here rather than sent, because the door would
    // answer it with the very sentence above.
    let err = ask_job_record(&requester, &responder_id, "", JobDoorOptions::default())
        .await
        .unwrap_err();
    assert!(format!("{err}").contains("task_id"), "{err}");

    requester.close().await;
    responder.close().await;
}
