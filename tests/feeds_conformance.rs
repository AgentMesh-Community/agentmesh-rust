//! Feeds conformance (SPEC §6.6a, §14.1, §18.3) against `conformance/feeds.json`.
//!
//! THE FIXTURE IS THE AUTHORITY for the shapes that must agree byte-for-byte
//! across the TypeScript SDK, this crate, the adapter and the platform: the
//! subject grammar (exactly four tokens, owner nkey then a single topic
//! token), the feed emit payload (`{topic, kind, data}` — NOT the
//! `{domain, event_type, data}` of a domain emit), the state-feed KV key
//! (`{agent_id}.{topic}`), and the current-value lookup on `mesh.feed.get`
//! (`{agent, topic}` in, `{found, envelope}` out). Divergences here are
//! one-byte ones — a dot that splits a topic, an owner token in the wrong
//! position — so the tests iterate the case arrays and a new fixture row runs
//! without touching any test.

use std::collections::BTreeSet;

use agentmesh::feed::{feed_lookup_payload, feed_payload, FeedKind};
use agentmesh::subjects;
use serde_json::Value;

static FIXTURE_JSON: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/conformance/feeds.json"));

fn fixture() -> Value {
    serde_json::from_str(FIXTURE_JSON).expect("conformance/feeds.json parses")
}

fn str_at<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

fn cases(fix: &Value, path: &[&str]) -> Vec<Value> {
    let mut v = fix;
    for key in path {
        v = v.get(key).unwrap_or_else(|| panic!("fixture has {path:?}"));
    }
    v.as_array().unwrap_or_else(|| panic!("{path:?} is an array")).clone()
}

// ── subjects.build_cases: the builder accepts or REFUSES, never mangles ─────

fn run_build_cases() -> Vec<String> {
    let fix = fixture();
    let mut ran = Vec::new();
    for case in cases(&fix, &["subjects", "build_cases"]) {
        let id = str_at(&case, "id").expect("case id").to_string();
        let agent = str_at(&case, "agent").expect("agent");
        let topic = str_at(&case, "topic").expect("topic");
        match str_at(&case, "verdict") {
            Some("accept") => {
                let want = str_at(&case, "subject").expect("accept case pins a subject");
                assert_eq!(
                    subjects::feed(agent, topic).unwrap_or_else(|e| panic!("{id}: {e}")),
                    want,
                    "{id}: built subject"
                );
                // The subscription form builds the same subject for a real topic.
                assert_eq!(subjects::feed_pattern(agent, topic).unwrap(), want, "{id}: pattern form");
            }
            Some("refuse") => {
                assert!(subjects::feed(agent, topic).is_err(), "{id}: builder must refuse");
                if topic == "*" {
                    // The one divergence §6.7 grants the SUBSCRIPTION form: the
                    // single-star wildcard matches all of one agent's feeds.
                    assert_eq!(
                        subjects::feed_pattern(agent, topic).unwrap(),
                        format!("mesh.feed.{agent}.*"),
                        "{id}: the pattern form admits the wildcard"
                    );
                } else {
                    assert!(subjects::feed_pattern(agent, topic).is_err(), "{id}: pattern refuses too");
                }
            }
            v => panic!("{id}: unknown verdict {v:?}"),
        }
        ran.push(id);
    }
    ran
}

#[test]
fn built_subjects_match_the_fixture() {
    assert!(!run_build_cases().is_empty());
}

// ── subjects.parse_cases: four tokens, right prefix, nkey owner, one topic ──

fn run_parse_cases() -> Vec<String> {
    let fix = fixture();
    let mut ran = Vec::new();
    for case in cases(&fix, &["subjects", "parse_cases"]) {
        let id = str_at(&case, "id").expect("case id").to_string();
        let subject = str_at(&case, "subject").expect("subject");
        match str_at(&case, "verdict") {
            Some("accept") => {
                let (agent, topic) = subjects::parse_feed_subject(subject)
                    .unwrap_or_else(|| panic!("{id}: {subject} must parse"));
                assert_eq!(agent, str_at(&case, "agent").expect("agent"), "{id}: owner");
                assert_eq!(topic, str_at(&case, "topic").expect("topic"), "{id}: topic");
            }
            Some("refuse") => {
                assert_eq!(subjects::parse_feed_subject(subject), None, "{id}: {subject} is not a feed");
            }
            v => panic!("{id}: unknown verdict {v:?}"),
        }
        ran.push(id);
    }
    ran
}

#[test]
fn parsed_subjects_match_the_fixture() {
    assert!(!run_parse_cases().is_empty());
}

// ── payload.shape_cases: {topic, kind, data}, never the domain split ────────

fn run_shape_cases() -> Vec<String> {
    let fix = fixture();
    let mut ran = Vec::new();
    for case in cases(&fix, &["payload", "shape_cases"]) {
        let id = str_at(&case, "id").expect("case id").to_string();
        let topic = str_at(&case, "topic").expect("topic");
        let kind: FeedKind = serde_json::from_value(case.get("kind").expect("kind").clone())
            .unwrap_or_else(|e| panic!("{id}: kind parses: {e}"));
        let data = case.get("data").expect("data").clone();
        let want = case.get("payload").expect("pinned payload");
        assert_eq!(&feed_payload(topic, kind, data), want, "{id}: payload deep-equals the pin");
        ran.push(id);
    }
    ran
}

#[test]
fn payload_shapes_match_the_fixture() {
    assert!(!run_shape_cases().is_empty());
}

// ── payload.kind_cases: "state" and "stream" are the whole vocabulary ───────

fn run_kind_cases() -> Vec<String> {
    let fix = fixture();
    let mut ran = Vec::new();
    for case in cases(&fix, &["payload", "kind_cases"]) {
        let id = str_at(&case, "id").expect("case id").to_string();
        let kind = case.get("kind").expect("kind").clone();
        match str_at(&case, "verdict") {
            Some("accept") => {
                let parsed: FeedKind = serde_json::from_value(kind.clone())
                    .unwrap_or_else(|e| panic!("{id}: must parse: {e}"));
                // Round trip: what parsed serializes back to the same word.
                assert_eq!(serde_json::to_value(parsed).unwrap(), kind, "{id}: round trip");
            }
            Some("refuse") => {
                assert!(
                    serde_json::from_value::<FeedKind>(kind).is_err(),
                    "{id}: not a §6.6a kind"
                );
            }
            v => panic!("{id}: unknown verdict {v:?}"),
        }
        ran.push(id);
    }
    ran
}

#[test]
fn kinds_round_trip_and_strangers_fail() {
    assert!(!run_kind_cases().is_empty());
}

// ── state_binding.kv_key_cases: the key is the subject minus its prefix ─────

fn run_kv_key_cases() -> Vec<String> {
    let fix = fixture();
    let mut ran = Vec::new();
    for case in cases(&fix, &["state_binding", "kv_key_cases"]) {
        let id = str_at(&case, "id").expect("case id").to_string();
        let agent = str_at(&case, "agent").expect("agent");
        let topic = str_at(&case, "topic").expect("topic");
        let want = str_at(&case, "key").expect("key");
        // The platform writes the key; this SDK's stake is that the key
        // grammar and the subject grammar are the SAME grammar — the key is
        // the built subject minus its `mesh.feed.` prefix, token for token.
        let subject = subjects::feed(agent, topic).unwrap_or_else(|e| panic!("{id}: {e}"));
        let key = subject.strip_prefix("mesh.feed.").expect("feed subjects share the prefix");
        assert_eq!(key, want, "{id}: KV key");
        // …and parsing the subject back yields the key's two halves.
        let (p_agent, p_topic) = subjects::parse_feed_subject(&subject).expect("round trip");
        assert_eq!(format!("{p_agent}.{p_topic}"), want, "{id}: parse agrees");
        ran.push(id);
    }
    ran
}

#[test]
fn state_kv_keys_match_the_fixture() {
    assert!(!run_kv_key_cases().is_empty());
}

// ── state_binding.lookup_request_cases: {agent, topic}, nothing else ────────

fn run_lookup_request_cases() -> Vec<String> {
    let fix = fixture();
    let mut ran = Vec::new();
    for case in cases(&fix, &["state_binding", "lookup_request_cases"]) {
        let id = str_at(&case, "id").expect("case id").to_string();
        let agent = str_at(&case, "agent").expect("agent");
        let topic = str_at(&case, "topic").expect("topic");
        let want = case.get("payload").expect("pinned payload");
        // `feed_value` sends exactly this builder's output on `mesh.feed.get`.
        assert_eq!(&feed_lookup_payload(agent, topic), want, "{id}: lookup payload");
        ran.push(id);
    }
    ran
}

#[test]
fn lookup_requests_match_the_fixture() {
    assert!(!run_lookup_request_cases().is_empty());
}

// ── every case ran ──────────────────────────────────────────────────────────

/// Collect the `id` of every element of every array whose key ends in `cases`.
///
/// Generic on purpose (the `inbound_protections` pattern): naming the six
/// arrays would mean a new group added to the fixture went unnoticed, which is
/// the one failure mode a conformance suite cannot have.
fn discover_case_ids(v: &Value, key: Option<&str>, out: &mut BTreeSet<String>) {
    match v {
        Value::Object(map) => {
            for (k, child) in map {
                discover_case_ids(child, Some(k), out);
            }
        }
        Value::Array(items) => {
            let is_case_list = key.is_some_and(|k| k.ends_with("cases"));
            for item in items {
                if is_case_list {
                    if let Some(id) = str_at(item, "id") {
                        out.insert(id.to_string());
                    }
                }
                discover_case_ids(item, key, out);
            }
        }
        _ => {}
    }
}

#[test]
fn no_case_in_the_fixture_is_unexercised() {
    let mut declared = BTreeSet::new();
    discover_case_ids(&fixture(), None, &mut declared);

    let mut executed = BTreeSet::new();
    for group in [
        run_build_cases(),
        run_parse_cases(),
        run_shape_cases(),
        run_kind_cases(),
        run_kv_key_cases(),
        run_lookup_request_cases(),
    ] {
        executed.extend(group);
    }

    let missed: Vec<&String> = declared.difference(&executed).collect();
    assert!(missed.is_empty(), "fixture cases never exercised: {missed:?}");
    assert!(!declared.is_empty(), "the fixture declares cases");
}
