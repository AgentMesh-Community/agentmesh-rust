//! What a statement rested on (SPEC.md §5.6), asserted against
//! `conformance/rests-on.json`.
//!
//! **The fixture is the authority.** When a case here fails, the fix is in
//! `src/rests_on.rs`, never in the JSON; the fixture itself changes only with
//! a spec change alongside. Cases are executed by **iterating** the fixture: a
//! row added to the JSON runs here without this file changing.
//!
//! Two implementations do not disagree about SHA-256. They disagree about
//! whether an unreachable input counts as agreement, whether a known change is
//! outranked by an unreachable neighbour, and whether "declared nothing" reads
//! as "nothing changed". Those are exactly what this fixture pins, and the TS
//! suite (`__tests__/unit/rests-on-conformance.test.ts`) asserts the same rows.

use std::cell::Cell;

use agentmesh::rests_on::{
    check_freshness, is_digest, validate_rests_on, Freshness, RestsOnEntry, MAX_RESTS_ON,
};
use serde_json::Value;

static FIXTURE_JSON: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/conformance/rests-on.json"));

fn fixture() -> Value {
    serde_json::from_str(FIXTURE_JSON).expect("conformance/rests-on.json parses")
}

fn entries_of(v: &Value) -> Vec<RestsOnEntry> {
    serde_json::from_value(v.clone()).expect("declared entries parse")
}

#[test]
fn digest_spelling_matches_the_fixture() {
    let f = fixture();
    let valid = f["digest"]["valid"].as_array().expect("valid digests").clone();
    assert!(!valid.is_empty());
    for d in valid {
        let s = d.as_str().expect("digest is a string");
        assert!(is_digest(s), "should accept {s}");
    }
    for bad in f["digest"]["invalid"].as_array().expect("invalid digests") {
        let s = bad["value"].as_str().expect("value is a string");
        let why = bad["why"].as_str().unwrap_or("");
        assert!(!is_digest(s), "should refuse {s:?}: {why}");
    }
}

#[test]
fn valid_entries_validate() {
    let f = fixture();
    let all = entries_of(&f["entries"]["valid"]);
    assert!(!all.is_empty());
    for e in &all {
        validate_rests_on(std::slice::from_ref(e)).unwrap_or_else(|err| panic!("{e:?}: {err}"));
    }
    validate_rests_on(&all).expect("the valid entries validate together");
}

#[test]
fn invalid_lists_are_refused() {
    let f = fixture();
    for case in f["entries"]["invalid"].as_array().expect("invalid cases") {
        let name = case["case"].as_str().unwrap_or("?");
        let why = case["why"].as_str().unwrap_or("");
        // A list that does not even deserialize into entries is refused at the
        // type boundary, which is the same refusal by another road: the point
        // is that no path accepts it.
        match serde_json::from_value::<Vec<RestsOnEntry>>(case["rests_on"].clone()) {
            Ok(entries) => assert!(
                validate_rests_on(&entries).is_err(),
                "{name} should be refused ({why})"
            ),
            Err(_) => { /* refused at parse */ }
        }
    }
}

#[test]
fn the_cap_matches_the_fixture_and_holds() {
    let f = fixture();
    assert_eq!(MAX_RESTS_ON, f["entries"]["max_entries"].as_u64().expect("max_entries") as usize);
    let base = entries_of(&f["entries"]["valid"])[0].clone();
    let many: Vec<RestsOnEntry> = (0..=MAX_RESTS_ON)
        .map(|i| RestsOnEntry { ref_: Some(format!("mesh:artifacts:{i}")), ..base.clone() })
        .collect();
    assert!(validate_rests_on(&many).is_err(), "one past the cap is refused");
    assert!(validate_rests_on(&many[..MAX_RESTS_ON]).is_ok(), "exactly the cap is fine");
}

#[test]
fn freshness_cases() {
    let f = fixture();
    for case in f["freshness"]["cases"].as_array().expect("freshness cases") {
        let name = case["name"].as_str().unwrap_or("?");
        let countersigned = case["countersigned"].as_bool().unwrap_or(false);
        let declared: Option<Vec<RestsOnEntry>> = if case["declared"].is_null() {
            None
        } else {
            Some(entries_of(&case["declared"]))
        };
        let observed = case["observed"].clone();

        let called = Cell::new(0usize);
        let result = check_freshness(
            declared.as_deref(),
            |entry| {
                called.set(called.get() + 1);
                let key = entry.ref_.as_deref()?;
                match observed.get(key) {
                    Some(Value::String(s)) => Some(s.clone()),
                    _ => None,
                }
            },
            countersigned,
        );

        let expected = &case["expected"];
        let want_state = match expected["state"].as_str().expect("state") {
            "fresh" => Freshness::Fresh,
            "stale" => Freshness::Stale,
            "unchecked" => Freshness::Unchecked,
            "undeclared" => Freshness::Undeclared,
            "not_applicable" => Freshness::NotApplicable,
            other => panic!("{name}: unknown expected state {other}"),
        };
        assert_eq!(result.state, want_state, "{name}");

        let got_changed: Vec<Option<&str>> =
            result.changed.iter().map(|c| c.entry.ref_.as_deref()).collect();
        let want_changed: Vec<Option<&str>> = expected["changed"]
            .as_array()
            .expect("changed")
            .iter()
            .map(|v| v.as_str())
            .collect();
        assert_eq!(got_changed, want_changed, "{name}: changed");

        let got_unreachable: Vec<Option<&str>> =
            result.unreachable.iter().map(|e| e.ref_.as_deref()).collect();
        let want_unreachable: Vec<Option<&str>> = expected["unreachable"]
            .as_array()
            .expect("unreachable")
            .iter()
            .map(|v| v.as_str())
            .collect();
        assert_eq!(got_unreachable, want_unreachable, "{name}: unreachable");

        // The agreement exclusion is not "we ignore the answer", it is "we do
        // not look". A verifier that resolved the refs anyway would be
        // spending requests to compute a verdict §5.6 says it must discard.
        if case["observe_must_not_be_called"].as_bool().unwrap_or(false) {
            assert_eq!(called.get(), 0, "{name}: nothing should have been resolved");
        }
    }
}

#[test]
fn undeclared_is_not_fresh() {
    // The failure this guards: a reader that treated "declared nothing" as
    // "nothing changed" would report a clean bill of health for a statement
    // that made no claim at all.
    assert_eq!(check_freshness(None, |_| None, false).state, Freshness::Undeclared);
    assert_eq!(check_freshness(Some(&[]), |_| None, false).state, Freshness::Undeclared);
}

#[test]
fn a_stale_verdict_names_the_input_that_moved() {
    let declared = vec![RestsOnEntry {
        digest: format!("sha256:{}", "1".repeat(64)),
        ref_: Some("a".to_string()),
        name: Some("invoices-q3.zip".to_string()),
        role: None,
    }];
    let r = check_freshness(
        Some(&declared),
        |_| Some(format!("sha256:{}", "9".repeat(64))),
        false,
    );
    assert_eq!(r.state, Freshness::Stale);
    assert!(r.describe().contains("invoices-q3.zip"), "{}", r.describe());
}

#[test]
fn an_unreadable_input_says_the_signature_is_still_good() {
    let declared = vec![RestsOnEntry {
        digest: format!("sha256:{}", "1".repeat(64)),
        ref_: Some("a".to_string()),
        name: None,
        role: None,
    }];
    let r = check_freshness(Some(&declared), |_| None, false);
    assert_eq!(r.state, Freshness::Unchecked);
    assert!(r.describe().contains("signature is good"), "{}", r.describe());
}

#[test]
fn the_wire_name_of_ref_is_ref() {
    // The rename is at the boundary, not in the data: `ref_` is a Rust
    // grammar problem and must not reach the wire, where the TS SDK and the
    // fixture both say `ref`.
    let e = RestsOnEntry {
        digest: format!("sha256:{}", "1".repeat(64)),
        ref_: Some("mesh:artifacts:1".to_string()),
        name: None,
        role: None,
    };
    let v = serde_json::to_value(&e).expect("serializes");
    assert_eq!(v["ref"], "mesh:artifacts:1");
    assert!(v.get("ref_").is_none());
}
