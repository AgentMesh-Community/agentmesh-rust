//! Agent SoW reporting (agentsow.com 0.13.0-draft §5.12), asserted against
//! `conformance/sow-reporting.json` — the same file the TypeScript SDK's
//! reporting conformance test reads.
//!
//! **The fixture is the authority.** When a case here fails, the fix is in
//! `src/sow.rs`, never in the JSON; a fixture changes only with a spec change
//! alongside. Cases are executed by ITERATING the fixture, so a row added to
//! the JSON runs here without this file changing.
//!
//! The load-bearing assertions are the cross-SDK ones: the ordinal levels and
//! their derived ranks, the meets-or-exceeds comparison, the restricted
//! cadence grammar with its pinned millisecond values, the exact shortfall
//! sentences a responder reads whichever SDK evaluated them, the pinned
//! boundary of the cadence-follows-the-money advisory, and the canonical
//! bytes of a document whose reporting clause sits INSIDE what is signed.

use serde_json::Value;

use agentmesh::{
    canonical_sow_json, meets_reporting_level, reporting_cadence_warning, reporting_every_ms,
    reporting_shortfall, validate_sow_reporting, SowReporting, SowReportingLevel,
    DEFAULT_REPORTING_LEVEL, SOW_REPORTING_GRADE, SOW_REPORTING_LEVELS,
};

static FIXTURE_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/conformance/sow-reporting.json"
));

fn fixture() -> Value {
    serde_json::from_str(FIXTURE_JSON).expect("conformance/sow-reporting.json parses")
}

fn strs(v: &Value) -> Vec<String> {
    v.as_array()
        .expect("array")
        .iter()
        .map(|s| s.as_str().expect("string").to_string())
        .collect()
}

fn level_of(s: &str) -> SowReportingLevel {
    SowReportingLevel::from_str(s).unwrap_or_else(|| panic!("'{s}' is a known reporting level"))
}

// ─── §5.12 the three levels, ordered ────────────────────────────────────────

#[test]
fn the_level_set_is_closed_ordered_and_matches_the_fixture() {
    let f = fixture();
    // Ordered, not just equal as sets: the order IS the rank.
    let want = strs(&f["levels"]["all"]);
    let got: Vec<String> = SOW_REPORTING_LEVELS.iter().map(|s| s.to_string()).collect();
    assert_eq!(got, want, "the ordered level set is the fixture's, in the fixture's order");
}

#[test]
fn every_rank_is_derived_from_the_level_and_matches_the_fixture() {
    let f = fixture();
    for (name, rank) in f["levels"]["rank"].as_object().expect("levels.rank") {
        let level = level_of(name);
        assert_eq!(
            level.rank() as u64,
            rank.as_u64().expect("rank"),
            "{name}: rank is derived from the level string"
        );
        // The wire string round-trips.
        assert_eq!(level.as_str(), name);
        // And position in the ordered set IS the rank.
        assert_eq!(
            SOW_REPORTING_LEVELS[level.rank() as usize], name,
            "{name}: position in the ordered set is the rank"
        );
    }
    // Nothing outside the closed vocabulary parses.
    assert!(SowReportingLevel::from_str("weekly").is_none());
}

#[test]
fn the_absent_clause_default_matches_the_fixture() {
    let f = fixture();
    assert_eq!(
        DEFAULT_REPORTING_LEVEL.as_str(),
        f["levels"]["default"].as_str().expect("levels.default"),
        "absent is NOT unknown: an undeclared clause offers the mechanical record"
    );
}

#[test]
fn the_grade_is_evidence_flatly() {
    let f = fixture();
    assert_eq!(
        serde_json::to_value(SOW_REPORTING_GRADE).expect("the grade serializes"),
        f["levels"]["grade"],
        "§5.12 grades this clause flatly"
    );
}

// ─── §5.12 meets or exceeds, never equals ───────────────────────────────────

#[test]
fn all_nine_meets_pairs_match_the_fixture() {
    let f = fixture();
    let cases = f["meets"]["cases"].as_array().expect("meets.cases");
    for c in cases {
        let offered = level_of(c["offered"].as_str().unwrap());
        let required = level_of(c["required"].as_str().unwrap());
        assert_eq!(
            meets_reporting_level(offered, required),
            c["meets"].as_bool().expect("meets"),
            "offered {} against required {}",
            offered.as_str(),
            required.as_str()
        );
    }
}

// ─── §5.12 the clause shape ─────────────────────────────────────────────────

#[test]
fn every_valid_reporting_clause_validates_and_round_trips_through_serde() {
    let f = fixture();
    for clause in f["clause"]["valid"].as_array().expect("clause.valid") {
        validate_sow_reporting(clause)
            .unwrap_or_else(|e| panic!("valid clause refused: {e}\n{clause:#}"));
        // The typed clause re-serializes to the same canonical bytes — the
        // clause sits inside the signed document, so serde may not add or drop
        // a member.
        let typed: SowReporting =
            serde_json::from_value(clause.clone()).expect("a valid clause deserializes");
        assert_eq!(
            agentmesh::canonical_json(&serde_json::to_value(&typed).unwrap()),
            agentmesh::canonical_json(clause),
            "the typed clause must re-serialize to the bytes it came from"
        );
    }
}

#[test]
fn every_invalid_reporting_clause_is_refused() {
    let f = fixture();
    for row in f["clause"]["invalid"].as_array().expect("clause.invalid") {
        let case = row["case"].as_str().unwrap();
        let why = row["why"].as_str().unwrap();
        assert!(
            validate_sow_reporting(&row["reporting"]).is_err(),
            "'{case}' must be refused — {why}"
        );
    }
}

// ─── §5.12 the cadence grammar ──────────────────────────────────────────────

#[test]
fn every_valid_cadence_yields_its_pinned_milliseconds() {
    let f = fixture();
    for row in f["every"]["valid"].as_array().expect("every.valid") {
        let value = row["value"].as_str().unwrap();
        assert_eq!(
            reporting_every_ms(value).unwrap_or_else(|e| panic!("'{value}' must parse: {e}")),
            row["ms"].as_u64().expect("ms"),
            "'{value}': both SDKs derive the same deadline from the same document"
        );
    }
}

#[test]
fn every_invalid_cadence_is_refused() {
    let f = fixture();
    for row in f["every"]["invalid"].as_array().expect("every.invalid") {
        let value = row["value"].as_str().unwrap();
        let why = row["why"].as_str().unwrap();
        assert!(
            reporting_every_ms(value).is_err(),
            "'{value}' must be refused — {why}"
        );
    }
}

// ─── §5.12 the shortfall sentence a mandate shows ───────────────────────────

#[test]
fn every_shortfall_case_reproduces_the_pinned_sentence_exactly() {
    let f = fixture();
    for c in f["shortfall"]["cases"].as_array().expect("shortfall.cases") {
        let name = c["name"].as_str().unwrap();
        let required = level_of(c["required"].as_str().unwrap());
        let got = reporting_shortfall(required, &c["document"]);
        match c["expected"].as_str() {
            // The wording is part of the fixture: a responder reads one
            // message whichever SDK evaluated it. String equality, not
            // contains.
            Some(sentence) => assert_eq!(
                got.as_deref(),
                Some(sentence),
                "'{name}': the sentence is pinned"
            ),
            None => assert_eq!(got, None, "'{name}': meets, so no shortfall"),
        }
    }
}

// ─── §5.12 cadence follows the money ────────────────────────────────────────

#[test]
fn the_cadence_warning_boundary_is_exact() {
    let f = fixture();
    for c in f["cadence_warning"]["cases"].as_array().expect("cadence_warning.cases") {
        let name = c["name"].as_str().unwrap();
        let clause: SowReporting =
            serde_json::from_value(c["reporting"].clone()).expect("the clause deserializes");
        let warning = reporting_cadence_warning(
            &clause,
            c["cap_remaining"].as_u64().expect("cap_remaining"),
            c["spend_per_day"].as_u64().expect("spend_per_day"),
        );
        // Only the boolean is pinned; the sentence is advisory prose, not
        // protocol.
        assert_eq!(
            warning.is_some(),
            c["warns"].as_bool().expect("warns"),
            "'{name}' (got {warning:?})"
        );
    }
}

// ─── §6 the clause sits inside the signed bytes ─────────────────────────────

#[test]
fn the_canonical_bytes_of_a_reporting_document_reproduce_exactly() {
    let f = fixture();
    assert_eq!(
        canonical_sow_json(&f["signing"]["document"]),
        f["signing"]["canonical"].as_str().expect("signing.canonical"),
        "one byte of canonical drift is a document that verifies in one SDK and is worthless \
         in the other"
    );
}
