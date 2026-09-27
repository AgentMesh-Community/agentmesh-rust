//! Agent SoW pricing arrangements (agentsow.com 0.9.0-draft §5.5), asserted
//! against `conformance/sow-pricing.json` — the same file
//! `sdk-typescript/__tests__/unit/sow-pricing-conformance.test.ts` reads.
//!
//! **The fixture is the authority.** When a case here fails, the fix is in
//! `src/sow.rs`, never in the JSON; a fixture changes only with a spec change
//! alongside. Cases are executed by ITERATING the fixture, so a row added to
//! the JSON runs here without this file changing.
//!
//! The load-bearing assertions are the cross-SDK byte ones. The §6.2
//! organization/mandate fields and the whole §5.5 price clause sit INSIDE the
//! signed bytes, so one byte of canonical drift is a document that verifies in
//! one SDK and is worthless in the other. Nothing here needs a broker, a
//! connection or a clock.

use serde_json::Value;

use agentmesh::{
    admit_settlement, canonical_sow_json, check_operator_fee, check_settlement, committed_price,
    directed_offer_refusal, is_directed_proposal,
    keypair_from_seed, load_sow_price, mandate_verified, max_rated_total_under_cap, operator_fee,
    operator_fee_amount,
    operator_fee_grade, pass_through_lines, provider_net, quote_with_operator_fee, rate_usage,
    rate_usage_with_operator_fee,
    refuse_further_work_under_operator, reservation_release_at, reservation_within_term,
    settlement_total, settlement_with_operator_fee, settles, sign_sow, sow_agreed,
    sow_signed_bytes, validate_operator_fee, validate_settlement_line, validate_sow_approval,
    qualification_grade_ceiling, qualification_refusal, required_assertions,
    validate_sow_offered_to, validate_sow_party, validate_sow_price, validate_sow_qualification,
    validate_sow_qualifications, verify_sow_signature, ApprovalAuthority,
    SowApprovalAct, SowApprovalRecord, SowCap, SowDocumentState, SowMeteredCount,
    SowOperatorFee, SowOperatorFeeBasis, SowPrice, SowQuote, SowScheduleLine, SowSettlementRecord,
    SowQualificationFacts, SowSignature, APPROVAL_AUTHORITIES, CHECKABLE_QUALIFICATION_KINDS,
    DEFAULT_AMENDMENT_AUTHORITY, DEFAULT_FORMATION_AUTHORITY, SOW_QUALIFICATION_KINDS,
    OPERATOR_FEE_BASIS_GRADE, PRICING_ARRANGEMENTS, SOW_END_STATES, SOW_SIG_PREFIX,
};

static FIXTURE_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/conformance/sow-pricing.json"
));

fn fixture() -> Value {
    serde_json::from_str(FIXTURE_JSON).expect("conformance/sow-pricing.json parses")
}

fn strs(v: &Value) -> Vec<String> {
    v.as_array()
        .expect("array")
        .iter()
        .map(|s| s.as_str().expect("string").to_string())
        .collect()
}

// ─── §5.5 the arrangement ───────────────────────────────────────────────────

#[test]
fn the_arrangement_set_is_closed_and_matches_the_fixture() {
    let f = fixture();
    let mut want = strs(&f["arrangement"]["values"]);
    want.sort();
    let mut got: Vec<String> = PRICING_ARRANGEMENTS.iter().map(|s| s.to_string()).collect();
    got.sort();
    assert_eq!(got, want);
}

#[test]
fn every_valid_price_clause_validates_and_loads() {
    let f = fixture();
    for price in f["price"]["valid"].as_array().expect("price.valid") {
        validate_sow_price(price)
            .unwrap_or_else(|e| panic!("valid clause refused: {e}\n{price:#}"));
        let loaded = load_sow_price(price).expect("a valid clause loads into the typed enum");
        // Round-trip: the typed clause re-serializes to the same canonical bytes.
        assert_eq!(
            agentmesh::canonical_json(&serde_json::to_value(&loaded).unwrap()),
            agentmesh::canonical_json(price),
            "the typed clause must re-serialize to the bytes it came from"
        );
    }
}

#[test]
fn every_invalid_price_clause_is_refused() {
    let f = fixture();
    for row in f["price"]["invalid"].as_array().expect("price.invalid") {
        let case = row["case"].as_str().unwrap();
        let why = row["why"].as_str().unwrap();
        assert!(
            validate_sow_price(&row["price"]).is_err(),
            "'{case}' must be refused — {why}"
        );
        assert!(load_sow_price(&row["price"]).is_err(), "'{case}' must not load");
    }
}

// ─── §5.5.3 the cap ─────────────────────────────────────────────────────────

#[test]
fn an_uncapped_time_and_materials_price_cannot_be_represented() {
    // The type-level half: `SowPrice::TimeAndMaterials.cap` is a `SowCap`, not
    // an `Option<SowCap>`, so serde has nothing to fill in and the whole clause
    // fails to deserialize. There is no constructor that omits it either — the
    // only way to build one takes `cap` positionally.
    let uncapped = serde_json::json!({
        "arrangement": "time_and_materials",
        "currency": "XCR",
        "schedule": [{"meter": "tokens_out", "unit": "1000 tokens", "per_unit": 1500}],
        "reservation": {"window_days": 30},
        "grade": "enforced"
    });
    assert!(serde_json::from_value::<SowPrice>(uncapped.clone()).is_err());
    let err = validate_sow_price(&uncapped).unwrap_err().to_string();
    assert!(err.contains("not-to-exceed cap"), "{err}");
}

#[test]
fn an_unreserved_time_and_materials_price_cannot_be_represented() {
    // §5.5.4 gets the same treatment as the cap: `reservation` is a
    // `SowReservation`, not an `Option<SowReservation>`, so serde has nothing to
    // fill in. The constructor takes it positionally for the same reason.
    let unreserved = serde_json::json!({
        "arrangement": "time_and_materials",
        "currency": "XCR",
        "schedule": [{"meter": "tokens_out", "unit": "1000 tokens", "per": 1000, "per_unit": 1500}],
        "cap": {"amount": 40_000_000},
        "grade": "enforced"
    });
    assert!(serde_json::from_value::<SowPrice>(unreserved.clone()).is_err());
    let err = validate_sow_price(&unreserved).unwrap_err().to_string();
    assert!(err.contains("no defined settlement behaviour"), "{err}");
}

// ─── §5.5.2 the divisor: the cross-SDK arithmetic contract ──────────────────

#[test]
fn the_divisor_floors_identically_to_typescript() {
    let f = fixture();
    // Every settlement line the fixture pins must recompute from its own
    // count/per/per_unit — that recomputation IS the buyer's protection, and it
    // has to give the same answer in both languages.
    for row in f["rating"]["cases"].as_array().unwrap() {
        for line in row["expect"]["lines"].as_array().unwrap() {
            let count = line["count"].as_u64().unwrap();
            let per = line["per"].as_u64().unwrap();
            let per_unit = line["per_unit"].as_u64().unwrap();
            let amount = line["amount"].as_u64().unwrap();
            let gross = (count as u128 * per_unit as u128 / per as u128) as u64;
            // `amount` may be clamped by the cap, never above the gross rate.
            assert!(amount <= gross, "a line may clamp at the cap, never exceed its rate");
            if !row["expect"]["exhausted"].as_bool().unwrap() {
                assert_eq!(amount, gross, "an unclamped line is exactly floor(count*per_unit/per)");
            }
        }
    }
}

#[test]
fn the_floor_favours_the_buyer_and_the_label_is_never_parsed() {
    let line = SowScheduleLine::per("tokens_out", "1000 tokens", 1000, 1500);
    assert_eq!(line.rate(2000).unwrap(), 3000);
    assert_eq!(line.rate(2999).unwrap(), 4498); // 4498.5 floors; the half unit is free
    assert_eq!(SowScheduleLine::new("tool_calls", "call", 2000).divisor(), 1);
    // A label contradicting the divisor changes no arithmetic (§5.5.2).
    let lying = SowScheduleLine::per("tokens_out", "1 token", 1000, 1500);
    assert_eq!(lying.rate(1000).unwrap(), 1500);
}

#[test]
fn the_committed_price_of_time_and_materials_is_the_cap() {
    let f = fixture();
    for price in f["price"]["valid"].as_array().unwrap() {
        let loaded = load_sow_price(price).unwrap();
        match &loaded {
            SowPrice::TimeAndMaterials { cap, .. } => {
                assert_eq!(committed_price(&loaded), Some(cap.amount));
            }
            SowPrice::FixedFee { ceiling, .. } => {
                assert_eq!(committed_price(&loaded), ceiling.as_ref().map(|c| c.amount));
            }
            // §5.5.7: zero, and any ceiling covers it. Not `None` — a no-charge
            // engagement commits to a figure, and the figure is nothing.
            SowPrice::NoCharge { .. } => assert_eq!(committed_price(&loaded), Some(0)),
        }
    }
}

// ─── §5.5.7 no charge ───────────────────────────────────────────────────────

#[test]
fn a_no_charge_clause_carrying_a_price_field_cannot_be_loaded() {
    let f = fixture();
    let clause = &f["no_charge"]["clause"];
    validate_sow_price(clause).expect("the clause §5.5.7 writes is valid");
    let loaded = load_sow_price(clause).expect("and it loads");
    assert!(matches!(loaded, SowPrice::NoCharge { .. }));

    // The type-level half: the variant has one field, `grade`, so there is no
    // slot to put a price into. The deserializing half is `load_sow_price`, not
    // serde — an internally tagged enum ignores unrecognized members, so a bare
    // `from_value` would take this document and quietly drop the currency,
    // which is the outcome §5.5.7 refuses. The assertion below is deliberately
    // written both ways so the difference cannot be forgotten.
    for field in ["currency", "rates", "schedule", "cap", "reservation", "ceiling", "minimum"] {
        let mut carrying = clause.clone();
        carrying[field] = serde_json::json!({});
        let err = validate_sow_price(&carrying).unwrap_err().to_string();
        assert!(err.contains(&format!("MUST NOT carry '{field}'")), "{field}: {err}");
        assert!(load_sow_price(&carrying).is_err(), "{field} must not load");
        assert!(
            serde_json::from_value::<SowPrice>(carrying).is_ok(),
            "{field}: serde alone accepts this, which is exactly why load_sow_price validates first"
        );
    }
}

#[test]
fn nothing_settles_under_a_no_charge_engagement() {
    let f = fixture();
    let nc = &f["no_charge"];
    let price = load_sow_price(&nc["clause"]).unwrap();

    assert_eq!(settles(&price), nc["settles"].as_bool().unwrap());
    for other in f["price"]["valid"].as_array().unwrap() {
        let loaded = load_sow_price(other).unwrap();
        assert_eq!(settles(&loaded), !loaded.is_no_charge());
    }

    // §5.5.7: a runtime MUST NOT rate work under it. Counts are refused, not
    // rated to zero.
    let err = rate_usage(&price, &usage_of(&nc["refuses_rating"]["usage"]), 0, &[])
        .unwrap_err()
        .to_string();
    assert!(err.contains("MUST NOT rate work under it"), "{err}");

    // §5.5.7: a client node MUST refuse a settlement record that cites one.
    // The record's lines are well formed, which is the point — the refusal is
    // about the engagement the record cites, not about the record's shape.
    for line in nc["refuses_settlement_record"]["record"]["lines"].as_array().unwrap() {
        validate_settlement_line(line).expect("the lines themselves are well formed");
    }
    let err = admit_settlement(&price, "file a settlement record for").unwrap_err().to_string();
    assert!(err.contains("file a settlement record for it"), "{err}");
    assert!(admit_settlement(&price, "draw from the client's balance for").is_err());

    // The other two arrangements admit one.
    for other in f["price"]["valid"].as_array().unwrap() {
        let loaded = load_sow_price(other).unwrap();
        if loaded.is_no_charge() {
            continue;
        }
        assert!(admit_settlement(&loaded, "settle").is_ok());
    }

    // No currency, because nothing settles in one.
    assert_eq!(price.currency(), None);
    assert!(pass_through_lines(&price).is_empty());
}

#[test]
fn a_no_charge_document_is_ordinary_and_its_bytes_match_typescript() {
    let f = fixture();
    let nc = &f["no_charge"];
    let canonical = nc["canonical"].as_str().unwrap();
    assert_eq!(
        canonical_sow_json(&nc["document"]),
        canonical,
        "the price clause is inside the signed bytes: an SDK that writes a currency into a \
         no_charge clause produces a document the other SDK will not verify"
    );
    assert_eq!(canonical_sow_json(&nc["signed"]), canonical);

    let record: SowSignature =
        serde_json::from_value(nc["signed"]["signatures"][0].clone()).expect("a signature record");
    assert!(
        verify_sow_signature(&nc["signed"], &record),
        "a TypeScript-signed no-charge engagement must verify in Rust"
    );

    let kp = keypair_from_seed(f["identities"]["sender_seed"].as_str().unwrap()).unwrap();
    let mut doc = nc["document"].clone();
    sign_sow(&mut doc, &kp, &record.role, &record.signed_at).unwrap();
    assert_eq!(doc["signatures"][0]["sig"].as_str().unwrap(), record.sig);
}

// ─── §5.5.2 rating, §5.5.3 stopping at the cap ──────────────────────────────

fn usage_of(v: &Value) -> Vec<SowMeteredCount> {
    v.as_array()
        .expect("usage array")
        .iter()
        .map(|u| {
            SowMeteredCount::new(
                u["meter"].as_str().expect("meter"),
                u["count"].as_u64().expect("count"),
            )
        })
        .collect()
}

fn receipts_of(v: Option<&Value>) -> Vec<(String, String)> {
    let Some(map) = v.and_then(Value::as_object) else { return Vec::new() };
    map.iter().map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string())).collect()
}

#[test]
fn every_rating_case_reproduces() {
    let f = fixture();
    for row in f["rating"]["cases"].as_array().expect("rating.cases") {
        let case = row["case"].as_str().unwrap();
        let price = load_sow_price(&row["price"]).expect("the case's price clause is valid");
        // §5.5.8's cut, where the row puts one in the path. Absent is the
        // peer-to-peer case, where every number below means what it always meant.
        let fee_basis: Option<SowOperatorFeeBasis> = row
            .get("operator_fee_basis")
            .map(|b| serde_json::from_value(b.clone()).expect("operator_fee_basis"));
        let already_billed = row["already_billed"].as_u64().unwrap_or(0);
        let rated = rate_usage_with_operator_fee(
            &price,
            &usage_of(&row["usage"]),
            already_billed,
            &receipts_of(row.get("receipts")),
            fee_basis,
            row.get("operator").and_then(Value::as_str),
        )
        .unwrap_or_else(|e| panic!("'{case}' must rate: {e}"));

        let want = &row["expect"];
        assert_eq!(rated.total, want["total"].as_u64().unwrap(), "{case}: total");
        assert_eq!(
            rated.client_total,
            want["client_total"].as_u64().unwrap(),
            "{case}: client_total"
        );
        assert_eq!(
            rated.cap_remaining,
            want["cap_remaining"].as_u64().unwrap(),
            "{case}: cap_remaining"
        );
        assert_eq!(rated.exhausted, want["exhausted"].as_bool().unwrap(), "{case}: exhausted");
        assert_eq!(rated.unbilled, want["unbilled"].as_u64().unwrap(), "{case}: unbilled");
        // §5.5.8: the fee line the rating took, and its absence where none was
        // taken. Absence is an assertion, so it is asserted rather than skipped.
        let want_fee: Option<SowOperatorFee> = want
            .get("operator_fee")
            .map(|v| serde_json::from_value(v.clone()).expect("operator_fee"));
        assert_eq!(rated.operator_fee, want_fee, "{case}: operator_fee");
        // The invariant every one of these rows has to satisfy, whether or not
        // an operator stands in the path: what the client pays over the
        // engagement never exceeds the cap (§5.5.3).
        let cap = row["price"]["cap"]["amount"].as_u64().unwrap();
        assert!(already_billed + rated.client_total <= cap, "{case}: past the cap");
        assert_eq!(
            rated.client_total,
            rated.total + rated.operator_fee.as_ref().map_or(0, |f| f.amount),
            "{case}: the client pays the lines plus the fee"
        );
        assert_eq!(
            rated.cap_remaining,
            cap - already_billed - rated.client_total,
            "{case}: cap_remaining is remaining client exposure"
        );
        // The settlement lines are the wire shape the two SDKs must agree on,
        // so they are compared as canonical JSON rather than field by field.
        assert_eq!(
            agentmesh::canonical_json(&serde_json::to_value(&rated.lines).unwrap()),
            agentmesh::canonical_json(&want["lines"]),
            "{case}: settlement lines"
        );
    }
}

#[test]
fn every_rating_refusal_is_refused() {
    let f = fixture();
    for row in f["rating"]["refuses"].as_array().expect("rating.refuses") {
        let case = row["case"].as_str().unwrap();
        let why = row["why"].as_str().unwrap();
        let price = load_sow_price(&row["price"]).unwrap();
        assert!(
            rate_usage(&price, &usage_of(&row["usage"]), 0, &[]).is_err(),
            "'{case}' must be refused — {why}"
        );
    }
}

#[test]
fn what_the_cap_clamps_away_is_never_re_billed() {
    let f = fixture();
    let price = load_sow_price(&f["rating"]["cases"][2]["price"]).unwrap();
    let first = rate_usage(&price, &[SowMeteredCount::new("tool_calls", 8)], 0, &[]).unwrap();
    assert!(first.exhausted);
    let second =
        rate_usage(&price, &[SowMeteredCount::new("tool_calls", 8)], first.total, &[]).unwrap();
    assert_eq!(second.total, 0);
    assert_eq!(second.unbilled, 8000);
}

#[test]
fn a_schedule_may_not_price_a_meter_the_offering_does_not_declare() {
    let price = SowPrice::time_and_materials(
        "XCR",
        vec![
            SowScheduleLine::per("tokens_out", "1000 tokens", 1000, 1500),
            SowScheduleLine::per("elapsed", "minute", 60, 12000),
        ],
        SowCap::new(1_000_000),
        agentmesh::SowReservation::new(30),
    )
    .unwrap();
    assert!(agentmesh::validate_schedule_against_meters(&price, &["tokens_out", "elapsed"]).is_ok());
    let err = agentmesh::validate_schedule_against_meters(&price, &["tokens_out"])
        .unwrap_err()
        .to_string();
    assert!(err.contains("elapsed"), "{err}");
}

// ─── §5.5.6 pass-through ────────────────────────────────────────────────────

#[test]
fn settlement_lines_follow_the_pass_through_rules() {
    let f = fixture();
    for line in f["settlement_line"]["valid"].as_array().unwrap() {
        validate_settlement_line(line).unwrap_or_else(|e| panic!("valid line refused: {e}"));
    }
    for row in f["settlement_line"]["invalid"].as_array().unwrap() {
        let case = row["case"].as_str().unwrap();
        let why = row["why"].as_str().unwrap();
        assert!(
            validate_settlement_line(&row["line"]).is_err(),
            "'{case}' must be refused — {why}"
        );
    }
}

// ─── §5.5.4 the reservation window ──────────────────────────────────────────

#[test]
fn the_reservation_window_arithmetic_matches_typescript() {
    let f = fixture();
    for c in f["reservation"]["cases"].as_array().expect("reservation.cases") {
        let window = agentmesh::SowReservation::new(c["window_days"].as_u64().unwrap());
        let starts_at = c["starts_at"].as_str().unwrap();
        assert_eq!(
            reservation_release_at(&window, starts_at).unwrap(),
            c["release_at"].as_str().unwrap(),
            "release instant for {starts_at}"
        );
        assert_eq!(
            reservation_within_term(&window, starts_at, c["ends_at"].as_str().unwrap()),
            c["within_term"].as_bool().unwrap(),
            "window within term for {starts_at}"
        );
    }
}

// ─── §7.1 document states, §5.5.5 exhausted ─────────────────────────────────

fn state_of(s: &str) -> SowDocumentState {
    serde_json::from_value(Value::String(s.to_string())).expect("a known document state")
}

#[test]
fn exhausted_ends_the_engagement_and_is_not_a_failure() {
    let f = fixture();
    let mut want = strs(&f["document_states"]["end_states"]);
    want.sort();
    let mut got: Vec<String> = SOW_END_STATES.iter().map(|s| s.to_string()).collect();
    got.sort();
    assert_eq!(got, want);

    let admits = strs(&f["document_states"]["admits_work"]);
    let unscored = strs(&f["document_states"]["unscored"]);
    for name in strs(&f["document_states"]["all"]) {
        let state = state_of(&name);
        assert_eq!(state.as_str(), name, "the wire string round-trips");
        assert_eq!(state.admits_work(), admits.contains(&name), "{name}: admits_work");
        assert_eq!(state.is_scored_outcome(), !unscored.contains(&name), "{name}: scored");
        assert_eq!(state.is_end_state(), SOW_END_STATES.contains(&name.as_str()), "{name}: ends");
    }

    // §7.1: lapse, exhaustion and termination are identical at the gate.
    for name in strs(&f["document_states"]["end_states"]) {
        assert!(!state_of(&name).admits_work(), "{name} must not admit work");
    }
}

#[test]
fn the_exhausted_document_state_round_trips_through_json() {
    let encoded = serde_json::to_value(SowDocumentState::Exhausted).unwrap();
    assert_eq!(encoded, Value::String("exhausted".into()));
    let back: SowDocumentState = serde_json::from_value(encoded).unwrap();
    assert_eq!(back, SowDocumentState::Exhausted);
    assert!(!back.is_scored_outcome());
}

#[test]
fn exhausted_is_a_terminal_task_state_and_not_a_failure() {
    let f = fixture();
    let t = &f["task_state"];
    let state = t["state"].as_str().unwrap();
    assert_eq!(
        agentmesh::is_terminal_task_state(state),
        t["terminal"].as_bool().unwrap(),
        "exhausted is terminal (§5.5.5)"
    );
    assert!(!t["is_failure"].as_bool().unwrap());
    assert!(agentmesh::TERMINAL_TASK_STATES.contains(&state));
    // Not `failed`, and never recorded as it.
    assert_ne!(state, "failed");
    for from in strs(&t["reachable_from"]) {
        assert!(
            !agentmesh::is_terminal_task_state(&from),
            "{from} must still be in flight for the cap to catch it"
        );
    }
}

// ─── §5.1 + §6.1 + §6.2 ─────────────────────────────────────────────────────

#[test]
fn parties_carry_the_optional_organization_reference() {
    let f = fixture();
    for party in f["party"]["valid"].as_array().unwrap() {
        validate_sow_party(party).unwrap_or_else(|e| panic!("valid party refused: {e}"));
    }
    for row in f["party"]["invalid"].as_array().unwrap() {
        let case = row["case"].as_str().unwrap();
        let why = row["why"].as_str().unwrap();
        assert!(validate_sow_party(&row["party"]).is_err(), "'{case}' must be refused — {why}");
    }
}

// ─── §12.1.1 the named counterparty ─────────────────────────────────────────

#[test]
fn the_offered_to_clause_names_exactly_one_party_and_says_when_it_ends() {
    let f = fixture();
    for clause in f["directed"]["clause"]["valid"].as_array().unwrap() {
        validate_sow_offered_to(clause)
            .unwrap_or_else(|e| panic!("valid offered_to refused: {e}"));
    }
    for row in f["directed"]["clause"]["invalid"].as_array().unwrap() {
        let case = row["case"].as_str().unwrap();
        let why = row["why"].as_str().unwrap();
        assert!(
            validate_sow_offered_to(&row["offered_to"]).is_err(),
            "'{case}' must be refused — {why}"
        );
    }
}

#[test]
fn a_directed_proposal_yields_no_public_listing() {
    let f = fixture();
    for c in f["directed"]["listing"]["cases"].as_array().unwrap() {
        let case = c["case"].as_str().unwrap();
        let doc = serde_json::json!({ "parties": c["parties"] });
        assert_eq!(
            is_directed_proposal(&doc),
            c["directed"].as_bool().unwrap(),
            "'{case}' directedness"
        );
        // The listing rule is the predicate's whole purpose: a surface reads
        // directedness off the offer rather than interpreting prose.
        assert_eq!(
            !is_directed_proposal(&doc),
            c["public_listing"].as_bool().unwrap(),
            "'{case}' public listing"
        );
    }
}

#[test]
fn only_the_named_party_forms_and_only_before_the_offer_lapses() {
    let f = fixture();
    for c in f["directed"]["formation"]["cases"].as_array().unwrap() {
        let case = c["case"].as_str().unwrap();
        let why = c["why"].as_str().unwrap();
        let doc = serde_json::json!({
            "parties": { "provider": {}, "client": Value::Null, "offered_to": c["offered_to"] }
        });
        let now_ms = chrono::DateTime::parse_from_rfc3339(c["now"].as_str().unwrap())
            .expect("the fixture's `now` is an RFC-3339 instant")
            .timestamp_millis();
        let refusal = directed_offer_refusal(&doc, c["client_agent"].as_str().unwrap(), now_ms);
        assert_eq!(refusal.is_none(), c["forms"].as_bool().unwrap(), "'{case}' — {why}");
        // A refusal names the restriction rather than shrugging: the
        // counterparty acted on a document it was handed.
        if let Some(reason) = refusal {
            assert!(reason.contains("§12.1.1"), "'{case}' refusal must name the rule: {reason}");
        }
    }
}

#[test]
fn the_named_counterparty_sits_inside_the_signed_bytes() {
    let f = fixture();
    let canonical = canonical_sow_json(&f["directed"]["signing"]["document"]);
    assert_eq!(canonical, f["directed"]["signing"]["canonical"].as_str().unwrap());
    // Naming a counterparty does not fill the client seat. Formation stays the
    // two-step gate: a countersign is a request to form.
    assert!(canonical.contains("\"client\":null"));
    assert!(canonical.contains("\"starts_at\":null"));
    // And the restriction is INSIDE those bytes, not laid over them.
    assert!(canonical.contains("\"offered_to\""));
}

// ─── §12.1 qualifications ───────────────────────────────────────────────────

#[test]
fn the_qualification_vocabulary_is_closed_and_each_kind_claims_only_what_it_can() {
    let f = fixture();
    let mut all = SOW_QUALIFICATION_KINDS.to_vec();
    all.sort_unstable();
    let mut want = strs(&f["qualifications"]["kinds"]["all"]);
    want.sort();
    assert_eq!(all, want);

    let mut checkable = CHECKABLE_QUALIFICATION_KINDS.to_vec();
    checkable.sort_unstable();
    let mut want_checkable = strs(&f["qualifications"]["kinds"]["checkable"]);
    want_checkable.sort();
    assert_eq!(checkable, want_checkable);

    for (kind, ceiling) in f["qualifications"]["kinds"]["grade_ceiling"].as_object().unwrap() {
        let got = serde_json::to_value(qualification_grade_ceiling(kind)).unwrap();
        assert_eq!(got.as_str().unwrap(), ceiling.as_str().unwrap(), "{kind} grade ceiling");
    }
}

#[test]
fn a_qualification_states_its_condition_and_carries_the_grade_it_has_earned() {
    let f = fixture();
    for q in f["qualifications"]["clause"]["valid"].as_array().unwrap() {
        validate_sow_qualification(q).unwrap_or_else(|e| panic!("valid qualification refused: {e}"));
    }
    for row in f["qualifications"]["clause"]["invalid"].as_array().unwrap() {
        let case = row["case"].as_str().unwrap();
        let why = row["why"].as_str().unwrap();
        assert!(
            validate_sow_qualification(&row["qualification"]).is_err(),
            "'{case}' must be refused — {why}"
        );
    }
    for list in f["qualifications"]["list"]["valid"].as_array().unwrap() {
        validate_sow_qualifications(list).unwrap_or_else(|e| panic!("valid clause refused: {e}"));
    }
    for row in f["qualifications"]["list"]["invalid"].as_array().unwrap() {
        let case = row["case"].as_str().unwrap();
        let why = row["why"].as_str().unwrap();
        assert!(
            validate_sow_qualifications(&row["qualifications"]).is_err(),
            "'{case}' must be refused — {why}"
        );
    }
}

#[test]
fn formation_completes_for_a_party_that_meets_the_conditions_and_refuses_one_that_does_not() {
    let f = fixture();
    for c in f["qualifications"]["formation"]["cases"].as_array().unwrap() {
        let case = c["case"].as_str().unwrap();
        let why = c["why"].as_str().unwrap();
        let doc = if c["qualifications"].is_null() {
            serde_json::json!({})
        } else {
            serde_json::json!({ "qualifications": c["qualifications"] })
        };
        let asserted: Vec<String> = strs(&c["asserted"]);
        let facts = c["facts"].as_object().map(|o| SowQualificationFacts {
            subject: o["subject"].as_str().unwrap_or_default().to_string(),
            registered: o.get("registered").and_then(Value::as_bool),
            offerings: o
                .get("offerings")
                .and_then(Value::as_array)
                .map(|l| l.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()),
            account: o.get("account").and_then(Value::as_bool),
        });
        let refusal = qualification_refusal(
            &doc,
            c["client_agent"].as_str().unwrap(),
            &asserted,
            facts.as_ref(),
        );
        assert_eq!(
            refusal.is_none(),
            c["forms"].as_bool().unwrap(),
            "'{case}' — {why} (got {refusal:?})"
        );
        // Rule 2: the refusal NAMES the unmet condition. A counterparty that
        // read a published offer and acted on it is owed the reason.
        if let Some(reason) = refusal {
            assert!(reason.contains("§12.1"), "'{case}' refusal must name the rule: {reason}");
        }
    }
}

#[test]
fn the_conditions_sit_inside_the_signed_bytes() {
    let f = fixture();
    let canonical = canonical_sow_json(&f["qualifications"]["signing"]["document"]);
    assert_eq!(canonical, f["qualifications"]["signing"]["canonical"].as_str().unwrap());
    // The whole of rule 1: the conditions are in the document the buyer reads
    // and the seller signed, not in a policy laid over it afterwards.
    assert!(canonical.contains("\"qualifications\""));
    // Both grades in one clause, singly graded (§4.2).
    assert!(canonical.contains("\"grade\":\"enforced\",\"id\":\"mesh-registered\""));
    assert!(canonical.contains("\"grade\":\"evidence\",\"id\":\"salesforce-licence\""));
    // And the assertion list a countersign must carry is derived from them.
    assert_eq!(
        required_assertions(&f["qualifications"]["signing"]["document"]),
        vec!["salesforce-licence".to_string()]
    );
}

#[test]
fn approvals_carry_the_authority_and_the_optional_mandate() {
    let f = fixture();
    let mut want = strs(&f["approval"]["authorities"]);
    want.sort();
    let mut got: Vec<String> = APPROVAL_AUTHORITIES.iter().map(|s| s.to_string()).collect();
    got.sort();
    assert_eq!(got, want);

    assert_eq!(
        serde_json::to_value(DEFAULT_FORMATION_AUTHORITY).unwrap(),
        f["approval"]["defaults"]["formation"]
    );
    assert_eq!(
        serde_json::to_value(DEFAULT_AMENDMENT_AUTHORITY).unwrap(),
        f["approval"]["defaults"]["amendment"]
    );

    for approval in f["approval"]["valid"].as_array().unwrap() {
        validate_sow_approval(approval).unwrap_or_else(|e| panic!("valid approval refused: {e}"));
        serde_json::from_value::<SowApprovalRecord>(approval.clone())
            .expect("a valid approval deserializes");
    }
    for row in f["approval"]["invalid"].as_array().unwrap() {
        let case = row["case"].as_str().unwrap();
        let why = row["why"].as_str().unwrap();
        assert!(
            validate_sow_approval(&row["approval"]).is_err(),
            "'{case}' must be refused — {why}"
        );
    }
}

#[test]
fn mandate_verified_is_false_wherever_the_checks_did_not_run() {
    let f = fixture();
    for c in f["approval"]["mandate_verified"]["cases"].as_array().unwrap() {
        let approval = SowApprovalRecord {
            act: SowApprovalAct::Amendment,
            authority: ApprovalAuthority::Person,
            key: f["identities"]["sender"].as_str().unwrap().to_string(),
            approved_at: "2026-08-06T09:14:02Z".to_string(),
            mandate: c["mandate"].as_str().map(str::to_string),
        };
        assert_eq!(
            mandate_verified(&approval, c["checks_performed"].as_bool().unwrap()),
            c["expect"].as_bool().unwrap(),
        );
    }
}

// ─── §6 canonicalization and signing: the cross-SDK byte contract ───────────

#[test]
fn the_typescript_canonical_bytes_reproduce_here_exactly() {
    let f = fixture();
    assert_eq!(f["signing"]["signed_bytes_prefix"].as_str().unwrap(), SOW_SIG_PREFIX);

    let document = &f["signing"]["document"];
    let canonical = f["signing"]["canonical"].as_str().unwrap();
    assert_eq!(
        canonical_sow_json(document),
        canonical,
        "one byte of drift here is a document that verifies in one SDK and not the other"
    );

    // The signatures array is outside the signed bytes (§6).
    assert_eq!(canonical_sow_json(&f["signing"]["signed"]), canonical);

    assert_eq!(
        String::from_utf8(sow_signed_bytes(document)).unwrap(),
        format!("{SOW_SIG_PREFIX}{canonical}")
    );
}

#[test]
fn the_typescript_signature_verifies_here() {
    let f = fixture();
    let signed = &f["signing"]["signed"];
    let record: SowSignature =
        serde_json::from_value(signed["signatures"][0].clone()).expect("a signature record");
    assert_eq!(record.key, f["identities"]["sender"].as_str().unwrap());
    assert_eq!(record.role, "provider");
    assert!(
        verify_sow_signature(signed, &record),
        "a TypeScript-signed Agent SoW document must verify in Rust"
    );
}

#[test]
fn re_signing_the_pinned_document_reproduces_the_pinned_signature() {
    let f = fixture();
    let kp = keypair_from_seed(f["identities"]["sender_seed"].as_str().unwrap()).unwrap();
    let mut doc = f["signing"]["document"].clone();
    let pinned = &f["signing"]["signed"]["signatures"][0];
    sign_sow(&mut doc, &kp, "provider", pinned["signed_at"].as_str().unwrap()).unwrap();
    assert_eq!(
        doc["signatures"][0]["sig"].as_str().unwrap(),
        pinned["sig"].as_str().unwrap(),
        "identical canonical bytes plus the same key must give identical signature bytes"
    );
}

#[test]
fn tampering_with_any_signed_field_breaks_the_signature() {
    let f = fixture();
    for path in strs(&f["signing"]["tamper"]["fields"]) {
        let mut doc = f["signing"]["signed"].clone();
        let record: SowSignature =
            serde_json::from_value(doc["signatures"][0].clone()).expect("a signature record");

        // Walk `a.b[0].c` down to the leaf and move it by one.
        let parts: Vec<String> = path
            .replace('[', ".")
            .replace(']', "")
            .split('.')
            .map(str::to_string)
            .collect();
        let mut node = &mut doc;
        for p in &parts[..parts.len() - 1] {
            node = match p.parse::<usize>() {
                Ok(i) => &mut node[i],
                Err(_) => &mut node[p.as_str()],
            };
        }
        let leaf = &parts[parts.len() - 1];
        let slot = match leaf.parse::<usize>() {
            Ok(i) => &mut node[i],
            Err(_) => &mut node[leaf.as_str()],
        };
        *slot = match slot {
            Value::Number(n) => Value::from(n.as_u64().unwrap_or(0) + 1),
            Value::String(s) => Value::String(format!("{s}x")),
            other => panic!("unhandled tamper target at {path}: {other}"),
        };

        assert!(
            !verify_sow_signature(&doc, &record),
            "moving {path} must break the signature — the §6.2 fields exist precisely so they \
             cannot be altered after signing"
        );
    }
}

#[test]
fn agreed_means_both_roles_verified_over_the_same_bytes() {
    let f = fixture();
    // The second seat needs a second key, which the repository deliberately does
    // not publish, so it is generated here rather than pinned.
    let provider = keypair_from_seed(f["identities"]["sender_seed"].as_str().unwrap()).unwrap();
    let (_, client_seed) = agentmesh::create_agent_identity().unwrap();
    let client = keypair_from_seed(&client_seed).unwrap();

    let mut doc = f["signing"]["document"].clone();
    sign_sow(&mut doc, &provider, "provider", "2026-08-04T14:02:11Z").unwrap();
    assert!(!sow_agreed(&doc), "one signature, whoever signed it, has no force (§7.1)");

    sign_sow(&mut doc, &client, "client", "2026-08-04T16:47:36Z").unwrap();
    assert!(sow_agreed(&doc));

    // §6: "over the same canonical bytes". Moving the cap after the fact
    // invalidates both signatures, because both cover the price clause.
    doc["price"]["cap"]["amount"] = Value::from(40_000_001u64);
    assert!(!sow_agreed(&doc));
}

// ─── §5.5.8 the operator fee ────────────────────────────────────────────────

fn fee_of(v: &Value) -> SowOperatorFee {
    serde_json::from_value(v.clone()).expect("the fixture's fee line deserializes")
}

#[test]
fn every_valid_operator_fee_line_validates() {
    let f = fixture();
    for row in f["operator_fee"]["valid"].as_array().expect("array") {
        assert!(
            validate_operator_fee(&row["fee"]).is_ok(),
            "{} must validate",
            row["case"]
        );
        // Since 0.9.0-draft every line the fixture calls valid also CLOSES: the
        // check is exact, so there is no longer a conformant line whose amount
        // is near its basis rather than equal to it. A shape-valid line that
        // does not close now lives in `arithmetic` with `closes: false`.
        assert!(
            check_operator_fee(&fee_of(&row["fee"])).is_ok(),
            "{} must close exactly",
            row["case"]
        );
    }
}

#[test]
fn every_invalid_operator_fee_line_is_refused() {
    let f = fixture();
    for row in f["operator_fee"]["invalid"].as_array().expect("array") {
        assert!(
            validate_operator_fee(&row["fee"]).is_err(),
            "{} must be refused — {}",
            row["case"],
            row["why"]
        );
    }
}

#[test]
fn the_base_is_required_and_a_client_node_must_not_infer_it() {
    // The reason the member exists: ten percent of the provider's price and ten
    // percent of the buyer's total are different numbers from the same
    // percentage.
    let line = serde_json::json!({ "basis": { "kind": "percent", "percent": 10 }, "amount": 250000 });
    let err = validate_operator_fee(&line).expect_err("a fee with no base is refused");
    assert!(err.to_string().contains("MUST NOT infer the base"));
}

#[test]
fn the_specifications_own_worked_example() {
    let f = fixture();
    let spec = fee_of(&f["operator_fee"]["valid"][0]["fee"]);
    assert_eq!(spec.base, 2_500_000);
    assert_eq!(spec.amount, 250_000);
    assert_eq!(
        operator_fee_amount(&spec.basis, spec.base).unwrap(),
        250_000
    );
    assert!(check_operator_fee(&spec).is_ok());
}

#[test]
fn the_arithmetic_closes_or_it_does_not() {
    let f = fixture();
    for row in f["operator_fee"]["arithmetic"]["cases"].as_array().expect("array") {
        let fee = fee_of(&row["fee"]);
        let closes = row["closes"].as_bool().expect("bool");
        assert_eq!(
            check_operator_fee(&fee).is_ok(),
            closes,
            "{}",
            row["case"]
        );
    }
}

#[test]
fn a_basis_applied_to_a_base_floors_and_there_is_no_other_answer() {
    let f = fixture();
    for row in f["operator_fee"]["computed"]["cases"].as_array().expect("array") {
        let basis: SowOperatorFeeBasis =
            serde_json::from_value(row["basis"].clone()).expect("basis");
        let base = row["base"].as_u64().expect("base");
        assert_eq!(
            operator_fee_amount(&basis, base).unwrap(),
            row["amount"].as_u64().expect("expected amount"),
            "{basis:?} on {base} floors"
        );
    }
}

#[test]
fn the_one_whole_unit_tolerance_is_withdrawn() {
    // The verdict change 0.9.0-draft makes on bytes that already exist. Both of
    // these closed under 0.8.0-draft, because the subsection defined no field
    // for a rounding rule so the fallback always applied.
    for amount in [250_001u64, 249_999] {
        let fee = SowOperatorFee {
            operator: None,
            basis: SowOperatorFeeBasis::Percent { percent: 10 },
            base: 2_500_000,
            amount,
        };
        let err = check_operator_fee(&fee).expect_err("one unit out is refused");
        assert!(err.to_string().contains("no tolerance"), "{err}");
    }
}

#[test]
fn a_percentage_too_small_to_earn_a_unit_earns_nothing_and_a_fixed_basis_says_so() {
    // §5.5.8's own instruction, and the change that made the platform's own
    // disclosed line restate itself: a percentage floors to nothing here, and an
    // operator that means to charge the unit states the charge.
    let floored = operator_fee(None, SowOperatorFeeBasis::Percent { percent: 10 }, 5).unwrap();
    assert_eq!(floored.amount, 0);
    let claimed = SowOperatorFee {
        operator: None,
        basis: SowOperatorFeeBasis::Percent { percent: 10 },
        base: 5,
        amount: 1,
    };
    assert!(check_operator_fee(&claimed).is_err());
    let stated = operator_fee(None, SowOperatorFeeBasis::Fixed { fixed: 1 }, 5).unwrap();
    assert_eq!(stated.amount, 1);
    assert!(check_operator_fee(&stated).is_ok());
}

#[test]
fn the_constructor_computes_the_amount_and_serializes_no_rounding_rule() {
    let fee = operator_fee(
        Some("acme-mesh.example"),
        SowOperatorFeeBasis::Percent { percent: 10 },
        2_500_000,
    )
    .unwrap();
    assert_eq!(fee.amount, 250_000);
    assert_eq!(
        serde_json::to_value(&fee).unwrap(),
        serde_json::json!({
            "operator": "acme-mesh.example",
            "basis": { "kind": "percent", "percent": 10 },
            "base": 2_500_000,
            "amount": 250_000
        })
    );

    // §5.5.8 defines no field in which an operator states its rounding rule, and
    // since 0.9.0-draft there is no rule left to state: the amount floors, so
    // neither SDK writes a rounding field and neither constructor takes one.
    let line = operator_fee(None, SowOperatorFeeBasis::Percent { percent: 10 }, 5).unwrap();
    assert_eq!(line.amount, 0);
    let json = serde_json::to_value(&line).unwrap();
    let mut keys: Vec<&String> = json.as_object().unwrap().keys().collect();
    keys.sort();
    assert_eq!(keys, vec!["amount", "base", "basis"]);
    assert!(check_operator_fee(&line).is_ok());
}

#[test]
fn the_cap_bounds_what_the_client_pays_fee_included() {
    let f = fixture();
    assert_eq!(f["operator_fee"]["cap"]["rule"], Value::String("maximal_fit".into()));
    for row in f["operator_fee"]["cap"]["cases"].as_array().expect("array") {
        let case = row["case"].as_str().unwrap();
        let basis: Option<SowOperatorFeeBasis> = if row["basis"].is_null() {
            None
        } else {
            Some(serde_json::from_value(row["basis"].clone()).expect("basis"))
        };
        let cap_remaining = row["cap_remaining"].as_u64().expect("cap_remaining");
        let fit = max_rated_total_under_cap(cap_remaining, basis.as_ref());
        assert_eq!(fit, row["max_rated_total"].as_u64().expect("max"), "{case}");

        let fee = match basis.as_ref() {
            Some(b) if fit > 0 => operator_fee_amount(b, fit).unwrap(),
            _ => 0,
        };
        assert_eq!(fee, row["fee"].as_u64().expect("fee"), "{case}: fee");
        assert_eq!(fit + fee, row["client_total"].as_u64().expect("client_total"), "{case}");

        // The two halves of "maximal": it FITS, and one more unit does not.
        assert!(fit + fee <= cap_remaining, "{case}: the fit must fit");
        if let Some(b) = basis.as_ref() {
            let next = fit + 1;
            assert!(
                next + operator_fee_amount(b, next).unwrap() > cap_remaining,
                "{case}: one more unit must NOT fit"
            );
        }
    }
}

#[test]
fn the_closed_form_is_not_the_rule_and_a_cap_of_100_at_ten_percent_admits_91() {
    // Pinned as its own test as well as a fixture row, because this is the one
    // number a second implementation writing only from the specification gets
    // wrong. floor(100 * 100 / 110) is 90 and 90 is conformant; 91 is also
    // conformant and is the answer both SDKs give.
    assert_eq!((100u64 * 100) / 110, 90);
    let ten = SowOperatorFeeBasis::Percent { percent: 10 };
    assert_eq!(max_rated_total_under_cap(100, Some(&ten)), 91);
    assert_eq!(91 + operator_fee_amount(&ten, 91).unwrap(), 100);
    assert_eq!(92 + operator_fee_amount(&ten, 92).unwrap(), 101);
}

#[test]
fn a_quote_and_a_record_are_asserted_against_the_cap_where_one_is_in_play() {
    let ten = SowOperatorFeeBasis::Percent { percent: 10 };
    let fee = operator_fee(None, ten, 91).unwrap();
    assert_eq!(
        quote_with_operator_fee(91, Some(fee.clone()), None, Some(100)).unwrap().total,
        100
    );
    assert!(quote_with_operator_fee(92, Some(fee), None, Some(100)).is_err());

    let price = SowPrice::time_and_materials(
        "XCR",
        vec![SowScheduleLine::new("tool_calls", "call", 1)],
        SowCap::new(100),
        agentmesh::SowReservation::new(7),
    )
    .unwrap();
    let rating = rate_usage_with_operator_fee(
        &price,
        &[SowMeteredCount::new("tool_calls", 200)],
        0,
        &[],
        Some(ten),
        None,
    )
    .unwrap();
    // The record's fee defaults to the one the rating took, so a caller cannot
    // clamp the work for a cut and then forget to disclose it.
    let record = settlement_with_operator_fee(&rating, None, Some(100)).unwrap();
    assert_eq!(record.total, 100);
    assert_eq!(record.operator_fee, rating.operator_fee);
    assert_eq!(settlement_total(&record), 100);
    assert_eq!(provider_net(record.total, record.operator_fee.as_ref()), 91);
}

#[test]
fn nothing_changes_for_a_caller_with_no_operator_in_the_path() {
    // The peer-to-peer path, which is what the adapter and the services helper
    // use: `client_total` is the total, `cap_remaining` is the old number, and
    // no line appears.
    let price = SowPrice::time_and_materials(
        "XCR",
        vec![SowScheduleLine::new("tool_calls", "call", 1000)],
        SowCap::new(5000),
        agentmesh::SowReservation::new(7),
    )
    .unwrap();
    let rated = rate_usage(&price, &[SowMeteredCount::new("tool_calls", 3)], 0, &[]).unwrap();
    assert_eq!(rated.total, 3000);
    assert_eq!(rated.client_total, 3000);
    assert_eq!(rated.cap_remaining, 2000);
    assert!(!rated.exhausted);
    assert!(rated.operator_fee.is_none());
    assert_eq!(max_rated_total_under_cap(2000, None), 2000);
}

#[test]
fn the_operator_fee_grades_are_never_claimed_upward() {
    let f = fixture();
    assert_eq!(
        serde_json::to_value(OPERATOR_FEE_BASIS_GRADE).unwrap(),
        f["operator_fee"]["grade"]["basis"]
    );
    for row in f["operator_fee"]["grade"]["cases"].as_array().expect("array") {
        let grade = operator_fee_grade(
            row["operator_built_quote"].as_bool().unwrap(),
            row["operator_settled"].as_bool().unwrap(),
        );
        assert_eq!(
            serde_json::to_value(grade).unwrap(),
            row["grade"],
            "quote {} / settle {}",
            row["operator_built_quote"],
            row["operator_settled"]
        );
    }
}

#[test]
fn the_quote_carries_the_line_beside_the_total_before_commitment() {
    let fee = operator_fee(
        Some("acme-mesh.example"),
        SowOperatorFeeBasis::Percent { percent: 10 },
        2_500_000,
    )
    .unwrap();
    let quote = quote_with_operator_fee(2_500_000, Some(fee.clone()), Some("XCR"), None).unwrap();
    assert_eq!(quote.total, 2_750_000);
    assert_eq!(quote.operator_fee.as_ref(), Some(&fee));
    // What disclosure reveals, stated rather than discovered.
    assert_eq!(provider_net(quote.total, quote.operator_fee.as_ref()), 2_500_000);
}

#[test]
fn the_fee_survives_rating_and_lands_in_the_settlement_record() {
    let price = SowPrice::time_and_materials(
        "XCR",
        vec![SowScheduleLine::per("items", "invoice", 1, 2_500_000)],
        SowCap::new(40_000_000),
        agentmesh::SowReservation::new(30),
    )
    .unwrap();
    let rating = rate_usage(&price, &[SowMeteredCount::new("items", 1)], 0, &[]).unwrap();
    assert_eq!(rating.total, 2_500_000);

    let fee =
        operator_fee(None, SowOperatorFeeBasis::Percent { percent: 10 }, rating.total).unwrap();
    let record = settlement_with_operator_fee(&rating, Some(fee.clone()), None).unwrap();

    assert_eq!(record.operator_fee.as_ref(), Some(&fee));
    assert_eq!(record.total, 2_750_000);
    // The record's own lines account for its total: the rated work plus the
    // operator's cut, which is the shape §5.5.6 gives a pass-through line.
    assert_eq!(settlement_total(&record), record.total);
    assert_eq!(
        provider_net(record.total, record.operator_fee.as_ref()),
        rating.total
    );

    let quote = quote_with_operator_fee(rating.total, Some(fee), Some("XCR"), None).unwrap();
    assert!(check_settlement(&quote, &record).is_settled());
}

#[test]
fn a_quote_with_no_fee_produces_a_record_with_no_fee() {
    let price = SowPrice::time_and_materials(
        "XCR",
        vec![SowScheduleLine::per("items", "invoice", 1, 2_500_000)],
        SowCap::new(40_000_000),
        agentmesh::SowReservation::new(30),
    )
    .unwrap();
    let rating = rate_usage(&price, &[SowMeteredCount::new("items", 1)], 0, &[]).unwrap();
    let quote = quote_with_operator_fee(rating.total, None, Some("XCR"), None).unwrap();
    let record = settlement_with_operator_fee(&rating, None, None).unwrap();
    assert!(quote.operator_fee.is_none());
    assert!(record.operator_fee.is_none());
    assert!(check_settlement(&quote, &record).is_settled());
}

#[test]
fn the_client_nodes_read_of_a_settlement_record() {
    let f = fixture();
    for row in f["operator_fee"]["settlement"]["cases"].as_array().expect("array") {
        let quote: SowQuote = serde_json::from_value(row["quote"].clone()).expect("quote");
        let record: SowSettlementRecord =
            serde_json::from_value(row["record"].clone()).expect("record");
        let verdict = check_settlement(&quote, &record);
        let settled = row["settled"].as_bool().expect("bool");
        assert_eq!(verdict.is_settled(), settled, "{}", row["case"]);
        if settled {
            assert_eq!(
                provider_net(record.total, record.operator_fee.as_ref()),
                row["provider_net"].as_u64().expect("provider_net"),
                "{}",
                row["case"]
            );
        } else {
            let disputed = verdict.disputed().expect("a disputed settlement");
            assert_eq!(
                disputed.reason().as_str(),
                row["reason"].as_str().expect("reason"),
                "{}",
                row["case"]
            );
            // The dispute holds BOTH documents exactly as they were compared.
            assert_eq!(disputed.quote(), &quote);
            assert_eq!(disputed.record(), &record);
            assert!(disputed.detail().contains("5.5.8"));
        }
    }
}

#[test]
fn the_client_node_must_not_repair_the_record() {
    let f = fixture();
    let row = f["operator_fee"]["settlement"]["cases"]
        .as_array()
        .expect("array")
        .iter()
        .find(|c| c["reason"] == "operator_fee_missing")
        .expect("the dropped-line case");
    let quote: SowQuote = serde_json::from_value(row["quote"].clone()).unwrap();
    let mut record: SowSettlementRecord = serde_json::from_value(row["record"].clone()).unwrap();
    let verdict = check_settlement(&quote, &record);
    let disputed = verdict.disputed().expect("disputed").clone();

    // Supplying the missing line is exactly the repair §5.5.8 forbids: a record
    // the client rewrote is no longer evidence of what the operator claimed. The
    // dispute holds its own copy and hands it back by shared reference only, so
    // the client's later edits to its own copy reach nothing.
    record.operator_fee = quote.operator_fee.clone();
    record.total = 0;
    assert!(disputed.record().operator_fee.is_none());
    assert_eq!(disputed.record().total, 2_750_000);
    // And no repair function exists to call: the module offers one verdict.
}

#[test]
fn one_discrepancy_is_not_grounds_to_stop_and_a_second_one_is() {
    let f = fixture();
    let after = f["operator_fee"]["settlement"]["refuse_further_work_after"]
        .as_u64()
        .expect("count") as u32;
    assert!(!refuse_further_work_under_operator(0));
    assert!(!refuse_further_work_under_operator(1));
    assert!(refuse_further_work_under_operator(after));
    assert!(refuse_further_work_under_operator(5));
}

#[test]
fn a_no_charge_engagement_has_no_total_for_a_fee_to_sit_inside() {
    let f = fixture();
    assert_eq!(f["operator_fee"]["no_charge"]["carries_a_line"], Value::Bool(false));
    let free = SowPrice::no_charge().unwrap();
    assert!(!settles(&free));
    // Nothing rates, so there is no rating to build a record from, so there is
    // nowhere a fee line could be attached in the first place.
    assert!(rate_usage(&free, &[], 0, &[]).is_err());
}
