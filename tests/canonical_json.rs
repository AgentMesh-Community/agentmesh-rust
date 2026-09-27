//! Canonical JSON (§5.3) — RFC 8785 (JCS) held to pinned bytes.
//!
//! `canonical_json` is under every envelope signature and both attestations, so
//! a one-byte drift against the TS SDK is a cross-SDK signature failure that
//! surfaces as IDENTITY_MISMATCH on valid traffic. The shared fixture
//! (`conformance/canonical-json.json`) pins the cases where implementations
//! actually diverge — and where THIS SDK diverged until 2026-07-27: serde_json's
//! number formatting used non-ECMAScript exponent thresholds (`1e+20`,
//! `1e-6`), kept `.0` on integral floats, preserved `-0.0`'s sign, printed
//! integers above 2^53 exactly (bytes TypeScript cannot produce), and sorted
//! keys in UTF-8 byte order, which flips a non-BMP key against U+E000..U+FFFF.
//! All of that is now delegated to `serde_jcs` (RFC 8785). The expected bytes
//! were derived from the RFC's rules and its Appendix B, then generated via the
//! TS SDK, so a failure here means this implementation left JCS — fix the code,
//! not the fixture. The other side: sdk-typescript/__tests__/unit/canonical-json.test.ts.

use agentmesh::identity::canonical_json;
use serde_json::Value;

fn fixture() -> Value {
    let raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/conformance/canonical-json.json"
    ))
    .expect("conformance/canonical-json.json");
    serde_json::from_str(&raw).expect("fixture parses")
}

#[test]
fn every_vector_produces_the_pinned_bytes() {
    let f = fixture();
    let vectors = f["vectors"].as_array().expect("vectors");
    // A fixture-driven suite that quietly loses a section reports a number that
    // sounds like coverage.
    assert_eq!(vectors.len(), 52, "vector count");
    for v in vectors {
        let name = v["name"].as_str().unwrap();
        let input: Value =
            serde_json::from_str(v["input_json"].as_str().unwrap()).expect(name);
        assert_eq!(
            canonical_json(&input),
            v["canonical"].as_str().unwrap(),
            "vector {name}"
        );
    }
}

#[test]
fn rfc_8785_appendix_b_bit_patterns() {
    // These enter as doubles, not as JSON text, so they also pin values a lossy
    // parser could never deliver (e.g. the exact 8000000000000000 = -0).
    let f = fixture();
    let rows = f["number_bits"].as_array().expect("number_bits");
    assert_eq!(rows.len(), 24, "Appendix B row count");
    for row in rows {
        let hex = row["ieee754_hex"].as_str().unwrap();
        let bits = u64::from_str_radix(hex, 16).unwrap();
        let v = Value::from(f64::from_bits(bits));
        assert_eq!(
            canonical_json(&v),
            row["canonical"].as_str().unwrap(),
            "bits {hex}"
        );
    }
}

#[test]
fn absent_is_omitted_and_null_is_distinct() {
    // The two AgentMesh rules stated in §5.3. The fixture can only carry JSON,
    // where "unset" cannot be written down; this is the struct side of the
    // member_absent vector — an unset Option MUST vanish from the bytes, the
    // way the envelope's own optional fields do (skip_serializing_if).
    #[derive(serde::Serialize)]
    struct Partial {
        b: i64,
        #[serde(skip_serializing_if = "Option::is_none")]
        a: Option<i64>,
    }
    let absent = serde_json::to_value(Partial { b: 1, a: None }).unwrap();
    assert_eq!(canonical_json(&absent), "{\"b\":1}");

    let null_member: Value = serde_json::from_str("{\"a\":null,\"b\":1}").unwrap();
    assert_eq!(canonical_json(&null_member), "{\"a\":null,\"b\":1}");
    assert_ne!(canonical_json(&null_member), canonical_json(&absent));
}

#[test]
fn integer_only_values_are_byte_stable_across_the_jcs_adoption() {
    // The adoption invariant: every number a protocol field actually carries —
    // timestamps in ms, revision counters, amount_micro, sizes — is an integer
    // well inside 2^53, and for those ECMAScript integer notation is exactly
    // what serde_json emitted before. The signed fixtures (budget_conformance,
    // inbound_protections) re-verify pinned signatures over such envelopes
    // elsewhere in this suite; this is the same assertion in miniature.
    let v: Value = serde_json::from_str(
        "{\"amount_micro\":2000000,\"revision\":0,\"ts_ms\":1753600000000}",
    )
    .unwrap();
    assert_eq!(
        canonical_json(&v),
        "{\"amount_micro\":2000000,\"revision\":0,\"ts_ms\":1753600000000}"
    );
}
