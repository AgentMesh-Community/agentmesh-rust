// The §8.5 deprecation window, Rust side: pre-rename documents keep reading,
// and everything this SDK writes carries only the new names. Mirror of the TS
// suite offering-rename-aliases.test.ts; delete when the alias is dropped.
use agentmesh::Manifest;

const LEGACY_MANIFEST: &str = r#"{
  "id": "UAKQRYZBYFOC65OQZVJ3QPCIERDTRNNZPMOJUYXC3DGPRCDWSKD4HV5A",
  "name": "old-timer",
  "description": "registered before the rename",
  "version": "1.0.0",
  "protocol_version": "0.2",
  "endpoint": "mesh.agent.X.inbox",
  "node": {
    "id": "UBMBH4BK6EIHQFVMHLSABFSQXB3JXUFZOXVZQTIERO33AD4HHAI3D7QP",
    "attestation": {
      "node": "UBMBH4BK6EIHQFVMHLSABFSQXB3JXUFZOXVZQTIERO33AD4HHAI3D7QP",
      "agent": "UAKQRYZBYFOC65OQZVJ3QPCIERDTRNNZPMOJUYXC3DGPRCDWSKD4HV5A",
      "issued_at": "2026-08-01T00:00:00Z",
      "expires_at": "2027-08-01T00:00:00Z",
      "sig": "not-checked-here"
    }
  },
  "capabilities": [],
  "skills": [
    { "id": "chat", "name": "Chat", "description": "talk" }
  ]
}"#;

#[test]
fn legacy_skills_field_reads_as_offerings() {
    let m: Manifest = serde_json::from_str(LEGACY_MANIFEST).expect("legacy manifest must parse");
    assert_eq!(m.offerings.len(), 1);
    assert_eq!(m.offerings[0].id, "chat");
    assert!(m.offering("chat").is_some());
}

#[test]
fn serialization_emits_only_the_new_name() {
    let m: Manifest = serde_json::from_str(LEGACY_MANIFEST).unwrap();
    let out = serde_json::to_string(&m).unwrap();
    assert!(out.contains("\"offerings\""));
    assert!(!out.contains("\"skills\""), "the legacy field must not ride the wire");
}

#[test]
fn needs_and_delivers_round_trip() {
    let json = r#"{
      "id": "x", "name": "n", "description": "d", "tags": null,
      "needs": [
        { "resource": "git", "access": "read-write", "description": "the repo to work in" },
        { "text": "your brand guidelines, if you have them" }
      ],
      "delivers": { "final": "a pushed branch and a PR", "interim": true, "in_resource": true }
    }"#;
    let o: agentmesh::Offering = serde_json::from_str(json).unwrap();
    let needs = o.needs.as_ref().unwrap();
    assert_eq!(needs[0].resource.as_deref(), Some("git"));
    assert_eq!(needs[0].access.as_deref(), Some("read-write"));
    assert_eq!(needs[1].text.as_deref(), Some("your brand guidelines, if you have them"));
    let d = o.delivers.as_ref().unwrap();
    assert_eq!(d.final_form.as_deref(), Some("a pushed branch and a PR"));
    assert_eq!(d.interim, Some(true));
    assert_eq!(d.in_resource, Some(true));
    // `final` is a Rust keyword; the serde rename must hold on the way out too.
    let out = serde_json::to_string(&o).unwrap();
    assert!(out.contains("\"final\""));
    assert!(!out.contains("final_form"));
}

#[test]
fn offered_reporting_level_round_trip() {
    // §8.5.2: the offered reporting level, declared on the offering. The SDK's
    // job is declaration only — the registry validates and materializes.
    let json = r#"{
      "id": "x", "name": "n", "description": "d",
      "reporting": { "level": "check_ins", "every": "P1W" }
    }"#;
    let o: agentmesh::Offering = serde_json::from_str(json).unwrap();
    let r = o.reporting.as_ref().unwrap();
    assert_eq!(r.level, "check_ins");
    assert_eq!(r.every.as_deref(), Some("P1W"));
    let out = serde_json::to_string(&o).unwrap();
    assert!(out.contains("\"reporting\""));
    assert!(out.contains("\"P1W\""));

    // Absent stays absent: no reporting key is serialized for the silent case,
    // so a manifest written before the field existed round-trips byte-stable.
    let silent: agentmesh::Offering =
        serde_json::from_str(r#"{ "id": "x", "name": "n", "description": "d" }"#).unwrap();
    assert!(silent.reporting.is_none());
    assert!(!serde_json::to_string(&silent).unwrap().contains("reporting"));

    // And `every` below check_ins is a registry-side drop, not a parse error:
    // a foreign manifest carrying it still deserializes.
    let below: agentmesh::Offering = serde_json::from_str(
        r#"{ "id": "x", "name": "n", "description": "d", "reporting": { "level": "on_change" } }"#,
    )
    .unwrap();
    assert_eq!(below.reporting.unwrap().level, "on_change");
}

#[test]
fn card_level_data_use_round_trip() {
    // §8.10: the card-level data-use declaration. Declaration-only in this
    // SDK — the registry validates on the way in and drops an unreadable
    // declaration WHOLE; this crate's job is to carry a readable one intact.
    let mut v: serde_json::Value = serde_json::from_str(LEGACY_MANIFEST).unwrap();
    v["data_use"] = serde_json::json!({
        "promises": { "no_training": true, "no_third_party_sharing": true, "no_human_reading": true },
        "retention": { "max_days": 30 },
        "processors": [
            { "service": "Anthropic API", "domain": "anthropic.com",
              "purpose": "model inference, zero-retention tier" }
        ],
        "processed_in": ["us"]
    });
    let m: Manifest = serde_json::from_value(v).unwrap();
    let du = m.data_use.as_ref().unwrap();
    assert_eq!(du.promises.as_ref().unwrap().no_training, Some(true));
    assert_eq!(du.promises.as_ref().unwrap().no_human_reading, Some(true));
    assert_eq!(du.retention.as_ref().unwrap().max_days, 30);
    let procs = du.processors.as_ref().unwrap();
    assert_eq!(procs.len(), 1);
    assert_eq!(procs[0].service, "Anthropic API");
    assert_eq!(procs[0].domain.as_deref(), Some("anthropic.com"));
    // §8.10 `processed_in`: a SET declaration in lowercase alpha-2, carried
    // verbatim — the registry is the validator, this crate is the carrier.
    assert_eq!(du.processed_in.as_deref(), Some(&["us".to_string()][..]));
    let out = serde_json::to_string(&m).unwrap();
    assert!(out.contains("\"data_use\""));
    assert!(out.contains("\"no_training\":true"));
    assert!(out.contains("\"max_days\":30"));
    assert!(out.contains("\"processed_in\":[\"us\"]"));

    // Absent stays absent: a manifest written before the field existed
    // round-trips byte-stable, with no data_use key invented for silence.
    let silent: Manifest = serde_json::from_str(LEGACY_MANIFEST).unwrap();
    assert!(silent.data_use.is_none());
    assert!(!serde_json::to_string(&silent).unwrap().contains("data_use"));

    // An EMPTY processors list survives as []: it is itself a statement —
    // content leaves the operator for nowhere — distinct from omission.
    let nowhere: agentmesh::AgentDataUse =
        serde_json::from_str(r#"{ "processors": [] }"#).unwrap();
    assert_eq!(nowhere.processors.as_deref(), Some(&[][..]));
    assert!(serde_json::to_string(&nowhere).unwrap().contains("\"processors\":[]"));

    // A declaration without jurisdictions stays without them: absence fails
    // any jurisdiction requirement (§8.10), so no key may be invented.
    assert!(nowhere.processed_in.is_none());
    assert!(!serde_json::to_string(&nowhere).unwrap().contains("processed_in"));
}

#[test]
fn card_level_compliance_round_trip() {
    // §8.11: the compliance postures the operator claims. Declaration-only in
    // this SDK — self-declared including the attestation pointer, validated
    // (and dropped whole when unreadable) by the registry on the way in.
    let mut v: serde_json::Value = serde_json::from_str(LEGACY_MANIFEST).unwrap();
    v["compliance"] = serde_json::json!([
        { "standard": "soc2",
          "scope": "the hosted pipeline, Type II",
          "attestation": { "by": "Example Auditors LLP",
                           "url": "https://example.com/soc2",
                           "expires_at": "2027-03-01" } },
        { "standard": "gdpr", "scope": "as processor, under the engagement DPA" }
    ]);
    let m: Manifest = serde_json::from_value(v).unwrap();
    let claims = m.compliance.as_ref().unwrap();
    assert_eq!(claims.len(), 2);
    assert_eq!(claims[0].standard, "soc2");
    assert_eq!(claims[0].scope.as_deref(), Some("the hosted pipeline, Type II"));
    let att = claims[0].attestation.as_ref().unwrap();
    assert_eq!(att.by.as_deref(), Some("Example Auditors LLP"));
    assert_eq!(att.url.as_deref(), Some("https://example.com/soc2"));
    assert_eq!(att.expires_at.as_deref(), Some("2027-03-01"));
    // The second entry carries no attestation, and none is invented: the
    // pointer is the operator's to offer, not the type's to require.
    assert_eq!(claims[1].standard, "gdpr");
    assert!(claims[1].attestation.is_none());
    let out = serde_json::to_string(&m).unwrap();
    assert!(out.contains("\"compliance\""));
    assert!(out.contains("\"standard\":\"soc2\""));
    assert!(out.contains("\"expires_at\":\"2027-03-01\""));
    assert!(!out.contains("\"attestation\":null"));

    // Absent stays absent: has-not-said survives the round trip as silence,
    // because a stated requirement treats silence as not meeting it and an
    // invented key would change what this agent is claiming.
    let silent: Manifest = serde_json::from_str(LEGACY_MANIFEST).unwrap();
    assert!(silent.compliance.is_none());
    assert!(!serde_json::to_string(&silent).unwrap().contains("compliance"));

    // The typed entry round-trips bare: standard alone is a complete claim.
    let bare: agentmesh::AgentComplianceEntry =
        serde_json::from_str(r#"{ "standard": "hipaa" }"#).unwrap();
    assert_eq!(bare.standard, "hipaa");
    assert_eq!(serde_json::to_string(&bare).unwrap(), r#"{"standard":"hipaa"}"#);
}

#[test]
fn resource_entry_shape() {
    let r: agentmesh::ResourceEntry = serde_json::from_str(
        r#"{ "uri": "https://github.com/example/parser", "kind": "git", "access": "read-write" }"#,
    )
    .unwrap();
    assert_eq!(r.kind, "git");
    assert_eq!(r.access, "read-write");
    assert!(r.name.is_none());
}
