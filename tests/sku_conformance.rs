//! §19.1 SKUs + §19.5 agreements, asserted against `conformance/commerce.json`
//! and the cross-language digest fixture `tests/fixtures/sku_digest.json`.
//!
//! **The fixtures are the authority.** When a case here fails, the fix is in
//! `src/sku.rs` / `src/agreement.rs` / `src/client.rs`, never in the JSON; a
//! fixture changes only with a spec change alongside. The load-bearing
//! assertions are the cross-SDK byte ones: every digest the TypeScript SDK
//! computed must reproduce here byte for byte — one byte of drift is a set of
//! terms that verifies in one SDK and strands agreements in the other.
//!
//! Shape and digest cases run with no broker, no connection and no clock. The
//! enforcement cases (the `AGREEMENT_REQUIRED` refusal at admission, the
//! approve-then-retry path) are behavioral, so they run against a live NATS
//! server at 127.0.0.1:4222 and skip gracefully without one, exactly like
//! `tests/e2e.rs`.

use std::time::Duration;

use futures::StreamExt;
use serde_json::{json, Value};

use agentmesh::{
    agreement_covers, agreement_required, canonical_agreement_bytes, canonical_json,
    load_agreement, public_sku_of, sign_agreement, sign_envelope, sku_digest, sku_digest_value,
    sku_for, validate_agreement, validate_sku, validate_sku_price, validate_skus, AgentMesh,
    AgreementDocument, AgreementRequiredDetails, AgreementWant, ConnectOptions, Envelope, KeyPair,
    PrimitiveType, RegisterOptions, Sku, SkuPriceModel, AGREEMENT_SIG_PREFIX, SKU_DIGEST_PREFIX,
};

static COMMERCE_JSON: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/conformance/commerce.json"));
static DIGEST_FIXTURE_JSON: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sku_digest.json"));

fn commerce() -> Value {
    serde_json::from_str(COMMERCE_JSON).expect("conformance/commerce.json parses")
}

fn digest_fixture() -> Value {
    serde_json::from_str(DIGEST_FIXTURE_JSON).expect("tests/fixtures/sku_digest.json parses")
}

const URL: &str = "nats://127.0.0.1:4222";

// ─── the cross-language digests (no broker, no clock) ───────────────────────

#[test]
fn every_ts_computed_digest_reproduces_byte_for_byte() {
    let f = digest_fixture();
    assert_eq!(f["digest_bytes_prefix"].as_str().unwrap(), format!("{SKU_DIGEST_PREFIX}\n"));
    let entries = f["entries"].as_array().expect("entries");
    assert!(entries.len() >= 3, "the fixture covers at least three price shapes");
    for e in entries {
        let raw = &e["sku"];
        let want = e["digest"].as_str().expect("digest");
        // Over the raw JSON, as a reader of a stored manifest would.
        assert_eq!(sku_digest_value(raw), want, "raw digest for {}", raw["sku"]);
        // And through the typed round-trip, as a registering seller would —
        // which also proves serde emits exactly the bytes TS canonicalized
        // (absent members omitted, `skills` never rewritten, §5.3).
        let typed: Sku = serde_json::from_value(raw.clone()).expect("typed SKU parses");
        assert_eq!(sku_digest(&typed).unwrap(), want, "typed digest for {}", raw["sku"]);
        validate_sku(raw).expect("fixture SKUs are valid");
    }
}

#[test]
fn the_fixture_covers_the_load_bearing_price_shapes() {
    let f = digest_fixture();
    let models: Vec<String> = f["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["sku"]["price"]["model"].as_str().unwrap().to_string())
        .collect();
    for want in ["flat", "per_unit", "package", "tiered"] {
        assert!(models.iter().any(|m| m == want), "fixture has a {want} price");
    }
}

// ─── the commerce fixture: shapes and refusals ──────────────────────────────

#[test]
fn valid_skus_and_prices_validate() {
    let f = commerce();
    let valid = f["sku"]["valid"].as_array().unwrap();
    for sku in valid {
        validate_sku(sku).unwrap_or_else(|e| panic!("valid SKU {} refused: {e}", sku["sku"]));
    }
    validate_skus(&f["sku"]["valid"]).expect("the valid set has unique ids");
    for price in f["price"]["valid"].as_array().unwrap() {
        validate_sku_price(price)
            .unwrap_or_else(|e| panic!("valid price {} refused: {e}", price["model"]));
    }
}

#[test]
fn invalid_skus_and_prices_refuse_for_their_stated_reason() {
    let f = commerce();
    for case in f["sku"]["invalid"].as_array().unwrap() {
        let name = case["case"].as_str().unwrap();
        assert!(validate_sku(&case["sku"]).is_err(), "sku case {name} must refuse");
    }
    for case in f["price"]["invalid"].as_array().unwrap() {
        let name = case["case"].as_str().unwrap();
        assert!(validate_sku_price(&case["price"]).is_err(), "price case {name} must refuse");
    }
}

#[test]
fn the_pinned_digest_and_its_canonical_bytes_reproduce() {
    let f = commerce();
    let d = &f["digest"];
    assert_eq!(d["digest_bytes_prefix"].as_str().unwrap(), format!("{SKU_DIGEST_PREFIX}\n"));
    assert_eq!(canonical_json(&d["sku"]), d["canonical"].as_str().unwrap());
    assert_eq!(sku_digest_value(&d["sku"]), d["sku_digest"].as_str().unwrap());
    // One moved micro-unit moves the digest — the identity property that
    // makes every standing agreement go stale at once.
    let mut moved = d["sku"].clone();
    moved["price"]["amount_micro"] = json!(1501);
    assert_eq!(
        sku_digest_value(&moved),
        d["one_micro_unit_moved"]["sku_digest"].as_str().unwrap()
    );
}

#[test]
fn most_specific_covers_wins_and_uncovered_is_free() {
    let f = commerce();
    let skus: Vec<Sku> = serde_json::from_value(f["sku"]["valid"].clone()).unwrap();
    // "caselaw-summary" is named by caselaw-metered; it beats both agent-wide SKUs.
    assert_eq!(sku_for(Some(&skus), "caselaw-summary").unwrap().sku, "caselaw-metered");
    // Anything else falls to the FIRST agent-wide SKU.
    assert_eq!(sku_for(Some(&skus), "not-covered-by-name").unwrap().sku, "everything-flat");
    // No SKUs at all: free.
    assert!(sku_for(None, "anything").is_none());
}

#[test]
fn public_sku_of_advertises_id_price_and_digest() {
    let f = commerce();
    let sku: Sku = serde_json::from_value(f["digest"]["sku"].clone()).unwrap();
    let public = public_sku_of(&sku).unwrap();
    assert_eq!(public.sku, "caselaw-metered");
    assert_eq!(public.digest, f["digest"]["sku_digest"].as_str().unwrap());
    assert_eq!(
        serde_json::to_value(&public.price).unwrap(),
        f["digest"]["sku"]["price"],
        "the advertised price is the SKU's price verbatim"
    );
}

// ─── the agreement: really-signed vector, matching rule, refusal ────────────

#[test]
fn the_signed_agreement_vector_verifies_and_its_canonical_bytes_rebuild() {
    let f = commerce();
    let a = &f["agreement"];
    assert_eq!(a["signed_bytes_prefix"].as_str().unwrap(), AGREEMENT_SIG_PREFIX);
    assert_eq!(
        String::from_utf8(canonical_agreement_bytes(&a["signed"]).unwrap()).unwrap(),
        a["canonical"].as_str().unwrap()
    );
    let doc = load_agreement(&a["signed"]).expect("the TS-signed vector loads");
    assert_eq!(doc.consumer_owner, f["identities"]["sender"].as_str().unwrap());
    assert_eq!(doc.seller_agent, f["identities"]["recipient"].as_str().unwrap());

    // Tampered terms (fixture case): flip the digest, verification MUST fail.
    let mut tampered = a["signed"].clone();
    tampered["sku_digest"] = a["invalid"][1]["document"]["sku_digest"].clone();
    assert!(load_agreement(&tampered).is_err(), "a tampered digest must not verify");
}

#[test]
fn invalid_agreement_documents_refuse() {
    let f = commerce();
    for case in f["agreement"]["invalid"].as_array().unwrap() {
        if case["document"].is_null() {
            continue; // SEMANTIC prose cases, asserted elsewhere
        }
        let name = case["case"].as_str().unwrap();
        assert!(validate_agreement(&case["document"]).is_err(), "agreement case {name} must refuse");
    }
}

#[test]
fn a_stale_digest_is_a_missing_agreement() {
    let f = commerce();
    let case = &f["agreement"]["stale_digest_case"];
    let doc = load_agreement(&f["agreement"]["signed"]).unwrap();
    assert_eq!(doc.sku_digest, case["holds_agreement_for"].as_str().unwrap());
    let covers = |digest: &str| {
        agreement_covers(
            &doc,
            &AgreementWant {
                consumer_owner: &doc.consumer_owner,
                seller_agent: &doc.seller_agent,
                sku: &doc.sku,
                sku_digest: digest,
                now_ms: None,
            },
        )
    };
    assert!(covers(case["holds_agreement_for"].as_str().unwrap()));
    // The seller moved the price: every standing agreement went stale at once.
    assert!(!covers(case["sku_current_digest"].as_str().unwrap()));
}

#[test]
fn the_refusal_carries_the_pinned_details_field_names() {
    let f = commerce();
    let refusal = &f["enforcement"]["refusal"];
    let err = agreement_required(
        AgreementRequiredDetails {
            sku: refusal["details"]["sku"].as_str().unwrap().to_string(),
            sku_digest: refusal["details"]["sku_digest"].as_str().unwrap().to_string(),
            approval_url: refusal["details"]["approval_url"].as_str().unwrap().to_string(),
        },
        None,
    );
    let eo = err.error_object().expect("a structured refusal — details are the protocol");
    assert_eq!(eo.code, refusal["error_code"].as_str().unwrap());
    assert!(!eo.retryable);
    assert_eq!(eo.details.as_ref().unwrap(), &refusal["details"]);
}

// ─── enforcement (live; skip without a broker) ──────────────────────────────

/// The SKU under test: per_unit with a checkout_url, covering one offering.
fn paid_sku() -> Sku {
    serde_json::from_value(json!({
        "sku": "paid-echo",
        "covers": { "offerings": ["paid-echo-offering"] },
        "price": { "model": "per_unit", "currency": "USD", "meter": "tokens_out", "amount_micro": 2 },
        "provider": { "id": "internal", "checkout_url": "https://pay.example.com/paid-echo" }
    }))
    .unwrap()
}

/// A fake registry answering `mesh.registry.get.<id>` with a signed manifest
/// carrying just the field the §19.5 owner resolution reads: `owner`. Maps
/// each agent id to its owner key; unknown agents get an error envelope.
async fn spawn_fake_registry(
    url: &str,
    owners: Vec<(String, String)>,
) -> tokio::task::JoinHandle<()> {
    let client = async_nats::connect(url).await.expect("registry connect");
    let kp = KeyPair::new_user();
    let registry_id = kp.public_key();
    let mut sub = client.subscribe("mesh.registry.get.*").await.expect("subscribe");
    tokio::spawn(async move {
        while let Some(msg) = sub.next().await {
            let Some(reply) = msg.reply else { continue };
            let agent_id = msg.subject.as_str().rsplit('.').next().unwrap_or("").to_string();
            let owner = owners.iter().find(|(a, _)| *a == agent_id).map(|(_, o)| o.clone());
            let mut env = Envelope::new(PrimitiveType::Respond, &registry_id);
            env.payload = Some(match owner {
                Some(owner) => json!({ "id": agent_id, "owner": owner }),
                None => json!({}),
            });
            sign_envelope(&mut env, &kp).unwrap();
            let bytes = serde_json::to_vec(&env).unwrap();
            let _ = client.publish(reply, bytes.into()).await;
        }
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_paid_offering_refuses_agreement_required_and_admits_once_approved() {
    let Some(responder) = AgentMesh::connect(URL, ConnectOptions { allow_unnamed: true, ..Default::default() }).await.ok() else {
        eprintln!("skipping sku live tests: no NATS server at {URL}");
        return;
    };
    let requester = AgentMesh::connect(URL, ConnectOptions { allow_unnamed: true, ..Default::default() }).await.expect("connect");

    let sku = paid_sku();
    let digest = sku_digest(&sku).unwrap();

    // Distinct owners on the two sides — same-owner traffic is not a sale and
    // would (correctly) bypass the check.
    let consumer_owner_kp = KeyPair::new_user();
    let seller_owner = KeyPair::new_user().public_key();
    let registry = spawn_fake_registry(
        URL,
        vec![
            (requester.id().to_string(), consumer_owner_kp.public_key()),
            (responder.id().to_string(), seller_owner),
        ],
    )
    .await;

    responder.on_request("paid-echo-offering", |input| async move { Ok(json!({ "echoed": input })) });
    responder.on_request("free-offering", |input| async move { Ok(json!({ "echoed": input })) });

    // The armed agreements, shared with the lookup hook: empty means the
    // platform holds no acceptance for this account.
    let held: std::sync::Arc<std::sync::Mutex<Vec<Value>>> = Default::default();
    let held_for_hook = held.clone();
    responder.on_agreement_lookup(move |_owner| Ok(held_for_hook.lock().unwrap().clone()));

    let manifest = responder
        .register(RegisterOptions {
            name: "paid-seller".into(),
            skus: Some(vec![sku.clone()]),
            ..Default::default()
        })
        .await
        .expect("register");
    // §8.7: the storefront advertises id + price + digest, derived from the
    // declared SKUs; the manifest carries the SKUs themselves too.
    let advertised = manifest.public.as_ref().and_then(|p| p.skus.as_ref()).expect("public.skus");
    assert_eq!(advertised.len(), 1);
    assert_eq!(advertised[0].sku, "paid-echo");
    assert_eq!(advertised[0].digest, digest);
    assert_eq!(manifest.skus.as_ref().map(Vec::len), Some(1));
    tokio::time::sleep(Duration::from_millis(150)).await;

    // 1. No agreement: refused at admission with the pinned details.
    let err = requester
        .request(responder.id(), "paid-echo-offering", json!({ "hi": 1 }))
        .await
        .expect_err("refused before any work");
    let eo = err.error_object().expect("AGREEMENT_REQUIRED is a structured refusal");
    assert_eq!(eo.code, "AGREEMENT_REQUIRED");
    let details = eo.details.as_ref().expect("details");
    assert_eq!(details["sku"], json!("paid-echo"));
    assert_eq!(details["sku_digest"], json!(digest));
    assert_eq!(details["approval_url"], json!("https://pay.example.com/paid-echo"));

    // 2. An offering covered by no SKU stays free — no agreement consulted.
    let res = requester
        .request(responder.id(), "free-offering", json!({ "hi": 2 }))
        .await
        .expect("uncovered is free (§19.1)");
    assert_eq!(res.payload["output"]["echoed"]["hi"], json!(2));

    // 3. Approve, then send again: the miss is deliberately uncached, so the
    //    very next request sees the new acceptance.
    let mut doc = AgreementDocument {
        v: 1,
        consumer_owner: String::new(),
        seller_agent: responder.id().to_string(),
        sku: "paid-echo".into(),
        sku_digest: digest.clone(),
        agreed_at: "2026-08-02T15:00:00Z".into(),
        expires_at: None,
        evidence: None,
        sig: String::new(),
    };
    sign_agreement(&mut doc, &consumer_owner_kp).unwrap();
    held.lock().unwrap().push(serde_json::to_value(&doc).unwrap());

    let res = requester
        .request(responder.id(), "paid-echo-offering", json!({ "hi": 3 }))
        .await
        .expect("approved terms admit");
    assert_eq!(res.payload["output"]["echoed"]["hi"], json!(3));

    registry.abort();
    responder.close().await;
    requester.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_malformed_sku_refuses_at_registration_and_free_models_never_enforce() {
    let Some(agent) = AgentMesh::connect(URL, ConnectOptions { allow_unnamed: true, ..Default::default() }).await.ok() else {
        eprintln!("skipping sku live tests: no NATS server at {URL}");
        return;
    };
    // §19.1: the refusal happens at register, where the operator can see it.
    let mut malformed = paid_sku();
    malformed.sku = "NOT-VALID".into();
    let err = agent
        .register(RegisterOptions {
            name: "bad-seller".into(),
            skus: Some(vec![malformed]),
            ..Default::default()
        })
        .await
        .expect_err("a malformed SKU refuses at registration");
    assert!(err.to_string().contains("INVALID_MANIFEST"), "{err}");

    // A free-model SKU registers fine and enforces nothing.
    let free: Sku = serde_json::from_value(json!({
        "sku": "free-terms",
        "covers": { "agent": true },
        "price": { "model": "free" },
        "provider": { "id": "internal" }
    }))
    .unwrap();
    assert_eq!(free.price.model, SkuPriceModel::Free);
    let requester = AgentMesh::connect(URL, ConnectOptions { allow_unnamed: true, ..Default::default() }).await.expect("connect");
    agent.on_request("anything", |input| async move { Ok(json!({ "ok": input })) });
    agent
        .register(RegisterOptions {
            name: "free-seller".into(),
            skus: Some(vec![free]),
            ..Default::default()
        })
        .await
        .expect("register");
    tokio::time::sleep(Duration::from_millis(150)).await;
    requester
        .request(agent.id(), "anything", json!({ "n": 1 }))
        .await
        .expect("a free SKU admits without any agreement machinery");

    agent.close().await;
    requester.close().await;
}
