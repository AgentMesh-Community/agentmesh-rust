//! Node-credential renewal (§4.8), mirroring `sdk-typescript`'s `credential.ts`
//! where the language boundary allows.
//!
//! The credential a node connects with is a lease, like the vouch that sits
//! under it: SPEC §4.8 requires a finite expiry, and an expiry with nothing
//! renewing it is a scheduled outage with a 30-day fuse. These tests pin the
//! three things that make renewal trustworthy:
//!
//!   - **the schedule** is read off the credential's OWN `iat`/`exp`, at the
//!     same two thirds a vouch uses, so a credential minted under a different
//!     operator policy still gets a proportionate deadline;
//!   - **the signing contract** is byte-exact, because the control plane and
//!     the TS SDK verify and produce these same two ASCII lines — the roster
//!     inside the node's signature is sorted (it covers a set) while the
//!     `agents` array keeps the caller's order (it is a list);
//!   - **an unpersisted renewal is a failed renewal.** `on_renewed` runs before
//!     the renewer adopts the fresh JWT, so a host that cannot write the
//!     credential down keeps the old one and its deadline, and retries.
//!
//! Most of it needs no server: the HTTP call goes through `CredentialTransport`,
//! which is both the seam these tests inject at and the supported path for a
//! host supplying its own client. The last section is the exception and the
//! point of the default `http` feature — it stands up a real socket and drives
//! the BUILT-IN transport across it, because "renewal works out of the box" is
//! the claim that parity with the TS SDK rests on and a mock cannot make it.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use agentmesh::{
    agent_consent_line, build_credential_request, create_agent_identity,
    credential_check_interval, credential_endpoint, credential_renew_at,
    decode_credential_claims, node_credential_line, BoxFuture, CredentialClaims,
    CredentialHttpResponse, CredentialRenewer, CredentialRenewerOptions, CredentialTransport,
    KeyPair, RenewalAgent, RenewalRoster, Result, SecurityWarning,
    MAX_VOUCH_CHECK_INTERVAL_MS,
};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;

// ── fixtures ────────────────────────────────────────────────────────────────

/// A NATS user JWT of the real shape: three base64url segments, the middle one
/// the claim set. The signature is not verified by anything here — §4.8 says so
/// explicitly, and `decode_credential_claims` documents why: only the broker can
/// check it against the account chain.
fn jwt(sub: &str, iat: Option<i64>, exp: Option<i64>) -> String {
    let header = serde_json::json!({ "typ": "JWT", "alg": "ed25519-nkey" });
    let mut claims = serde_json::json!({
        "jti": "7ZQ2SAMPLEJTIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "iss": "ACCOUNTSAMPLEKEYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "name": "node",
        "sub": sub,
        "nats": { "type": "user", "version": 2 },
    });
    if let Some(iat) = iat {
        claims["iat"] = serde_json::json!(iat);
    }
    if let Some(exp) = exp {
        claims["exp"] = serde_json::json!(exp);
    }
    let seg = |v: &serde_json::Value| URL_SAFE_NO_PAD.encode(v.to_string().as_bytes());
    format!("{}.{}.{}", seg(&header), seg(&claims), URL_SAFE_NO_PAD.encode([0u8; 64]))
}

const DAY_SEC: i64 = 24 * 3_600;

/// The control plane, faked: records every POST and answers whatever it was
/// told to. `Err` is never returned — a transport error and an HTTP refusal are
/// different things, and the refusal is the interesting one (§4.8: a refusal to
/// renew IS revocation).
struct FakeApi {
    calls: Mutex<Vec<(String, String)>>,
    reply: Mutex<(u16, String)>,
}

impl FakeApi {
    fn ok_with(jwt: &str) -> Arc<FakeApi> {
        Arc::new(FakeApi {
            calls: Mutex::new(Vec::new()),
            reply: Mutex::new((
                200,
                serde_json::json!({
                    "ok": true,
                    "jwt": jwt,
                    "expires_at": "2026-10-01T00:00:00.000Z",
                    "mesh": "agentmesh",
                })
                .to_string(),
            )),
        })
    }

    fn refusing(status: u16, error: &str) -> Arc<FakeApi> {
        Arc::new(FakeApi {
            calls: Mutex::new(Vec::new()),
            reply: Mutex::new((status, serde_json::json!({ "error": error }).to_string())),
        })
    }

    fn call_count(&self) -> usize {
        self.calls.lock().unwrap().len()
    }

    fn last_body(&self) -> serde_json::Value {
        let calls = self.calls.lock().unwrap();
        let (_, body) = calls.last().expect("at least one POST");
        serde_json::from_str(body).expect("the body is JSON")
    }

    fn last_url(&self) -> String {
        self.calls.lock().unwrap().last().expect("at least one POST").0.clone()
    }
}

impl CredentialTransport for FakeApi {
    fn post_json<'a>(
        &'a self,
        url: &'a str,
        body: String,
    ) -> BoxFuture<'a, Result<CredentialHttpResponse>> {
        let url = url.to_string();
        Box::pin(async move {
            self.calls.lock().unwrap().push((url, body));
            let (status, body) = self.reply.lock().unwrap().clone();
            Ok(CredentialHttpResponse { status, body })
        })
    }
}

/// Verify a standard-base64 detached signature by `public_key` over `message`.
fn verifies(public_key: &str, message: &str, sig_b64: &str) -> bool {
    let Ok(kp) = KeyPair::from_public_key(public_key) else { return false };
    let Ok(sig) = STANDARD.decode(sig_b64) else { return false };
    kp.verify(message.as_bytes(), &sig).is_ok()
}

fn renewer(
    api: Arc<FakeApi>,
    credential: &str,
    node_seed: &str,
    agents: Vec<RenewalAgent>,
) -> Arc<CredentialRenewer> {
    CredentialRenewer::new(CredentialRenewerOptions {
        api_base: "https://api.agentmesh.ai".into(),
        jwt: credential.to_string(),
        node_seed: node_seed.to_string(),
        agents: RenewalRoster::Fixed(agents),
        transport: Some(api),
        on_renewed: None,
        on_warning: None,
    })
}

// ── claims ──────────────────────────────────────────────────────────────────

#[test]
fn reads_sub_iat_and_exp_off_a_real_shaped_jwt() {
    let (node_id, _) = create_agent_identity().expect("identity");
    let claims = decode_credential_claims(&jwt(&node_id, Some(1_800_000_000), Some(1_802_592_000)))
        .expect("a JWT");
    assert_eq!(claims.sub.as_deref(), Some(node_id.as_str()));
    assert_eq!(claims.iat, Some(1_800_000_000));
    assert_eq!(claims.exp, Some(1_802_592_000));
}

#[test]
fn garbage_is_not_a_jwt() {
    assert_eq!(decode_credential_claims(""), None);
    assert_eq!(decode_credential_claims("not-a-jwt"), None);
    assert_eq!(decode_credential_claims("only.two"), None);
    assert_eq!(decode_credential_claims("a.b.c.d"), None);
    // Three segments, but the claim set will not base64-decode.
    assert_eq!(decode_credential_claims("aaaa.!!!!.cccc"), None);
    // Three segments, decodable, but not JSON.
    let not_json = URL_SAFE_NO_PAD.encode(b"hello there");
    assert_eq!(decode_credential_claims(&format!("aaaa.{not_json}.cccc")), None);
}

#[test]
fn a_jwt_that_says_nothing_about_its_lifetime_decodes_to_all_none() {
    // Not the same answer as "not a JWT": it IS one, it just carries no
    // schedulable window — the pre-§4.8 shape this module exists to retire.
    let claim_set = URL_SAFE_NO_PAD.encode(br#"{"nats":{"type":"user"}}"#);
    let claims = decode_credential_claims(&format!("aaaa.{claim_set}.cccc")).expect("a JWT");
    assert_eq!(claims, CredentialClaims::default());
    assert_eq!(credential_renew_at(&claims), None);
}

// ── the schedule ────────────────────────────────────────────────────────────

#[test]
fn renews_two_thirds_of_the_way_through_the_credentials_own_lifetime() {
    let iat = 1_800_000_000i64;
    let exp = iat + 30 * DAY_SEC;
    let at = credential_renew_at(&CredentialClaims {
        sub: None,
        iat: Some(iat),
        exp: Some(exp),
    })
    .expect("a deadline");
    // 20 days in, 10 days of runway left to retry in — exactly the vouch's
    // two thirds, from the same constant.
    assert_eq!(at, iat * 1000 + 20 * DAY_SEC * 1000);
    assert_eq!(at - iat * 1000, (exp - iat) * 1000 * 2 / 3);
}

#[test]
fn derives_the_deadline_from_the_jwt_not_from_a_configured_ttl() {
    // A credential minted under a shorter operator policy still gets a
    // proportionate deadline rather than the 30-day default's.
    let iat = 1_800_000_000i64;
    let at = credential_renew_at(&CredentialClaims {
        sub: None,
        iat: Some(iat),
        exp: Some(iat + 3),
    })
    .expect("a deadline");
    assert_eq!(at, iat * 1000 + 2_000);
}

#[test]
fn a_credential_that_never_expires_has_no_deadline() {
    assert_eq!(
        credential_renew_at(&CredentialClaims {
            sub: Some("UNODE".into()),
            iat: Some(1_800_000_000),
            exp: None,
        }),
        None
    );
    // ... and neither has one read off a JWT with no `exp` at all.
    let claims = decode_credential_claims(&jwt("UNODE", Some(1_800_000_000), None)).unwrap();
    assert_eq!(claims.exp, None);
    assert_eq!(credential_renew_at(&claims), None);
}

#[test]
fn checks_hourly_for_a_30_day_credential_and_proportionally_for_a_short_one() {
    let thirty_days_ms = 30 * DAY_SEC * 1000;
    assert_eq!(
        credential_check_interval(thirty_days_ms),
        Duration::from_millis(MAX_VOUCH_CHECK_INTERVAL_MS as u64),
        "capped at one hour"
    );
    // Four checks inside the last third of a 600ms lifetime.
    assert_eq!(credential_check_interval(600), Duration::from_millis(50));
    // Never a zero-delay spin.
    assert!(credential_check_interval(1) > Duration::ZERO);
    assert!(credential_check_interval(0) > Duration::ZERO);
}

// ── the signing contract ────────────────────────────────────────────────────

#[test]
fn signs_the_exact_canonical_lines_with_a_sorted_roster_and_an_unsorted_array() {
    let (node_id, node_seed) = create_agent_identity().expect("node identity");
    let mut ids: Vec<(String, String)> =
        (0..3).map(|_| create_agent_identity().expect("agent identity")).collect();
    ids.sort_by(|a, b| a.0.cmp(&b.0));
    let sorted: Vec<&str> = ids.iter().map(|(id, _)| id.as_str()).collect();

    // Hand them over in the WRONG order on purpose: the node's signature must
    // still cover the sorted roster, and the array must still be as passed.
    let input: Vec<RenewalAgent> = ids
        .iter()
        .rev()
        .map(|(id, seed)| RenewalAgent::with_seed(id.clone(), seed.clone()))
        .collect();

    let ts = 1_800_000_123i64;
    let req = build_credential_request(&node_seed, &input, ts).expect("a request");

    assert_eq!(req.node_id, node_id);
    assert_eq!(req.ts, ts);

    // The node line, byte for byte.
    let expected_line = format!("mesh-node-cred-v1:{ts}:{node_id}:{}", sorted.join(","));
    assert_eq!(node_credential_line(ts, &node_id, &sorted), expected_line);
    assert!(
        verifies(&node_id, &expected_line, &req.node_sig),
        "the node key signed the sorted roster"
    );

    // ... and NOT the order the caller passed, which is the whole point of
    // sorting: two hosts with the same agents must produce the same line.
    let caller_order: Vec<&str> = input.iter().map(|a| a.id.as_str()).collect();
    let unsorted_line = format!("mesh-node-cred-v1:{ts}:{node_id}:{}", caller_order.join(","));
    assert_ne!(unsorted_line, expected_line, "the test order really is unsorted");
    assert!(!verifies(&node_id, &unsorted_line, &req.node_sig));

    // The array keeps the caller's order, and each agent consented in its own
    // name with its own key.
    assert_eq!(
        req.agents.iter().map(|a| a.id.as_str()).collect::<Vec<_>>(),
        caller_order
    );
    for entry in &req.agents {
        let line = format!("mesh-node-agent-v1:{ts}:{node_id}:{}", entry.id);
        assert_eq!(agent_consent_line(ts, &node_id, &entry.id), line);
        assert!(verifies(&entry.id, &line, &entry.sig), "agent {} consented", entry.id);
        // One agent's consent cannot stand in for another's.
        for other in &req.agents {
            if other.id != entry.id {
                assert!(!verifies(&other.id, &line, &entry.sig));
            }
        }
    }
}

#[test]
fn a_signing_callback_consents_without_the_node_holding_the_seed() {
    let (node_id, node_seed) = create_agent_identity().expect("node identity");
    let (agent_id, agent_seed) = create_agent_identity().expect("agent identity");
    let kp = KeyPair::from_seed(&agent_seed).expect("agent keypair");
    let ts = 1_800_000_000i64;

    let req = build_credential_request(
        &node_seed,
        &[RenewalAgent::with_signer(agent_id.clone(), move |m| {
            STANDARD.encode(kp.sign(m.as_bytes()).expect("sign"))
        })],
        ts,
    )
    .expect("a request");

    let line = agent_consent_line(ts, &node_id, &agent_id);
    assert!(verifies(&agent_id, &line, &req.agents[0].sig));
    // Byte-identical to what the seed path would have produced: the callback is
    // a place the key lives, not a different signature.
    let by_seed = build_credential_request(
        &node_seed,
        &[RenewalAgent::with_seed(agent_id.clone(), agent_seed)],
        ts,
    )
    .expect("a request");
    assert_eq!(by_seed, req);
}

#[test]
fn refuses_a_request_it_cannot_honestly_sign() {
    let (_, node_seed) = create_agent_identity().expect("node identity");
    let (agent_id, _) = create_agent_identity().expect("agent identity");
    let (_, other_seed) = create_agent_identity().expect("another identity");

    // A credential covering nobody is not a thing.
    assert!(build_credential_request(&node_seed, &[], 1).is_err());
    // No seed and no callback: nothing to prove consent with.
    assert!(build_credential_request(
        &node_seed,
        &[RenewalAgent { id: agent_id.clone(), ..Default::default() }],
        1
    )
    .is_err());
    // A seed that derives a different key would produce a request the server
    // rejects with nothing local to explain why. Caught here instead.
    let err = build_credential_request(
        &node_seed,
        &[RenewalAgent::with_seed(agent_id.clone(), other_seed)],
        1,
    )
    .expect_err("mismatched seed");
    assert!(err.to_string().contains("does not match id"), "{err}");
}

#[test]
fn posts_to_the_v1_node_credential_endpoint() {
    assert_eq!(
        credential_endpoint("https://api.agentmesh.ai"),
        "https://api.agentmesh.ai/v1/node-credential"
    );
}

// ── the loop ────────────────────────────────────────────────────────────────

/// A credential issued at `now - age`, expiring 30 days after issue.
fn credential_aged(sub: &str, now_ms: i64, age_days: i64) -> String {
    let iat = now_ms / 1000 - age_days * DAY_SEC;
    jwt(sub, Some(iat), Some(iat + 30 * DAY_SEC))
}

#[tokio::test]
async fn a_credential_short_of_its_deadline_is_left_alone() {
    let (node_id, node_seed) = create_agent_identity().expect("node identity");
    let now = 1_800_000_000_000i64;
    let api = FakeApi::ok_with("fresh.credential.here");
    let r = renewer(
        Arc::clone(&api),
        &credential_aged(&node_id, now, 10), // 10 days into 30: deadline is day 20
        &node_seed,
        vec![RenewalAgent::with_seed(node_id.clone(), node_seed.clone())],
    );

    assert!(!r.renew_if_due(now).await, "not due");
    assert_eq!(api.call_count(), 0, "nothing was asked of the control plane");

    let status = r.status(now);
    assert!(!status.expired);
    assert_eq!(status.last_error, None);
    assert!(status.renew_at.is_some() && status.expires_at.is_some());
}

#[tokio::test]
async fn a_credential_past_its_deadline_is_renewed_and_adopted() {
    let (node_id, node_seed) = create_agent_identity().expect("node identity");
    let (agent_id, agent_seed) = create_agent_identity().expect("agent identity");
    let now = 1_800_000_000_000i64;
    let old = credential_aged(&node_id, now, 25); // 25 days into 30: past day 20
    // The replacement is young again, so adoption is observable in the status.
    let fresh = credential_aged(&node_id, now, 0);
    let api = FakeApi::ok_with(&fresh);

    let r = renewer(
        Arc::clone(&api),
        &old,
        &node_seed,
        vec![RenewalAgent::with_seed(agent_id.clone(), agent_seed)],
    );
    let deadline_before = r.status(now).renew_at;

    assert!(r.renew_if_due(now).await, "past the deadline, so renewed");
    assert_eq!(api.call_count(), 1);
    assert_eq!(api.last_url(), "https://api.agentmesh.ai/v1/node-credential");

    // The POST carried a properly signed request for exactly this roster.
    let body = api.last_body();
    assert_eq!(body["node_id"], serde_json::json!(node_id));
    assert_eq!(body["agents"][0]["id"], serde_json::json!(agent_id));
    let ts = body["ts"].as_i64().expect("a ts");
    assert!(verifies(
        &node_id,
        &node_credential_line(ts, &node_id, &[agent_id.as_str()]),
        body["node_sig"].as_str().unwrap()
    ));
    assert!(verifies(
        &agent_id,
        &agent_consent_line(ts, &node_id, &agent_id),
        body["agents"][0]["sig"].as_str().unwrap()
    ));

    // Adopted: the fresh credential is what the renewer now hands out, and the
    // deadline moved with it.
    assert_eq!(r.credential(), fresh);
    let after = r.status(now);
    assert_eq!(after.last_error, None);
    assert_ne!(after.renew_at, deadline_before, "the deadline moved forward");
    assert!(!after.expired);

    // A second call at the same instant is not due any more.
    assert!(!r.renew_if_due(now).await);
    assert_eq!(api.call_count(), 1);
}

#[tokio::test]
async fn an_already_expired_credential_still_renews_the_case_that_matters() {
    // A host powered off through its whole renewal window comes back with a
    // dead credential. Renewal is HTTPS, so it works anyway — that is the
    // property §4.8 rests on.
    let (node_id, node_seed) = create_agent_identity().expect("node identity");
    let now = 1_800_000_000_000i64;
    let dead = credential_aged(&node_id, now, 45); // 15 days past expiry
    let api = FakeApi::ok_with(&credential_aged(&node_id, now, 0));
    let r = renewer(
        Arc::clone(&api),
        &dead,
        &node_seed,
        vec![RenewalAgent::with_seed(node_id.clone(), node_seed.clone())],
    );

    assert!(r.status(now).expired, "the credential really is dead");
    assert!(r.renew_if_expiring(now).await, "and it renews anyway");
    assert_eq!(api.call_count(), 1);
    assert!(!r.status(now).expired);
}

#[tokio::test]
async fn a_refusal_is_recorded_warned_about_and_retried_from_the_same_deadline() {
    let (node_id, node_seed) = create_agent_identity().expect("node identity");
    let now = 1_800_000_000_000i64;
    let old = credential_aged(&node_id, now, 25);
    let api = FakeApi::refusing(403, "this node's registration was retired");

    let seen: Arc<Mutex<Vec<SecurityWarning>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    let r = CredentialRenewer::new(CredentialRenewerOptions {
        api_base: "https://api.agentmesh.ai".into(),
        jwt: old.clone(),
        node_seed: node_seed.clone(),
        agents: RenewalRoster::Fixed(vec![RenewalAgent::with_seed(
            node_id.clone(),
            node_seed.clone(),
        )]),
        transport: Some(api.clone()),
        on_renewed: None,
        on_warning: Some(Arc::new(move |w| sink.lock().unwrap().push(w))),
    });
    let deadline = r.status(now).renew_at;

    assert!(!r.renew_if_due(now).await);
    assert_eq!(r.credential(), old, "the old credential is still what we hold");

    let status = r.status(now);
    assert_eq!(
        status.last_error.as_deref(),
        Some("transport: this node's registration was retired"),
        "the server's own words, not just an HTTP code"
    );
    assert_eq!(status.renew_at, deadline, "the deadline stays put so the next tick retries");

    {
        let warnings = seen.lock().unwrap();
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].code, "credential_renewal_failed");
        assert_eq!(warnings[0].subject.as_deref(), Some(node_id.as_str()));
        assert!(warnings[0].message.contains("registration was retired"), "{}", warnings[0].message);
        assert!(warnings[0].message.contains("cannot open a connection to the mesh"));
    }

    // Still due, so the next pass tries again.
    assert!(!r.renew_if_due(now).await);
    assert_eq!(api.call_count(), 2);
}

#[tokio::test]
async fn an_unpersisted_renewal_does_not_count_as_a_renewal() {
    // `on_renewed` is where the host writes the credential down. If that fails,
    // adopting the new JWT would clear the deadline that gets us retried — and
    // the next process start would come back holding the OLD credential with
    // nothing scheduled to fix it.
    let (node_id, node_seed) = create_agent_identity().expect("node identity");
    let now = 1_800_000_000_000i64;
    let old = credential_aged(&node_id, now, 25);
    let fresh = credential_aged(&node_id, now, 0);
    let api = FakeApi::ok_with(&fresh);

    let offered: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_by_host = Arc::clone(&offered);
    let r = CredentialRenewer::new(CredentialRenewerOptions {
        api_base: "https://api.agentmesh.ai".into(),
        jwt: old.clone(),
        node_seed: node_seed.clone(),
        agents: RenewalRoster::Fixed(vec![RenewalAgent::with_seed(
            node_id.clone(),
            node_seed.clone(),
        )]),
        transport: Some(api.clone()),
        on_renewed: Some(Arc::new(move |c| {
            let seen = Arc::clone(&seen_by_host);
            Box::pin(async move {
                seen.lock().unwrap().push(c.jwt.clone());
                Err(agentmesh::MeshError::Transport("disk is read-only".into()))
            })
        })),
        on_warning: None,
    });
    let deadline = r.status(now).renew_at;

    assert!(!r.renew_if_due(now).await, "a renewal that was not written down did not happen");
    assert_eq!(api.call_count(), 1, "the control plane WAS asked");
    assert_eq!(
        offered.lock().unwrap().as_slice(),
        std::slice::from_ref(&fresh),
        "and the host was offered the fresh credential"
    );

    // ... but nothing was adopted.
    assert_eq!(r.credential(), old);
    let status = r.status(now);
    assert_eq!(status.renew_at, deadline, "still due, so the next tick retries");
    assert!(status.last_error.as_deref().unwrap().contains("disk is read-only"));

    // Persisting works on the retry, and only then is the credential adopted.
    let ok: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let r2 = CredentialRenewer::new(CredentialRenewerOptions {
        api_base: "https://api.agentmesh.ai".into(),
        jwt: old.clone(),
        node_seed: node_seed.clone(),
        agents: RenewalRoster::Fixed(vec![RenewalAgent::with_seed(node_id, node_seed)]),
        transport: Some(api),
        on_renewed: Some(Arc::new({
            let ok = Arc::clone(&ok);
            move |c| {
                let ok = Arc::clone(&ok);
                Box::pin(async move {
                    ok.lock().unwrap().push(c.jwt);
                    Ok(())
                })
            }
        })),
        on_warning: None,
    });
    assert!(r2.renew_if_due(now).await);
    assert_eq!(r2.credential(), fresh);
    assert_eq!(ok.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn a_dynamic_roster_is_read_at_renewal_time() {
    // The node case: an agent added after the loop started is covered by the
    // next credential, with no bookkeeping at the renewer.
    let (node_id, node_seed) = create_agent_identity().expect("node identity");
    let (first_id, first_seed) = create_agent_identity().expect("agent identity");
    let (late_id, late_seed) = create_agent_identity().expect("agent identity");
    let now = 1_800_000_000_000i64;

    let hosted: Arc<Mutex<Vec<(String, String)>>> =
        Arc::new(Mutex::new(vec![(first_id.clone(), first_seed)]));
    let roster_src = Arc::clone(&hosted);
    let api = FakeApi::ok_with(&credential_aged(&node_id, now, 25));

    let r = CredentialRenewer::new(CredentialRenewerOptions {
        api_base: "https://api.agentmesh.ai".into(),
        jwt: credential_aged(&node_id, now, 25),
        node_seed,
        agents: RenewalRoster::dynamic(move || {
            roster_src
                .lock()
                .unwrap()
                .iter()
                .map(|(id, seed)| RenewalAgent::with_seed(id.clone(), seed.clone()))
                .collect()
        }),
        transport: Some(api.clone()),
        on_renewed: None,
        on_warning: None,
    });

    assert!(r.renew_if_due(now).await);
    assert_eq!(api.last_body()["agents"].as_array().unwrap().len(), 1);

    hosted.lock().unwrap().push((late_id.clone(), late_seed));
    r.renew().await.expect("a second renewal");
    let ids: Vec<String> = api.last_body()["agents"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["id"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(ids, vec![first_id, late_id], "the agent added later is covered");
}

#[tokio::test]
async fn a_credential_with_no_expiry_is_never_due() {
    let (node_id, node_seed) = create_agent_identity().expect("node identity");
    let api = FakeApi::ok_with("unused.credential.here");
    let r = renewer(
        Arc::clone(&api),
        &jwt(&node_id, Some(1_700_000_000), None),
        &node_seed,
        vec![RenewalAgent::with_seed(node_id.clone(), node_seed.clone())],
    );

    // Far in the future, and still nothing to renew before: there is no
    // deadline to be past. `expires_at: None` is a finding, not health.
    assert!(!r.renew_if_due(2_000_000_000_000).await);
    assert_eq!(api.call_count(), 0);
    let status = r.status(2_000_000_000_000);
    assert_eq!(status.expires_at, None);
    assert_eq!(status.renew_at, None);
    assert!(!status.expired);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn start_is_idempotent_and_stop_really_stops() {
    let (node_id, node_seed) = create_agent_identity().expect("node identity");
    // The loop reads the REAL wall clock — that is the whole point of a
    // periodic check — so this fixture is anchored to it rather than to a fixed
    // instant. A one-second lease that expired nine seconds ago: checks land
    // every 83ms and every one of them is due, so the loop is easy to observe.
    // The replacement is the same stale credential, so it stays due.
    let now_sec = agentmesh::now_ms() / 1000;
    let stale = jwt(&node_id, Some(now_sec - 10), Some(now_sec - 9));
    let api = FakeApi::ok_with(&stale);
    let r = renewer(
        Arc::clone(&api),
        &stale,
        &node_seed,
        vec![RenewalAgent::with_seed(node_id.clone(), node_seed.clone())],
    );

    r.start();
    r.start(); // idempotent: the second call replaces the loop, never adds one
    tokio::time::sleep(Duration::from_millis(300)).await;
    let while_running = api.call_count();
    assert!(while_running >= 2, "the loop ticked ({while_running} calls)");

    // ONE stop for TWO starts. If `start` had left two tasks behind, the
    // survivor would keep renewing and this count would move.
    //
    // `stop` cannot un-fire a request already in flight, and at an 83ms cadence
    // there usually is one, so the count is read AFTER that last call has had
    // time to land rather than at the instant of stopping. Asserting the count
    // then stays put is the stronger claim anyway: it says the loop is dead,
    // where an exact count at the moment of stopping only says it was quick.
    // The drop case below already made this allowance; this one did not, and
    // that is the whole of the flake it produced in CI.
    r.stop();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let settled = api.call_count();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(api.call_count(), settled, "one stop stops the only loop");
    assert!(
        settled <= while_running + 1,
        "stop let more than one in-flight call land ({while_running} running, {settled} settled)"
    );

    // Dropping the last handle stops it too: the task holds a WEAK reference,
    // so a renewal loop can never be what keeps a renewer (or the node holding
    // it) alive.
    r.start();
    let at_drop = api.call_count();
    drop(r);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        api.call_count() <= at_drop + 1,
        "the loop went with its renewer (one tick may already be in flight)"
    );
}

// ── the client surface ──────────────────────────────────────────────────────

#[tokio::test]
async fn an_unwatched_credential_reports_nothing_and_refuses_a_manual_renewal() {
    // A node with no `credential_renewal` is not claiming its credential is
    // healthy — it is saying nothing is watching it.
    // `with_client` is the only way to build a node without dialling, and it
    // still wants a connection handle — so this one needs a broker present.
    let Ok(conn) = async_nats::connect("nats://127.0.0.1:4222").await else {
        eprintln!("skipping: no NATS server at 127.0.0.1:4222");
        return;
    };
    let node = agentmesh::MeshNode::with_client(conn, agentmesh::NodeConnectOptions::default())
        .expect("a node");

    assert_eq!(node.credential(), agentmesh::CredentialStatus::default());
    let err = node.renew_credential().await.expect_err("no renewal configured");
    assert!(err.to_string().contains("without credential_renewal"), "{err}");
    assert!(!node.renew_credential_if_due(agentmesh::now_ms()).await);
    node.close().await;
}
