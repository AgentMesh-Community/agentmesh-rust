//! PACT 1.0 for agent builders (BRIDGE-A2A.md §14.6, §14.8; the TypeScript
//! SDK's `pact` namespace, src/pact/agent.ts, is the same set).
//!
//! An agent that serves a business on AgentMesh is handed each PACT turn on
//! the envelope's `meta.pact` (and, for a packaged agent, in its job's context
//! bag). Under a person's permission the turn carries a delegation token.
//! Check it with [`check_delegation`] before acting on anybody's account. Then
//! answer with [`pact_report`] (what was used and done, for the receipt) or
//! [`pact_needs_permission`] (what is missing, for the step-up).
//!
//! For anyone who is their own personal-agent platform: [`sign_pa_jwt`] makes
//! the per-request JWT, and, with the `http` feature, [`send_pact_message`]
//! talks to a business and [`fetch_gateway_keys`] reads a Brand's keys.
//!
//! ES256 only: AgentMesh's gateway signs with ES256, and a token in any other
//! algorithm is refused here rather than half-checked.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

/// The context bag schema of a PACT turn.
pub const PACT_TURN_SCHEMA: &str = "https://schemas.agentmesh.ai/pact-delegation/v1";
/// AgentMesh's A2A gateways, production and dev.
pub const AGENTMESH_GATEWAYS: [&str; 2] = ["https://a2a.agentmesh.ai", "https://a2a.dev.agentmesh.ai"];
/// Clock skew allowed on `exp` (PACT §3.2).
pub const MAX_SKEW_S: i64 = 30;

/// A delegation the agent checked.
#[derive(Debug, Clone, PartialEq)]
pub struct CheckedDelegation {
    /// The person's id at the business.
    pub person: String,
    pub scopes: Vec<String>,
    pub grant_id: Option<String>,
    pub interface_url: String,
    pub expires_at: i64,
}

/// What a token must satisfy.
pub struct CheckRules<'a> {
    /// The personal-agent platform that sent the turn (`meta.pact.pa`).
    pub pa_issuer: &'a str,
    /// This Brand's interface URL, when the agent knows it; else any interface on `gateways`.
    pub interface_url: Option<&'a str>,
    pub gateways: &'a [&'a str],
    /// The Brand's keys (a JWKS's `keys`), from `{interface}/oauth/jwks.json`.
    pub keys: &'a [Value],
    pub now: i64,
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn unb64(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')).ok()
}

/// A compact JWS's header and claims, decoded and unchecked.
pub fn decode_jwt(token: &str) -> Option<(Value, Value)> {
    let mut parts = token.split('.');
    let (h, p, s) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || s.is_empty() {
        return None;
    }
    let header: Value = serde_json::from_slice(&unb64(h)?).ok()?;
    let claims: Value = serde_json::from_slice(&unb64(p)?).ok()?;
    if !header.is_object() || !claims.is_object() {
        return None;
    }
    Some((header, claims))
}

fn verifying_key(jwk: &Value) -> Option<VerifyingKey> {
    if jwk.get("kty")?.as_str()? != "EC" || jwk.get("crv")?.as_str()? != "P-256" {
        return None;
    }
    let x = unb64(jwk.get("x")?.as_str()?)?;
    let y = unb64(jwk.get("y")?.as_str()?)?;
    if x.len() != 32 || y.len() != 32 {
        return None;
    }
    let mut sec1 = vec![4u8];
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    VerifyingKey::from_sec1_bytes(&sec1).ok()
}

/// Whether an ES256 compact JWS verifies against one of `keys` (by `kid` when it names one).
pub fn verify_es256(token: &str, keys: &[Value]) -> bool {
    let Some((header, _)) = decode_jwt(token) else { return false };
    if header.get("alg").and_then(Value::as_str) != Some("ES256") {
        return false;
    }
    let Some(dot) = token.rfind('.') else { return false };
    let (signing_input, sig) = (&token[..dot], &token[dot + 1..]);
    let Some(sig) = unb64(sig).and_then(|b| Signature::from_slice(&b).ok()) else { return false };
    let kid = header.get("kid").and_then(Value::as_str);
    keys.iter()
        .filter(|k| kid.is_none() || k.get("kid").and_then(Value::as_str) == kid)
        .filter_map(verifying_key)
        .any(|vk| vk.verify(signing_input.as_bytes(), &sig).is_ok())
}

/// Check a delegation token before acting on anybody's account (PACT §5.4,
/// §5.5): `typ: at+jwt`, ES256, audience this Brand's interface, issuer its
/// authorization server, `client_id` the personal agent that sent the turn,
/// not expired, signed by one of the Brand's keys. `None` when anything fails.
pub fn check_delegation(token: &str, rules: &CheckRules) -> Option<CheckedDelegation> {
    let (header, c) = decode_jwt(token)?;
    if header.get("typ").and_then(Value::as_str) != Some("at+jwt") {
        return None;
    }
    let aud = c.get("aud")?.as_str()?.trim_end_matches('/');
    match rules.interface_url {
        Some(iface) => {
            if aud != iface.trim_end_matches('/') {
                return None;
            }
        }
        None => {
            let (origin, path) = split_origin(aud)?;
            let ok_path = path.starts_with("/a2a/") && path.len() > 5 && !path[5..].contains('/');
            if !rules.gateways.contains(&origin) || !ok_path {
                return None;
            }
        }
    }
    if c.get("iss")?.as_str()? != format!("{aud}/oauth") || c.get("client_id")?.as_str()? != rules.pa_issuer {
        return None;
    }
    let exp = c.get("exp")?.as_i64()?;
    if exp < rules.now - MAX_SKEW_S {
        return None;
    }
    let person = c.get("sub")?.as_str().filter(|s| !s.is_empty())?.to_string();
    let scope = c.get("scope")?.as_str()?;
    if !verify_es256(token, rules.keys) {
        return None;
    }
    let mut scopes: Vec<String> = Vec::new();
    for s in scope.split_whitespace() {
        if !scopes.iter().any(|x| x == s) {
            scopes.push(s.to_string());
        }
    }
    Some(CheckedDelegation {
        person,
        scopes,
        grant_id: c.get("grant_id").and_then(Value::as_str).map(str::to_string),
        interface_url: aud.to_string(),
        expires_at: exp,
    })
}

/// `https://host[:port]` and the path of an absolute https URL.
fn split_origin(url: &str) -> Option<(&str, &str)> {
    let rest = url.strip_prefix("https://")?;
    let cut = rest.find('/').unwrap_or(rest.len());
    let origin = &url[..8 + cut];
    Some((origin, &url[8 + cut..]))
}

/// The scopes a turn needs and the person has not allowed.
pub fn missing_scopes(held: Option<&CheckedDelegation>, needed: &[&str]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for n in needed {
        let have = held.map(|h| h.scopes.iter().any(|s| s == n)).unwrap_or(false);
        if !have && !out.iter().any(|x| x == n) {
            out.push((*n).to_string());
        }
    }
    out
}

/// The output of a turn done on the person's account: `{text, pact: {scopes_used, actions}}`.
/// Each action is `(tool, args_hash)`.
pub fn pact_report(text: &str, scopes_used: &[&str], actions: &[(&str, Option<&str>)]) -> Value {
    let mut used: Vec<&str> = Vec::new();
    for s in scopes_used {
        if !used.contains(s) {
            used.push(s);
        }
    }
    let actions: Vec<Value> = actions
        .iter()
        .map(|(tool, h)| match h {
            Some(h) => json!({ "tool": tool, "argsHash": h }),
            None => json!({ "tool": tool }),
        })
        .collect();
    json!({ "text": text, "pact": { "scopes_used": used, "actions": actions } })
}

/// The output of a turn that needs more permission: the gateway answers it with the step-up task.
pub fn pact_needs_permission(text: &str, missing: &[&str]) -> Value {
    json!({ "text": text, "pact": { "missing_scopes": missing } })
}

/// A receipt's `argsHash`: base64url SHA-256 of the arguments as canonical
/// JSON (RFC 8785), or of a string as itself.
pub fn args_hash(args: &Value) -> String {
    let text = match args {
        Value::String(s) => s.clone(),
        other => serde_jcs::to_string(other).unwrap_or_default(),
    };
    b64(&Sha256::digest(text.as_bytes()))
}

/// A personal-agent JWT (PACT §3.2), ES256, signed with a private P-256 JWK
/// (`d`, `x`, `y`): `iss`, `sub`, `aud`, `iat` now and `exp` two minutes on.
pub fn sign_pa_jwt(private_jwk: &Value, iss: &str, sub: &str, aud: &str, now: i64) -> Option<String> {
    let d = unb64(private_jwk.get("d")?.as_str()?)?;
    let key = SigningKey::from_slice(&d).ok()?;
    let mut header = Map::new();
    header.insert("alg".into(), json!("ES256"));
    header.insert("typ".into(), json!("JWT"));
    if let Some(kid) = private_jwk.get("kid") {
        header.insert("kid".into(), kid.clone());
    }
    let claims = json!({ "iss": iss, "sub": sub, "aud": aud, "iat": now, "exp": now + 120 });
    let signing_input = format!("{}.{}", b64(Value::Object(header).to_string().as_bytes()), b64(claims.to_string().as_bytes()));
    let sig: Signature = key.sign(signing_input.as_bytes());
    Some(format!("{signing_input}.{}", b64(&sig.to_bytes())))
}

/// The PACT turn on an envelope's meta (`meta.pact`), or `None`.
pub fn pact_turn_from_meta(meta: &Value) -> Option<&Value> {
    let t = meta.get("pact")?;
    (t.get("pa")?.is_string() && t.get("user")?.is_string()).then_some(t)
}

/// A Brand's keys from `{interface}/oauth/jwks.json`.
#[cfg(feature = "http")]
pub async fn fetch_gateway_keys(client: &reqwest::Client, interface_url: &str) -> Option<Vec<Value>> {
    let url = format!("{}/oauth/jwks.json", interface_url.trim_end_matches('/'));
    let text = client.get(url).send().await.ok()?.error_for_status().ok()?.text().await.ok()?;
    let body: Value = serde_json::from_str(&text).ok()?;
    body.get("keys")?.as_array().cloned()
}

/// One message to a business (PACT §4, §5.5): the answer's JSON (`message` or
/// the step-up `task`), or the HTTP status and body when it was not 200.
#[cfg(feature = "http")]
pub async fn send_pact_message(
    client: &reqwest::Client,
    interface_url: &str,
    text: &str,
    pa_jwt: &str,
    delegation_token: Option<&str>,
    context_id: Option<&str>,
) -> Result<Value, (u16, String)> {
    let mut message = json!({ "messageId": uuid::Uuid::now_v7().to_string(), "role": "ROLE_USER", "parts": [{ "text": text }] });
    if let Some(c) = context_id {
        message["contextId"] = json!(c);
    }
    let mut req = client
        .post(format!("{}/message:send", interface_url.trim_end_matches('/')))
        .header("Authorization", format!("Bearer {pa_jwt}"))
        .header("A2A-Version", "1.0")
        .header("Content-Type", "application/json")
        .body(json!({ "message": message }).to_string());
    if let Some(d) = delegation_token {
        req = req.header("X-A2A-User-Delegation", format!("Bearer {d}"));
    }
    let res = req.send().await.map_err(|e| (0, e.to_string()))?;
    let status = res.status().as_u16();
    let body = res.text().await.unwrap_or_default();
    if status != 200 {
        return Err((status, body));
    }
    serde_json::from_str(&body).map_err(|e| (status, e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::elliptic_curve::rand_core::OsRng;

    fn keypair() -> (Value, Value, SigningKey) {
        let sk = SigningKey::random(&mut OsRng);
        let point = sk.verifying_key().to_encoded_point(false);
        let x = b64(point.x().unwrap());
        let y = b64(point.y().unwrap());
        let private = json!({ "kty": "EC", "crv": "P-256", "x": x, "y": y, "d": b64(&sk.to_bytes()), "kid": "k1" });
        let public = json!({ "kty": "EC", "crv": "P-256", "x": x, "y": y, "kid": "k1" });
        (private, public, sk)
    }

    fn token(sk: &SigningKey, claims: Value, typ: &str) -> String {
        let h = b64(json!({ "alg": "ES256", "typ": typ, "kid": "k1" }).to_string().as_bytes());
        let p = b64(claims.to_string().as_bytes());
        let sig: Signature = sk.sign(format!("{h}.{p}").as_bytes());
        format!("{h}.{p}.{}", b64(&sig.to_bytes()))
    }

    const IFACE: &str = "https://a2a.agentmesh.ai/a2a/UBRAND";
    const PA: &str = "https://pa.example/pact";

    #[test]
    fn checks_a_delegation_token_and_refuses_the_rest() {
        let (_, public, sk) = keypair();
        let now = 1_791_000_000;
        let claims = |over: Value| {
            let mut c = json!({ "iss": format!("{IFACE}/oauth"), "aud": IFACE, "sub": "person-1", "client_id": PA, "scope": "orders:read orders:read", "grant_id": "pactgrant_1", "iat": now, "exp": now + 3600 });
            for (k, v) in over.as_object().unwrap() {
                c[k] = v.clone();
            }
            c
        };
        let keys = [public];
        let rules = CheckRules { pa_issuer: PA, interface_url: None, gateways: &AGENTMESH_GATEWAYS, keys: &keys, now };
        let ok = check_delegation(&token(&sk, claims(json!({})), "at+jwt"), &rules).unwrap();
        assert_eq!(ok.person, "person-1");
        assert_eq!(ok.scopes, vec!["orders:read"]);
        assert_eq!(ok.grant_id.as_deref(), Some("pactgrant_1"));
        let other = SigningKey::random(&mut OsRng);
        for (why, t) in [
            ("another gateway", token(&sk, claims(json!({ "aud": "https://evil.example/a2a/X", "iss": "https://evil.example/a2a/X/oauth" })), "at+jwt")),
            ("another personal agent", token(&sk, claims(json!({ "client_id": "https://other.example" })), "at+jwt")),
            ("expired", token(&sk, claims(json!({ "exp": now - 120 })), "at+jwt")),
            ("not an access token", token(&sk, claims(json!({})), "JWT")),
            ("another key", token(&other, claims(json!({})), "at+jwt")),
        ] {
            assert!(check_delegation(&t, &rules).is_none(), "{why}");
        }
        let pinned = CheckRules { interface_url: Some("https://a2a.agentmesh.ai/a2a/UOTHER"), ..rules };
        assert!(check_delegation(&token(&sk, claims(json!({})), "at+jwt"), &pinned).is_none());
    }

    #[test]
    fn reports_and_hashes_as_the_typescript_sdk_does() {
        assert_eq!(missing_scopes(None, &["orders:read", "orders:read"]), vec!["orders:read"]);
        assert_eq!(
            pact_report("Done.", &["orders:read", "orders:read"], &[("lookup_orders", None)]),
            json!({ "text": "Done.", "pact": { "scopes_used": ["orders:read"], "actions": [{ "tool": "lookup_orders" }] } })
        );
        assert_eq!(pact_needs_permission("Need OK.", &["orders:cancel"]), json!({ "text": "Need OK.", "pact": { "missing_scopes": ["orders:cancel"] } }));
        // The same value the TypeScript SDK and the shop-desk package give.
        assert_eq!(args_hash(&json!("LG-1043")), "xvttFnAwuRxJPlfxED4tNNBMBIE6v7Gx0TN8efVwsjo");
        assert_eq!(args_hash(&json!({ "b": 1, "a": 2 })), args_hash(&json!({ "a": 2, "b": 1 })));
    }

    #[test]
    fn signs_a_personal_agent_jwt_that_verifies() {
        let (private, public, _) = keypair();
        let t = sign_pa_jwt(&private, PA, "person-1", "https://p.example/a2a", 1_791_000_000).unwrap();
        assert!(verify_es256(&t, &[public]));
        let (_, claims) = decode_jwt(&t).unwrap();
        assert_eq!(claims["exp"], json!(1_791_000_120));
        assert!(pact_turn_from_meta(&json!({ "pact": { "pa": PA, "user": "u", "context": "c" } })).is_some());
        assert!(pact_turn_from_meta(&json!({})).is_none());
    }
}
