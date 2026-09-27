//! Raw cross-impl probe: send a signed echo request, print the RAW reply,
//! then check Rust-side verification + canonical form.
use agentmesh::{canonical_json, sign_envelope, verify_envelope_sig, Envelope, KeyPair, PrimitiveType};
use serde_json::Value;

#[tokio::main]
async fn main() {
    let url = std::env::var("URL").unwrap();
    let jwt = std::env::var("JWT").unwrap();
    let seed = std::env::var("SEED").unwrap(); // signing key bound to the JWT
    let echo_id = std::env::var("ECHO").unwrap();

    let seed2 = seed.clone();
    let client = async_nats::ConnectOptions::with_jwt(jwt, move |nonce| {
        let s = seed2.clone();
        async move {
            let kp = KeyPair::from_seed(&s).map_err(|e| async_nats::AuthError::new(e.to_string()))?;
            kp.sign(&nonce).map_err(|e| async_nats::AuthError::new(e.to_string()))
        }
    })
    .connect(&url)
    .await
    .expect("connect");

    // Sign the request with the SAME key (self-hosted agent = the pool key).
    let kp = KeyPair::from_seed(&seed).expect("kp");
    let mut env = Envelope::new(PrimitiveType::Request, kp.public_key());
    env.to = Some(echo_id.clone());
    env.payload = Some(serde_json::json!({ "offering": "echo", "input": { "n": 1 } }));
    sign_envelope(&mut env, &kp).expect("sign");

    let resp = client
        .request(format!("mesh.agent.{}.inbox", echo_id), serde_json::to_vec(&env).unwrap().into())
        .await
        .expect("request");

    let raw = String::from_utf8_lossy(&resp.payload);
    println!("RAW_REPLY={}", raw);

    let parsed: Envelope = serde_json::from_slice(&resp.payload).expect("parse");
    println!("RUST_VERIFY={}", verify_envelope_sig(&parsed));

    // What Rust thinks was signed:
    let mut v: Value = serde_json::from_slice(&resp.payload).unwrap();
    v.as_object_mut().unwrap().remove("sig");
    println!("RUST_CANONICAL={}", canonical_json(&v));
}
