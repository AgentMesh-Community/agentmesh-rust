//! Sandbox connectivity probe: connect with a credential issued to an account (the no-signup guest door closed on 2026-09-27), print
//! connection events, then send a signed echo request.
//! Run: URL=... JWT=... SEED=... ECHO=... cargo run --example sandbox_probe
use agentmesh::{sign_envelope, Envelope, KeyPair, PrimitiveType};

#[tokio::main]
async fn main() {
    let url = std::env::var("URL").unwrap();
    let jwt = std::env::var("JWT").unwrap();
    let seed = std::env::var("SEED").unwrap();
    let echo_id = std::env::var("ECHO").unwrap();

    let seed2 = seed.clone();
    let client = async_nats::ConnectOptions::with_jwt(jwt, move |nonce| {
        let s = seed2.clone();
        async move {
            let kp = KeyPair::from_seed(&s).map_err(|e| async_nats::AuthError::new(e.to_string()))?;
            kp.sign(&nonce).map_err(|e| async_nats::AuthError::new(e.to_string()))
        }
    })
    .event_callback(|event| async move {
        println!("EVENT: {event}");
    })
    .connect(&url)
    .await
    .expect("connect");

    client.flush().await.expect("flush");
    println!("CONNECTED state={:?}", client.connection_state());

    let kp = KeyPair::from_seed(&seed).expect("kp");
    let mut env = Envelope::new(PrimitiveType::Request, kp.public_key());
    env.to = Some(echo_id.clone());
    env.payload = Some(serde_json::json!({ "offering": "echo", "input": { "probe": true } }));
    sign_envelope(&mut env, &kp).expect("sign");

    match tokio::time::timeout(
        std::time::Duration::from_secs(15),
        client.request(
            format!("mesh.agent.{}.inbox", echo_id),
            serde_json::to_vec(&env).unwrap().into(),
        ),
    )
    .await
    {
        Ok(Ok(resp)) => println!("REPLY={}", String::from_utf8_lossy(&resp.payload)),
        Ok(Err(e)) => println!("REQUEST_ERR={e}"),
        Err(_) => println!("REQUEST_TIMEOUT"),
    }
}
