//! Cross-implementation signature check.
//!   1. Verify a TS-signed envelope (proves Rust canonicalization matches TS).
//!   2. Emit a Rust-signed envelope for TS to verify (the reverse direction).
//! Run: cargo run --example xcheck

use agentmesh::{codec, sign_envelope, Envelope, PrimitiveType};
use nkeys::KeyPair;
use serde_json::json;
use std::fs;
use std::path::Path;

fn main() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");

    // 1. TS → Rust
    let ts_path = dir.join("ts_signed.json");
    let bytes = fs::read(&ts_path).expect("read ts_signed.json (run the TS emit step first)");
    match codec::decode(&bytes) {
        Ok(env) => println!(
            "Rust verifies TS-signed envelope: PASS  (from={}, payload preserved={})",
            &env.from[..12.min(env.from.len())],
            env.payload.is_some()
        ),
        Err(e) => {
            println!("Rust verifies TS-signed envelope: FAIL — {e}");
            std::process::exit(1);
        }
    }

    // 2. Rust → TS
    let kp = KeyPair::new_user();
    let mut env = Envelope::new(PrimitiveType::Request, kp.public_key());
    env.to = Some("UDEST".to_string());
    env.payload = Some(json!({ "z": 1, "a": "héllo/世界", "nested": { "b": true, "arr": [3, 2, 1], "n": null } }));
    sign_envelope(&mut env, &kp).unwrap();
    fs::write(dir.join("rust_signed.json"), serde_json::to_vec_pretty(&env).unwrap()).unwrap();
    println!("Rust emitted rust_signed.json  from={}", &kp.public_key()[..12]);
}
