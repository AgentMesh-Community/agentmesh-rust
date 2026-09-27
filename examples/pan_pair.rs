//! PAN §4.2 pairing signer — the proof that pairing is host-neutral.
//!
//! Given a pairing code (from the registrar's "pair" action) and the agent's
//! seed, signs the canonical string `pan-pair-v1:<code>:<agent-id>` and
//! prints the completion request. Anything holding the key can do this; this
//! example is the whole of what a "host integration" requires.
//!
//! Usage: cargo run --example pan_pair -- <code> <agent-seed>

use base64::Engine;
use nkeys::KeyPair;

fn main() {
    let mut args = std::env::args().skip(1);
    let (Some(code), Some(seed)) = (args.next(), args.next()) else {
        eprintln!("usage: pan_pair <code> <agent-seed>");
        std::process::exit(2);
    };

    let kp = KeyPair::from_seed(&seed).expect("invalid seed");
    let agent_id = kp.public_key();
    let msg = format!("pan-pair-v1:{code}:{agent_id}");
    let sig = kp.sign(msg.as_bytes()).expect("sign");
    let signature = base64::engine::general_purpose::STANDARD.encode(sig);

    let body = serde_json::json!({ "code": code, "agent_id": agent_id, "signature": signature });
    println!("{body}");
    eprintln!("\nsend it:\n  curl -X POST <registrar>/api/pair/complete -H \"Content-Type: application/json\" -d '{body}'");
}
