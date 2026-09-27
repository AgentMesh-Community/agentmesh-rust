//! The Rust conformance agent: the `agentmesh` crate as the AGENT UNDER TEST
//! for `conformance/core`, driven over that suite's line protocol.
//!
//! Until this existed, every core conformance test that needed a live agent was
//! an assertion about the TypeScript SDK, because the Node runner can only
//! import Node. This binary is the seam: the harness spawns it, tells it who to
//! be and what to register, and reads back what it observed — so the same test
//! can be pointed at either implementation.
//!
//! It is deliberately the thinnest possible wrapper. It contains no protocol
//! logic of its own: envelopes, signatures, registration and dispatch are all
//! the crate's, and every offering has one fixed behaviour (answer `{"ok": input}`
//! and report a `handled` event). Judgement lives in the harness, which
//! verifies what this reports with the reference verifier. Anything
//! test-specific added here would make the suite test this file instead of the
//! crate.
//!
//! Build (the harness will not build it for you — a cold `cargo run` inside a
//! test makes the test's result a statement about the host's build cache):
//!
//! ```text
//! cd sdk-rust && cargo build --example conformance_agent
//! ```
//!
//! Run: the harness sets MESH_URL, MESH_CREDS_JWT, MESH_CREDS_SEED and
//! MESH_AGENT_SEED, writes commands on stdin and reads events on stdout. See
//! `conformance/core/lib/agent-under-test.mjs` for the protocol.
//!
//! `register` accepts `name`, `visibility`, `offerings`, and — for c14 (§8.2) and
//! c07 (EXT-6) — `interaction` and `guarded`. The harness's own driver forwards
//! only the first three today, so a test that needs the last two needs that
//! driver widened as well; this side is not the blocker.

use agentmesh::{AgentMesh, ConnectOptions, RegisterOptions, Offering};
use serde_json::{json, Value};
use std::io::{BufRead, Write};

/// One JSON object per line on stdout. Rust's stdout is line-buffered, but the
/// flush is explicit because a lost line here reads to the harness as a hung
/// agent.
fn say(v: &Value) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{v}");
    let _ = out.flush();
}

fn required(key: &str) -> String {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => v,
        _ => {
            eprintln!("{key} is not set");
            std::process::exit(2);
        }
    }
}

fn str_at(v: &Value, key: &str) -> String {
    v.get(key).and_then(|x| x.as_str()).unwrap_or("").to_string()
}

#[tokio::main]
async fn main() {
    let url = required("MESH_URL");
    let jwt = required("MESH_CREDS_JWT");
    let creds_seed = required("MESH_CREDS_SEED");
    let agent_seed = required("MESH_AGENT_SEED");

    let agent = match AgentMesh::connect(
        &url,
        ConnectOptions {
            agent_seed: Some(agent_seed),
            // The crate signs the broker's auth nonce with the NODE key, so the
            // durable credential's key is declared as this agent's node: the
            // agent keeps its own ephemeral identity and the node vouches for
            // it (§4.4). The TypeScript SDK reaches the same place differently
            // — a NATS authenticator separate from the agent key, node
            // defaulting to the agent — which is a real difference in shape,
            // recorded here rather than papered over.
            node_seed: Some(creds_seed),
            // A conformance throwaway identity: exempt from the naming rule
            // (CLAUDE.md, "Whose an agent is"), which connect turns on by
            // default since 2026-09-27.
            allow_unnamed: true,
            jwt: Some(jwt),
            ..Default::default()
        },
    )
    .await
    {
        Ok(a) => a,
        Err(e) => {
            eprintln!("connect failed: {e}");
            std::process::exit(3);
        }
    };

    say(&json!({
        "ev": "ready",
        "agent_id": agent.id(),
        "sdk": format!("agentmesh-rust {}", env!("CARGO_PKG_VERSION")),
    }));

    // Commands arrive on a blocking reader thread and cross into the async
    // world on a channel. Tokio's own stdin needs the `io-std` feature, and a
    // conformance wrapper is not a reason to change the crate's manifest.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines() {
            match line {
                Ok(l) => {
                    if tx.send(l).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    while let Some(line) = rx.recv().await {
        let text = line.trim();
        if text.is_empty() {
            continue;
        }
        let msg: Value = match serde_json::from_str(text) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("unparsable command: {text} ({e})");
                continue;
            }
        };
        let id = msg.get("id").cloned().unwrap_or(Value::Null);
        let ok = |extra: Value| {
            let mut o = json!({ "ev": "reply", "id": id, "ok": true });
            if let (Some(map), Some(add)) = (o.as_object_mut(), extra.as_object()) {
                for (k, v) in add {
                    map.insert(k.clone(), v.clone());
                }
            }
            say(&o);
        };
        let failed = |why: String| say(&json!({ "ev": "reply", "id": id, "ok": false, "error": why }));

        match msg.get("cmd").and_then(|v| v.as_str()).unwrap_or("") {
            "close" => {
                ok(json!({}));
                break;
            }
            "register" => {
                let name = str_at(&msg, "name");
                let visibility = match str_at(&msg, "visibility") {
                    v if v.is_empty() => None,
                    v => Some(v),
                };
                // §8.2/§8.3a (c14). Absent stays ABSENT — "unknown" and
                // "service" mean very different things to a caller, so an
                // unsent field must not become a declaration.
                let interaction = match str_at(&msg, "interaction") {
                    v if v.is_empty() => None,
                    v => Some(v),
                };
                // EXT-6 §7.1 (c07). The SDK falls back to the public inbox on
                // any refusal, so asking is safe even where no admission
                // service is deployed.
                let guarded = msg.get("guarded").and_then(|v| v.as_bool()).unwrap_or(false);
                let offerings: Vec<Offering> = msg
                    .get("offerings")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .map(|s| Offering {
                                id: str_at(s, "id"),
                                name: str_at(s, "name"),
                                description: str_at(s, "description"),
                                tags: None,
                                input_modes: None,
                                output_modes: None,
                                streaming: None,
                needs: None,
                delivers: None, reporting: None,
                            })
                            .collect()
                    })
                    .unwrap_or_default();

                // One fixed behaviour per offering: report what arrived, echo the
                // input back. The harness decides whether that was correct.
                for s in &offerings {
                    let offering_id = s.id.clone();
                    agent.on_request_ctx(&s.id, move |input, ctx| {
                        let offering_id = offering_id.clone();
                        async move {
                            say(&json!({
                                "ev": "handled",
                                "offering": offering_id,
                                "envelope_id": ctx.request_id,
                                "from": ctx.from,
                                "input": input,
                            }));
                            Ok(json!({ "ok": input }))
                        }
                    });
                }

                match agent
                    .register(RegisterOptions {
                        name,
                        description: "conformance agent under test".into(),
                        offerings,
                        visibility,
                        interaction,
                        guarded,
                        ..Default::default()
                    })
                    .await
                {
                    // `guarded` reports what the SDK CONCLUDED, not what was
                    // asked: a refused guard leaves the agent on its public
                    // inbox, and a harness that assumed otherwise would be
                    // watching the wrong subject.
                    Ok(_) => ok(json!({ "guarded": agent.listening_on_guarded() })),
                    Err(e) => failed(format!("register failed: {e}")),
                }
            }
            "deregister" => match agent.deregister().await {
                Ok(()) => ok(json!({})),
                Err(e) => failed(format!("deregister failed: {e}")),
            },
            // `unsupported` is what the harness turns into `not-validated`:
            // this implementation cannot exercise the behaviour, which is
            // neither a pass nor evidence that the crate is wrong. Adding a
            // command here means adding it to every conformance agent.
            other => say(&json!({
                "ev": "reply", "id": id, "ok": false, "unsupported": true,
                "error": format!("unsupported command: {other}"),
            })),
        }
    }

    agent.close().await;
}
