use agentmesh::{
    canonical_json, codec, create_agent_identity, create_attestation, keypair_from_seed,
    sign_envelope, signed_envelope_bytes, verify_attestation, verify_envelope_sig, Envelope,
    PrimitiveType, ENVELOPE_SIG_PREFIX, VOUCH_SIG_PREFIX,
};
use nkeys::KeyPair;
use serde_json::json;

fn signed(kind: PrimitiveType, kp: &KeyPair, payload: serde_json::Value) -> Envelope {
    let mut env = Envelope::new(kind, kp.public_key());
    env.payload = Some(payload);
    sign_envelope(&mut env, kp).unwrap();
    env
}

#[test]
fn canonical_json_is_stable_and_sorted() {
    assert_eq!(canonical_json(&json!({ "b": 1, "a": 2 })), r#"{"a":2,"b":1}"#);
    assert_eq!(canonical_json(&json!({ "x": [{ "z": 1, "y": 2 }] })), r#"{"x":[{"y":2,"z":1}]}"#);
}

#[test]
fn agent_seed_round_trips_to_same_public_key() {
    let (public, seed) = create_agent_identity().unwrap();
    assert!(public.starts_with('U'));
    let kp = keypair_from_seed(&seed).unwrap();
    assert_eq!(kp.public_key(), public);
}

#[test]
fn signs_and_verifies_an_envelope() {
    let kp = KeyPair::new_user();
    let env = signed(PrimitiveType::Request, &kp, json!({ "a": 1 }));
    assert!(env.sig.is_some());
    assert!(verify_envelope_sig(&env));
}

#[test]
fn fails_verification_on_tamper() {
    let kp = KeyPair::new_user();
    let mut env = signed(PrimitiveType::Request, &kp, json!({ "a": 1 }));
    env.payload = Some(json!({ "a": 999 }));
    assert!(!verify_envelope_sig(&env));
}

#[test]
fn signs_the_tagged_form_sig_covers_prefix_plus_canonical() {
    // §5.3: the signed bytes are `agentmesh-envelope-v1` + LF + the canonical
    // envelope JSON. The emitted signature verifies over exactly them, never
    // the bare canonical form.
    use base64::Engine;
    assert_eq!(ENVELOPE_SIG_PREFIX, "agentmesh-envelope-v1\n");
    let kp = KeyPair::new_user();
    let env = signed(PrimitiveType::Request, &kp, json!({ "a": 1 }));
    let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(env.sig.as_ref().unwrap())
        .unwrap();
    let tagged = signed_envelope_bytes(&env).unwrap();
    assert!(tagged.starts_with(ENVELOPE_SIG_PREFIX.as_bytes()));
    assert!(kp.verify(&tagged, &sig).is_ok());
    assert!(kp.verify(&tagged[ENVELOPE_SIG_PREFIX.len()..], &sig).is_err());
}

#[test]
fn refuses_a_legacy_untagged_signature_from_03() {
    // The pre-tag scheme: a signature over the bare canonical JSON. The 0.2
    // draft window's dual-accept took it; §5.3 closed that window at protocol
    // 0.3, so a correctly-signed-but-untagged envelope is refused on BOTH
    // verify paths, the direct one and decode's received-JSON one.
    use base64::Engine;
    let kp = KeyPair::new_user();
    let mut env = Envelope::new(PrimitiveType::Request, kp.public_key());
    env.payload = Some(json!({ "a": 1 }));
    let bare = &signed_envelope_bytes(&env).unwrap()[ENVELOPE_SIG_PREFIX.len()..];
    let sig = kp.sign(bare).unwrap();
    env.sig = Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig));
    assert!(!verify_envelope_sig(&env), "untagged form refused from 0.3 (§5.3)");
    let bytes = codec::encode(&env).unwrap();
    assert!(codec::decode(&bytes).is_err(), "decode refuses it too");
    // Control: the same envelope signed in the tagged form still verifies.
    sign_envelope(&mut env, &kp).unwrap();
    assert!(verify_envelope_sig(&env));
}

#[test]
fn fails_when_from_does_not_match_signer() {
    let kp = KeyPair::new_user();
    let other = KeyPair::new_user();
    let mut env = Envelope::new(PrimitiveType::Request, other.public_key());
    sign_envelope(&mut env, &kp).unwrap(); // signed by kp, from = other
    assert!(!verify_envelope_sig(&env));
}

#[test]
fn encode_decode_round_trip_verifies_sig() {
    let kp = KeyPair::new_user();
    let env = signed(PrimitiveType::Emit, &kp, json!({ "hello": "world" }));
    let bytes = codec::encode(&env).unwrap();
    let decoded = codec::decode(&bytes).unwrap();
    assert_eq!(decoded.from, kp.public_key());
    assert_eq!(decoded.payload, Some(json!({ "hello": "world" })));
}

#[test]
fn decode_rejects_unsigned_envelope() {
    let kp = KeyPair::new_user();
    let mut env = Envelope::new(PrimitiveType::Emit, kp.public_key());
    env.payload = Some(json!({}));
    let bytes = codec::encode(&env).unwrap();
    let err = codec::decode(&bytes).unwrap_err();
    assert!(format!("{err}").to_lowercase().contains("signature"));
}

#[test]
fn node_attestation_create_and_verify() {
    let node = KeyPair::new_user();
    let agent = KeyPair::new_user().public_key();
    let att = create_attestation(&node, &agent, 30 * 24 * 60 * 60 * 1000).unwrap();
    assert_eq!(att.node, node.public_key());
    assert!(verify_attestation(&att, None));
    assert!(verify_attestation(&att, Some(&agent)));
    assert!(!verify_attestation(&att, Some("UOTHER")));
}

#[test]
fn tampered_attestation_fails() {
    let node = KeyPair::new_user();
    let agent = KeyPair::new_user().public_key();
    let mut att = create_attestation(&node, &agent, 1000).unwrap();
    att.agent = KeyPair::new_user().public_key();
    assert!(!verify_attestation(&att, None));
}

/// The canonical JSON of an attestation with `sig` removed.
fn attestation_canonical(att: &agentmesh::AgentAttestation) -> Vec<u8> {
    let mut v = serde_json::to_value(att).unwrap();
    v.as_object_mut().unwrap().remove("sig");
    canonical_json(&v).into_bytes()
}

#[test]
fn attestation_signs_the_tagged_form_sig_covers_prefix_plus_canonical() {
    // §4.4: the signed bytes are `agentmesh-vouch-v1` + LF + the canonical
    // attestation JSON. The emitted signature verifies over exactly them,
    // never the bare canonical form.
    use base64::Engine;
    assert_eq!(VOUCH_SIG_PREFIX, "agentmesh-vouch-v1\n");
    let node = KeyPair::new_user();
    let agent = KeyPair::new_user().public_key();
    let att = create_attestation(&node, &agent, 1000).unwrap();
    let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&att.sig).unwrap();
    let canonical = attestation_canonical(&att);
    let mut tagged = VOUCH_SIG_PREFIX.as_bytes().to_vec();
    tagged.extend_from_slice(&canonical);
    assert!(node.verify(&tagged, &sig).is_ok());
    assert!(node.verify(&canonical, &sig).is_err());
}

#[test]
fn attestation_refuses_a_legacy_untagged_signature_from_03() {
    // The pre-tag scheme: a signature over the bare canonical JSON. §5.3
    // closed the 0.2 dual-accept at protocol 0.3, and the vouch rides the same
    // shared verify path, so an untagged attestation is refused too.
    use base64::Engine;
    let node = KeyPair::new_user();
    let agent = KeyPair::new_user().public_key();
    let mut att = create_attestation(&node, &agent, 1000).unwrap();
    att.sig = String::new();
    let legacy = node.sign(&attestation_canonical(&att)).unwrap();
    att.sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(legacy);
    assert!(!verify_attestation(&att, Some(&agent)), "untagged form refused from 0.3 (§4.4)");
    // Control: a freshly minted (tagged) attestation still verifies.
    let tagged = create_attestation(&node, &agent, 1000).unwrap();
    assert!(verify_attestation(&tagged, Some(&agent)));
}

/// Cross-impl regression (§5.3): verification MUST run over the received JSON,
/// not a struct round-trip. Another implementation may sign optional fields as
/// explicit `null` (e.g. `error.retry_after_ms: null`) or include fields this
/// SDK doesn't model — neither may break verification.
#[test]
fn decode_verifies_envelopes_with_null_optionals_and_unknown_fields() {
    let kp = KeyPair::new_user();
    // Build the envelope as raw JSON, the way the TS SDK shapes it.
    let mut raw = json!({
        "v": "0.3.0",
        "id": "019f0000-0000-7000-8000-000000000001",
        "type": "respond",
        "ts": "2026-07-14T00:00:00.000Z",
        "from": kp.public_key(),
        "trace": { "trace_id": "t", "span_id": "s" },
        "payload": { "status": "failed" },
        "error": {
            "code": "INTERNAL_ERROR",
            "message": "boom",
            "retryable": true,
            "retry_after_ms": null            // explicit null (TS shape)
        },
        "some_future_field": { "x": 1 }        // unknown to this SDK
    });
    // Sign over the tagged raw canonical form (what a foreign impl actually
    // signs, §5.3).
    let mut tagged = ENVELOPE_SIG_PREFIX.as_bytes().to_vec();
    tagged.extend_from_slice(canonical_json(&raw).as_bytes());
    let sig_bytes = kp.sign(&tagged).unwrap();
    let sig = base64_url_encode(&sig_bytes);
    raw["sig"] = json!(sig);

    let bytes = serde_json::to_vec(&raw).unwrap();
    let env = codec::decode(&bytes).expect("must verify over received JSON");
    assert_eq!(env.from, kp.public_key());
}

fn base64_url_encode(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

// ─── §11.6 stream chunk validation ──────────────────────────────────────────

mod chunk_rules {
    use super::*;
    use agentmesh::{validate_chunk, ChunkOutcome};

    fn chunk_json(payload: serde_json::Value, kp: Option<&KeyPair>) -> Vec<u8> {
        let mut raw = json!({
            "v": "0.3.0",
            "id": "019f0000-0000-7000-8000-00000000000a",
            "type": "respond",
            "ts": "2026-07-14T00:00:00.000Z",
            "from": kp.map(|k| k.public_key()).unwrap_or_else(|| "UNOKEY".into()),
            "trace": { "trace_id": "t", "span_id": "s" },
            "task_id": "task-1",
            "payload": payload,
        });
        if let Some(kp) = kp {
            let mut tagged = ENVELOPE_SIG_PREFIX.as_bytes().to_vec();
            tagged.extend_from_slice(canonical_json(&raw).as_bytes());
            let sig = kp.sign(&tagged).unwrap();
            use base64::Engine;
            raw["sig"] = json!(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig));
        }
        serde_json::to_vec(&raw).unwrap()
    }

    #[test]
    fn accepts_unsigned_intermediate_chunk_by_default() {
        let data = chunk_json(json!({ "status": "working", "chunk_index": 0, "final": false, "data": "a" }), None);
        match validate_chunk(&data, false, 1).unwrap() {
            ChunkOutcome::Chunk(c) => {
                assert_eq!(c.chunk_index, 0);
                assert!(!c.is_final);
                assert_eq!(c.data, json!("a"));
            }
            _ => panic!("expected chunk"),
        }
    }

    #[test]
    fn sign_chunks_mode_rejects_unsigned_chunk() {
        let data = chunk_json(json!({ "status": "working", "chunk_index": 0, "final": false, "data": "a" }), None);
        let err = validate_chunk(&data, true, 1).unwrap_err();
        assert!(err.to_string().contains("sign_chunks"), "{err}");
    }

    #[test]
    fn rejects_unsigned_final_chunk() {
        let data = chunk_json(json!({ "status": "completed", "chunk_index": 0, "final": true, "data": null, "chunk_count": 1 }), None);
        let err = validate_chunk(&data, false, 1).unwrap_err();
        assert!(err.to_string().contains("unsigned"), "{err}");
    }

    #[test]
    fn signed_final_with_matching_chunk_count_passes() {
        let kp = KeyPair::new_user();
        let data = chunk_json(json!({ "status": "completed", "chunk_index": 2, "final": true, "data": null, "chunk_count": 3 }), Some(&kp));
        match validate_chunk(&data, false, 3).unwrap() {
            ChunkOutcome::Chunk(c) => assert!(c.is_final),
            _ => panic!("expected final chunk"),
        }
    }

    #[test]
    fn detects_truncation_via_chunk_count() {
        let kp = KeyPair::new_user();
        let data = chunk_json(json!({ "status": "completed", "chunk_index": 2, "final": true, "data": null, "chunk_count": 3 }), Some(&kp));
        // Only 2 envelopes actually arrived.
        let err = validate_chunk(&data, false, 2).unwrap_err();
        assert!(err.to_string().contains("incomplete or tampered"), "{err}");
    }

    #[test]
    fn rejects_tampered_present_signature() {
        let kp = KeyPair::new_user();
        let mut data = chunk_json(json!({ "status": "working", "chunk_index": 0, "final": false, "data": "a" }), Some(&kp));
        // flip a payload byte after signing
        let s = String::from_utf8(data.clone()).unwrap().replace("\"a\"", "\"b\"");
        data = s.into_bytes();
        let err = validate_chunk(&data, false, 1).unwrap_err();
        assert!(err.to_string().contains("does not verify"), "{err}");
    }

    #[test]
    fn surfaces_error_envelope_as_stream_error() {
        let kp = KeyPair::new_user();
        let mut raw = json!({
            "v": "0.3.0", "id": "019f0000-0000-7000-8000-00000000000b",
            "type": "respond", "ts": "2026-07-14T00:00:00.000Z",
            "from": kp.public_key(),
            "trace": { "trace_id": "t", "span_id": "s" },
            "payload": { "status": "failed" },
            "error": { "code": "INTERNAL_ERROR", "message": "boom", "retryable": false, "retry_after_ms": null },
        });
        let mut tagged = ENVELOPE_SIG_PREFIX.as_bytes().to_vec();
        tagged.extend_from_slice(canonical_json(&raw).as_bytes());
        let sig = kp.sign(&tagged).unwrap();
        use base64::Engine;
        raw["sig"] = json!(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig));
        let data = serde_json::to_vec(&raw).unwrap();
        match validate_chunk(&data, false, 1).unwrap() {
            ChunkOutcome::Error(e) => assert!(e.to_string().contains("boom")),
            _ => panic!("expected error outcome"),
        }
    }
}
