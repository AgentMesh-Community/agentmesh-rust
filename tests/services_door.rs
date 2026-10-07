//! The service door's caller: what it sends without an agent, and what it
//! makes of answers that are not answers. tests/services_shapes_generated.rs
//! covers every request's own shape.

#[path = "support/service_door.rs"]
mod service_door;

use std::sync::Arc;

use agentmesh::credential::BoxFuture;
use agentmesh::services::*;
use serde_json::json;
use service_door::{StandIn, API};

#[tokio::test]
async fn a_caller_with_only_a_key_signs_nothing() {
    let door = StandIn::answering(json!({ "result": { "errors": [] } }));
    // The stand-in's own caller signs; build one that does not, on the same wire.
    let signed = door.caller();
    let _ = signed.errors().list(ErrorsListInput::default()).await.unwrap();
    let sent = door.sent.lock().unwrap().pop().unwrap();
    assert!(sent.body.get("sig").is_some());

    struct Keep(std::sync::Mutex<Vec<String>>);
    impl ServiceTransport for Keep {
        fn post_json<'a>(&'a self, _url: &'a str, bearer: Option<&'a str>, body: String) -> BoxFuture<'a, Result<ServiceHttpResponse, String>> {
            self.0.lock().unwrap().push(format!("{}|{body}", bearer.unwrap_or("")));
            Box::pin(async { Ok(ServiceHttpResponse { status: 200, body: r#"{"result":{"errors":[]}}"#.into() }) })
        }
        fn get<'a>(&'a self, _url: &'a str, _bearer: Option<&'a str>) -> BoxFuture<'a, Result<ServiceHttpResponse, String>> {
            Box::pin(async { Err("not used".to_string()) })
        }
    }
    let keep = Arc::new(Keep(Default::default()));
    let caller = ServiceCaller::new(Some(API), Some("op_key")).with_transport(keep.clone());
    caller.errors().list(ErrorsListInput::default()).await.unwrap();
    let line = keep.0.lock().unwrap().pop().unwrap();
    let (bearer, body) = line.split_once('|').unwrap();
    assert_eq!(bearer, "op_key");
    let body: serde_json::Value = serde_json::from_str(body).unwrap();
    assert_eq!(body, json!({ "input": {}, "door": "sdk" }));
}

#[tokio::test]
async fn an_answer_that_is_not_one_is_a_failure_not_a_refusal() {
    let door = StandIn::raw(502, json!("bad gateway"));
    let err = door.caller().runs().list(RunsListInput::default()).await.unwrap_err();
    assert!(err.refusal().is_none());
    assert!(err.to_string().contains("HTTP 502"), "{err}");

    // An answer whose shape is not the definition's says so.
    let door = StandIn::answering(json!({ "result": { "runs": "not a list" } }));
    let err = door.caller().runs().list(RunsListInput::default()).await.unwrap_err();
    assert!(err.to_string().contains("does not match the definition"), "{err}");
}

#[test]
fn a_caller_with_no_address_uses_this_environments() {
    assert!(ServiceCaller::new(None, None).api().starts_with("https://api."));
}

#[test]
fn every_request_is_listed_once() {
    let mut ids: Vec<&str> = SDK_REQUESTS.iter().map(|r| r.id).collect();
    let n = ids.len();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), n);
    assert!(SDK_REQUESTS.iter().any(|r| r.id == "rooms.open" && r.transport == "mesh"));
    assert!(SDK_REQUESTS.iter().any(|r| r.id == "schedules.create" && r.transport == "platform"));
    // The definition keeps rooms.close off the SDK: a live room closes itself.
    assert!(!SDK_REQUESTS.iter().any(|r| r.id == "rooms.close"));
}
