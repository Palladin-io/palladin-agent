use palladin_browser_bridge::capture::{CapturePlan, CaptureRequest, CaptureResult};
use palladin_browser_bridge::secure_transport::INJECT_PROVIDER_PROTOCOL;
use serde_json::{Value, json};

fn plan() -> Value {
    json!({"targetTabId":7,"targetUrl":"https://example.test/token","fields":[
        {"entryFieldId":"username","selector":"#username","read":"value"},
        {"entryFieldId":"password","selector":".token","read":"textContent"}
    ]})
}

#[test]
fn capture_plan_accepts_only_declarative_exact_target_fields() {
    let parsed = CapturePlan::parse(&plan().to_string()).unwrap();
    assert_eq!(parsed.target_tab_id, 7);
    for (key, bad) in [
        ("targetTabId", json!(0)),
        ("targetUrl", json!("http://example.test/token")),
        ("fields", json!([])),
    ] {
        let mut invalid = plan();
        invalid[key] = bad;
        assert!(CapturePlan::parse(&invalid.to_string()).is_err());
    }
    let mut invalid = plan();
    invalid["fields"][0]["value"] = json!("must-never-be-literal");
    assert!(CapturePlan::parse(&invalid.to_string()).is_err());
    invalid = plan();
    invalid["fields"][1]["entryFieldId"] = json!("username");
    assert!(CapturePlan::parse(&invalid.to_string()).is_err());
    invalid = plan();
    invalid["fields"][1]["selector"] = json!("#username");
    assert!(CapturePlan::parse(&invalid.to_string()).is_err());
    invalid = plan();
    invalid["fields"][0]["read"] = json!("javascript");
    assert!(CapturePlan::parse(&invalid.to_string()).is_err());
}

#[test]
fn capture_response_requires_exact_correlation_and_complete_field_set() {
    let request = CaptureRequest::new(
        "capture-1",
        CapturePlan::parse(&plan().to_string()).unwrap(),
    );
    let good = json!({"protocol":INJECT_PROVIDER_PROTOCOL,"type":"capture.result","transactionId":"capture-1","outcome":"captured","values":[
        {"entryFieldId":"username","value":"test-user"},
        {"entryFieldId":"password","value":"test-token"}
    ]});
    let response: CaptureResult = serde_json::from_value(good.clone()).unwrap();
    assert!(response.validate(&request).is_ok());
    for invalid in [
        {
            let mut v = good.clone();
            v["transactionId"] = json!("another-operation");
            v
        },
        {
            let mut v = good.clone();
            v["values"][1]["entryFieldId"] = json!("username");
            v
        },
        {
            let mut v = good.clone();
            v["values"] = json!([]);
            v
        },
        {
            let mut v = good.clone();
            v["outcome"] = json!("rejected");
            v
        },
        {
            let mut v = good.clone();
            v["values"][1]["value"] = json!("x".repeat(65537));
            v
        },
    ] {
        let response: CaptureResult = serde_json::from_value(invalid).unwrap();
        assert!(response.validate(&request).is_err());
    }
    let rejection: CaptureResult=serde_json::from_value(json!({"protocol":INJECT_PROVIDER_PROTOCOL,"type":"capture.result","transactionId":"capture-1","outcome":"rejected"})).unwrap();
    assert!(rejection.validate(&request).is_ok());
}
