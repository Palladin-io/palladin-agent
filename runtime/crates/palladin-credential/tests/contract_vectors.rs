use palladin_api::CredentialAccess;
use palladin_credential::access::exit_code_for_access;
use palladin_credential::fields::{FieldSelector, redact_totp_secrets, resolve_field_at};
use palladin_credential::secret::{parse_secret, parse_totp_value};
use palladin_credential::totp::TotpAlgorithm;
use palladin_credential::wait::{
    HeartbeatInfo, ProgressMode, WaitError, WaitHints, WaitOptions, WaitPolicy, await_grant,
    resolve_wait_policy,
};
use secrecy::ExposeSecret;
use serde::Deserialize;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use tokio_util::sync::CancellationToken;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CredentialFixture {
    totp_unix_seconds: u64,
    cases: Vec<CredentialCase>,
    totp_uri_acceptances: Vec<TotpUriAcceptance>,
    totp_uri_rejections: Vec<TotpUriRejection>,
    totp_rejections: Vec<TotpRejection>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TotpUriAcceptance {
    name: String,
    uri: String,
    expected_secret: String,
    expected_algorithm: String,
    expected_digits: u32,
    expected_period: u64,
}

#[derive(Deserialize)]
struct TotpUriRejection {
    name: String,
    uri: String,
}

#[derive(Deserialize)]
struct TotpRejection {
    name: String,
    descriptor: serde_json::Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CredentialCase {
    name: String,
    plaintext: String,
    primary: Option<String>,
    custom_field_count: Option<usize>,
    #[serde(default)]
    parse_error: bool,
    totp_field_id: Option<String>,
    totp_field_label: Option<String>,
    totp_code: Option<String>,
    script_ref_count: Option<usize>,
    redaction_forbidden: Option<String>,
    redaction_contains: Option<String>,
    selector_field: Option<String>,
    selector_field_id: Option<String>,
    expected_field_value: Option<String>,
    #[serde(default)]
    selection_error: bool,
}

#[test]
fn credential_blob_contract_is_consumed_byte_for_byte() {
    let fixture: CredentialFixture =
        serde_json::from_str(include_str!("../../../contracts/v1/credential-blobs.json"))
            .expect("credential fixture");
    for acceptance in fixture.totp_uri_acceptances {
        let params = parse_totp_value(&acceptance.uri).expect(&acceptance.name);
        assert_secret_equal(
            params.secret.expose_secret(),
            &acceptance.expected_secret,
            &acceptance.name,
        );
        let algorithm = match params.algorithm {
            TotpAlgorithm::Sha1 => "SHA1",
            TotpAlgorithm::Sha256 => "SHA256",
            TotpAlgorithm::Sha512 => "SHA512",
        };
        assert_eq!(
            algorithm, acceptance.expected_algorithm,
            "{}",
            acceptance.name
        );
        assert_eq!(
            params.digits, acceptance.expected_digits,
            "{}",
            acceptance.name
        );
        assert_eq!(
            params.period, acceptance.expected_period,
            "{}",
            acceptance.name
        );
    }
    for rejection in fixture.totp_uri_rejections {
        assert!(
            parse_totp_value(&rejection.uri).is_none(),
            "{}",
            rejection.name
        );
    }
    for rejection in fixture.totp_rejections {
        let descriptor = serde_json::to_string(&rejection.descriptor).expect("TOTP descriptor");
        assert!(
            parse_totp_value(&descriptor).is_none(),
            "{}",
            rejection.name
        );
    }
    for case in fixture.cases {
        let parsed = parse_secret(case.plaintext.as_bytes());
        if case.parse_error {
            assert!(parsed.is_err(), "{}", case.name);
            continue;
        }
        let parsed = parsed.expect(&case.name);
        if let Some(primary) = case.primary.as_deref() {
            assert_secret_equal(parsed.password.expose_secret(), primary, &case.name);
        }
        if let Some(expected) = case.custom_field_count {
            assert_eq!(parsed.custom_fields.len(), expected, "{}", case.name);
        }
        if let Some(expected) = case.totp_code.as_deref() {
            let selector = FieldSelector {
                field: case.totp_field_label,
                field_id: case.totp_field_id,
            };
            let resolved = resolve_field_at(&parsed, &selector, fixture.totp_unix_seconds)
                .expect("TOTP field");
            assert_secret_equal(
                resolved.expose_for_authorized_operation(),
                expected,
                &case.name,
            );
        }
        if let Some(expected) = case.script_ref_count {
            assert_eq!(parsed.script.as_ref().expect("script").refs.len(), expected);
        }
        if case.redaction_forbidden.is_some() || case.redaction_contains.is_some() {
            let redacted =
                redact_totp_secrets(case.plaintext.as_bytes(), fixture.totp_unix_seconds)
                    .expect("redaction");
            if let Some(forbidden) = case.redaction_forbidden.as_deref() {
                assert!(
                    !redacted.expose_secret().contains(forbidden),
                    "{}",
                    case.name
                );
            }
            if let Some(expected) = case.redaction_contains.as_deref() {
                assert!(redacted.expose_secret().contains(expected), "{}", case.name);
            }
        }
        if case.selector_field.is_some() || case.selector_field_id.is_some() {
            let result = resolve_field_at(
                &parsed,
                &FieldSelector {
                    field: case.selector_field,
                    field_id: case.selector_field_id,
                },
                fixture.totp_unix_seconds,
            );
            if case.selection_error {
                assert!(result.is_err(), "{}", case.name);
            } else {
                assert_secret_equal(
                    result
                        .expect("selected field")
                        .expose_for_authorized_operation(),
                    case.expected_field_value
                        .as_deref()
                        .expect("expected field value"),
                    &case.name,
                );
            }
        }
    }
}

fn assert_secret_equal(actual: &str, expected: &str, case_name: &str) {
    assert!(actual == expected, "{case_name}: secret value diverged");
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GrantFixture {
    states: Vec<GrantState>,
    wait_policies: Vec<WaitPolicyCase>,
    durations: Vec<DurationCase>,
    wait_scenarios: Vec<WaitScenario>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GrantState {
    access: String,
    exit_code: u8,
    retryable: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WaitPolicyCase {
    name: String,
    options: WaitOptionsFixture,
    hints: WaitHintsFixture,
    expected: WaitExpected,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WaitOptionsFixture {
    wait_ms: Option<u64>,
    poll_ms: Option<u64>,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WaitHintsFixture {
    poll_interval_ms: Option<u64>,
    max_wait_ms: Option<u64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WaitExpected {
    wait_ms: u64,
    poll_ms: u64,
    heartbeat_ms: u64,
    poll_timeout_ms: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DurationCase {
    input: String,
    expected_ms: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WaitScenario {
    name: String,
    policy: WaitScenarioPolicy,
    #[serde(default)]
    responses: Vec<String>,
    #[serde(default)]
    expected_sleep_ms: Vec<u64>,
    #[serde(default)]
    expected_heartbeat_ms: Vec<u64>,
    expected_access: Option<String>,
    cancel_during: Option<String>,
    expected_error: Option<String>,
    #[serde(default)]
    hang_poll: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WaitScenarioPolicy {
    wait_ms: u64,
    poll_ms: u64,
    heartbeat_ms: u64,
    poll_timeout_ms: u64,
}

#[test]
fn grant_state_and_wait_policy_contract_is_exhaustive() {
    let fixture: GrantFixture =
        serde_json::from_str(include_str!("../../../contracts/v1/grant-access.json"))
            .expect("grant fixture");
    for state in fixture.states {
        let access = access(&state.access);
        assert_eq!(
            exit_code_for_access(&access),
            state.exit_code,
            "{}",
            state.access
        );
        assert_eq!(state.exit_code == 75, state.retryable, "{}", state.access);
    }
    for case in fixture.wait_policies {
        let policy = resolve_wait_policy(
            WaitOptions {
                wait_ms: case.options.wait_ms,
                poll_ms: case.options.poll_ms,
                progress: None,
            },
            WaitHints {
                poll_interval_ms: case.hints.poll_interval_ms,
                max_wait_ms: case.hints.max_wait_ms,
            },
        )
        .expect(&case.name);
        assert_eq!(policy.wait_ms, case.expected.wait_ms, "{}", case.name);
        assert_eq!(policy.poll_ms, case.expected.poll_ms, "{}", case.name);
        assert_eq!(
            policy.heartbeat_ms, case.expected.heartbeat_ms,
            "{}",
            case.name
        );
        assert_eq!(
            policy.poll_timeout_ms, case.expected.poll_timeout_ms,
            "{}",
            case.name
        );
    }
    for case in fixture.durations {
        assert_eq!(
            palladin_credential::wait::parse_duration(&case.input).expect("duration"),
            case.expected_ms,
            "{}",
            case.input
        );
    }
}

#[tokio::test]
async fn frozen_wait_scenarios_cover_schedule_and_cancellation() {
    let fixture: GrantFixture =
        serde_json::from_str(include_str!("../../../contracts/v1/grant-access.json"))
            .expect("grant fixture");
    for scenario in fixture.wait_scenarios {
        let policy = WaitPolicy {
            wait_ms: scenario.policy.wait_ms,
            poll_ms: scenario.policy.poll_ms,
            heartbeat_ms: scenario.policy.heartbeat_ms,
            poll_timeout_ms: scenario.policy.poll_timeout_ms,
            progress: ProgressMode::Plain,
        };
        if scenario.cancel_during.as_deref() == Some("poll") {
            let cancellation = CancellationToken::new();
            let trigger = cancellation.clone();
            let result = await_grant(
                pending("grant-fixture"),
                policy,
                &cancellation,
                move || {
                    trigger.cancel();
                    async { std::future::pending::<Result<CredentialAccess, Infallible>>().await }
                },
                |_| async {},
                |_| {},
            )
            .await;
            assert!(
                matches!(result, Err(WaitError::Cancelled)),
                "{}",
                scenario.name
            );
            assert_eq!(scenario.expected_error.as_deref(), Some("cancelled"));
            continue;
        }
        if scenario.hang_poll {
            let heartbeats = Arc::new(Mutex::new(Vec::<HeartbeatInfo>::new()));
            let observed = Arc::clone(&heartbeats);
            let result = await_grant(
                pending("grant-fixture"),
                policy,
                &CancellationToken::new(),
                || async { std::future::pending::<Result<CredentialAccess, Infallible>>().await },
                |_| async {},
                move |heartbeat| {
                    observed.lock().expect("heartbeats").push(heartbeat);
                },
            )
            .await
            .expect("bounded hung poll");
            assert_eq!(
                heartbeats
                    .lock()
                    .expect("heartbeats")
                    .iter()
                    .map(|heartbeat| heartbeat.elapsed_ms)
                    .collect::<Vec<_>>(),
                scenario.expected_heartbeat_ms,
                "{}",
                scenario.name
            );
            assert_eq!(
                access_name(&result),
                scenario
                    .expected_access
                    .as_deref()
                    .expect("expected access")
            );
            continue;
        }

        let sleeps = Arc::new(Mutex::new(Vec::new()));
        let observed_sleeps = Arc::clone(&sleeps);
        let heartbeats = Arc::new(Mutex::new(Vec::<HeartbeatInfo>::new()));
        let observed_heartbeats = Arc::clone(&heartbeats);
        let mut responses = scenario.responses.iter().map(|state| access(state));
        let result = await_grant(
            pending("grant-fixture"),
            policy,
            &CancellationToken::new(),
            || {
                let response = responses.next().expect("fixture response");
                async move { Ok::<_, Infallible>(response) }
            },
            move |duration| {
                let observed_sleeps = Arc::clone(&observed_sleeps);
                async move {
                    observed_sleeps
                        .lock()
                        .expect("sleeps")
                        .push(duration.as_millis() as u64);
                }
            },
            move |heartbeat| {
                observed_heartbeats
                    .lock()
                    .expect("heartbeats")
                    .push(heartbeat);
            },
        )
        .await
        .expect("wait scenario");
        assert_eq!(
            *sleeps.lock().expect("sleeps"),
            scenario.expected_sleep_ms,
            "{}",
            scenario.name
        );
        assert_eq!(
            heartbeats
                .lock()
                .expect("heartbeats")
                .iter()
                .map(|heartbeat| heartbeat.elapsed_ms)
                .collect::<Vec<_>>(),
            scenario.expected_heartbeat_ms,
            "{}",
            scenario.name
        );
        assert_eq!(
            access_name(&result),
            scenario.expected_access.as_deref().unwrap()
        );
    }
}

fn access(name: &str) -> CredentialAccess {
    match name {
        "granted" => serde_json::from_value(serde_json::json!({
            "access": "granted",
            "entryId": "entry-fixture",
            "label": "Fixture",
            "urlDomain": null,
            "reEncryptedBlob": "AA==",
            "nonce": "AA==",
            "agentWrappedDek": "AA=="
        }))
        .expect("granted fixture"),
        "pending" => CredentialAccess::Pending {
            grant_id: "grant-fixture".to_owned(),
            created: None,
            poll_interval_ms: None,
            max_wait_ms: None,
        },
        "unavailable" => CredentialAccess::Unavailable,
        "denied" => CredentialAccess::Denied,
        "revoked" => CredentialAccess::Revoked,
        "expired" => CredentialAccess::Expired,
        "consumed" => CredentialAccess::Consumed,
        "method-not-allowed" => CredentialAccess::MethodNotAllowed,
        "script-exec-only" => CredentialAccess::ScriptExecOnly,
        "blocked" => CredentialAccess::Blocked,
        _ => panic!("unknown fixture access state"),
    }
}

fn pending(id: &str) -> CredentialAccess {
    CredentialAccess::Pending {
        grant_id: id.to_owned(),
        created: None,
        poll_interval_ms: None,
        max_wait_ms: None,
    }
}

const fn access_name(access: &CredentialAccess) -> &'static str {
    match access {
        CredentialAccess::Granted { .. } => "granted",
        CredentialAccess::Pending { .. } => "pending",
        CredentialAccess::Denied => "denied",
        CredentialAccess::Revoked => "revoked",
        CredentialAccess::Expired => "expired",
        CredentialAccess::Consumed => "consumed",
        CredentialAccess::MethodNotAllowed => "method-not-allowed",
        CredentialAccess::ScriptExecOnly => "script-exec-only",
        CredentialAccess::Unavailable => "unavailable",
        CredentialAccess::Blocked => "blocked",
    }
}
