use super::*;
use crate::native_browser::test_peer::ExtensionPeer;
use serde_json::json;

fn form() -> InjectionFormDefinition {
    serde_json::from_value(json!({"version":2,"steps":[{"fields":[{"entryFieldId":"credential.username","control":"username","selector":format!("palladin-live:{}:{}","a".repeat(32),"b".repeat(32))}],"submit":{"action":"deferred-native-click","selector":format!("palladin-live:{}:{}","a".repeat(32),"c".repeat(32))}}]})).unwrap()
}
fn password_form(deferred: bool) -> InjectionFormDefinition {
    let mut plan = form();
    if !deferred {
        plan.version = 1;
        plan.steps[0].submit.action = palladin_browser_bridge::InjectionSubmitKind::Click;
    }
    plan.steps[0].fields[0].entry_field_id = "credential.password".into();
    plan.steps[0].fields[0].control = palladin_browser_bridge::InjectionControl::Password;
    plan
}

fn ready() -> SubmitReady {
    SubmitReady {
        pending_id: "d".repeat(32),
        current_url: "https://example.test/login".into(),
        document_id: "document-1".into(),
        submit_selector: format!("palladin-live:{}:{}", "d".repeat(32), "f".repeat(32)),
    }
}

fn password_ready() -> SubmitReady {
    SubmitReady {
        pending_id: "e".repeat(32),
        current_url: "https://example.test/password".into(),
        document_id: "document-2".into(),
        submit_selector: format!("palladin-live:{}:{}", "e".repeat(32), "f".repeat(32)),
    }
}

#[tokio::test]
async fn deferred_flow_fills_once_and_requires_bound_reauthorized_commit() {
    run_deferred_cases(&[
        "completed",
        "continued",
        "continued-deferred",
        "revoked",
        "expired",
        "cancel",
        "changed-grant",
        "changed-entry",
        "changed-domain",
        "changed-document",
        "changed-url",
        "changed-selector",
        "changed-pending",
        "reused-transaction",
        "lost-commit-ack",
        "premature-injected",
        "repeated-ready",
    ])
    .await;
}

#[tokio::test]
async fn committed_submit_waits_for_continuation_beyond_pending_ttl() {
    run_deferred_cases(&["slow-continuation"]).await;
}

#[tokio::test]
async fn committed_submit_reply_cannot_extend_original_authorization() {
    run_deferred_cases(&["reply-after-authorization"]).await;
}

async fn run_deferred_cases(cases: &[&'static str]) {
    for &case in cases {
        let operation_budget = if case == "slow-continuation" {
            Duration::from_secs(20)
        } else {
            Duration::from_secs(5)
        };
        let continues = matches!(
            case,
            "continued" | "continued-deferred" | "slow-continuation"
        );
        let deferred_password = case == "continued-deferred";
        let succeeds = case == "completed" || continues;
        let identity = BrowserHostIdentity::from_secret_bytes([59; 32]);
        let (open, pending) = LocalClientHandshake::start(&identity).unwrap();
        let (session_ready, mut local_session) = accept_local_client(&identity, &open).unwrap();
        let (stream, mut local) = UnixStream::pair().unwrap();
        let mut client = ExtensionClient {
            stream,
            session: pending.finish(&session_ready).unwrap(),
        };
        let (mut extension_session, peer) = ExtensionPeer::start(&identity);
        let (native, mut extension) = tokio::io::duplex(32768);
        let (mut input, mut output) = tokio::io::split(native);
        let checks = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let host_checks = checks.clone();
        let host = tokio::spawn(async move {
            let prepare = OwnedPrepareRequest {
                protocol: INJECT_PROVIDER_PROTOCOL.into(),
                message_type: "prepare".into(),
                nonce: "a".repeat(32),
                target_tab_id: Some(7),
                target_url: Some("https://example.test/login".into()),
                live_detection: Some(true),
            };
            let prepared = PrepareResult {
                protocol: INJECT_PROVIDER_PROTOCOL.into(),
                message_type: "prepare.result".into(),
                nonce: Some(prepare.nonce.clone()),
                current_url: prepare.target_url.clone(),
                live_form: Some(form()),
                outcome: "ready".into(),
            };
            super::super::live_flow::serve_inject_flow(
                &mut local,
                &mut local_session,
                &mut extension_session,
                (&mut input, &mut output),
                (&prepare, &prepared),
                &|_| {
                    let count = host_checks.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    if case == "revoked" && count == 1 {
                        Err(NativeBrowserError::Revoked)
                    } else {
                        Ok(())
                    }
                },
            )
            .await
        });
        let peer_task = tokio::spawn(async move {
            let frame: SecureFrame = read_message(&mut extension).await.unwrap();
            let initial = peer.open(&frame, 0);
            assert_eq!(initial["values"].as_array().unwrap().len(), 1);
            assert_eq!(initial["type"], "inject");
            assert!(initial["expiresAt"].as_u64().unwrap() > epoch_ms().unwrap());
            let reply = if case == "premature-injected" {
                json!({"protocol":INJECT_PROVIDER_PROTOCOL,"type":"inject.result","transactionId":"fill-1","outcome":"injected"})
            } else {
                json!({"protocol":INJECT_PROVIDER_PROTOCOL,"type":"inject.result","transactionId":"fill-1","outcome":"submit-ready","submitReady":ready()})
            };
            write_message(&mut extension, &peer.seal(reply, 0))
                .await
                .unwrap();
            let second = read_message::<SecureFrame>(&mut extension).await;
            if !matches!(
                case,
                "completed"
                    | "continued"
                    | "continued-deferred"
                    | "slow-continuation"
                    | "reply-after-authorization"
                    | "lost-commit-ack"
                    | "repeated-ready"
                    | "cancel"
            ) {
                assert!(
                    second.is_err(),
                    "unauthorized commit reached extension: {case}"
                );
                return;
            }
            let commit = peer.open(&second.unwrap(), 1);
            assert!(
                commit.get("values").is_none(),
                "no credential replay in phase two"
            );
            assert!(commit.get("form").is_none());
            if case == "cancel" {
                assert_eq!(commit["type"], "cancel-submit");
                return;
            }
            assert_eq!(commit["type"], "submit");
            assert_eq!(commit["preparedTransactionId"], "fill-1");
            assert_eq!(
                commit["submitReady"],
                serde_json::to_value(ready()).unwrap()
            );
            if case == "lost-commit-ack" {
                return;
            }
            if case == "slow-continuation" {
                // The click already committed while pending; only next-page discovery is slow.
                tokio::time::sleep(Duration::from_millis(9_950)).await;
            }
            if case == "reply-after-authorization" {
                // A later caller deadline must not renew the original native authorization.
                tokio::time::sleep(Duration::from_millis(200)).await;
                let next = read_message::<SecureFrame>(&mut extension).await;
                assert!(
                    next.is_err(),
                    "an expired committed operation must close without retry"
                );
                return;
            }
            let reply = if case == "repeated-ready" {
                json!({"protocol":INJECT_PROVIDER_PROTOCOL,"type":"inject.result","transactionId":"commit-1","outcome":"submit-ready","submitReady":ready()})
            } else if continues {
                json!({"protocol":INJECT_PROVIDER_PROTOCOL,"type":"inject.result","transactionId":"commit-1","outcome":"injected","continuation":{"outcome":"ready","currentUrl":"https://example.test/password","documentId":"document-2","liveForm":password_form(deferred_password)}})
            } else {
                json!({"protocol":INJECT_PROVIDER_PROTOCOL,"type":"inject.result","transactionId":"commit-1","outcome":"injected","continuation":{"outcome":"no-form"}})
            };
            write_message(&mut extension, &peer.seal(reply, 1))
                .await
                .unwrap();
            if continues {
                let frame = read_message::<SecureFrame>(&mut extension).await.unwrap();
                let password = peer.open(&frame, 2);
                assert_eq!(password["values"].as_array().unwrap().len(), 1);
                assert_eq!(password["values"][0]["entryFieldId"], "credential.password");
                assert_eq!(
                    password["form"],
                    serde_json::to_value(password_form(deferred_password)).unwrap()
                );
                if deferred_password {
                    let result = json!({"protocol":INJECT_PROVIDER_PROTOCOL,"type":"inject.result","transactionId":"password-1","outcome":"submit-ready","submitReady":password_ready()});
                    write_message(&mut extension, &peer.seal(result, 2))
                        .await
                        .unwrap();
                    let frame = read_message::<SecureFrame>(&mut extension).await.unwrap();
                    let commit = peer.open(&frame, 3);
                    assert_eq!(commit["preparedTransactionId"], "password-1");
                    assert_eq!(
                        commit["submitReady"],
                        serde_json::to_value(password_ready()).unwrap()
                    );
                    assert!(commit.get("values").is_none());
                }
                let result = json!({"protocol":INJECT_PROVIDER_PROTOCOL,"type":"inject.result","transactionId":if deferred_password { "password-commit" } else { "password-1" },"outcome":"injected","continuation":{"outcome":"no-form"}});
                write_message(
                    &mut extension,
                    &peer.seal(result, if deferred_password { 3 } else { 2 }),
                )
                .await
                .unwrap();
            }
        });
        let plan = form();
        let request = InjectRequest {
            expires_at: Some(epoch_ms().unwrap() + 5000),
            continue_live: Some(true),
            protocol: INJECT_PROVIDER_PROTOCOL,
            message_type: "inject",
            transaction_id: "fill-1",
            grant_id: "grant",
            entry_id: "entry",
            expected_domain: "example.test",
            form: &plan,
            values: vec![InjectFieldValue {
                entry_field_id: "credential.username",
                value: "synthetic-identifier",
            }],
        };
        let original_deadline = monotonic_not_after_ns(
            monotonic_now_ns().unwrap(),
            if matches!(case, "expired" | "reply-after-authorization") {
                Duration::from_millis(100)
            } else {
                operation_budget
            },
        )
        .unwrap();
        let sealed = client.seal_inject(&request, original_deadline).unwrap();
        let response = client.send_inject(sealed, Duration::from_secs(5)).await;
        if case == "premature-injected" {
            assert!(response.is_err());
        } else {
            assert_eq!(response.unwrap().outcome, "submit-ready");
            if case == "expired" {
                tokio::time::sleep(Duration::from_millis(120)).await;
            }
            if case == "slow-continuation" {
                // Reauthorization consumes part of the pending window before commit.
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            let mut request = SubmitRequest {
                protocol: INJECT_PROVIDER_PROTOCOL.into(),
                message_type: "submit".into(),
                transaction_id: "commit-1".into(),
                prepared_transaction_id: "fill-1".into(),
                grant_id: "grant".into(),
                entry_id: "entry".into(),
                expected_domain: "example.test".into(),
                submit_ready: ready(),
                expires_at: epoch_ms().unwrap() + 5000,
            };
            match case {
                "changed-grant" => request.grant_id = "other".into(),
                "changed-entry" => request.entry_id = "other".into(),
                "changed-domain" => request.expected_domain = "other.test".into(),
                "changed-document" => request.submit_ready.document_id = "other".into(),
                "changed-url" => {
                    request.submit_ready.current_url = "https://other.test/login".into()
                }
                "changed-selector" => request.submit_ready.submit_selector = "#guess".into(),
                "changed-pending" => request.submit_ready.pending_id = "e".repeat(32),
                "reused-transaction" => request.transaction_id = "fill-1".into(),
                _ => (),
            }
            let command = if case == "cancel" {
                json!({"protocol":LOCAL_TRANSPORT_PROTOCOL,"type":"submit.cancel","request":{"protocol":INJECT_PROVIDER_PROTOCOL,"type":"cancel-submit","transactionId":"cancel-1","preparedTransactionId":"fill-1","pendingId":ready().pending_id}})
            } else {
                json!({"protocol":LOCAL_TRANSPORT_PROTOCOL,"type":"submit.forward","notAfterMonotonicNs":monotonic_not_after_ns(monotonic_now_ns().unwrap(),operation_budget).unwrap().to_string(),"request":request})
            };
            let frame = client.session.seal(&command).unwrap();
            // An expired host may already have closed: even then nothing is retried.
            let result = client
                .send_inject(
                    SealedInject {
                        frame,
                        transaction_id: "commit-1".into(),
                    },
                    operation_budget,
                )
                .await;
            assert_eq!(result.is_ok(), succeeds, "{case}");
            if continues {
                let plan = password_form(deferred_password);
                let request = InjectRequest {
                    expires_at: deferred_password.then(|| epoch_ms().unwrap() + 5000),
                    continue_live: Some(true),
                    protocol: INJECT_PROVIDER_PROTOCOL,
                    message_type: "inject",
                    transaction_id: "password-1",
                    grant_id: "grant",
                    entry_id: "entry",
                    expected_domain: "example.test",
                    form: &plan,
                    values: vec![InjectFieldValue {
                        entry_field_id: "credential.password",
                        value: "synthetic-only",
                    }],
                };
                let sealed = client.seal_inject(&request, original_deadline).unwrap();
                let mut response = client
                    .send_inject(sealed, Duration::from_secs(5))
                    .await
                    .unwrap();
                if deferred_password {
                    assert_eq!(response.outcome, "submit-ready");
                    let commit = SubmitRequest {
                        protocol: INJECT_PROVIDER_PROTOCOL.into(),
                        message_type: "submit".into(),
                        transaction_id: "password-commit".into(),
                        prepared_transaction_id: "password-1".into(),
                        grant_id: "grant".into(),
                        entry_id: "entry".into(),
                        expected_domain: "example.test".into(),
                        submit_ready: password_ready(),
                        expires_at: epoch_ms().unwrap() + 5000,
                    };
                    let frame = client.session.seal(&json!({"protocol":LOCAL_TRANSPORT_PROTOCOL,"type":"submit.forward","notAfterMonotonicNs":original_deadline.to_string(),"request":commit})).unwrap();
                    response = client
                        .send_inject(
                            SealedInject {
                                frame,
                                transaction_id: "password-commit".into(),
                            },
                            Duration::from_secs(5),
                        )
                        .await
                        .unwrap();
                }
                assert_eq!(response.outcome, "injected");
            }
        }
        drop(client);
        assert_eq!(host.await.unwrap().is_ok(), succeeds, "{case}");
        peer_task.await.unwrap();
        if succeeds {
            assert_eq!(
                checks.load(std::sync::atomic::Ordering::SeqCst),
                if deferred_password {
                    4
                } else if continues {
                    3
                } else {
                    2
                }
            );
        }
    }
}

#[test]
fn submit_contract_rejects_values_and_unknown_keys() {
    let mut request = json!({"protocol":INJECT_PROVIDER_PROTOCOL,"type":"submit","transactionId":"commit","preparedTransactionId":"fill","grantId":"grant","entryId":"entry","expectedDomain":"example.test","submitReady":ready(),"expiresAt":1});
    serde_json::from_value::<SubmitRequest>(request.clone()).unwrap();
    request["values"] = json!([{ "entryFieldId":"credential.password","value":"synthetic" }]);
    assert!(serde_json::from_value::<SubmitRequest>(request).is_err());
    let mut ready = serde_json::to_value(ready()).unwrap();
    ready["password"] = json!("synthetic");
    assert!(serde_json::from_value::<SubmitReady>(ready).is_err());
}

#[test]
fn extension_fixture_bytes_match_native_deferred_contract() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../contracts/inject-provider/live-v2/deferred-submit.json"
    ))
    .unwrap();
    let inject: OwnedInjectRequest = serde_json::from_value(fixture["inject"].clone()).unwrap();
    validate_inject_request(&inject).unwrap();
    let result: InjectResult = serde_json::from_value(fixture["submitReady"].clone()).unwrap();
    validate_inject_result(&result, &inject.transaction_id).unwrap();
    let ready = result.submit_ready.unwrap();
    ready
        .validate("https://login.example.test/", &inject.form)
        .unwrap();
    let request: SubmitRequest = serde_json::from_value(fixture["submit"].clone()).unwrap();
    let binding = PendingBinding {
        prepared_transaction_id: inject.transaction_id.clone(),
        grant_id: inject.grant_id.clone(),
        entry_id: inject.entry_id.clone(),
        expected_domain: inject.expected_domain.clone(),
        form: inject.form.clone(),
        original_url: ready.current_url.clone(),
        not_after_monotonic_ns: "1".into(),
    };
    validate_commit(&request, &binding, &ready).unwrap();
    let cancel: CancelSubmitRequest = serde_json::from_value(fixture["cancel"].clone()).unwrap();
    assert_eq!(cancel.pending_id, ready.pending_id);
}

#[test]
fn extension_password_fixtures_match_native_deferred_contract() {
    let examples: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../contracts/inject-provider/live-v2/deferred-password.json"
    ))
    .unwrap();
    for fixture in examples.as_object().unwrap().values() {
        let inject: OwnedInjectRequest = serde_json::from_value(fixture["inject"].clone()).unwrap();
        validate_inject_request(&inject).unwrap();
        let result: InjectResult = serde_json::from_value(fixture["submitReady"].clone()).unwrap();
        validate_inject_result(&result, &inject.transaction_id).unwrap();
        let ready = result.submit_ready.unwrap();
        ready
            .validate("https://login.example.test/", &inject.form)
            .unwrap();
        let request: SubmitRequest = serde_json::from_value(fixture["submit"].clone()).unwrap();
        let binding = PendingBinding {
            prepared_transaction_id: inject.transaction_id.clone(),
            grant_id: inject.grant_id.clone(),
            entry_id: inject.entry_id.clone(),
            expected_domain: inject.expected_domain.clone(),
            form: inject.form.clone(),
            original_url: ready.current_url.clone(),
            not_after_monotonic_ns: "1".into(),
        };
        validate_commit(&request, &binding, &ready).unwrap();
        let cancel: CancelSubmitRequest =
            serde_json::from_value(fixture["cancel"].clone()).unwrap();
        assert_eq!(cancel.pending_id, ready.pending_id);
    }
}
