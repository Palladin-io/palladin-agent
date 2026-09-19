use super::*;
use crate::native_browser::test_peer::ExtensionPeer;
use serde_json::json;

fn form(index: usize) -> InjectionFormDefinition {
    let (id, control) = [
        ("credential.username", "username"),
        ("credential.password", "password"),
        ("credential.totp", "otp"),
    ][index];
    serde_json::from_value(json!({"version":1,"steps":[{"fields":[{"entryFieldId":id,"control":control,"selector":format!("palladin-live:{:032x}:{}",index+1,"a".repeat(32))}],"submit":{"action":"click","selector":format!("palladin-live:{:032x}:{}",index+1,"b".repeat(32))}}]})).unwrap()
}

#[tokio::test]
async fn one_authenticated_host_session_advances_three_steps_and_rechecks_every_handoff() {
    for case in [
        "completed",
        "changed-grant",
        "changed-entry",
        "changed-domain",
        "changed-form",
        "revoked",
        "lost-reply",
        "challenge",
        "foreign-origin",
        "repeated-stage",
        "expired",
    ] {
        let identity = BrowserHostIdentity::from_secret_bytes([51; 32]);
        let (open, pending) = LocalClientHandshake::start(&identity).unwrap();
        let (ready, mut local_session) = accept_local_client(&identity, &open).unwrap();
        let (stream, mut local) = UnixStream::pair().unwrap();
        let mut client = ExtensionClient {
            stream,
            session: pending.finish(&ready).unwrap(),
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
                live_form: Some(form(0)),
                outcome: "ready".into(),
            };
            serve_inject_flow(
                &mut local,
                &mut local_session,
                &mut extension_session,
                (&mut input, &mut output),
                (&prepare, &prepared),
                &|_| {
                    let step = host_checks.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    if case == "revoked" && step == 1 {
                        Err(NativeBrowserError::AuthorizationExpired)
                    } else {
                        Ok(())
                    }
                },
            )
            .await
        });
        let peer_task = tokio::spawn(async move {
            for index in 0..3 {
                let incoming = read_message::<SecureFrame>(&mut extension).await;
                if index == 1
                    && matches!(
                        case,
                        "changed-grant"
                            | "changed-entry"
                            | "changed-domain"
                            | "changed-form"
                            | "revoked"
                            | "expired"
                    )
                {
                    assert!(incoming.is_err(), "second secret must not be forwarded");
                    return;
                }
                let frame = incoming.unwrap();
                assert!(
                    !serde_json::to_string(&frame)
                        .unwrap()
                        .contains("synthetic-only")
                );
                let request = peer.open(&frame, index as u64);
                assert_eq!(request["continueLive"], true);
                assert_eq!(request["form"], serde_json::to_value(form(index)).unwrap());
                assert_eq!(request["values"].as_array().unwrap().len(), 1);
                if case == "lost-reply" {
                    return;
                }
                let continuation = if case == "challenge" {
                    json!({"outcome":"challenge"})
                } else if index == 2 {
                    json!({"outcome":"no-form"})
                } else {
                    json!({"outcome":"ready","currentUrl":if case=="foreign-origin" {"https://other.test/next"} else {"https://example.test/next"},"documentId":"document-2","liveForm":form(if case == "repeated-stage" {index} else {index+1})})
                };
                let reply = json!({"protocol":INJECT_PROVIDER_PROTOCOL,"type":"inject.result","transactionId":request["transactionId"],"outcome":"injected","continuation":continuation});
                write_message(&mut extension, &peer.seal(reply, index as u64))
                    .await
                    .unwrap();
                if matches!(case, "challenge" | "foreign-origin" | "repeated-stage") {
                    return;
                }
            }
        });
        for index in 0..3 {
            let mut current_form = form(index);
            if index == 1 && case == "changed-form" {
                current_form = form(2);
            }
            let transaction = format!("transaction-{index}");
            let request = InjectRequest {
                continue_live: Some(true),
                protocol: INJECT_PROVIDER_PROTOCOL,
                message_type: "inject",
                transaction_id: &transaction,
                grant_id: if index == 1 && case == "changed-grant" {
                    "other"
                } else {
                    "grant"
                },
                entry_id: if index == 1 && case == "changed-entry" {
                    "other"
                } else {
                    "entry"
                },
                expected_domain: if index == 1 && case == "changed-domain" {
                    "other.test"
                } else {
                    "example.test"
                },
                form: &current_form,
                values: vec![InjectFieldValue {
                    entry_field_id: current_form.field_ids().next().unwrap(),
                    value: "synthetic-only",
                }],
            };
            let deadline = if index == 1 && case == "expired" {
                1
            } else {
                monotonic_not_after_ns(monotonic_now_ns().unwrap(), Duration::from_secs(5)).unwrap()
            };
            let sealed = client.seal_inject(&request, deadline).unwrap();
            let result = client.send_inject(sealed, Duration::from_secs(5)).await;
            if case == "completed"
                || (index == 0
                    && !matches!(case, "lost-reply" | "foreign-origin" | "repeated-stage"))
            {
                assert_eq!(result.unwrap().outcome, "injected");
            } else {
                assert!(result.is_err());
                break;
            }
            if case == "challenge" {
                break;
            }
        }
        drop(client);
        assert_eq!(
            host.await.unwrap().is_ok(),
            matches!(case, "completed" | "challenge")
        );
        peer_task.await.unwrap();
        if case == "completed" {
            assert_eq!(checks.load(std::sync::atomic::Ordering::SeqCst), 3);
        }
    }
}
