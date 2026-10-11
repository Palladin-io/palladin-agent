//! Synthetic integration fixture, never shipped or used with local Agent state.
//! Exercises production transport while substituting identity/grant authorization.
#[cfg(unix)]
use palladin_inject::BrowserTarget;
#[cfg(unix)]
#[allow(dead_code)]
#[path = "../../palladin-inject/src/transport.rs"]
mod transport;

#[cfg(unix)]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use palladin_browser_bridge::InjectionFormDefinition;
    use palladin_browser_bridge::secure_transport::{
        BrowserHostIdentity, INJECT_PROVIDER_PROTOCOL,
    };
    use std::{path::PathBuf, time::Duration};
    let mut args = std::env::args().skip(1);
    let mode = args.next().ok_or("mode missing")?;
    let root = PathBuf::from(args.next().ok_or("root missing")?);
    let identity = BrowserHostIdentity::from_secret_bytes([41; 32]);
    if mode == "host" {
        let origin = palladin_cli::browser::ChromeExtensionOrigin::from_native_arguments(
            args.map(Into::into),
        )
        .ok_or("invalid extension origin")?;
        palladin_cli::native_browser::serve_native_host(
            &root,
            &identity,
            origin,
            (tokio::io::stdin(), tokio::io::stdout()),
            |_| Ok(()),
        )
        .await?;
        return Ok(());
    }
    if mode == "discover" {
        let report = transport::discover_browser_sessions(&root, &identity).await?;
        println!("{}", serde_json::to_string(&report)?);
        return Ok(());
    }
    let tab_id = args.next().ok_or("tab missing")?.parse()?;
    let page_url = args.next().ok_or("URL missing")?;
    if !page_url.starts_with("https://login.example.test/") {
        return Err("synthetic host only".into());
    }
    let hold_ms: u64 = args.next().unwrap_or_else(|| "0".into()).parse()?;
    let count: usize = args.next().unwrap_or_else(|| "1".into()).parse()?;
    let browser_session = args.next();
    let form: InjectionFormDefinition = serde_json::from_value(serde_json::json!({
        "version": 1, "steps": [{"fields": [
            {"entryFieldId":"credential.username", "selector":"#username", "control":"text"},
            {"entryFieldId":"credential.password", "selector":"#password", "control":"password"}
        ], "submit":{"action":"click", "selector":"#submit"}}]
    }))?;
    for _ in 0..count {
        let mut random = [0; 16];
        getrandom::fill(&mut random)?;
        let nonce = hex::encode(random);
        let (mut client, prepared) = transport::ExtensionClient::connect_prepared(
            &root,
            &identity,
            &nonce,
            Some(BrowserTarget {
                tab_id,
                page_url: &page_url,
                browser_session: browser_session.as_deref(),
            }),
            false,
        )
        .await?;
        println!("prepared:{}", prepared.outcome);
        if prepared.outcome != "ready" {
            return Err("preparation failed".into());
        }
        tokio::time::sleep(Duration::from_millis(hold_ms)).await;
        getrandom::fill(&mut random)?;
        let transaction_id = hex::encode(random);
        let request = transport::InjectRequest {
            expires_at: None,
            continue_live: None,
            protocol: INJECT_PROVIDER_PROTOCOL,
            message_type: "inject",
            transaction_id: &transaction_id,
            grant_id: "00000000-0000-4000-8000-000000000001",
            entry_id: "00000000-0000-4000-8000-000000000002",
            expected_domain: "login.example.test",
            form: &form,
            values: vec![
                transport::InjectFieldValue {
                    entry_field_id: "credential.username",
                    value: "synthetic@example.test",
                },
                transport::InjectFieldValue {
                    entry_field_id: "credential.password",
                    value: "Synthetic-password!42",
                },
            ],
        };
        let validity = Duration::from_secs(5);
        let sealed = client.seal_inject(
            &request,
            transport::monotonic_not_after_ns(transport::monotonic_now_ns()?, validity)?,
        )?;
        let result = client.send_inject(sealed, validity).await?;
        println!("injected:{}", result.outcome);
        if result.outcome != "injected" {
            return Err("injection failed".into());
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn main() {}
