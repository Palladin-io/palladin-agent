use std::future::Future;
use std::time::Duration;

use palladin_api::CredentialAccess;
use palladin_core::terminal::shorten_identifier;
use serde::Serialize;
use thiserror::Error;
use tokio::time::{Instant, timeout_at};
use tokio_util::sync::CancellationToken;

pub const DEFAULT_WAIT_MS: u64 = 180_000;
pub const MAX_WAIT_MS: u64 = 300_000;
pub const DEFAULT_POLL_MS: u64 = 30_000;
pub const DEFAULT_HEARTBEAT_MS: u64 = 10_000;
pub const DEFAULT_POLL_TIMEOUT_MS: u64 = 10_000;
pub const MIN_POLL_MS: u64 = 5_000;
pub const MIN_HEARTBEAT_MS: u64 = 1_000;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ProgressMode {
    #[default]
    Plain,
    Json,
    None,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaitPolicy {
    pub wait_ms: u64,
    pub poll_ms: u64,
    pub heartbeat_ms: u64,
    pub poll_timeout_ms: u64,
    pub progress: ProgressMode,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WaitHints {
    pub poll_interval_ms: Option<u64>,
    pub max_wait_ms: Option<u64>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WaitOptions {
    pub wait_ms: Option<u64>,
    pub poll_ms: Option<u64>,
    pub progress: Option<ProgressMode>,
}

pub fn resolve_wait_policy(
    options: WaitOptions,
    hints: WaitHints,
) -> Result<WaitPolicy, WaitPolicyError> {
    let wait_ms = options
        .wait_ms
        .or(hints.max_wait_ms)
        .unwrap_or(DEFAULT_WAIT_MS);
    if wait_ms > MAX_WAIT_MS {
        return Err(WaitPolicyError::WaitTooLong);
    }
    let poll_ms = options
        .poll_ms
        .or(hints.poll_interval_ms)
        .unwrap_or(DEFAULT_POLL_MS)
        .max(MIN_POLL_MS);
    let heartbeat_ms = DEFAULT_HEARTBEAT_MS.min(poll_ms).max(MIN_HEARTBEAT_MS);
    Ok(WaitPolicy {
        wait_ms,
        poll_ms,
        heartbeat_ms,
        poll_timeout_ms: DEFAULT_POLL_TIMEOUT_MS.min(heartbeat_ms),
        progress: options.progress.unwrap_or_default(),
    })
}

#[derive(Clone, Eq, PartialEq)]
pub struct HeartbeatInfo {
    pub grant_id: Option<String>,
    pub elapsed_ms: u64,
    pub deadline_ms: u64,
}

impl std::fmt::Debug for HeartbeatInfo {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HeartbeatInfo")
            .field("grant_id", &self.grant_id.as_ref().map(|_| "[REDACTED]"))
            .field("elapsed_ms", &self.elapsed_ms)
            .field("deadline_ms", &self.deadline_ms)
            .finish()
    }
}

#[must_use]
pub fn heartbeat_line(mode: ProgressMode, info: &HeartbeatInfo) -> Option<String> {
    match mode {
        ProgressMode::None => None,
        ProgressMode::Json => serde_json::to_string(&JsonHeartbeat {
            event: "awaiting-approval",
            grant_id: info.grant_id.as_deref().map(shorten_identifier),
            elapsed_ms: info.elapsed_ms,
            deadline_ms: info.deadline_ms,
        })
        .ok()
        .map(|value| format!("{value}\n")),
        ProgressMode::Plain => Some(format!(
            "[palladin] awaiting approval - grant={} - {}s/{}s - approve in the app\n",
            info.grant_id
                .as_deref()
                .map(shorten_identifier)
                .unwrap_or_else(|| "unknown".to_owned()),
            info.elapsed_ms / 1_000,
            info.deadline_ms / 1_000
        )),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsonHeartbeat {
    event: &'static str,
    grant_id: Option<String>,
    elapsed_ms: u64,
    deadline_ms: u64,
}

pub async fn await_grant<P, PollFuture, S, SleepFuture, H, E>(
    initial: CredentialAccess,
    policy: WaitPolicy,
    cancellation: &CancellationToken,
    mut poll: P,
    mut sleep: S,
    mut heartbeat: H,
) -> Result<CredentialAccess, WaitError<E>>
where
    P: FnMut() -> PollFuture,
    PollFuture: Future<Output = Result<CredentialAccess, E>>,
    S: FnMut(Duration) -> SleepFuture,
    SleepFuture: Future<Output = ()>,
    H: FnMut(HeartbeatInfo),
{
    let grant_id = match &initial {
        CredentialAccess::Pending { grant_id, .. } => grant_id.clone(),
        _ => return Ok(initial),
    };
    if policy.wait_ms == 0 {
        return Ok(initial);
    }
    let poll_ms = policy.poll_ms.max(MIN_POLL_MS);
    let heartbeat_ms = policy.heartbeat_ms.max(MIN_HEARTBEAT_MS).min(poll_ms);
    let poll_timeout_ms = policy.poll_timeout_ms.max(1).min(heartbeat_ms);

    let mut last = initial;
    let mut grant_id = Some(grant_id);
    let mut elapsed_ms = 0_u64;
    let mut next_poll_ms = poll_ms;
    let mut next_heartbeat_ms = heartbeat_ms;
    let wall_deadline = Instant::now() + Duration::from_millis(policy.wait_ms);

    while elapsed_ms < policy.wait_ms {
        if cancellation.is_cancelled() {
            return Err(WaitError::Cancelled);
        }
        let next_event_ms = next_poll_ms.min(next_heartbeat_ms).min(policy.wait_ms);
        let step_ms = next_event_ms.saturating_sub(elapsed_ms);
        let sleep_result = tokio::select! {
            () = cancellation.cancelled() => return Err(WaitError::Cancelled),
            result = timeout_at(wall_deadline, sleep(Duration::from_millis(step_ms))) => result,
        };
        if sleep_result.is_err() {
            return Ok(last);
        }
        elapsed_ms = next_event_ms;

        if elapsed_ms >= next_heartbeat_ms {
            heartbeat(HeartbeatInfo {
                grant_id: grant_id.clone(),
                elapsed_ms,
                deadline_ms: policy.wait_ms,
            });
            next_heartbeat_ms = next_heartbeat_ms.saturating_add(heartbeat_ms);
        }

        if elapsed_ms >= next_poll_ms {
            if cancellation.is_cancelled() {
                return Err(WaitError::Cancelled);
            }
            let poll_deadline =
                wall_deadline.min(Instant::now() + Duration::from_millis(poll_timeout_ms));
            let result = tokio::select! {
                () = cancellation.cancelled() => return Err(WaitError::Cancelled),
                result = timeout_at(poll_deadline, poll()) => result,
            };
            let result = match result {
                Ok(result) => result.map_err(WaitError::Poll)?,
                Err(_) => {
                    heartbeat(HeartbeatInfo {
                        grant_id: grant_id.clone(),
                        elapsed_ms,
                        deadline_ms: policy.wait_ms,
                    });
                    next_poll_ms = next_poll_ms.saturating_add(poll_ms);
                    continue;
                }
            };
            if !matches!(result, CredentialAccess::Pending { .. }) {
                return Ok(result);
            }
            if let CredentialAccess::Pending {
                grant_id: current, ..
            } = &result
                && !current.is_empty()
            {
                grant_id = Some(current.clone());
            }
            last = result;
            next_poll_ms = next_poll_ms.saturating_add(poll_ms);
        }
    }
    Ok(last)
}

#[must_use]
pub fn signal_cancellation_token() -> CancellationToken {
    let token = CancellationToken::new();
    let signal = token.clone();
    tokio::spawn(async move {
        wait_for_shutdown_signal().await;
        signal.cancel();
    });
    token
}

#[cfg(unix)]
async fn wait_for_shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    let terminate = signal(SignalKind::terminate());
    if let Ok(mut terminate) = terminate {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    } else {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(windows)]
async fn wait_for_shutdown_signal() {
    use tokio::signal::windows::ctrl_break;

    if let Ok(mut ctrl_break) = ctrl_break() {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = ctrl_break.recv() => {}
        }
    } else {
        let _ = tokio::signal::ctrl_c().await;
    }
}

pub fn parse_duration(value: &str) -> Result<u64, DurationParseError> {
    let normalized = value.trim().to_ascii_lowercase();
    let (number, multiplier) = if let Some(number) = normalized.strip_suffix("ms") {
        (number, 1_u64)
    } else if let Some(number) = normalized.strip_suffix('s') {
        (number, 1_000)
    } else if let Some(number) = normalized.strip_suffix('m') {
        (number, 60_000)
    } else if let Some(number) = normalized.strip_suffix('h') {
        (number, 3_600_000)
    } else {
        (normalized.as_str(), 1_000)
    };
    let valid_decimal = !number.is_empty()
        && !number.starts_with('.')
        && !number.ends_with('.')
        && number
            .chars()
            .all(|character| character.is_ascii_digit() || character == '.')
        && number.matches('.').count() <= 1;
    if !valid_decimal {
        return Err(DurationParseError::Invalid);
    }
    let number = number
        .parse::<f64>()
        .map_err(|_| DurationParseError::Invalid)?;
    let milliseconds = number * multiplier as f64;
    if !milliseconds.is_finite() || milliseconds > 9_007_199_254_740_991_f64 {
        return Err(DurationParseError::Invalid);
    }
    Ok(milliseconds.round() as u64)
}

pub fn parse_wait_duration(value: &str) -> Result<u64, DurationParseError> {
    let milliseconds = parse_duration(value)?;
    if milliseconds > MAX_WAIT_MS {
        return Err(DurationParseError::WaitTooLong);
    }
    Ok(milliseconds)
}

#[derive(Debug, Error)]
pub enum WaitError<E> {
    #[error("credential wait was cancelled")]
    Cancelled,
    #[error("credential poll failed")]
    Poll(E),
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum DurationParseError {
    #[error("invalid duration; use a number with ms, s, m, or h")]
    Invalid,
    #[error("wait duration exceeds the five-minute limit")]
    WaitTooLong,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum WaitPolicyError {
    #[error("wait duration exceeds the five-minute limit")]
    WaitTooLong,
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::sync::{Arc, Mutex};

    use palladin_api::CredentialAccess;
    use tokio_util::sync::CancellationToken;

    use super::{
        DEFAULT_POLL_MS, DEFAULT_WAIT_MS, DurationParseError, HeartbeatInfo, MAX_WAIT_MS,
        MIN_POLL_MS, ProgressMode, WaitError, WaitHints, WaitOptions, WaitPolicyError, await_grant,
        heartbeat_line, parse_duration, parse_wait_duration, resolve_wait_policy,
    };

    fn pending(id: &str) -> CredentialAccess {
        CredentialAccess::Pending {
            grant_id: id.to_owned(),
            created: None,
            poll_interval_ms: None,
            max_wait_ms: None,
        }
    }

    #[test]
    fn policy_hierarchy_and_duration_parsing_match_the_cli_contract() {
        let defaults =
            resolve_wait_policy(WaitOptions::default(), WaitHints::default()).expect("defaults");
        assert_eq!(defaults.wait_ms, DEFAULT_WAIT_MS);
        assert_eq!(defaults.poll_ms, DEFAULT_POLL_MS);
        let overridden = resolve_wait_policy(
            WaitOptions {
                wait_ms: Some(60_000),
                poll_ms: Some(1_000),
                progress: Some(ProgressMode::Json),
            },
            WaitHints {
                poll_interval_ms: Some(45_000),
                max_wait_ms: Some(120_000),
            },
        )
        .expect("overrides");
        assert_eq!(overridden.wait_ms, 60_000);
        assert_eq!(overridden.poll_ms, MIN_POLL_MS);
        assert_eq!(parse_duration("3M").expect("duration"), 180_000);
        assert_eq!(parse_duration("500ms").expect("duration"), 500);
        assert_eq!(parse_duration("1.5s").expect("duration"), 1_500);
        assert_eq!(parse_duration("soon"), Err(DurationParseError::Invalid));
    }

    #[test]
    fn five_minute_wait_boundary_is_enforced_for_parsed_and_resolved_options() {
        assert_eq!(parse_wait_duration("5m"), Ok(MAX_WAIT_MS));
        assert_eq!(parse_wait_duration("300000ms"), Ok(MAX_WAIT_MS));
        assert_eq!(
            parse_wait_duration("300001ms"),
            Err(DurationParseError::WaitTooLong)
        );

        let accepted = resolve_wait_policy(
            WaitOptions {
                wait_ms: Some(MAX_WAIT_MS),
                ..WaitOptions::default()
            },
            WaitHints::default(),
        )
        .expect("five-minute boundary");
        assert_eq!(accepted.wait_ms, MAX_WAIT_MS);
        assert_eq!(
            resolve_wait_policy(
                WaitOptions {
                    wait_ms: Some(MAX_WAIT_MS + 1),
                    ..WaitOptions::default()
                },
                WaitHints::default(),
            ),
            Err(WaitPolicyError::WaitTooLong)
        );
        assert_eq!(
            resolve_wait_policy(
                WaitOptions::default(),
                WaitHints {
                    max_wait_ms: Some(MAX_WAIT_MS + 1),
                    ..WaitHints::default()
                },
            ),
            Err(WaitPolicyError::WaitTooLong)
        );
    }

    #[tokio::test]
    async fn polls_at_exact_non_multiple_intervals_and_stops_on_granted() {
        let sleeps = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::clone(&sleeps);
        let heartbeats = Arc::new(Mutex::new(Vec::<HeartbeatInfo>::new()));
        let emitted = Arc::clone(&heartbeats);
        let mut responses = vec![pending("grant-two"), CredentialAccess::Denied].into_iter();
        let result = await_grant(
            pending("grant-one"),
            super::WaitPolicy {
                wait_ms: 40_000,
                poll_ms: 15_000,
                heartbeat_ms: 10_000,
                poll_timeout_ms: 10_000,
                progress: ProgressMode::Plain,
            },
            &CancellationToken::new(),
            || {
                let response = responses.next().expect("response");
                async move { Ok::<_, Infallible>(response) }
            },
            move |duration| {
                let observed = Arc::clone(&observed);
                async move {
                    observed
                        .lock()
                        .expect("sleeps")
                        .push(duration.as_millis() as u64)
                }
            },
            move |info| emitted.lock().expect("heartbeats").push(info),
        )
        .await
        .expect("wait");
        assert!(matches!(result, CredentialAccess::Denied));
        assert_eq!(
            *sleeps.lock().expect("sleeps"),
            vec![10_000, 5_000, 5_000, 10_000]
        );
        let heartbeat_ids = heartbeats
            .lock()
            .expect("heartbeats")
            .iter()
            .map(|info| info.grant_id.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            heartbeat_ids,
            vec![
                Some("grant-one".to_owned()),
                Some("grant-two".to_owned()),
                Some("grant-two".to_owned())
            ]
        );
    }

    #[tokio::test]
    async fn cancellation_interrupts_sleep_and_maps_to_a_distinct_error() {
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let result = await_grant(
            pending("grant"),
            resolve_wait_policy(WaitOptions::default(), WaitHints::default())
                .expect("default policy"),
            &cancellation,
            || async { Ok::<_, Infallible>(CredentialAccess::Denied) },
            |_| async { std::future::pending::<()>().await },
            |_| {},
        )
        .await;
        assert!(matches!(result, Err(WaitError::Cancelled)));
    }

    #[tokio::test]
    async fn cancellation_interrupts_an_in_flight_poll() {
        let cancellation = CancellationToken::new();
        let trigger = cancellation.clone();
        let result = await_grant(
            pending("grant"),
            super::WaitPolicy {
                wait_ms: 6_000,
                poll_ms: 5_000,
                heartbeat_ms: 1_000,
                poll_timeout_ms: 1_000,
                progress: ProgressMode::None,
            },
            &cancellation,
            move || {
                trigger.cancel();
                async { std::future::pending::<Result<CredentialAccess, Infallible>>().await }
            },
            |_| async {},
            |_| {},
        )
        .await;
        assert!(matches!(result, Err(WaitError::Cancelled)));
    }

    #[tokio::test]
    async fn a_hung_poll_is_bounded_by_the_heartbeat_interval() {
        let started = tokio::time::Instant::now();
        let heartbeats = Arc::new(Mutex::new(Vec::<HeartbeatInfo>::new()));
        let observed = Arc::clone(&heartbeats);
        let result = await_grant(
            pending("grant"),
            super::WaitPolicy {
                wait_ms: 6_000,
                poll_ms: 5_000,
                heartbeat_ms: 1_000,
                poll_timeout_ms: 10,
                progress: ProgressMode::None,
            },
            &CancellationToken::new(),
            || async { std::future::pending::<Result<CredentialAccess, Infallible>>().await },
            |_| async {},
            move |info| observed.lock().expect("heartbeats").push(info),
        )
        .await
        .expect("wait");
        assert!(matches!(result, CredentialAccess::Pending { .. }));
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        assert!(heartbeats.lock().expect("heartbeats").len() >= 6);
    }

    #[test]
    fn heartbeat_is_stderr_ready_and_shortens_public_ids() {
        let info = HeartbeatInfo {
            grant_id: Some("1234567890abcdefghijklmnopqrstuvwxyz".to_owned()),
            elapsed_ms: 40_000,
            deadline_ms: 180_000,
        };
        let plain = heartbeat_line(ProgressMode::Plain, &info).expect("plain");
        assert!(plain.contains("12345678…uvwxyz"));
        let json = heartbeat_line(ProgressMode::Json, &info).expect("json");
        assert!(json.contains("awaiting-approval"));
        assert_eq!(heartbeat_line(ProgressMode::None, &info), None);
    }
}
