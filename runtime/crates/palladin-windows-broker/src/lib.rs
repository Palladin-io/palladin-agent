#![deny(unsafe_op_in_unsafe_fn)]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[cfg(windows)]
mod windows;

#[cfg(windows)]
mod windows_store;

#[cfg(windows)]
mod companion;

#[cfg(windows)]
pub use windows::*;

#[cfg(windows)]
pub use windows_store::*;

#[cfg(windows)]
pub use companion::*;

pub const PIPE_NAME: &str = r"\\.\pipe\LOCAL\Palladin.Runtime.v1";
pub const SERVICE_NAME: &str = "PalladinRuntime";
pub const WORKER_FILE_NAME: &str = "palladin-worker.exe";

pub struct UserSessionLimiter {
    window: Duration,
    max_concurrent_sessions: u32,
    max_sessions_per_window: u32,
    states: Mutex<BTreeMap<String, UserSessionState>>,
}

struct UserSessionState {
    active: u32,
    attempts: u32,
    window_started: Instant,
}

pub struct UserSessionPermit {
    limiter: Arc<UserSessionLimiter>,
    user_sid: String,
}

impl UserSessionLimiter {
    #[must_use]
    pub fn new(
        window: Duration,
        max_concurrent_sessions: u32,
        max_sessions_per_window: u32,
    ) -> Self {
        Self {
            window,
            max_concurrent_sessions,
            max_sessions_per_window,
            states: Mutex::new(BTreeMap::new()),
        }
    }

    pub fn try_acquire(
        self: &Arc<Self>,
        user_sid: &str,
        now: Instant,
    ) -> Option<UserSessionPermit> {
        if self.max_concurrent_sessions == 0 || self.max_sessions_per_window == 0 {
            return None;
        }
        let mut states = self
            .states
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        states.retain(|_, state| {
            state.active > 0
                || now.saturating_duration_since(state.window_started) < self.window * 2
        });
        let state = states
            .entry(user_sid.to_owned())
            .or_insert(UserSessionState {
                active: 0,
                attempts: 0,
                window_started: now,
            });
        if now.saturating_duration_since(state.window_started) >= self.window {
            state.window_started = now;
            state.attempts = 0;
        }
        if state.active >= self.max_concurrent_sessions
            || state.attempts >= self.max_sessions_per_window
        {
            return None;
        }
        state.active = state.active.saturating_add(1);
        state.attempts = state.attempts.saturating_add(1);
        Some(UserSessionPermit {
            limiter: Arc::clone(self),
            user_sid: user_sid.to_owned(),
        })
    }
}

impl Drop for UserSessionPermit {
    fn drop(&mut self) {
        let mut states = self
            .limiter
            .states
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(state) = states.get_mut(&self.user_sid) {
            state.active = state.active.saturating_sub(1);
        }
    }
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum BrokerPathError {
    #[error("ProgramData root must be absolute")]
    ProgramDataNotAbsolute,
    #[error("caller SID is invalid")]
    InvalidCallerSid,
}

/// Returns the only allowed profile root for a caller. The value comes from
/// the authenticated token, never from IPC, argv, the caller environment, or
/// the LocalService account home.
pub fn broker_profile_root(
    program_data: &std::path::Path,
    authenticated_user_sid: &str,
) -> Result<std::path::PathBuf, BrokerPathError> {
    if !program_data.is_absolute() {
        return Err(BrokerPathError::ProgramDataNotAbsolute);
    }
    if !valid_windows_user_sid(authenticated_user_sid) {
        return Err(BrokerPathError::InvalidCallerSid);
    }
    Ok(program_data
        .join("Palladin")
        .join("Runtime")
        .join("v1")
        .join(authenticated_user_sid))
}

fn valid_windows_user_sid(value: &str) -> bool {
    if !value.starts_with("S-1-") || value.len() > 184 {
        return false;
    }
    value[2..].split('-').all(|component| {
        !component.is_empty() && component.bytes().all(|byte| byte.is_ascii_digit())
    })
}

#[cfg(not(windows))]
pub fn unsupported_platform() -> ! {
    panic!("Palladin Windows broker binaries can run only on Windows")
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use super::{BrokerPathError, UserSessionLimiter, broker_profile_root};

    #[test]
    fn profile_root_is_broker_owned_and_sid_scoped() {
        let root = if cfg!(windows) {
            Path::new(r"C:\ProgramData")
        } else {
            Path::new("/ProgramData")
        };
        assert!(
            broker_profile_root(root, "S-1-5-21-100-200-300-1001")
                .expect("root")
                .ends_with("Palladin/Runtime/v1/S-1-5-21-100-200-300-1001")
        );
    }

    #[test]
    fn profile_root_rejects_path_injection_and_relative_roots() {
        assert_eq!(
            broker_profile_root(Path::new("ProgramData"), "S-1-5-21-1"),
            Err(BrokerPathError::ProgramDataNotAbsolute)
        );
        let root = if cfg!(windows) {
            Path::new(r"C:\ProgramData")
        } else {
            Path::new("/ProgramData")
        };
        assert_eq!(
            broker_profile_root(root, "S-1-5-21-1/../../Users"),
            Err(BrokerPathError::InvalidCallerSid)
        );
    }

    #[test]
    fn one_sid_cannot_monopolize_concurrent_sessions() {
        let limiter = Arc::new(UserSessionLimiter::new(Duration::from_secs(60), 2, 10));
        let now = Instant::now();
        let first = limiter.try_acquire("S-1-5-21-1", now).expect("first");
        let second = limiter.try_acquire("S-1-5-21-1", now).expect("second");
        assert!(limiter.try_acquire("S-1-5-21-1", now).is_none());
        assert!(limiter.try_acquire("S-1-5-21-2", now).is_some());
        drop(first);
        assert!(limiter.try_acquire("S-1-5-21-1", now).is_some());
        drop(second);
    }

    #[test]
    fn sid_session_rate_is_bounded_per_window() {
        let limiter = Arc::new(UserSessionLimiter::new(Duration::from_secs(60), 2, 2));
        let now = Instant::now();
        drop(limiter.try_acquire("S-1-5-21-1", now).expect("first"));
        drop(limiter.try_acquire("S-1-5-21-1", now).expect("second"));
        assert!(limiter.try_acquire("S-1-5-21-1", now).is_none());
        assert!(
            limiter
                .try_acquire("S-1-5-21-1", now + Duration::from_secs(60))
                .is_some()
        );
    }
}
