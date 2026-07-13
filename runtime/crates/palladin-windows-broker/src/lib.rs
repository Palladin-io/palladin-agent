#![deny(unsafe_op_in_unsafe_fn)]

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

    use super::{BrokerPathError, broker_profile_root};

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
}
