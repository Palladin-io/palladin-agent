#![forbid(unsafe_code)]

use std::path::PathBuf;

use directories::BaseDirs;
use thiserror::Error;

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
compile_error!("Palladin runtime supports only macOS, Windows, and Linux");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlatformInfo {
    pub operating_system: &'static str,
    pub architecture: &'static str,
    pub standalone_tier: &'static str,
    pub hardened_candidate: &'static str,
}

#[derive(Debug, Error)]
pub enum PlatformError {
    #[error("the operating system did not provide a home directory")]
    HomeDirectoryUnavailable,
}

#[must_use]
pub const fn current() -> PlatformInfo {
    PlatformInfo {
        operating_system: std::env::consts::OS,
        architecture: std::env::consts::ARCH,
        standalone_tier: "Convenience",
        hardened_candidate: hardened_candidate(),
    }
}

pub fn palladin_root() -> Result<PathBuf, PlatformError> {
    let base = BaseDirs::new().ok_or(PlatformError::HomeDirectoryUnavailable)?;
    Ok(base.home_dir().join(".palladin"))
}

#[cfg(target_os = "macos")]
const fn hardened_candidate() -> &'static str {
    "provisioned Data Protection Keychain bundle plus user presence"
}

#[cfg(target_os = "windows")]
const fn hardened_candidate() -> &'static str {
    "optional restricted service-SID broker"
}

#[cfg(target_os = "linux")]
const fn hardened_candidate() -> &'static str {
    "dedicated UID/systemd service or dedicated Agent container"
}

#[cfg(test)]
mod tests {
    use super::current;

    #[test]
    fn reports_only_compile_time_platform_metadata() {
        let info = current();
        assert!(!info.operating_system.is_empty());
        assert!(!info.architecture.is_empty());
        assert_eq!(info.standalone_tier, "Convenience");
        assert!(!info.hardened_candidate.is_empty());
    }
}
