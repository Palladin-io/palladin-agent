#![forbid(unsafe_code)]

use std::path::PathBuf;

use thiserror::Error;

pub mod broker_protocol;
pub mod legacy_typescript_store;
pub mod secure_store;

#[cfg(all(target_os = "macos", feature = "macos-hardened"))]
mod macos_hardened_store;

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
    #[error("the operating system account directory is unavailable")]
    AccountDirectoryUnavailable,
    #[error("the operating system account lookup failed")]
    AccountLookupFailed,
}

#[must_use]
pub fn current() -> PlatformInfo {
    PlatformInfo {
        operating_system: std::env::consts::OS,
        architecture: std::env::consts::ARCH,
        standalone_tier: standalone_tier(),
        hardened_candidate: hardened_candidate(),
    }
}

fn standalone_tier() -> &'static str {
    #[cfg(all(target_os = "macos", feature = "macos-hardened"))]
    {
        if crate::macos_hardened_store::runtime_is_hardened() {
            "Hardened"
        } else {
            "Unavailable"
        }
    }
    #[cfg(not(all(target_os = "macos", feature = "macos-hardened")))]
    {
        "Convenience"
    }
}

pub fn palladin_root() -> Result<PathBuf, PlatformError> {
    Ok(account_home()?.join(".palladin"))
}

#[cfg(unix)]
fn account_home() -> Result<PathBuf, PlatformError> {
    use nix::unistd::{Uid, User};

    let user = User::from_uid(Uid::current()).map_err(|_| PlatformError::AccountLookupFailed)?;
    user.map(|account| account.dir)
        .ok_or(PlatformError::AccountDirectoryUnavailable)
}

#[cfg(windows)]
fn account_home() -> Result<PathBuf, PlatformError> {
    use directories::BaseDirs;

    let base = BaseDirs::new().ok_or(PlatformError::AccountDirectoryUnavailable)?;
    Ok(base.home_dir().to_path_buf())
}

#[cfg(target_os = "macos")]
const fn hardened_candidate() -> &'static str {
    "provisioned Data Protection Keychain bundle plus user presence"
}

#[cfg(target_os = "windows")]
const fn hardened_candidate() -> &'static str {
    "optional restricted service-SID broker"
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
const fn hardened_candidate() -> &'static str {
    "dedicated UID with the systemd 252+ DEB/RPM broker boundary"
}

#[cfg(all(target_os = "linux", target_env = "musl"))]
const fn hardened_candidate() -> &'static str {
    "unsupported - Alpine/OpenRC Hardened is not available in the MVP"
}

#[cfg(test)]
mod tests {
    use super::{current, palladin_root};

    #[test]
    fn reports_only_compile_time_platform_metadata() {
        let info = current();
        assert!(!info.operating_system.is_empty());
        assert!(!info.architecture.is_empty());
        #[cfg(all(target_os = "macos", feature = "macos-hardened"))]
        assert!(matches!(info.standalone_tier, "Hardened" | "Unavailable"));
        #[cfg(not(all(target_os = "macos", feature = "macos-hardened")))]
        assert_eq!(info.standalone_tier, "Convenience");
        assert!(!info.hardened_candidate.is_empty());
        #[cfg(all(target_os = "linux", target_env = "musl"))]
        assert_eq!(
            info.hardened_candidate,
            "unsupported - Alpine/OpenRC Hardened is not available in the MVP"
        );
    }

    #[test]
    fn data_root_comes_from_an_absolute_os_account_directory() {
        let root = palladin_root().expect("OS account directory");
        assert!(root.is_absolute());
        assert!(root.ends_with(".palladin"));
    }
}
