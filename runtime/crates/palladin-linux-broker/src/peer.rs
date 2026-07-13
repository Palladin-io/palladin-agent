use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use nix::unistd::{Uid, User};
use thiserror::Error;
use tokio::net::UnixStream;
use url::{Host, Url};

const RECORD_VERSION: &str = "1";
const PRODUCTION_ORIGIN: &str = "https://api.palladin.io";
const STAGING_ORIGIN: &str = "https://api.stage.palladin.io";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedPrincipal {
    pub uid: u32,
    pub account: String,
    pub principal_id: String,
    pub profile: String,
    pub host: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedPeer {
    pub uid: u32,
    pub principal_id: String,
    pub profile: String,
    pub host: String,
}

pub fn authenticate_peer(stream: &UnixStream) -> Result<AuthenticatedPeer, PeerError> {
    let credentials = stream.peer_cred().map_err(|_| PeerError::Credentials)?;
    let uid = credentials.uid();
    if uid == 0 {
        return Err(PeerError::Credentials);
    }
    let principal = load_authorized_principal(Path::new("/etc/palladin/agents.d"), uid)?;
    Ok(AuthenticatedPeer {
        uid,
        principal_id: principal.principal_id,
        profile: principal.profile,
        host: principal.host,
    })
}

pub fn load_authorized_principal(
    directory: &Path,
    uid: u32,
) -> Result<AuthorizedPrincipal, PeerError> {
    let directory_metadata =
        fs::symlink_metadata(directory).map_err(|_| PeerError::UnauthorizedUid)?;
    if !directory_metadata.file_type().is_dir()
        || directory_metadata.file_type().is_symlink()
        || directory_metadata.uid() != 0
        || directory_metadata.permissions().mode() & 0o022 != 0
    {
        return Err(PeerError::AuthorizationConfiguration);
    }
    let path = directory.join(uid.to_string());
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(PeerError::UnauthorizedUid);
        }
        Err(_) => return Err(PeerError::AuthorizationConfiguration),
    };
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o777 != 0o644
        || metadata.nlink() != 1
        || metadata.size() > 2048
    {
        return Err(PeerError::AuthorizationConfiguration);
    }
    let contents = fs::read_to_string(path).map_err(|_| PeerError::AuthorizationConfiguration)?;
    parse_principal_record(&contents, uid)
}

fn parse_principal_record(
    contents: &str,
    expected_uid: u32,
) -> Result<AuthorizedPrincipal, PeerError> {
    let mut lines = contents.lines();
    let version = record_value(lines.next(), "version")?;
    let status = record_value(lines.next(), "status")?;
    let uid = record_value(lines.next(), "uid")?
        .parse::<u32>()
        .map_err(|_| PeerError::AuthorizationConfiguration)?;
    let account = record_value(lines.next(), "account")?;
    let principal_id = record_value(lines.next(), "principal")?;
    let profile = record_value(lines.next(), "profile")?;
    let host = record_value(lines.next(), "host")?;
    if lines.any(|line| !line.is_empty())
        || version != RECORD_VERSION
        || uid != expected_uid
        || status != "active"
        || !valid_account(account)
        || !valid_principal_id(principal_id)
        || !valid_profile(profile)
        || !valid_authorized_host(host)
    {
        return Err(if status == "revoked" {
            PeerError::RevokedUid
        } else {
            PeerError::AuthorizationConfiguration
        });
    }
    let user = User::from_uid(Uid::from_raw(uid))
        .map_err(|_| PeerError::AuthorizationConfiguration)?
        .ok_or(PeerError::AuthorizationConfiguration)?;
    if user.name != account {
        return Err(PeerError::AuthorizationConfiguration);
    }
    Ok(AuthorizedPrincipal {
        uid,
        account: account.to_owned(),
        principal_id: principal_id.to_owned(),
        profile: profile.to_owned(),
        host: host.to_owned(),
    })
}

fn record_value<'a>(line: Option<&'a str>, key: &str) -> Result<&'a str, PeerError> {
    let line = line.ok_or(PeerError::AuthorizationConfiguration)?;
    line.strip_prefix(key)
        .and_then(|value| value.strip_prefix('='))
        .filter(|value| !value.is_empty())
        .ok_or(PeerError::AuthorizationConfiguration)
}

fn valid_account(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && !value.starts_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_principal_id(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_profile(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value != "."
        && value != ".."
        && !value.starts_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_authorized_host(value: &str) -> bool {
    if matches!(value, PRODUCTION_ORIGIN | STAGING_ORIGIN) {
        return true;
    }
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    let literal_loopback = matches!(
        url.host(),
        Some(Host::Ipv4(address)) if address == std::net::Ipv4Addr::LOCALHOST
    ) || matches!(
        url.host(),
        Some(Host::Ipv6(address)) if address == std::net::Ipv6Addr::LOCALHOST
    );
    url.scheme() == "http"
        && url.port().is_some_and(|port| port != 0)
        && url.path() == "/"
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && literal_loopback
}

pub fn principal_profile_root(state_root: &Path, principal_id: &str) -> Result<PathBuf, PeerError> {
    if !state_root.is_absolute() || !valid_principal_id(principal_id) {
        return Err(PeerError::InvalidStateRoot);
    }
    Ok(state_root.join("agents").join(principal_id))
}

pub fn prepare_principal_profile_root(
    state_root: &Path,
    principal_id: &str,
) -> Result<PathBuf, PeerError> {
    validate_owned_directory(state_root, 0o700)?;
    let agents = state_root.join("agents");
    create_or_validate_directory(&agents)?;
    let profile = principal_profile_root(state_root, principal_id)?;
    create_or_validate_directory(&profile)?;
    Ok(profile)
}

fn create_or_validate_directory(path: &Path) -> Result<(), PeerError> {
    match fs::symlink_metadata(path) {
        Ok(_) => validate_owned_directory(path, 0o700),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path).map_err(|_| PeerError::State)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .map_err(|_| PeerError::State)?;
            validate_owned_directory(path, 0o700)
        }
        Err(_) => Err(PeerError::State),
    }
}

fn validate_owned_directory(path: &Path, mode: u32) -> Result<(), PeerError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| PeerError::State)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.permissions().mode() & 0o777 != mode
    {
        return Err(PeerError::State);
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum PeerError {
    #[error("Unix peer credentials are unavailable")]
    Credentials,
    #[error("this OS account has never been designated as a Palladin Agent UID")]
    UnauthorizedUid,
    #[error("this Palladin Agent UID has been revoked")]
    RevokedUid,
    #[error("the dedicated Agent UID authorization is invalid")]
    AuthorizationConfiguration,
    #[error("the broker state root is invalid")]
    InvalidStateRoot,
    #[error("broker-owned state permissions are invalid")]
    State,
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    use super::{
        PeerError, parse_principal_record, prepare_principal_profile_root, principal_profile_root,
    };

    #[test]
    fn immutable_principal_is_the_state_selector_not_reusable_uid() {
        let root = Path::new("/var/lib/palladin-runtime/v1");
        assert_eq!(
            principal_profile_root(root, "0123456789abcdef0123456789abcdef").expect("root"),
            Path::new("/var/lib/palladin-runtime/v1/agents/0123456789abcdef0123456789abcdef")
        );
        assert!(matches!(
            principal_profile_root(root, "1001"),
            Err(PeerError::InvalidStateRoot)
        ));
    }

    #[test]
    fn tampered_state_permissions_fail_closed() {
        let root = tempfile::tempdir().expect("root");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).expect("permissions");
        assert!(matches!(
            prepare_principal_profile_root(root.path(), "0123456789abcdef0123456789abcdef"),
            Err(PeerError::State)
        ));
    }

    #[test]
    fn revoked_record_is_a_durable_fail_closed_tombstone() {
        let record = format!(
            "version=1\nstatus=revoked\nuid={}\naccount={}\nprincipal=0123456789abcdef0123456789abcdef\nprofile=production\nhost=https://api.palladin.io\n",
            nix::unistd::geteuid().as_raw(),
            UserName::current()
        );
        assert!(matches!(
            parse_principal_record(&record, nix::unistd::geteuid().as_raw()),
            Err(PeerError::RevokedUid)
        ));
    }

    #[test]
    fn record_rejects_uid_or_account_rebinding_and_untrusted_hosts() {
        let uid = nix::unistd::geteuid().as_raw();
        let account = UserName::current();
        let valid = format!(
            "version=1\nstatus=active\nuid={uid}\naccount={account}\nprincipal=0123456789abcdef0123456789abcdef\nprofile=production\nhost=https://api.stage.palladin.io\n"
        );
        assert!(parse_principal_record(&valid, uid).is_ok());
        assert!(parse_principal_record(&valid, uid.saturating_add(1)).is_err());
        let attacker = valid.replace("https://api.stage.palladin.io", "https://attacker.example");
        assert!(parse_principal_record(&attacker, uid).is_err());
    }

    struct UserName;

    impl UserName {
        fn current() -> String {
            nix::unistd::User::from_uid(nix::unistd::geteuid())
                .expect("lookup")
                .expect("user")
                .name
        }
    }
}
