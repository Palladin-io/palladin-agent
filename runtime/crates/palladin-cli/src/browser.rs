use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use palladin_browser_bridge::secure_transport::BrowserHostIdentity;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::{Uuid, Version};

pub const NATIVE_HOST_NAME: &str = "io.palladin.browser_bridge";
pub const CHROME_EXTENSION_ID: &str = "hmljnknogdeonphikmeofcbkikmpokba";
pub const CHROME_EXTENSION_ORIGIN: &str = "chrome-extension://hmljnknogdeonphikmeofcbkikmpokba/";
pub const PAIRING_PROTOCOL: &str = "palladin.inject-pairing.v1";
pub const PAIRING_DISCOVER_TYPE: &str = "pairing.discover";
pub const PAIRING_OFFER_TYPE: &str = "pairing.offer";
const NATIVE_HOST_DESCRIPTION: &str = "Palladin authenticated Chrome Inject bridge";

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingBundle {
    pub protocol: &'static str,
    pub host_signing_public_key: String,
    pub fingerprint: String,
}

impl PairingBundle {
    #[must_use]
    pub fn from_identity(identity: &BrowserHostIdentity) -> Self {
        Self {
            protocol: PAIRING_PROTOCOL,
            host_signing_public_key: identity.public_key(),
            fingerprint: identity.fingerprint(),
        }
    }
}

/// Public, value-free request used only to discover the installed native host.
///
/// Discovery never creates trust. The extension keeps the returned key in memory, shows the
/// fingerprint for out-of-band comparison with the CLI, and persists the pin only after an
/// explicit user confirmation.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PairingDiscoveryRequest {
    pub protocol: String,
    #[serde(rename = "type")]
    pub message_type: String,
    pub extension_origin: String,
    pub challenge: String,
}

impl PairingDiscoveryRequest {
    pub fn validate(&self) -> Result<(), BrowserInstallError> {
        let challenge =
            Uuid::parse_str(&self.challenge).map_err(|_| BrowserInstallError::PairingDiscovery)?;
        if self.protocol != PAIRING_PROTOCOL
            || self.message_type != PAIRING_DISCOVER_TYPE
            || self.extension_origin != CHROME_EXTENSION_ORIGIN
            || challenge.get_version() != Some(Version::Random)
            || challenge.to_string() != self.challenge
        {
            return Err(BrowserInstallError::PairingDiscovery);
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingOffer {
    pub protocol: &'static str,
    #[serde(rename = "type")]
    pub message_type: &'static str,
    pub extension_origin: String,
    pub challenge: String,
    pub host_signing_public_key: String,
    pub fingerprint: String,
}

impl PairingOffer {
    pub fn from_request(
        request: PairingDiscoveryRequest,
        identity: &BrowserHostIdentity,
    ) -> Result<Self, BrowserInstallError> {
        request.validate()?;
        let bundle = PairingBundle::from_identity(identity);
        Ok(Self {
            protocol: PAIRING_PROTOCOL,
            message_type: PAIRING_OFFER_TYPE,
            extension_origin: request.extension_origin,
            challenge: request.challenge,
            host_signing_public_key: bundle.host_signing_public_key,
            fingerprint: bundle.fingerprint,
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NativeHostManifest {
    name: String,
    description: String,
    path: String,
    #[serde(rename = "type")]
    host_type: String,
    allowed_origins: Vec<String>,
}

pub fn install_manifest(palladin_root: &Path) -> Result<PathBuf, BrowserInstallError> {
    require_macos()?;
    let executable =
        fs::canonicalize(std::env::current_exe().map_err(|_| BrowserInstallError::Executable)?)
            .map_err(|_| BrowserInstallError::Executable)?;
    let executable_metadata =
        fs::symlink_metadata(&executable).map_err(|_| BrowserInstallError::Executable)?;
    if !executable_metadata.file_type().is_file() || executable_metadata.file_type().is_symlink() {
        return Err(BrowserInstallError::Executable);
    }
    let directory = manifest_directory(palladin_root)?;
    fs::create_dir_all(&directory).map_err(|_| BrowserInstallError::Directory)?;
    validate_owner_directory(&directory)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .map_err(|_| BrowserInstallError::Directory)?;
    }
    let destination = directory.join(format!("{NATIVE_HOST_NAME}.json"));
    let manifest = NativeHostManifest {
        name: NATIVE_HOST_NAME.to_owned(),
        description: NATIVE_HOST_DESCRIPTION.to_owned(),
        path: executable
            .to_str()
            .ok_or(BrowserInstallError::Executable)?
            .to_owned(),
        host_type: "stdio".to_owned(),
        allowed_origins: vec![CHROME_EXTENSION_ORIGIN.to_owned()],
    };
    let bytes = serde_json::to_vec_pretty(&manifest).map_err(|_| BrowserInstallError::Manifest)?;
    let temporary = directory.join(format!(".{NATIVE_HOST_NAME}.{}.tmp", std::process::id()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .map_err(|_| BrowserInstallError::Manifest)?;
    file.write_all(&bytes)
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
        .map_err(|_| BrowserInstallError::Manifest)?;
    drop(file);
    fs::rename(&temporary, &destination).map_err(|_| BrowserInstallError::Manifest)?;
    Ok(destination)
}

pub fn manifest_status(palladin_root: &Path) -> Result<bool, BrowserInstallError> {
    require_macos()?;
    let path = manifest_directory(palladin_root)?.join(format!("{NATIVE_HOST_NAME}.json"));
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err(BrowserInstallError::Manifest),
    };
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(BrowserInstallError::Manifest);
    }
    let bytes = fs::read(&path).map_err(|_| BrowserInstallError::Manifest)?;
    if bytes.len() > 16 * 1024 {
        return Err(BrowserInstallError::Manifest);
    }
    let manifest: NativeHostManifest =
        serde_json::from_slice(&bytes).map_err(|_| BrowserInstallError::Manifest)?;
    let executable =
        fs::canonicalize(std::env::current_exe().map_err(|_| BrowserInstallError::Executable)?)
            .map_err(|_| BrowserInstallError::Executable)?;
    Ok(manifest.name == NATIVE_HOST_NAME
        && manifest.description == NATIVE_HOST_DESCRIPTION
        && manifest.host_type == "stdio"
        && manifest.allowed_origins == [CHROME_EXTENSION_ORIGIN]
        && Path::new(&manifest.path) == executable)
}

pub fn remove_manifest(palladin_root: &Path) -> Result<bool, BrowserInstallError> {
    require_macos()?;
    let path = manifest_directory(palladin_root)?.join(format!("{NATIVE_HOST_NAME}.json"));
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_file() && !metadata.file_type().is_symlink() => {
            fs::remove_file(path).map_err(|_| BrowserInstallError::Manifest)?;
            Ok(true)
        }
        Ok(_) => Err(BrowserInstallError::Manifest),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(BrowserInstallError::Manifest),
    }
}

#[must_use]
pub fn local_socket_path(palladin_root: &Path) -> PathBuf {
    palladin_root.join("browser-bridge.sock")
}

fn manifest_directory(palladin_root: &Path) -> Result<PathBuf, BrowserInstallError> {
    let home = palladin_root
        .parent()
        .ok_or(BrowserInstallError::Directory)?;
    Ok(home
        .join("Library")
        .join("Application Support")
        .join("Google")
        .join("Chrome")
        .join("NativeMessagingHosts"))
}

fn validate_owner_directory(path: &Path) -> Result<(), BrowserInstallError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| BrowserInstallError::Directory)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(BrowserInstallError::Directory);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != nix::unistd::geteuid().as_raw() {
            return Err(BrowserInstallError::Directory);
        }
    }
    let canonical = fs::canonicalize(path).map_err(|_| BrowserInstallError::Directory)?;
    if canonical != path {
        return Err(BrowserInstallError::Directory);
    }
    Ok(())
}

fn require_macos() -> Result<(), BrowserInstallError> {
    if cfg!(target_os = "macos") {
        Ok(())
    } else {
        Err(BrowserInstallError::UnsupportedPlatform)
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum BrowserInstallError {
    #[error(
        "the authenticated browser host is currently supported only for Google Chrome on macOS"
    )]
    UnsupportedPlatform,
    #[error("the Palladin native executable path is invalid")]
    Executable,
    #[error("the Chrome Native Messaging directory is not owner-controlled")]
    Directory,
    #[error("the Chrome Native Messaging manifest is invalid")]
    Manifest,
    #[error("the native-host pairing discovery request is invalid")]
    PairingDiscovery,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairing_bundle_is_exact_and_fingerprint_is_derived() {
        let identity = BrowserHostIdentity::from_secret_bytes([19_u8; 32]);
        let json = serde_json::to_value(PairingBundle::from_identity(&identity)).expect("bundle");
        assert_eq!(json.as_object().expect("object").len(), 3);
        assert_eq!(json["protocol"], PAIRING_PROTOCOL);
        assert_eq!(json["hostSigningPublicKey"], identity.public_key());
        assert_eq!(json["fingerprint"], identity.fingerprint());
    }

    #[test]
    fn pairing_offer_is_challenge_bound_and_exact() {
        let identity = BrowserHostIdentity::from_secret_bytes([23_u8; 32]);
        let request = PairingDiscoveryRequest {
            protocol: PAIRING_PROTOCOL.to_owned(),
            message_type: PAIRING_DISCOVER_TYPE.to_owned(),
            extension_origin: CHROME_EXTENSION_ORIGIN.to_owned(),
            challenge: "00000000-0000-4000-8000-000000000001".to_owned(),
        };
        let offer = PairingOffer::from_request(request, &identity).expect("offer");
        let json = serde_json::to_value(offer).expect("offer json");
        assert_eq!(json.as_object().expect("object").len(), 6);
        assert_eq!(json["protocol"], PAIRING_PROTOCOL);
        assert_eq!(json["type"], PAIRING_OFFER_TYPE);
        assert_eq!(json["extensionOrigin"], CHROME_EXTENSION_ORIGIN);
        assert_eq!(json["challenge"], "00000000-0000-4000-8000-000000000001");
        assert_eq!(json["hostSigningPublicKey"], identity.public_key());
        assert_eq!(json["fingerprint"], identity.fingerprint());
    }

    #[test]
    fn pairing_discovery_rejects_wrong_origin_and_noncanonical_challenge() {
        let identity = BrowserHostIdentity::from_secret_bytes([29_u8; 32]);
        for request in [
            PairingDiscoveryRequest {
                protocol: PAIRING_PROTOCOL.to_owned(),
                message_type: PAIRING_DISCOVER_TYPE.to_owned(),
                extension_origin: "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/".to_owned(),
                challenge: "00000000-0000-4000-8000-000000000001".to_owned(),
            },
            PairingDiscoveryRequest {
                protocol: PAIRING_PROTOCOL.to_owned(),
                message_type: PAIRING_DISCOVER_TYPE.to_owned(),
                extension_origin: CHROME_EXTENSION_ORIGIN.to_owned(),
                challenge: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".to_uppercase(),
            },
        ] {
            assert!(matches!(
                PairingOffer::from_request(request, &identity),
                Err(BrowserInstallError::PairingDiscovery)
            ));
        }
    }

    #[test]
    fn chrome_identity_is_compiled_and_exact() {
        assert_eq!(CHROME_EXTENSION_ID.len(), 32);
        assert_eq!(
            CHROME_EXTENSION_ORIGIN,
            format!("chrome-extension://{CHROME_EXTENSION_ID}/")
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn manifest_lifecycle_is_exact_and_tampering_fails_status() {
        let temporary = tempfile::tempdir().expect("temporary home");
        let home = std::fs::canonicalize(temporary.path()).expect("canonical home");
        let root = home.join(".palladin");
        std::fs::create_dir(&root).expect("root");
        let manifest = install_manifest(&root).expect("install");
        assert!(manifest_status(&root).expect("status"));

        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&manifest).expect("manifest"))
                .expect("manifest json");
        value["allowed_origins"] =
            serde_json::json!(["chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/"]);
        std::fs::write(&manifest, serde_json::to_vec(&value).expect("encode")).expect("tamper");
        assert!(!manifest_status(&root).expect("tampered status"));
        assert!(remove_manifest(&root).expect("remove"));
        assert!(!manifest.exists());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn symlinked_manifest_directory_is_rejected() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().expect("temporary home");
        let home = std::fs::canonicalize(temporary.path()).expect("canonical home");
        let root = home.join(".palladin");
        std::fs::create_dir(&root).expect("root");
        let chrome = home.join("Library/Application Support/Google/Chrome");
        std::fs::create_dir_all(&chrome).expect("chrome directory");
        let target = home.join("redirected");
        std::fs::create_dir(&target).expect("target");
        symlink(&target, chrome.join("NativeMessagingHosts")).expect("symlink");
        assert_eq!(install_manifest(&root), Err(BrowserInstallError::Directory));
    }
}
