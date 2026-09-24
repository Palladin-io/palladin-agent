use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const PRODUCTION_NATIVE_HOST_NAME: &str = "io.palladin";
pub const DEVELOPMENT_NATIVE_HOST_NAME: &str = "io.palladin.debug";
pub const NATIVE_HOST_NAME: &str = if cfg!(debug_assertions) {
    DEVELOPMENT_NATIVE_HOST_NAME
} else {
    PRODUCTION_NATIVE_HOST_NAME
};
const LEGACY_NATIVE_HOST_NAME: &str = "io.palladin.browser_bridge";
const STORE_CHROME_EXTENSION_ORIGIN: &str = "chrome-extension://ecejlpkceehnckgenjafoppffmbmmagf/";
pub const CHROME_EXTENSION_ORIGINS: &[&str] = &[
    STORE_CHROME_EXTENSION_ORIGIN,
    #[cfg(debug_assertions)]
    "chrome-extension://hmljnknogdeonphikmeofcbkikmpokba/",
];

const NATIVE_HOST_DESCRIPTION: &str = "Palladin authenticated Chrome Inject host";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChromeExtensionOrigin(&'static str);

impl ChromeExtensionOrigin {
    // The caller must authenticate Chrome's parent process before trusting this argv binding.
    pub fn from_native_arguments(mut arguments: impl Iterator<Item = OsString>) -> Option<Self> {
        let argument = arguments.next()?;
        if arguments.next().is_some() {
            return None;
        }
        CHROME_EXTENSION_ORIGINS
            .iter()
            .copied()
            .find(|origin| argument == *origin)
            .map(Self)
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
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
    remove_manifest_file(&directory.join(format!("{LEGACY_NATIVE_HOST_NAME}.json")))?;
    let destination = directory.join(format!("{NATIVE_HOST_NAME}.json"));
    let manifest = NativeHostManifest {
        name: NATIVE_HOST_NAME.to_owned(),
        description: NATIVE_HOST_DESCRIPTION.to_owned(),
        path: executable
            .to_str()
            .ok_or(BrowserInstallError::Executable)?
            .to_owned(),
        host_type: "stdio".to_owned(),
        allowed_origins: CHROME_EXTENSION_ORIGINS
            .iter()
            .map(|origin| (*origin).to_owned())
            .collect(),
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
        && manifest.allowed_origins == CHROME_EXTENSION_ORIGINS
        && Path::new(&manifest.path) == executable)
}

pub fn remove_manifest(palladin_root: &Path) -> Result<bool, BrowserInstallError> {
    require_macos()?;
    let directory = manifest_directory(palladin_root)?;
    let current = remove_manifest_file(&directory.join(format!("{NATIVE_HOST_NAME}.json")))?;
    let legacy = remove_manifest_file(&directory.join(format!("{LEGACY_NATIVE_HOST_NAME}.json")))?;
    Ok(current || legacy)
}

fn remove_manifest_file(path: &Path) -> Result<bool, BrowserInstallError> {
    match fs::symlink_metadata(path) {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_arguments_select_one_exact_origin_for_the_build() {
        let parse = |arguments: &[&str]| {
            ChromeExtensionOrigin::from_native_arguments(arguments.iter().map(OsString::from))
        };
        assert_eq!(
            parse(&["chrome-extension://ecejlpkceehnckgenjafoppffmbmmagf/"])
                .expect("store origin")
                .as_str(),
            "chrome-extension://ecejlpkceehnckgenjafoppffmbmmagf/"
        );
        let development = "chrome-extension://hmljnknogdeonphikmeofcbkikmpokba/";
        assert_eq!(parse(&[development]).is_some(), cfg!(debug_assertions));
        for origin in CHROME_EXTENSION_ORIGINS {
            assert_eq!(parse(&[origin]).expect("allowed origin").as_str(), *origin);
            assert!(parse(&[origin, "extra"]).is_none());
        }
        assert!(parse(&[]).is_none());
        for invalid in [
            "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/",
            "chrome-extension://ecejlpkceehnckgenjafoppffmbmmagf",
            "chrome-extension://ecejlpkceehnckgenjafoppffmbmmagf.evil/",
            "chrome-extension://ecejlpkceehnckgenjafoppffmbmmagf/popup.html",
            "chrome-extension://ecejlpkceehnckgenjafoppffmbmmagf/?source=store",
            "https://ecejlpkceehnckgenjafoppffmbmmagf/",
        ] {
            assert!(parse(&[invalid]).is_none(), "must reject {invalid}");
        }
    }

    #[test]
    fn native_host_name_matches_the_build_security_mode() {
        assert_eq!(
            NATIVE_HOST_NAME,
            if cfg!(debug_assertions) {
                DEVELOPMENT_NATIVE_HOST_NAME
            } else {
                PRODUCTION_NATIVE_HOST_NAME
            }
        );
        assert_ne!(PRODUCTION_NATIVE_HOST_NAME, DEVELOPMENT_NATIVE_HOST_NAME);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn manifest_lifecycle_is_exact_and_tampering_fails_status() {
        let temporary = tempfile::tempdir().expect("temporary home");
        let home = std::fs::canonicalize(temporary.path()).expect("canonical home");
        let root = home.join(".palladin");
        std::fs::create_dir(&root).expect("root");
        let manifest_directory = manifest_directory(&root).expect("manifest directory");
        std::fs::create_dir_all(&manifest_directory).expect("create manifest directory");
        let legacy_manifest = manifest_directory.join(format!("{LEGACY_NATIVE_HOST_NAME}.json"));
        std::fs::write(&legacy_manifest, b"legacy").expect("legacy manifest");
        let manifest = install_manifest(&root).expect("install");
        assert!(!legacy_manifest.exists());
        assert_eq!(
            manifest.file_name().and_then(std::ffi::OsStr::to_str),
            Some(format!("{NATIVE_HOST_NAME}.json").as_str())
        );
        assert!(manifest_status(&root).expect("status"));

        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&manifest).expect("manifest"))
                .expect("manifest json");
        assert_eq!(
            value["allowed_origins"],
            serde_json::json!(CHROME_EXTENSION_ORIGINS)
        );
        for origins in [
            serde_json::json!(["chrome-extension://hmljnknogdeonphikmeofcbkikmpokba/"]),
            serde_json::json!([STORE_CHROME_EXTENSION_ORIGIN]),
            serde_json::json!([
                STORE_CHROME_EXTENSION_ORIGIN,
                "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/"
            ]),
        ] {
            value["allowed_origins"] = origins.clone();
            std::fs::write(&manifest, serde_json::to_vec(&value).expect("encode")).expect("tamper");
            assert_eq!(
                manifest_status(&root).expect("tampered status"),
                origins == serde_json::json!(CHROME_EXTENSION_ORIGINS)
            );
        }
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
