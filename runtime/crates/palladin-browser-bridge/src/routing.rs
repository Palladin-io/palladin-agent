//! Public, ephemeral browser connection locators. Socket ownership and mutual
//! authentication remain mandatory before any request is sent.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use thiserror::Error;

pub fn valid_browser_session_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn session_socket_path(root: &Path, authenticated_session_id: &str) -> PathBuf {
    root.join(format!(
        "b-{}.sock",
        session_locator(authenticated_session_id)
    ))
}

pub fn session_locator(authenticated_session_id: &str) -> String {
    let digest = Sha256::digest(authenticated_session_id.as_bytes());
    digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn browser_socket_paths(root: &Path) -> Result<Vec<PathBuf>, BrowserRouteError> {
    let entries = std::fs::read_dir(root).map_err(|_| BrowserRouteError::Unavailable)?;
    let mut routes = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|_| BrowserRouteError::Unavailable)?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let session_id = name
            .strip_prefix("b-")
            .and_then(|name| name.strip_suffix(".sock"));
        if name == "browser-bridge.sock" || session_id.is_some_and(valid_browser_session_id) {
            // Do not follow or discard unsafe entries here. The transport must
            // report its ownership/type check, not silently choose another route.
            routes.push(entry.path());
        }
    }
    routes.sort();
    Ok(routes)
}

pub fn single_browser_socket(root: &Path) -> Result<PathBuf, BrowserRouteError> {
    select_browser_socket(root, None)
}

pub fn select_browser_socket(
    root: &Path,
    session_id: Option<&str>,
) -> Result<PathBuf, BrowserRouteError> {
    let mut routes = browser_socket_paths(root)?;
    if let Some(id) = session_id {
        if !valid_browser_session_id(id) {
            return Err(BrowserRouteError::Unavailable);
        }
        let selected = root.join(format!("b-{id}.sock"));
        routes.retain(|path| path == &selected);
    }
    match routes.len() {
        0 => Err(BrowserRouteError::Unavailable),
        1 => Ok(routes.remove(0)),
        _ => Err(BrowserRouteError::Ambiguous),
    }
}

#[derive(Debug, Error)]
pub enum BrowserRouteError {
    #[error("no browser connection is available")]
    Unavailable,
    #[error("multiple browser connections are available; select the target browser session")]
    Ambiguous,
}
