//! Value-free discovery over the independently authenticated local host channel.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserSessionInfo {
    pub browser_session: String,
    pub concurrent: bool,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserDiscovery {
    pub sessions: Vec<BrowserSessionInfo>,
    pub unavailable_connections: usize,
    pub legacy_socket_present: bool,
}

#[derive(Deserialize, Serialize)]
pub enum BrowserStatusRequestType {
    #[serde(rename = "browser.status")]
    Status,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserStatusRequest {
    pub protocol: String,
    #[serde(rename = "type")]
    pub message_type: BrowserStatusRequestType,
    pub nonce: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrowserStatusResult {
    pub protocol: String,
    #[serde(rename = "type")]
    pub message_type: String,
    pub nonce: String,
    pub session: BrowserSessionInfo,
}
