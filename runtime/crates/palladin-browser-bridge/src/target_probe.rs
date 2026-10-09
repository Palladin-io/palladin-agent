//! Public target locators are checked by the authenticated browser before routing.
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub enum TargetProbeType {
    #[serde(rename = "target.probe")]
    Probe,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TargetProbeRequest {
    pub protocol: String,
    #[serde(rename = "type")]
    pub message_type: TargetProbeType,
    pub nonce: String,
    pub target_tab_id: u64,
    pub target_url: String,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum TargetProbeOutcome {
    Match,
    NoMatch,
    Unavailable,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TargetProbeResult {
    pub protocol: String,
    #[serde(rename = "type")]
    pub message_type: String,
    pub nonce: String,
    pub outcome: TargetProbeOutcome,
}
