//! Bounded, declarative browser capture. Captured values never implement Debug.
use crate::{secure_transport::INJECT_PROVIDER_PROTOCOL, validate_https_page_url};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use zeroize::Zeroize;

#[derive(Debug, thiserror::Error)]
#[error("invalid browser capture contract")]
pub struct CaptureError;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapturePlan {
    pub target_tab_id: u64,
    pub target_url: String,
    pub fields: Vec<CaptureField>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaptureField {
    pub entry_field_id: String,
    pub selector: String,
    pub read: CaptureRead,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub enum CaptureRead {
    #[serde(rename = "value")]
    Value,
    #[serde(rename = "textContent")]
    TextContent,
}
impl CapturePlan {
    pub fn parse(value: &str) -> Result<Self, CaptureError> {
        if value.len() > 65536 {
            return Err(CaptureError);
        }
        let plan: Self = serde_json::from_str(value).map_err(|_| CaptureError)?;
        plan.validate()?;
        Ok(plan)
    }
    pub fn validate(&self) -> Result<(), CaptureError> {
        if !(1..=9_007_199_254_740_991).contains(&self.target_tab_id) {
            return Err(CaptureError);
        }
        validate_fields(&self.target_url, &self.fields)
    }
}
fn identifier(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
}
fn validate_fields(url: &str, fields: &[CaptureField]) -> Result<(), CaptureError> {
    if url.len() > 4096
        || validate_https_page_url(url).is_err()
        || fields.is_empty()
        || fields.len() > 32
    {
        return Err(CaptureError);
    }
    let mut ids = BTreeSet::new();
    let mut selectors = BTreeSet::new();
    for field in fields {
        if !identifier(&field.entry_field_id, 128)
            || field.selector.is_empty()
            || field.selector.len() > 1024
            || field.selector.trim() != field.selector
            || field.selector.contains('\0')
            || !ids.insert(&field.entry_field_id)
            || !selectors.insert(&field.selector)
        {
            return Err(CaptureError);
        }
    }
    Ok(())
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaptureRequest {
    pub protocol: String,
    #[serde(rename = "type")]
    pub message_type: String,
    pub transaction_id: String,
    pub target_url: String,
    pub fields: Vec<CaptureField>,
}
impl CaptureRequest {
    pub fn new(transaction_id: &str, plan: CapturePlan) -> Self {
        Self {
            protocol: INJECT_PROVIDER_PROTOCOL.into(),
            message_type: "capture".into(),
            transaction_id: transaction_id.into(),
            target_url: plan.target_url,
            fields: plan.fields,
        }
    }
    pub fn validate(&self) -> Result<(), CaptureError> {
        if self.protocol != INJECT_PROVIDER_PROTOCOL
            || self.message_type != "capture"
            || !identifier(&self.transaction_id, 256)
        {
            return Err(CaptureError);
        }
        validate_fields(&self.target_url, &self.fields)
    }
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapturedValue {
    pub entry_field_id: String,
    pub value: String,
}
impl Drop for CapturedValue {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaptureResult {
    pub protocol: String,
    #[serde(rename = "type")]
    pub message_type: String,
    pub transaction_id: String,
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<CapturedValue>>,
}
impl CaptureResult {
    pub fn validate(&self, request: &CaptureRequest) -> Result<(), CaptureError> {
        request.validate()?;
        if self.protocol != INJECT_PROVIDER_PROTOCOL
            || self.message_type != "capture.result"
            || self.transaction_id != request.transaction_id
        {
            return Err(CaptureError);
        }
        match self.outcome.as_str() {
            "captured" => {
                let values = self.values.as_ref().ok_or(CaptureError)?;
                if values.len() != request.fields.len() {
                    return Err(CaptureError);
                }
                let expected: BTreeSet<_> = request
                    .fields
                    .iter()
                    .map(|f| f.entry_field_id.as_str())
                    .collect();
                let actual: BTreeSet<_> =
                    values.iter().map(|v| v.entry_field_id.as_str()).collect();
                if expected != actual
                    || values.iter().any(|v| v.value.len() > 65536)
                    || values.iter().map(|v| v.value.len()).sum::<usize>() > 262144
                {
                    return Err(CaptureError);
                }
            }
            "rejected" | "provider-unavailable" if self.values.is_none() => {}
            _ => return Err(CaptureError),
        }
        Ok(())
    }
}
