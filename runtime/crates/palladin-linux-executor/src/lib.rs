#![forbid(unsafe_code)]

use palladin_windows_executor::ExecutorRequest;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

pub const SOCKET_PATH: &str = "/run/palladin-executor/executor.sock";
pub const SYSTEM_EXECUTOR: &str = "/usr/lib/palladin/runtime/palladin-linux-executor";
pub const INSTALL_MARKER: &str = "/etc/palladin/runtime-v1";
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
pub const MAX_OUTPUT_BYTES: usize = 64 * 1024;
pub const EXECUTOR_PROTOCOL_VERSION: u16 = 2;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ExecutorRequestEnvelope<T> {
    version: u16,
    request: T,
}

pub fn encode_request(
    request: &ExecutorRequest,
) -> Result<Zeroizing<Vec<u8>>, ExecutorProtocolError> {
    let bytes = serde_json::to_vec(&ExecutorRequestEnvelope {
        version: EXECUTOR_PROTOCOL_VERSION,
        request,
    })
    .map_err(|_| ExecutorProtocolError::Invalid)?;
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err(ExecutorProtocolError::Invalid);
    }
    Ok(Zeroizing::new(bytes))
}

pub fn decode_request(bytes: &[u8]) -> Result<ExecutorRequest, ExecutorProtocolError> {
    let envelope: ExecutorRequestEnvelope<ExecutorRequest> =
        serde_json::from_slice(bytes).map_err(|_| ExecutorProtocolError::Invalid)?;
    if envelope.version != EXECUTOR_PROTOCOL_VERSION {
        return Err(ExecutorProtocolError::Invalid);
    }
    Ok(envelope.request)
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ExecutorProtocolError {
    #[error("the Linux executor protocol is invalid")]
    Invalid,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ExecutorFrame {
    Output {
        stream: ExecutorOutput,
        sequence: u64,
        bytes: Vec<u8>,
    },
    Exited {
        code: i32,
    },
    Rejected,
}

impl Drop for ExecutorFrame {
    fn drop(&mut self) {
        if let Self::Output { bytes, .. } = self {
            bytes.zeroize();
        }
    }
}

impl std::fmt::Debug for ExecutorFrame {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Output {
                stream, sequence, ..
            } => formatter
                .debug_struct("Output")
                .field("stream", stream)
                .field("sequence", sequence)
                .field("bytes", &"[REDACTED]")
                .finish(),
            Self::Exited { code } => formatter
                .debug_struct("Exited")
                .field("code", code)
                .finish(),
            Self::Rejected => formatter.write_str("Rejected"),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExecutorOutput {
    Stdout,
    Stderr,
}

pub fn parse_install_identity(contents: &str) -> Option<(u32, u32, u32)> {
    let mut broker = None;
    let mut broker_group = None;
    let mut executor_group = None;
    for line in contents.lines() {
        if let Some(value) = line.strip_prefix("broker_uid=") {
            broker = value.parse::<u32>().ok().filter(|uid| *uid != 0);
        } else if let Some(value) = line.strip_prefix("broker_gid=") {
            broker_group = value.parse::<u32>().ok().filter(|gid| *gid != 0);
        } else if let Some(value) = line.strip_prefix("executor_gid=") {
            executor_group = value.parse::<u32>().ok().filter(|gid| *gid != 0);
        } else if !line.trim().is_empty() {
            return None;
        }
    }
    let broker_group = broker_group?;
    let executor_group = executor_group?;
    if broker_group == executor_group {
        return None;
    }
    Some((broker?, broker_group, executor_group))
}

#[cfg(test)]
mod tests {
    use palladin_windows_executor::ExecutorRequest;

    use super::{decode_request, encode_request, parse_install_identity};

    #[test]
    fn install_identity_requires_non_root_broker_uid_and_group() {
        assert_eq!(
            parse_install_identity("broker_uid=981\nbroker_gid=982\nexecutor_gid=983\n"),
            Some((981, 982, 983))
        );
        assert_eq!(parse_install_identity("broker_uid=981\n"), None);
        assert_eq!(
            parse_install_identity("broker_uid=0\nbroker_gid=982\nexecutor_gid=983\n"),
            None
        );
        assert_eq!(
            parse_install_identity("broker_uid=981\nbroker_gid=982\nexecutor_gid=982\n"),
            None
        );
    }

    #[test]
    fn executor_request_requires_the_matching_protocol_version() {
        let request = ExecutorRequest::command(vec!["true".to_owned()], Vec::new());
        let encoded = encode_request(&request).expect("encode");
        assert!(decode_request(&encoded).is_ok());
        let stale = String::from_utf8(encoded.to_vec())
            .expect("utf8")
            .replace("\"version\":2", "\"version\":1");
        assert!(decode_request(stale.as_bytes()).is_err());
    }
}
