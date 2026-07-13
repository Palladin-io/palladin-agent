use std::io;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroize;

pub const PROTOCOL_VERSION: u16 = 2;
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
pub const MAX_STREAM_CHUNK_BYTES: usize = 64 * 1024;
const MAX_ARGUMENTS: usize = 256;
const MAX_ARGUMENT_BYTES: usize = 32 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ClientFrame {
    Start {
        version: u16,
        request_id: [u8; 16],
        arguments: Vec<String>,
        interactive: bool,
    },
    Input {
        request_id: [u8; 16],
        sequence: u64,
        bytes: Vec<u8>,
    },
    InputClosed {
        request_id: [u8; 16],
        sequence: u64,
    },
    Cancel {
        request_id: [u8; 16],
    },
}

impl Drop for ClientFrame {
    fn drop(&mut self) {
        if let Self::Input { bytes, .. } = self {
            bytes.zeroize();
        }
    }
}

impl std::fmt::Debug for ClientFrame {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Start {
                version,
                request_id,
                arguments,
                interactive,
            } => formatter
                .debug_struct("Start")
                .field("version", version)
                .field("request_id", request_id)
                .field("arguments", arguments)
                .field("interactive", interactive)
                .finish(),
            Self::Input {
                request_id,
                sequence,
                ..
            } => formatter
                .debug_struct("Input")
                .field("request_id", request_id)
                .field("sequence", sequence)
                .field("bytes", &"[REDACTED]")
                .finish(),
            Self::InputClosed {
                request_id,
                sequence,
            } => formatter
                .debug_struct("InputClosed")
                .field("request_id", request_id)
                .field("sequence", sequence)
                .finish(),
            Self::Cancel { request_id } => formatter
                .debug_struct("Cancel")
                .field("request_id", request_id)
                .finish(),
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ServerFrame {
    Accepted {
        request_id: [u8; 16],
    },
    Output {
        request_id: [u8; 16],
        stream: OutputStream,
        sequence: u64,
        bytes: Vec<u8>,
    },
    Exited {
        request_id: [u8; 16],
        code: u8,
    },
    Rejected {
        request_id: Option<[u8; 16]>,
        code: RejectionCode,
    },
}

impl Drop for ServerFrame {
    fn drop(&mut self) {
        if let Self::Output { bytes, .. } = self {
            bytes.zeroize();
        }
    }
}

impl std::fmt::Debug for ServerFrame {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Accepted { request_id } => formatter
                .debug_struct("Accepted")
                .field("request_id", request_id)
                .finish(),
            Self::Output {
                request_id,
                stream,
                sequence,
                ..
            } => formatter
                .debug_struct("Output")
                .field("request_id", request_id)
                .field("stream", stream)
                .field("sequence", sequence)
                .field("bytes", &"[REDACTED]")
                .finish(),
            Self::Exited { request_id, code } => formatter
                .debug_struct("Exited")
                .field("request_id", request_id)
                .field("code", code)
                .finish(),
            Self::Rejected { request_id, code } => formatter
                .debug_struct("Rejected")
                .field("request_id", request_id)
                .field("code", code)
                .finish(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum OutputStream {
    Stdout,
    Stderr,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RejectionCode {
    InvalidRequest,
    UnsupportedVersion,
    UnauthorizedPeer,
    UserAuthorizationDenied,
    Busy,
    Unavailable,
}

pub fn validate_arguments(arguments: &[String]) -> Result<(), ProtocolError> {
    if arguments.is_empty() || arguments.len() > MAX_ARGUMENTS {
        return Err(ProtocolError::InvalidRequest);
    }
    let total = arguments.iter().try_fold(0_usize, |total, argument| {
        if argument.is_empty()
            || argument.as_bytes().contains(&0)
            || argument.chars().any(char::is_control)
        {
            return Err(ProtocolError::InvalidRequest);
        }
        total
            .checked_add(argument.len())
            .ok_or(ProtocolError::InvalidRequest)
    })?;
    if total > MAX_ARGUMENT_BYTES
        || arguments.iter().any(|argument| {
            argument == "--api-key"
                || argument.starts_with("--api-key=")
                || argument.starts_with("--api-key-stdin=")
                || argument == "--host"
                || argument.starts_with("--host=")
        })
    {
        return Err(ProtocolError::InvalidRequest);
    }
    Ok(())
}

pub async fn write_frame<W: AsyncWrite + Unpin, T: Serialize>(
    writer: &mut W,
    frame: &T,
) -> Result<(), ProtocolError> {
    let bytes =
        zeroize::Zeroizing::new(serde_json::to_vec(frame).map_err(|_| ProtocolError::Malformed)?);
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::Oversized);
    }
    writer.write_u32(bytes.len() as u32).await?;
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read_frame<R: AsyncRead + Unpin, T: for<'de> Deserialize<'de>>(
    reader: &mut R,
) -> Result<T, ProtocolError> {
    let length = reader.read_u32().await? as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(ProtocolError::Oversized);
    }
    let mut bytes = vec![0_u8; length];
    if let Err(error) = reader.read_exact(&mut bytes).await {
        bytes.zeroize();
        return Err(error.into());
    }
    let result = serde_json::from_slice(&bytes).map_err(|_| ProtocolError::Malformed);
    bytes.zeroize();
    result
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("broker frame is empty or exceeds the configured limit")]
    Oversized,
    #[error("broker frame is malformed")]
    Malformed,
    #[error("broker request is invalid")]
    InvalidRequest,
    #[error("broker transport failed")]
    Io(#[from] io::Error),
}

#[cfg(test)]
mod tests {
    use super::{ClientFrame, ProtocolError, validate_arguments};

    #[test]
    fn arguments_reject_raw_api_keys_hosts_and_controls() {
        for arguments in [
            vec!["connect".to_owned(), "--api-key=pl_secret".to_owned()],
            vec!["status".to_owned(), "--host".to_owned()],
            vec!["get\nsecret".to_owned()],
        ] {
            assert!(matches!(
                validate_arguments(&arguments),
                Err(ProtocolError::InvalidRequest)
            ));
        }
    }

    #[test]
    fn input_debug_does_not_render_bytes_as_text() {
        let frame = ClientFrame::Input {
            request_id: [1; 16],
            sequence: 0,
            bytes: b"synthetic-secret".to_vec(),
        };
        // Debug renders byte values but never a plaintext string. Production has tracing disabled.
        assert!(!format!("{frame:?}").contains("synthetic-secret"));
    }
}
