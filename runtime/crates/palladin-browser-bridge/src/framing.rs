//! Bounded length-prefixed JSON framing for Native Messaging and local encrypted IPC.

use serde::{Serialize, de::DeserializeOwned};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

pub const MAX_FRAME_BYTES: usize = 1024 * 1024;

pub async fn read_message<T: DeserializeOwned>(
    input: &mut (impl AsyncRead + Unpin),
) -> Result<T, FramingError> {
    let length = input
        .read_u32_le()
        .await
        .map_err(|_| FramingError::Transport)?;
    let length = usize::try_from(length).map_err(|_| FramingError::InvalidFrame)?;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(FramingError::InvalidFrame);
    }
    let mut bytes = Zeroizing::new(vec![0_u8; length]);
    input
        .read_exact(bytes.as_mut())
        .await
        .map_err(|_| FramingError::Transport)?;
    serde_json::from_slice(bytes.as_ref()).map_err(|_| FramingError::InvalidFrame)
}

pub async fn write_message<T: Serialize>(
    output: &mut (impl AsyncWrite + Unpin),
    message: &T,
) -> Result<(), FramingError> {
    let bytes =
        Zeroizing::new(serde_json::to_vec(message).map_err(|_| FramingError::InvalidFrame)?);
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err(FramingError::InvalidFrame);
    }
    let length = u32::try_from(bytes.len()).map_err(|_| FramingError::InvalidFrame)?;
    output
        .write_u32_le(length)
        .await
        .map_err(|_| FramingError::Transport)?;
    output
        .write_all(bytes.as_ref())
        .await
        .map_err(|_| FramingError::Transport)?;
    output.flush().await.map_err(|_| FramingError::Transport)
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum FramingError {
    #[error("browser transport frame is invalid")]
    InvalidFrame,
    #[error("browser transport closed")]
    Transport,
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use tokio::io::{AsyncWriteExt, duplex};

    use super::*;

    #[tokio::test]
    async fn bounded_frame_round_trips() {
        let (mut sender, mut receiver) = duplex(512);
        let send =
            tokio::spawn(async move { write_message(&mut sender, &json!({"ok":true})).await });
        let value: Value = read_message(&mut receiver).await.expect("read");
        send.await.expect("join").expect("write");
        assert_eq!(value, json!({"ok":true}));
    }

    #[tokio::test]
    async fn oversized_frame_is_rejected_before_allocation() {
        let (mut sender, mut receiver) = duplex(16);
        sender
            .write_u32_le(u32::try_from(MAX_FRAME_BYTES + 1).expect("bounded"))
            .await
            .expect("header");
        assert_eq!(
            read_message::<Value>(&mut receiver).await,
            Err(FramingError::InvalidFrame)
        );
    }
}
