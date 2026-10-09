use super::multiplex::{OperationChannel, PendingResponse};
use super::*;
use palladin_browser_bridge::secure_transport::HostSecureSession;
use serde::de::DeserializeOwned;

pub(super) enum BrowserExchange<'a, R, W> {
    Direct {
        session: &'a mut HostSecureSession,
        input: &'a mut R,
        output: &'a mut W,
    },
    Multiplex(OperationChannel),
}

pub(super) enum QueuedExchange {
    Direct {
        frame: SecureFrame,
        not_after: Option<String>,
    },
    Multiplex {
        response: PendingResponse,
        not_after: Option<String>,
    },
}

impl<R: tokio::io::AsyncRead + Unpin, W: tokio::io::AsyncWrite + Unpin> BrowserExchange<'_, R, W> {
    pub(super) fn enqueue<T: Serialize>(
        &mut self,
        request: &T,
        not_after: Option<&str>,
    ) -> Result<QueuedExchange, NativeBrowserError> {
        match self {
            Self::Direct { session, .. } => Ok(QueuedExchange::Direct {
                frame: session.seal(request)?,
                not_after: not_after.map(str::to_owned),
            }),
            Self::Multiplex(operation) => Ok(QueuedExchange::Multiplex {
                response: operation.enqueue(request, not_after)?,
                not_after: not_after.map(str::to_owned),
            }),
        }
    }

    pub(super) async fn receive<T: DeserializeOwned>(
        &mut self,
        request: QueuedExchange,
        local: &UnixStream,
    ) -> Result<T, NativeBrowserError> {
        tokio::select! {
            result = self.receive_inner(request) => result,
            error = local_disconnect(local) => Err(error),
        }
    }

    async fn receive_inner<T: DeserializeOwned>(
        &mut self,
        request: QueuedExchange,
    ) -> Result<T, NativeBrowserError> {
        match (self, request) {
            (
                Self::Direct {
                    session,
                    input,
                    output,
                },
                QueuedExchange::Direct { frame, not_after },
            ) => {
                let deadline = if let Some(not_after) = not_after {
                    write_authorized_extension_frame(*output, &frame, &not_after).await?
                } else {
                    timeout(OPERATION_TIMEOUT, write_message(*output, &frame))
                        .await
                        .map_err(|_| NativeBrowserError::Unavailable)??;
                    Instant::now() + OPERATION_TIMEOUT
                };
                let frame: SecureFrame = timeout_at(deadline, read_message(*input))
                    .await
                    .map_err(|_| NativeBrowserError::AuthorizationExpired)??;
                Ok(session.open(&frame)?)
            }
            (
                Self::Multiplex(_),
                QueuedExchange::Multiplex {
                    response,
                    not_after,
                },
            ) => {
                let budget = not_after
                    .as_deref()
                    .map(authorization_remaining_until)
                    .transpose()?
                    .unwrap_or(OPERATION_TIMEOUT)
                    .min(OPERATION_TIMEOUT);
                response.receive(budget).await
            }
            _ => Err(NativeBrowserError::InvalidMessage),
        }
    }

    pub(super) async fn send_cancel(
        &mut self,
        request: QueuedExchange,
    ) -> Result<(), NativeBrowserError> {
        match (self, request) {
            (Self::Direct { output, .. }, QueuedExchange::Direct { frame, .. }) => {
                timeout(Duration::from_millis(200), write_message(*output, &frame))
                    .await
                    .map_err(|_| NativeBrowserError::Unavailable)??;
                Ok(())
            }
            (Self::Multiplex(_), QueuedExchange::Multiplex { .. }) => Ok(()),
            _ => Err(NativeBrowserError::InvalidMessage),
        }
    }
}

async fn local_disconnect(local: &UnixStream) -> NativeBrowserError {
    loop {
        if local.readable().await.is_err() {
            return NativeBrowserError::Unavailable;
        }
        let mut byte = [0_u8; 1];
        match local.try_read(&mut byte) {
            Ok(0) => return NativeBrowserError::Unavailable,
            // The request/reply protocol permits no pipelined local command
            // before the current browser result has been delivered.
            Ok(_) => return NativeBrowserError::InvalidMessage,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(_) => return NativeBrowserError::Unavailable,
        }
    }
}
