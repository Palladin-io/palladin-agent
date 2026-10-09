use super::*;
use palladin_browser_bridge::secure_transport::HostSecureSession;
use serde::de::DeserializeOwned;
use serde_json::{Value, value::RawValue};
use std::collections::HashMap;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

type Reply = oneshot::Sender<Result<Value, NativeBrowserError>>;

enum Outbound {
    Request {
        id: String,
        body: Zeroizing<String>,
        not_after: Option<String>,
        reply: Reply,
        closed: Arc<AtomicBool>,
    },
    Close {
        id: String,
        permit: OwnedSemaphorePermit,
    },
}

#[derive(Clone)]
pub(super) struct BrowserConnection {
    sender: mpsc::Sender<Outbound>,
    stopped: CancellationToken,
    capacity: Arc<Semaphore>,
}

pub(super) struct OperationChannel {
    id: String,
    connection: BrowserConnection,
    closed: Arc<AtomicBool>,
    permit: Option<OwnedSemaphorePermit>,
}

pub(super) struct PendingResponse(oneshot::Receiver<Result<Value, NativeBrowserError>>);

pub(super) struct BrowserBroker {
    session: HostSecureSession,
    outbound: mpsc::Receiver<Outbound>,
    stopped: CancellationToken,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RequestEnvelope<'a> {
    protocol: &'static str,
    #[serde(rename = "type")]
    kind: &'static str,
    operation_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    request: Option<&'a RawValue>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ResponseEnvelope {
    protocol: String,
    #[serde(rename = "type")]
    kind: String,
    operation_id: String,
    response: Option<Value>,
}

impl BrowserConnection {
    pub(super) fn new(session: HostSecureSession) -> (Self, BrowserBroker) {
        // At most 32 client operations, each with one request and one cleanup.
        let (sender, outbound) = mpsc::channel(64);
        let stopped = CancellationToken::new();
        (
            Self {
                sender,
                stopped: stopped.clone(),
                capacity: Arc::new(Semaphore::new(32)),
            },
            BrowserBroker {
                session,
                outbound,
                stopped,
            },
        )
    }

    pub(super) fn operation(&self) -> Result<OperationChannel, NativeBrowserError> {
        if self.stopped.is_cancelled() {
            return Err(NativeBrowserError::Unavailable);
        }
        let permit = self
            .capacity
            .clone()
            .try_acquire_owned()
            .map_err(|_| NativeBrowserError::Unavailable)?;
        let mut id = [0_u8; 16];
        getrandom::fill(&mut id).map_err(|_| NativeBrowserError::Unavailable)?;
        Ok(OperationChannel {
            id: hex::encode(id),
            connection: self.clone(),
            closed: Arc::new(AtomicBool::new(false)),
            permit: Some(permit),
        })
    }

    pub(super) fn stop(&self) {
        self.stopped.cancel();
    }
}

impl OperationChannel {
    /// The only queued plaintext owner is zeroizing. Encryption happens at the
    /// writer so an expired queued request can be discarded without a sequence gap.
    pub(super) fn enqueue<T: Serialize>(
        &self,
        request: &T,
        not_after: Option<&str>,
    ) -> Result<PendingResponse, NativeBrowserError> {
        if self.connection.stopped.is_cancelled() {
            return Err(NativeBrowserError::Unavailable);
        }
        let body = Zeroizing::new(
            serde_json::to_string(request).map_err(|_| NativeBrowserError::InvalidMessage)?,
        );
        let (reply, receiver) = oneshot::channel();
        self.connection
            .sender
            .try_send(Outbound::Request {
                id: self.id.clone(),
                body,
                not_after: not_after.map(str::to_owned),
                reply,
                closed: self.closed.clone(),
            })
            .map_err(|_| NativeBrowserError::Unavailable)?;
        Ok(PendingResponse(receiver))
    }
}

impl Drop for OperationChannel {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Release);
        if self
            .connection
            .sender
            .try_send(Outbound::Close {
                id: self.id.clone(),
                permit: self
                    .permit
                    .take()
                    .expect("operation owns its capacity until cleanup"),
            })
            .is_err()
        {
            // If cleanup cannot be delivered, dispose the connection rather than
            // leave a credential operation live without its owning client.
            self.connection.stop();
        }
    }
}

impl PendingResponse {
    pub(super) async fn receive<T: DeserializeOwned>(
        self,
        budget: Duration,
    ) -> Result<T, NativeBrowserError> {
        let result = timeout(budget, self.0)
            .await
            .map_err(|_| NativeBrowserError::Unavailable)?
            .map_err(|_| NativeBrowserError::Unavailable)??;
        serde_json::from_value(result).map_err(|_| NativeBrowserError::InvalidMessage)
    }
}

impl BrowserBroker {
    pub(super) async fn run<R: tokio::io::AsyncRead + Unpin, W: tokio::io::AsyncWrite + Unpin>(
        mut self,
        input: &mut R,
        output: &mut W,
    ) -> Result<(), NativeBrowserError> {
        let (frames, incoming) = mpsc::channel(32);
        let read = async {
            use tokio::io::AsyncReadExt;
            loop {
                let mut first = [0_u8; 1];
                if input
                    .read(&mut first)
                    .await
                    .map_err(|_| NativeBrowserError::Unavailable)?
                    == 0
                {
                    drop(frames);
                    // Let the pump consume already-read responses before EOF.
                    return std::future::pending::<Result<(), NativeBrowserError>>().await;
                }
                let mut prefixed = std::io::Cursor::new(first).chain(&mut *input);
                let frame: SecureFrame = read_message(&mut prefixed).await?;
                frames
                    .send(frame)
                    .await
                    .map_err(|_| NativeBrowserError::Unavailable)?;
            }
        };
        let stop = self.stopped.clone();
        // The reader future is never restarted after a partial frame. Only a
        // terminal channel shutdown cancels it.
        let result = tokio::select! {
            result = read => result,
            result = self.pump(output, incoming) => result,
            () = stop.cancelled() => Ok(()),
        };
        stop.cancel();
        result
    }

    async fn pump<W: tokio::io::AsyncWrite + Unpin>(
        &mut self,
        output: &mut W,
        mut incoming: mpsc::Receiver<SecureFrame>,
    ) -> Result<(), NativeBrowserError> {
        let mut pending: HashMap<String, Reply> = HashMap::new();
        let mut closing: HashMap<String, (Instant, OwnedSemaphorePermit)> = HashMap::new();
        loop {
            let cleanup_deadline = closing.values().map(|(deadline, _)| *deadline).min();
            tokio::select! {
                () = async {
                    if let Some(deadline) = cleanup_deadline { tokio::time::sleep_until(deadline).await; }
                    else { std::future::pending::<()>().await; }
                } => return Err(NativeBrowserError::Unavailable),
                command = self.outbound.recv() => {
                    let Some(command) = command else { return Ok(()); };
                    match command {
                        Outbound::Request { id, body, not_after, reply, closed } => {
                            if closed.load(Ordering::Acquire) || reply.is_closed() { continue; }
                            if pending.contains_key(&id) || closing.contains_key(&id) { return Err(NativeBrowserError::InvalidMessage); }
                            if let Some(deadline) = not_after.as_deref()
                                && let Err(error) = authorization_remaining_until(deadline) {
                                let _ = reply.send(Err(error));
                                continue;
                            }
                            let raw: &RawValue = serde_json::from_str(&body).map_err(|_| NativeBrowserError::InvalidMessage)?;
                            let frame = self.session.seal(&RequestEnvelope { protocol: INJECT_PROVIDER_PROTOCOL, kind: "operation.request", operation_id: &id, request: Some(raw) })?;
                            drop(body);
                            pending.insert(id, reply);
                            if let Some(deadline) = not_after.as_deref() {
                                write_authorized_extension_frame(output, &frame, deadline).await?;
                            } else {
                                timeout(OPERATION_TIMEOUT, write_message(output, &frame)).await.map_err(|_| NativeBrowserError::Unavailable)??;
                            }
                        }
                        Outbound::Close { id, permit } => {
                            if closing.insert(id.clone(), (Instant::now() + OPERATION_TIMEOUT, permit)).is_some() { return Err(NativeBrowserError::InvalidMessage); }
                            let frame = self.session.seal(&RequestEnvelope { protocol: INJECT_PROVIDER_PROTOCOL, kind: "operation.close", operation_id: &id, request: None })?;
                            timeout(OPERATION_TIMEOUT, write_message(output, &frame)).await.map_err(|_| NativeBrowserError::Unavailable)??;
                        }
                    }
                }
                frame = incoming.recv() => {
                    let Some(frame) = frame else {
                        return if pending.is_empty() { Ok(()) } else { Err(NativeBrowserError::Unavailable) };
                    };
                    let response: ResponseEnvelope = self.session.open(&frame)?;
                    if response.protocol != INJECT_PROVIDER_PROTOCOL { return Err(NativeBrowserError::InvalidMessage); }
                    match response.kind.as_str() {
                        "operation.result" => {
                            let reply = pending.remove(&response.operation_id).ok_or(NativeBrowserError::InvalidMessage)?;
                            let value = response.response.ok_or(NativeBrowserError::InvalidMessage)?;
                            let _ = reply.send(Ok(value));
                        }
                        "operation.closed" if response.response.is_none() && closing.remove(&response.operation_id).is_some()
                            && !pending.contains_key(&response.operation_id) => {},
                        _ => return Err(NativeBrowserError::InvalidMessage),
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
