//! Bounded newline-delimited MCP stdio transport.

use std::future::Future;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use rmcp::RoleServer;
use rmcp::model::{ClientJsonRpcMessage, ClientRequest, ErrorData, GetMeta, ProtocolVersion, ServerJsonRpcMessage};
use rmcp::transport::Transport;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Mutex, mpsc};
use tokio_util::bytes::BytesMut;
use tokio_util::codec::{Decoder, Encoder, FramedRead, FramedWrite, LinesCodec, LinesCodecError};

use crate::lifecycle::{AdmissionFailure, ProtocolFamily, RequestAdmission};

/// Maximum size of one complete newline-delimited MCP frame.
pub(crate) const MAX_MCP_MESSAGE_BYTES: usize = 1_024 * 1_024;

const CLIENT_INFO_META_KEY: &str = "io.modelcontextprotocol/clientInfo";
const LOG_LEVEL_META_KEY: &str = "io.modelcontextprotocol/logLevel";
const MCP_OUTPUT_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

/// Stdio transport with explicit input, output and drain bounds.
pub(crate) struct BoundedStdioTransport<R, W> {
    reader: FramedRead<R, BoundedJsonRpcDecoder>,
    writer: Arc<Mutex<FramedWrite<W, BoundedJsonRpcEncoder>>>,
    family: ProtocolFamily,
    admission: RequestAdmission,
    error_sender: mpsc::Sender<ServerJsonRpcMessage>,
    error_writer_failed: Arc<AtomicBool>,
    pending_error: Option<PendingError>,
}

impl<R, W> BoundedStdioTransport<R, W>
where
    R: AsyncRead,
    W: AsyncWrite + Send + Unpin + 'static,
{
    pub(crate) fn new(reader: R, writer: W, family: ProtocolFamily, admission: RequestAdmission) -> Self {
        let writer = Arc::new(Mutex::new(FramedWrite::new(
            writer,
            BoundedJsonRpcEncoder::new(family.clone()),
        )));
        let (error_sender, mut error_receiver) = mpsc::channel::<ServerJsonRpcMessage>(1);
        let error_writer = Arc::clone(&writer);
        let error_writer_failed = Arc::new(AtomicBool::new(false));
        let task_failed = Arc::clone(&error_writer_failed);
        tokio::spawn(async move {
            while let Some(message) = error_receiver.recv().await {
                if send_server_message(Arc::clone(&error_writer), message).await.is_err() {
                    task_failed.store(true, Ordering::Release);
                    break;
                }
            }
        });
        Self {
            reader: FramedRead::new(reader, BoundedJsonRpcDecoder::new()),
            writer,
            family,
            admission,
            error_sender,
            error_writer_failed,
            pending_error: None,
        }
    }
}

impl<R, W> Drop for BoundedStdioTransport<R, W> {
    fn drop(&mut self) {
        self.admission.close();
    }
}

impl<R, W> Transport<RoleServer> for BoundedStdioTransport<R, W>
where
    R: AsyncRead + Send + Unpin,
    W: AsyncWrite + Send + Unpin + 'static,
{
    type Error = io::Error;

    fn send(
        &mut self,
        message: ServerJsonRpcMessage,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send + 'static {
        let writer = self.writer.clone();
        let admission = self.admission.clone();
        let response_id = response_id(&message).cloned();
        if let Some(id) = response_id.as_ref() {
            admission.start_response(id);
        }
        async move {
            let result = send_server_message(writer, message).await;
            if let Some(id) = response_id.as_ref() {
                admission.finish_response(id);
            }
            result
        }
    }

    async fn receive(&mut self) -> Option<ClientJsonRpcMessage> {
        loop {
            if self.error_writer_failed.load(Ordering::Acquire) {
                return None;
            }
            if self.pending_error.is_some() {
                let permit = self.error_sender.reserve().await.ok()?;
                let pending = self.pending_error.take()?;
                let terminal = pending.terminal;
                permit.send(pending.message);
                if terminal {
                    return None;
                }
                continue;
            }
            match self.reader.next().await? {
                Ok(InboundFrame::Message(message)) => match prepare_message(&self.family, &self.admission, message) {
                    Preparation::Deliver(message) => return Some(message),
                    Preparation::Ignore => {}
                    Preparation::Reject(pending) => self.pending_error = Some(pending),
                    Preparation::Close => return None,
                },
                Ok(InboundFrame::ParseError) => {
                    self.pending_error = Some(PendingError::new(
                        ErrorData::parse_error("Parse error", None),
                        None,
                        false,
                    ));
                }
                Ok(InboundFrame::ProtocolError { error, id }) => {
                    self.pending_error = Some(PendingError::new(error, id, false));
                }
                Ok(InboundFrame::IgnoredNotification) => {}
                Ok(InboundFrame::Oversized) | Err(_) => return None,
            }
        }
    }

    async fn close(&mut self) -> Result<(), Self::Error> {
        tokio::time::timeout(MCP_OUTPUT_DRAIN_TIMEOUT, async {
            self.writer.lock().await.close().await
        })
        .await
        .map_err(|_error| output_timeout())?
    }
}

fn prepare_message(
    family: &ProtocolFamily,
    admission: &RequestAdmission,
    message: Box<ClientJsonRpcMessage>,
) -> Preparation {
    if family.is_unopened() && matches!(message.as_ref(), ClientJsonRpcMessage::Notification(_)) {
        return Preparation::Ignore;
    }
    if let Some((id, error)) = modern_metadata_error(&message, family) {
        return Preparation::Reject(PendingError::new(error, Some(id), false));
    }
    if let Some(id) = request_id(&message).cloned()
        && let Err(failure) = admission.reserve(id.clone())
    {
        if failure == AdmissionFailure::Duplicate {
            return Preparation::Close;
        }
        let terminal = failure != AdmissionFailure::Capacity;
        return Preparation::Reject(PendingError::new(failure.error(), Some(id), terminal));
    }
    if let Some(id) = cancellation_id(&message) {
        admission.cancel(id);
    }
    Preparation::Deliver(*message)
}

enum Preparation {
    Deliver(ClientJsonRpcMessage),
    Ignore,
    Reject(PendingError),
    Close,
}

struct PendingError {
    message: ServerJsonRpcMessage,
    terminal: bool,
}

impl PendingError {
    fn new(error: ErrorData, id: Option<rmcp::model::RequestId>, terminal: bool) -> Self {
        Self {
            message: ServerJsonRpcMessage::error(error, id),
            terminal,
        }
    }
}

#[derive(Debug)]
enum InboundFrame {
    Message(Box<ClientJsonRpcMessage>),
    ProtocolError {
        error: ErrorData,
        id: Option<rmcp::model::RequestId>,
    },
    IgnoredNotification,
    ParseError,
    Oversized,
}

#[derive(Debug)]
struct BoundedJsonRpcDecoder {
    lines: LinesCodec,
}

impl BoundedJsonRpcDecoder {
    fn new() -> Self {
        Self {
            lines: LinesCodec::new_with_max_length(MAX_MCP_MESSAGE_BYTES - 1),
        }
    }

    fn parse(line: Result<Option<String>, LinesCodecError>) -> Option<InboundFrame> {
        match line {
            Ok(Some(line)) => {
                let without_bom = line.strip_prefix('\u{feff}').unwrap_or(&line);
                let value = match serde_json::from_str::<serde_json::Value>(without_bom) {
                    Ok(value) => value,
                    Err(_error) => return Some(InboundFrame::ParseError),
                };
                if invalid_request_id(&value) {
                    return Some(InboundFrame::ProtocolError {
                        error: ErrorData::invalid_request("Invalid Request", None),
                        id: None,
                    });
                }
                Some(serde_json::from_value(value.clone()).map_or_else(
                    |_error| recover_protocol_value(&value),
                    |message| InboundFrame::Message(Box::new(message)),
                ))
            }
            Ok(None) => None,
            Err(LinesCodecError::MaxLineLengthExceeded) => Some(InboundFrame::Oversized),
            Err(LinesCodecError::Io(_error)) => Some(InboundFrame::ParseError),
        }
    }
}

fn recover_protocol_value(value: &serde_json::Value) -> InboundFrame {
    let serde_json::Value::Object(object) = value else {
        return InboundFrame::ProtocolError {
            error: ErrorData::invalid_request("Invalid Request", None),
            id: None,
        };
    };
    let recognizable_message = object.get("jsonrpc").and_then(serde_json::Value::as_str) == Some("2.0")
        && object.get("method").and_then(serde_json::Value::as_str).is_some();
    if recognizable_message && !object.contains_key("id") {
        return InboundFrame::IgnoredNotification;
    }
    let recognizable_request = recognizable_message && object.contains_key("id");
    if !recognizable_request {
        return InboundFrame::ProtocolError {
            error: ErrorData::invalid_request("Invalid Request", None),
            id: None,
        };
    }
    let id = recover_request_id(object.get("id"));
    id.map_or_else(
        || InboundFrame::ProtocolError {
            error: ErrorData::invalid_request("Invalid Request", None),
            id: None,
        },
        |id| InboundFrame::ProtocolError {
            error: ErrorData::invalid_params("request parameters do not match the MCP method schema", None),
            id: Some(id),
        },
    )
}

fn invalid_request_id(value: &serde_json::Value) -> bool {
    let serde_json::Value::Object(object) = value else {
        return false;
    };
    object.contains_key("id") && recover_request_id(object.get("id")).is_none()
}

fn recover_request_id(value: Option<&serde_json::Value>) -> Option<rmcp::model::RequestId> {
    match value? {
        serde_json::Value::Number(number) => number.as_i64().map(rmcp::model::RequestId::Number),
        serde_json::Value::String(value) if value.len() <= 128 => {
            Some(rmcp::model::RequestId::String(std::sync::Arc::from(value.as_str())))
        }
        _ => None,
    }
}

impl Decoder for BoundedJsonRpcDecoder {
    type Item = InboundFrame;
    type Error = io::Error;

    fn decode(&mut self, input: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        Ok(Self::parse(self.lines.decode(input)))
    }

    fn decode_eof(&mut self, input: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        Ok(Self::parse(self.lines.decode_eof(input)))
    }
}

async fn send_server_message<W>(
    writer: Arc<Mutex<FramedWrite<W, BoundedJsonRpcEncoder>>>,
    message: ServerJsonRpcMessage,
) -> Result<(), io::Error>
where
    W: AsyncWrite + Unpin,
{
    tokio::time::timeout(MCP_OUTPUT_DRAIN_TIMEOUT, async move {
        writer.lock().await.send(message).await
    })
    .await
    .map_err(|_error| output_timeout())?
}

fn output_timeout() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "MCP output stopped draining")
}

fn modern_metadata_error(
    message: &ClientJsonRpcMessage,
    family: &ProtocolFamily,
) -> Option<(rmcp::model::RequestId, ErrorData)> {
    let ClientJsonRpcMessage::Request(request) = message else {
        return None;
    };
    if family.is_legacy()
        || matches!(
            request.request,
            ClientRequest::InitializeRequest(_) | ClientRequest::PingRequest(_)
        )
    {
        return None;
    }
    let meta = request.request.get_meta();
    let mut missing = meta.missing_required_keys(&ProtocolVersion::V_2026_07_28);
    if meta.contains_key(CLIENT_INFO_META_KEY) && meta.client_info().is_none() {
        missing.push(CLIENT_INFO_META_KEY);
    }
    if meta.contains_key(LOG_LEVEL_META_KEY) && meta.log_level().is_none() {
        missing.push(LOG_LEVEL_META_KEY);
    }
    (!missing.is_empty()).then(|| {
        (
            request.id.clone(),
            ErrorData::invalid_params(
                format!("request _meta is missing or malformed: {}", missing.join(", ")),
                None,
            ),
        )
    })
}

fn request_id(message: &ClientJsonRpcMessage) -> Option<&rmcp::model::RequestId> {
    match message {
        ClientJsonRpcMessage::Request(request) => Some(&request.id),
        _ => None,
    }
}

fn cancellation_id(message: &ClientJsonRpcMessage) -> Option<&rmcp::model::RequestId> {
    match message {
        ClientJsonRpcMessage::Notification(notification) => match &notification.notification {
            rmcp::model::ClientNotification::CancelledNotification(cancelled) => cancelled.params.request_id.as_ref(),
            _ => None,
        },
        _ => None,
    }
}

fn response_id(message: &ServerJsonRpcMessage) -> Option<&rmcp::model::RequestId> {
    match message {
        ServerJsonRpcMessage::Response(response) => Some(&response.id),
        ServerJsonRpcMessage::Error(error) => error.id.as_ref(),
        _ => None,
    }
}

#[derive(Debug, Clone)]
struct BoundedJsonRpcEncoder {
    family: ProtocolFamily,
}

impl BoundedJsonRpcEncoder {
    fn new(family: ProtocolFamily) -> Self {
        Self { family }
    }
}

impl Encoder<ServerJsonRpcMessage> for BoundedJsonRpcEncoder {
    type Error = io::Error;

    fn encode(&mut self, message: ServerJsonRpcMessage, output: &mut BytesMut) -> Result<(), Self::Error> {
        let mut value =
            serde_json::to_value(&message).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        ensure_error_id(&message, &mut value)?;
        if self.family.is_modern() {
            stamp_server_info(&mut value)?;
        }
        let encoded = serde_json::to_vec(&value).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let framed_length = encoded
            .len()
            .checked_add(1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "MCP output length overflowed"))?;
        if framed_length > MAX_MCP_MESSAGE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "MCP output exceeded the one-MiB frame limit",
            ));
        }
        output.reserve(framed_length);
        output.extend_from_slice(&encoded);
        output.extend_from_slice(b"\n");
        Ok(())
    }
}

fn ensure_error_id(message: &ServerJsonRpcMessage, value: &mut serde_json::Value) -> Result<(), io::Error> {
    let ServerJsonRpcMessage::Error(error) = message else {
        return Ok(());
    };
    if error.id.is_some() {
        return Ok(());
    }
    value
        .as_object_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "JSON-RPC error was not an object"))?
        .insert("id".to_owned(), serde_json::Value::Null);
    Ok(())
}

fn stamp_server_info(value: &mut serde_json::Value) -> Result<(), io::Error> {
    let Some(result) = value.get_mut("result").and_then(serde_json::Value::as_object_mut) else {
        return Ok(());
    };
    let meta = result
        .entry("_meta")
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()))
        .as_object_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "MCP result _meta was not an object"))?;
    let implementation = serde_json::to_value(crate::server::server_implementation())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    meta.insert("io.modelcontextprotocol/serverInfo".to_owned(), implementation);
    Ok(())
}
