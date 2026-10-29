// SPDX-License-Identifier: GPL-3.0-or-later
//! Adversarial tests for the bounded MCP transport.

use std::error::Error;

use rmcp::model::{ClientJsonRpcMessage, ErrorData, RequestId, ServerJsonRpcMessage};
use rmcp::transport::Transport;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

use crate::lifecycle::{ProtocolFamily, RequestAdmission};
use crate::transport::{BoundedStdioTransport, MAX_MCP_MESSAGE_BYTES};

#[tokio::test]
async fn oversized_input_closes_without_unbounded_growth() -> Result<(), Box<dyn Error>> {
    let (mut input, reader) = duplex(MAX_MCP_MESSAGE_BYTES + 2);
    let (_output, writer) = duplex(1024);
    let task = tokio::spawn(async move {
        input.write_all(&vec![b'x'; MAX_MCP_MESSAGE_BYTES + 1]).await?;
        input.write_all(b"\n").await
    });
    let mut transport = bounded(reader, writer);
    assert!(transport.receive().await.is_none());
    task.await??;
    Ok(())
}

#[tokio::test]
async fn oversized_output_is_rejected_before_writing() -> Result<(), Box<dyn Error>> {
    let (_input, reader) = duplex(1024);
    let (mut output, writer) = duplex(1024);
    let mut transport = bounded(reader, writer);
    let message = ServerJsonRpcMessage::error(
        ErrorData::internal_error("x".repeat(MAX_MCP_MESSAGE_BYTES), None),
        Some(RequestId::Number(1)),
    );
    let error = match transport.send(message).await {
        Ok(()) => return Err("oversized output was accepted".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    drop(transport);
    let mut bytes = Vec::new();
    output.read_to_end(&mut bytes).await?;
    assert_eq!(bytes, Vec::<u8>::new());
    Ok(())
}

#[tokio::test]
async fn stalled_output_has_a_bounded_deadline() -> Result<(), Box<dyn Error>> {
    let (_input, reader) = duplex(1024);
    let (_stalled_output, writer) = duplex(1);
    let mut transport = bounded(reader, writer);
    let message = ServerJsonRpcMessage::error(
        ErrorData::internal_error("x".repeat(4096), None),
        Some(RequestId::Number(1)),
    );
    let started = std::time::Instant::now();
    let error = match transport.send(message).await {
        Ok(()) => return Err("stalled output completed without a reader".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    assert!(started.elapsed() < std::time::Duration::from_secs(3));
    let close_started = std::time::Instant::now();
    let close_error = match transport.close().await {
        Ok(()) => return Err("stalled transport closed without a reader".into()),
        Err(error) => error,
    };
    assert_eq!(close_error.kind(), std::io::ErrorKind::TimedOut);
    assert!(close_started.elapsed() < std::time::Duration::from_secs(3));
    Ok(())
}

#[tokio::test]
async fn malformed_json_is_not_echoed_and_the_stream_recovers() -> Result<(), Box<dyn Error>> {
    let (mut input, reader) = duplex(4096);
    let (mut output, writer) = duplex(4096);
    let mut transport = bounded(reader, writer);
    input.write_all(b"{\"secret\":\"do-not-echo\",\n").await?;
    write_line(&mut input, &modern_request(1)).await?;
    let received = tokio::time::timeout(std::time::Duration::from_secs(1), transport.receive())
        .await
        .map_err(|_error| "transport receive timed out after malformed JSON")?;
    assert!(matches!(received, Some(ClientJsonRpcMessage::Request(_))));
    let response = tokio::time::timeout(std::time::Duration::from_secs(1), read_line(&mut output))
        .await
        .map_err(|_error| "parse-error output timed out after malformed JSON")??;
    assert_eq!(response["id"], serde_json::Value::Null);
    assert_eq!(response["error"]["code"], -32700);
    assert!(!response.to_string().contains("do-not-echo"));
    Ok(())
}

#[tokio::test]
async fn malformed_method_parameters_preserve_the_request_id() -> Result<(), Box<dyn Error>> {
    let (mut input, reader) = duplex(4096);
    let (mut output, writer) = duplex(4096);
    let mut transport = bounded(reader, writer);
    input
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\",\"params\":{}}\n")
        .await?;
    write_line(&mut input, &modern_request(6)).await?;
    let received = tokio::time::timeout(std::time::Duration::from_secs(1), transport.receive()).await?;
    assert!(matches!(received, Some(ClientJsonRpcMessage::Request(_))));
    let response = tokio::time::timeout(std::time::Duration::from_secs(1), read_line(&mut output)).await??;
    assert_eq!(response["id"], 5);
    assert_eq!(response["error"]["code"], -32602);
    Ok(())
}

#[tokio::test]
async fn malformed_notifications_never_receive_responses() -> Result<(), Box<dyn Error>> {
    let (mut input, reader) = duplex(4096);
    let (mut output, writer) = duplex(4096);
    let mut transport = bounded(reader, writer);
    input
        .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{}}\n")
        .await?;
    write_line(&mut input, &modern_request(1)).await?;
    assert!(matches!(
        transport.receive().await,
        Some(ClientJsonRpcMessage::Request(_))
    ));
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), output.read_u8())
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn preflight_notification_is_ignored_without_closing() -> Result<(), Box<dyn Error>> {
    let (mut input, reader) = duplex(4096);
    let (mut output, writer) = duplex(4096);
    let mut transport = bounded(reader, writer);
    input
        .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n")
        .await?;
    write_line(&mut input, &modern_request(1)).await?;
    assert!(matches!(
        transport.receive().await,
        Some(ClientJsonRpcMessage::Request(_))
    ));
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), output.read_u8())
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn invalid_request_ids_receive_invalid_request() -> Result<(), Box<dyn Error>> {
    let (mut input, reader) = duplex(4096);
    let (mut output, writer) = duplex(4096);
    let mut transport = bounded(reader, writer);
    input
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":{},\"method\":\"tools/list\"}\n")
        .await?;
    write_line(&mut input, &modern_request(1)).await?;
    let received = tokio::time::timeout(std::time::Duration::from_secs(1), transport.receive())
        .await
        .map_err(|_error| "transport receive timed out after invalid id")?;
    assert!(matches!(received, Some(ClientJsonRpcMessage::Request(_))));
    let response = tokio::time::timeout(std::time::Duration::from_secs(1), read_line(&mut output))
        .await
        .map_err(|_error| "error output timed out after invalid id")??;
    assert_eq!(response["id"], serde_json::Value::Null);
    assert_eq!(response["error"]["code"], -32600);
    Ok(())
}

#[tokio::test]
async fn batch_input_receives_invalid_request() -> Result<(), Box<dyn Error>> {
    let (mut input, reader) = duplex(4096);
    let (mut output, writer) = duplex(4096);
    let mut transport = bounded(reader, writer);
    input.write_all(b"[]\n").await?;
    write_line(&mut input, &modern_request(1)).await?;
    let received = tokio::time::timeout(std::time::Duration::from_secs(1), transport.receive()).await?;
    assert!(matches!(received, Some(ClientJsonRpcMessage::Request(_))));
    let response = tokio::time::timeout(std::time::Duration::from_secs(1), read_line(&mut output)).await??;
    assert_eq!(response["id"], serde_json::Value::Null);
    assert_eq!(response["error"]["code"], -32600);
    Ok(())
}

#[tokio::test]
async fn malformed_modern_metadata_is_rejected_then_valid_input_recovers() -> Result<(), Box<dyn Error>> {
    let (mut input, reader) = duplex(8192);
    let (mut output, writer) = duplex(8192);
    let mut transport = bounded(reader, writer);
    write_line(
        &mut input,
        &json!({"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {}}),
    )
    .await?;
    write_line(
        &mut input,
        &json!({"jsonrpc": "2.0", "id": 2, "method": "server/discover", "params": modern_meta()}),
    )
    .await?;
    let received = transport.receive().await.ok_or("valid request missing")?;
    assert!(matches!(received, ClientJsonRpcMessage::Request(_)));
    let error = read_line(&mut output).await?;
    assert_eq!(error["id"], 1);
    assert_eq!(error["error"]["code"], -32602);
    Ok(())
}

#[tokio::test]
async fn duplicate_live_request_ids_close_the_transport() -> Result<(), Box<dyn Error>> {
    let (mut input, reader) = duplex(8192);
    let (_output, writer) = duplex(8192);
    let mut transport = bounded(reader, writer);
    let request = json!({
        "jsonrpc": "2.0", "id": "same", "method": "server/discover", "params": modern_meta()
    });
    write_line(&mut input, &request).await?;
    write_line(&mut input, &request).await?;
    assert!(matches!(
        transport.receive().await,
        Some(ClientJsonRpcMessage::Request(_))
    ));
    assert!(transport.receive().await.is_none());
    Ok(())
}

/// Admit request 7, mark its handler running, cancel it, then reuse its id.
async fn reuse_cancelled_running_id(
    input: &mut tokio::io::DuplexStream,
    transport: &mut BoundedStdioTransport<tokio::io::DuplexStream, tokio::io::DuplexStream>,
    admission: &RequestAdmission,
) -> Result<crate::lifecycle::RequestGuard, Box<dyn Error>> {
    write_line(input, &modern_request(7)).await?;
    assert!(matches!(
        transport.receive().await,
        Some(ClientJsonRpcMessage::Request(_))
    ));
    let running = admission.claim(RequestId::Number(7))?;
    // What the transport records on reading `notifications/cancelled` for 7;
    // an unopened test transport ignores notifications themselves.
    admission.cancel(&RequestId::Number(7));
    write_line(input, &modern_request(7)).await?;
    Ok(running)
}

#[tokio::test]
async fn reusing_a_cancelled_running_id_waits_for_its_release() -> Result<(), Box<dyn Error>> {
    let (mut input, reader) = duplex(8192);
    let (_output, writer) = duplex(8192);
    let admission = RequestAdmission::new();
    let mut transport = BoundedStdioTransport::new(reader, writer, ProtocolFamily::new(), admission.clone());
    let running = reuse_cancelled_running_id(&mut input, &mut transport, &admission).await?;
    // The cancelled handler still runs, so the reuse waits; dropping the
    // receive mid-wait must keep the request instead of losing it.
    let early = tokio::time::timeout(std::time::Duration::from_millis(200), transport.receive()).await;
    assert!(early.is_err(), "the reused id was admitted while its predecessor ran");
    drop(running);
    let admitted = transport.receive().await.ok_or("the reused request was lost")?;
    let ClientJsonRpcMessage::Request(request) = admitted else {
        return Err("expected the reused request".into());
    };
    assert_eq!(request.id, RequestId::Number(7));
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn a_cancelled_id_that_never_frees_gets_a_non_terminal_error() -> Result<(), Box<dyn Error>> {
    let (mut input, reader) = duplex(8192);
    let (mut output, writer) = duplex(8192);
    let admission = RequestAdmission::new();
    let mut transport = BoundedStdioTransport::new(reader, writer, ProtocolFamily::new(), admission.clone());
    let _running = reuse_cancelled_running_id(&mut input, &mut transport, &admission).await?;
    write_line(&mut input, &modern_request(8)).await?;
    // Paused time advances past the bounded wait; the session keeps serving.
    let next = transport.receive().await.ok_or("the session closed")?;
    let ClientJsonRpcMessage::Request(request) = next else {
        return Err("expected the following request".into());
    };
    assert_eq!(request.id, RequestId::Number(8));
    let error = read_line(&mut output).await?;
    assert_eq!(error["id"], 7);
    assert_eq!(error["error"]["code"], -32600);
    Ok(())
}

fn bounded<R, W>(reader: R, writer: W) -> BoundedStdioTransport<R, W>
where
    R: tokio::io::AsyncRead,
    W: tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    BoundedStdioTransport::new(reader, writer, ProtocolFamily::new(), RequestAdmission::new())
}

fn modern_meta() -> serde_json::Value {
    json!({"_meta": {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {}
    }})
}

fn modern_request(id: i64) -> serde_json::Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "server/discover",
        "params": modern_meta(),
    })
}

async fn write_line(writer: &mut tokio::io::DuplexStream, value: &serde_json::Value) -> Result<(), Box<dyn Error>> {
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    writer.write_all(&bytes).await?;
    Ok(())
}

async fn read_line(reader: &mut tokio::io::DuplexStream) -> Result<serde_json::Value, Box<dyn Error>> {
    let mut bytes = Vec::new();
    loop {
        let byte = reader.read_u8().await?;
        bytes.push(byte);
        if byte == b'\n' {
            return Ok(serde_json::from_slice(&bytes)?);
        }
    }
}
