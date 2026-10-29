//! End-to-end cancellation and admission proofs for the shipped transport.

use std::error::Error;
use std::fs::OpenOptions;
use std::io;
use std::path::PathBuf;
use std::time::Duration;

use fs4::FileExt;
use quarters_core::{HostEnvironment, SpaceName, Store};
use quarters_mcp::serve_duplex;
use rmcp::model::{ClientJsonRpcMessage, ServerJsonRpcMessage};
use rmcp::service::RoleClient;
use rmcp::transport::{IntoTransport, Transport};
use serde_json::{Value, json};

#[tokio::test]
async fn cancellation_is_graceful_and_the_session_survives() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("quarters");
    let store = Store::new(root.clone())?;
    let space = store.create(SpaceName::parse("work")?, PathBuf::from("/bin/sh"))?;
    store.lease_state(&space)?;
    let observation = OpenOptions::new().read(true).write(true).open(root.join(".observe"))?;
    FileExt::lock(&observation)?;

    let (server_io, client_io) = tokio::io::duplex(32 * 1_024);
    let server_task = tokio::spawn(serve_duplex(server_io, store, HostEnvironment::capture()));
    let mut client = IntoTransport::<RoleClient, _, _>::into_transport(client_io);
    client.send(message(discover_request(1))?).await?;
    assert_response_id(receive(&mut client).await?, 1)?;

    client.send(message(status_request(2))?).await?;
    tokio::time::sleep(Duration::from_millis(50)).await;
    client
        .send(message(json!({
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {"requestId": 2, "reason": "bounded cancellation test"}
        }))?)
        .await?;
    tokio::time::sleep(Duration::from_millis(50)).await;
    drop(observation);
    tokio::time::sleep(Duration::from_millis(50)).await;

    // MCP cancellation: a response for the cancelled id may still arrive if
    // the operation finished before the cancellation was processed, and the
    // client must tolerate it. Anything else must be the reply to id 3.
    client.send(message(list_tools_request(3))?).await?;
    let mut late_original = false;
    loop {
        let reply = response_value(receive(&mut client).await?)?;
        if reply["id"] == 3 {
            break;
        }
        late_original = accept_late_status(&reply, late_original)?;
    }

    // The session remains usable afterwards. Reusing a cancelled id is covered
    // deterministically by the transport tests, because the specification
    // forbids reusing an id that has not received a response.
    client.send(message(list_tools_request(4))?).await?;
    loop {
        let reply = response_value(receive(&mut client).await?)?;
        if reply["id"] == 4 {
            break;
        }
        late_original = accept_late_status(&reply, late_original)?;
    }

    drop(client);
    server_task.await??;
    Ok(())
}

fn discover_request(id: i64) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "server/discover",
        "params": modern_params(json!({}))
    })
}

fn status_request(id: i64) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": modern_params(json!({
            "name": "quarters_status",
            "arguments": {"name": "work"}
        }))
    })
}

fn list_tools_request(id: i64) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/list",
        "params": modern_params(json!({}))
    })
}

fn modern_params(mut value: Value) -> Value {
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "_meta".to_owned(),
            json!({
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientInfo": {"name": "cancellation-test", "version": "1"},
                "io.modelcontextprotocol/clientCapabilities": {}
            }),
        );
    }
    value
}

fn message(value: Value) -> Result<ClientJsonRpcMessage, serde_json::Error> {
    serde_json::from_value(value)
}

async fn receive<T>(transport: &mut T) -> Result<ServerJsonRpcMessage, Box<dyn Error>>
where
    T: Transport<RoleClient>,
    T::Error: Error + 'static,
{
    tokio::time::timeout(Duration::from_secs(10), transport.receive())
        .await?
        .ok_or_else(|| io::Error::other("server closed without a response").into())
}

fn response_value(message: ServerJsonRpcMessage) -> Result<Value, Box<dyn Error>> {
    Ok(serde_json::to_value(message)?)
}

/// Accept at most one late reply for the cancelled status call (id 2).
fn accept_late_status(reply: &Value, already_seen: bool) -> Result<bool, Box<dyn Error>> {
    let is_status = reply["id"] == 2 && reply["result"]["content"].is_array();
    if is_status && !already_seen {
        return Ok(true);
    }
    Err(io::Error::other(format!("unexpected reply: {reply}")).into())
}

fn assert_response_id(message: ServerJsonRpcMessage, expected: i64) -> Result<(), Box<dyn Error>> {
    let value = serde_json::to_value(message)?;
    if value["id"] == expected {
        Ok(())
    } else {
        Err(io::Error::other(format!("expected response {expected}, received {}", value["id"])).into())
    }
}
