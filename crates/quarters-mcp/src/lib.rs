//! MCP tools, resources and dual-version compatibility for Quarters.

mod lifecycle;
mod model;
mod output;
mod params;
mod resources;
mod server;
mod transport;
#[cfg(test)]
mod transport_tests;

pub use server::SUPPORTED_PROTOCOL_VERSIONS;

use quarters_core::{ErrorKind, HostEnvironment, QuartersError, Result, Store, validate_command_launcher};
use rmcp::ServiceExt;
use rmcp::service::QuitReason;
use std::path::PathBuf;
use tokio::io::{AsyncRead, AsyncWrite};

/// Serve Quarters over bounded local MCP stdio until the host disconnects.
///
/// Standard output is reserved exclusively for MCP frames. The function opens
/// no network listener and returns runtime failures to the CLI for stderr.
///
/// # Errors
///
/// Returns a safe Quarters diagnostic for runtime, handshake or transport
/// failure without echoing an untrusted MCP request body.
pub fn serve_stdio(store: Store, host: HostEnvironment) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .map_err(|error| {
            QuartersError::new(ErrorKind::System, "could not create the Quarters MCP runtime").with_source(error)
        })?;
    runtime.block_on(serve_stdio_async(store, host))
}

async fn serve_stdio_async(store: Store, host: HostEnvironment) -> Result<()> {
    let launcher = current_launcher()?;
    serve_io(tokio::io::stdin(), tokio::io::stdout(), store, host, Some(launcher)).await
}

/// Serve Quarters over one bounded in-memory duplex stream until its peer disconnects.
///
/// This integration-test surface applies the same frame, lifecycle, metadata,
/// duplicate-ID and concurrency controls as [`serve_stdio`]. Its concrete
/// stream type cannot wrap a network connection.
///
/// # Errors
///
/// Returns a safe diagnostic when startup, lifecycle handling or transport
/// shutdown fails.
pub async fn serve_duplex(stream: tokio::io::DuplexStream, store: Store, host: HostEnvironment) -> Result<()> {
    let (reader, writer) = tokio::io::split(stream);
    serve_io(reader, writer, store, host, None).await
}

async fn serve_io<R, W>(
    reader: R,
    writer: W,
    store: Store,
    host: HostEnvironment,
    command_launcher: Option<PathBuf>,
) -> Result<()>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    let family = lifecycle::ProtocolFamily::new();
    let admission = lifecycle::RequestAdmission::new();
    let transport = transport::BoundedStdioTransport::new(reader, writer, family.clone(), admission.clone());
    let service = lifecycle::QuartersService::with_controls(store, host, command_launcher, family, admission)
        .serve(transport)
        .await
        .map_err(|_error| startup_error())?;
    let reason = service.waiting().await.map_err(|_error| runtime_error())?;
    match reason {
        QuitReason::Cancelled | QuitReason::Closed => Ok(()),
        _ => Err(runtime_error()),
    }
}

fn current_launcher() -> Result<PathBuf> {
    let executable = std::env::current_exe().map_err(|error| {
        QuartersError::new(ErrorKind::System, "could not resolve the Quarters MCP executable").with_source(error)
    })?;
    let launcher = std::fs::canonicalize(&executable)
        .map_err(|error| QuartersError::io("resolve the stable Quarters MCP executable", &executable, error))?;
    validate_command_launcher(&launcher).map_err(|error| {
        QuartersError::new(
            ErrorKind::Unsupported,
            "the running MCP executable is not a protected stable Quarters launcher",
        )
        .with_hint("invoke an installed 'quarters' command from a protected root- or user-owned directory tree")
        .with_source(error)
    })
}

fn startup_error() -> QuartersError {
    QuartersError::new(
        ErrorKind::System,
        "the MCP host did not complete a supported Quarters lifecycle",
    )
    .with_hint("configure the host for MCP 2026-07-28 discovery or 2025-11-25 initialization")
}

fn runtime_error() -> QuartersError {
    QuartersError::new(ErrorKind::System, "the Quarters MCP service ended unexpectedly")
        .with_hint("restart the MCP host; run 'quarters doctor' if the failure repeats")
}
