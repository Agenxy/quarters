//! Managed-agent and command-adapter output.

use super::{escape_for_human, path_for_human, print_success};
use crate::adapter::AdapterReport;
use quarters_core::{AgentStatus, Result};

pub(crate) fn print_agent(action: &str, status: &AgentStatus, json_output: bool) -> Result<()> {
    if json_output {
        return print_success(&format!("agent.{action}"), status, true);
    }
    println!("Private SSH agent for {}: {}", status.space, status.state.as_str());
    if let Some(pid) = status.pid {
        println!("  PID     {pid}");
    }
    if let Some(socket) = &status.socket {
        println!("  Socket  {}", escape_for_human(socket));
    }
    println!("  Check   {}", status.detail);
    println!("  Scope   separate credential process; host account authority is unchanged");
    Ok(())
}

pub(crate) fn print_adapter(action: &str, report: &AdapterReport, json_output: bool) -> Result<()> {
    if json_output {
        return print_success(&format!("adapter.{action}"), report, true);
    }
    println!("OpenSSH adapters for {}", report.space);
    println!(
        "  quarters {:<10} {}",
        report.launcher.state.as_str(),
        path_for_human(&report.launcher.path)
    );
    for entry in &report.tools {
        println!(
            "  {:<8} {:<10} {}",
            entry.tool,
            entry.state.as_str(),
            path_for_human(&entry.path)
        );
    }
    println!("  Boundary {}", report.boundary);
    Ok(())
}
