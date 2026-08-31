//! Cooperative freeze policy output.

use super::print_success;
use quarters_core::{FreezeReport, Result};

pub(crate) fn print_freeze(report: &FreezeReport, json_output: bool) -> Result<()> {
    if json_output {
        return print_success("freeze", report, true);
    }
    println!("Cooperative policy for {}: {}", report.name, report.state.as_str());
    println!("  ID        {}", report.space_id);
    println!("  Changed   {}", if report.changed { "yes" } else { "no" });
    println!("  Scope     {}", report.scope);
    println!("  Boundary  {}", report.boundary);
    Ok(())
}
