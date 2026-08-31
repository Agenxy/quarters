//! Human presentation for store-layout diagnosis.

pub(super) fn print_store_layout(layout: &quarters_core::StoreLayoutDiagnosis) {
    println!(
        "  Store layout   {}{}",
        layout.state,
        if layout.writable { " (writable)" } else { " (read-only)" }
    );
    if let Some(issue) = &layout.issue {
        println!("    issue: {issue}");
    }
    if let Some(hint) = &layout.hint {
        println!("    hint: {hint}");
    }
    if let Some(issue) = &layout.staging_issue {
        println!("    staging issue: {issue}");
    }
    for staging in &layout.staging_entries {
        println!("    reserved staging: {staging}");
    }
    if layout.staging_entries_at_least > layout.staging_entries.len() {
        println!(
            "    reserved staging: showing {} of at least {} entries",
            layout.staging_entries.len(),
            layout.staging_entries_at_least
        );
    }
}
