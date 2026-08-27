//! Shared work budgets for hostile or unexpectedly large directories.

use crate::{ErrorKind, QuartersError, Result};

pub(crate) const MAX_DIRECTORY_SCAN_ENTRIES: usize = 131_072;

pub(crate) struct ScanBudget {
    examined: usize,
    context: &'static str,
}

impl ScanBudget {
    pub(crate) const fn new(context: &'static str) -> Self {
        Self { examined: 0, context }
    }

    pub(crate) fn observe(&mut self) -> Result<()> {
        self.examined = self.examined.saturating_add(1);
        if self.examined <= MAX_DIRECTORY_SCAN_ENTRIES {
            return Ok(());
        }
        Err(QuartersError::new(
            ErrorKind::ResourceLimit,
            format!(
                "{} contains more than {MAX_DIRECTORY_SCAN_ENTRIES} filesystem entries",
                self.context
            ),
        )
        .with_hint("inspect the protected directory before retrying the operation"))
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn work_budget_fails_after_the_declared_bound() {
        let mut budget = ScanBudget::new("test directory");
        for _ in 0..MAX_DIRECTORY_SCAN_ENTRIES {
            budget.observe().expect("within budget");
        }
        assert!(budget.observe().is_err());
    }
}
