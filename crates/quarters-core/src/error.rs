//! Stable errors shared by the CLI and core.

use std::error::Error;
use std::fmt::{Display, Formatter};
use std::io;

/// Machine-readable error categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    /// User input was invalid.
    InvalidInput,
    /// A requested object does not exist.
    NotFound,
    /// A requested object already exists.
    AlreadyExists,
    /// A space is active in another process.
    SpaceActive,
    /// The host cannot provide the requested capability.
    Unsupported,
    /// Stored state was malformed or violated an invariant.
    CorruptState,
    /// A bounded operation refused attacker-controlled or unexpectedly large input.
    ResourceLimit,
    /// An operating-system operation failed.
    System,
}

impl ErrorKind {
    /// Stable lowercase representation used in JSON output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidInput => "invalid_input",
            Self::NotFound => "not_found",
            Self::AlreadyExists => "already_exists",
            Self::SpaceActive => "space_active",
            Self::Unsupported => "unsupported",
            Self::CorruptState => "corrupt_state",
            Self::ResourceLimit => "resource_limit",
            Self::System => "system",
        }
    }
}

/// An actionable Quarters failure.
#[derive(Debug)]
pub struct QuartersError {
    kind: ErrorKind,
    message: String,
    hint: Option<String>,
    source: Option<Box<dyn Error + Send + Sync>>,
}

impl QuartersError {
    /// Construct an error without an underlying source.
    #[must_use]
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            hint: None,
            source: None,
        }
    }

    /// Add a concrete next action.
    #[must_use]
    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    /// Attach a lower-level cause.
    #[must_use]
    pub fn with_source(mut self, source: impl Error + Send + Sync + 'static) -> Self {
        self.source = Some(Box::new(source));
        self
    }

    /// Machine-readable category.
    #[must_use]
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Human-readable explanation.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Optional recovery instruction.
    #[must_use]
    pub fn hint(&self) -> Option<&str> {
        self.hint.as_deref()
    }

    /// Wrap an I/O error with operation context.
    #[must_use]
    pub fn io(operation: &str, path: &std::path::Path, source: io::Error) -> Self {
        Self::new(ErrorKind::System, format!("could not {operation} {}", path.display())).with_source(source)
    }
}

impl Display for QuartersError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for QuartersError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source.as_deref().map(|source| source as &(dyn Error + 'static))
    }
}

/// Core result type.
pub type Result<T> = std::result::Result<T, QuartersError>;
