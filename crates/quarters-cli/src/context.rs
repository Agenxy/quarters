//! Parsed routing marker for modes that cannot reopen the host store.

use std::ffi::OsStr;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RestrictedContext {
    HomeView,
    Filesystem,
    HomeViewFilesystem,
}

impl RestrictedContext {
    pub(crate) fn current() -> Option<Self> {
        match std::env::var_os("QUARTERS_NO_HOST_ESCAPE").as_deref() {
            Some(value) if value == OsStr::new("home-view") => Some(Self::HomeView),
            Some(value) if value == OsStr::new("filesystem") => Some(Self::Filesystem),
            Some(value) if value == OsStr::new("home-view+filesystem") => Some(Self::HomeViewFilesystem),
            Some(_) | None => None,
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::HomeView => "home-view",
            Self::Filesystem => "filesystem-confinement",
            Self::HomeViewFilesystem => "home-view+filesystem-confinement",
        }
    }
}
