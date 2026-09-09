use super::{DiscoveryClass, DiscoverySelector};
use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

pub(super) const CREDENTIAL_PATTERN_SET_VERSION: u32 = 2;

pub(super) const CREDENTIAL_PATTERNS: &[&str] = &[
    ".anthropic",
    ".anthropic/**",
    ".aws",
    ".aws/**",
    ".azure",
    ".azure/**",
    ".cargo/credentials",
    ".cargo/credentials/**",
    ".cargo/credentials.toml",
    ".cargo/credentials.toml/**",
    ".claude",
    ".claude/**",
    ".codex",
    ".codex/**",
    ".config/anthropic",
    ".config/anthropic/**",
    ".config/gcloud",
    ".config/gcloud/**",
    ".config/gh",
    ".config/gh/**",
    ".config/opencode",
    ".config/opencode/**",
    ".docker",
    ".docker/**",
    ".env",
    ".env.*",
    ".env.*/**",
    ".env/**",
    ".git-credentials",
    ".git-credentials/**",
    ".gnupg",
    ".gnupg/**",
    ".kube",
    ".kube/**",
    ".netrc",
    ".netrc/**",
    ".npmrc",
    ".npmrc/**",
    ".openai",
    ".openai/**",
    ".pgpass",
    ".pypirc",
    ".pypirc/**",
    ".ssh",
    ".ssh/**",
    "**/.pgpass",
    "**/*.kdbx",
    "**/*.key",
    "**/*.p12",
    "**/*.pem",
    "**/*.pfx",
    "**/auth.json",
    "**/credentials",
    "**/credentials.json",
    "**/hosts.yml",
    "**/token",
    "**/token.json",
];

pub(super) fn classify(selector: DiscoverySelector, path: &[OsString], mode: nix::libc::mode_t) -> DiscoveryClass {
    if credential_shaped_components(path) {
        return DiscoveryClass::CredentialShaped;
    }
    if mode & nix::libc::S_IFMT == nix::libc::S_IFSOCK {
        return DiscoveryClass::RuntimeSocket;
    }
    if selector == DiscoverySelector::Runtime {
        return DiscoveryClass::Runtime;
    }
    let Some(first) = path.first().map(|value| value.as_bytes()) else {
        return DiscoveryClass::Unclassified;
    };
    if first == b".cache" || derived_cache(path) {
        DiscoveryClass::Cache
    } else if first == b".config" {
        DiscoveryClass::Configuration
    } else if components_start_with(path, &[b".local", b"state"]) {
        DiscoveryClass::State
    } else if components_start_with(path, &[b".local", b"share"])
        || components_start_with(path, &[b".local", b"bin"])
        || !first.starts_with(b".")
    {
        DiscoveryClass::Data
    } else if path.len() == 1 && mode & nix::libc::S_IFMT == nix::libc::S_IFREG {
        DiscoveryClass::Configuration
    } else {
        DiscoveryClass::Unclassified
    }
}

pub(crate) fn credential_shaped_path(path: &Path) -> bool {
    let components = path
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(value) => Some(value.to_os_string()),
            _ => None,
        })
        .collect::<Vec<_>>();
    credential_shaped_components(&components)
}

fn credential_shaped_components(path: &[OsString]) -> bool {
    let value = joined_ascii_lowercase(path);
    let basename = path
        .last()
        .map(|value| ascii_lowercase(value.as_bytes()))
        .unwrap_or_default();
    let prefix = [
        b".anthropic".as_slice(),
        b".aws".as_slice(),
        b".azure",
        b".cargo/credentials",
        b".cargo/credentials.toml",
        b".claude",
        b".codex",
        b".config/anthropic",
        b".config/gcloud",
        b".config/gh",
        b".config/opencode",
        b".docker",
        b".env",
        b".git-credentials",
        b".gnupg",
        b".kube",
        b".netrc",
        b".npmrc",
        b".openai",
        b".pypirc",
        b".ssh",
    ]
    .iter()
    .any(|prefix| value == *prefix || value.strip_prefix(*prefix).is_some_and(|tail| tail.starts_with(b"/")));
    prefix
        || value == b".env"
        || value.starts_with(b".env.")
        || matches!(
            basename.as_slice(),
            b"auth.json" | b"credentials" | b"credentials.json" | b"hosts.yml" | b"token" | b"token.json" | b".pgpass"
        )
        || [b".pem".as_slice(), b".key", b".p12", b".pfx", b".kdbx"]
            .iter()
            .any(|suffix| basename.ends_with(suffix))
}

fn joined_ascii_lowercase(path: &[OsString]) -> Vec<u8> {
    let mut value = Vec::new();
    for (index, component) in path.iter().enumerate() {
        if index > 0 {
            value.push(b'/');
        }
        value.extend(ascii_lowercase(component.as_bytes()));
    }
    value
}

fn ascii_lowercase(value: &[u8]) -> Vec<u8> {
    value.iter().map(u8::to_ascii_lowercase).collect()
}

fn components_start_with(path: &[OsString], prefix: &[&[u8]]) -> bool {
    path.len() >= prefix.len()
        && path
            .iter()
            .zip(prefix)
            .all(|(component, expected)| component.as_bytes() == *expected)
}

fn derived_cache(path: &[OsString]) -> bool {
    crate::platform::derived_cache_directories().iter().any(|root| {
        let root = PathBuf::from(root);
        let components = root
            .components()
            .filter_map(|component| match component {
                std::path::Component::Normal(value) => Some(value.as_bytes()),
                _ => None,
            })
            .collect::<Vec<_>>();
        components_start_with(path, &components)
    })
}
