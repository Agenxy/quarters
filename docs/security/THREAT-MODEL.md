# Threat model

## Assets

- host credentials, histories and CLI configuration
- state in one Quarters space that should not be selected accidentally by
  another space
- host files reachable by the real Unix account
- the validated storage root and removal target
- terminal control and process exit status

## Trust boundaries

The Quarters binary and its manifest are trusted first-party code and data. The
space name, environment, stored files, child executable and every process in the
child tree are untrusted inputs.

The operating system remains the authority boundary. Quarters baseline is not
one. A malicious child can use absolute paths, passwd records, open host files,
connect to host services and inspect other same-user processes subject to host
policy.

## Defenses in the alpha

| Risk | Control |
|---|---|
| Path traversal through a name | Strict 1-32 character validated name type |
| Partial creation | Same-filesystem temporary directory and atomic rename |
| Wrong removal target | Manifest/name validation, exact confirmation, rename then delete |
| Removal during a supervised entry | Shared lease held for the lifetime of the Quarters supervisor |
| Credential environment leakage | `env_clear()` plus safe allowlist; explicit values are redacted |
| Host Git helper reuse | Generated config clears inherited credential helpers |
| Shared SSH agent | Per-space short `SSH_AUTH_SOCK`; host socket is not inherited |
| Runtime socket collision | Mode-0700 short runtime directory per UID and space |
| Unsupported stronger mode | Capability check and fail-closed error |
| Namespace setup affecting caller | Dedicated internal child performs Linux namespace calls |
| Secret diagnostics | No state content reads; explicit inherited values render as redacted |

## Explicit non-goals

- containing malicious or compromised child processes
- hiding the host filesystem from the real account in baseline mode
- separating network, process, device or IPC namespaces
- virtualizing macOS Keychain, TCC, app containers or Secure Enclave
- preserving ordinary `sudo` inside Linux `--home-view`
- discovering detached descendants or same-user servers after their Quarters supervisor exits
- secure deletion from snapshots, backups or recovery media
- crash-consistent live snapshot or export

## Host and sudo escape

`quarters host` is a named convenience boundary, not an authority transition.
It restores captured host state paths. It is disabled in `--home-view` because
the real home is hidden in that mount namespace and restrictions cannot be
undone safely from inside the process tree.

In baseline mode, `sudo` uses host policy and normally switches to the target
user's home. It can write outside the profile. Users must treat it as a full
escape. In Linux `--home-view`, the root identity is unmapped, so set-id `sudo`
is expected to fail.

## Residual risks

Compatibility contracts can change between tool releases. `doctor` reports
installed executables and Quarters' configured route, but the alpha does not
trace every file open. A tool can ignore its documented variable. Absolute paths
and same-user services remain reachable. Detached processes can keep using a
space after its supervisor releases the activity lease, so users must stop them
before removal. CoreFoundation's override is undocumented and may change.
