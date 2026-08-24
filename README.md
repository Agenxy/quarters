<img src="docs/icon.svg" width="72" height="72" alt="">

# Quarters

Quarters gives native shells and commands another persistent home while they
continue to run as your real operating-system account.

**Different quarters. Same host.**

```text
same account, machine and permissions
                 |
        +--------+--------+
        |                 |
     host state       quarters state
     ~/.config        <space>/home/.config
     ~/.gitconfig     <space>/home/.gitconfig
     shell history    <space>/home/.local/state/shell
     CLI sessions     <space>/home/.config and tool homes
```

It is useful when personal, work, open-source and agent sessions need separate
configuration, histories and credentials, but should still use native host
binaries and files. It is not a VM, an OCI container, an alternate Unix user or
a security boundary.

## Alpha status

The macOS baseline works end to end. It creates a private folder, launches a
native process tree with a strict environment allowlist, redirects common
user-state locations, isolates shell history and runtime sockets, and preserves
the host UID, GID and permissions.

Linux uses the same baseline. An experimental `--home-view` can additionally
bind the space home over the real passwd home inside an unprivileged user and
mount namespace. It is opt-in because distro policy can disable user
namespaces, supplementary groups cannot be mapped without added privilege, and
ordinary `sudo` does not work inside that view. Quarters fails closed instead of
starting a home view that would silently reduce the account's group authority.

Filesystem confinement is not implemented. `doctor` reports Seatbelt and
Landlock as implementation gaps without claiming protection. The prebuilt
macOS npm binaries are unsigned and unnotarized in this alpha; use Homebrew or
Cargo to build locally if host policy rejects them.

## Try it

```sh
cargo build --release
target/release/quarters create agenxy
target/release/quarters create studio --layout workspace
target/release/quarters exec agenxy -- env
target/release/quarters enter agenxy
```

Inside the shell:

```sh
echo "$QUARTERS_SPACE"
git config --global user.name "Agenxy contributor"
quarters current
```

Install the current checkout with `make install`. The command is placed under
`~/.local/bin` by default. The checkout is the unreleased alpha.3 development
line. The latest public release is alpha.2, currently available through these
verified channels:

```sh
brew install agenxy/tap/quarters
cargo install --locked --version 0.1.0-alpha.2 quarters
npm install --global quarters-cli@alpha
```

The npm package selects native builds for macOS arm64, macOS x64 and Linux x64.
Linux arm64 is not yet published through npm, which rejects that target
directly. PyPI publication is not yet available and is not advertised as an
install path.

## Commands

| Command | Purpose |
|---|---|
| `create NAME [--layout profile\|workspace]` | Atomically create a minimal profile or expanded workspace |
| `list` | List healthy and unhealthy space entries without hiding siblings |
| `status [NAME]` | Observe whether Quarters' cooperative lease is free or held |
| `current` | Print the current space or `host` |
| `env NAME` | Prepare and show the exact computed environment; explicit inherited values are redacted |
| `enter NAME` | Open the space's interactive shell |
| `exec NAME -- COMMAND` | Run one native command |
| `host -- COMMAND` | Restore default host HOME and runtime paths from a baseline space |
| `doctor [NAME]` | Inspect platform/tools; named form prepares and validates the baseline environment |
| `rm NAME --confirm NAME` | Remove a space after exact-name confirmation and an inactive supervisor lease |
| `recover --confirm stale-state` | Reclaim validated internal state left by an interrupted create or remove |
| `shell-init zsh\|bash` | Print composable prompt integration without editing shell files |
| `shortcut status\|install\|remove [NAME]` | Inspect or manage a collision-safe short command; `qts` is recommended |
| `mcp` | Serve the bounded local MCP adapter over standard input/output |

Management and inspection commands accept `--json`. Pass-through commands do
not because child standard output must remain unchanged.

`env` and `doctor NAME` prepare the private runtime directories referenced by
the computed environment. Neither starts a child or reads user content stored
inside the space home.

`status` reports the cooperative lease used by Quarters supervisors and
management operations. It does not guess from PIDs or scan processes. A
detached process, background job or server can outlive the lease and is not
discoverable portably, so its state is reported as unknown. Removal is blocked
while the lease is held; stop detached processes before removing their space.
An unhealthy home or manifest remains visible to `list` and `status` and can be
removed after exact-name confirmation, but Quarters refuses removal when the
space root or activity lock itself cannot be validated.
Quarters deliberately does not rebuild or bypass a damaged published activity
lock: a supervisor may still hold the old inode, so automated deletion could
misclassify active state. Repairing such corruption remains a manual
filesystem-recovery operation.
`current` is a convenience report, never proof of identity or confinement. It
matches the space marker to a healthy store entry in baseline mode. Linux
home-view cannot reopen the store hidden by its mount, so there it reports the
validated marker established by the Quarters launcher.
If the stored entry name itself is invalid, copy its exact value from
the filesystem only after inspecting it safely; JSON and human diagnostics
escape and bound untrusted names rather than replaying terminal controls. `rm`
accepts one literal visible directory-entry name while rejecting empty names
and path separators. Dot-prefixed entries are internal recovery state and are
never removal targets. A losing concurrent creation is cleaned automatically.
`doctor` reports any interrupted creation or retirement residue by count;
`recover --confirm stale-state` removes only those reserved, private-directory
prefixes while holding the same bounded management lock as creation/removal.
If recovery metadata is corrupt, `doctor` keeps reporting platform and tool
capabilities while marking only recovery inspection unavailable.

New space startup files compose a cyan `[q:NAME]` marker with the existing zsh
or bash prompt when `quarters` resolves on `PATH`. Existing spaces are never
rewritten; opt in from their `.zshrc` or `.bashrc` with the corresponding
`eval "$(quarters shell-init zsh)"` or `eval "$(quarters shell-init bash)"`
line. The marker is context, not proof of confinement.

After installing `quarters` on the host PATH, `quarters shortcut install qts`
can add the recommended shorthand to an existing, protected `~/.local/bin`
that is already on PATH. It never replaces an entry. Use
`quarters shortcut status qts` plus the printed `type -a qts` check before and
after mutation; a child process cannot inspect aliases or functions in its
parent shell. Status distinguishes `managed`, `relocated` and `stale` links;
remove accepts only those closed Quarters-launcher shapes. `q` is available
only when requested explicitly.

## MCP for local agents

`quarters mcp` exposes the same validated store through a local, newline-framed
stdio server. It implements MCP `2026-07-28` stateless discovery and the latest
2025 revision, `2025-11-25`, as separate lifecycle families. It does not open a
network listener.

```json
{
  "mcpServers": {
    "quarters": {
      "command": "/absolute/path/to/quarters",
      "args": ["mcp"]
    }
  }
}
```

The deliberately small tool surface is `quarters_status`, `quarters_doctor`
and `quarters_create`. There is no MCP tool for entering a shell, executing a
command, inheriting environment variables, selecting an arbitrary root or
removing data. Agents can read `quarters://help`, `quarters://security` and the
private, short-lived `quarters://status` resource. Read the security resource
before permitting mutations.

The transport caps each frame at one MiB, caps active requests, rejects reused
legacy or duplicate live request IDs, bounds store listings and keeps blocking
filesystem work off the protocol executor. Unhealthy directory names are
hex-encoded in agent responses so stored text cannot become model directives.
See the [MCP guide](docs/mcp/README.md) and
[verification contract](docs/mcp/VERIFICATION.md).

## What moves into a space

Quarters configures:

- `HOME` and XDG config, data, state and cache roots
- a short private XDG runtime directory and `TMPDIR`
- zsh and bash startup state and shell history
- Git global config, with inherited credential helpers cleared
- GitHub CLI, GnuPG, tmux, Cargo, npm and uv state locations
- Codex, Claude Code and OpenCode config locations where those tools honor
  their documented or established environment contracts
- no inherited SSH-agent socket; `SSH_AUTH_SOCK` stays unset until reviewed
  private-agent management exists
- `CFFIXED_USER_HOME` on macOS as a best-effort CoreFoundation compatibility
  enhancement

The child starts from a safe environment allowlist. Use `--inherit NAME` to
pass any additional variable deliberately. Quarters never prints its value.
Profile-owned variables such as `HOME`, `PATH`, `SSH_AUTH_SOCK`, XDG paths and
`QUARTERS_*` cannot be inherited because Quarters computes them after the
allowlist boundary.

`--layout profile` is the schema-1 default and creates only the shell and CLI
state surface. `--layout workspace` uses schema 2, assigns a random stable
space ID and also creates private `Desktop`, `Documents`, `Downloads`, media,
public and template directories. On macOS it adds conventional `Applications`
and `Library` subdirectories. These are state-location conventions backed by
HOME/XDG and platform adapters, not containment; applications may still use
passwd-home, Keychain, TCC, app containers or absolute host paths.

A custom `--root` is an operator-selected trust anchor. Put it beneath a
directory that is owned by the current user and not writable by another user;
Quarters validates the selected root and its control files, but does not claim
authority over every ancestor directory.

## What does not move

- UID, GID, groups, ACLs, `sudo` authority and filesystem permissions
- the kernel, devices, network, host processes and login session
- macOS Keychain, TCC, Secure Enclave and app containers
- systemd user services, D-Bus activation and already-running agents
- programs that insist on `getpwuid()` paths on macOS
- explicit absolute paths into the real home

`sudo` escapes a baseline profile. Linux `--home-view` is unavailable when the
account has supplementary groups; when it is available, ordinary `sudo` cannot
cross the unmapped root identity and is expected to fail. `quarters host`
restores default host state paths only; it cannot recover credential variables
that were never inherited. It keeps the current working directory; use an
explicit executable path if command lookup must not depend on the active
space's launch context.

## Why copy commands are not in this alpha

The product model includes clone, template and export workflows. Copying a live
home can capture SQLite WALs, Unix sockets, agent state and partial writes, so
this alpha does not expose a command that looks safe but is not. The intended
transaction and quiescence contract is recorded in
[the architecture](docs/architecture/ARCHITECTURE.md).

## Documentation

- [Getting started](docs/tutorials/GETTING-STARTED.md)
- [Architecture](docs/architecture/ARCHITECTURE.md)
- [Platform decision](docs/architecture/ADR-0001-PORTABLE-PROFILE-CORE.md)
- [Agent-native MCP decision](docs/architecture/ADR-0002-AGENT-NATIVE-MCP.md)
- [Lifecycle copy transaction](docs/architecture/ADR-0003-LIFECYCLE-COPY-TRANSACTION.md)
- [Host inheritance and fork policy](docs/architecture/ADR-0004-INHERITANCE-AND-HOST-FORK.md)
- [Private agent lifecycle](docs/architecture/ADR-0005-PRIVATE-AGENT-LIFECYCLE.md)
- [Storage migration and runtime identity](docs/architecture/ADR-0006-STORAGE-MIGRATION-AND-RUNTIME-IDENTITY.md)
- [Maximum native isolation](docs/architecture/ADR-0007-MAXIMUM-NATIVE-ISOLATION.md)
- [MCP guide](docs/mcp/README.md)
- [Threat model](docs/security/THREAT-MODEL.md)
- [Compatibility matrix](docs/compatibility/MATRIX.md)
- [Security policy](SECURITY.md)
- [Registry publishing](docs/operations/REGISTRY-PUBLISHING.md)
- [Changelog](CHANGELOG.md)

Apache 2.0. No account, service, telemetry or proprietary dependency.
