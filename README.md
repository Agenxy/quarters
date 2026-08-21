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
namespaces, and ordinary `sudo` does not work inside that view.

Filesystem confinement is not implemented. `doctor` reports Seatbelt and
Landlock as capabilities or gaps without claiming protection.

## Try it

```sh
cargo build --release
target/release/quarters create agenxy
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
`~/.local/bin` by default. Published builds are also available through
Homebrew and Cargo:

```sh
brew install agenxy/tap/quarters
cargo install --locked quarters
```

## Commands

| Command | Purpose |
|---|---|
| `create NAME` | Atomically create a private persistent space |
| `list` | List spaces and their homes |
| `current` | Print the current space or `host` |
| `env NAME` | Prepare and show the exact computed environment; explicit inherited values are redacted |
| `enter NAME` | Open the space's interactive shell |
| `exec NAME -- COMMAND` | Run one native command |
| `host -- COMMAND` | Restore host state paths from a baseline space |
| `doctor [NAME]` | Inspect platform and installed-tool compatibility |
| `rm NAME --confirm NAME` | Remove a space after exact-name confirmation and an inactive supervisor lease |

Management and inspection commands accept `--json`. Pass-through commands do
not because child standard output must remain unchanged.

`env` prepares the private runtime directories that the displayed environment
references. It does not start a child or inspect any state stored in the space.

Removal is blocked while the supervising `quarters` process for an entry is
running. A detached process, background job or server can outlive that
supervisor and is not discoverable portably. Exit those processes before
removing their space.

## What moves into a space

Quarters configures:

- `HOME` and XDG config, data, state and cache roots
- a short private XDG runtime directory and `TMPDIR`
- zsh and bash startup state and shell history
- Git global config, with inherited credential helpers cleared
- GitHub CLI, GnuPG, tmux, Cargo, npm and uv state locations
- Codex, Claude Code and OpenCode config locations where those tools honor
  their documented or established environment contracts
- an isolated `SSH_AUTH_SOCK` path
- `CFFIXED_USER_HOME` on macOS as a best-effort CoreFoundation compatibility
  enhancement

The child starts from a safe environment allowlist. Use `--inherit NAME` to
pass any additional variable deliberately. Quarters never prints its value.

## What does not move

- UID, GID, groups, ACLs, `sudo` authority and filesystem permissions
- the kernel, devices, network, host processes and login session
- macOS Keychain, TCC, Secure Enclave and app containers
- systemd user services, D-Bus activation and already-running agents
- programs that insist on `getpwuid()` paths on macOS
- explicit absolute paths into the real home

`sudo` escapes a baseline profile. In Linux `--home-view`, ordinary `sudo`
cannot cross the unmapped root identity and is expected to fail. `quarters host`
restores state paths only; it cannot recover credential variables that were
never inherited.

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
- [Threat model](docs/security/THREAT-MODEL.md)
- [Compatibility matrix](docs/compatibility/MATRIX.md)
- [Security policy](SECURITY.md)
- [Changelog](CHANGELOG.md)

Apache 2.0. No account, service, telemetry or proprietary dependency.
