<img src="https://raw.githubusercontent.com/Agenxy/quarters/main/docs/icon.svg" width="72" height="72" alt="">

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

The development line also provides bounded cloning, reusable templates,
verifiable named snapshots and guarded rollback for inactive spaces. Each
credential-bearing mutation has a preview and exact confirmation. Rollback
first captures an automatic recovery snapshot and uses a durable three-state
transaction that `doctor` can explain and `recover` can finish safely.

A cooperative freeze blocks new managed process/agent launches and mutations
of the space itself while allowing the already-running Quarter to continue. From
that running context, `template create --from-active` can capture immediate
stationery under a shared lease and records `frozen-active` provenance. Direct,
detached or malicious same-UID writers remain possible: freeze is protection
from accidental Quarters actions, not filesystem immutability or containment.

A previewed host fork can seed a new Quarter with a closed set of shell startup
files plus explicitly named regular files. Its confirmation digest binds the
source generations and policy; credentials, history, cache, runtime and agent
stores are excluded by path. Selected file contents are deliberately
uninspected and may themselves contain secrets. Creation never evaluates copied
startup code, but entering the resulting Quarter may do so. This is a
convenience and review boundary, not containment from the host account.
Unsafe optional preset entries are reported as ineligible; an explicitly named
unsafe path is an error.

Verified templates and snapshots can be exported as one versioned,
key-authenticated plaintext bundle and imported as a fresh external template.
The bundle preserves the exact canonical tree and therefore requires explicit
sensitive-state confirmation. Import authenticates the complete file twice on
one retained descriptor, extracts only into private staging, verifies the
canonical digest and publishes atomically. Authentication is not encryption or
content review; imported startup files remain untrusted.

New spaces have opaque stable identities, recoverable display-name changes,
managed OpenSSH invocation adapters and an explicit private SSH-agent
lifecycle. The socket enters a child environment only after process liveness,
socket identity and the SSH-agent protocol all verify.

Linux uses the same baseline. An experimental `--home-view` can additionally
bind the space home over the real passwd home inside an unprivileged user and
mount namespace. It is opt-in because distro policy can disable user
namespaces, supplementary groups cannot be mapped without added privilege, and
ordinary `sudo` does not work inside that view. Quarters fails closed instead of
starting a home view that would silently reduce the account's group authority.
Before the mount, it copies the current native launcher and the four managed
OpenSSH links into the private runtime directory that remains reachable after
the host home is covered.

Linux also offers experimental, opt-in `--confinement filesystem`. It requires
Landlock ABI 3, starts in the Quarter home, reconstructs PATH from Quarter and
granted system locations, and fails closed unless the complete policy is
enforced. Inspect it first with
`quarters --json env NAME --confinement filesystem`. macOS remains unsupported;
Seatbelt and App Sandbox are not portable CLI foundations. The prebuilt macOS
npm binaries are unsigned and unnotarized in this alpha.

## Try it

```sh
cargo build --release
target/release/quarters create work
target/release/quarters create studio --layout workspace
target/release/quarters create familiar --from-host shell --preview
target/release/quarters clone studio experiment --preview
target/release/quarters clone studio experiment --confirm-sensitive-state studio
target/release/quarters template create clean-room --from studio --preview
target/release/quarters snapshot create studio before-change --preview
target/release/quarters exec work -- env
target/release/quarters enter work
```

Inside the shell:

```sh
echo "$QUARTERS_SPACE"
git config --global user.name "Work identity"
quarters current
quarters freeze
quarters template create current-room --from-active --preview
quarters template create current-room --from-active --confirm-sensitive-state work
quarters unfreeze --confirm work
```

Install the current checkout with `make install`. Building from source requires
a current Rust toolchain plus a working C compiler and assembler for optimized
BLAKE3. The complete repository gate and typed npm launcher development also
require Bun 1.3.14 and Node.js 26.2.0. npm remains the package registry,
artifact-publication tool and global-install surface. The command is placed
under `~/.local/bin` by default. The checkout is the unreleased alpha.4
development line. The latest public release is alpha.2, currently available
through these verified channels:

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
| `create NAME --from-host shell --preview` | Review selected host shell files without reading them into output or creating a space |
| `create NAME --from-host shell --confirm-plan DIGEST` | Atomically create only the exact metadata-bound host-fork plan |
| `clone SOURCE DESTINATION --preview` | Validate and summarize a bounded clone without mutation |
| `clone SOURCE DESTINATION --confirm-sensitive-state SOURCE` | Copy included persistent state into a new independent space |
| `upgrade NAME --preview\|--confirm NAME` | Assign stable identity to an inactive legacy profile |
| `rename PREVIOUS NAME --preview\|--confirm PREVIOUS` | Recoverably change an inactive space's display name |
| `freeze [NAME]` | Block new managed process/agent launches and space mutation; existing activity continues |
| `unfreeze [NAME] --confirm NAME` | Remove a cooperative freeze marker after exact confirmation |
| `template create NAME --from-active` | Capture stationery from the current frozen Quarter with a held cooperative lease |
| `template create\|list\|show\|use\|rename\|rm` | Manage reusable, integrity-checked creation sources |
| `snapshot create\|list\|show\|verify\|rename\|rm` | Manage named, integrity-checked recovery points |
| `rollback SPACE SNAPSHOT --recovery-name NAME --preview` | Verify replacement and automatic recovery capture without mutation |
| `rollback SPACE SNAPSHOT --recovery-name NAME --confirm-space SPACE --confirm-replace-state SPACE` | Capture recovery, then replace the complete home while retaining space identity |
| `export-key create PATH` | Create a private 32-byte bundle authentication key without printing its path or bytes |
| `export template\|snapshot NAME --to PATH --key PATH --preview` | Verify and disclose an authenticated plaintext export plan |
| `export template\|snapshot NAME --to PATH --key PATH --confirm-sensitive-state NAME` | No-clobber publish one authenticated bundle outside the store |
| `import BUNDLE NAME --key PATH --preview` | Authenticate a bundle and return its exact import-plan digest |
| `import BUNDLE NAME --key PATH --confirm-plan DIGEST` | Re-authenticate and atomically import a fresh external template |
| `list` | List healthy and unhealthy space entries without hiding siblings |
| `status [NAME]` | Observe cooperative freeze, lease and private-agent state |
| `current` | Print the current space or `host` |
| `env NAME [--confinement filesystem]` | Show the exact environment and optional non-mutating Landlock policy plan |
| `enter NAME [--confinement filesystem]` | Open the shell; confined Linux mode starts in the Quarter home |
| `exec NAME [--confinement filesystem] -- COMMAND` | Run one command; requested confinement never degrades silently |
| `host -- COMMAND` | Restore default host HOME and runtime paths from a baseline space |
| `agent status\|start\|stop\|restart [NAME]` | Manage a protocol-verified private OpenSSH agent |
| `agent recover NAME --confirm NAME` | Reconcile only dead or protocol-verified private-agent state |
| `adapter status\|install\|remove [NAME]` | Inspect or manage collision-safe OpenSSH invocation adapters |
| `doctor [NAME]` | Inspect platform/tools; named form attempts baseline validation and still reports stale agent state |
| `rm NAME --confirm NAME` | Remove a space after exact-name confirmation and an inactive supervisor lease |
| `recover --confirm stale-state` | Reclaim validated internal state left by an interrupted lifecycle operation |
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
An unhealthy home or manifest remains visible to `list` and `status`. An
unhealthy home can be removed after exact-name confirmation only when the
space's private root, activity lock and manifest still prove its stable
identity and no private SSH-agent state exists. A damaged or unparseable
manifest cannot prove which runtime belongs to the entry, so removal fails
closed until that protected control file is repaired from trusted evidence.
Quarters also refuses removal when the space root or activity lock itself
cannot be validated.
Quarters deliberately does not rebuild or bypass a damaged published activity
lock: a supervisor may still hold the old inode, so automated deletion could
misclassify active state. Repairing such corruption remains a manual
filesystem-recovery operation.
`current` is a convenience report, never proof of identity or confinement. It
matches the space marker to a healthy store entry in baseline mode. Linux
home-view and filesystem confinement do not reopen the store, so they report
only the grammar-validated marker established by the launcher.
If the stored entry name itself is invalid, copy its exact value from
the filesystem only after inspecting it safely; JSON and human diagnostics
escape and bound untrusted names rather than replaying terminal controls. `rm`
accepts one literal visible directory-entry name while rejecting empty names
and path separators. Dot-prefixed entries are internal recovery state and are
never removal targets. A losing concurrent creation is cleaned automatically.
`doctor` reports any interrupted creation or retirement residue by count;
`recover --confirm stale-state` retires only those reserved, private-directory
prefixes while holding the bounded management lock, then performs potentially
large deletion after releasing it.
Cleanup is iterative and fails closed beyond 256 directory levels or 131,072
descendant directories. Such a retired tree is retained for exact-path manual
inspection; Quarters does not partially guess at deletion. On Linux, restoring
mode-`000` directories requires working no-follow `fchmodat` support, which may
depend on `/proc` on older libc/kernel combinations.
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

Each new space also gets a managed `quarters` launcher plus `ssh`, `scp`,
`sftp` and `ssh-add` links in its private `.local/bin`, which is first on the
space PATH. The network-client adapters initially resolve the real executable
from the captured host PATH, canonicalize candidates, skip the running
Quarters filesystem identity and every candidate that resolves to a launcher
named `quarters`, and stop direct recursive dispatch. They force the protected
per-space `.ssh/config` and user-known-hosts path while disabling passwd-home
default identity files.
Keys intentionally loaded into the private agent and explicit `-i` keys remain
possible; leading and bundled competing `-F` arguments are rejected.
Bare `ssh-add` and host-keychain import flags are refused because OpenSSH would
search host-account defaults; name a per-space key explicitly. Inspection and
agent-management forms such as `ssh-add -l` and `ssh-add -D` remain available.
`quarters host -- ssh ...` is the intentional host-config escape, and absolute
host-tool paths bypass adaptation. No link replaces an existing entry, and
lifecycle copies omit machine-local links before recreating them for the
destination.

`quarters agent start NAME` launches `/usr/bin/ssh-agent` without a shell. Its
private socket is advertised only after a bounded SSH protocol exchange and
socket device/inode and kernel-reported peer-PID checks. Status remains
read-only when no runtime exists. Stop signals only that fully verified record.
Stale or ambiguous state blocks process launch; confirmed `agent recover`
removes only dead records or exact recorded socket identities and never follows
a link. Space removal refuses non-unset private-agent state and reclaims the
exact private runtime tree after the persistent space has been removed.

Moving or replacing the installed Quarters executable can make an existing
space's absolute launcher stale. `exec` and `enter` warn before launch when the
managed route is incomplete; repair it explicitly with
`quarters adapter install NAME`. Like every environment value under the same
UID, `QUARTERS_HOST_PATH` can be changed by the running process and is not an
integrity boundary.

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
and `quarters_create`. There is no MCP tool for cloning, entering a shell,
executing a command, inheriting environment variables, selecting an arbitrary
root or removing data. Agents can read `quarters://help`, `quarters://security` and the
private, short-lived `quarters://status` resource. Read the security resource
before permitting mutations.

When MCP is served by the installed `quarters` executable, created spaces get
the same managed command links as CLI-created spaces. Library test hosts that
are not the Quarters executable deliberately skip machine-local launcher links.

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
- no inherited SSH-agent socket; `SSH_AUTH_SOCK` is present only while that
  space's private agent passes process, inode and protocol verification
- `CFFIXED_USER_HOME` on macOS as a best-effort CoreFoundation compatibility
  enhancement

The child starts from a safe environment allowlist. Use `--inherit NAME` to
pass any additional variable deliberately. Quarters never prints its value.
Profile-owned variables such as `HOME`, `PATH`, `SSH_AUTH_SOCK`, XDG paths and
`QUARTERS_*` cannot be inherited because Quarters computes them after the
allowlist boundary.

New profile and workspace spaces use schema 3 with a random stable identity.
The profile layout creates only the shell and CLI state surface. The workspace
layout also creates private `Desktop`, `Documents`, `Downloads`, media,
public and template directories. On macOS it adds conventional `Applications`
and `Library` subdirectories. These are state-location conventions backed by
HOME/XDG and platform adapters, not containment; applications may still use
passwd-home, Keychain, TCC, app containers or absolute host paths.

Linux filesystem confinement is a separate earned capability. It denies
content reads, directory listing and mutation outside explicit grants, but it
does not hide known-path metadata: `stat`, `readlink`, existence checks and
`O_PATH` remain outside Landlock ABI 3. `/proc`, selected terminal devices,
network and IPC remain shared; already-open descriptors remain usable. The
real account and unconfined same-UID processes retain their normal authority.

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

`sudo` escapes a baseline profile. Landlock confinement sets `no_new_privs`, so
ordinary set-id elevation is disabled. Linux `--home-view` is unavailable when the
account has supplementary groups; when it is available, ordinary `sudo` cannot
cross the unmapped root identity and is expected to fail. `quarters host`
restores default host state paths only; it cannot recover credential variables
that were never inherited. It keeps the current working directory; use an
explicit executable path if command lookup must not depend on the active
space's launch context.

## Lifecycle scope and limits

`clone` creates a writable independent Quarter through the shared lifecycle
transaction. Preview it first:

```sh
quarters clone work experiment --preview
quarters clone work experiment --confirm-sensitive-state work
```

The exact-name confirmation is required because arbitrary included files may
contain credentials, histories, tokens and private agent state. Derived cache
roots are recreated empty unless `--include-cache` is selected. Runtime sockets,
FIFOs, devices and foreign-owned entries are skipped and counted. Safe relative
symlinks are preserved; absolute or lexically escaping links fail closed.
Hard-linked files become independent files. Quarters counts preserved links
into omitted cache roots; links into omitted sockets, FIFOs, devices or
foreign-owned entries may also dangle and are not separately counted.
Cache-root matching uses the documented home-relative spelling byte for byte;
Quarters does not guess at filesystem-specific case or Unicode aliases.

The portable backend preserves bytes and ordinary Unix permission bits. It
reports timestamps, ACLs, extended attributes, filesystem flags, set-ID/sticky
bits, sparse layout and hard-link relationships as not preserved. Embedded
absolute paths are not rewritten and may still select source state.

Clone and ordinary artifact capture hold Quarters' cooperative source lease
exclusively, stage on the same filesystem and publish with one rename. Active
stationery capture instead requires a valid cooperative freeze, observes an
existing held cooperative lease and holds a shared lease. Schema-3 artifacts record
`inactive` or `frozen-active` source evidence. A free lease cannot
discover detached writers, so neither clone nor a named snapshot is
crash-consistent. Templates omit derived caches by default; snapshots include
them by default. Artifact content is bound to a canonical BLAKE3 digest and
verified before use, but the digest is not authentication against another
process with the same UID.

Portable bundles add symmetric keyed-BLAKE3 authentication. Keys are exact
32-byte mode-`0600` files and travel separately; Quarters never prints their
path or bytes. Key creation and every key use reject paths inside the active
store, preventing a captured space from carrying the key that authenticates
its own bundle. A bundle is mode `0600`, plaintext, never overwrites a destination
and must live outside the store. Import accepts only current-user, single-link
bundle and key files, returns a metadata-bound preview digest, then repeats
authentication while extracting. A snapshot bundle becomes a template because
foreign source identity is historical provenance, not local rollback authority.
Case-colliding or filename-normalizing destination filesystems fail closed with
an explicit portability error.
If a final link or rename is already visible but directory sync or hidden
staging cleanup fails, Quarters reports the publication as committed with an
explicit warning instead of claiming that nothing was created.

The storage expand phase recognizes both the current `spaces`/`trash` layout
and the future `.spaces`/`.trash` layout. All writers still use the current
visible categories. Unmarked visible stores remain compatible; dotted stores
require a strict `.quarters-store.json` marker and are inspection-only in this
release. Dual layouts, active migrations, malformed markers, unexplained links
and newer marker schemas fail closed. The exact two-link no-clobber publication
state remains readable and is repaired under the management lease. `quarters
doctor` reports this state with bounded detail without creating or repairing
it.
Reserved staging problems are shown separately, without falsely describing an
otherwise valid visible store as read-only. Safe orphan staging is reclaimed on
the next explicit layout initialization even when the marker already exists;
ordinary reads remain non-mutating.

Rollback never merges in place. It verifies that the snapshot belongs to the
exact target generation, creates and verifies the required automatic recovery
snapshot, stages the replacement, preserves the target identity, and publishes
through durable `prepared`, `retired` and `published` states. The visible state
is old, new, or explicitly `rollback_in_progress`; `doctor` reports the exact
recovery action. This still adds no containment boundary. Display-name rename
is a separate recoverable transaction that retains stable identity and snapshot
binding. Cooperative freeze is implemented; enforceable filesystem freeze,
encrypted-at-rest storage and supported macOS confinement remain unavailable.

## Documentation

- [Getting started](docs/tutorials/GETTING-STARTED.md)
- [Architecture](docs/architecture/ARCHITECTURE.md)
- [Platform decision](docs/architecture/ADR-0001-PORTABLE-PROFILE-CORE.md)
- [Agent-native MCP decision](docs/architecture/ADR-0002-AGENT-NATIVE-MCP.md)
- [Lifecycle copy transaction](docs/architecture/ADR-0003-LIFECYCLE-COPY-TRANSACTION.md)
- [Host inheritance and fork policy](docs/architecture/ADR-0004-INHERITANCE-AND-HOST-FORK.md)
- [Private agent lifecycle](docs/architecture/ADR-0005-PRIVATE-AGENT-LIFECYCLE.md)
- [Storage migration and runtime identity](docs/architecture/ADR-0006-STORAGE-MIGRATION-AND-RUNTIME-IDENTITY.md)
- [Linux Landlock confinement](docs/architecture/ADR-0011-LINUX-LANDLOCK-CONFINEMENT.md)
- [Maximum native isolation](docs/architecture/ADR-0007-MAXIMUM-NATIVE-ISOLATION.md)
- [Lifecycle artifacts and rollback](docs/architecture/ADR-0008-LIFECYCLE-ARTIFACTS-AND-ROLLBACK.md)
- [Authenticated portable bundles](docs/architecture/ADR-0009-AUTHENTICATED-BUNDLES.md)
- [Cooperative freeze and active capture](docs/architecture/ADR-0010-COOPERATIVE-FREEZE-AND-ACTIVE-CAPTURE.md)
- [MCP guide](docs/mcp/README.md)
- [Threat model](docs/security/THREAT-MODEL.md)
- [Alpha 3 security review](docs/security/ALPHA3-SECURITY-REVIEW.md)
- [Compatibility matrix](docs/compatibility/MATRIX.md)
- [Security policy](SECURITY.md)
- [Registry publishing](docs/operations/REGISTRY-PUBLISHING.md)
- [Changelog](CHANGELOG.md)

Apache 2.0. No account, service, telemetry or proprietary dependency.
