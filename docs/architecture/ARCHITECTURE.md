# Architecture

## Product contract

Quarters virtualizes user-owned state for a native process tree. It does not
virtualize the host identity or machine.

```text
CLI / local MCP stdio
 |
 +-- validated commands, typed tools and stable output
 |
 +-- portable core
 |    +-- private atomic store
 |    +-- manifest schema
 |    +-- environment allowlist
 |    +-- process activity leases
 |    +-- compatibility inventory
 |
 +-- platform backend
      +-- macOS HOME + CFFIXED_USER_HOME
      +-- Linux portable baseline
      +-- Linux opt-in user/mount home view
```

The CLI and MCP adapter are sibling presentation layers. Both use the same
`quarters-core` store, environment planner and platform inventory. The MCP
adapter cannot spawn profile processes and does not reimplement filesystem
authority.

## Storage

The default root is `~/.quarters`:

```text
.quarters/
  .observe
  spaces/
    work/
      .quarters.json
      .quarters-provenance.json  # clone destinations only
      .active
      home/
        .config/
        .local/{bin,share,state}/
        .cache/
        .gitconfig
        .ssh/config
        .gnupg/
  trash/
  .templates/<artifact-id>/{.quarters-artifact.json,home/}
  .snapshots/<artifact-id>/{.quarters-artifact.json,home/}
```

Creation builds a complete directory under `.creating-<name>-<unique>` on the
same filesystem, syncs private files and publishes it with `rename()`. A schema
marker and matching directory name are required when opening a space.
Schemas 1 and 2 remain readable legacy profile and workspace forms. Every new
profile or workspace uses schema 3, records its layout explicitly and receives
a random 128-bit opaque ID. Unsupported versions and inconsistent field sets
fail closed before a space becomes healthy. The ID binds runtime and artifact
lifecycle across display-name changes; it is not an authentication secret.
Inactive schema-1 profiles can receive it through atomic `upgrade`.
Creation, lifecycle publication, recovery, lease acquisition and removal share
the bounded root management lock. Rename losers
clean their skeleton immediately; interrupted `.creating-*` state and
`.retired-*` trash are counted by `doctor` and reclaimed only by the confirmed
`recover` command after private-directory validation. Recovery and ordinary
removal retire exact targets under the lock, then restore owner access only
inside the retired private tree and delete it after releasing the lock.

Root-lock deadlines reflect the kind of work waiting: read-only observation
waits up to 500 ms and reports activity as unknown when another operation is
busy; management operations wait up to five seconds before failing closed; a
space supervisor waits up to one second for its shared activity lease. All use
bounded exponential retry with jitter, so a slow host cannot turn a transient
management operation into an indefinite hang or make ordinary concurrent
creation spuriously fail at the observation deadline.

Removal takes an exclusive nonblocking lock, atomically renames the space under
`trash`, then removes that exact retired directory. A Quarters supervisor holds
a shared lease while its direct entry is running, so removal fails during that
period. A detached descendant, tmux server or other process that outlives its
supervisor is outside this portable lease model and must be stopped by the user
before removal.

`status` observes whether this cooperative lease is free or held. Supervisor
lease acquisition, status probes and the retirement phase of removal briefly
serialize through the root `.observe` lock. This prevents a probe from
mistaking another probe for a supervisor and prevents a waiting launch from
starting against a space that removal just retired. The observation is not a
later mutation precondition, and detached-process state remains unknown. Stored
root, home, manifest and lock anchors are validated without following their
final symlink and must retain their declared owner, type and private mode.
Aggregate status holds one observation guard for the entire bounded listing,
so contention has one deadline rather than one deadline per space.

Directory inspection treats every published entry independently. A damaged
home or manifest is reported as unhealthy without hiding valid siblings.
Removal deliberately validates only the invariants it needs: the exact named
private root and cooperative lock. A damaged root or lock remains fail-closed.
Stable spaces can be renamed through a private durable marker, same-filesystem
directory move and atomic manifest replacement. Recovery aborts before the
move or completes after it; malformed and ambiguous markers are retained
without blocking unrelated names. Each recovery pass scans the complete
same-UID marker namespace so ambiguous records cannot starve later actionable
work, while limiting successful filesystem mutations to 128. The scan is
therefore linear in retained marker count, not constant-time.

## Environment authority

The launcher calls `env_clear()` and rebuilds the child environment from a
small terminal and locale allowlist. Profile paths are then inserted. A user can
name additional variables with `--inherit`; diagnostic output redacts those
values.

This prevents accidental reuse of common and unknown credential variables. It
does not stop a child from reading credentials directly from any host path its
real account can access.

`SSH_AUTH_SOCK` is intentionally not inherited. It remains unset unless the
space has an explicitly started private OpenSSH agent whose PID, socket inode
and device, kernel-reported socket peer PID and SSH identities protocol response
all verify. Stale, starting or stopping state blocks process launch rather than
advertising ambiguous authority. Status does not create a missing runtime.

The generated Git config starts with an empty credential helper. This resets
helpers inherited from host or system policy before any per-space choice. It
avoids silently sharing macOS Keychain credentials.

Prompt context is computed only from the validated portable space name.
`quarters shell-init zsh|bash` emits first-party, versioned snippets that
prefix rather than replace the current prompt, so Git, virtualenv and theme
state can remain visible. Newly created startup files resolve `quarters` at
shell startup; existing startup files are never modified. Host escape clears
all Quarters prompt variables.

The optional `qts` or `q` shortcut is a managed symlink to the first
`quarters` launcher on PATH, not to the currently running executable. Its
directory must already be a protected host PATH directory. Installation never
overwrites, and removal deletes only a symlink whose target is relative
`quarters` or an absolute executable named `quarters`. Status distinguishes the
current managed target, a relocated live launcher and a stale target. Every
observed PATH match is reported. Parent-shell aliases and functions require the printed
`type -a` check because a child cannot observe them.

New spaces receive a machine-local absolute `quarters` launcher and relative
`ssh`, `scp`, `sftp` and `ssh-add` links in private `.local/bin`. Lifecycle
copies omit this closed five-link set and recreate it against the destination's
launcher. Network-client adapters force the protected per-space SSH config and
reject competing `-F`. Because OpenSSH's defaults use the passwd home rather
than HOME, adapters also force a current-space user-known-hosts path and
`IdentityFile=none` while retaining `IdentitiesOnly=no`, so only explicitly
named files and keys intentionally loaded into the private agent are offered.
They initially resolve host executables through the captured absolute host
PATH, canonicalizing candidates and skipping both the running Quarters
device/inode and any candidate whose resolved basename is `quarters`. The
basename rule also covers Linux home-view's deliberately distinct runtime copy.
A parent-PID handoff stops direct recursive dispatch. The child can change the
host-path environment value under the same-UID boundary.
Baseline dispatch reopens the declared store and validates the space, home,
SSH config and managed-command ancestry. Exact adapter links report stale when
their launcher is unavailable, and `doctor NAME` folds that observation into
the SSH route instead of claiming a managed path statically. Absolute tool
paths remain an intentional bypass.
`exec` and `enter` emit a warning when the observed managed launcher or adapter
set is incomplete, preventing a relocated installation from degrading silently.
Shortcut-spelled CLI and MCP launchers are canonicalized before managed-command
installation, so creation through `qts` still records the stable `quarters`
executable.

### Host-fork transaction

`create --from-host shell` is a separate file-selection authority from child
environment inheritance. Preview anchors the host `HOME` with a protected
directory descriptor and opens each closed-preset or explicit regular file one
component at a time with no-follow semantics. Credentials, directories,
history, runtime and caches are outside this policy.

The confirmation digest binds the request and every observed source and parent
directory generation. Execution recomputes that plan, keeps the exact source
descriptors open through a bounded copy, checks them again, then reopens each
path and compares its generation before atomic publication. A generated startup
file is replaced only when `--replace-generated` was part of the preview. The
private provenance file stores selection metadata and exclusions, not source
contents or secret-derived hashes. This narrows accidental state selection; it
does not restrict the authority of the resulting same-UID process.

## Process boundary

`enter` and `exec` spawn the requested native executable directly. No shell is
inserted for `exec`. The supervising parent holds the activity lease and
forwards the child's terminal naturally through inherited file descriptors.

`host` is an explicit baseline escape. It restores the captured host `HOME`,
`PATH`, `TMPDIR` and runtime path, clears profile variables and runs the target.
It does not restore variables that were omitted by the allowlist. Nested spaces
preserve the original backup chain, so this returns to the real host rather
than merely to the outer space.

The private SSH-agent helper is a narrow process boundary of its own. Quarters
spawns its current executable with an unguessable handoff token and registered
PID, then that helper uses `exec` to become fixed `/usr/bin/ssh-agent -D`.
Lifecycle control is serialized per stable space ID. Stop and recovery never
signal or unlink from PID data alone; full active socket ownership is required,
including the kernel-reported peer PID, and unowned links or malformed records
are retained.

## Agent protocol boundary

`quarters mcp` is a local stdio adapter built on the official Rust SDK. It
requires the canonical installed `quarters` launcher before accepting input,
so MCP creation and CLI creation apply the same machine-local link policy.
The in-memory library test transport has no launcher authority and explicitly
omits those links. The adapter supports exactly `2026-07-28` and `2025-11-25`.
A connection commits to one
lifecycle family: 2026 uses stateless `server/discover` and per-request
metadata; 2025 uses `initialize` and the initialized notification. Cross-family
methods and version metadata fail closed.

Transport admission owns request capacity from frame acceptance until response
write completion. It rejects oversized frames, overlong or duplicate request
IDs, bounds legacy-session ID retention, supports cancellation and times out
all writes and transport shutdown within two seconds when output is not
draining. Store operations execute through a
two-slot blocking-work gate. Status-all refuses stores larger than 128 visible
entries instead of returning a misleading partial view.

Transport-level errors are handed to a single-slot writer actor. Once an error
is decoded, cancellation of the SDK receive future cannot discard it; the actor
either writes the complete bounded frame within two seconds or marks the transport
failed. Valid JSON batches and invalid JSON-RPC IDs receive a fixed Invalid
Request response with a null ID. Pre-lifecycle notifications are ignored and
cannot select a protocol family.

Cancellation stops response delivery but never interrupts a filesystem
mutation mid-transaction. A cancelled create is allowed to finish atomically;
a retry may therefore report that the space already exists.

The MCP capability surface is intentionally narrower than the CLI. It can
inspect status, inspect capabilities and create a validated space. It cannot
clone state, run commands, open shells, inherit host environment, request home
views, change the bound root or delete data. Static resources are public-cacheable only under
2026; status is private with a 500 ms TTL. Legacy responses omit 2026 cache and
`resultType` fields.

Stored entry names and failure text are untrusted. Healthy names must pass the
portable grammar. Unhealthy names are represented as bounded hexadecimal and
their detailed filesystem diagnostics are replaced with a fixed validation
message on the agent surface. Terminal CLI output retains escaped, actionable
names for human recovery.

## Platform backends

### macOS

The baseline sets `HOME`, all supported tool-specific paths and
`CFFIXED_USER_HOME`. Apple's open CoreFoundation source consults that variable
before the passwd home when the process is not set-id. It remains undocumented,
so Quarters reports it as best effort and never treats it as the correctness
anchor.

macOS has no per-process mount namespace. Programs using `getpwuid()` can still
find the real home. SSH is therefore Class C and uses managed invocation links
that force `ssh -F` with the space config. Keychain, TCC, app containers and
login services remain host-bound.

Seatbelt is not part of the alpha's guarantee. `doctor` can report the deprecated
`sandbox-exec` binary, but no confinement flag exists without a reviewed policy.

Workspace layout additionally creates conventional personal directories plus
`Applications`, `Movies` and selected `Library` state directories beneath the
space home. No Launch Services, TCC, app-container or Finder registration is
performed, and applications are free to ignore these paths.

### Linux

The portable baseline matches macOS environment behavior without the
CoreFoundation variable.

Workspace layout creates the portable personal-directory set beneath the
space home. It does not edit host `user-dirs.dirs`, register desktop services
or imply that programs using passwd records have been redirected. Linux
`--home-view` remains the separate opt-in compatibility mechanism.

`--home-view` starts an internal Quarters child, creates a user namespace, maps
the real UID and GID to the same numeric values, creates a private mount
namespace, makes propagation private and bind-mounts the space home over the
passwd home. The target still has the same numeric user and host DAC authority.
Before the mount, Quarters publishes a private runtime copy of itself plus
relative `ssh`, `scp`, `sftp` and `ssh-add` links and prepends that runtime bin.
This keeps managed OpenSSH policy reachable even when the installed launcher
was beneath the host home that the mount covers.

This mode is opt-in for three reasons:

1. AppArmor, sysctls or distribution policy can block unprivileged user
   namespaces.
2. An unprivileged process cannot preserve arbitrary supplementary groups.
   Quarters reports the view as unavailable when the account has any, rather
   than silently reducing its filesystem authority.
3. Only the user's primary identity is mapped. Set-id root programs such as
   ordinary `sudo` cannot work inside the view.

The internal child prevents namespace calls from changing the invoking shell
or the supervising Quarters process. Requested setup fails closed.

Inside that mounted view, the authoritative store path is deliberately hidden.
The non-authoritative `current` convenience command therefore reports the
portable, grammar-validated space marker established at launch instead of
reopening the hidden store. Other management commands remain disabled, and no
security decision may use `current` as proof of process identity.

Landlock is future work. The build does not equate namespace path changes with
filesystem confinement.

## Lifecycle copy and artifact contract

Clone, template capture, snapshot capture, template use and rollback share a
bounded portable copy engine. Preview and execution
share a descriptor-relative walker rooted in already-open source and staging
directories. It uses no-follow `openat`/`fstatat` operations, fixed entry/byte/
depth/path limits, an exclusive cooperative source lease, private same-filesystem
staging, fresh control files and one publication rename.

The default policy recreates derived cache roots empty. Sockets, FIFOs, devices
and foreign-owned entries are omitted and counted. Regular hard links are copied
independently. Safe relative symlinks retain their link text; absolute and
lexically escaping links fail closed. User content is never listed in results.
Cache roots match the declared home-relative component bytes exactly; the
portable core does not infer case or Unicode aliases from filesystem behavior.
The report counts preserved links into omitted cache roots. Links into omitted
sockets, FIFOs, devices or foreign-owned entries may also dangle and are not
separately counted.
Arbitrary included state may contain credentials, so mutation requires an exact
source-name confirmation and writes versioned provenance without source content.

The backend preserves file bytes and ordinary permission bits, but not
timestamps, ACLs, xattrs, filesystem flags, set-ID/sticky bits, sparse extents or
hard-link topology. Embedded absolute paths are copied without rewriting. A free
cooperative lease cannot discover detached writers, so these copies are not
live database snapshots or quiescence proof.

Published templates and snapshots use opaque 128-bit physical IDs and strict
manifests. A canonical BLAKE3 stream binds stored paths, types, ordinary modes,
file bytes, symlink targets and terminal counts. Every consuming operation
verifies the complete artifact. Integrity detects change but does not
authenticate against another process with the same UID.

Rollback verifies exact source identity, captures an automatic recovery
snapshot, and replaces the complete target home while preserving its controls.
A durable `prepared`/`retired`/`published` marker permits deterministic
recovery. Readers report `rollback_in_progress`; recovery never guesses from an
ambiguous filesystem tuple. Artifact and rollback staging are included in the
bounded `doctor`/confirmed `recover` contract.

Platform clonefile/reflink acceleration, export, encryption and live freeze
remain deferred. Stable identity upgrade and inactive display-name rename are
implemented; hidden store-root migration remains deferred. ADR 0003 records
the copy boundary; ADR 0008 defines lifecycle artifacts and rollback.
