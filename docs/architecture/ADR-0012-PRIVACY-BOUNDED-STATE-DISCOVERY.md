# ADR 0012: Privacy-bounded state discovery

Status: accepted; experimental portable CLI instrument

## Context

Quarters redirects many user-state locations, but compatibility classes are
necessarily based on documented conventions and representative probes. A user
needs a way to observe what one native command changed inside a Quarter without
turning Quarters into a general tracer, collecting secrets, or implying that
unchanged Quarter state proves host isolation.

Linux Landlock denial logging is not a portable application API. Current
kernel documentation describes system-wide audit controls and privileged
tracepoints, with logging controls introduced after the ABI-3 policy Quarters
uses. Those facilities can help host operators investigate denials, but an
unprivileged Quarters invocation cannot treat them as complete, private,
per-command evidence. See the official
[Landlock user-space API](https://www.kernel.org/doc/html/latest/userspace-api/landlock.html)
and [Landlock LSM administration guide](https://www.kernel.org/doc/html/latest/admin-guide/LSM/landlock.html).

## Decision

The first instrument is `quarters discover SPACE [--scan home|runtime]...
[--report-fd N] [PROFILE OPTIONS] -- COMMAND...`. Both roots are selected by
default. `--preview` is a non-mutating plan: it takes no activity lease, creates
no runtime state, performs no scan and discloses the exact root selectors,
fixed limits and ASCII case-insensitive credential-shaped pattern set. Profile
options are validated only when execution prepares the launch. Global `--json`
is available only for preview. Executing discovery keeps child stdout and stderr
unchanged; human output goes to stderr and optional
machine output uses an inherited writable descriptor numbered three or higher.
Quarters writes that caller-selected sink after the post-scan, so the sink is
outside the measured delta. Callers should not direct it into a selected root.
The caller transfers ownership of the inherited descriptor. Quarters validates
and reopens it close-on-exec before opening any store or Quarter state, then
closes the original number. This prevents an absent caller number from aliasing
a later internal descriptor. macOS uses `/dev/fd`. Linux requires
`/proc/self/fd`; regular files retain their observed position and append mode,
and `/proc/self/fdinfo` must expose parseable `pos`, `flags`, and `ino` fields.
Blocking anonymous pipes are supported; sockets, named FIFOs and nonblocking
pipes fail explicitly.

Quarters holds the lifecycle lease exclusively for the full invocation. It
prepares the environment, runtime directory and any namespace launcher before
the pre-scan. It then starts exactly one direct child,
waits, performs the post-scan and preserves the child's native exit or signal
status even when post-scan, serialization or descriptor output fails.

Each scanner phase is descriptor-relative and no-follow. It opens directories
only, gathers `fstatat` metadata, never opens regular files or FIFOs, and never
resolves link targets. Transient relative component bytes feed a
domain-separated BLAKE3 entry key and one class: configuration, data, state,
cache, credential-shaped, runtime socket, runtime or unclassified. Neither the
opaque snapshots nor entry keys are serialized or persisted.

The selected root device/inode identities must agree across phases. Every
nested directory opened after a no-follow metadata observation must still match
that exact object before traversal. Root replacement, duplicate opaque keys or
other metadata races become observation gaps, never partial deltas. A vanished,
replaced or metadata-changing entry observed within either scan increments the
single truthful `unstable_entries` counter. Because
Quarters prepares runtime launch machinery before the first scan, later child
writes under runtime `bin` are measured rather than excluded.

The alpha gives each selected root an independent per-phase budget of 262,144
entries, depth 64, 4,096 relative-path bytes, 16 MiB of pending directory-entry
names and five seconds. Each root reports its own completeness and bound state.
Any exceeded bound or observation gap suppresses the entire delta. Unreadable
directories are counted by semantic class without exposing their paths.
Credential classification uses disclosed path shapes only and explicitly
expects false positives and false negatives.

Selected roots must be current-UID directories with exact mode `0700`, matching
the existing Quarters private-root contract. Discovery fails rather than
repairing a root or accepting a weaker mode.

With both roots selected, two retained snapshots can contain at most 1,048,576
entry records in aggregate, plus the current scanner's 16 MiB pending-name
budget. The five-second limit is per root and phase, for a 20-second maximum
across the default two-root pre/post scan.

## Claim boundary

The report measures selected Quarter-owned metadata. It does not measure file
reads, file contents, host paths, external grants, host writes, network, IPC,
devices, process access, platform keychains or writes preserving every compared
metadata field. The exclusive lease coordinates only Quarters participants;
detached and direct same-UID writers remain unknown. macOS LaunchServices GUI
applications are out of scope. Discovery is not containment, tracing, a
forensic log or proof that the host was left unchanged.

MCP deliberately receives no discovery or process-execution tool. Reports are
not written beneath the store, included in lifecycle artifacts or added to
ordinary logs. A caller may explicitly persist the JSON descriptor stream
outside Quarters.

## Verification

Unit tests prove mode-000 regular files, FIFOs and symbolic links are never
opened or resolved; hostile names and targets do not appear in serialized
reports; all change classes work; and bounds or unreadable subtrees suppress
the delta. Tests exercise every resource bound and prove that one bounded root
does not consume another root's budget. CLI acceptance proves non-mutating and
non-locking preview behavior, exact child streams, runtime-`bin` observation,
descriptor non-inheritance, regular-file append/position and pipe delivery,
read-only descriptor rejection, classified JSON, post-scan failure handling,
pre-execution JSON refusal and exclusive cooperative coordination.

## Consequences

The feature can reveal that a tool used redirected state and which broad class
changed without revealing filenames. It cannot prove that a tool did not read
or write elsewhere. More detailed platform observability would require a new
capability, privacy model and ADR rather than silently expanding this report.
