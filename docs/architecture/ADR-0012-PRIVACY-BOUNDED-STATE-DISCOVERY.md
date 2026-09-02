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
default. `--preview` performs the prepared pre-scan but starts no child and
discloses the exact root selectors, fixed limits and credential-shaped pattern
set. Global `--json` is available only for preview. Executing discovery keeps
child stdout and stderr unchanged; human output goes to stderr and optional
machine output uses an inherited writable descriptor numbered three or higher.
Quarters writes that caller-selected sink after the post-scan, so the sink is
outside the measured delta. Callers should not direct it into a selected root.

Quarters holds the lifecycle lease exclusively for the full invocation. It
prepares the environment, runtime directory and any namespace launcher before
the pre-scan; runtime `bin` is excluded. It then starts exactly one direct child,
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
other metadata races become observation gaps, never partial deltas. Runtime
`bin` contents are excluded and declared because they contain Quarters-prepared
launch machinery rather than measured application state.

The alpha limits each phase to 65,536 entries, depth 64, 4,096 relative-path
bytes and five seconds. Any exceeded bound or observation gap suppresses the
entire delta. Credential classification uses disclosed path shapes only and
explicitly expects false positives and false negatives.

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
the delta. CLI acceptance proves preview behavior, exact child streams,
descriptor non-inheritance, classified JSON, post-scan failure handling,
pre-execution JSON refusal and exclusive cooperative coordination.

## Consequences

The feature can reveal that a tool used redirected state and which broad class
changed without revealing filenames. It cannot prove that a tool did not read
or write elsewhere. More detailed platform observability would require a new
capability, privacy model and ADR rather than silently expanding this report.
