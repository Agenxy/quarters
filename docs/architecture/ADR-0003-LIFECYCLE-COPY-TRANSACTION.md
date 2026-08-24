# ADR 0003: One transaction primitive for lifecycle copies

Status: accepted for bounded portable clone; broader lifecycle gates remain open

## Context

A space home can contain databases with write-ahead logs, hard links, extended
attributes, sparse files, FIFOs, sockets and symlinks. A free Quarters lease
only proves that no current supervisor holds the cooperative lock; detached
processes can still write. Recursive copy therefore cannot provide an honest
snapshot or rollback boundary.

Clone, named stationery, snapshots, backups, exports and rollback need the same
rules. Independent implementations would drift on exclusions, links,
quiescence and crash recovery.

## Decision

Build one internal lifecycle transaction engine before exposing any of those
commands.

The engine has these phases:

1. Resolve and validate the source and destination through the store layout.
2. Acquire the store management lock and an exclusive source activity lock.
3. Require a lifecycle policy and record that detached-process state remains
   unknowable. A later managed-agent registry can strengthen this check; a free
   cooperative lease alone must never be described as a frozen filesystem.
4. Walk beneath an already-open source root without following symlinks. Reject
   escaping links and multiply linked control files. Omit and count devices,
   FIFOs, sockets and foreign-owned user entries.
5. Apply a declared inclusion policy. Runtime sockets, `.active`, temporary
   state and derived caches are excluded by default. Credentials are included
   only when the selected operation explicitly says so. Platform backends own
   their exact home-relative derived-cache roots; the portable root is `.cache`.
6. Copy into a private same-filesystem staging directory. The accepted first
   backend is a bounded portable copy. clonefile/reflink acceleration remains
   deferred until capability and semantic-equivalence gates pass.
7. Write operation provenance, fresh controls and the appropriate display name.
   Schema-2 workspace clones receive a new stable ID. Schema-1 profiles retain
   their compatible no-ID contract until ADR 0006 supplies a migration.
8. Sync files and directories, revalidate the completed tree, and publish with
   one rename while the management lock is held.
9. Leave only a recognizable private staging prefix after interruption so the
   existing recovery model can classify and reclaim it.

Every operation has explicit byte, entry, depth and path-length limits. Limit
failure publishes nothing. File modes, timestamps and selected extended
attributes have a documented portability policy; ownership remains the current
UID/GID. ACLs and platform metadata that cannot be represented are reported,
never silently claimed as preserved.

## Operation semantics

- `clone` creates a writable independent space with a new name and, for schema
  2, a new stable ID. `--preview` is the accepted dry-run surface.
- `template` stores a named, immutable-by-interface creation source with
  provenance and a credential inclusion declaration.
- `snapshot` creates an immutable-by-interface recovery point. Filesystem
  immutability flags are optional hardening, not the correctness anchor.
- `export` writes a versioned, authenticated manifest plus bounded content. It
  defaults to excluding credentials and must never include runtime sockets.
- `rollback` first creates and verifies an automatic recovery snapshot, then
  replaces the target through the same publish transaction. In-place recursive
  overwrite is forbidden.

## Acceptance gates

- crash injection at every phase leaves either the old published state or one
  complete new state
- adversarial symlink, hard-link, sparse-file, socket and permission fixtures
- concurrent create/remove/launch and lifecycle-operation stress tests
- clone/reflink and portable-copy outputs are semantically equivalent
- cache and credential policies are visible in dry-run JSON before mutation
- rollback recovery is proven after forced failure
- macOS and Linux filesystem fixtures, including unsupported metadata reports

## Accepted subset and deferred gates

The portable clone test suite covers adversarial link, hard-link, sparse,
socket, FIFO, permission, limit, concurrency and injected-failure fixtures in
the shared macOS/Linux implementation. It reports unsupported metadata rather
than claiming preservation and exposes no MCP clone authority.
Device nodes and foreign-UID entries require privilege or a second account and
therefore have classification coverage but no unprivileged filesystem fixture.

These gates remain explicitly unmet: clonefile/reflink equivalence, schema-1
stable identity, managed-agent or detached-process quiescence, immutable
templates/snapshots, authenticated export and rollback recovery after forced
replacement failure. Quarters therefore exposes `clone` but still no freeze,
snapshot, template, export or rollback command.
