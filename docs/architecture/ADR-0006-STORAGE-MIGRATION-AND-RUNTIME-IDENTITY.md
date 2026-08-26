# ADR 0006: Expand-contract storage migration and runtime identity

Status: proposed; required before hidden internal directories or rename

## Context

The current store has a hidden root but visible internal `spaces` and `trash`
directories. The walkthrough requires Quarters-owned top-level directories to
be dot-prefixed. Renaming them immediately would strand older binaries and race
active spaces. Runtime directory names currently depend on the display name
and root path, which complicates rename and migration.

## Decision

Use an expand, migrate, contract sequence across separate compatibility
releases:

1. **Expand:** readers understand both legacy `spaces`/`trash` and future
   `.spaces`/`.trash`; writers continue using legacy paths. A root-format marker
   records which layout is authoritative. Ambiguous dual state fails closed.
2. **Migrate:** a confirmed command acquires the management lock, requires all
   known activity leases to be free, writes a durable migration marker, renames
   one directory at a time on the same filesystem, syncs parents, verifies the
   destination and records completion. Recovery resumes or rolls forward from
   the marker; it never guesses from partial names.
3. **Contract:** only after the compatible reader is common may new stores
   default to hidden internals. Legacy reading remains for a declared support
   window and never silently creates a second store.

Schema-2 spaces use their random stable ID for runtime identity. Schema-1
spaces derive a deterministic transition identity from the validated name and
`created_unix_ms`, domain-separated by the schema version. It is an identity
key, not a secret. The first release that changes runtime keys sweeps only
private, verified Quarters runtime directories; stale entries are reported and
reclaimed through a confirmed recovery action.

Rename is unavailable until every space has a stable identity. A rename will
change only the display name and directory entry under an exclusive lifecycle
transaction; it will not change the stable ID or silently edit user content.

## Required invariants

- one authoritative store layout at a time
- older compatible readers fail loudly during an active migration
- no migration while a Quarters supervisor lease is held
- detached-process uncertainty is presented before confirmation
- directory renames remain on one filesystem and sync their parents
- rollback never recursively merges two layouts
- runtime cleanup validates owner, type, mode and stable identity

## Acceptance gates

- crash injection before and after every marker write, rename and sync
- old-reader/new-reader matrix for expand, migrate and contract releases
- dual-layout and malicious-marker fixtures
- active lease and concurrent management refusal
- runtime re-key tests for schema 1 and schema 2
- macOS and Linux filesystem acceptance

## Consequences

The visible internal directories remain in this alpha. That is intentional:
changing them safely is a release sequence, not a cosmetic rename.

The additive `.templates` and `.snapshots` roots introduced by ADR 0008 are
older-reader-opaque artifact catalogs. They are not evidence that the future
authoritative `spaces` to `.spaces` and `trash` to `.trash` migration has begun,
and they do not participate in the dual-layout ambiguity check.
