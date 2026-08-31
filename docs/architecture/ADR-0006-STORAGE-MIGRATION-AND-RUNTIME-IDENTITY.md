# ADR 0006: Expand-contract storage migration and runtime identity

Status: partially accepted; expand reader, stable identity and rename
implemented; dotted writing and physical migration deferred until incompatible
readers can be prevented from mutating the store

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
   `.spaces`/`.trash`; writers continue using legacy paths. A strict
   `.quarters-store.json` marker records which layout is authoritative.
   Unmarked visible stores remain compatible; unmarked dotted or ambiguous
   dual state fails closed. This phase is implemented.
2. **Compatibility gate:** neither existing-store migration nor fresh dotted
   stores may ship while Alpha 1 or Alpha 2 can open the shared root, ignore the
   marker and create conflicting visible categories. A support window is not
   sufficient by itself; Quarters must be able to prevent incompatible readers
   from mutating the store.
3. **Future migrate and contract:** only after that gate is satisfied may a new
   ADR specify a recoverable physical migration and dotted-store writer. Until
   then all new stores and all writers remain visible inside the already-hidden
   `.quarters` root. There is no migration command or active migration state.

Schema-3 spaces use their random stable ID for runtime identity. Legacy
schema-1 spaces derive a deterministic transition identity from the validated
name and `created_unix_ms`, domain-separated by the schema version. It is an
identity key, not a secret. An explicit, inactive-space `upgrade` atomically
assigns schema 3 and a random ID. An existing legacy runtime tree is then
re-keyed by same-parent rename to that ID and its parent is synced. Runtime
lookup recognizes the exact legacy transition identity until re-keying
completes, and also recognizes `NAME-{fnv(root):016x}`, the spelling used by
the released alpha.1 and alpha.2 builds. Exactly one validated predecessor is
renamed;
multiple candidates fail closed without merge or deletion. An interrupted
upgrade can therefore resume without guessing. Rename
completes that re-key before changing the display name. Existing legacy
artifacts remain bound to the upgraded generation through their original name
and creation-time identity.

Rename is available only after a space has stable identity. It changes the
display name and directory entry under exclusive lifecycle and management
locks, retains the stable ID, updates only the manifest control file and does
not edit arbitrary user content. A private durable marker lets recovery abort
a pre-move transaction or finish a post-move manifest replacement. Ambiguous
or malformed markers are retained and do not block unrelated spaces.

## Required invariants

- one authoritative store layout at a time
- no dotted writer or physical migration before incompatible readers can be
  prevented from mutating the store
- ordinary reads never create or repair the root-format marker
- every mutation owns the bounded management lease and a resolved writable-layout token
- current-schema markers are strict, protected files: steady state has one
  link, while the exact two-link no-clobber publication state remains readable
  and is repaired only under the management lease; a lenient schema header
  makes newer schemas a distinct upgrade requirement
- dotted stores are inspection-only until a future ADR activates a compatible
  writer contract
- runtime cleanup validates owner, type, mode and stable identity
- normal space removal refuses non-unset private-agent state and reclaims the
  exact validated runtime tree only after persistent space deletion

## Acceptance gates

- old-reader/new-reader matrix before any future dotted writer or migration
- dual-layout and malicious-marker fixtures
- active lease and concurrent management refusal
- runtime re-key tests for schema 1; schema-2 upgrade remains unsupported
- released pre-alpha.4 runtime spelling migrates without abandoning state
- macOS and Linux filesystem acceptance

## Consequences

The visible internal `spaces` and `trash` directories remain in this alpha and
later releases until the compatibility gate is met. That is intentional: an
older binary can create visible categories in a fresh dotted store just as it
can after a migration. Space display-name rename does not begin a store-layout
migration.

The additive `.templates` and `.snapshots` roots introduced by ADR 0008 are
older-reader-opaque artifact catalogs. They are not evidence that the future
authoritative `spaces` to `.spaces` and `trash` to `.trash` migration has begun,
and they do not participate in the dual-layout ambiguity check.
