# Lifecycle clone implementation plan

Date: 2026-08-24
Status: approved by independent Claude Opus 5 review

## Outcome

Add one production-shaped lifecycle operation:

```text
quarters clone SOURCE DESTINATION --confirm-sensitive-state SOURCE
quarters clone SOURCE DESTINATION --confirm-sensitive-state SOURCE --include-cache
quarters clone SOURCE DESTINATION --preview
quarters --json clone SOURCE DESTINATION --preview
```

The command creates a writable independent Quarter with the source layout,
shell configuration and included persistent home state. It is not a live
snapshot, a security boundary or proof that detached processes are absent.
Snapshot, rollback, templates, export, rename, hidden-store migration and host
forking remain unavailable until they can reuse this boundary safely.

## User contract

- `SOURCE` and `DESTINATION` use the existing validated portable name type.
- Mutation requires `--confirm-sensitive-state SOURCE`, exactly repeating the
  source name. Quarters cannot reliably infer which arbitrary files contain
  credentials, so there is no misleading "credential-free clone" mode. The
  confirmation means the complete included tree may contain credentials,
  histories, tokens and agent state.
- `--preview` conflicts with `--confirm-sensitive-state`. It performs the same
  bounded descriptor-relative validation walk and reports the policy, estimated
  entry count and logical byte count without creating a destination.
- Derived cache roots are excluded by default: `.cache` and platform roots
  returned by `platform::derived_cache_directories()` (initially
  `Library/Caches` on macOS). `--include-cache` opts them in. An excluded cache
  root is recreated empty at mode 0700 so the destination retains the directory
  skeleton guaranteed by `quarters create`.
- Runtime sockets, FIFOs, devices and entries not owned by the current UID are
  excluded rather than copied. Preview and execution both return bounded counts
  for `sockets`, `fifos`, `devices`, `foreign_owned`, `cache_roots`,
  `hard_linked_files_copied_independently` and
  `symlinks_into_omitted_cache_roots`. They never enumerate home paths.
- Runtime control files at the space root are always regenerated and never
  copied.
- Human and JSON results always say that detached-process activity is unknown.
  They list the metadata classes not preserved by the portable copy.
- A held cooperative source lease fails with `space_active`. Clone holds the
  source activity lock exclusively for the full preview or copy; concurrent
  `enter` and `exec` fail after the existing one-second bounded deadline.
  A free lease is cooperative evidence only, never filesystem quiescence.
- Preview and execution share one result shape: `mode` is `preview` or
  `execute`; the JSON envelope command remains `clone`.
- The MCP server does not gain clone authority in this slice.
- Embedded absolute paths in copied configuration and state are not rewritten;
  they may still select the source Quarter and this is disclosed in both output
  modes.

## Core transaction

Create a lifecycle module tree:

```text
store/lifecycle/mod.rs
store/lifecycle/policy.rs
store/lifecycle/walk.rs
store/lifecycle/copy.rs
store/lifecycle/publish.rs
```

The as-built module tree folds publication into `copy.rs` and adds
`cleanup.rs`, `walk/support.rs` and test-only `walk/test_support.rs`; the public
transaction entry point is `clone_space_controlled`.

`Store::clone_plan` and `Store::clone_space` share the same walker and policy.

1. Resolve and validate both names through the authoritative store layout.
2. Revalidate the source default shell with `validate_shell` before staging.
   Acquire the store management lock, then a new bounded
   `lock_exclusive_bounded_for_lifecycle` source activity lock. A deadline maps
   to `space_active`, not the generic lock-contention error.
3. Recheck that the destination and reserved staging path do not exist. For a
   mutation, create a private same-filesystem staging directory and hold the
   standard private creation-marker lock. Release the management lock while the
   potentially long walk runs, retaining the source activity lock.
4. Open source-home and staging-home descriptors with
   `O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC`. Walk entries relative to held directory
   descriptors using the already-vendored `nix` crate with its `fs` and `dir`
   features: `fstatat(..., AT_SYMLINK_NOFOLLOW)`, `openat`, `mkdirat`,
   `readlinkat` and `symlinkat`. Raw libc and `unsafe` remain forbidden.
5. The portable engine accepts current-user directories, regular files and
   safe relative symlinks. A symlink's lexical target must remain within the
   source home. Absolute or escaping symlinks and unclassifiable entry types
   fail closed. Sockets, FIFOs, devices and foreign-owned entries are skipped
   and counted. Multiply linked regular user files are copied independently and
   counted; the existing single-link rule remains mandatory for control files.
6. Enforce fixed alpha limits before each allocation or copy: 100,000 entries,
   10 GiB logical bytes, 2 GiB per regular file, depth 64, 255 component bytes,
   4,096 engine-relative path bytes and 4,096 symlink-target bytes. A limit
   failure reports observed versus allowed counts and publishes nothing. Logical
   file length, not allocated block count, enforces byte limits; sparse holes
   are materialized as zeros by this backend.
7. Compare device, inode, UID, GID, full mode, link count, size, and both the
   seconds and nanoseconds of modification and change times for source files,
   directories and symbolic links. This rejects inode reuse whenever any
   compared metadata differs. A same-type replacement within one filesystem
   timestamp interval that matches the entire tuple remains a portable
   limitation. A metadata change by a non-cooperating writer between inspection
   and open aborts the clone. Open regular files relative to their held parent
   descriptor with `O_NONBLOCK|O_NOFOLLOW`; the opened descriptor is then
   authoritative. Clear `O_NONBLOCK`, enforce per-file and aggregate
   actual-byte limits while reading, and report the actual copied length.
   Create destination files relative to a held parent descriptor with
   `O_EXCL|O_NOFOLLOW`; apply the source Unix permission bits after writing.
   Create destination directories at 0700 and defer their source modes to one
   bottom-up pass immediately before validation.
8. Copy without `File::sync_all`. Before pre-publish validation, issue one
   ordinary `nix::unistd::fsync` per written file and sync directories bottom-up.
   This avoids macOS `F_FULLFSYNC` per entry. After rename, sync the spaces parent.
   The promise is atomic publication plus ordinary filesystem durability; no
   device-level flush-ordering guarantee is made.
9. Generate destination controls explicitly:

   - `schema_version`: source schema
   - `layout`: source layout under its existing schema contract
   - `name`: destination name
   - `created_unix_ms`: fresh timestamp
   - `default_shell`: source value after current `validate_shell`
   - `authority_model`: first-party constant, never copied bytes
   - `space_id`: fresh random value for schema 2, absent for schema 1
   - `.active`: fresh private control file

   Also write `.quarters-provenance.json` at mode 0600. It has its own schema
   version, operation, source name, time and declared inclusion policy, contains
   no source content, and is not read in this slice. A future reader must use the
   same permissive-version-probe then strict-schema validation as manifests.
10. Reacquire the management lock while still holding the activity lock, re-open
    the source and verify the source manifest equals the one that began the
    transaction, recheck destination absence, remove and sync the private
    creation marker, revalidate completed destination anchors, then publish with
    one rename and sync the parent. All waits are bounded. The existing portable
    check-then-rename same-UID replacement race is documented as residual; this
    slice does not add divergent Apple/Linux rename primitives.
11. Before publication, any error calls a shared
    `remove_tree_restoring_owner_access` helper. It restores `u+rwx` top-down on
    current-user directories before removing them. Existing creation cleanup and
    `store_recovery::recover()` use the same helper so a cloned 0500 directory
    cannot wedge recovery. If cleanup still fails, the `.creating-*` directory
    remains recognizable and recoverable. After publication, durability errors
    state that the complete destination exists and must be inspected before
    retrying.

The lock-order transition (management then activity during setup; retained
activity then management at publish) is bounded and documented. Recovery is
changed not to hold the management lock across unbounded tree deletion: it
retires validated stale paths under the lock, then removes them with the shared
helper after releasing the lock.

## Metadata and disclosure contract

The first backend is a bounded native portable copy. It preserves file bytes,
safe relative symlink text and Unix permission bits. Hard-linked regular files
become independent files. Sparse holes become allocated zero bytes. Results
report these metadata classes as not preserved: timestamps, ACLs, extended
attributes, filesystem flags, sparse extent layout and hard-link relationships.
Ownership is the current real UID/GID because this is a native same-account
operation.

Copied modes are masked to ordinary `0o777` permissions. Set-user-ID,
set-group-ID and sticky bits are not preserved. Owned source entries that cannot
be opened fail closed; Quarters never changes source permissions and returns one
escaped relative path with a concrete permission hint.

Outputs contain aggregate counts and class names only. An error may include one
actionable source-home-relative path, escaped and bounded to 512 bytes through
the existing untrusted-text helper. Absolute source paths and file content are
never included in clone results or errors.

`clonefile` and reflink acceleration remain behind a future capability backend.
No acceleration is claimed in this slice, so semantic-equivalence testing is
explicitly deferred and unmet. The portable implementation is shared by macOS
and Linux and performs no shellouts.

## Fault and race test seam

The private `clone_space_controlled` transaction accepts a test-only abort point:

```text
BeforeCopy
MidCopy
BeforeIdentityRecheck
BeforePublish
AfterPublish
```

The parameter and branches exist only under `cfg(test)`; public production
entry points cannot select them. The identity-recheck abort point also supports
a deterministic source-entry replacement fixture. Each fault proves one of:
no destination and no staging; no destination and one recoverable staging path;
or one fully published destination.

## Tests and acceptance

Core tests must prove:

- profile and workspace clones copy included files, preserve the create-
  guaranteed directory skeleton, receive a new name/fresh timestamp/fresh
  control state, and never reuse a schema-2 stable ID
- preview and execution report identical policy and exclusion counts on an
  unchanged tree
- default cache exclusion with empty-root recreation and explicit cache inclusion
- held cooperative lease refusal for the full operation, correct
  `space_active` mapping and detached-process disclosure
- descriptor-relative rejection for absolute, escaping and deterministically
  replaced symlinks
- independent copying/counting of hard-linked files
- sparse-file logical-length accounting with materialized output bytes
- exclusion/counting of sockets, FIFOs, devices and foreign-owned entries,
  with no path disclosure
- entry, byte, file, depth, component, relative-path and symlink-target limits
  fail without publication
- permissions and relative in-tree symlinks are preserved as declared
- destination collision and concurrent clone/create/remove behavior
- read-only directories can be cleaned after injected failure and by recovery
- each test-only abort point leaves no destination, recoverable staging or one
  complete published destination as declared

CLI tests must cover help, exact sensitive-state confirmation, flag conflicts,
human output, stable JSON output, preview non-mutation and actionable escaped,
bounded errors.

Acceptance requires formatting, warnings-as-errors linting, all Rust and npm
tests, structural ceilings, warning-free docs, dependency audits, an installed
release-profile end-to-end clone on the current macOS host and an independent
Claude Opus final review returning `VERDICT: SHIP` after findings are resolved.

## Documentation changes

Update the README, getting-started tutorial, architecture, threat model,
capability matrix, recovery wording and walkthrough ledger. Add threat-model
rows for aggregate clone disclosure and the absence of an MCP clone tool.

Amend ADR 0003 as accepted only for the bounded portable clone subset. Record
these gates as deferred and unmet: clonefile/reflink equivalence, stable IDs for
schema-1 clones, stronger detached-process quiescence, snapshot, rollback,
template, export and their operation-specific crash/immutability/authentication
requirements. Reconcile the ADR's `dry-run` wording with the public `--preview`
name. Never describe clone as crash-consistent against detached writers.
