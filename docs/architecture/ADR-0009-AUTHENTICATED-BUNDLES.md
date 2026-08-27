# ADR 0009: Authenticated portable bundles

Status: accepted for the first export/import implementation

## Context

Quarters templates and snapshots are private store artifacts. They have a
canonical whole-tree digest, but that digest is stored beside the content and
does not authenticate a copy against an actor that can modify both. Users need
a portable backup and transfer format without treating a live-space copy as a
crash-consistent snapshot or adding a network service.

The portable format crosses a trust boundary. Its framing, paths, modes,
metadata and content are hostile until a separate key authenticates them. The
bundle is plaintext and can contain arbitrary credentials and executable shell
startup files.

## Decision

### Scope

Version 1 exports only an already verified named template or snapshot. It never
copies a live space. Import always creates a new schema-2 template and never a
rollback point. A snapshot exported on one host is therefore usable as a
creation source without claiming that its source identity authorizes rollback
on another host.

Export preserves the exact verified tree. It does not filter credentials,
because doing so would invalidate the canonical content record and would still
be unable to identify arbitrary secrets. Execution requires an exact artifact
name through `--confirm-sensitive-state`. Users who need a reduced bundle must
first create and inspect a deliberately reduced template.

MCP receives no key, export or import authority. Compression, encryption,
confinement, live freeze and remote transfer remain separate gates.

### Key contract

`export-key create PATH` writes exactly 32 unpredictable bytes. Creation uses a
retained parent descriptor, a private exclusive temporary, file and directory
sync, and no-clobber link publication. Reading requires a current-UID regular
file with one link, mode `0600`, exact length 32, no symbolic-link traversal and
stable metadata before and after the read.

Key paths and bytes never appear in human output, JSON, diagnostics or stored
bundle metadata. Key creation and consumption reject resolved paths inside the
active Quarters store, so a captured tree cannot embed the key that
authenticates its bundle. Keys travel out of band. Memory zeroization is not claimed.
The same-UID host authority can read a mounted key or bundle.

### Format and authentication

The file contains fixed magic and version, a strict JSON header no larger than
16 KiB, typed entry records, a terminal marker and a 32-byte keyed-BLAKE3 tag.
Distinct fixed domains separate key derivation, bundle authentication and
import-plan confirmation from artifact integrity and host-fork plans.

The tag covers every byte from magic through the terminal marker. The only
accepted content algorithm is
`blake3-256:quarters-canonical-v1`. BLAKE3 hash equality supplies the crate's
constant-time 32-byte comparison.

Records are byte-preserving and type-specific:

- directory: tag, relative path and ordinary mode;
- file: tag, relative path, ordinary mode, length and exact bytes;
- symbolic link: tag, relative path, target length and target bytes.

Symlinks have no portable mode. Special files and special mode bits are
rejected. Paths contain nonempty relative components and no NUL, empty, dot or
dot-dot component. A link target is relative and remains lexically beneath the
bundle root.

Order is the canonical recursive traversal. Sibling final components are
strictly byte-sorted at each depth; a record can descend only into the directory
just declared or pop to an ancestor. Whole paths are never compared as a sort
key. Every parent precedes its children and duplicates are rejected by strict
sibling order.

The unauthenticated stream must be parsed before its trailing tag is available.
Compile-time `CloneLimits::ALPHA` and the fixed header ceiling therefore govern
all parsing regardless of header claims. Canonical order is tracked with one
fallibly allocated active-directory stack bounded by maximum depth, rather than
retaining every hostile path. No foreign text is rendered before authentication,
and authenticated text is still bounded and escaped.

### Export transaction

Export retains the verified artifact descriptors. One sorted descriptor-
relative walk emits the stream and MAC while independently computing the exact
canonical tree digest. Every entry is checked before open, after open/read and
after emission. Publication aborts unless the computed record equals the stored
artifact integrity.

The destination is an absolute path outside the validated Quarters root. Its
retained current-UID parent cannot be group- or world-writable. A mode-`0600`
hidden temporary is streamed and synced, then linked to an absent final name.
The final path is never replaced. Cleanup verifies the retained temporary
identity before unlinking; an irreducible same-UID race prefers a retained
temporary over removing an unknown path. External temporaries are not managed
by `quarters recover`. Successful linking is the commit point. A later parent
sync or hidden-link cleanup failure returns the committed report with an
explicit warning, never an ordinary failure implying that the destination is
absent.

### Import transaction

Import opens one no-follow bundle descriptor and retains it throughout. Pass 1
strictly parses and authenticates the complete file under compile-time bounds,
rejects trailing bytes, and rechecks its filesystem generation. Preview returns
only authenticated bounded metadata and a plan digest binding the requested
template name, bundle generation, authenticated header/tag and local policy.

Execution repeats pass 1 and requires the exact digest. Pass 2 seeks the same
descriptor, reparses and re-authenticates every byte while extracting beneath a
private template staging descriptor. It never reopens the bundle path. The
staged canonical digest must equal the authenticated content record before a
schema-2 manifest is written and reopened through the normal 16-KiB manifest
gate.

Extraction uses descriptor-relative, no-follow, exclusive creation. Expected
raw child names and inodes are collected within the global entry budget and
checked with one bounded directory sweep when that directory completes. A
byte-distinct collision and a filesystem-normalized name have separate
diagnostics. Both fail without publication.

The final template rename is also a commit point. Failure to sync the artifact
root afterward is returned as a committed import with an explicit durability
warning; retrying cannot reinterpret the visible template as a failed
publication.

Schema 2 carries no local source binding. `source_identity` is absent and can
never match a local space, bind a legacy artifact, satisfy rollback filtering or
authorize source-sensitive work. Authenticated historical source data lives in
an `ImportedBundleProvenance` record, and inspection reports `external`.
Imported artifacts are valid only as templates with origin `imported-bundle`.

No whole-tree parse, MAC, hash, copy or extraction holds the management lock.
The lock is held only for bounded staging reservation and final revalidation and
publication.

## Security meaning

The MAC is symmetric and supplies no non-repudiation. It proves only that the
bytes match a bundle produced by a holder of the key. It says nothing about
whether content is safe to run. Replay is possible, but import creates only a
fresh named template and never overwrites. The bundle is not confidential,
encrypted, contained or protected from the real Unix account.

## Acceptance gates

- exact template and snapshot round trips into fresh external templates;
- bit flips, truncation, trailing data, wrong keys and malformed framing fail;
- traversal, duplicates, missing parents, special entries and escaping links
  publish nothing;
- source mutation during export and bundle mutation between import phases fail;
- case collision and filename normalization have distinct portable errors;
- key symlinks, links, modes, types and lengths fail without disclosure;
- another healthy space can acquire a lease during each whole-tree phase;
- old readers reject schema 2 before mutation;
- macOS installed-binary and Linux static-target gates pass;
- independent security review returns an explicit ship verdict.

## Consequences

Quarters gains a portable, authenticated backup and transfer primitive without
claiming live quiescence or confidentiality. The format deliberately starts
uncompressed so bounds, framing and content identity remain inspectable. Future
encryption can wrap an authenticated bundle only after ADR 0007's key and mount
gates are met.
