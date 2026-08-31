# Lifecycle artifacts and rollback implementation plan

Date: 2026-08-25
Status: approved for implementation by independent Claude Opus 5 review

Historical scope note: ADR 0010 later implements cooperative freeze and
immediate `--from-active` template capture without the deferred supervisor
handoff considered below. The newer design records `frozen-active` evidence
and does not claim that already-running or same-UID writers are quiescent.

## Outcome

Deliver the next coherent lifecycle slice after portable clone:

```text
quarters template create NAME --from SPACE [--include-cache] --preview
quarters template create NAME --from SPACE [--include-cache] --confirm-sensitive-state SPACE
quarters template list
quarters template show NAME
quarters template rename OLD NEW
quarters template use NAME DESTINATION [--shell PATH] --preview
quarters template use NAME DESTINATION [--shell PATH] --confirm-sensitive-state NAME
quarters template rm NAME --confirm NAME

quarters snapshot create SPACE NAME --preview
quarters snapshot create SPACE NAME --preview --exclude-cache
quarters snapshot create SPACE NAME --confirm-sensitive-state SPACE
quarters snapshot create SPACE NAME --confirm-sensitive-state SPACE --exclude-cache
quarters snapshot list [SPACE]
quarters snapshot show NAME
quarters snapshot verify NAME
quarters snapshot rename OLD NEW
quarters snapshot rm NAME --confirm NAME

quarters rollback SPACE SNAPSHOT --recovery-name NAME --preview
quarters rollback SPACE SNAPSHOT --recovery-name NAME --preview --exclude-recovery-cache
quarters rollback SPACE SNAPSHOT --recovery-name NAME \
  --confirm-space SPACE --confirm-replace-state SPACE
quarters rollback SPACE SNAPSHOT --recovery-name NAME \
  --confirm-space SPACE --confirm-replace-state SPACE --exclude-recovery-cache
```

Templates are named creation sources. Snapshots are named recovery points.
Rollback always preserves the target's space identity and first creates a
verified automatic recovery snapshot. All three operations reuse the bounded,
descriptor-relative portable-copy boundary accepted for clone.

This slice does not claim a crash-consistent filesystem snapshot, freeze
detached writers, provide a same-UID security boundary, rewrite embedded paths,
or preserve metadata that the clone backend already reports as unsupported.
Export, encryption, confinement, application capture, host forking and live
space rename/freeze remain separate gates.

## Command and confirmation contract

- `template`, `snapshot` and their verbs use noun-first command groups. Their
  JSON envelopes retain schema 1 and use stable commands such as
  `template.create` and `snapshot.verify`.
- Artifact names use the existing portable 1--32 character name grammar.
  Names are globally unique within their artifact kind and are display labels,
  not directory names.
- This slice deliberately exposes only `template create --from SPACE`.
  A supervised shell holds the shared activity lease that a safe artifact copy
  must upgrade to exclusive, so an unqualified `--current` invoked inside that
  shell would always fail. Current-context capture is deferred until a
  supervisor handoff or exit-time request protocol can release the caller's own
  lease without weakening writer-quiescence claims.
- Template and snapshot creation include arbitrary persistent state and may
  contain credentials. No heuristic scrub mode is claimed. Exact confirmation
  is mandatory for mutation. Derived caches are omitted for templates unless
  `--include-cache` is set and included for snapshots because recovery fidelity
  takes precedence over portability.
- Template instantiation requires exact template-name confirmation because a
  template may contain credentials. It creates a fresh space identity and
  creation timestamp. Snapshot rollback never adopts snapshot identity.
- Every mutating copy has a `--preview` form using the same bounded walk and
  result shape. Preview conflicts with confirmation flags and does not create
  directories, markers, snapshots or destinations. Rollback preview also checks
  recovery-name availability under its bounded management acquisition.
- Rollback requires `--confirm-space SPACE`, rejects a snapshot whose recorded
  source identity does not match the target, and reports the automatic recovery
  snapshot name supplied through required `--recovery-name`. Execution also
  requires `--confirm-replace-state SPACE`; the independent flag acknowledges
  complete replacement of the target home and creation of another
  credential-bearing artifact. A schema-2 identity is its random space ID. A schema-1
  transition identity is the tuple of schema, validated name and creation time;
  live space rename remains unavailable for that reason.
- Human and JSON output always disclose cooperative-only activity evidence,
  unknown detached writers, included sensitive state, unsupported metadata and
  unchanged host authority.
- `template rm` and `snapshot rm` require exact artifact-name confirmation,
  rename the validated opaque-ID directory to a generated reclaiming entry
  under the same kind root while holding the management lock, then delete it
  outside that lock. `quarters rm SPACE` neither deletes nor is blocked by
  artifacts from that space. Such artifacts remain usable records and are
  reported as `source_status: orphaned` when their source identity no longer
  resolves.
- `quarters rm SPACE` never cascades, but its human and JSON result reports the
  count of surviving templates and snapshots matching the removed identity and
  points to their separate confirmed removal commands.

## Store format

Existing `spaces` and `trash` remain authoritative. New older-reader-opaque
roots are additive and private:

```text
~/.quarters/
  .templates/<artifact-id>/
    .quarters-artifact.json
    home/
  .snapshots/<artifact-id>/
    .quarters-artifact.json
    home/
```

An artifact ID is 128 random bits rendered as 32 lowercase hexadecimal
characters. Directory entries use only IDs generated and parsed by Quarters;
artifact names never participate in path construction. Adding new hidden root
siblings does not change the authoritative `spaces`/`trash` layout and does not
activate the ADR 0006 migration. Existing binaries ignore these siblings.

Artifact roots and entries are current-UID directories at mode 0700. Manifests
are regular single-link files at mode 0600 with a 16 KiB read limit, a
permissive schema header followed by strict schema-1 deserialization, and these
logical fields:

```text
schema_version
artifact_id
kind                 template | snapshot
name
created_unix_ms
source_identity      schema, name, creation time, optional stable ID
source_layout
source_platform
default_shell
include_cache
includes_sensitive_state
origin                user | automatic-rollback-recovery
content_integrity    algorithm, digest, counts
```

Opening an artifact requires its generated directory component to parse as the
same ID stored in `manifest.artifact_id`; moving a complete artifact under a
different ID is corrupt state even if its content digest still matches.

The content algorithm is `blake3-256:quarters-canonical-v1`: BLAKE3-256 over a
canonical record stream initialized with `blake3::Hasher::new_derive_key` and
the exact context string
`org.agenxy.quarters.artifact.quarters-canonical-v1`. It is not a per-file
Merkle structure and supports neither partial nor incremental verification.
Version 1 has this byte grammar:

```text
root       = 0x52, mode:u32be
directory  = 0x44, path_len:u64be, path:path_len, mode:u32be
file       = 0x46, path_len:u64be, path:path_len, mode:u32be,
             content_len:u64be, content:content_len
symlink    = 0x4c, path_len:u64be, path:path_len,
             target_len:u64be, target:target_len
terminal   = 0x00, entries:u64be, directories:u64be, files:u64be,
             symlinks:u64be, logical_bytes:u64be
stream     = root, record*, terminal
```

`path` is the raw Unix byte representation of the non-empty relative path,
whose components are separated by `/`; Unix entry names cannot contain `/`.
Traversal is depth-first pre-order, with each directory's immediate children
sorted by raw byte order of the single name component. Mode is masked to
ordinary `0o777` permission bits. The digest binds root and entry modes, paths,
types, regular-file bytes and symlink target bytes, except that symlink modes
are neither preserved nor bound. It does not bind ownership, timestamps,
extended attributes, ACLs, filesystem flags, symlink permission bits, hard-link
topology, sparse layout or the artifact manifest.

Terminal fields come from a dedicated `ArtifactCounts`, never from clone's
`CloneCounts.entries` (which includes examined exclusions). For the stored tree,
`entries` equals directories + files + symlinks and excludes the root,
`directories` excludes the root, `logical_bytes` is regular-file content bytes
plus symlink-target bytes, and no excluded source entry contributes to any
terminal count. JSON presents `examined_counts` and `stored_counts` as distinct
objects so their semantics cannot be confused.
This distinction is scoped to `template.*`, `snapshot.*` and `rollback` result
types. Existing clone JSON retains its stable `counts` and `exclusions` keys and
their fixtures unchanged; `metadata_not_preserved` gains the declared symlink-
permission entry.

Integrity uses two explicit walker modes. Creation-source mode retains clone's
safe source policy: sockets, FIFOs, devices and foreign-owned entries are
omitted and counted; multiply-linked regular files are copied independently and
counted; unclassifiable entries and unsafe links fail closed. Its digest visitor
sees only records actually stored in the artifact. Published-verification mode
is strict: any special, foreign-owned, unclassifiable or multiply-linked regular
entry inside artifact `home/` is a hard error because creation can never publish
one. A source directory whose owner permission bits lack either read or
traverse access is also rejected at artifact creation with one bounded escaped
relative path and a concrete permission hint. Artifact sources are therefore
slightly narrower than clone sources only for empty read-only directories such
as mode 0400 or 0600; their special/foreign/hard-link policy otherwise matches
clone. Non-empty inaccessible directories already fail clone's descriptor walk.
The preflight converts those cases into one stable early error and guarantees
every accepted artifact remains traversable by later verification without
permission mutation. Both modes compare pre-open, opened and post-read metadata so a
concurrent change aborts. This is a shared lifecycle-walker hardening, so clone
also gains the narrower post-read regular-file and directory race check; ADR
0003 and hostile mutation fixtures record that accepted-behavior change.
Verification requires both digest and all terminal
counts to equal the manifest. Unknown algorithm names fail closed. The digest
detects accidental or out-of-band modification but is not authentication
against another process with the same account authority; the manifest and
content share that authority.

Renaming an artifact atomically replaces only its validated private manifest
while holding the management lock. Replacement writes a generated private
`.manifest-<artifact-id>.tmp` file in the artifact directory, syncs it, renames
it over the manifest and syncs the directory. A stray exact-form manifest temp
is reported by doctor and recoverable; other hidden entries fail closed. The
physical artifact ID and content digest do not change. Name uniqueness is
rechecked under that lock.

Artifact enumeration is capped at 4,096 entries per kind and uses a bounded
manifest-index build outside the management lock followed by an identity recheck
inside it. It ignores only exact reserved staging/transaction forms and returns unhealthy entries rather than
letting one corrupt artifact hide its healthy siblings. Name lookup fails
closed on duplicate manifest names.

## Artifact creation transaction

Template and snapshot creation share `store/artifact` modules for identity,
manifest parsing, inspection, integrity and publication.

1. Resolve and validate the source space and artifact name. For preview, do not
   create the store or artifact roots.
2. The outer lifecycle coordinator acquires the global management token,
   validates the source controls, acquires a bounded exclusive lifecycle token,
   checks artifact-name uniqueness, and reserves a generated artifact ID.
3. For execution, create a private same-filesystem
   `.creating-<artifact-id>` directory under the final artifact root with a held
   private creation lock. Release the management lock while retaining the
   source activity lease.
4. Run the descriptor-relative lifecycle copy into `home/` in artifact
   creation-source mode. It reports the same special, foreign-owned and
   independently materialized hard-link aggregate counts as clone. Artifact cache
   exclusion means omission: unlike clone, it does not create empty cache
   placeholders inside the stored `home/`. The same fixed alpha limits apply. A digest visitor
   receives canonical metadata from source `fstat` and hashes the exact buffers
   successfully written by the copy, before bottom-up directory-mode changes;
   creation never depends on reopening a now-restricted destination directory.
5. Finalize that creation digest, write the strict artifact manifest, sync files
   and directories, then independently verify both manifest and digest from the
   staging root. The source owner-mode precondition guarantees every accepted
   artifact is verifiable after publication.
6. Reacquire the management lock, revalidate the source manifest and artifact
   name uniqueness, remove the staging creation lock, sync staging, revalidate
   its controls, then rename staging to `<artifact-id>` and sync the artifact
   root. A fault point covers the interval after lock removal and before rename.
   Cleanup before publication is bounded and recoverable. Recovery treats an
   artifact staging directory with a free or absent creation lock as stale.

Artifact recovery extends `quarters doctor` and `quarters recover` to classify
and reclaim only private, generated `.creating-<artifact-id>` directories with
free creation locks, `.reclaiming-<artifact-id>` directories, and exact stray
manifest temps. Additive schema-1 recovery-summary fields report active and
stale artifact creations, reclaiming artifacts, manifest temps, rollback
transactions and orphaned artifacts. Unknown hidden entries fail closed and
remain reported but do not block recovery of valid unrelated space, trash or
artifact candidates. Here "fail closed" means never remove and report as
unknown. An entry matching an exact reserved generated form but failing its
owner/type/mode/link validation remains a hard recovery error.

The reserved namespace is explicit and closed:

| parent | form | purpose |
|---|---|---|
| store root | `.observe`, `spaces`, `trash`, `.templates`, `.snapshots` | coordination and category roots |
| `spaces` | `.creating-<space-name>-<pid>-<epoch-ms>-<counter>` | existing create/clone staging |
| `spaces` | `.rollback-<32-hex>.json` | rollback marker |
| `spaces` | `.rollback-staging-<32-hex>` | locked rollback staging |
| `spaces` | `.rolled-back-<32-hex>` | retired rollback target |
| `trash` | `.retired-<pid>-<epoch-ms>-<counter>` | existing remove retirement |
| `trash` | `.reclaiming-<pid>-<epoch-ms>-<counter>` | deletion outside management lock |
| artifact kind root | `<32-hex>` | published artifact |
| artifact kind root | `.creating-<32-hex>` | locked artifact staging |
| artifact kind root | `.reclaiming-<32-hex>` | artifact deletion |
| artifact directory | `.quarters-artifact.json`, `home`, transient `.manifest-<32-hex>.tmp` | published controls, content and atomic rename temp |
| artifact staging | `.creating.lock`, `.quarters-artifact.json`, `home` | active lock, pending controls and content |

Unknown hidden entries have a saturating `unknown_entries_at_least` count and
are never included in a hard candidate budget. Each exact known family has its
own 1,024-candidate limit. Exceeding one family prevents mutation of that family
but recovery still processes unrelated families before returning the bounded
resource-limit diagnostic.

The fixed budget families are: space creation; rollback marker; rollback
staging; rolled-back target; trash retirement; trash reclaiming; template
creation; template reclaiming; snapshot creation; snapshot reclaiming; and
published-artifact manifest temp. Increasing or combining that set requires an
on-disk recovery-contract change.

This slice splits trash retirement and trash reclaiming into independent
1,024-entry families. The recovery-contract expansion is recorded in the new
ADR and tested at each independent cap.

This slice does not tighten the existing prefix-compatible recognition of
legacy `spaces/.creating-*`, `trash/.retired-*` and `trash/.reclaiming-*`
entries. Private owner/mode/type checks and the creation lock remain the
compatibility classifier for nonconforming entries created by an older build.
New writers emit the exact grammars above. Contracting legacy recognition needs
its own support-window decision and cannot silently turn old staging into
unknown state.

`ManagementGuard` and `LifecycleLease` are explicit non-cloneable ownership
tokens. Public Store methods acquire them only at the outer boundary; internal
artifact, snapshot and rollback helpers borrow a `LifecycleContext` containing
the already-held tokens and never open or lock the same file again. The
management token may be deliberately dropped during a long copy and reacquired
by the outer coordinator, while the lifecycle lease remains held. Tests make
self-contention observable by asserting rollback never maps its own locks to
`space_active` or management `resource_limit` errors.

Code holding a `LifecycleContext` must not call `lease_state`, `lease_states` or
`Store::lease`, because management and observation currently share `.observe`
and the transaction already owns the source lease. The context exposes those
known facts directly. Lifecycle results must never report `unknown` or `held`
for the lease the transaction itself owns.

## Template instantiation

Instantiation opens the selected template and captures its bounded manifest and
directory identity under the management lock, then releases that token before
any whole-tree digest or copy. It verifies the content digest, creates a standard
private staging space, and copies from the immutable-by-interface artifact.
The copy includes every entry already present in the artifact; cache exclusion
is not re-applied.

The destination controls are generated exactly like clone: the template's
source schema/layout/default shell are validated, the destination has a fresh
creation time and schema-2 ID, `.active` is fresh, and provenance records the
template artifact ID and name without recording user content. Publication uses
the existing single-rename space transaction. The template digest is reverified
before reacquiring management; publication then rechecks only captured manifest
bytes and directory identity, so no whole-tree hash holds the global token.

Artifacts record the creating platform. Template use reapplies the destination
platform's exact create-time directory skeleton for the recorded layout. A
profile gets only the private-directory set; a workspace additionally gets the
portable and platform workspace sets. Platform cache roots are not invented for
a layout whose `quarters create` path does not create them. A no-follow
create-if-absent helper validates any existing directory's owner and type
without requiring or changing its copied mode, and creates only missing
components at 0700. These consumer-created empty roots are not part of the
artifact digest.
The stored default shell must validate on the destination host or the user must
provide `--shell PATH`; failure has a dedicated cross-platform hint. Human and
JSON output identify cross-platform adaptation. Schema-1 template use creates
no random stable ID and says explicitly that its fresh transition identity is
only the schema/name/creation-time tuple.

## Snapshot and rollback semantics

A snapshot is immutable through the Quarters command surface except for
explicit rename and confirmed whole-artifact removal. No digest-bound mode is
mutated after finalization. Filesystem immutability flags remain optional future
hardening because flags are deliberately outside the digest; this slice does
not claim or apply them. All reads, instantiation and rollback still verify the
canonical digest, and this slice does not expose snapshot content mutation. User and automatic-recovery origin
are stored explicitly and exposed by list/show; origin is never inferred from
the display name. Snapshot creation includes caches by default for recovery
fidelity and accepts `--exclude-cache`; preview reports cache entry and byte
counts separately. Cache-inclusive walks retain the accepted 100,000-entry,
10-GiB and per-file limits. A limit error explicitly suggests
`--exclude-cache` for `snapshot create` and `--exclude-recovery-cache` for
rollback; no limit is silently raised. Automatic rollback recovery is
cache-inclusive by default and therefore can safely refuse a rollback before
replacement. `--exclude-recovery-cache` is an explicit escape hatch whose
preview and output state that restoration remains complete for included
persistent state but not for derived cache contents. When the selected snapshot
was created with `--exclude-cache`, rollback
reapplies the target layout's guaranteed empty cache-root skeleton after copying
the verified artifact; those empty consumer roots are outside the snapshot
digest.

Rollback stages a complete replacement; recursive merge and in-place overwrite
are forbidden:

1. Preview validates target identity, obtains the target lifecycle lease,
   verifies the selected snapshot and performs a bounded walk of both the
   snapshot and current target. It reports the required `--recovery-name`, the
   credential-bearing recovery artifact and replacement policy but creates no
   recovery point.
2. Execution acquires and retains the target's exclusive lifecycle lease. It
   creates and verifies an automatic full-state snapshot using the required
   `--recovery-name` while reusing that already-held lease.
3. Copy the requested snapshot into a private staging space. Generate controls
   from the current target manifest, preserving name, schema, creation time and
   stable ID. Write rollback provenance and verify the staging tree and selected
   snapshot digest before reacquiring the management token. The generated
   `.rollback-staging-<transaction-id>` holds a private creation lock for its
   entire pre-publication lifetime, including the interval before a marker
   exists. After the retire rename and durable `retired` marker state, the
   management token remains held while Quarters removes and syncs the staging
   creation lock, revalidates staging controls, and performs the publish rename.
   Under any valid marker, marker state governs; a missing staging lock is never
   interpreted as generic staleness.
4. Write and sync a strict private `.rollback-<transaction-id>.json` marker
   under `spaces` in `prepared` state, recording generated staging and retired
   entry names, target identity, selected snapshot ID and recovery snapshot ID.
   Reacquire the management lock and retain it continuously for this ordered
   sequence: bounded identity revalidation; retire rename + parent sync; atomic
   `retired` marker write + sync; staging-lock removal + staging sync; staging
   control revalidation; publish rename + parent sync; atomic `published` marker
   write + sync. No tree digest or copy runs under this token. Every delimiter in
   that sequence has an injected fault point.
5. Only after publication may the retired tree be reclaimed. The automatic
   recovery snapshot remains available.

The exclusive lifecycle lease remains attached to the old `.active` inode when
that tree becomes `.rolled-back-<transaction-id>`; the staged target contains a
fresh validated `.active`. The continuously held management token prevents a
new supervisor from interleaving across that inode handoff. After `published`
is durable and cleanup state is classified, Quarters releases the old lease and
then the management token. A new supervisor must be able to lease the published
target immediately afterward.

Portable rollback is a deliberate three-state transition, not an atomic
old-or-new swap: observers may see the old target, the new target, or a marked
in-progress replacement. Read paths that encounter an absent target plus an
exact validated rollback marker return `space_active` with a rollback-specific
hint rather than a misleading `not_found`. Quarters does not use divergent
`RENAME_EXCHANGE`/`RENAME_SWAP` primitives.

Marker awareness covers every named and enumerating surface. `list`, unfiltered
`status` and MCP status emit one stable `rollback_in_progress` entry for the
marked name. `create`, `clone`, template use, `Store::remove`/`retire_space`,
`rm`, `current`, `status NAME`, `doctor NAME`, MCP named status, `enter`, `exec`,
`env` and every other mutation or named read fail with the rollback-specific
`space_active` result rather than `not_found` or `already_exists`. Marker target
names are parsed again through `SpaceName` before output. Marker discovery is a
bounded scan of at most 1,024 exact-form rollback markers; exceeding it fails the
specific named/enumeration request with a resource-limit error and does not
consume the caller's `inspect_at_most` healthy-space budget.

This does not add a variant to the published `SpaceInspection` enum. A separate
non-breaking `RollbackObservation` collection is merged by CLI and MCP status
presentation; `Store::list()` retains its existing healthy-space contract.

Recovery derives no arbitrary paths from a marker. It accepts only generated
components and exact validated identities. Marker state has three exact values:
`prepared`, `retired` and `published`. The state selects its allowed filesystem
tuples; the observed tuple must agree or recovery reports corrupt state and does
not guess:

- `prepared`: target present + staging present + retired absent aborts by
  retiring staging; target absent + staging present + retired present means the
  retire rename completed before the state write and restores retired first
- `retired`: target absent + staging present + retired present restores retired
  and retires staging; target present + staging absent + retired present means
  publication completed before the state write and advances to `published`
- `published`: target present + staging absent, with retired either present or
  already moved to trash, retains the new target and finishes reclamation
- every other tuple is corrupt state and remains untouched

Marker writes are atomic private-file replacements with parent syncs. Test-only
fault points cover each marker write, rename and parent sync. A failure after
publication says the new complete target may be live and directs the user to
`doctor` before retrying.

Before confirmed recovery acts, doctor reports each rollback target, marker
state and deterministic action (`abort`, `restore-old` or `complete-new`) in
human and JSON output. The generic `--confirm stale-state` token is never the
only disclosure for a whole-home recovery decision.

After `published` is durable, the retired tree is renamed under the management
token to a generated `trash/.reclaiming-<suffix>` entry. The marker is then
removed and the spaces parent synced before releasing the token; recursive
deletion occurs outside it. A crash after the trash rename but before marker
removal is the allowed `published` tuple with retired absent. Recovery finishes
the existing trash candidate and removes the marker only after validating that
the new target remains complete.

Exact generated reserved forms are `.rollback-<32-hex>.json`,
`.rollback-staging-<32-hex>` and `.rolled-back-<32-hex>`. Recovery validates
marker schema, owner, mode, link count, target identity and generated components
before applying the tuple. Doctor and recovery count all three forms; recovery
summary changes are additive within the existing JSON envelope schema.

A rollback staging directory with a held private creation lock is active and
never touched. With a free lock and no marker, it is an abandoned pre-marker
staging tree and is retired through the normal reclaiming path. With a marker,
the validated marker state and filesystem tuple govern. Fault injection covers
the interval after staging verification and before marker publication, plus
lock removal immediately before the publish rename.

Rollback requires the snapshot's recorded source platform to equal the current
host platform. A mismatch fails with a dedicated unsupported/cross-platform
hint; cross-platform template use remains the portable adaptation path.

## Security and correctness boundaries

- Quarters continues to run as the real UID/GID. Another process with that
  authority can read or change artifact content, manifests and locks. Digest
  verification is integrity evidence, not a same-account trust boundary.
- Cooperative leases cannot discover detached processes. Snapshots and rollback
  are therefore point-in-time portable copies only relative to cooperating
  Quarters supervisors. Output never calls them crash-consistent.
- Every artifact path traversal is descriptor-relative and no-follow. Absolute
  and escaping symlinks fail closed. Aggregate results disclose no home paths;
  one bounded escaped relative path may appear in an actionable error.
- Rollback retains the target identity so runtime state and current-space
  claims do not silently select a different logical Quarter. Embedded paths in
  restored files are not rewritten.
- BLAKE3 is pinned exactly at the newest stable version verified at plan-review
  time, 2026-08-25: `blake3 = "=1.8.7"`. A temporary exact-pin resolution
  confirmed `arrayvec 0.7.8`, `cfg-if 1.0.4`, `constant_time_eq 0.4.2`,
  `cc 1.4.4`, `find-msvc-tools 0.1.11` and `shlex 2.0.1`; target-specific
  resolution adds only dependencies with currently accepted Apache/MIT license
  alternatives. The current `deny.toml` allowlist accepts that dependency graph
  without a new license exception. Default features and their `cc` build
  dependency are accepted because the upstream platform-optimized native
  implementation is open, Apache-compatible and materially improves repeated
  multi-gigabyte verification. The static x86_64 Linux musl publication job is
  an explicit acceptance gate; upstream's `pure` feature is the documented
  fallback only if the optimized build cannot pass that target. Dependency and
  license audits remain mandatory.
- The optimized BLAKE3 build makes a working C compiler and assembler an
  explicit source-install prerequisite. README source-install instructions say
  so and point users without that toolchain to prebuilt Homebrew, npm and PyPI
  packages. Performance remains the default; the `pure` fallback is not silently
  selected per host.
- MCP gains no template, snapshot, artifact-removal or rollback tools in this
  slice. Its current create/status/doctor authority does not expand.
- Alpha.3 and older binaries do not understand rollback markers. During normal
  operation the continuously held management lock leaves no interleaving window
  between retire and publish, even for those binaries because they share
  `.observe`. After a crash in the target-absent window, an older binary can see
  the name as absent and create a new space before a new build recovers. Recovery
  validates the unexpected target identity, preserves every tree and reports a
  conflict rather than guessing or overwriting. The new ADR, threat model and
  compatibility matrix record this crash-to-recovery compatibility exposure;
  automatic resolution remains unavailable until marker-aware readers meet a
  declared minimum-version window.
- MCP models rollback observation with an optional `state` field whose value is
  `rollback_in_progress`; its `health` uses the existing `unhealthy` value and
  its issue uses the existing `space_active` error shape. Existing healthy entry
  responses omit `state` and remain byte-identical in 2025-family fixtures.

## Tests and acceptance

Core tests must cover:

- artifact ID parsing/generation, manifest schema/version/size/mode/link checks,
  corrupt and duplicate names, the 4,096-entry cap, and unknown reserved entries
- deterministic tree digests independent of directory iteration order; digest
  changes for bytes, path, type, mode and symlink target; mutation/race failure
- template preview/execute count parity, cache policy, exact source recheck,
  rename without physical movement, explicit `--from` behavior, and
  fresh identities on use
- cache omission creates no placeholder records in artifacts; template use and
  cache-excluded rollback reapply only guaranteed empty destination skeletons
- snapshot preview/execute parity, full-state cache inclusion, source identity,
  verification before every consuming operation, and immutable-by-interface
  behavior
- successful independent verification immediately after artifact publication
  and again after manifest-only rename, proving digest-bound modes did not move
- snapshot list filtering by the full identity of a currently resolved space,
  with stale-name/new-identity artifacts excluded or marked predictably before
  rollback
- rollback mismatch refusal, target identity retention, verified automatic
  recovery snapshot, the documented old/new/marked-in-progress visibility, every injected fault tuple,
  and idempotent recovery
- rollback platform-mismatch refusal and preview-time recovery-name collision
  refusal before a mutating lease is retained
- artifact deletion, interrupted deletion recovery, the per-kind cap remaining
  reclaimable, orphan status after space deletion/recreation, and no implicit
  cascade from `quarters rm`
- strict digest rejection of added sockets, FIFOs, devices, foreign-owned,
  unclassifiable and multiply-linked entries; unknown algorithm refusal; exact
  manifest count comparison
- creation-source fixtures prove a socket is omitted and one `nlink == 2` source
  file is materialized independently with aggregate disclosure, after which the
  published artifact verifies successfully
- artifact-creation refusal for source directories at modes 0000, 0300 and
  0400 with exact error kind and permission hint, plus the invariant that every
  accepted created artifact immediately passes independent verification
- no self-contention during nested rollback snapshot creation and rollback-aware
  `space_active` errors during the target-absent publication window
- adversarial symlink/hard-link/sparse/socket/FIFO/permission/limit fixtures and
  concurrent create/remove/launch/lifecycle stress
- no absolute paths or file content in human/JSON result data and stable JSON
  fixtures for every command
- clone and artifact metadata disclosures explicitly list symbolic-link
  permission bits as not preserved
- continuous management-token ownership across both rollback renames and syncs,
  plus rollback-in-progress behavior on named, enumerating, human and MCP status
  surfaces
- lifecycle-lease handoff proving the freshly published target can be leased as
  soon as `published` is durable and the old retired-inode lease is released
- an unrelated space successfully acquiring a supervisor lease throughout a
  large rollback, proving no whole-tree hash or copy holds the management token

Acceptance requires formatting, warnings-as-errors linting, every Rust and npm
test, structural ceilings, documentation checks, dependency/license/advisory
audits, release-installed macOS end-to-end scenarios, Linux CI, and an
independent final Claude Opus 5 `VERDICT: SHIP` after all findings are resolved.

CI gains a mandatory x86_64-unknown-linux-musl build and target test on every
change, not only release dispatch. Its dependency-policy job runs full
`cargo deny check`, including bans, licenses, advisories and sources. `deny.toml`
adds an explicit bans policy matching the currently accepted warning for
duplicate compatible dependency majors and denying wildcard requirements.
`cargo audit --deny warnings` remains deliberately independent defense in depth
rather than being retired. The release musl job remains a second acceptance
path.

There is no automatic artifact retention policy in this alpha. Template and
snapshot list plus doctor report aggregate logical bytes per kind so users can
make informed confirmed-removal decisions before either the 4,096-item catalog
cap or storage capacity becomes a surprise.

Before implementation, add an accepted ADR for the artifact format, explicit
lock-token ownership, three-state rollback and recovery forms. Amend ADR 0003's
Decision steps 4--5 to define creation-source and published-verification walker
modes plus their per-operation policy, then amend its accepted/deferred section.
Reserve `.templates`/`.snapshots` as additive known root children in ADR 0006. Update the threat model for unauthenticated
same-UID integrity, duplicate credential state, three-state rollback and the
explicit absence of MCP lifecycle authority.

ADR 0006's status gate is narrowed to the authoritative `spaces` to `.spaces`
and `trash` to `.trash` migration. Additive `.templates`/`.snapshots` are never
evidence of that future root format and do not participate in its dual-layout
ambiguity check.

Before marker logic grows the store, move `store.rs`'s inline tests to
`store/tests.rs`; artifact output lives in `output/artifacts.rs`. The separate
rollback-observation type avoids a breaking `SpaceInspection` variant. The
additive MCP status health/state fields receive exact compatibility fixtures.
Replace `print_doctor`'s seven positional parameters with a `DoctorReport`
value before adding artifact aggregates. The rollback state/tuple matcher is
split into small state-specific functions and must pass the existing complexity
16, nesting 8 and parameter 8 ceilings without exemptions.

Documentation updates include `ARCHITECTURE.md`'s clone-only lifecycle section
and `docs/compatibility/MATRIX.md`'s lifecycle rows, as well as README,
getting-started, ADRs and the threat model. The resulting docs distinguish
creation-source omissions from published-artifact verification failures.

## Explicitly deferred

- Live space rename until stable identity is universal under ADR 0006.
- Live `template create --current` until a supervisor handoff or exit-time
  capture protocol can release the invoking Quarter's own shared lease.
- Live freeze until Quarters can distinguish a launch-policy marker from an
  enforceable write boundary; snapshots do not imply frozen writers.
- Export/import until authenticated manifests, archive extraction limits and
  credential-default policy have their own threat review.
- Encrypted volumes and stronger confinement until native platform backends can
  state exactly which external reads and writes they prevent.
- Clonefile/reflink acceleration until semantic-equivalence fixtures pass on
  both supported operating systems.
