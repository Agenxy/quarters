# Alpha 4 through Alpha 6 implementation plan

Status: revised after independent Claude Opus 5 maximum-effort review on
2026-08-31. This plan is executable only after the reviewer accepts the
decisions and gates below.

## Outcome

Quarters will advance the capabilities it can support honestly and fail closed
for the ones it cannot. The next releases prioritize distribution correctness,
explicit Linux data grants, privacy-bounded compatibility discovery, and a safe
hidden layout for new stores. They do not claim same-UID containment,
guaranteed online encryption locks, or a supported macOS filesystem sandbox
that the available platform mechanisms cannot provide.

The accepted Alpha 4 source checkpoint was merged to `main` through pull
request 6 at commit `7443a16`. No tag or registry publication occurred. The
static-musl job is now a required `main` check because it caught a real
headless-terminal regression that the other required jobs missed.

## Release 1: complete Alpha 4 distribution

Before creating an Alpha 4 tag:

1. Add a native `quarters-cli-linux-arm64` npm package built on GitHub's public
   `ubuntu-24.04-arm` runner for `aarch64-unknown-linux-musl`.
2. Add that package to the typed launcher map and optional dependencies, with
   Bun-managed launcher tests for target selection and missing-package errors.
3. Correct documentation that attributed the missing target to npm rather than
   to Quarters' incomplete matrix.
4. Correct the dotted-store mutation error before publication. Alpha 4 must not
   promise a future migration-capable release that this plan does not schedule.
5. Add a native `aarch64-unknown-linux-gnu` PyPI wheel on
   `ubuntu-24.04-arm`, retaining Linux x86_64 and both macOS wheels.
6. Keep registry publishing and artifact construction separate. Every native
   archive and wheel is smoke-tested before any publish job can run.
7. Bootstrap the new npm native package interactively once, configure trusted
   publishing for all five npm packages, then revoke the bootstrap session.
8. Configure the PyPI pending trusted publisher and let the official workflow
   create `quarters` on first publish.
9. Publish native packages before the launcher. Move the npm `latest` tag to
   the accepted Alpha 4 launcher version so a bare install cannot remain on
   Alpha 2.
10. Verify clean installs outside the repository on macOS arm64/x86_64 and Linux
   arm64/x86_64. Test npm `@alpha`, bare npm, and PyPI installation; each must
   run `quarters --version` and an isolated create/exec round trip.

Registry credentials, one-time passwords, and account responses are never
written to repository files, logs, review records, or Quarters state.

## Release 2: explicit Linux host-path grants

`enter`, `exec`, and `env` gain repeatable, invocation-local grants:

```text
--grant-path <ABSOLUTE_PATH>:<ro|rw>
--workdir <ABSOLUTE_PATH>
```

The command line is the sole authority. Grants are not accepted from the
environment and are not persisted in a space manifest. The JSON plan records
canonical path, requested access, `source: "user-granted"`, and
`required: true` before enforcement.

`--grant-path` is Linux-only and fails with `Unsupported` and exit code 6 on
macOS, whether or not filesystem confinement was also requested. It is never
accepted as an inert cross-platform option. `--workdir` is portable baseline
process behavior: it selects the initial directory without claiming to grant
access. Under Linux filesystem confinement, an external workdir must lie
within a user grant. Under macOS, requesting filesystem confinement still
fails with exit code 6. Acceptance tests pin every combination.

User grants use a data-only access class. They can never make a workspace an
executable search root. Executable resolution remains limited to the Quarter
home and existing reviewed system executable grants. Under Linux filesystem
confinement, a working directory must be the Quarter home or lie within an
explicit data grant.

Every grant is canonicalized, recorded by device and inode, reopened and
identity-matched, then held by that descriptor until Landlock is enforced.
Quarters rejects overlapping or nested user grants, because Landlock combines
rules by union rather than using a narrower rule to subtract authority. It also
rejects grants that overlap:

- the Quarters store;
- the passwd user's SSH or GnuPG credential roots, independent of inherited
  `HOME`;
- the running Quarters executable;
- another reserved Quarters runtime or management path;
- a path hidden beneath the optional home-view bind mount.

The plan reports that granted host paths are exposed to the confined tree and
that Quarters does not inspect their content. It also probes and reports Linux
`dev.tty.legacy_tiocsti` because Landlock ABI 3 does not mediate terminal
ioctls.

Required evidence includes real Landlock enforcement on Ubuntu, writable and
read-only positive cases, an ungranted sibling denial, executable-resolution
refusal from a granted workspace, disjointness failures, home-view composition
refusal, JSON stability, and Linux-target warnings-as-errors checks.

CI gains a second Ubuntu path that leaves
`kernel.apparmor_restrict_unprivileged_userns` at the distribution default and
proves the optional home view reports unavailable and fails closed when
requested. The existing job continues to prove the mount-capable path.

Idmapped mounts are not part of this design. They remap ownership, while
Quarters deliberately preserves the real UID and GID; an identity mapping adds
no isolation property.

## Release 3: storage-contract cleanup and hidden-layout gate

Alpha 4 through Alpha 6 continue creating visible `spaces` and `trash` inside
the already-hidden `.quarters` root. They read both layouts but mutate only the
visible layout. Quarters will neither physically rename an existing store nor
create a fresh dotted store while Alpha 1 and Alpha 2 binaries can ignore the
marker and create a conflicting visible layout.

The same old-reader hazard applies to both migration and a fresh dotted store:
an old binary creates `spaces`, after which the new reader sees an ambiguous
dual layout and fails. There is no safe automatic repair if the old binary
wrote real state. Cosmetic hidden names do not justify that risk.

This is an expand-only compatibility decision:

- new readers understand both formats;
- old readers continue to operate on existing visible stores;
- no detached process loses an absolute `HOME` path beneath a renamed tree;
- no crash-recovery transaction is introduced solely for cosmetic names inside
  an already-hidden `.quarters` root.

Creating dotted stores or physically migrating existing stores may be
reconsidered only after a documented support window in which every supported
reader recognizes the root marker and Quarters can prevent unsupported readers
from mutating the store. Until then there is no `migrate` command and no claim
that a store was converted.

The unused `.quarters-store-migration.json` denial path is removed before first
publication, so a same-UID process cannot plant a reserved marker that no
command can clear. Its unreleased serialized `doctor --json`/MCP field and
`active-migration` state are removed at the same time. No released Quarters
version emitted them. ADR 0006 records that any future physical migration must
first publish a newer root-marker schema and must not reuse the retired
sidecar name. Alpha 4 through Alpha 6 are explicitly dotted readers, not dotted
writers.

## macOS confinement decision

The supported filesystem confinement backend remains `none` on macOS. The
project will not use deprecated/private Seatbelt policy as a product foundation
or present App Sandbox, Endpoint Security, or FSKit as CLI capabilities.

Apple's supported mechanisms require a separately signed and notarized app or
extension; some require restricted entitlements and external approval. App
Sandbox also does not express Quarters' arbitrary absolute-path policy for a
standalone native shell tree. Those facts are recorded as research outcomes,
not placeholders for a weaker implementation.

Acceptance tests will pin `enter`, `exec`, and `env` with requested filesystem
confinement to a stable unsupported error and exit code 6 on macOS. Capability
and compatibility documentation will state the exact boundary.

## Encryption decision

Quarters will not ship a feature named `encrypted-at-rest spaces` in this
series. Linux fscrypt is filesystem-specific, may require prior administrator
filesystem configuration, and cannot guarantee that per-file keys for open
files are removed. It also does not protect an unlocked space from another
process with the same UID. macOS exposes no public native API for the disk-image
or APFS encrypted-volume lifecycle required by a Rust CLI under the project's
no-shellout constraint.

Documentation will distinguish host full-disk encryption from per-space
containment and will not imply that FileVault, LUKS, or fscrypt protects an
unlocked Quarter from same-UID applications. A future Linux-only fscrypt
integration would require a weaker, exact capability name, filesystem probes,
busy-key reporting, user-admin prerequisites, and a separate threat model and
ADR before code is written.

## Privacy-bounded application-state discovery

The first discovery feature is opt-in, per invocation, CLI-focused, and a test
instrument. It never records raw host paths or file contents. Results contain
bounded counts and classifications such as configuration, cache, credential
shaped, runtime socket, or unknown host-state access.

On Linux, Quarters will research Landlock audit evidence on kernels that expose
the required ABI and log access, but it will not make audit-log availability a
runtime correctness dependency. A portable bounded before/after delta of
explicitly selected Quarter-owned roots provides the baseline instrument.

On macOS, discovery is limited to directly exec'd processes and bounded state
deltas. LaunchServices GUI applications do not reliably inherit Quarters'
environment and are explicitly out of scope. Quarters will not bypass
LaunchServices by launching arbitrary bundle executables directly.

Discovery artifacts are excluded from templates, snapshots, portable bundles,
and ordinary logs. Tests use synthetic secret-bearing names and prove output
contains only classifications and bounded counts.

## Final acceptance

Each release slice receives:

- warnings-as-errors formatting, Clippy, rustdoc, unit, integration, and
  acceptance gates;
- Linux target checks before Linux runtime tests;
- dependency licence/source policy and RustSec;
- structural ceilings and `git diff --check`;
- installed-binary smoke tests from temporary directories outside the source
  tree;
- hosted macOS, default Ubuntu, mount-capable Ubuntu, Linux x86_64 musl, and
  Linux arm64 evidence where applicable;
- updated threat model, architecture ADRs, capability matrix, tutorials,
  changelog, registry operations, and stable JSON examples;
- a comprehensive Codex security scan and an independent read-only Opus 5
  maximum-effort review, with every high and medium finding resolved before
  merge or publication.

Publication, registry visibility, hosted CI, and reviewer acceptance are
separate gates. None may be inferred from another.
