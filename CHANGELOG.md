# Changelog

Quarters follows [Semantic Versioning](https://semver.org/). Until 1.0, minor
versions may refine the space format and environment contract; migrations and
compatibility notes will be called out here.

## 0.1.0-alpha.4 — unreleased

- Add identity-bound cooperative freeze/unfreeze, immediate stationery capture
  from a current Quarter holding a cooperative lease, and explicit
  `frozen-active` source evidence without claiming filesystem immutability.
- Advance local artifact manifests to schema 3 for source-state provenance;
  earlier Quarters builds reject these new local artifacts, while schema-1
  local artifacts and schema-2 imported templates remain readable.
- Require omitted-name private-agent and adapter commands to match the current
  Quarter's validated name, root and home evidence rather than trusting a name
  marker alone.
- Add versioned keyed-BLAKE3 plaintext bundles for verified templates and
  snapshots, private no-clobber key creation, two-pass authenticated import as
  schema-2 external templates, plan-digest confirmation and atomic publication.
- Reject bundle keys inside the active store, preserve legal parent-relative
  links and deepest leaves, release hostile path metadata at directory close,
  validate authenticated provenance before extraction, and report post-commit
  durability or cleanup failures without implying that publication vanished.
- Pin Bun 1.3.14 as the typed npm launcher's development package manager and
  lockfile owner, rename its local gate to `make launcher-check`, and retain
  npm as the consumer installation, artifact packaging and publication surface.
- Add previewed, digest-confirmed host shell forking with descriptor-anchored
  no-follow source selection, strict credential exclusions, bounded explicit
  files, generation revalidation, private provenance and atomic publication.
- Require a distinct `--replace-generated` plan before replacing generated
  startup files; creation never evaluates copied content and MCP deliberately
  receives no host-fork authority.
- Give every newly created profile and workspace an opaque schema-3 identity;
  add an atomic legacy-profile upgrade and recoverable display-name rename
  without breaking existing snapshot binding.
- Add an explicit per-space OpenSSH agent lifecycle with bounded startup and
  shutdown, private ownership records, process and socket-identity checks,
  protocol liveness, fail-closed environment injection and narrow recovery.
- Publish the private-agent `starting` reservation under its lifecycle lock,
  retain a separate startup-owner lease during bounded protocol readiness, and
  revalidate the record and socket when concurrent starters converge on one
  active process or a failed owner terminates its child.
- Retry one private-agent launcher that exits before readiness through an
  atomic reservation handoff, with deterministic six-caller fault injection.
- Add the inspected link change timestamp to shortcut removal's target,
  device and inode checks, narrowing immediate matching-identity reuse without
  claiming a portable same-UID security boundary.
- Install collision-safe `ssh`, `scp`, `sftp` and `ssh-add` invocation adapters
  into new CLI and installed-server MCP spaces; force a protected per-space SSH
  configuration while preserving child output and exit status.
- Add installed-tool compatibility evidence for representative shells, CLIs
  and coding agents when present, with host sentinels proving the probes did
  not mutate host state.
- Preserve the original host environment across nested Quarters launches so
  adapters do not recurse and `quarters host` does not escape only one level.
- Keep agent status and MCP inspection read-only when no runtime exists; verify
  the kernel-reported socket peer PID before advertising or stopping an agent.
- Reject legacy agent start before runtime creation, boundedly reap failed
  launchers and retain failed ownership records when socket cleanup is unsafe.
- Validate every managed-command directory ancestor and adapter context, report
  exact links with a missing launcher as stale, and reverify created links
  before rollback cleanup.
- Override OpenSSH's passwd-home-derived user-known-hosts and default identity
  paths so ordinary adapted invocations do not silently select host SSH state.
- Prevent adapter self-resolution through overmounted Linux home paths by
  rejecting the running executable inode and direct parent-child recursion.
- Keep the complete managed OpenSSH route reachable inside Linux home-view by
  publishing a protected runtime launcher and four verified relative links
  before the host home is mounted over.
- Prevent that distinct runtime launcher from rediscovering a system-installed
  Quarters binary through an overmounted host-home PATH entry; remove staged
  runtime copies after failed publication.
- Canonicalize shortcut-spelled launchers before installing managed commands,
  preserve bounded MCP recovery hints and drain rename recovery in bounded
  batches beyond the inspection ceiling.
- Recognize and re-key the released pre-alpha.4 runtime-directory spelling,
  refusing multiple candidate trees rather than abandoning or merging state.
- Bind Linux home-view launch to descriptor-validated passwd and space homes,
  then verify the post-mount current directory before executing the child.
- Retain generation-safe process handles while stopping private agents: pidfd
  signalling and readiness polling on Linux, and start-time revalidation on
  macOS; removal proves agent absence even when a space home is damaged.
- Bind creation, copy, rollback, template and removal cleanup to retained
  filesystem generations; preserve replacement trees and shortcut links rather
  than deleting pathnames that changed during a transaction.
- Separate protocol result ceilings from 131,072-entry filesystem work budgets
  across space, artifact, rename and recovery scans; ordinary spaces no longer
  consume rollback-marker limits.
- Validate the complete SSH-agent identities response, every persisted launcher
  ancestor, and effective executable access; clean partial private registry
  temporaries without following replacements.

- Add named, verifiable templates and snapshots with create, list, show,
  verify, use, rename and removal lifecycles, stable JSON contracts and private
  content-addressed manifests.
- Add guarded whole-space rollback with mandatory automatic recovery snapshots,
  exact confirmations, durable three-state publication and idempotent
  interruption recovery.
- Extend doctor and confirmed recovery to bounded artifact staging, manifest
  temporaries and rollback state without removing unknown hidden entries.
- Add previewed, transaction-safe `clone` for inactive spaces, with explicit
  sensitive-state confirmation, descriptor-relative traversal, bounded resource
  limits, counted cache/runtime exclusions, fresh controls and atomic publish.
- Harden creation, removal and recovery cleanup for nested owner-read-only
  directories; retire large deletion targets under the management lock and
  delete them after releasing it.
- Add schema-gated expanded workspaces with stable opaque IDs, private common
  user directories, platform-specific macOS conventions, additive CLI/MCP
  reporting and creation support across both MCP revisions. Legacy schema-1
  profiles remain readable and can now be upgraded explicitly.
- Add composable zsh/bash `[q:NAME]` prompt context for new spaces through
  `shell-init`, without rewriting existing startup files.
- Add collision-safe `qts`/`q` shortcut inspection, installation and removal
  against the installed PATH launcher, with stable JSON and doctor reporting.
- Split storage creation/layout policy, reject unknown manifest fields after a
  schema-first probe, and sync parent directories after publication renames.
- Stop exporting a reserved but inactive `SSH_AUTH_SOCK`; the host agent stays
  blocked and the variable remains unset unless a managed private agent is
  fully verified.
- Add a stdio-only MCP server with separately tested `2026-07-28` stateless and
  `2025-11-25` initialized lifecycles.
- Expose typed, schema-validated status, doctor and create tools plus bounded
  help, security and private-status resources; deliberately omit process
  execution, environment inheritance, root selection and deletion.
- Bound MCP frames, response-lifetime concurrency, legacy request IDs, store
  listings and blocking filesystem workers; harden cancellation, duplicate IDs,
  output backpressure and untrusted stored-name presentation.
- Preserve every decoded MCP transport error across SDK receive cancellation,
  reject batches and invalid IDs correctly, and prove recovery after a
  200-request over-capacity burst.
- Bound ordinary MCP responses, transport errors and shutdown to the same
  two-second output-drain deadline.
- Add honest cooperative-lease inspection through `quarters status [NAME]`.
- Validate the `QUARTERS_SPACE` marker against the active store before `current`
  or status reports a process as being inside a space.
- Validate space roots, homes, manifests and activity locks before use,
  rejecting symlinked or non-private anchors.
- Keep healthy spaces inspectable when a sibling is damaged, and permit
  exact-name removal only when the damaged entry's root and lock remain safe.
- Make `doctor NAME` construct and validate the space's baseline environment.
- Add bounded reporting and confirmed cleanup for interrupted internal creation
  and retirement state.
- Serialize lease observation, launch acquisition and removal retirement to
  avoid false activity and deleted-home races.
- Give read-only observation, management and supervisor leases separate bounded
  contention deadlines with jittered retry.
- Classify same-name creation and removal races deterministically, and preserve
  the current-space report inside Linux home-view where the authoritative store
  is intentionally hidden.
- Validate stored names during deserialization and escape terminal control
  characters without damaging printable Unicode.
- Request npm provenance attestations for every native and launcher package.

## 0.1.0-alpha.2 — 2026-08-20

- Stop carrying host credential and agent paths under backup variable names;
  the baseline now satisfies the documented deny-by-default environment policy.
- Refuse Linux home view when supplementary group authority cannot be
  preserved.
- Refuse non-private existing storage roots without changing their permissions.
- Add tested, prerelease-safe PyPI and multi-platform npm distributions with
  short-lived trusted-publishing workflows.
- Add distribution-version, target-build and npm runtime checks, plus package
  assembly preflights, to the release gate.

## 0.1.0-alpha.1 — 2026-08-20

First public alpha.

- Create, inspect, enter, execute within and remove persistent named spaces.
- Redirect `HOME`, XDG roots, shell history, runtime paths and representative
  developer-tool state while preserving the real host identity and authority.
- Start children from a strict environment allowlist with explicit inheritance.
- Restore host state paths through the named `host` escape on baseline spaces.
- Probe macOS and Linux capabilities without overstating confinement.
- Offer an opt-in Linux bind-mounted home view backed by user and mount
  namespaces, with unsupported configurations failing closed.
- Provide stable JSON output for management and inspection commands.
