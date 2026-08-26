# Changelog

Quarters follows [Semantic Versioning](https://semver.org/). Until 1.0, minor
versions may refine the space format and environment contract; migrations and
compatibility notes will be called out here.

## 0.1.0-alpha.3 — unreleased

- Add previewed, transaction-safe `clone` for inactive spaces, with explicit
  sensitive-state confirmation, descriptor-relative traversal, bounded resource
  limits, counted cache/runtime exclusions, fresh controls and atomic publish.
- Harden creation, removal and recovery cleanup for nested owner-read-only
  directories; retire large deletion targets under the management lock and
  delete them after releasing it.
- Add schema-gated expanded workspaces with stable opaque IDs, private common
  user directories, platform-specific macOS conventions, additive CLI/MCP
  reporting and creation support across both MCP revisions. Existing/default
  profiles remain schema 1 without new manifest fields.
- Add composable zsh/bash `[q:NAME]` prompt context for new spaces through
  `shell-init`, without rewriting existing startup files.
- Add collision-safe `qts`/`q` shortcut inspection, installation and removal
  against the installed PATH launcher, with stable JSON and doctor reporting.
- Split storage creation/layout policy, reject unknown manifest fields after a
  schema-first probe, and sync parent directories after publication renames.
- Stop exporting a reserved but inactive `SSH_AUTH_SOCK`; the host agent stays
  blocked and the variable remains unset until private-agent lifecycle
  management exists.
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
