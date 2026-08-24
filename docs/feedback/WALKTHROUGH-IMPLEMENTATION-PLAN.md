# Walkthrough implementation plan

Status: complete. The revised plan was approved before implementation; three
post-implementation Claude Code Opus reviews returned `VERDICT: SHIP`.

## Guardrails

- Preserve the baseline contract: native process state redirection under the real host identity, not a sandbox.
- Keep unsupported protection modes fail-closed and capability-labelled.
- Treat manifests, roots, child input, MCP input, environment values, and shell-facing text as untrusted.
- Preserve warning-as-error, structural, dependency, documentation, and cross-platform gates.
- Do not silently copy credentials, rewrite user-owned startup files, replace commands, migrate storage, or perform destructive rollback.
- Only a validated `SpaceName` may reach a prompt-expanded variable. A root, path, manifest string, or other untrusted value must never reach prompt expansion.

## Step 0: storage groundwork without behavior changes

1. Split the near-limit `store.rs` into cohesive creation/layout modules without changing its public behavior.
2. Introduce one internal store-layout resolver used by creation, inspection, removal, and recovery. For this release it resolves and writes only the existing `spaces`/`trash` layout.
3. Add `#[serde(deny_unknown_fields)]` to stored manifests and preserve schema-1 compatibility. Probe `schema_version` through a minimal permissive header before strict deserialization so unsupported schemas produce an upgrade-specific error and hint rather than a generic invalid-manifest message.
4. Add a reviewed parent-directory durability helper and use it after existing creation/removal publication renames.
5. Add regression tests proving existing stores, recovery state, activity leases, and malformed anchors behave identically, plus a stable `doctor --json` contract test used by later increments.

## Step 1a: truthful SSH-agent state

1. Stop inserting the dead private `SSH_AUTH_SOCK` path into launched environments.
2. Keep `SSH_AUTH_SOCK` profile-owned: it remains blocked from implicit and explicit inheritance, cleared during host-state restoration, and absent by default.
3. Defer any host-agent adapter or private-agent lifecycle to an ADR; neither ships implicitly in this increment.
4. Update README, architecture, threat model, compatibility matrix, existing OpenSSH probe/MCP doctor text, and changelog together. Do not add a separate `ssh-agent` probe row until the probe model can express lifecycle state; executable presence is not agent activity.
5. Test that `env` omits the variable, `--inherit SSH_AUTH_SOCK` still fails, `quarters host` does not leak it, and diagnostics describe the unavailable private-agent lifecycle honestly without equating an installed executable with an active agent.

## Step 1b: composable prompt context

1. Add stable prompt-context environment variables derived only from the validated space name, and add every new variable to the explicit host-restoration clear list.
2. Add `quarters shell-init zsh|bash`, which prints a versioned Quarters-owned integration snippet from first-party Rust constants without modifying or shipping shell-script files.
3. Make startup files for newly created spaces resolve Quarters at shell start and evaluate `quarters shell-init <shell>` behind a `command -v quarters` guard. Never freeze an installation path into a space and never rewrite startup files in an existing space. Resolution intentionally uses the space PATH and same-UID trust model.
4. Document the one-line opt-in for existing spaces and common prompt frameworks.
5. Preserve existing prompt composition rather than replacing Git, virtualenv, or theme integrations wholesale.
6. Add negative tests with roots containing `%F{red}`, `$(id)`, backticks, dollar signs, and backslashes; none may reach prompt-expanded values.

## Step 2: distribution-aware shortcut management

1. Add `quarters shortcut status|install|remove [qts|q]` with stable JSON and one canonical help name (`quarters`).
2. Resolve every installed `quarters` match on the host `PATH`; do not assume `current_exe()` is a PATH entry or write beside it.
3. Install a precisely defined managed link into a user-selected PATH directory, defaulting to the real host `~/.local/bin` only when that directory is on the host PATH.
4. Fail closed for install/remove when `QUARTERS_SPACE` is active and for every shortcut command in home-view. Status may run inside a baseline space only and must label that it inspected the space environment, not the host.
5. Detect and report every filesystem/PATH collision in resolution order plus conservative shell builtin/reserved-name collisions. State that a child cannot observe transient aliases/functions in its parent and print the exact `type -a <name>` preflight.
6. Never replace an existing entry. Remove only a symlink whose target exactly matches the managed-link contract, using `remove_file` only.
7. Recommend `qts`; offer `q` only by explicit request. `make install` installs `quarters` and prints the shortcut command rather than claiming a short name automatically.
8. Test install/status/remove idempotency, PATH absence, all collision types, in-space refusal, npm/Homebrew-style indirection, and use from outside the repository and inside a clean Quarter.

## Step 3: schema-gated expanded workspace

1. Keep schema 1 for the existing profile layout with no new layout field.
2. Introduce schema 2 for workspace spaces with an explicit closed `layout` value and a stable internal space ID independent of the display name.
3. New readers accept schema 1 as profile and schema 2 as workspace; older readers fail closed on schema 2 through the existing exact-version check.
4. Add `create --layout profile|workspace`, retaining profile as the default.
5. Create a portable workspace directory set and platform-specific macOS/Linux directories behind the platform module. Every creation target must remain beneath the validated space root, use existing private-directory helpers and modes, create no escaping symlink, and perform no host-side registration.
6. Describe workspace directories as conventions backed by HOME/XDG and best-effort platform adapters—not containment, passwd-home replacement, TCC isolation, or proof that every application follows them.
7. Expose layout and capability limits in list/status/doctor, CLI JSON, documentation, and the compatibility matrix. The additive CLI output schema remains version 1 unless a breaking shape is introduced.
8. Extend MCP `CreateParams` with an optional closed layout enum and `SpaceView` with an optional layout for unhealthy/legacy entries; verify schemas and calls on both 2026-07-28 and 2025-11-25.
9. Test v1 compatibility, v2 fail-closed behavior, platform directories/modes, CLI JSON, MCP valid/invalid layout on both families, and doctor JSON.

## Step 4: architecture decisions only

1. Lifecycle/copy ADR: quiescence, exclusive leases, symlinks, special files, metadata, cache/runtime exclusions, limits, acceleration, portable copy, provenance, and recovery.
2. Inheritance ADR: clean, selected environment, selected shell configuration, selected paths, explicit credentials, dry-run preview, and host-fork provenance.
3. Agent ADR: explicit private-agent lifecycle and opt-in host-agent adapter without default credential authority.
4. Storage-layout migration ADR: expand/migrate/contract releases, old-reader behavior, live-lease refusal, stale-runtime collection, durable marker, crash injection, and recovery. Define stable runtime identity for schema-1 spaces from the existing `(name, created_unix_ms)` pair; document and sweep the one-time runtime re-key in a release separate from physical migration.
5. Maximum-isolation ADR/research plan: encrypted-at-rest storage, mounted-state limits, adversaries, and earned capability labels.
6. Do not expose clone, template, snapshot, freeze, rollback, host-fork, encryption, or hidden-layout mutations until their shared transaction foundations pass adversarial tests.

## Later compatibility releases

1. First ship a reader that understands both legacy and hidden storage but continues writing legacy storage.
2. Only after that reader is common may a confirmed migration release move live data, and only with exclusive leases, stable runtime IDs, crash recovery, and old-reader loud failure.
3. Build clone first on the lifecycle transaction primitive, then templates/current-context stationery, immutable snapshots/backups, and finally previewed rollback with an automatic recovery point.
4. Add rename only after stable internal IDs are universal.
5. Build host-fork creation on the reviewed copy/inheritance primitives, never an independent broad recursive copier.

## Acceptance for this implementation session

- Complete steps 0–3 only after the revised plan receives independent approval.
- Land the step-4 ADRs needed to make later work implementation-ready; ship no unsafe partial commands.
- Run `make check`, `cargo deny check`, `cargo audit --deny warnings`, CLI acceptance outside the repository, installed-command and shortcut checks, macOS end-to-end creation/entry checks, and MCP verification for both protocol families.
- Verify `docs/mcp/VERIFICATION.md` and `docs/compatibility/MATRIX.md` as acceptance surfaces.
- Obtain a final independent Claude Code review with an explicit `SHIP` or `BLOCK`, then resolve every validated blocking concern.
