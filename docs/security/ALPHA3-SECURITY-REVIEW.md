# Alpha 3 security review

Status: local findings resolved and acceptance passed; final independent review pending

Date: 2026-08-26

## Scope

This review covers the schema-3 identity and rename transaction, private
OpenSSH-agent lifecycle, managed OpenSSH command adapters, nested host escape,
MCP status/create integration and their interaction with existing clone,
artifact, rollback, recovery and lease boundaries.

The review assumes the real Unix account, operating system and installed
Quarters binary are trusted. Another process with the same UID is deliberately
outside Quarters' protection boundary. The review still treats same-UID races,
malformed local state and accidental command substitution as correctness and
safe-cleanup risks wherever the portable OS interfaces permit a defense.

## Method

- traced every new process launch, signal, socket, rename, link, metadata read,
  environment backup and lifecycle-lock path
- exercised hostile links, forged adapter context, missing launchers,
  interrupted rename and agent transitions, nested spaces and host sentinels
- ran Rust formatting, warnings-as-errors linting, structural limits, unit and
  acceptance tests, MCP revision tests and installed-binary checks
- inspected exact dependency versions and license/advisory policy
- commissioned independent Claude Code Opus 5 review before implementation;
  the final review runs after local evidence is complete

The managed Codex Security deep-scan worker could not start because this local
task did not provide the required managed read-only filesystem permission
profile. No result from that unavailable worker is counted as review evidence.

## Resolved findings

### QSR-001: nested environments lost the real host backup chain — high

An inner Quarter originally captured the outer Quarter's redirected HOME and
PATH as its host values. This could recurse through the outer OpenSSH adapter
and made `quarters host` escape only one level. Environment construction now
prefers an existing `QUARTERS_HOST_*` backup over the current redirected value.
Acceptance tests prove nested adapter dispatch and host escape return to the
original host values.

### QSR-002: adapter dispatch trusted forgeable baseline context — high

The managed adapter originally accepted path variables without reopening the
declared store. Baseline dispatch now validates the absolute root, parsed space
name and exact space home through the store, then validates the protected `.ssh`
directory and single-link regular config file. Forged context fails closed.
Linux home-view remains an explicitly documented exception because its mount
hides the authoritative store and disables host escape.

### QSR-003: private-agent PID evidence was insufficient at signal time — high

PID liveness, socket inode and protocol response did not prove that the process
accepting the Unix connection still matched the registry PID. Verification now
requires the kernel-reported Unix peer PID on macOS and Linux. Stop repeats the
complete device, inode, peer-PID and protocol proof immediately before sending
SIGTERM. Interrupted stopping recovery uses the same proof.

### QSR-004: lifecycle operations could overlap agent mutations — high

Agent start, stop and recovery were serialized only by the runtime agent lock.
They now also acquire the space activity lease and reject rename or rollback
targets, preventing Quarters-managed rename or replacement from racing an
agent transition.

### QSR-005: interrupted transactions did not consistently guard normal use — high

Some CLI entry paths could open a raw space while it was the named target of a
durable rename or rollback marker. Public store opening now routes through the
guarded named inspection path, and creation, copy, artifact, rollback, upgrade,
agent and command-link mutations reject affected names. Unrelated spaces remain
available, and recovery continues past an ambiguous independent rename marker.

### QSR-006: command-link cleanup could unlink a replaced entry — medium

Installation rollback remembered only paths, and adapter removal relied on an
earlier classification. Rollback now records and rechecks link type, target,
device and inode before cleanup. Removal preflights the complete set and
rechecks the exact relative target immediately before unlinking.

### QSR-007: managed-command ancestry and operational state were incomplete — medium

Inspection validated only the final `.local/bin` directory and could describe
an exact adapter link as managed after its launcher disappeared. It now rejects
symlinked or broadly writable home, `.local` or bin anchors; reports exact links
as stale when the launcher is absent; and repairs an absent launcher without
replacing those exact links.

### QSR-008: read-only status created runtime directories — medium

Agent status used the runtime creation function, so CLI and MCP observation
could mutate temporary state. Observation now performs validation-only lookup
and returns `unset` when the per-space runtime does not exist. Start remains the
only status-path operation that creates the runtime hierarchy.

### QSR-009: post-publication command-link failure could be mistaken for rollback — low

Managed command links are derived machine-local state installed after a space
publication. Failure now retains the published space and returns an explicit
repair instruction; it never deletes a successfully published tree. Lifecycle
copies omit only the closed managed link set and recreate it for the target.

### QSR-010: OpenSSH defaults still resolved through the passwd home — high

Installed-binary `ssh -G` evidence showed that forcing a per-space config does
not change OpenSSH's compiled default identity and user-known-host paths. Those
defaults expanded to the real host `~/.ssh` even though HOME was redirected.
The network adapters now inject a current-space `UserKnownHostsFile` path and
disable default identity files with `IdentityFile=none` before user arguments.
An explicit `-i` or agent key remains an intentional user choice. Acceptance
tests assert the resolved OpenSSH configuration contains the space path and no
host user-known-host path.

### QSR-011: agent failure paths could lose cleanup evidence — high

A legacy-space start created runtime state and spawned the helper before
rejecting the missing stable identity. Separately, automatic restart of a dead
failed record removed that record before checking whether an unowned socket
occupied its path. Stable identity is now checked before runtime creation or
spawn, spawned children are boundedly terminated and reaped on startup failure,
and failed-state restart uses the same exact recovery validation before removing
its record. Hostile socket paths retain both the record and filesystem entry.

### QSR-012: a recycled live PID could pin stale active state — high

After reboot or PID reuse, an `active` record could describe an unrelated live
process while its exact recorded socket was absent or disconnected. Recovery
now treats that combination as stale ownership evidence: it removes only the
absent or exact device/inode socket and matching registry, and never signals the
live PID. Tests cover both a dead record with a leftover socket and a live
unrelated process whose PID was placed in the record.

### QSR-013: OpenSSH option parsing and path representation were incomplete — high

The first adapter revision rejected only a standalone `-F`, and an unquoted
`UserKnownHostsFile` value was reparsed incorrectly when a space path contained
spaces. The adapter now scans leading OpenSSH option clusters, rejects attached
and bundled `-F`, stops at the destination so remote `grep -F` remains valid,
quotes and escapes the path for OpenSSH's option grammar, and rejects line
breaks that grammar cannot safely represent. Installed-tool acceptance uses a
store path containing spaces.

### QSR-014: removal could orphan an agent holding keys — high

Space removal now refuses every private-agent state except `unset`. After a
verified stop, removal deletes persistent state first and then reclaims only
that space's validated private runtime tree. The acceptance test starts a real
agent, proves removal is blocked, stops it, removes the space and confirms the
runtime is gone.

### QSR-015: private-agent keys were not offered by network clients — medium

The generated config and adapter combination previously made the empty default
identity set too restrictive. Adapters now pair `IdentityFile=none` with
`IdentitiesOnly=no`: passwd-home default key files are suppressed, while keys
intentionally added to the private agent and explicit `-i` keys remain usable.
Acceptance generates an ephemeral Ed25519 key, loads it through the managed
`ssh-add` path and verifies the private agent lists it.

### QSR-016: compatibility reporting could claim a stale adapter route — medium

`doctor NAME` now includes the observed launcher and all four command-link
states. Its SSH compatibility mechanism is derived from that report, so stale,
absent or colliding links say PATH may fall through rather than claiming the
managed route. Global doctor output describes the conditional mechanism only.

### QSR-017: socket probing could exceed a bounded status budget — low

Unix-socket connect is now nonblocking and poll-bounded before the existing
read/write deadlines. Named MCP status performs full agent verification; the
bounded all-spaces inventory reports `not-inspected` instead of multiplying a
per-socket deadline across as many as 128 spaces.

### QSR-018: upgrade and removal could strand runtime directories — low

Stable-ID upgrade recognizes the exact deterministic legacy runtime identity
and re-keys an existing tree by same-parent rename. Lookup accepts that fallback
until migration completes, and rename completes re-keying before changing the
display name. Removal reclaims the exact validated runtime after refusing live
agent state. Acceptance preserves a runtime proof file across upgrade and
confirms the legacy path disappears.

### QSR-019: adapter context and helper launch checks were too permissive — low

The home-view bypass now requires the exact internal value `home-view`; mere
presence is insufficient. Agent start validates the fixed executable and Unix
socket path length before spawning, and stored failure reasons are surfaced in
status instead of collapsing into a generic message. Restart stops only an
actually active verified agent, then delegates stale-state handling to the same
start/recovery policy.

### QSR-020: bare ssh-add could import passwd-home defaults — high

The managed `ssh-add` link originally passed every argument through unchanged.
OpenSSH defines a no-file invocation as loading its default identity files,
whose `~` expansion may resolve through the real account home. The adapter now
refuses implicit default loading, modifier-only forms such as `-t 1h`, and
Apple host-keychain import flags. Explicit per-space key paths, listing,
locking and deletion remain available; intentional host import uses the
explicit host escape. Acceptance proves both refusal and explicit ephemeral-key
loading.

### QSR-021: one shared OpenSSH option grammar left -F bypasses — high

`ssh`, `scp` and `sftp` do not assign arguments to the same short options. A
shared table consumed `ssh -F` after `-X`, stopped early after `ssh -D`, and
missed `sftp -s`. Parsing now uses separate current OpenSSH option grammars for
each tool. Unit and process acceptance reject all three forms plus attached and
bundled `-F`, while still allowing `-F` in a remote command after the SSH
destination.

### QSR-022: stale-state triage and aggregate status were not bounded — medium

Named doctor previously aborted while building an environment for a stale
agent, even though doctor is the triage surface. It now reports the agent,
marks environment validation false and prints the exact confirmed recovery
command. Named status retains full live verification; aggregate CLI and MCP
status both report `not-inspected`, preventing a per-space socket deadline from
multiplying across a large store.

### QSR-023: forged home-view context and relocated launchers degraded silently — medium

The environment-only home-view adapter exception is now compiled only on
Linux, where that experimental mount mode can hide the authoritative store.
macOS always reopens and validates the declared store, even if the sentinel is
forged. `exec` and `enter` now warn whenever the observed launcher or adapter
set is incomplete, so a moved package installation does not silently fall
through to host OpenSSH state. Environment values remain mutable under the
documented same-UID boundary.

### QSR-024: residual agent and lifecycle states needed bounded exits — low

The agent handoff token moved from process arguments to the short-lived helper
environment and is cleared before exec into OpenSSH. A disconnected exact
`stopping` socket can now be recovered without signaling a recycled live PID;
ambiguous endpoints retain their record with an exact retry hint. Rename now
refuses legacy artifact bindings that would otherwise become unreachable after
an upgrade/name change. Artifact source lookup indexes spaces once per bounded
catalog pass, and single-artifact display no longer repeats the catalog scan.

### QSR-025: home-view host-tool resolution could recurse — medium

Linux home-view can place a space's `.local/bin` at a path that also appeared
in the original host PATH. A managed `ssh` link there could therefore resolve
back to the running Quarters executable. Host-tool resolution now rejects the
running executable's device/inode, including symlink and hard-link spellings.
A parent-PID handoff also stops direct recursive adapter dispatch before it can
spawn, without blocking a later adapter launched by an OpenSSH proxy command.

### QSR-026: shortcut-spelled launchers could strand managed commands — medium

Some platforms can report the invoked symlink path from `current_exe()`. The
documented `qts create` path could publish a space and then fail launcher-name
validation. CLI and MCP installation now canonicalize the running executable
before validating it. Acceptance invokes the test binary through a `qts`
symlink and verifies all five managed links are present.

### QSR-027: MCP failures discarded recovery guidance — low

MCP diagnostics previously serialized the error category and message but
dropped the bounded Quarters hint. Diagnostic output now carries an optional,
escaped 512-byte recovery hint, so stale private-agent failures retain the
exact confirmed-recovery guidance available to the CLI.

### QSR-028: rename-marker limits could prevent recovery — low

Rename inspection previously combined valid and malformed markers under one
128-entry hard failure. Malformed records could therefore make every operation,
including recovery, fail permanently. Inspection now counts the complete
namespace, target checks scan all valid markers, and recovery processes valid
records in bounded batches of 128 successful mutations. Retained ambiguous
records do not consume that progress budget. Regressions prove 129 actionable
markers drain in two passes and 128 ambiguous markers cannot starve a later
actionable record, without weakening target blocking.

### QSR-029: home-view could overmount the installed adapter — low-medium

When the installed launcher lived beneath the host home, Linux home-view could
cover its absolute target and leave the managed space links unreachable. The
launcher now copies itself into the protected runtime bin and installs four
verified relative OpenSSH links there before mounting. That directory is first
on PATH; collisions fail closed and no unverified entry is replaced.

### QSR-030: released runtime spelling was not recognized — low

The stable-ID transition initially recognized only its new BLAKE3 legacy key,
not the released `NAME-{fnv(root):016x}` directory. Runtime lookup, migration
and post-removal cleanup now consider both exact predecessors. Exactly one may
be authoritative; multiple live candidates are retained with a corruption
error rather than merged or deleted. Upgrade acceptance moves an actual
released-form tree and preserves its contents.

### QSR-031: special OpenSSH path bytes lacked parser evidence — low

The known-hosts option encoder had only a string-shape unit test for quotes and
backslashes. Installed-tool acceptance now creates the complete store beneath a
path containing spaces, quotes and backslashes and requires `ssh -G` to return
the exact per-space path and exactly one `identityfile none` directive.

### QSR-032: standalone MCP launcher policy diverged — informational

The stdio MCP server now resolves and validates the canonical installed
`quarters` launcher before accepting requests, matching CLI-created command
policy. The bounded in-memory library transport explicitly receives no
machine-local launcher and continues to omit command links for test embedding.

### QSR-033: a distinct home-view launcher could rediscover Quarters — medium

The protected home-view launcher copy has a different inode from a
system-installed Quarters binary. If the captured host PATH began with the
overmounted host `.local/bin`, its managed `ssh` link could therefore resolve
to that system binary and fail closed through the recursion fuse instead of
reaching OpenSSH. Host-tool lookup now canonicalizes candidates and rejects
both the running device/inode and every resolved basename of `quarters`. A
home-view-shaped regression uses distinct launcher and fallback inodes.

### QSR-034: failed runtime publication retained staging — low

A launcher-copy failure removed its private temporary, but a following rename
failure did not. Publication now removes that exact staging file on either
failure path, and a collision regression verifies the runtime bin contains no
temporary residue.

### QSR-035: agent registry staging exposed the ownership token — informational

The private registry directory is mode 0700, but its temporary filename did
not need to repeat the handoff token. Registry replacement now uses the
existing process/time/counter unique suffix; the token remains only in the
protected record and short-lived helper environment where ownership handoff
requires it.

## Residual boundaries

- Quarters does not contain hostile same-UID processes. They can read files,
  connect to a private agent, replace user-writable launchers and use absolute
  host paths under normal OS authority.
- The portable activity lease cannot discover detached writers. Clone,
  snapshot and rollback are transaction-safe publication operations, not a
  global process or filesystem freeze.
- OpenSSH adaptation governs ordinary PATH resolution. Absolute executables,
  embedded libraries and explicit absolute key paths bypass it.
- Artifact BLAKE3 digests detect accidental change; they do not authenticate
  state against another process with the same UID.
- Linux compilation and namespace logic remain CI-covered until a physical
  Linux runtime acceptance pass is recorded. Nested launches preserve the
  original host `XDG_RUNTIME_DIR` backup when available and otherwise fall back
  to `/tmp`, rather than nesting beneath a space runtime.
- Freeze, authenticated export, encryption at rest and enforced confinement are
  not implemented and are not claimed.

## Acceptance record

- `make check`: 201 Rust tests and 4 typed npm launcher tests passed; formatting,
  warnings-as-errors clippy, repository ceilings, warning-free Rustdoc and npm
  high-severity audit passed.
- `cargo deny check`: advisories, bans, licenses and sources passed. It reports
  the configured informational duplicate-version note for transitive `syn` 2
  and 3; both are required by current upstream dependency families.
- `cargo audit --deny warnings`: 185 locked crate dependencies scanned against
  1,226 RustSec advisories with no finding.
- clean release install under a fresh private temporary prefix. The installed
  binary created profile and workspace spaces, installed all five managed
  command links, preserved the invoking numeric UID, kept Git mutation inside
  the space, returned through two nested spaces to the captured host HOME, and
  dispatched nested OpenSSH without adapter recursion.
- a final fresh release install created a complete space through the installed
  `qts` symlink, then resolved host OpenSSH with the space command directory
  deliberately first in the captured host PATH. The adapter skipped itself,
  ran OpenSSH once and retained all five managed links.
- installed OpenSSH evidence resolved `identityfile none` and the exact
  per-space `userknownhostsfile`, with no host user-known-host path.
- installed private-agent evidence passed unset, active, ephemeral-key load,
  rename-stable and stop transitions with peer-PID verification.
- installed MCP evidence passed 2026-07-28 discovery/create and 2025-11-25
  initialize/create against one native binary; MCP-created spaces received the
  managed command set.
- Physical Linux runtime acceptance remains open and is not represented by the
  macOS and CI evidence above.
- The sixth independent maximum-effort Opus pass was source-only because its
  sandbox denied compiler execution. It verified the cumulative repairs and
  returned the explicit final verdict `VERDICT: SHIP`; the full record keeps
  that limitation separate from the local executable evidence.
