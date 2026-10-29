# Claude Code review record

Date: 2026-08-23

Claude Code Opus was used as an independent planning and acceptance reviewer,
as requested. It ran in read-only plan/safe mode and did not modify the
repository or substitute for local test execution.

## Before implementation

1. The first maximum-effort architecture review returned `BLOCK` with six
   planning concerns.
2. The implementation plan was revised to add schema expand/contract rules,
   prompt-input constraints, distribution-aware shortcut behavior, honest
   SSH-agent state and transaction prerequisites for deferred lifecycle work.
3. The second architecture review returned `APPROVE`. Its seven cautions were
   incorporated before code changes began.

The plan reviewed is
[`WALKTHROUGH-IMPLEMENTATION-PLAN.md`](WALKTHROUGH-IMPLEMENTATION-PLAN.md).

## After implementation

Three independent maximum-effort passes inspected the working-tree source,
tests, threat model and documentation:

- full implementation review: `VERDICT: SHIP`, no blockers
- post-review refinement review: `VERDICT: SHIP`, no blockers
- narrow final shortcut/state-machine delta review: `VERDICT: SHIP`, no blockers

Nonblocking findings were iterated into the code between passes, including
layout padding, startup PATH trust documentation, schema constant clarity,
durability diagnostics, unhealthy JSON consistency, quiet older-binary prompt
compatibility, relocated/stale shortcut states, dangling-link cleanup and
relative-PATH target refusal.

Claude explicitly noted that it did not execute the gates because review mode
was read-only. Local acceptance remained a separate requirement.

## Local evidence on the reviewed result

- `git diff --check`
- `make check`
- `make dependencies`
- 99 Rust tests and 4 typed npm launcher tests
- warnings-as-errors Clippy and rustdoc
- repository structural ceilings
- npm high-severity audit: zero vulnerabilities
- Cargo advisory, license and source policy: pass
- release-profile installation and end-to-end use from a temporary prefix
- official Rust SDK interoperability for MCP `2026-07-28` and `2025-11-25`

`cargo deny` reports the permitted transitive `syn` 2/3 duplication while all
advisory, ban, license and source gates pass.

## Lifecycle clone review, 2026-08-24

### Before implementation

Claude Opus 5 reviewed
[`LIFECYCLE-CLONE-IMPLEMENTATION-PLAN.md`](LIFECYCLE-CLONE-IMPLEMENTATION-PLAN.md)
at maximum effort in read-only mode. The first pass returned `BLOCK`. Its
findings required the plan to specify descriptor-relative traversal, bounded
logical-file copying, hard-link treatment, special-file exclusion, robust
cleanup of private read-only trees, deterministic transaction fault points,
fresh control-plane identity and exact derived-cache policy.

The revised plan incorporated those findings. A second maximum-effort pass
returned `VERDICT: APPROVE`; its remaining cautions were carried into the
implementation and tests. Final implementation review is recorded below once
the resulting working tree has passed independent inspection.

### Local evidence before final review

- warning-free `make check`, initially including 114 Rust tests and 4 npm tests
- Cargo advisory, license and source policy: pass
- release-profile installation and end-to-end clone execution from a temporary
  prefix
- default cache exclusion, fresh destination identity, healthy reopened state,
  redirected HOME and preserved host UID verified from the installed binary

### First implementation review

The first maximum-effort implementation pass returned `VERDICT: BLOCK` with
three findings:

1. descriptor-identity and live file-growth defenses lacked deterministic
   hostile-source tests;
2. one very wide directory could allocate names beyond the advertised entry
   budget before rejection; and
3. human output described a cache-specific symlink count as covering every
   exclusion.

All three were repaired. The test seam now replaces regular files,
directories and symlinks after metadata inspection, deletes an entry, and grows
a file after `stat`. Directory-name buffers share the global entry budget and
reserve only bounded chunks. The JSON field and human label now name omitted
cache roots precisely, with the remaining dangling-link cases documented.

The same iteration also applied the review's hardening suggestions: cleanup
permission restoration uses a verified no-follow directory descriptor,
symlink accounting has constant cache-root cardinality, post-publication reopen
errors identify the completed publication, absent-store preview returns the
named `not_found` result, diagnostics are byte-bounded, and unprivileged fixture
limits are recorded. The cleanup concurrency path was then stress-tested across
20 consecutive passes.

After these repairs, `make check` passed with 124 Rust tests and 4 npm tests.

### Final implementation acceptance

The next maximum-effort pass re-audited the repaired transaction and returned
`VERDICT: SHIP` with no blocking findings. Its additional hardening suggestions
were applied: iterative no-follow cleanup, bounded cleanup depth and directory
count, continued recovery after one cleanup failure, accurate root diagnostics,
original error-kind preservation on compound failure, clone help coverage and
as-built plan corrections.

A second maximum-effort regression pass returned `VERDICT: SHIP`. Its strongest
nonblocking observations led to explicit cleanup ceilings and manual-recovery
guidance, an honest Linux no-follow `fchmodat` portability note, a larger cleanup
budget than any clone-produced tree, concurrent parent-disappearance handling
and staging-specific permission guidance.

The exact resulting tree then received another `VERDICT: SHIP`. Its only two
notes were closed with a root guard on the mode-dependent diagnostic test and
the same concurrent-`ENOENT` rule on a restored-directory reopen. A final narrow
Opus 5 inspection of those two lines returned `VERDICT: SHIP` without findings.

Claude remained read-only throughout and did not execute local gates.

### Final local evidence

- `git diff --check`, `make check` and `make dependencies`
- 129 Rust tests and 4 typed npm launcher tests
- warnings-as-errors Clippy and rustdoc plus repository structural ceilings
- npm audit: zero vulnerabilities
- Cargo advisory, license and source policy: pass; the approved transitive
  `syn` 2/3 duplication remains the only `cargo deny` warning
- `cargo audit --deny warnings`: pass
- release-profile installation and clone execution from a temporary prefix
- default cache exclusion, fresh destination identity, healthy reopened state,
  redirected HOME and preserved host UID verified from the installed binary

### Rebase integration acceptance, 2026-08-25

After upstream `main` added the Quarters mark, the reviewed implementation was
rebased without source changes. A fresh read-only Opus 5 review returned
`VERDICT: SHIP` and confirmed that the post-review delta was limited to the
README inclusion and `docs/icon.svg`. Its only low-severity observation was
that a repository-relative image would not resolve on package-registry README
pages. The README now uses the absolute repository-hosted image URL it
recommended.

### Linux CI identity-race correction, 2026-08-25

The first GitHub Ubuntu quality run exposed immediate inode reuse in the three
source-replacement tests. The production identity check was strengthened to
compare ownership, full mode, link count, size, modification time and change
time as well as device, inode and type. The threat model records the remaining
matching-tuple and filesystem-timestamp-granularity limit.

Two maximum-effort Opus 5 passes returned `BLOCK` while the hostile-growth test
could still pass without reaching its intended post-open copy path. The test
seam was split into pre-open replacement and post-open growth phases, every
mutation now proves it ran, the growth failure names its exact target, directory
replacement is deterministic across umasks, and each new metadata comparison
has direct regression coverage. The repaired exact delta then received
`VERDICT: SHIP`.

## Dibs availability

The final Codex session checked callable tools, MCP resources and MCP resource
templates. No Dibs server or Dibs tool surface was available, so registration
or agent messaging could not be performed from this session. Work continued
without treating that integration as a blocker.

## Lifecycle artifacts and rollback review, 2026-08-25

### Before implementation

Claude Opus 5 reviewed
[`LIFECYCLE-ARTIFACTS-IMPLEMENTATION-PLAN.md`](LIFECYCLE-ARTIFACTS-IMPLEMENTATION-PLAN.md)
at maximum effort in read-only mode. It confirmed that named templates,
verifiable portable snapshots and guarded rollback are worth building and
feasible without VM or container semantics, subject to Quarters' existing
same-account and detached-writer boundaries.

Four adversarial passes returned `VERDICT: BLOCK` while the proposal still had
format or recovery contradictions. The review forced the design to add bounded
artifact deletion, a byte-level canonical digest grammar, explicit lock-owner
tokens, a three-state rollback contract, strict creation-versus-verification
walker modes, reclaimable pre-marker staging, operation-specific cache policy,
continuous coordination across both rollback renames, compatibility behavior
for older binaries and a closed recovery namespace.

The fifth pass re-read the complete amended plan and current implementation and
returned `VERDICT: APPROVE`. Its remaining precision findings were folded into
the approved plan before production code changed: ordered creation-lock removal,
platform-bound rollback, surviving-artifact disclosure on space removal, exact
MCP rollback state, every durable marker-state write, independent recovery
budgets, shared post-read race hardening, the ADR 0006 gate clarification and
doctor disclosure before whole-home recovery.

Approval authorizes implementation; it is not a ship verdict. Claude remained
read-only and executed no local acceptance gates.

### Implementation and security acceptance

Two initial maximum-effort implementation passes returned `VERDICT: BLOCK`.
They found fail-closed behavior that was too broad around malformed rollback
markers, non-atomic first-marker publication, duplicate transitional rows,
uncounted retired trees, coupled recovery budgets and retry-ordering defects.
The implementation now itemizes ambiguous markers, preserves unrelated space
availability, publishes marker updates through a private temporary file plus
rename and parent sync, uses non-cloneable lock tokens, retains every ambiguous
tree and keeps recovery families independently bounded.

Codex Security scan `20226dd7-5764-4ffe-b7b0-923294850dfb` reported one
low-severity terminal-injection path in artifact diagnostics. Output now escapes
untrusted IDs and messages in both human and JSON carriers, with a regression
test. Its two non-reportable correctness observations also led to relocated-root
recovery support and retry-safe recovery ordering. The scan workbench could not
be updated because its remediation action token was unavailable; the exact fix
was reproduced and verified locally.

A subsequent complete Opus 5 pass reproduced an MCP status-budget bypass:
rollback rows appended after the 128-space check could produce hundreds of
agent-context entries. It also found an incorrect empty-list message,
post-commit cleanup wording and artifact-catalog marker rescanning. All four
were repaired. The combined MCP budget now applies after rollback rows and
retained issues are merged; 128 entries succeed and 129 fail closed on both the
tool and resource paths. Catalog source status parses marker inventory once,
and cleanup failures after publication explicitly report that rollback already
completed.

The next maximum-effort pass returned `VERDICT: SHIP` after live hostile probes.
Its two low-severity notes were also closed: actionable and malformed markers
for one target collapse to one list/status row, and the final marker-directory
sync uses the same post-commit diagnostic. A final narrow Opus 5 pass tested
those exact repairs, returned `VERDICT: SHIP` with no findings and left the
repository unchanged.

### Final lifecycle-artifacts evidence

- 157 Rust tests across core, CLI, MCP and compatibility suites
- warnings-as-errors formatting, Clippy, rustdoc and structural ceilings
- Cargo advisory, license and source policy plus npm checks and audit
- hostile MCP probes at the 128/129 combined-entry boundary
- live forced post-commit cleanup failure with recovery-state verification
- malformed, ambiguous, duplicate and mixed rollback-marker probes

Linux-only home-view and non-UTF-8-entry paths remain CI-gated rather than
executed on this macOS host. Dibs registration was unavailable to the read-only
Opus sessions, so these reviews were not recorded on the board.

## Stable identity, private credentials and adapters, 2026-08-26

### Before implementation

Claude Code Opus 5 inspected `main` at `f4e0a95` in maximum-effort, read-only
mode. The first attempt was stopped after the unavailable Dibs MCP integration
prevented useful output; the review was rerun with an explicit empty MCP
configuration and completed normally.

The review returned `VERDICT: PROCEED`. It judged Quarters worth building,
useful and feasible within its same-UID boundary, and changed the implementation
order to make stable identity and recoverable rename prerequisites for private
agents and OpenSSH adaptation. It explicitly rejected presenting cooperative
freeze as enforcement and deferred export until an authentication-key story
exists. It also required old snapshot binding across upgrade and rename,
socket-protocol evidence instead of path existence, collision-safe adapters,
host-path bypass disclosure and representative tool evidence.

Final implementation and security acceptance for this phase is recorded only
after the local security scan, all gates, installed-binary E2E and a separate
Opus 5 ship verdict complete.

### First implementation review

The first maximum-effort, read-only implementation review returned
`VERDICT: DO NOT SHIP`. It identified three high-severity defects: stale active
agent state could remain pinned by PID reuse, OpenSSH's option parser split an
unquoted per-space known-hosts path, and space removal could orphan a live
private agent holding keys. It also found incomplete bundled-`-F` parsing,
nested Linux runtime drift, static adapter claims in doctor output, private
agent keys disabled by the generated SSH policy, unbounded aggregate MCP socket
probing, weak launch preflight, a permissive home-view sentinel and runtime
cleanup/re-key gaps.

The implementation was revised across those boundaries rather than accepting
them as residual risk. Adversarial tests now cover disconnected exact sockets,
an unrelated live recycled PID, active-agent removal refusal, bundled and
remote `-F`, paths containing spaces, stale doctor routes, real ephemeral-key
loading, rollback adapter recreation and schema-1 runtime re-keying. A fresh
Opus verdict is required after the complete local gate and installed-binary
walkthrough; the initial non-ship verdict is not superseded until that review
explicitly returns `VERDICT: SHIP`.

### Second implementation review

The next fresh maximum-effort pass again returned `VERDICT: DO NOT SHIP`. Its
two high findings were concrete OpenSSH credential regressions: bare `ssh-add`
could load passwd-home defaults into the private agent, and a shared option
arity table let `ssh -D ... -F`, `ssh -X -F` and `sftp -s ... -F` bypass the
managed configuration. Medium findings covered stale-agent doctor failure,
unbounded aggregate CLI status, a cross-platform forged home-view sentinel and
silent host-tool fallback after launcher relocation. Lower findings covered
argv handoff metadata, unrecoverable disconnected stopping state, quadratic
artifact source lookup, legacy-artifact rename binding, and unused visibility
widening.

All were addressed or made fail-closed with explicit disclosure. In
particular, bare/default and keychain `ssh-add` imports are refused, each
OpenSSH tool has its own option grammar, stale doctor remains usable, aggregate
status skips live agent probing, macOS ignores the Linux-only bypass, launch
warns on incomplete managed links, stopping recovery never signals an
unverified PID, legacy bindings block rename, artifact lookup is indexed, and
the unused visibility changes were reverted. New regressions cover every
reported bypass and failure mode. A later explicit ship verdict is still
required.

### Third implementation review

The third maximum-effort pass verified every prior finding as resolved, then
returned `VERDICT: DO NOT SHIP` for two newly identified edge cases. In Linux
home-view, a host PATH entry beneath the overmounted home could resolve a
managed OpenSSH name back to the running Quarters inode and recurse. Invoking
creation through the documented `qts` symlink could also leave a published
space without its managed command set on platforms where `current_exe()`
retains the symlink spelling. Two lower findings concerned discarded MCP error
hints and a rename-marker ceiling that blocked recovery with the same limit it
reported.

All four were repaired. Host-tool lookup skips the running executable by
device/inode and direct recursive dispatch has a parent-PID guard. Launcher
paths are canonicalized before installation, with a process test that creates
a complete space through a `qts` symlink. MCP diagnostics retain bounded
recovery hints. Rename inspection counts every valid marker while recovery
drains at most 128 actionable records per pass, so repeated recovery remains
bounded and makes progress. Retained ambiguous markers are inspected but do not
consume that progress budget, so they cannot starve a later actionable record.
Regression coverage also proves the managed SSH
configuration resolves exactly one `IdentityFile` entry.

The final independent verdict is recorded only after the repaired tree passes
the complete local and installed-binary gates.

### Fourth implementation review

The fourth maximum-effort pass verified all carried findings and found two
remaining ship blockers. Linux home-view could cover an absolute launcher
installed beneath the host home, leaving the managed OpenSSH links unreachable.
The getting-started guide also suggested renaming immediately after a legacy
upgrade even though pre-upgrade artifacts deliberately block that operation.
Lower observations covered released pre-alpha.4 runtime spelling, OpenSSH
quoting evidence for quote/backslash path bytes, embedded MCP launcher policy
and the linear cost of complete rename-marker scans.

The home-view launcher now publishes its own protected five-command set in the
private runtime bin before mounting, with collision-safe verification and a
directory sync. The tutorial states the artifact precondition. Runtime lookup,
migration and removal recognize both the released FNV spelling and the
transition identity, accepting exactly one predecessor and refusing ambiguous
state. Compatibility acceptance runs OpenSSH from a store path containing
spaces, quotes and backslashes; hard-link and poisoned-host-PATH regressions
exercise executable-identity exclusion. Standalone MCP now resolves its
canonical launcher before serving, while the in-memory test transport
explicitly has no launcher authority. Documentation records that rename
recovery bounds mutations but performs a complete linear same-UID scan.

A later explicit ship verdict is still required.

### Fifth implementation review

The fifth maximum-effort pass verified five of the six carried fixes and found
one remaining Linux capability defect. The home-view launcher copy is a
different inode from a system-installed Quarters binary, so an overmounted
host-home PATH entry could resolve a managed OpenSSH name to that other binary
and hit the recursion fuse instead of reaching OpenSSH. A lower cleanup finding
covered a staged launcher retained after failed rename; informational notes
requested clearer rename-scan documentation and avoiding the agent ownership
token in a private temporary filename.

Host-tool lookup now canonicalizes each candidate and skips both the running
device/inode and every candidate resolving to a basename of `quarters`. The
regression models distinct runtime and system launchers before a real fallback.
Failed runtime publication removes its exact staging file, with collision
coverage. Architecture documentation now states the complete linear marker
scan and 128-success mutation bound. Agent registry staging uses the existing
process/time/counter unique suffix rather than the ownership token.

A later explicit ship verdict is still required.

### Sixth acceptance review

The sixth maximum-effort read-only pass verified the fifth-pass repairs from
source and re-audited the cumulative alpha surface. It confirmed that
canonical basename rejection closes both Linux installation layouts, that the
device/inode and basename regressions exercise independent guards, and that
failed runtime publication leaves no staging residue. It also verified the
token-free registry staging name, complete linear rename scan disclosure,
stable identity/runtime migration, agent peer verification, OpenSSH policy,
MCP bounds and same-UID non-boundary statements.

Claude's environment denied compiler execution, so this pass was source-only;
the local `make check`, dependency policy and installed-binary evidence remain
separate acceptance inputs. The reviewer independently counted the conditional
test inventory and reconciled it to the 201 tests run on macOS. Its remaining
observations were informational availability, same-UID and Linux-composition
residuals, not authority or data-isolation defects.

The explicit final verdict for the exact tested implementation tree was:

> VERDICT: SHIP

## Stable-identity security hardening, 2026-08-26

Codex Security scan `dfb84c4f-7ba7-4af0-a853-f314670c5df8` inspected exact
commit `51b2a65063ee52cf7408c64b99433a53c9cdeb19` and reported four medium and
six low findings. The repaired tree now binds staging and removal roots to
retained filesystem generations, validates persisted launcher ancestry, fully
parses SSH-agent replies, separates filesystem work budgets from result
ceilings and retains generation-safe process handles through shutdown.

Claude Code Opus 5 first returned `VERDICT: REPAIR REQUIRED`. It confirmed four
blocking paths: Linux home-view entered a descriptor behind the bind mount,
ordinary spaces consumed the rollback-marker limit, damaged-home removal could
not safely distinguish agent state, and several filtered directory scans had
no total-work bound. Each path received direct regression coverage.

A second Opus pass found that `pidfd-util::try_wait` relied on child-only
`waitid`, which fails for the ordinary later-process stop topology. Linux now
uses rustix `pidfd_open`, `pidfd_send_signal` and readiness polling on the
retained pidfd. Its Linux-only test creates a verified orphaned non-child,
signals it through the pidfd and observes exit without resolving the numeric
PID again. An exact `x86_64-unknown-linux-musl` all-targets check passes.

The final safe-mode, read-only Opus 5 pass returned
`VERDICT: READY FOR HOST-FORK PHASE`. Its nonblocking determinism notes were
also closed by enabling rustix `std` explicitly and asserting the regression
target's parent differs from the polling test process.

Local evidence on this checkpoint:

- `make check`: 209 Rust tests and 4 typed npm launcher tests
- warnings-as-errors Clippy and rustdoc, formatting and structural ceilings
- `cargo deny check`: advisory, ban, license and source policy pass; only the
  approved transitive `syn` 2/3 duplication warning remains
- `cargo audit --deny warnings`: pass
- `x86_64-unknown-linux-musl` all-targets core check: pass
- `git diff --check`: pass

## Host-fork implementation review, 2026-08-26

Claude Code 2.1.233 ran the latest Opus 5 in safe, read-only mode against the
complete host-fork implementation. Its first substantive pass returned
`VERDICT: REPAIR REQUIRED` for two issues: symlink-managed optional dotfiles
made the entire shell preset unusable, and the accepted ADR named security
invariants without direct adversarial evidence.

Optional preset links and unsafe entries are now content-free, digest-bound
`ineligible` rows; the same path explicitly requested remains a hard error.
Tests directly exercise missing explicit presets, case-folded sensitive paths,
hard links, FIFOs, writable files and homes, absolute and parent paths,
per-file, total-byte and explicit-path limits, a HOME beneath the store, and a
source truncation after staging with no destination or residue. Unit evidence
covers duplicate filesystem identity and the sensitive-path classifier.

The repair also states that selected file contents remain uninspected and may
embed secrets. Copied zsh and bash interactive startup files receive a constant
tail that reasserts the private history path before prompt integration.
Human and JSON previews expose the complete bounded selected, absent and
ineligible path sets without content or content-derived hashes. MCP retains its
three-tool catalog and rejects a `from_host` create parameter.

Opus rechecked every carried finding and returned `VERDICT: SHIP`. A final
delta-only pass then verified exact human path disclosure, stable symbolic-link
reasoning, portable POSIX mode checks and Linux pidfd lint repairs. Its verdict
for the final source tree was again:

> VERDICT: SHIP

Final local evidence on the reviewed checkpoint:

- `make check`: 220 Rust tests and 4 typed npm launcher tests
- warnings-as-errors Clippy and rustdoc, formatting and structural ceilings
- `cargo deny check` and `cargo audit --deny warnings`: pass; only the approved
  transitive `syn` 2/3 duplication warning remains
- Rust 1.97.1 `x86_64-unknown-linux-musl` all-targets core Clippy with warnings
  denied: pass
- release-installed macOS host fork: content-free preview, exact confirmation,
  interactive zsh execution, private history, provenance and status all pass
- `git diff --check`: pass

## Authenticated portable-bundle review, 2026-08-27

Claude Code 2.1.233 used Claude Opus 5 at maximum effort in read-only mode
before implementation. It judged authenticated, plaintext template and snapshot
bundles useful and feasible within Quarters' stated same-account boundary. The
plan was revised through its findings until it returned
`VERDICT: READY TO IMPLEMENT`.

The first implementation audit returned `VERDICT: REPAIR REQUIRED` with eight
findings: parent-relative link and maximum-depth mismatches, incomplete early
header validation, unsafe foreign-field presentation, store-internal keys,
ambiguous post-commit errors, whole-tree parser metadata retention and an
incomplete key-transfer tutorial. All were repaired. A fresh independent
read-only bypass review then found three residual paths: pathname check/use
races around keys, one unbounded human shell-path field and missing receiver
parent setup. The final implementation retains protected parent descriptors
through key and bundle use, rejects descriptor ancestry beneath the active
store, keeps pre-authentication metadata proportional to active depth, shares
link and header validators with artifact state, and reports post-commit
durability uncertainty without claiming publication failed.

Opus re-derived all eleven repairs from source and returned `VERDICT: SHIP`.
Its three remaining low-severity UX observations were also closed: both key
help strings now state the complete path contract, symlinked store roots reuse
the standard precise diagnostic, and in-store key errors use source-appropriate
wording. A narrow final pass found no regressions or incomplete fixes and again
returned:

> VERDICT: SHIP

Claude remained read-only and could not execute compiler gates. Final local
evidence is separate:

- `make check`: 242 Rust tests and 4 Bun-managed typed npm launcher tests
- warnings-as-errors Clippy and rustdoc, formatting and structural ceilings
- `cargo deny check` and `cargo audit --deny warnings`: pass; only the approved
  transitive `syn` 2/3 duplication warning remains
- Rust 1.97.1 `x86_64-unknown-linux-musl` all-targets Clippy with warnings
  denied: pass
- release-installed macOS export, transfer, authenticated preview, import,
  template use, state content and parent-relative link round trip: pass
- sender and receiver key directories mode `0700`; transferred key and bundle
  mode `0600`: pass
- `git diff --check`: pass

Dibs registration was attempted by the reviewer but blocked by its read-only
permission layer. This did not affect implementation or acceptance evidence.

## Alpha.4 P0 planning and private-agent review, 2026-08-27

Claude Code 2.1.233 used Claude Opus 5 at maximum effort in read-only mode
before implementation. It judged the broader native userspace-virtualization
roadmap worth building and feasible when Quarters preserves its honest
same-account boundary. It returned `VERDICT: READY FOR IMPLEMENTATION` after
prioritizing the alpha.4 version boundary, physical Linux evidence and the
private-agent concurrency flake ahead of broader confinement work.

The first implementation review returned `VERDICT: REVISE P0` for a spawned
launcher that could outlive a failed activation commit and a lifecycle-lock
deadline shorter than its own shutdown work. Startup now uses a separate
close-on-exec owner lease, exact registry revalidation, bounded cleanup and an
absolute protocol deadline. The lifecycle budget dominates verified shutdown
work, and the Linux acceptance target covers the real home-view, host escape,
XDG runtime fallback and overlong agent-socket behavior.

The next complete read-only pass confirmed both blockers structurally resolved
and returned:

> VERDICT: SHIP P0

Its three nonblocking concurrency observations were closed before publication:
orphan recovery now takes the lifecycle lock before probing the owner lease,
only one observer may publish recovery, and abort rechecks an exact committed
activation under lock before signaling. Claude remained read-only, so local and
hosted compiler evidence remains a separate requirement.

A final narrow pass audited the resulting deadline proof, transient activation
convergence, cleanup semantics, native 20-round six-caller stress test and line
ceilings. It again returned `VERDICT: SHIP P0`. The complete local gate passed
243 Rust tests and 4 Bun-managed launcher tests, warnings-as-errors Clippy and
rustdoc, formatting and structural ceilings. Dependency advisory, licence and
source policy also passed; the approved transitive `syn` 2/3 duplication is the
only `cargo deny` warning. Hosted Linux and macOS results remain required.

### First hosted run and repair

GitHub Actions run `33136834820` supplied the missing host evidence and failed
usefully. Ubuntu and static-musl tests reproduced immediate shortcut inode reuse;
macOS reproduced one pre-readiness OpenSSH-agent exit during repeated six-caller
startup. The implementation was not accepted on the earlier source review alone.

Shortcut removal now compares a symmetric platform-normalized device, inode,
target and change timestamp while documenting that a matching tuple and the
final check/unlink race remain inside the same-UID boundary. Agent startup keeps
one owner lease across one bounded replacement generation, publishes the fresh
token and PID atomically while already holding the lifecycle lock, lets observers
follow only a validated replacement, and caps all followed generations at ten
seconds. A debug-only, private-runtime fault marker forces the first launcher to
exit; separate 20-round tests cover both injected and ordinary six-caller starts.

Opus first returned `VERDICT: REVISE P0 REPAIR` with four blockers: release-only
unused import failure, an overclaim about change-time discrimination, a retry
spawn/deadline inversion and asymmetric macOS device normalization. All four
were corrected. Its complete re-review returned `VERDICT: SHIP P0 REPAIR`; the
three remaining nonblocking observations were then closed. The final delta-only
pass again returned `VERDICT: SHIP P0 REPAIR` with no blockers. Claude remained
read-only and did not execute compiler gates.

### Second hosted run and repair

GitHub Actions run `33344130609` then exposed two independent test-contract
defects. Ubuntu and static-musl correctly rejected a test launcher placed below
world-writable `/tmp`; macOS reproduced a concurrent-removal loser reporting
corrupt state after the winner had already retired the exact space. Dependency
licence/source and RustSec jobs passed.

The launcher fixture now lives below the protected test-executable ancestor, so
the test exercises the production ancestry policy instead of bypassing it.
Removal now holds the existing management lease across exact identity lookup,
private-agent absence proof and atomic retirement. Exact absence is represented
as `Ok(None)`, not inferred from a broad error category or a post-error path
sample. Deterministic tests preserve corrupt-state reporting for a present space
with no manifest and prove that present and dangling space links are never
followed. The same-name removal race passed one hundred consecutive local runs.

Opus initially returned `VERDICT: REVISE P0 REPAIR` because the first attempted
repair matched a coarse `NotFound` category and only narrowed the timing window.
After the lease-scoped design replaced that approach, its complete re-review
confirmed the earlier blockers closed and returned:

> VERDICT: SHIP P0 REPAIR

The review's remaining coverage suggestion for present and dangling space links
was also implemented before publication. The final local gate passed 246 Rust
tests and 4 Bun-managed launcher tests, warnings-as-errors Clippy and rustdoc,
formatting and structural ceilings. Release and `x86_64-unknown-linux-musl`
all-target builds, dependency policy and RustSec auditing also passed. Claude
remained read-only and did not execute compiler gates.

## Alpha.4 storage expand foundation, 2026-08-30

Claude Code 2.1.233 used Claude Opus 5 at maximum effort in read-only mode for
the expand-only root-format foundation. The first complete review returned
`VERDICT: REVISE`: legacy removal could lose its validated category anchor, an
interrupted two-link marker publication was unreadable, a FIFO swap could block
a marker open, staging diagnosis could mask newer or migrating formats, and
diagnostic output and path construction needed tighter bounds and ownership.

The implementation now resolves visible and dotted layouts through one strict
marker reader, keeps dotted stores inspection-only, derives mutation paths from
a management-held layout token, validates category anchors, reads markers with
nonblocking no-follow descriptors, converges only the exact visible two-link
publication state, and exposes bounded non-mutating diagnosis to the CLI and
MCP server. Ordinary reads never materialize marker or observation state.

The second full review found one medium truthfulness defect: reserved staging
damage made `doctor` claim a valid visible store was read-only even though
normal mutations remained permitted. Opus also identified low-severity cleanup
and presentation gaps. Diagnosis now preserves the authoritative format and
writability while reporting staging damage separately; human and JSON/MCP
output expose bounded itemization and its lower-bound count; marker failures
are surfaced; orphan staging is reclaimed on explicit initialization; missing
optional trash does not block unrelated launch; existing trash must validate;
and a named doctor request still returns store diagnosis when space inspection
is impossible.

During the exact full gate, the injected private-agent concurrency test then
reproduced a real pre-existing atomic-replacement race. A helper could retain
the just-retired registry inode after its link count became zero and mistake it
for a malicious hard link. Registry reads now use a bounded stable-snapshot
loop with pre-open, descriptor and post-read identity checks. Only exact inode
retirement or replacement retries; symlinks, real hard links, broad modes,
foreign ownership, oversized content and sustained churn still fail closed.
Deterministic retired-inode and real-hard-link tests pass, as do one hundred
consecutive six-caller injected-exit rounds.

Opus re-derived the repaired invariants and returned `VERDICT: ACCEPT`. Every
remaining low observation was then addressed or tested, including the unlocked
marker-reader convergence race and uninitialized removal semantics. Its final
narrow delta pass found no high or medium issue and again returned:

> VERDICT: ACCEPT

Claude remained read-only and did not execute compiler gates. Final local
evidence is separate:

- `make check`: all Rust unit and acceptance suites, 152 core tests and 4
  Bun-managed typed npm launcher tests pass
- warnings-as-errors Clippy and rustdoc, formatting and structural ceilings:
  pass
- `cargo deny check` and `cargo audit --deny warnings`: pass; only the approved
  transitive `syn` 2/3 duplication warning remains
- Rust 1.97.1 `x86_64-unknown-linux-musl` all-target workspace check: pass
- injected private-agent replacement stress: 100 consecutive six-caller
  rounds pass
- `git diff --check`: pass

Hosted macOS, Ubuntu, static-musl and dependency-policy jobs remain a separate
acceptance gate after publication of this commit.

## Cooperative freeze and active stationery, 2026-08-30

Claude Code used Claude Opus 5 at maximum effort in read-only mode before
implementation. It rejected a deferred supervisor-request design because exit
did not prove quiescence and delayed capture broke preview and confirmation
semantics. The accepted replacement is an immediate CLI-only capture from the
current Quarter, requiring strict name/root/home evidence, an existing held
cooperative lease and an identity-bound cooperative freeze.

The first complete implementation review returned `VERDICT: REVISE`. It found
that direct marker creation could leave a partial final file after interruption,
stranding the space with no product escape; observation could race publication
or unfreeze; publication did not recheck freeze state; and schema compatibility,
scope wording and maintenance-path coverage were incomplete. Freeze publication
now uses private temporary state plus atomic rename and directory sync. Exact
confirmed unfreeze safely removes malformed identity-bound markers only after
private-file revalidation. Losing reads become unfrozen observations, active
capture rechecks the marker under the management guard, and stale freeze
temporaries are counted and removed by confirmed recovery.

The second complete review independently reproduced the original stranded-marker
case, reran the Rust suites and returned `VERDICT: ACCEPT`. Every remaining low
observation was then closed: all marker errors identify the path and remedy,
unsafe temporary state blocks before unfreeze changes the final marker,
schema-forward clearing is explicit, omitted-name agent/adapter commands and
import provenance are documented, and Linux home-view management limits remain
plainly stated. A narrow final delta review found no regression and again
returned:

> VERDICT: ACCEPT

Final local evidence on the reviewed checkpoint:

- `make check`: all Rust unit and acceptance suites, 158 core tests and 4
  Bun-managed typed npm launcher tests pass
- warnings-as-errors Clippy and rustdoc, formatting and structural ceilings:
  pass
- `cargo deny check` and `cargo audit --deny warnings`: pass; only the approved
  transitive `syn` 2/3 duplication warning remains
- malformed, oversized, linked, broad-mode, newer-schema and interrupted
  freeze-marker cases fail closed or recover through the exact documented path
- frozen launch, enter, agent start, adapter mutation, rename, upgrade, rollback
  and removal refusal; agent maintenance; clone/snapshot/template reads; and
  active-capture provenance round trips pass end to end
- `git diff --check`: pass

The separate managed Codex deep-scan worker could not start because the parent
session did not expose a managed filesystem permission profile. No scan result
is claimed; the read-only Opus review and local security gates above are the
available evidence. Hosted macOS, Ubuntu, static-musl and dependency-policy
jobs remain a separate acceptance gate after publication of this commit.

## Linux Landlock confinement, 2026-08-30

Claude Code 2.1.233 used Claude Opus 5 at maximum effort in read-only mode
before implementation. The review took five explicit iterations. It first
rejected a broad, brittle allowlist and identified store-dependent adapters,
host-home toolchains, cwd semantics, `/proc` claims and ABI truncation coverage.
Subsequent passes required a reconstructed PATH, Nix and resolver handling,
precise metadata limits, required hosted enforcement and an unconfined control
arm for proc evidence. The final pre-implementation verdict was:

> VERDICT: ACCEPT

The accepted design requires Landlock ABI 3, hard compatibility,
`no_new_privs` and `FullyEnforced`; grants only the exact Quarter home/runtime
plus fixed reported system paths; blocks store operations without treating the
environment marker as authority; and reports known-path metadata, proc,
network, IPC, device, same-UID and inherited-descriptor limits explicitly.
Claude remained read-only and did not execute compiler or kernel gates. Final
implementation review and local/hosted evidence are recorded separately after
the code is complete.

The first complete implementation pass returned `VERDICT: REVISE` with five
blockers. It found a post-mount plan rebuild that broke the default home-view
topology, an unbounded resolver-parent grant, custom stores that could overlap
system grants, an unreadable JSON PATH representation and canonical PATH aliases
counted as omissions. Quarters now opens every inode-backed rule anchor before
an optional home-view mount and enforces that prepared ruleset afterward; grants
only the exact derived resolver file; rejects stores beneath broad system
hierarchies; and reports bounded, readable paths with explicit provenance.

Two review iterations then repaired the acceptance evidence itself. The
composition test now places a private temporary store beneath the canonical
passwd home so the mount genuinely hides its path, without touching the user's
real store. Optional home-view availability is separate from the required
Landlock gate. Linux-target Clippy exposed three target-only denied lints before
runtime execution; all were refactored without suppression, and the complete
Linux-musl warnings-as-errors check now passes. Runtime placement also excludes
both environment and passwd homes, and the proc witness has fail-safe process
cleanup.

The final read-only Opus 5 maximum-effort pass re-derived the namespace ordering,
descriptor lifetime, hard ABI compatibility, full-enforcement condition,
store/path policy, fail-closed macOS behavior and Linux test topology. It ran
host tests plus Linux-musl all-target Clippy and returned:

> VERDICT: ACCEPT

Final local evidence on the accepted checkpoint:

- `make check`: Bun-managed launcher checks and audit, formatting, host Clippy,
  all host unit and acceptance suites, structural ceilings and warning-free
  rustdoc pass
- `make dependencies`: licence/source policy and RustSec pass; only the approved
  transitive `syn` 2/3 duplication warning remains
- Rust 1.97.1 `x86_64-unknown-linux-musl` all-target, all-feature Clippy with
  explicit `-D warnings`: pass
- `git diff --check`: pass

The macOS host cannot execute Landlock. Hosted Ubuntu with
`QUARTERS_REQUIRE_LANDLOCK=1` remains the required real enforcement gate after
publication; source checks and reviewer acceptance do not substitute for it.

The first hosted execution proved the required Ubuntu enforcement matrix after
the POSIX shell witness repair, then exposed a static-musl portability failure:
the headless runner had no controlling terminal and policy preparation refused
`/dev/tty`. A first attempted repair used `PathFd` as a usability preflight.
Opus rejected it because `O_PATH` does not prove device usability and because
silently omitting every open error would hide descriptor exhaustion, permission
failure and path races.

The accepted repair probes only optional `/dev/tty` with ordinary read-write
access. It omits only an absent node or Linux `ENXIO` (no controlling terminal),
while every other probe failure remains fatal. Available terminals rejoin the
ordinary canonical grant path, and Landlock separately opens every reported
anchor or aborts the launch. Direct Linux-target tests pin the omittable and
fatal errno classes. A final read-only maximum-effort Opus pass re-read the
complete launch ordering, policy builder, tests and ADR, found no high or medium
issue and returned:

> VERDICT: ACCEPT

Fresh hosted Ubuntu and static-musl execution remain mandatory for the repaired
checkpoint; the prior successful Ubuntu gate does not substitute for that
rerun.

## Remaining-program architecture, 2026-08-31

Claude Code used Claude Opus 5 at maximum effort in three read-only passes over
the complete post-Alpha-4 program. The first pass returned `VERDICT: REVISE`.
It rejected physical store migration while released Alpha 1 and Alpha 2 readers
can ignore the marker, rejected an encryption capability whose online lock
cannot be guaranteed, and found no supportable macOS confinement backend under
the project's public-API and distribution constraints. It also required Linux
workspace grants to remain data-only, default-Ubuntu user-namespace evidence,
truthful Linux arm64 registry documentation, a discovery privacy contract,
TIOCSTI reporting and macOS refusal tests.

The second pass found that fresh dotted stores have the same old-reader hazard
as migrated stores, that the unreleased dotted-store error promised a migration
release no longer scheduled, and that cross-platform grant flags needed an
explicit macOS contract. The plan now gates every dotted writer and physical
migration until incompatible readers can be prevented from mutating the shared
store, corrects the Alpha 4 error before publication, refuses Linux-only grants
on macOS and keeps portable working-directory selection separate from access
authority.

The third pass re-read the revised plan and current diff, confirmed that all
high and medium blockers were closed, and returned:

> VERDICT: APPROVE

The accepted order completes four-target npm and PyPI distribution before new
capabilities, then implements invocation-local Linux data grants, default-policy
CI evidence, storage-contract cleanup and privacy-bounded CLI discovery.
Seatbelt, App Sandbox, idmapped mounts, per-space encryption and LaunchServices
GUI capture are not represented as weaker features under stronger names.

## Alpha 5 Linux grants and home-view composition, 2026-09-01

Claude Code used Claude Opus at maximum effort in read-only mode throughout
the Alpha 5 implementation. An early complete checkpoint at `524823c` returned
`VERDICT: ACCEPT` with three nonblocking observations: complete the TIOCSTI
JSON binding, split the Linux acceptance file before its structural ceiling and
centralize duplicated home-view working-directory mapping. Those changes landed
in `7eacab3`, whose hosted matrix appeared green in run `33584150117`.

An exact re-review rejected that checkpoint. The centralized resolver had
revalidated a mapped Quarter-home workdir at its post-mount passwd path before
the mount existed, and GitHub runner supplementary groups caused every real
home-view execution to skip. Quarters repaired the resolver and added a
dedicated `setpriv --clear-groups` acceptance step that requires both home view
and Landlock and fails if the exact composition test is absent or skipped.

Making the hidden path executable exposed the real kernel behavior rather than
producing another cosmetic green gate. Hosted runs rejected, in order, a
post-mount identity mismatch at `53a3f49`, a proc-descriptor bind target at
`15f3ec1`, `open_tree(OPEN_TREE_CLONE)` at `ec7b8f5`, a proc-descriptor bind
source at `ed19920`, and `move_mount` of the attached staging mount at
`ae071a8`. The accepted implementation uses only namespace-owned recursive
binds: it stages the source below the private runtime, verifies the mounted
device and inode against a pre-opened descriptor, revalidates the passwd-home
target, attaches the verified staging mount inside the private namespace,
detaches staging and verifies the final home view before process replacement.

Opus returned `VERDICT: ACCEPT` on `5442ec9` and identified additional
nonblocking hardening. Quarters then detached the staging path, proved its known
Quarter-only child is absent after attach, required Landlock and home-view
capabilities independently, and documented both the residual same-UID
passwd-parent target race and the fact that home view is reversible path
compatibility rather than confinement. The first broad capability assertion at
`ab1549c` correctly failed ordinary hosted CI because supplementary groups make
home view unavailable there; `bc5ec6b` corrected the test contract while the
dedicated cleared-group step continued to require both capabilities.

The final exact-head, clean-worktree Opus maximum-effort review of `bc5ec6b`
re-derived mount propagation, detach lifetime, inode checks, Landlock ordering,
test non-vacuity and documented boundaries and returned:

> VERDICT: ACCEPT

Final evidence on the accepted source checkpoint:

- local `make check`: Bun launcher checks and audit, formatting, host Clippy,
  all unit and acceptance suites, structural ceilings and warning-free rustdoc
  pass
- `x86_64-unknown-linux-musl` workspace, all-target, all-feature Clippy with
  explicit `-D warnings`: pass
- hosted push run `33588714585` and pull-request run `33588716967`: all six
  jobs pass, including the non-skipping home-view plus Landlock composition,
  default-policy refusal, macOS, static musl, release smoke, RustSec and
  dependency licence/source policy
- `git diff --check`: pass

The managed Codex deep security scan remains unavailable because this host
session exposes an unmanaged/disabled filesystem permission profile, so no
deep-scan result is claimed and pull request 8 remains unmerged. Dibs was known
to be unavailable during this phase and was not treated as an acceptance gate.

## Alpha 6 storage-contract cleanup, 2026-09-01

Claude Code used Claude Opus at maximum effort before implementation. The
read-only review of clean checkpoint `1f3cf28` confirmed that the unreleased
`.quarters-store-migration.json` sidecar was only read: no command created,
cleared or recovered it. A same-UID process could therefore plant a permanent
store-wide denial while the architecture simultaneously stated that no active
migration state existed. The review accepted removal with two required
documentation corrections: any future physical migration must publish a newer
authoritative root-marker schema before changing a category directory, and the
removed doctor/MCP field must be described as unreleased rather than as a
shipped JSON-contract break. It returned:

> VERDICT: ACCEPT

The implementation at `6c4b640` removed the runtime refusal, diagnosis state
and doctor/MCP field while retaining visible-only writers, dotted read-only
inspection, dual-layout detection, strict marker handling, bounded staging
diagnosis and the management-held writable-layout token. Tests prove the
retired filename is inert and preserved, cannot make a dotted store writable,
and cannot outrank dual-layout failure. CLI acceptance proves ordinary doctor
and creation continue without deleting the file. MCP acceptance now validates
successful and failed `quarters_doctor` structured output against its
advertised closed schema and proves that schema omits `migration_marker`.

An exact-head Opus review re-derived the error precedence, unlink reachability,
schema references, test non-vacuity, released-tag history and every retained
`SpaceActive` exit-code path. It returned `VERDICT: ACCEPT` with nonblocking
coverage and prose observations. Checkpoint `b6da2a3` then extended the doctor
schema proof to both official protocol families, 2026-07-28 and 2025-11-25,
drove the core preservation test through `ensure_layout` and staging
reclamation, and repaired the prose. A second exact-head Opus review reran the
gates, confirmed every requested correction and returned:

> VERDICT: ACCEPT

Final evidence on the accepted source checkpoint `b6da2a3`:

- local `make check`: Bun launcher install/typecheck/tests/audit, formatting,
  host Clippy, all unit and acceptance suites, structural ceilings and
  warning-free rustdoc pass
- dependency advisories, bans, licences and sources: pass
- `x86_64-unknown-linux-musl` workspace, all-target, all-feature Clippy with
  explicit `-D warnings`: pass
- hosted push run `33591513238` and pull-request run `33591518639`: all six
  jobs pass on the exact source checkpoint, including macOS, Ubuntu, static
  musl, default-policy refusal, RustSec and dependency policy
- `git diff --check`: pass

The managed Codex deep security scan remains unavailable under this host
session's unmanaged/disabled filesystem permission profile. No deep-scan result
is claimed. Pull request 9 remains unmerged and stacked on the likewise
unmerged pull request 8.
