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

## Dibs availability

The final Codex session checked callable tools, MCP resources and MCP resource
templates. No Dibs server or Dibs tool surface was available, so registration
or agent messaging could not be performed from this session. Work continued
without treating that integration as a blocker.
