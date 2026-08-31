# ADR 0008: Verifiable lifecycle artifacts and three-state rollback

Status: accepted for implementation

## Context

Clone can create an independent writable Quarter, but it cannot provide named
stationery, recovery points or guarded replacement. Those operations persist
credential-bearing copies and introduce an on-disk format plus a destructive
two-rename transition. Quarters remains a same-UID state tool: detached writers
are unknowable and another process with the same account authority can modify
its store.

## Decision

Templates and snapshots are additive private roots, `.templates` and
`.snapshots`. Published entries use random 128-bit IDs; display names live only
in strict manifests. Existing `spaces` and `trash` remain authoritative, so the
ADR 0006 expand/migrate/contract gate applies only to their future `.spaces` and
`.trash` migration. Artifact roots never signal that future root format.

Artifact creation uses the accepted descriptor-relative lifecycle walker. Its
creation-source mode omits and counts sockets, FIFOs, devices and foreign-owned
entries, materializes hard-linked files independently, omits requested cache
roots and hashes only stored output. Published-verification mode rejects any
special, foreign-owned, unclassifiable or multiply-linked entry. Both modes
compare entry metadata before open, after open and after read; clone adopts the
same stronger post-read race check.

Content integrity is BLAKE3-256 over the canonical byte stream specified in the
approved lifecycle-artifacts plan. It detects accidental or out-of-band change;
it is not authentication against the same UID. No digest-bound mode changes
after finalization. Filesystem immutability flags remain optional future
hardening.

Non-cloneable management and lifecycle-lease tokens make lock ownership
explicit. Whole-tree copy and hashing never hold the global management token.
Rollback verifies first, then holds management continuously across a portable
three-state transition: `prepared`, `retired`, `published`. The visible state is
old, new or marked in progress—not an atomic exchange. Recovery validates state,
identity and filesystem tuples and never guesses. Recovery first moves the
durable marker to a state whose next filesystem tuple remains accepted on
retry; once the marker is removed, leftover staging is an independently
reclaimable orphan. Initial and replacement marker writes use a private
temporary file, atomic rename and parent-directory sync. An automatic named
recovery snapshot precedes replacement.

Recovery budgets are bounded per reserved family. Existing trash retirement
and reclaiming entries move from one shared 1,024-entry scan to independent
1,024-entry families; this deliberate expansion prevents one family from
starving another. Unknown hidden entries are counted but never removed.
Malformed reserved-looking names are unknown rather than transaction state and
cannot deny unrelated spaces or recovery. Malformed exact markers and exact
valid markers with ambiguous tuples are retained as itemized issues. A known
target is blocked only by its own issue; actionable unrelated transactions and
other recovery families continue.

## Consequences

- Artifact names can change without moving content.
- Snapshot verification is whole-tree and can cost up to the declared limits.
- Artifact sources reject empty owner-inaccessible directories so every
  published artifact remains verifiable.
- Cache exclusion is true omission; consumers recreate only the exact missing
  directory skeleton guaranteed for their recorded layout.
- Rollback preserves the target manifest identity and rejects cross-platform
  snapshots.
- Alpha.3 readers do not understand rollback markers after a crash. New recovery
  preserves every conflicting tree and reports the incompatibility rather than
  overwriting it.
- MCP gains observation of rollback-in-progress state but no lifecycle mutation
  authority.
- ADR 0010 adds schema-3 local source evidence and an immediate active capture
  path. It preserves this ADR's canonical staging-tree verification while
  replacing exclusive source evidence with an explicit `frozen-active` class.

## Acceptance

The normative command, byte-format, recovery tuple, fault-injection and
portability gates are in
`docs/feedback/LIFECYCLE-ARTIFACTS-IMPLEMENTATION-PLAN.md`. Implementation ships
only after macOS installed-command tests, Linux and musl CI, dependency policy,
strict structural gates and independent Claude Opus review pass.
