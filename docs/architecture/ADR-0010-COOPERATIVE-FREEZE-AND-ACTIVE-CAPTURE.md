# ADR 0010: Cooperative freeze and active stationery capture

Status: accepted for the portable alpha

## Context

A user should be able to protect a Quarter from accidental Quarters-managed
changes and turn the Quarter they are using into reusable stationery. The
existing supervisor holds a shared activity lease for the child lifetime.
Ordinary template capture requires the exclusive form of that lease, so it
cannot capture the Quarter from inside its own supervised process tree.

Waiting until the supervisor exits does not solve the security problem.
Detached processes and same-UID services can outlive it, the confirmed preview
would describe a different tree from the later capture, and a delayed request
would need session binding, expiry, crash recovery and a completion channel.
Quarters therefore rejects deferred capture as both weaker and more complex.

The operating system still sees every process as the real user. A same-UID
process can write space content or remove a policy marker directly. No marker
can honestly provide filesystem immutability, confinement or encryption.

## Decision

Quarters implements a persistent **cooperative freeze**. A versioned
`.freeze-<space-id>.json` marker lives in the spaces category and is bound to
the stable space identity. Freeze and unfreeze hold the store management guard,
which serializes them with Quarters lifecycle operations. They do not acquire
the exclusive space lease: that would make freezing the currently running
Quarter impossible.

Freeze has this exact contract:

- existing activity continues;
- new `enter`, `exec` and private-agent starts fail before their environment or
  runtime preparation; read-only `env` inspection remains permitted and may
  prepare the private runtime it reports;
- rename, upgrade, rollback, removal and adapter mutation require unfreeze;
- status, list, current, environment inspection and doctor remain available;
- agent status, stop and recovery remain available so a frozen Quarter can be
  made safer;
- clone, template capture and snapshot capture may read a frozen source;
- direct or detached same-UID writers remain possible.

The marker is a current-UID, mode-`0600`, single-link regular file read without
following links and bounded to 4 KiB. Its schema is probed before strict
deserialization. Publication writes a private temporary sibling, atomically
renames it to the visible marker and syncs the spaces directory before success.
An interrupted temporary is replaced by a confirmed retry. Unsafe, oversized
or newer marker state fails closed instead of being treated as unfrozen; exact
`unfreeze NAME --confirm NAME` can remove an identity-bound invalid marker only
when it still passes private-file validation. The marker protects against
accidental product actions, not a malicious process holding the user's authority.

## Active stationery capture

`quarters template create NAME --from-active` is a CLI-only authority. The CLI
resolves the source from `QUARTERS_SPACE` only after reopening a healthy space
and matching both `QUARTERS_SPACE_ROOT` and `QUARTERS_SPACE_HOME`. The core then
requires an already-held cooperative activity lease and a valid freeze marker.
This prevents an inactive space with forged environment variables from being
misreported as an active capture. MCP receives only the additive freeze status
field; it gains no freeze or capture mutation tool.

While holding the store management guard, active capture establishes its own
shared activity lease. The guard is then released before the bounded copy walk.
The freeze marker blocks new managed launches; the shared lease excludes
Quarters lifecycle writers. The already-running process tree and direct
same-UID writers can still change files during the walk.

Artifact integrity is computed over the completed staging tree, then verified
again before atomic publication. Publication also rechecks that the cooperative
freeze remains present. It does not claim the source was a
crash-consistent filesystem snapshot. Artifact schema 3 records one of two
source evidence classes:

- `inactive`: Quarters held the exclusive lifecycle lease;
- `frozen-active`: Quarters observed an existing held cooperative lease, required a
  cooperative freeze and held a shared lease during capture.

Historical schema-1 artifacts remain readable without retroactively inventing
quiescence evidence. Schema-2 imported templates remain external authenticated
provenance and do not acquire local source authority.

## Consequences

The user can freeze, preview and capture stationery without leaving the active
Quarter, and the preview-to-confirm flow still refers to immediate current
state. There are no delayed side effects or orphaned requests. The result is a
self-verifying artifact, not a database-consistent snapshot.

A read-only shell is not part of this decision. Enforceable write restriction
belongs to the separate Linux Landlock and macOS confinement work. Encrypted
storage likewise remains a platform capability, not a property inferred from
cooperative freeze.

## Acceptance

- freeze succeeds while the supervisor's shared lease is held;
- frozen launch and agent-start paths fail through the core lease gate;
- launch refusal occurs before private runtime creation;
- the documented mutation matrix is covered end to end;
- active capture without freeze, without current-path evidence or without a
  pre-existing held cooperative lease fails closed;
- a frozen-active template verifies and recreates the captured content;
- marker symlinks, hard links, broad modes, oversize and newer schemas fail
  closed;
- macOS and Linux execute the same portable policy and artifact tests.
