# ADR 0005: Explicit private-agent lifecycle

Status: proposed; required before any agent socket is advertised

## Context

Setting a socket environment variable does not start an agent. The first live
walkthrough exposed this distinction when `SSH_AUTH_SOCK` pointed at a path
with no listener. SSH, GnuPG and long-running tool servers also differ in
protocol, lifecycle, credential authority and cleanup.

## Decision

Model each supported agent as an explicit state machine:

```text
unset -> starting -> active -> stopping -> unset
             |          |
             +-> failed <-+
active -> stale, when identity or liveness verification fails
```

The baseline exports no SSH-agent socket. A future `quarters agent` surface
must support `status`, `start`, `stop` and `restart` for a closed adapter set.
Only a successfully started, identity-verified private agent may add its socket
to a launch environment.

Each agent receives a runtime directory derived from the stable space identity,
private mode, a bounded startup deadline and a first-party ownership record.
Liveness requires a protocol-aware check where available, not socket existence.
PID files alone are never trusted. Stop verifies recorded process identity and
removes only owned runtime entries. Stale state is reported separately and
requires a narrow recovery path.

Host-agent use is a separate explicit adapter. It previews the authority being
shared, is off by default and never copies the host socket into persistent
space metadata. `quarters host` continues to clear agent variables unless the
host command receives a future explicit host-agent grant.

No generic daemon runner is part of this feature. SSH agent is the first
candidate; GnuPG must use its native discovery and control contracts rather
than being forced into the SSH model.

## Acceptance gates

- start/status/stop races and crashed supervisors
- stale PID reuse, replaced sockets and symlinked runtime paths
- bounded startup and shutdown with no orphan created on error
- two spaces cannot observe each other's private agent through Quarters state
- host-agent authority requires an explicit, visible choice
- environment and doctor output distinguish every state above
- lifecycle behavior passes on macOS and Linux without shellouts from the core

## Consequences

Agent-backed credentials remain unavailable by default today. The eventual
feature can be useful without repeating the false implication that a reserved
path is a running or isolated service.
