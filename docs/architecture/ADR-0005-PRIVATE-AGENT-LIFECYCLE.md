# ADR 0005: Explicit private-agent lifecycle

Status: accepted for OpenSSH; other agent protocols remain separate work

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

The baseline exports no host SSH-agent socket. The implemented `quarters agent`
surface supports `status`, `start`, `stop`, `restart` and confirmed narrow
recovery for OpenSSH.
Only a successfully started, identity-verified private agent may add its socket
to a launch environment.

The agent receives a runtime directory derived from the stable space identity,
private mode, a bounded startup deadline and an atomic first-party ownership
record. The launcher uses the current Quarters executable only for an
environment-carried token and PID handoff, then clears its environment and
replaces itself with fixed `/usr/bin/ssh-agent -D`; no shell
or PATH lookup is involved. Liveness sends a bounded SSH identities request and
requires the corresponding protocol response while comparing the socket device
and inode before and after the exchange. The kernel-reported peer PID must also
match the ownership record. PID files alone are never trusted.

Stop first re-verifies the active process, exact socket identity, peer PID and
protocol, records `stopping`, repeats the complete socket proof immediately
before signaling only that PID, waits within a deadline, and removes only the
same device/inode. Recovery promotes an interrupted `starting` record
only when that protocol proof succeeds. Dead records without a socket and dead
records with an exact stored socket identity can be cleared after exact-name
confirmation. Unowned sockets, symbolic links, live incomplete records and
malformed registries are retained without signaling or unlinking.

Host-agent use is a separate explicit adapter. It previews the authority being
shared, is off by default and never copies the host socket into persistent
space metadata. `quarters host` continues to clear agent variables unless the
host command receives a future explicit host-agent grant.

No generic daemon runner is part of this feature. SSH agent is the first
candidate; GnuPG must use its native discovery and control contracts rather
than being forced into the SSH model.

## Acceptance gates

- start/status/stop races and interrupted startup reconciliation
- stale PID reuse, replaced sockets and symlinked runtime paths
- bounded startup and shutdown with no orphan created on error
- two spaces cannot observe each other's private agent through Quarters state
- host-agent authority remains unavailable; the host socket is always blocked
- environment and doctor output distinguish every state above
- lifecycle behavior passes on macOS and Linux without shellouts from the core

## Consequences

Agent-backed credentials remain unavailable until a user explicitly starts the
private agent and adds keys to it. The record, socket and keys are still owned
by the real UID: this lifecycle prevents accidental host-agent sharing and
unsafe cleanup, but does not protect keys from another process with the same
account authority.
