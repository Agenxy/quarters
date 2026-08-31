# ADR 0011: Fail-closed Linux filesystem confinement

Status: accepted; experimental Linux backend

## Context

The portable Quarters profile redirects user state but preserves the real Unix
account and all of its discretionary filesystem authority. A child can ignore
`HOME`, use absolute paths and reach every host file permitted to that UID.
Linux Landlock can irreversibly restrict ambient path access for one process
tree without a privileged helper, namespace container or first-party unsafe
code.

## Decision

`enter`, `exec` and `env` accept `--confinement filesystem`. The option is
Linux-only and requires complete Landlock ABI 3 support so `TRUNCATE`, `REFER`
and all ABI-1 rights are handled together. Quarters uses the safe `landlock`
crate, requests hard compatibility, sets `no_new_privs`, accepts only
`FullyEnforced`, and never falls back when the option was requested.

The policy gives full ABI-3 rights to the exact validated Quarter home and its
private runtime. It gives read/execute access to a fixed set of existing system
software roots, read access to `/etc` and `/proc`, exact-file read access to an
active resolver target outside `/etc`, and narrow file access to terminal and
null/random devices. Every reported grant includes its fixed or derived source. The
store, sibling Quarters, host homes, `/tmp`, `/sys`, `/dev/shm`, mounts and
media are not granted as hierarchies. The exact runtime may itself live under
`/run/user` or `/tmp` without granting its parent.

The launcher prepares its private runtime copy and reconstructs PATH from
Quarter-local bins and granted system entries. Its child builds one policy plan
and opens every Landlock rule anchor before any optional `--home-view` mount,
then reuses that exact prepared ruleset for enforcement on its single thread
before immediately executing the program. Executable resolution uses the same
reported roots and the mounted Quarter-home alias. Relative program paths
containing a separator are refused. `quarters env ... --confinement filesystem
--json` reports the complete planned grant, readable PATH-entry array and
omission set before enforcement. Quarters probes `/dev/tty` with ordinary
read-write access and omits it when the process has no controlling terminal.
Unexpected probe failures remain fatal. Landlock opens every admitted rule
anchor separately and fails closed if any required or optional anchor cannot be
prepared exactly as reported.

Inside the domain, `current`, prompt generation, shortcut inspection and
managed OpenSSH adapters use a no-store route; shortcut mutation still refuses
Quarter context. Store management, `doctor`, MCP and `host` are refused
proactively. The environment marker selects this UX route; it is not the
security boundary and removing it cannot relax the kernel domain.

## Claim boundary

The handled rights deny file-content reads, directory enumeration and mutation
outside grants. ABI 3 does not restrict `stat`, `statx`, `readlink`, `access`,
`O_PATH` or path traversal alone, so known-name metadata can remain visible.
`/proc` is granted for compatibility and Landlock also has ptrace-domain side
effects; Quarters claims neither general process isolation nor credential
confidentiality from those effects. Processes in the same domain are not
separated from one another.

Network and IPC remain shared. Device access is not isolated. Inherited
standard streams and other already-open descriptors remain usable. Terminal
devices can interact with host terminals subject to ordinary DAC. The real UID,
GID, groups, kernel and same-UID processes outside the domain are unchanged.
`no_new_privs` prevents ordinary set-id elevation, including `sudo`. An
unconfined same-UID process can still read mounted Quarter state.

## Verification

Linux acceptance compares unconfined and confined behavior, proves permitted
home/runtime operations and hostile host/store/sibling denials, and exercises
the shell plus Git, OpenSSH, Python and Node paths when those tools are present.
Hosted Linux sets
`QUARTERS_REQUIRE_LANDLOCK=1`; unavailable or partial enforcement fails the
job. macOS and older-kernel behavior is fail-closed capability evidence, not a
substitute for Linux enforcement.

## Consequences

This is an earned filesystem-policy capability, not a container. Its initial
working directory is always the Quarter home, so host-repository work awaits a
separate explicit workspace-grant design. Host-home tool shims are omitted;
tools installed inside the Quarter and fixed system roots remain usable.
Encrypted-at-rest storage remains a separate capability.
