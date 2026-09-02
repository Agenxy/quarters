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

Executable resolution opens the accepted canonical file with `O_PATH`,
`O_NOFOLLOW` and close-on-exec, verifies the descriptor's device and inode
against the reviewed metadata, and holds it across Landlock enforcement.
Process replacement uses `execveat(AT_EMPTY_PATH)` without a libc path
fallback, so a same-UID rename cannot substitute a different file after
review. Linux's interpreter-script case retries only
after clearing close-on-exec on that same already-validated descriptor.
That kernel-required script path can appear as `/dev/fd/N` to the interpreter,
and the readless `O_PATH` handle remains inherited for that script tree; both
are explicit compatibility limitations rather than hidden isolation claims.

An invocation may add up to 32 distinct explicit data roots with
`--grant-path ABSOLUTE_PATH:ro|rw`. These grants are never persisted or read
from the environment. Canonical grant roots must be non-overlapping and
non-nested, preventing broader Landlock rules from silently overriding a
narrower access request. Their rules omit executable access, so an executable in
a granted workspace cannot become a command root. Quarters canonicalizes each
path, reports the requested access and rejects overlap with its store, runtime,
running executable, passwd-home SSH/GnuPG roots or a passwd home hidden by
`--home-view`, and every built-in configuration, compatibility or executable
root. Each anchor's validated device and inode must match the opened
Landlock descriptor, so replacement between review and enforcement fails
closed. `--workdir` is portable process behavior; in confined mode an external
directory must be covered by one of these data grants.

The policy report also records the observed
`/proc/sys/dev/tty/legacy_tiocsti` state. Landlock ABI 3 does not mediate that
terminal ioctl, so an enabled legacy setting remains a host-policy limitation,
not an unreported part of the filesystem claim. JSON reports this as
`probed` plus the stable `state`, never as generic capability availability.
An unreadable or non-disabled setting also appears in the explicit limitations
array because a shared controlling terminal can cross the filesystem boundary.

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
job. A separate Ubuntu job retains the distribution's default unprivileged
user-namespace policy and proves `--home-view` is unavailable and fails closed.
macOS and older-kernel behavior is fail-closed capability evidence, not a
substitute for Linux enforcement.

## Consequences

This is an earned filesystem-policy capability, not a container. The default
working directory remains the Quarter home; explicit data-only grants allow a
reviewed host workspace without turning it into an executable search root.
Host-home tool shims are omitted; tools installed inside the Quarter and fixed
system roots remain usable. Encrypted-at-rest storage remains a separate
capability.
