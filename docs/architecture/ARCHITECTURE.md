# Architecture

## Product contract

Quarters virtualizes user-owned state for a native process tree. It does not
virtualize the host identity or machine.

```text
CLI
 |
 +-- validated command and stable output
 |
 +-- portable core
 |    +-- private atomic store
 |    +-- manifest schema
 |    +-- environment allowlist
 |    +-- process activity leases
 |    +-- compatibility inventory
 |
 +-- platform backend
      +-- macOS HOME + CFFIXED_USER_HOME
      +-- Linux portable baseline
      +-- Linux opt-in user/mount home view
```

## Storage

The default root is `~/.quarters`:

```text
.quarters/
  spaces/
    work/
      .quarters.json
      .active
      home/
        .config/
        .local/{bin,share,state}/
        .cache/
        .gitconfig
        .ssh/config
        .gnupg/
  trash/
```

Creation builds a complete directory under `.creating-<name>-<unique>` on the
same filesystem, syncs private files and publishes it with `rename()`. A schema
marker and matching directory name are required when opening a space.

Removal takes an exclusive nonblocking lock, atomically renames the space under
`trash`, then removes that exact retired directory. A Quarters supervisor holds
a shared lease while its direct entry is running, so removal fails during that
period. A detached descendant, tmux server or other process that outlives its
supervisor is outside this portable lease model and must be stopped by the user
before removal.

## Environment authority

The launcher calls `env_clear()` and rebuilds the child environment from a
small terminal and locale allowlist. Profile paths are then inserted. A user can
name additional variables with `--inherit`; diagnostic output redacts those
values.

This prevents accidental reuse of common and unknown credential variables. It
does not stop a child from reading credentials directly from any host path its
real account can access.

`SSH_AUTH_SOCK` always points to a short per-space socket. It is intentionally
not inherited. A missing per-space agent makes agent-backed SSH unavailable;
explicit key paths in the per-space SSH config still work.

The generated Git config starts with an empty credential helper. This resets
helpers inherited from host or system policy before any per-space choice. It
avoids silently sharing macOS Keychain credentials.

## Process boundary

`enter` and `exec` spawn the requested native executable directly. No shell is
inserted for `exec`. The supervising parent holds the activity lease and
forwards the child's terminal naturally through inherited file descriptors.

`host` is an explicit baseline escape. It restores the captured host `HOME`,
`PATH`, `TMPDIR` and runtime path, clears profile variables and runs the target.
It does not restore variables that were omitted by the allowlist.

## Platform backends

### macOS

The baseline sets `HOME`, all supported tool-specific paths and
`CFFIXED_USER_HOME`. Apple's open CoreFoundation source consults that variable
before the passwd home when the process is not set-id. It remains undocumented,
so Quarters reports it as best effort and never treats it as the correctness
anchor.

macOS has no per-process mount namespace. Programs using `getpwuid()` can still
find the real home. SSH is therefore Class C and needs `ssh -F` with the space
config. Keychain, TCC, app containers and login services remain host-bound.

Seatbelt is not part of the alpha's guarantee. `doctor` can report the deprecated
`sandbox-exec` binary, but no confinement flag exists without a reviewed policy.

### Linux

The portable baseline matches macOS environment behavior without the
CoreFoundation variable.

`--home-view` starts an internal Quarters child, creates a user namespace, maps
the real UID and GID to the same numeric values, creates a private mount
namespace, makes propagation private and bind-mounts the space home over the
passwd home. The target still has the same numeric user and host DAC authority.

This mode is opt-in for two reasons:

1. AppArmor, sysctls or distribution policy can block unprivileged user
   namespaces.
2. Only the user's identity is mapped. Set-id root programs such as ordinary
   `sudo` cannot work inside the view.

The internal child prevents namespace calls from changing the invoking shell
or the supervising Quarters process. Requested setup fails closed.

Landlock is future work. The build does not equate namespace path changes with
filesystem confinement.

## Clone, snapshot, template and export contract

These workflows require a stronger transaction model than recursive copy:

- take an exclusive space lease
- stop or prove quiescence of agents and daemons
- omit runtime sockets and derived caches by declared policy
- use platform clone/reflink support when available, with a correct copy
  fallback
- validate symlinks without following them outside the space
- preserve mode and extended metadata deliberately
- mark exports as private material and define a safe import format

The alpha documents this contract and does not ship partial commands.
