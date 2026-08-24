# User walkthrough notes — 2026-08-22

These notes capture direct product feedback from the first guided Quarters walkthrough. They are intentionally descriptive; implementation decisions belong in the normal design and review process after the walkthrough.

## Implementation status

Applied in this development line:

- composable zsh/bash `[q:NAME]` prompt context for new spaces, with an
  explicit `shell-init` path for existing spaces
- distribution-aware `qts`/`q` shortcut status, collision-safe installation,
  exact managed-link removal and doctor reporting
- truthful SSH-agent behavior: the unavailable private socket is no longer
  exported
- an expanded `workspace` layout with visible personal directories,
  platform-specific macOS conventions and a stable opaque space ID
- CLI and MCP creation/reporting for both profile and workspace layouts
- previewed, bounded CLI clone with exact sensitive-state confirmation,
  descriptor-relative traversal, aggregate exclusions and atomic publication

Specified but deliberately not exposed until their transaction and adversarial
gates pass:

- hidden internal-store migration and runtime re-keying (ADR 0006)
- template, snapshot, freeze, export and rollback beyond the accepted portable
  clone subset (ADR 0003)
- previewed host-state forking and inheritance policies (ADR 0004)
- private and opt-in host agent lifecycle (ADR 0005)
- native confinement and encrypted-at-rest capability research (ADR 0007)

## Prompt awareness

- The existing `[demo]` prompt marker provides the essential active-context signal.
- Improve that baseline into rich, composable prompt context comparable to Python virtual environments and Git integrations.
- The presentation should remain unmistakable without requiring users to run `quarters status` or remember hidden environment state, while fitting naturally into established prompt themes and frameworks.

## Installation and command availability

- The normal installation flow should place `quarters` on the host shell's `PATH`.
- Every created Quarter should also be able to invoke `quarters` directly. The walkthrough should never require a repository-relative path such as `./target/release/quarters`.
- Installation and shell-integration changes must be explicit, reversible, idempotent, and diagnosable across supported shells.
- Provide an installer-managed short command for `quarters`, with `qts` and `q` offered as default choices.
- Before installing a shorthand, detect existing executables, shell aliases, functions, builtins, reserved names, and other command-resolution collisions. Warn clearly and never overwrite an existing mapping silently.
- Make shorthand installation removable and idempotent, and expose its state through doctor/status output.
- Prefer a real executable entry point or managed link on `PATH` where practical so shorthand behavior is consistent across supported shells and inside every Quarter; keep completions and help behavior equivalent to `quarters`.

## On-disk presentation

- Quarters-managed top-level implementation directories should be hidden with a leading dot by default.
- Apply the convention consistently to storage-root and per-space internals such as spaces, metadata, snapshots, templates, runtime bookkeeping, locks, and staging areas.
- Keep intentional user-facing directories inside an expanded workspace—such as Desktop, Documents, Downloads, and Applications—normally visible.
- Provide friendly CLI commands for locating or opening managed storage so hidden internals do not become undiscoverable.
- Introduce the layout change through a versioned, transactional migration that preserves existing alpha spaces and can recover safely from interruption.

## Host inheritance and fork workflows

- Support both a clean Quarter and a Quarter forked from selected host shell/user state.
- Provide intentional, fine-grained controls for inheriting host environment variables, `PATH` values, sourced shell configuration, and other useful state. Clarify the intended meaning and scope of `src` during design.
- A host-fork workflow is a primary use case: reproduce a familiar environment for experimentation while protecting the host's shell configuration and user-state files from ordinary tool writes.
- Treat host secrets and credentials as a distinct, high-risk category. Do not copy or inherit them silently; preview the plan, classify inputs, require explicit selection, and preserve provenance.
- Make the safety boundary plain: user-state redirection can protect host configuration from ordinary writes, but it is not a security sandbox. Claims of filesystem isolation require an enabled and verified confinement backend.

## Space lifecycle and versioning

- Spaces must be clonable and renameable.
- Users should be able to freeze a space, take named snapshots/backups, inspect them, and roll back safely.
- Templates ("stationery") must be nameable and renameable, and users must be able to create one directly from the currently active Quarter.
- Use a stable internal identity separate from a mutable display name so renames do not break snapshots, references, automation, or provenance.
- Snapshot consistency must be real: coordinate with active leases, provide an explicit quiescence model, and use atomic or copy-on-write platform facilities where available with a verified portable fallback.
- Rollback is destructive. It must preview its target, refuse unsafe active-state transitions, preserve a recovery point by default, and replace state transactionally.
- Frozen state needs a precise contract: distinguish an immutable named snapshot from a live space whose writes are intentionally locked.

## Expanded workspace mode

- Offer an expanded mode that creates and redirects familiar user directories such as Desktop, Documents, Downloads, Applications, and other platform-appropriate folders inside the space.
- The goal is to feel like a distinct user/workspace/account while retaining the real OS login, UID/GID, permissions, kernel, hardware, and session identity.
- Keep the portable conceptual model consistent while allowing macOS- and Linux-specific directory layouts and adapters.
- Clearly distinguish user-state virtualization from security confinement in status, help, and prompt context.

## Application-localization research track

- Investigate per-space installation and execution of shell applications, including their binaries, configuration, data, state, caches, temporary files, sockets, and package-manager prefixes.
- Experiment with per-space desktop application installation and execution, including an Applications directory and capture/redirection of application-owned writes.
- Build an evidence-based compatibility harness that observes filesystem and runtime behavior and classifies each application or tool. Do not claim that every write is localized unless the test backend can verify it.
- On macOS, explicitly research Foundation home resolution, `CFFIXED_USER_HOME`, `~/Library`, app-sandbox containers, Keychain, TCC, LaunchServices, launch agents/daemons, XPC services, and applications that resolve the passwd home instead of `HOME`.
- On Linux, research XDG coverage, passwd-home lookups, package prefixes, desktop-session services, D-Bus, portals, user namespaces, mount views, and confinement backends.
- Treat dynamic interposition as an optional compatibility technique, never the correctness foundation. Report host-bound behavior honestly when the OS or application prevents complete localization.

## Runtime-agent walkthrough finding

- The alpha sets `SSH_AUTH_SOCK` to a private per-space path, but the first walkthrough found no agent listening there; `ssh-add -l` failed with `Error connecting to agent: No such file or directory`.
- Do not present a reserved socket path as an active private agent. Status and doctor output must distinguish unset, reserved, starting, active, stale, and failed states.
- Decide on a deliberate lifecycle: explicit agent management, safe lazy start, or an opt-in host-agent adapter. Avoid silently inheriting the host agent or starting credential-bearing services without clear policy.
- When private agents are supported, coordinate their lifecycle with leases, stale-socket cleanup, crash recovery, locking, and per-space key policy.

## Maximum-isolation research frontier

- Research how closely a Quarter can emulate a fresh user, account, workspace, or machine without becoming a VM or OCI container.
- Define progressive, independently verifiable modes rather than one ambiguous "isolated" switch: redirected user state; expanded user-directory view; localized tool/application state; optional process confinement; encrypted storage at rest; protected mounted-state experiments; and machine-like identity presentation.
- In the furthest-reaching mode, redirect every practical user-owned path, runtime directory, package prefix, temporary path, socket, agent, configuration store, cache, and application data location into the space.
- Explore per-space encrypted storage that Quarters can create, unlock, mount, lease, unmount, back up, and recover. Prefer OS-native facilities and native library bindings where public, supported APIs exist.
- Keep encryption keys out of arguments, environment variables, logs, crash reports, and persistent plaintext. Research Keychain or platform-keystore integration, optional user-presence requirements, key rotation, recovery material, and zeroization limits.
- Treat an unmounted encrypted space and an unlocked/mounted space as different security states. Encryption at rest does not by itself prevent another same-UID process from reading mounted plaintext.
- On macOS, determine the strongest supported protection possible despite the shared real UID and lack of general per-process mount namespaces. Evaluate encrypted APFS disk images or volumes, mount lifecycle, permissions and ACLs, indexing and backup exposure, sandbox/confinement capabilities, and whether any public API can enforce process-scoped access to mounted content.
- On Linux, evaluate encrypted directory or block storage, private mount namespaces, bind/overlay views, `fscrypt`, `dm-crypt`/LUKS, Landlock, keyrings, and visibility of decrypted mounts outside the Quarters process tree.
- Explicitly decide whether using native namespace primitives crosses the project's "no containers" boundary. Using a kernel primitive directly does not require OCI images or a container runtime, but the product must describe the mechanism honestly.
- Model hostile or merely curious same-user applications, other Quarters processes, background indexers, backup tools, crash reporters, root/administrator access, physical/offline access, and compromised Quarter processes.
- Do not promise protection from the real user, root/administrator, the kernel, or a compromised host. Document which adversaries each mode can and cannot resist.
- Build adversarial tests for unauthorized reads and writes, mount leakage, key leakage, stale mounts, crash recovery, rollback, backup consistency, and cross-space access. Capability labels must be earned by those tests.
