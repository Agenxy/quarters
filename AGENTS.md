# Quarters agent briefing

Quarters gives native process trees a persistent alternate user-state profile
while preserving the host account, permissions, kernel and machine identity.
The baseline is state redirection, not containment.

## Invariants

- Never describe the baseline profile as a sandbox, container or security
  boundary.
- The real UID, GID, supplementary groups and filesystem authority remain
  unchanged.
- Portable behavior must not depend on Apple-only APIs, Linux namespaces,
  dynamic interposition or an external service.
- Requested capabilities fail closed. Unsupported home views or confinement
  modes are errors, never silent fallback.
- Host credential variables are not inherited unless the user names them.
- Space paths are created atomically, kept private and validated before any
  destructive operation.
- Platform-specific work stays behind the platform module.

## Workflow

Use Rust 1.97.1 and run `make check`. Every warning is an error. The native
quality gate enforces source files at 1,024 lines, functions at 128 lines, type
bodies at 512 lines, eight parameters, cyclomatic complexity 16 and nesting
eight. Never weaken a gate to land a change.

Read `docs/security/THREAT-MODEL.md` before changing process launching,
environment policy, filesystem behavior or platform capabilities. Add an ADR
for changes to the trust boundary or platform contract.
