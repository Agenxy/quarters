# ADR 0001: Portable profile core with optional platform depth

Status: accepted for alpha

## Context

The product needs to separate user-owned CLI state on macOS and Linux without a
guest root filesystem, VM, OCI image or second operating-system account.

macOS and Linux do not offer symmetric filesystem-view primitives. Treating an
Apple app container or a Linux mount namespace as the product core would make
one platform's optional mechanism define the other platform's semantics.

## Decision

The portable guarantee is a strict child environment, private folder-backed
home and explicit state-location adapters. Platform backends can improve
compatibility or restriction but cannot weaken or silently replace that core.

- Rust owns the portable store, policy, CLI and process lifecycle.
- macOS adds best-effort `CFFIXED_USER_HOME`.
- Linux offers an opt-in bind-mounted passwd-home view.
- Dynamic interposition is outside the baseline.
- App Sandbox, Seatbelt and Landlock are never correctness dependencies.
- A requested optional capability fails if unavailable.

## Consequences

The default works on both platforms and has one honest authority model. Linux
can reach passwd-home compatibility at the cost of `sudo` and distro-policy
constraints. macOS retains a larger Class C compatibility surface. The CLI and
documentation must show those differences instead of claiming parity.

