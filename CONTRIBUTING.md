# Contributing

Read `AGENTS.md`, the threat model and the platform ADR before changing
behavior. Run:

```sh
make check
```

The gate formats, lints, tests, checks structural ceilings and builds API
documentation with warnings denied. Use Bun 1.4.4 and Node.js 26.13.0 for the
typed npm launcher; its lockfile is committed, while npm remains the registry
packaging and publication interface. Direct dependencies are exact in
`Cargo.toml`; `Cargo.lock` is committed. Platform behavior stays behind the
platform module, and capability requests fail rather than degrading silently.

The gate also refuses shell scripts, whether named `.sh` or started with a
shell shebang (write a uv script or a compiled program instead), and em dashes
in any text file. The only exceptions are entries in
`crates/quarters-quality/shell-allowlist.txt`, each with a reason, reviewed as
decisions; it has none today.

Changes to process authority, environment inheritance, filesystem mutation,
stored schema or platform guarantees need tests and an architecture decision.

Tests leave nothing outside their temporary directory. Acceptance tests that
start a private agent hold an `AgentGuard`, declared before `agent start`, so
a failing test still stops its `ssh-agent`. Acceptance tests take their
temporary directory from `tests/support/test_store.rs`, which removes every
space with `quarters rm` on drop and fails the test if a private runtime
directory survives. Core unit tests that create a runtime directory hold a
`TestRuntime` guard, which removes it the same way.

## Licensing of contributions

Quarters is licensed under GPL-3.0-or-later, and Agenxy also offers it under a
commercial licence (see `COMMERCIAL-LICENSING.md`). So that both remain
possible, outside contributions need a signed contributor licence agreement or
copyright assignment to Agenxy before they can be merged. Open an issue first
to arrange it. New source files start with
`// SPDX-License-Identifier: GPL-3.0-or-later`.
