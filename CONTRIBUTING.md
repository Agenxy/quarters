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

Changes to process authority, environment inheritance, filesystem mutation,
stored schema or platform guarantees need tests and an architecture decision.

Acceptance tests that start a private agent hold an `AgentGuard`
(`crates/quarters-cli/tests/support/agent_guard.rs`), declared before
`agent start`, so a failing test still stops its `ssh-agent`. Tests do not
remove their spaces before dropping the temporary store, so each leaves an
empty, private `quarters-<uid>/<id>` runtime directory under the system
temporary directory. That is deliberate: the tests exercise the real runtime
location, `quarters remove` is the supported cleanup path, and the operating
system clears those directories at reboot.

## Licensing of contributions

Quarters is licensed under GPL-3.0-or-later, and Agenxy also offers it under a
commercial licence (see `COMMERCIAL-LICENSING.md`). So that both remain
possible, outside contributions need a signed contributor licence agreement or
copyright assignment to Agenxy before they can be merged. Open an issue first
to arrange it. New source files start with
`// SPDX-License-Identifier: GPL-3.0-or-later`.
