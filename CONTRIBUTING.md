# Contributing

Read `AGENTS.md`, the threat model and the platform ADR before changing
behavior. Run:

```sh
make check
```

The gate formats, lints, tests, checks structural ceilings and builds API
documentation with warnings denied. Direct dependencies are exact in
`Cargo.toml`; `Cargo.lock` is committed. Platform behavior stays behind the
platform module, and capability requests fail rather than degrading silently.

Changes to process authority, environment inheritance, filesystem mutation,
stored schema or platform guarantees need tests and an architecture decision.
