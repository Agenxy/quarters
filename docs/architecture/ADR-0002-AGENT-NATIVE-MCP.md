# ADR 0002: Narrow, stdio-only agent protocol adapter

Status: accepted for alpha

## Context

Local coding agents benefit from inspecting and preparing Quarters spaces, but
the full CLI can launch arbitrary native processes as the host account. Mapping
every CLI command into an agent tool would enlarge both the authority surface
and the consequences of prompt injection. MCP also has two materially different
current lifecycles: stateless `2026-07-28` and initialized `2025-11-25`.

## Decision

Ship `quarters mcp` as a native Rust stdio server in the existing binary.

- Use the official `rmcp` SDK, pinned exactly and without network features.
- Support exactly `2026-07-28` discovery and `2025-11-25` initialization.
- Commit each connection to one lifecycle family and reject cross-family use.
- Bind one `Store` and one captured host-environment snapshot at startup.
- Expose only status, doctor and create tools.
- Expose fixed help, security and bounded status resources.
- Omit exec, enter, host, inherit, home-view, root-selection and removal tools.
- Keep transport framing, active responses, legacy IDs, output, listings and
  blocking filesystem work explicitly bounded.
- Treat stored names and diagnostics as untrusted model input.
- Keep MCP in the default binary so installation has one predictable command;
  the dependency gate prevents accidental HTTP or TLS transport expansion.

## Consequences

Agents can prepare a persistent space but cannot use Quarters as a general
native command runner or delete state. The existing core remains the only
filesystem authority, so the CLI and MCP cannot drift on anchor validation.
The binary includes the SDK and async runtime even for CLI-only users; that
cost buys a single install and is measured against release artifacts. Remote
MCP would require a new ADR, authentication model, threat analysis and explicit
dependency-gate change.

Supporting two protocol families adds tests and state. It avoids claiming
compatibility through permissive negotiation: cache hints, resource-not-found
codes, `resultType` and lifecycle methods are verified separately for both.
