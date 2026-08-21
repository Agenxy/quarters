# Quarters MCP

Quarters MCP is a local agent-facing window into one folder-backed store. It is
not a remote service and it does not turn Quarters into a command-execution
tool.

## Start it

Configure an MCP host to launch an absolute Quarters binary with `mcp` as its
argument. Standard output is reserved for newline-delimited JSON-RPC frames;
diagnostics use standard error only after the protocol process ends.

For a custom store, configure arguments in this order:

```text
--root /absolute/private/path mcp
```

The root is validated and bound once. No MCP request can change it.

## Protocols

| Revision | Lifecycle | Quarters behavior |
|---|---|---|
| `2026-07-28` | Stateless `server/discover` | Required per-request metadata, server identity metadata, scoped cache hints and `resultType` |
| `2025-11-25` | `initialize` plus notification | No 2026 result discriminators or cache fields; legacy resource-not-found code |

An `initialize` proposal for another revision receives a successful
`2025-11-25` offer, as required by the initialized lifecycle; a client that
cannot accept that downgrade disconnects. The 2026 behavior remains reachable
only through stateless discovery and per-request metadata.

One connection cannot mix the two families. The official SDK handles an
optional pre-initialization `ping` without selecting a family; the first
lifecycle request does.

## Tools

| Tool | Mutation | Contract |
|---|---|---|
| `quarters_status` | No | Bounded health and cooperative-lease observation for one or all spaces |
| `quarters_doctor` | Conditional local preparation | Capability inventory; a named check prepares private runtime paths and validates the environment |
| `quarters_create` | Yes | Atomically creates one private space using the captured default shell |

Every parameter object rejects unknown fields. Space names use the core
1–32-byte portable ASCII grammar. Tool output has a published JSON Schema and
both structured and human-readable carriers.

## Resources

- `quarters://help` — stable agent workflow
- `quarters://security` — authority and privacy boundary
- `quarters://status` — private bounded snapshot with a 500 ms 2026 cache TTL

The static resources may be cached publicly for one hour under 2026. The 2025
family receives no cache extensions.

## Deliberate limits

The one-MiB frame ceiling, 32 response-lifetime request slots, 8,192 legacy-ID
budget, 128-entry status ceiling and two blocking filesystem workers are
security boundaries against accidental or hostile local peers. Exceeding them
returns a bounded error or closes a protocol-abusing connection.

Cancellation suppresses the response but does not abort a blocking filesystem
transaction. In particular, a cancelled create may still complete atomically;
inspect status before retrying the same name.

MCP cannot compensate for Quarters' baseline authority model: processes still
run as the real account, and same-account malware can invoke the CLI directly.
