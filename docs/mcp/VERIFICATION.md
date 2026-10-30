# MCP verification contract

The MCP adapter is acceptable only when all of these remain true.

## Interoperability

- the official SDK client completes a 2026 discovery session
- the official SDK client completes a 2025 initialization session
- newer and older initialization proposals receive the supported 2025 offer
- a pipelined post-initialize request is evaluated under the 2025 family
- both sessions operate on the same core store without protocol-specific state
- 2026 requests include `resultType`, server metadata and scoped cache fields
- 2025 responses omit those fields
- unknown resources use the revision-appropriate error code
- a lifecycle method from the other family is rejected

## Schemas and authority

- all tools publish input and output schemas with closed parameter objects
- successful and failed structured outputs validate against the published schema
- profile and workspace creation, plus invalid layout rejection, pass under
  both supported protocol families
- incomplete outputs fail validation
- the catalog contains only status, doctor and create
- no tool accepts a clone source/destination, executable, arguments, inherited
  variable, home-view flag, root path or removal target

## Hostile transport behavior

- oversized input closes without buffering beyond one frame
- oversized output writes no partial frame
- stalled output bounds ordinary responses, transport errors and shutdown to a
  two-second drain deadline
- malformed JSON returns a fixed parse error without echoing request content
- valid JSON batches and structurally invalid request IDs receive a fixed
  Invalid Request error with a null ID
- malformed method parameters preserve a recoverable request ID
- valid traffic can recover after a non-terminal parse or metadata error
- notifications before lifecycle selection are ignored without selecting a
  protocol family or closing the stream
- duplicate live IDs and overlong IDs are terminal protocol violations; an ID
  whose request the client cancelled is not, because its operation may still be
  finishing
- legacy IDs cannot be reused, including IDs rejected at active capacity
- every decodable request in a 200-request capacity burst receives either its
  result or a bounded capacity error, and a later request still succeeds
- decoded transport errors are owned by a bounded writer actor, so cancellation
  of the SDK receive future cannot silently discard them
- a request cancelled before its handler starts releases its ID and capacity at
  once; a cancelled running handler keeps its slot until it finishes
- reusing a cancelled ID waits, for at most five seconds, for its operation to
  finish and is then admitted; the request is held by the transport, so a
  dropped receive cannot lose it, and an ID still held after the bound receives
  a non-terminal error
- an end-to-end blocked status call proves cancellation is graceful: a late
  response for the cancelled ID is tolerated as the specification allows, and
  the session keeps serving fresh requests
- stalled output cannot produce unbounded request or error queues

## Stored-state hostility

- roots, spaces, homes, manifests and lock anchors retain no-follow, ownership,
  type and private-mode validation in the shared core
- non-UTF-8 directory names are marked lossy and unusable
- unhealthy entry names are hexadecimal on the agent surface
- unhealthy entry diagnostics contain no planted natural-language name, command
  arguments, environment values, working directory or state-file contents

Run `make check`, `make dependencies` and the end-to-end stdio acceptance tests
on macOS and Linux before release. Cross-platform CI is evidence for portable
behavior; namespace behavior also requires a Linux host whose policy
allows the feature.

## MCP 2026-07-28 conformance audit

Audited on 2026-10-29 against the published 2026-07-28 changelog and
versioning pages, on rmcp 3.8.0, by driving the built `quarters mcp` binary
and the acceptance suites. Quarters is a dual-era stdio server: modern
requests carrying `_meta` are served statelessly, and `initialize` opens the
2025-11-25 legacy family.

| Requirement (2026-07-28) | Status | Evidence |
|---|---|---|
| Stateless requests carry `protocolVersion` and `clientCapabilities` in `_meta` (major 2) | Holds | A request without them is refused with `-32602` naming the missing keys |
| Servers SHOULD identify themselves in each result's `_meta` (major 2) | Holds | `io.modelcontextprotocol/serverInfo` is present on every result |
| Unsupported versions return `UnsupportedProtocolVersionError` (major 2) | Holds | An unknown version returns `-32022` naming `2026-07-28`; a legacy version without `initialize` is refused the same way |
| `server/discover` MUST be implemented (major 3) | Holds | Returns `supportedVersions: ["2026-07-28"]`, capabilities and identity |
| A discover-only stdio probe is a normal client (major 3, versioning) | Holds | `a_discover_only_client_exits_cleanly`; the binary exits 0 |
| `ping`, `logging/setLevel` and `notifications/roots/list_changed` are removed (major 5) | Holds | A ping carrying modern `_meta` and `logging/setLevel` both return `-32601` |
| No `notifications/message` without a per-request `logLevel` (major 5) | Holds | Quarters emits no log notifications |
| A bare ping before any lifecycle is the legacy pre-initialize ping (versioning, dual-era) | Holds | `bare_ping_after_a_modern_probe_is_a_legacy_preinitialize_ping` |
| Only advertised capabilities are served (capability negotiation) | Holds | Prompts and completions are not advertised; `prompts/list` and `completion/complete` return `-32601` instead of rmcp's empty defaults (`unadvertised_prompts_and_completions_are_unknown_methods`) |
| Every result carries `resultType` (major 8) | Holds | `complete` on every result; Quarters returns no interim results |
| List and read results carry `ttlMs` and `cacheScope` (minor 5) | Holds | `tools/list`, `resources/list` and static `resources/read` are public for one hour; dynamic status reads are private and short |
| `tools/list` order is deterministic (minor 3) | Holds | Tools are returned sorted by name |
| Resource not found is `-32602` (minor 6) | Holds | An unknown `quarters://` URI returns `-32602` |
| Legacy clients keep working through `initialize` (versioning, dual-era) | Holds | The legacy initialize and pipelining suites pass unchanged |
| Only the two tested revisions are negotiable | Holds | The transport reports exactly `2026-07-28` and `2025-11-25` to rmcp whatever rmcp supports (`the_reported_protocol_set_is_exactly_the_tested_revisions`); initialize-less requests claiming `2025-06-18`, `2025-03-26` or `2024-11-05` are refused with `-32022` |
| Sessions, `subscriptions/listen`, SSE resumability, HTTP headers (major 1, 4, 9; minor 4) | Not applicable | Quarters serves stdio only and offers no subscriptions |
| Tasks extension, MRTR and elicitation changes (major 6, 7; minor 11) | Not applicable | Quarters issues no server-initiated requests or tasks |
