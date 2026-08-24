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
- no tool accepts an executable, arguments, inherited variable, home-view flag,
  root path or removal target

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
- duplicate live IDs and overlong IDs are terminal protocol violations
- legacy IDs cannot be reused, including IDs rejected at active capacity
- every decodable request in a 200-request capacity burst receives either its
  result or a bounded capacity error, and a later request still succeeds
- decoded transport errors are owned by a bounded writer actor, so cancellation
  of the SDK receive future cannot silently discard them
- an end-to-end blocked status call proves cancellation suppresses delivery,
  lets the filesystem operation finish and releases its request ID for reuse
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
behavior; namespace behavior additionally requires a Linux host whose policy
allows the feature.
