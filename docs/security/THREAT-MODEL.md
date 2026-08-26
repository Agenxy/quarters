# Threat model

## Assets

- host credentials, histories and CLI configuration
- state in one Quarters space that should not be selected accidentally by
  another space
- host files reachable by the real Unix account
- the validated storage root and removal target
- terminal control and process exit status
- agent context integrity and bounded MCP availability

## Trust boundaries

The Quarters binary is trusted first-party code. Manifests use a first-party
format but, like the space name, environment, stored files, child executable and
every process in the child tree, their bytes are untrusted until validated.

MCP clients are untrusted local peers. Their frames, request IDs, metadata,
parameters, cancellation notifications and willingness to read output are all
hostile inputs. A same-UID process may also plant malformed directory entries
whose names or errors attempt terminal or model-context injection.

The operating system remains the authority boundary. Quarters baseline is not
one. A malicious child can use absolute paths, passwd records, open host files,
connect to host services and inspect other same-user processes subject to host
policy.

## Defenses in the alpha

| Risk | Control |
|---|---|
| Path traversal through a name | Strict 1-32 character validated name type |
| Partial creation | Same-filesystem temporary directory and atomic rename |
| Partial or redirected clone | Exclusive cooperative lease, descriptor-relative no-follow walk, private staging, fresh controls and atomic rename |
| Clone leaks file inventory | Human and JSON results expose bounded aggregate classes and counts, never home paths or file content |
| Clone silently duplicates credentials | Mutation requires exact source-name sensitive-state confirmation; preview and provenance declare the policy |
| Artifact content changes after capture | Canonical whole-tree BLAKE3 verification binds stored paths, types, ordinary modes, content, link targets and counts before every use |
| Artifact digest is mistaken for authentication | Output and documentation state that another same-UID process can alter both content and manifest |
| Partial rollback replaces only some state | Complete staging, verified automatic recovery snapshot and durable prepared/retired/published transaction; recursive merge is forbidden |
| Crash leaves a target apparently absent | Atomic marker publication and exact filesystem tuples produce bounded actions; malformed or ambiguous markers preserve every tree, become itemized issues, block only a known named target and do not stop unrelated recovery |
| Recovery deletes an unrelated path | Only private exact-form generated IDs, free creation locks and validated manifest temporaries are reclaimable; malformed reserved-looking and unknown hidden entries remain counted without blocking unrelated recovery |
| Manifest downgrade or field confusion | Permissive version probe followed by strict closed schema and version/layout/ID invariants |
| Abandoned internal state | Bounded doctor counts; confirmed recovery retires entries under the management lock, then deletes outside it |
| Wrong removal target | Manifest/name validation, exact confirmation, rename then delete |
| Removal during a supervised entry | Shared lease held for the lifetime of the Quarters supervisor |
| Activity lock denial | Read-only observation, management and supervisor acquisition have separate bounded deadlines and fail closed or report unknown as appropriate |
| Misleading activity inspection | Reports only cooperative lease state and marks detached processes unknown |
| Probe mistaken for activity | Root observation lock serializes status probes and removal before the activity-lock check |
| Launch races retirement | Supervisor lease acquisition and removal retirement serialize before opening the activity lock |
| Symlinked or broadly accessible space anchors | No-follow type, ownership and private-mode validation for roots, homes, manifests and locks |
| Damaged entry hides healthy siblings | Inspection reports each entry independently with machine-readable health |
| Unsafe removal of damaged state | Removal requires the exact validated private root and activity lock, not a readable home or manifest |
| Cleanup resource exhaustion | Iterative private cleanup refuses trees deeper than 256 levels or containing more than 131,072 descendant directories and leaves them recoverable for manual inspection |
| Credential environment leakage | `env_clear()` plus safe allowlist; explicit values are redacted |
| Profile override through explicit inheritance | `--inherit` rejects every Quarters-owned state variable |
| Prompt-code injection | Prompt-expanded values come only from the validated ASCII name; roots and stored text never reach prompt expansion |
| Startup integration resolves altered code | Generated rc files resolve `quarters` through the active space PATH; the space-local bin directory is user-writable and therefore inside the same-UID trust boundary |
| Shortcut replacement or deletion | Protected PATH directory, non-overwriting symlink creation and removal only of links with the closed Quarters-launcher target shape |
| Host Git helper reuse | Generated config clears inherited credential helpers |
| Shared SSH agent | Host socket is not inherited; `SSH_AUTH_SOCK` remains unset until reviewed private-agent management exists |
| Runtime socket collision | Mode-0700 short runtime directory per UID and space |
| Unsupported stronger mode | Capability check and fail-closed error |
| Namespace setup affecting caller | Dedicated internal child performs Linux namespace calls |
| Supplementary groups in home view | Capability is unavailable unless the primary group is the only active group |
| Secret diagnostics | No state content reads; explicit inherited values render as redacted |
| MCP lifecycle confusion | Exact 2026/2025 families; cross-family methods and version metadata fail closed |
| MCP memory or task exhaustion | One-MiB frames, two-second output deadlines, 32 response-lifetime request slots, 8,192 legacy IDs, bounded listings, one queued transport error and two blocking store workers |
| MCP receive cancellation drops protocol errors | Decoded transport errors transfer synchronously into a bounded writer actor before input processing resumes |
| MCP output backpressure | Bounded encoding and timed error writes; stalled peers cannot grow unbounded queues |
| MCP request replay | Duplicate live IDs close the connection; legacy IDs are never reusable in-session |
| Agent prompt injection from disk | Invalid entry names are bounded hex and detailed stored-entry errors are replaced on MCP surfaces |
| Terminal or JSON presentation injection | Human and JSON stored text is escaped and bounded before emission |
| Agent overreach | MCP has no clone, exec, enter, host, inherit, home-view, root-selection or removal tool |
| Remote attack surface | MCP transport is stdio-only; dependency gate rejects common HTTP/TLS server stacks |

## Explicit non-goals

- containing malicious or compromised child processes
- hiding the host filesystem from the real account in baseline mode
- separating network, process, device or IPC namespaces
- virtualizing macOS Keychain, TCC, app containers or Secure Enclave
- preserving ordinary `sudo` inside Linux `--home-view`
- discovering detached descendants or same-user servers after their Quarters supervisor exits
- secure deletion from snapshots, backups or recovery media
- crash-consistent live snapshot or export
- authenticating artifact state against another process with the same UID
- treating a free cooperative lease as proof that detached clone writers are absent
- treating workspace directories or a stable space ID as containment or authorization
- remote MCP, OAuth, agent-triggered command execution or agent-triggered deletion

## Host and sudo escape

`quarters host` is a named convenience boundary, not an authority transition.
It restores captured `HOME`, `PATH`, `TMPDIR` and `XDG_RUNTIME_DIR` values and
clears Quarters' tool-specific overrides so tools use their defaults below the
host home. Custom host credential and profile variables never cross implicitly.
The command is disabled in `--home-view` because the real home is hidden in that
mount namespace and restrictions cannot be undone safely from inside the
process tree.

In baseline mode, `sudo` uses host policy and normally switches to the target
user's home. It can write outside the profile. Users must treat it as a full
escape. In Linux `--home-view`, the root identity is unmapped, so set-id `sudo`
is expected to fail.

`quarters current` is informational, not an authority signal. Baseline mode
matches its environment marker to a healthy space in the active store. In
Linux home-view, where that store is intentionally hidden, it reports only the
grammar-validated marker established by the Quarters launcher.

## Residual risks

Compatibility contracts can change between tool releases. `doctor` reports
installed executables and Quarters' configured route, but the alpha does not
trace every file open. A tool can ignore its documented variable. Absolute paths
and same-user services remain reachable. Detached processes can keep using a
space after its supervisor releases the activity lease, so users must stop them
before removal. CoreFoundation's override is undocumented and may change.
An operator-selected custom store root is trusted along with its ancestor
directories; it must not be placed beneath a directory writable by another
user. Quarters validates the selected root without claiming to secure or
rewrite its ancestors.

Clone, template and snapshot capture copy arbitrary included state without interpreting or rewriting embedded
absolute paths. Such paths can still read or mutate the source Quarter or host.
Detached same-UID processes can change source files during a clone despite the
exclusive cooperative lease. Descriptor identity checks reject replacements
when any compared ownership, mode, topology, size or timestamp field changes.
A same-type replacement can still pass if every field matches within the
filesystem's timestamp granularity; held descriptors and no-follow opens still
prevent path escape. Concurrent metadata changes before open, after open or
after read abort the copy,
but the portable copy is not a database-consistent snapshot. Skipped sockets,
FIFOs, devices, foreign-owned entries and cache roots are reported by count.
Timestamps, ACLs, xattrs, filesystem flags, special mode bits, sparse extents
and hard-link topology are not preserved.

Rollback provides recoverable publication, not containment or a global process
freeze. A detached same-UID writer can continue using the retired inode or
change newly published state. Rollback therefore preserves a verified automatic
recovery artifact, reports detached writers as unknown and exposes old, new or
marked-in-progress visibility rather than claiming atomic exchange.

An exact, valid rollback marker with a filesystem tuple outside the documented
state table is intentionally non-automatic: Quarters preserves all paths,
reports the marker and observed tuple, and leaves that transaction for an
operator to reconcile while continuing unrelated recovery. Normal operations
on unrelated named spaces remain available. A malformed exact marker is also
retained and itemized but cannot be attributed to a target safely.
A failed rollback attempt may already have published its automatic recovery
snapshot; retry with a new `--recovery-name`, or verify and explicitly remove
the preserved snapshot before reusing its name.

Once the replacement is published and its marker is removed, a subsequent
retired-tree cleanup failure does not undo the rollback. The error states that
replacement completed, retains the cleanup tree under `.trash`, and directs the
operator through bounded doctor and recovery inspection.

MCP is not an authorization boundary against another process already running as
the same account. A peer can invoke the same CLI or edit files it owns. The MCP
controls limit accidental agent authority, protocol confusion, context
injection and resource exhaustion; they do not create a new Unix principal.
The 128-entry MCP status budget is applied after rollback rows are merged and
also counts the separate retained-issue records.
