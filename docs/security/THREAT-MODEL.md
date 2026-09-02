# Threat model

## Assets

- host credentials, histories and CLI configuration
- integrity and confidentiality of host files considered for a host-fork plan
- state in one Quarters space that should not be selected accidentally by
  another space
- host files reachable by the real Unix account
- the validated storage root and removal target
- terminal control and process exit status
- agent context integrity and bounded MCP availability
- bundle authentication keys and exported plaintext state
- cooperative freeze policy and recorded artifact source evidence
- integrity of host and sibling-space file content during an opt-in Landlock launch

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
| Host fork imports broad or known sensitive paths | Closed shell preset, explicit regular-file allowlist, case-insensitive credential/history/cache path denylist, file/count/size bounds and no directory recursion; output admits selected contents are uninspected |
| Host fork follows a swapped source path | Protected absolute HOME anchor, descriptor-relative no-follow component walk, retained source descriptors and pre-publication path-generation verification; linked presets are digest-bound ineligible entries |
| Preview approves different host state | Domain-separated digest binds destination policy, home and traversed-directory identities, file metadata, missing presets and replacement choice; any observed change requires a new preview |
| Copied startup content runs during creation | Source bytes are never evaluated; copy is native descriptor I/O and acceptance uses an execution sentinel |
| Generated startup state is overwritten silently | Conflicts fail until `--replace-generated` is included in a new preview and therefore in a new digest |
| Artifact content changes after capture | Canonical whole-tree BLAKE3 verification binds stored paths, types, ordinary modes, content, link targets and counts before every use |
| Artifact digest is mistaken for authentication | Output and documentation state that another same-UID process can alter both content and manifest |
| Cooperative freeze is mistaken for write protection | Human, JSON, status and provenance call it cooperative; the boundary states that existing, detached and direct same-UID writers continue |
| Malformed freeze marker fails open or strands the space | Atomic temporary-and-rename publication, stable-ID path, 4-KiB bounded no-follow read, current-UID/type/mode/single-link validation, strict parsing and fail-closed launch errors; exact confirmed unfreeze removes an invalid marker only after its private file anchor revalidates |
| Launch or mutation races freeze | Freeze and lifecycle entry serialize under the management guard; launch checks the marker before taking its shared lease, and existing operations are explicitly allowed to finish |
| Forged current context retargets active capture | CLI-only inference reopens a healthy space and requires name, root and home evidence to agree; core active capture also observes a pre-existing held cooperative lease and valid freeze marker |
| Active capture claims source quiescence | Schema-3 records `frozen-active`, publication rechecks the freeze under the management guard, output admits already-running writers, and integrity binds the completed staging tree rather than claiming a crash-consistent source snapshot |
| Bundle mutation or wrong key | Complete keyed-BLAKE3 tag over strict bounded framing; import authenticates twice on one retained descriptor and compares tags in constant time |
| Bundle traversal or extraction collision | Compile-time limits, canonical parent-first paths, descriptor-relative exclusive creation, one bounded raw-name/inode sweep and private atomic staging |
| Bundle overwrites a user file | Retained protected parent, exclusive hidden staging and no-clobber link publication outside the Quarters store |
| Bundle key leaks through output | Exact private key-file contract; key path and bytes are omitted from reports, errors and stored metadata |
| Bundle key is captured into its own plaintext bundle | Key creation and every export/import key use reject resolved paths inside the active store |
| Post-commit filesystem failure is mistaken for no publication | Link and rename commit points return visible state with an explicit durability or hidden-staging warning |
| Hostile bundle path metadata exhausts memory before authentication | Compile-time byte/entry limits plus a fallible active-directory stack; extraction verifies and releases each directory as traversal leaves it |
| Foreign bundle identity authorizes local state | Schema-2 imported templates have no local source binding and always report `external`; snapshots import only as creation sources |
| Partial rollback replaces only some state | Complete staging, verified automatic recovery snapshot and durable prepared/retired/published transaction; recursive merge is forbidden |
| Interrupted display-name rename | Stable identity, private durable marker, same-filesystem move and atomic manifest replacement; valid states recover deterministically while malformed markers remain localized issues |
| Crash leaves a target apparently absent | Atomic marker publication and exact filesystem tuples produce bounded actions; malformed or ambiguous markers preserve every tree, become itemized issues, block only a known named target and do not stop unrelated recovery |
| Recovery deletes an unrelated path | Only private exact-form generated IDs, free creation locks and validated manifest temporaries are reclaimable; malformed reserved-looking and unknown hidden entries remain counted without blocking unrelated recovery |
| Manifest downgrade or field confusion | Permissive version probe followed by strict closed schema and version/layout/ID invariants |
| Abandoned internal state | Bounded doctor counts; confirmed recovery retires entries under the management lock, then deletes outside it |
| Root-format confusion creates two stores | Strict authoritative marker, visible/dotted dual detection, active-migration refusal and one management-held writable-layout token for every mutation |
| Malicious or interrupted format marker is followed | Nonblocking no-follow bounded reads, current-UID/type/mode/link validation, newer-schema header probe, exact descriptor-relative staging cleanup, management-held two-link crash convergence and bounded non-mutating doctor diagnosis |
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
| Shortcut replacement or deletion | Protected PATH directory, non-overwriting symlink creation and descriptor-relative removal only when target, device, inode and change timestamp still match the inspected Quarters-launcher link; matching-tuple reuse and the final check/unlink race remain inside the same-UID boundary |
| Host Git helper reuse | Generated config clears inherited credential helpers |
| Shared SSH agent | Host socket is never inherited; only an explicitly started, fully verified private socket is advertised |
| Forged or replaced private agent | Atomic token-bearing record, live PID, current-user socket device/inode, kernel-reported peer PID and bounded SSH identities response must all agree |
| Agent cleanup signals or unlinks the wrong target | Stop is limited to a fully verified active record; recovery removes only dead socketless records or exact stored socket identities and never follows links |
| Agent startup failure, race or supervisor crash | Stable identity is required before spawn; a bounded `starting` reservation and separate startup-owner lease are published under the lifecycle lock, readiness waits without that lock, and only the live owner or a proven orphan may promote after exact-record and full-socket revalidation; one exited launcher may be replaced under the same lease through an atomic reservation transition, while every final spawned-owner error resolves to verified active state or bounded termination and ambiguous persistent state remains fail-closed |
| OpenSSH ignores redirected HOME | Managed links force protected per-space config, a per-space user-known-hosts path and no default identity files; tool-specific parsing rejects competing `-F`, bare `ssh-add` and host-keychain import; host-tool resolution excludes relative directories |
| Forged adapter context | Baseline adapters reopen the validated store and require the declared root, space and home to agree; protected OpenSSH config anchors are revalidated before invocation |
| Managed command collision | Installation never replaces entries, validates every command-directory ancestor and reports exact links as stale when their launcher is unavailable; lifecycle copying omits only the closed managed-link shapes |
| Runtime socket collision | Mode-0700 short runtime directory per UID and stable space identity |
| Read-only status creates runtime state | Agent status uses a validation-only runtime lookup and reports unset without creating directories |
| Unsupported stronger mode | Capability check and fail-closed error |
| Requested Linux confinement silently degrades | ABI-3 hard requirement, `no_new_privs`, `FullyEnforced` check and required hosted-kernel gate |
| Confined child reads or mutates host/store content | Fixed descriptor-anchored allowlist; exact Quarter home/runtime are writable while ungranted content reads, directory enumeration and mutation are denied |
| User grant expands confinement unexpectedly | Invocation-local absolute path plus explicit `ro`/`rw`; canonical data-only rule, distinct bounded roots, JSON disclosure, validated device/inode match on the opened rule anchor and overlap rejection for store/runtime/current and request executables/executable-root/passwd credential/home-view roots |
| Granted workspace supplies an executable | User grants omit Landlock execute rights, cannot overlap broader executable grants, and executable resolution uses the separate Quarter command root plus reviewed system roots rather than the selected workdir |
| Executable changes between policy review and process replacement | Quarters verifies and holds an `O_PATH` descriptor, then uses descriptor-bound execution after Landlock is enforced; interpreter fallback retains the same reviewed descriptor |
| External confined working directory is ambient | `--workdir` is canonicalized and must lie below the Quarter home, an explicit directory data grant, or a passwd-home path whose same relative directory is verified inside the Quarter home before `--home-view` mounts it |
| Confinement is mistaken for invisibility | Policy JSON and docs state that known-path metadata, `stat`, `readlink`, existence checks, `O_PATH` and path traversal alone remain observable |
| Confinement launcher leaks store or host handles | Parent retains the cooperative lease; policy anchors are close-on-exec; launcher is single-threaded and immediately execs after restriction; inherited caller descriptors remain an explicit limitation; descriptor-bound interpreter scripts intentionally inherit one readless `O_PATH` handle and can observe `/dev/fd` as their source path |
| Host PATH bypasses the policy | Confined PATH is reconstructed from Quarter-local bins and entries whose canonical directories fall beneath fixed executable grants; omitted host entries are counted |
| Namespace setup affecting caller | Dedicated internal child performs Linux namespace calls |
| Home-view source or target changes during setup | Both owned directories remain open; a private runtime staging mount is verified against the source descriptor, then Linux `move_mount` attaches it to the target descriptor before the mounted inode is verified |
| Terminal injection is mistaken for filesystem mediation | Policy output reports `dev.tty.legacy_tiocsti`; any state not proven disabled is repeated in the limitations array, and Landlock ABI 3 is not claimed to mediate terminal ioctls |
| Supplementary groups in home view | Capability is unavailable unless the primary group is the only active group |
| Secret diagnostics | No state content reads; explicit inherited values render as redacted |
| MCP lifecycle confusion | Exact 2026/2025 families; cross-family methods and version metadata fail closed |
| MCP memory or task exhaustion | One-MiB frames, two-second output deadlines, 32 response-lifetime request slots, 8,192 legacy IDs, bounded listings, one queued transport error and two blocking store workers |
| MCP receive cancellation drops protocol errors | Decoded transport errors transfer synchronously into a bounded writer actor before input processing resumes |
| MCP output backpressure | Bounded encoding and timed error writes; stalled peers cannot grow unbounded queues |
| MCP request replay | Duplicate live IDs close the connection; legacy IDs are never reusable in-session |
| Agent prompt injection from disk | Invalid entry names are bounded hex and detailed stored-entry errors are replaced on MCP surfaces |
| Terminal or JSON presentation injection | Human and JSON stored text is escaped and bounded before emission |
| Agent overreach | MCP has no clone, host-fork, freeze, active-capture, exec, enter, host, inherit, home-view, root-selection or removal tool |
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
- confidentiality, non-repudiation or content-safety review for authenticated bundles
- authenticating artifact state against another process with the same UID
- treating a free cooperative lease as proof that detached clone writers are absent
- treating cooperative freeze as filesystem immutability, confinement,
  encryption or protection from a process with the same UID
- treating `frozen-active` provenance as proof that already-running writers
  were quiescent
- treating workspace directories or a stable space ID as containment or authorization
- claiming network, IPC, device, process or credential isolation from Linux filesystem confinement
- treating a user-granted path as inspected, trusted, or executable authority
- hiding known-path metadata or revoking file descriptors opened before Landlock enforcement
- treating a private SSH agent as protection from another process with the same UID
- treating host-fork preview or provenance as authentication against the same UID
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

Linux `--confinement filesystem` is a distinct opt-in boundary. It sets
`no_new_privs`, so ordinary set-id elevation is disabled, and `quarters host`
cannot remove the inherited kernel domain. The routing marker proactively
blocks store commands but is not the boundary: a child can unset it without
relaxing Landlock. The policy grants `/proc` and selected terminal devices for
compatibility. Ptrace-domain effects and host policy can change which proc
entries are visible; Quarters makes no general process or credential-
confidentiality claim. Network and IPC remain shared.

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

Host fork copies selected startup files as untrusted data. Creation does not
run them, but a later interactive shell may. The metadata digest detects the
changes Quarters observes between preview and publication; it is not a MAC and
cannot stop another process with the same UID from modifying both source and
destination state. This phase rejects credentials and directories rather than
claiming a general host-home clone. Startup and explicit files can still embed
secrets because Quarters does not inspect or redact their contents. It preserves
file bytes but intentionally normalizes destination permissions and appends a
constant state-and-prompt tail to zsh and bash interactive startup files. The
tail reasserts Quarters' history path, but startup code can still perform
arbitrary host-account reads and writes before it runs.

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

Active stationery capture narrows only Quarters-managed concurrency. It
requires a valid freeze marker, an existing held cooperative lease and an additional
shared lease during the copy, so new managed launches and exclusive lifecycle
operations cannot begin. The already-running process tree can still write, and
another same-UID process can alter either the source or marker directly.
`frozen-active` provenance records that weaker evidence class; it is not a
global process freeze or database checkpoint.

An authenticated bundle is intentionally plaintext and uses one symmetric key:
it provides neither confidentiality nor proof of which key holder created it.
The receiver must protect and transport the key separately, and can replay any
older bundle authenticated by that key. Import refuses case-folding or
normalizing filesystems when the extracted byte names do not reproduce the
authenticated canonical tree. Successful authentication proves only the bytes;
startup files, credentials and executables inside the bundle remain untrusted
content that can act with the real account's authority after use.

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

Private-agent ownership is operational evidence, not a new principal. Another
process with the same UID can read space files, connect to the socket, alter
runtime state or signal the agent under ordinary host policy. The random token
coordinates the Quarters helper handoff and prevents accidental record mixups;
it is not an authorization secret against the real account. PID reuse cannot
pass active verification while the original live socket device/inode,
kernel-reported socket peer PID and SSH protocol endpoint remain required
together. Stop repeats that complete socket proof immediately before signaling.
Incomplete records intentionally prefer retained state and a blocked launch
over speculative cleanup.

Managed OpenSSH links improve default state selection, but users can bypass
them with absolute executable paths, altered PATH entries or tools that invoke
OpenSSH internally by absolute path. The forced config controls OpenSSH's own
configuration lookup. The adapter also overrides the passwd-home-derived
user-known-hosts path and disables default identity files; an explicit `-i`,
agent key or absolute path remains an intentional escape. It cannot prevent
access to any host file readable by the real UID.

Nested Quarters launches retain the original host HOME, PATH and runtime
backups instead of treating the outer Quarter as the host. This prevents
adapter recursion and makes `quarters host` return to the real captured host
state. Linux home-view is an explicit exception to baseline adapter context
reopening because its mount intentionally hides the authoritative store; its
adapter still validates protected config paths, but it is not an authority
boundary and host escape remains disabled.

Host-tool resolution canonicalizes candidates and rejects both the running
Quarters device/inode and every candidate whose resolved basename is
`quarters`; direct parent-child adapter recursion fails before another process
is spawned. The basename rule matters in Linux home-view, where an original
`$HOME/.local/bin` path can refer to a distinct runtime launcher copy after the
home bind mount.
The home-view launcher therefore installs a validated private runtime command
set before mounting: one copied `quarters` executable and four relative
OpenSSH links. OpenSSH-link collisions fail closed and are never replaced.

MCP is not an authorization boundary against another process already running as
the same account. A peer can invoke the same CLI or edit files it owns. The MCP
controls limit accidental agent authority, protocol confusion, context
injection and resource exhaustion; they do not create a new Unix principal.

Rename recovery bounds successful filesystem mutations to 128 per pass but
scans the complete marker namespace so retained ambiguous records cannot starve
later actionable work. This is linear work controlled by the same UID, not a
constant-time operation or a containment property.
The 128-entry MCP status budget is applied after rollback rows are merged and
also counts the separate retained-issue records.
