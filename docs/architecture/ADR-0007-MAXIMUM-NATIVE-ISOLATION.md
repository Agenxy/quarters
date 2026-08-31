# ADR 0007: Earned levels for maximum native isolation

Status: research plan; no stronger protection is claimed by this alpha

## Context

Quarters aims to emulate more of a separate user or machine without becoming a
VM or OCI container. Environment redirection improves state selection but does
not stop a same-UID process from reading host paths. Encryption can protect an
unmounted space at rest, yet cannot exclude other same-UID processes while its
keys and mounted files are accessible. Platform confinement mechanisms differ
substantially and can break ordinary developer workflows.

## Decision

Report isolation as independently earned capabilities, never one marketing
mode:

1. `state-profile`: HOME/XDG and tool adapters; current portable baseline.
2. `workspace-profile`: expanded user-directory conventions; current schema-3
   layout, still not containment.
3. `passwd-home-view`: Linux user/mount namespace compatibility where policy
   and group mapping permit it; currently experimental.
4. `filesystem-policy`: an experimental Linux Landlock ABI-3 backend is earned
   by ADR 0011; macOS still has no reviewed policy backend.
5. `encrypted-at-rest`: a dismounted space is encrypted under a user-controlled
   key; mounted same-UID access remains in scope and must be stated plainly.

No level may imply network, process, device, keychain, TCC, login-session or
kernel isolation. Dynamic interposition remains optional deep compatibility,
never the correctness or security foundation.

## Research tracks

### Linux

- Probe Landlock ABI and filesystem coverage using native syscalls. Define a
  policy around an allowlisted workspace plus explicit host paths; fail closed
  when the requested ruleset cannot be enforced.
- Compare a separate idmapped/user-namespace mount design with the existing
  same-numeric-ID home view. Preserve the no-privileged-helper default.
- Evaluate kernel-backed encrypted filesystems and loop/device requirements.
  Root-dependent setup is not an automatic Quarters action. FUSE candidates
  require an open implementation, native integration and a candid same-UID
  mount-access model.

### macOS

- Treat Seatbelt only as an optional capability. Private profiles and deprecated
  `sandbox-exec` are not stable public product foundations; distribution and
  policy review must precede any flag.
- Evaluate native Disk Images and APFS encrypted-volume APIs without parsing
  shell command output. Determine signing, authorization, mount ownership,
  cleanup and crash-recovery requirements before selecting a backend.
- Measure `CFFIXED_USER_HOME`, passwd-home and application-specific behavior;
  never generalize successful CLI adapters to GUI applications.

### Shared

- Define adversaries separately: lost disk, accidental host writes, curious
  same-UID application, malicious child, administrator and kernel compromise.
- Build syscall/file-open tracing only as a test instrument. Tracing evidence
  can discover gaps but is not a runtime guarantee.
- Add capability probes, compatibility corpus, performance budgets and clear
  degraded-mode errors before public UX.

## Acceptance gates

- a written policy maps every claim to a mechanism and adversary
- adversarial escape tests and representative developer-tool compatibility
- keys never appear in arguments, environment diagnostics, logs or persistent
  plaintext metadata
- mount/unmount and crash recovery are bounded and cannot target host paths
- requested protection fails closed; baseline behavior is selected explicitly,
  never by silent fallback
- independent security review on macOS and Linux

## Consequences

Quarters can pursue a very deep native experience while keeping capability
claims composable and falsifiable. Linux confinement is now an explicit
experimental capability; encryption and a supported macOS backend remain
research work. The portable baseline still protects against accidental state
mixing, not malicious same-account access.
