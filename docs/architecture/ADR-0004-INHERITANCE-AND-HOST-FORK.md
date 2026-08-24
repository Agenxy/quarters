# ADR 0004: Previewed inheritance and host-fork policy

Status: proposed; required before host-state forking

## Context

Some users want a clean room. Others want to fork selected host configuration
into a new space so experiments cannot mutate the originals accidentally.
Broadly copying the host home would import credentials, sockets, caches,
absolute paths and live databases while suggesting more protection than the
same-UID model provides.

Environment inheritance and file inheritance are different authorities and
must not share one vague switch.

## Decision

Keep launch-time environment inheritance explicit through the existing
`--inherit NAME` model. Build future host forking on typed, previewed policies:

- `clean`: generated first-party defaults only
- `shell`: selected rc fragments and history policy, never arbitrary evaluation
  during creation
- `config`: named tool configuration adapters
- `paths`: user-selected files or directories beneath the host home
- `credentials`: separate, opt-in adapters with conspicuous review
- `environment`: selected variable names; values remain redacted in output

There is no `inherit all`. Every preset expands into a machine-readable plan
showing source category, destination, size estimate, conflict behavior,
sensitivity and whether an adapter transforms the data. The user can save a
named policy, but not hidden approvals for credential categories.

Host fork uses the lifecycle transaction from ADR 0003. Sources are opened
without following a final symlink; selected paths must remain beneath a
validated host-home anchor unless a separate exact path is explicitly granted.
Destination conflicts fail by default. Provenance records categories and
content metadata, never secret values.

Startup files are data, not trusted code. Quarters may copy them only as files
after preview and must warn that entering the space can execute their contents.
It never sources host startup files during creation. Absolute host paths are
reported by adapters when detectable but are not rewritten heuristically.

## Command shape under consideration

```text
quarters create NAME --from-host POLICY --preview
quarters create NAME --from-host POLICY --confirm-plan DIGEST
quarters inheritance inspect POLICY
```

The plan digest binds confirmation to the exact source metadata and policy.
Changes between preview and execution force a new preview.

## Acceptance gates

- adversarial symlink and source-replacement races fail closed
- credential categories never appear without explicit selection
- previews and errors contain no values or file contents
- adapter transformations are deterministic and independently testable
- interrupted creation publishes no partial space
- tests cover shell files that contain commands, hostile filenames and large
  source trees

## Consequences

Users can build a familiar Quarter without a dangerous blanket home copy. The
same-UID process can still read the original host state by absolute path; host
fork reduces accidental mutation and state selection, not host authority.
