# ADR 0004: Previewed inheritance and host-fork policy

Status: accepted; shell-policy host fork implemented

## Context

Some users want a clean room. Others want to fork selected host configuration
into a new space so experiments cannot mutate the originals accidentally.
Broadly copying the host home would import credentials, sockets, caches,
absolute paths and live databases while suggesting more protection than the
same-UID model provides.

Environment inheritance and file inheritance are different authorities and do
not share one vague switch.

## Decision

Launch-time environment inheritance remains explicit through `--inherit NAME`.
Host forking begins with one closed `shell` policy:

```text
quarters create NAME --from-host shell --preview
quarters create NAME --from-host shell --confirm-plan DIGEST
```

The preset selects only conventional zsh, bash, profile, input and editor
startup files. Up to 32 additional regular files can be named with
`--from-host-path RELATIVE_PATH`. Credentials, histories, caches, runtime
state and agent state are excluded from the preset. Known credential, history
and cache paths fail even when named explicitly; later credential support
requires typed adapters and a separate security review. Quarters does not
inspect selected file contents, so startup and explicit files may still embed
secrets.

Planning opens the absolute host `HOME` as a protected current-user directory.
Every selected component is then opened descriptor-relatively without following
links. Intermediate directories and final files must stay current-user-owned
and non-writable by group or other; files must be regular, single-link entries.
An unsafe optional preset is reported as ineligible and digest-bound; the same
path named explicitly is a hard error. The phase accepts at most 1 MiB per file
and 8 MiB total. It never evaluates a startup file during creation.

The content-free preview reports paths, categories, sizes, missing optional
preset paths, ineligible presets, deterministic transformations and generated-file conflicts. Its
domain-separated BLAKE3 digest binds the destination, layout, shell, policy,
replacement choice, home identity, every selected path and file generation,
every traversed directory generation, and absent or ineligible preset paths. Execution
recomputes the plan, requires the exact lowercase digest, retains the opened
source descriptors, verifies each source before and after copying, and
revalidates all source paths before publication.

Generated `.zshrc` and `.bashrc` files are conflicts. Replacing them requires a
new preview with `--replace-generated`, which changes the confirmation digest.
Copied versions receive a constant state-and-prompt tail that reasserts the
per-space history path. Other selected files are copied byte-for-byte with
private mode. Provenance records the plan, selection metadata and exclusions,
never content or content-derived hashes.

Creation uses a private generation-bound staging root and same-filesystem atomic
rename. A failure publishes nothing. Host forking is unavailable from inside a
Quarter so the source anchor cannot silently become an outer space. The local
MCP server deliberately receives no host-fork authority.

## Acceptance gates

- stale previews and source replacements fail closed without publication;
  linked optional presets are ineligible and linked explicit paths are errors
- unprotected homes, broad source modes, hard links, special files and resource
  excesses fail closed
- dedicated sensitive paths never enter the shell policy, selected contents
  are marked uninspected, and previews contain no values or file contents
- generated-file replacement requires a distinct reviewed plan
- startup commands are not executed during creation
- execution produces either no destination or one complete private space with
  provenance
- warnings-as-errors, structural limits, macOS end-to-end acceptance and Linux
  target compilation pass before the feature is accepted

## Consequences

Users can seed a familiar Quarter without a blanket home copy. This reduces
accidental mutation and makes the selection reviewable; it does not make
untrusted startup files safe. Entering the result may execute copied code.

The same-UID process can still read or alter original host state through
absolute paths, open services or other account authority. The plan digest is a
confirmation binding, not authentication against another same-UID process.
Directories, arbitrary configuration trees, environment values, credentials
and history remain future typed policies rather than implied support.
