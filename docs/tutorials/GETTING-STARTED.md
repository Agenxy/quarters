# Getting started

## 1. Build and inspect the host

```sh
cargo build --release
target/release/quarters doctor
```

Read the authority line first. The baseline separates state selection, not file
access.

## 2. Create a space

```sh
target/release/quarters create clean
target/release/quarters list
target/release/quarters status clean
target/release/quarters env clean
```

The home is under `~/.quarters/spaces/clean/home`. The generated Git config
deliberately has no credential helper. `list` reports unhealthy entries instead
of letting one damaged space hide its healthy siblings.

For a broader user-workspace shape, choose it explicitly:

```sh
target/release/quarters create studio --layout workspace
target/release/quarters --json status studio
```

This adds private personal directories such as `Desktop`, `Documents` and
`Downloads`; macOS also gets conventional `Applications` and selected
`Library` paths. It is still the same OS account and filesystem authority.

## 3. Clone a space safely

Preview the included state and exclusions without creating anything:

```sh
target/release/quarters clone studio experiment --preview
```

When the policy and counts are expected, exactly repeat the source name:

```sh
target/release/quarters clone studio experiment --confirm-sensitive-state studio
```

This acknowledgement matters because arbitrary files may contain credentials,
histories, tokens and agent state. Cache roots are recreated empty by default;
use `--include-cache` only when their contents are deliberately needed. Runtime
sockets, FIFOs, devices and foreign-owned entries are skipped and counted.

Clone holds the cooperative source lease exclusively, but detached writers are
still unknown. It is an atomic independent copy, not a live database snapshot or
containment boundary. Embedded absolute paths are copied unchanged and may still
point at the source.

## 4. Create a template, snapshot and guarded rollback

Capture reusable stationery after reviewing the preview:

```sh
quarters template create studio-clean --from studio --preview
quarters template create studio-clean --from studio --confirm-sensitive-state studio
quarters template use studio-clean new-studio --preview
quarters template use studio-clean new-studio --confirm-sensitive-state studio-clean
```

Templates omit derived caches unless `--include-cache` is explicit and create a
fresh space identity. They can contain credentials; Quarters does not guess at
a safe scrub policy.

Create and independently verify a recovery point:

```sh
quarters snapshot create studio before-change --preview
quarters snapshot create studio before-change --confirm-sensitive-state studio
quarters snapshot verify before-change
```

Snapshots include caches by default. To restore one, first preview the selected
snapshot and the required automatic recovery capture:

```sh
quarters rollback studio before-change --recovery-name before-rollback --preview
quarters rollback studio before-change --recovery-name before-rollback \
  --confirm-space studio --confirm-replace-state studio
```

Rollback replaces the complete home and retains the target identity. It is not
a merge or same-UID security boundary. If power loss interrupts publication,
`quarters doctor` reports `abort`, `restore-old` or `complete-new`; inspect that
decision before running `quarters recover --confirm stale-state`.

If a rollback attempt fails after its automatic recovery snapshot is created,
that snapshot is deliberately retained. Inspect it, then retry with a new
`--recovery-name`; alternatively verify and explicitly remove the retained
snapshot before reusing the old name.

## 5. Add an optional short command

Install Quarters first. When `~/.local/bin` is already on the host PATH:

```sh
quarters shortcut status qts
type -a qts
quarters shortcut install qts
type -a qts
```

Quarters will not replace an existing filesystem entry. The explicit `type -a`
check matters because a child cannot see aliases and functions defined only in
its parent shell. Remove only the managed link with
`quarters shortcut remove qts`. The shorter `q` name is opt-in.

## 6. Prove state separation

```sh
target/release/quarters exec clean -- sh -c 'printf "%s\n" "$HOME" "$QUARTERS_SPACE"'
target/release/quarters exec clean -- git config --global user.name "Clean profile"
git config --global user.name
```

The last command runs on the host and should retain the host value. File
permissions and access are still those of the same account.

## 7. Enter the shell

```sh
target/release/quarters enter clean
```

The generated prompt includes `[q:clean]`. `quarters current` prints `clean` when
the installed binary is on PATH.

Quarters composes with the existing prompt. For a space created by an older
build, add one of these lines to its own startup file:

```sh
eval "$(quarters shell-init zsh)"
eval "$(quarters shell-init bash)"
```

Use only the line for that shell. Quarters never edits an existing startup
file automatically.

Use a login shell only when required:

```sh
target/release/quarters enter clean --login
```

Host system profiles can run in login mode.

## 8. Pass a variable deliberately

The baseline does not inherit arbitrary variables:

```sh
MY_SETTING=present target/release/quarters exec clean -- env
MY_SETTING=present target/release/quarters exec clean --inherit MY_SETTING -- env
```

`env clean --inherit MY_SETTING` shows the value as redacted.

## 9. Use host state explicitly

Inside a baseline shell:

```sh
quarters host -- sh -c 'printf "%s\n" "$HOME"'
```

This restores host path variables only. It does not restore blocked credential
variables. Exit the space when you need the exact original host environment.

## 10. Remove the space

Exit every process launched in the space, inspect the name, then run:

```sh
target/release/quarters status clean
target/release/quarters rm clean --confirm clean
```

Quarters refuses removal while the supervising `quarters` process for an entry
is active. It cannot portably detect a detached child, background job or server
after that supervisor exits, so `status` reports detached processes as unknown
and you must stop those processes first. Removal is not
secure erasure from backups or filesystem snapshots.

If a home or manifest is unhealthy, `list` and `status` show the exact issue and
`rm` can still remove the named entry after validating its private root and
activity lock. Quarters fails closed and requires manual inspection when either
of those removal anchors is invalid.
For an invalid stored name, obtain the exact value from `quarters --json list`.
Removal accepts one literal entry name but never a path, `.` or `..`.

## 11. Connect a local agent

Build or install Quarters, then configure the agent host to run the absolute
binary path with the single `mcp` argument. Quarters communicates only over the
host-provided standard input/output pipes.

Ask the agent to read `quarters://security` before using a mutating tool. It can
inspect, run doctor and create a space. It cannot enter that space, execute a
command, clone state, pass host credentials or remove anything. Use the human
CLI for those operations after reviewing their authority implications.

The create tool accepts an optional closed `layout` value of `profile` or
`workspace` under both supported protocol revisions.

For a non-default store, place `--root` and its absolute path before `mcp` in
the configured argument list. Tool calls cannot change that startup binding.
