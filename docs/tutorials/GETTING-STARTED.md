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

## 3. Prove state separation

```sh
target/release/quarters exec clean -- sh -c 'printf "%s\n" "$HOME" "$QUARTERS_SPACE"'
target/release/quarters exec clean -- git config --global user.name "Clean profile"
git config --global user.name
```

The last command runs on the host and should retain the host value. File
permissions and access are still those of the same account.

## 4. Enter the shell

```sh
target/release/quarters enter clean
```

The generated prompt includes `[clean]`. `quarters current` prints `clean` when
the installed binary is on PATH.

Use a login shell only when required:

```sh
target/release/quarters enter clean --login
```

Host system profiles can run in login mode.

## 5. Pass a variable deliberately

The baseline does not inherit arbitrary variables:

```sh
MY_SETTING=present target/release/quarters exec clean -- env
MY_SETTING=present target/release/quarters exec clean --inherit MY_SETTING -- env
```

`env clean --inherit MY_SETTING` shows the value as redacted.

## 6. Use host state explicitly

Inside a baseline shell:

```sh
quarters host -- sh -c 'printf "%s\n" "$HOME"'
```

This restores host path variables only. It does not restore blocked credential
variables. Exit the space when you need the exact original host environment.

## 7. Remove the space

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

## 8. Connect a local agent

Build or install Quarters, then configure the agent host to run the absolute
binary path with the single `mcp` argument. Quarters communicates only over the
host-provided standard input/output pipes.

Ask the agent to read `quarters://security` before using a mutating tool. It can
inspect, run doctor and create a space. It cannot enter that space, execute a
command, pass host credentials or remove anything. Use the human CLI for those
operations after reviewing their authority implications.

For a non-default store, place `--root` and its absolute path before `mcp` in
the configured argument list. Tool calls cannot change that startup binding.
