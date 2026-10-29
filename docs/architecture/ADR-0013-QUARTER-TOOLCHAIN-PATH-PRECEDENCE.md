# ADR 0013: Quarter toolchain PATH precedence

Status: accepted

## Context

The baseline profile redirects tool homes into the Quarter: `CARGO_HOME`,
`HOME` (and with it Go's default `GOPATH` of `~/go` and Bun's default install
root of `~/.bun`) and the XDG directories. Until this decision the launch PATH
was the Quarter's `~/.local/bin` followed by the inherited host PATH, which on a
developer machine usually contains the host home's `~/.cargo/bin`, `~/go/bin`
and `~/.bun/bin`.

A user testing a Quarter measured the consequence. `go install` inside a
Quarter wrote the binary to the Quarter's `go/bin`, but a bare command name then
ran the host's older copy from the host home's `go/bin`, and nothing said so.
The same applies to `cargo install` and `bun install --global`. The Quarter's
promise that it has its own user-owned state broke silently at the point where
a developer checks what they just built.

## Options

1. Put each redirected toolchain home's executable directory on PATH ahead of
   the host PATH.
2. Remove host-home executable directories from the Quarter PATH.
3. Keep the order and warn from `env` or `doctor` when a name resolves to a
   host-home directory.

Option 2 breaks the baseline: host tools such as rustup's proxies in
`~/.cargo/bin` are how many hosts provide `cargo` at all, and the baseline
preserves the host's executables. Option 3 documents a trap instead of
removing it, and a warning in a separate command does not reach the moment a
user runs the wrong binary.

## Decision

The baseline PATH is, in order, the Quarter's `~/.local/bin`, `CARGO_HOME/bin`
(`~/.cargo/bin`), `~/go/bin` and `~/.bun/bin`, followed by the host PATH
unchanged. A tool installed inside the Quarter therefore shadows a same-named
host copy, and host tools that were not installed in the Quarter stay
reachable after them. The directories are listed whether or not they exist yet,
so a tool installed in the current shell is found without starting a new one.

Filesystem confinement keeps its separately reconstructed PATH, and the Linux
home view keeps its private runtime launcher directory first.

## Consequences

- Development inside a Quarter runs what it built. An acceptance test drives the
  real launcher and proves Quarter copies win for each directory, that user
  installs come first among them, and that host-only tools still resolve.
- Like every PATH-based route, this is precedence, not isolation. An absolute
  path or a tool that ignores PATH still reaches the host copy.
- A Quarter that has not installed a tool keeps using the host's, which is the
  intended baseline behavior.
