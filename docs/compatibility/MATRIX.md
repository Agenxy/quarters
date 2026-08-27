# Compatibility matrix

Classes describe state-location behavior, not security:

- **A:** follows `HOME` or XDG paths directly
- **B:** follows an explicit environment or config override
- **C:** needs invocation-specific adaptation
- **D:** remains tied to host account or service state

`quarters doctor` combines this contract with executable discovery on the
current host. It does not read credentials.

| Tool or state | Class | Quarters route | Remaining gap |
|---|---:|---|---|
| zsh | A | `HOME`, `ZDOTDIR`, `HISTFILE` | `/etc/zprofile` runs only with `--login` and may reorder PATH |
| bash | A | `HOME`, `.bashrc` | system login profiles can still run |
| Prompt context | B | validated `QUARTERS_PROMPT_PREFIX` plus `shell-init` | parent themes may need explicit ordering; marker is not proof of isolation |
| Expanded workspace | A/C | HOME/XDG plus conventional personal directories | passwd-home, platform registration and absolute paths may remain host-bound |
| Host shell fork | B/C | previewed descriptor-anchored selection, digest confirmation and atomic publication | entering may execute copied startup code; credentials, history and directories remain excluded |
| Lifecycle clone | B/C | bounded native copy with explicit policy and atomic publication | detached writers unknown; selected metadata and embedded absolute paths are not transformed |
| Named templates | B/C | canonical BLAKE3-verified portable copy plus fresh destination controls | arbitrary state may contain credentials; embedded paths are not rewritten |
| Named snapshots | B/C | immutable-by-interface recovery point with whole-tree verification | cooperative lease cannot prove detached writers are absent |
| Rollback | C | verified recovery capture plus durable three-state whole-home replacement | old, new or marked-in-progress visibility; no recursive merge or detached-writer proof |
| Authenticated bundle | C | keyed-BLAKE3 plaintext export of a verified artifact; retained-descriptor two-pass import as an external template | key travels separately; no confidentiality or content-safety claim; case-colliding or normalizing filesystems may refuse import |
| Space rename | C | durable marker, same-filesystem directory move and atomic manifest replacement | display name only; detached same-UID processes remain unknown |
| Private cleanup | C | iterative owner-checked removal with depth/count limits | mode-`000` recovery on Linux may require `/proc` for no-follow `fchmodat` emulation |
| Git | B | `GIT_CONFIG_GLOBAL` | repository-local config still wins |
| Git credentials | B/D | empty per-space helper | macOS Keychain is host-bound if a user adds that helper |
| OpenSSH | C | managed `ssh`, `scp` and `sftp` links force protected config, user-known-hosts path and no default identity files | passwd home is unchanged; explicit or absolute host paths remain intentional bypasses |
| `ssh-add` | C | managed link permits explicit per-space keys and agent inspection; bare/default and host-keychain import are refused | explicit host import requires `quarters host -- ssh-add ...` |
| SSH agent | C/D | explicit private lifecycle and narrow recovery; host socket stays blocked | agent keys remain same-UID state and are not a containment boundary |
| GitHub CLI | B | `GH_CONFIG_DIR` | environment tokens require explicit `--inherit` |
| tmux | B | `TMUX_TMPDIR` | host sessions are intentionally not visible |
| GnuPG | B | `GNUPGHOME`, short runtime | external keychain or hardware identity remains host hardware |
| Python | A | `HOME`, XDG | system and site packages remain shared |
| uv | B | cache, Python and tool directory variables | host binaries remain shared |
| Cargo | B | `CARGO_HOME` | system and rustup toolchains may remain shared |
| npm | B | user config and cache variables | global system prefix remains shared |
| Codex | B/D | `CODEX_HOME` | OS keychain, permissions and login session remain host-bound |
| Claude Code | B/D | `CLAUDE_CONFIG_DIR` | OS keychain, permissions and login session remain host-bound |
| OpenCode | B | XDG and config variable | behavior depends on installed release |
| `sudo` | D | host authority | escapes baseline; unavailable in Linux home view |
| systemd user services | D | none | attached to real login user manager |
| macOS Keychain and TCC | D | none | attached to real login identity and code signature |
