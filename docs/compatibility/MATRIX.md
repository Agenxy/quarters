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
| Git | B | `GIT_CONFIG_GLOBAL` | repository-local config still wins |
| Git credentials | B/D | empty per-space helper | macOS Keychain is host-bound if a user adds that helper |
| OpenSSH | C | per-space config used with `ssh -F` | macOS passwd home is unchanged; absolute invocations bypass adapters |
| SSH agent | B | short per-space `SSH_AUTH_SOCK` | no agent is started automatically in this alpha |
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
