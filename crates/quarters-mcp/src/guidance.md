# Quarters MCP

Quarters gives native processes persistent alternate user-owned state while the
operating system continues to see the real host account.

Start with `quarters_status`. A `free` cooperative lease does not prove that no
detached same-user process still uses the space. Read `quarters://security`
before mutation.

`quarters_create` creates a new private folder-backed space and fails when that
name already exists. It never starts a shell or command. `quarters_doctor` reads
platform and tool compatibility; when given a space name, it also constructs
the environment and may create private runtime directories.

This MCP server intentionally exposes no arbitrary process execution, shell
entry, host escape, credential inheritance, or remote network listener. Use the
human CLI for those explicit operations.
