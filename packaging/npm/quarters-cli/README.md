# Quarters for npm

This package installs the native `quarters` command. It selects a matching
architecture package and then hands control to the same Rust binary distributed
through Homebrew, Cargo and GitHub Releases.

```sh
npm install --global quarters-cli
quarters --version
```

The current npm targets are macOS arm64, macOS x64 and Linux x64. An unsupported
platform fails with a direct explanation; the package does not download or run
unverified code during installation.

Quarters redirects user-owned state for native process trees. It does not change
your UID, permissions or machine identity, and its baseline is not a sandbox or
security boundary.

Apache-2.0. Source: <https://github.com/Agenxy/quarters>
