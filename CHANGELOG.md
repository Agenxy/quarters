# Changelog

Quarters follows [Semantic Versioning](https://semver.org/). Until 1.0, minor
versions may refine the space format and environment contract; migrations and
compatibility notes will be called out here.

## 0.1.0-alpha.1 — 2026-08-20

First public alpha.

- Create, inspect, enter, execute within and remove persistent named spaces.
- Redirect `HOME`, XDG roots, shell history, runtime paths and representative
  developer-tool state while preserving the real host identity and authority.
- Start children from a strict environment allowlist with explicit inheritance.
- Restore host state paths through the named `host` escape on baseline spaces.
- Probe macOS and Linux capabilities without overstating confinement.
- Offer an opt-in Linux bind-mounted home view backed by user and mount
  namespaces, with unsupported configurations failing closed.
- Provide stable JSON output for management and inspection commands.
