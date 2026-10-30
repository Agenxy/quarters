# Engineering standards audit

Quarters against Agenxy's `ENGINEERING.md` (organisation `.github` repository),
audited on 2026-10-29. Each rule has a status, its evidence, and either the fix
that made it hold or a departure with its reason. Departures are recorded here
because the standard allows departing in writing and forbids departing
silently.

Status is one of **Holds**, **Fixed** (made to hold by the change that added
this audit or an earlier release-list PR) or **Departure**.

| Rule | Status | Evidence, fix or departure |
|---|---|---|
| Elite technical choice; no security or performance problem postponed | Holds | The alpha ships only when every known issue is handled. Each release-list item lands as its own reviewed PR, and none was waived. |
| Latest stable release of every language, tool, library and runtime | Fixed | Every pin was moved to its current release (#14). `quarters-quality drift` compares all 37 pins with upstream and the scheduled Drift workflow runs it daily (#31). |
| Pin the toolchain and keep the pins current | Fixed | `rust-toolchain.toml`, the launcher's `packageManager`, `pyproject.toml`, workflow pins and exact `=x` Cargo pins. The gate refuses a workflow or document naming a version other than the pin (#31). |
| Warnings are errors | Holds | `[workspace.lints]` denies `warnings`, `clippy::pedantic`, `unsafe_code`, `missing_docs`, `expect_used`, `unwrap_used` and `panic`; `tsc` runs with `strict`. |
| Suppress one occurrence, narrowly, with a comment saying why | Fixed | All 23 `#[allow]` attributes now carry a reason: 21 test modules using `expect` for failure context, one platform `dev_t` cast, one deprecated rmcp entry point a test exercises on purpose. |
| Line length 120 | Fixed | `rustfmt` uses `max_width = 120`. The gate now refuses any `.rs`, `.ts`, `.toml` or `.yml` line over 120 characters; 58 long string literals were wrapped with `\` continuations that keep each value. |
| Function length 512 lines, 300 statements | Holds | The gate is stricter: 128 lines per function. |
| Cyclomatic complexity 15 | Fixed | The gate allowed 16; it now enforces 15, and no function needed to change. |
| Cognitive complexity 20 | Fixed | `clippy::cognitive_complexity` is denied with `cognitive-complexity-threshold = 20`. Four test functions over it were split into named helpers. |
| No shell scripts; a reviewed allowlist for bootstrap and completions | Fixed | The gate refuses `*.sh` and any file starting with a shell shebang. `crates/quarters-quality/shell-allowlist.txt` takes reviewed entries, each with a reason, and is empty (#29). |
| No subprocesses as an architecture | Departure | `quarters-quality drift` fetches upstream releases by running `curl`. Reason: the workspace carries no network dependencies, so neither the shipped binaries nor the gate's own build gain an HTTP and TLS stack for one scheduled developer check. The real fix is an HTTP client crate (`ureq` with `rustls`) scoped to `quarters-quality`, about two hours of work. The product spawning `ssh-agent` and the user's command is its purpose, not an architecture of subprocesses. |
| Native bindings over boundary chatter | Holds | The npm launcher crosses into the native binary once, by exec, and does not relay calls. |
| Python through `uv` with PEP 723 | Holds | The repository has no Python scripts; `pyproject.toml` is packaging metadata for maturin. |
| Preferred languages | Holds | Rust and TypeScript; JavaScript exists only as `tsc` output. |
| `bun` for JavaScript and TypeScript work, never `npm` | Departure | Development uses Bun (`bun.lock`, `bun run check`, `bun audit`). npm is used to publish, because `npm publish --provenance` produces the registry provenance attestation each package carries, and users install with `npm install --global` because that is the npm registry's front door. The publishing npm is a pinned, watched version (#31). |
| Threat-model first; personal data never logged | Holds | `docs/security/THREAT-MODEL.md`, read before process, environment, filesystem or platform changes (AGENTS.md); diagnostics never read state contents and redact inherited values. |
| Errors say what happened, why and what to do | Holds | Every `QuartersError` carries a kind, a message and, where an action exists, a `Try:` hint; acceptance tests assert hints on the refusal paths. |
| Every command explains itself | Holds | `clap` help on every command and flag; commands that copy, import, roll back or rename state offer `--preview`, and destructive ones require an exact-name confirmation. |
| Terminal behaviour; parseable when asked | Holds | Human output plus `--json` on every command; no colour and no interactive prompt. |
| Writing: no em dashes or the listed vocabulary | Fixed | The gate refuses em dashes in any text file (#29) and the listed words and openers in Markdown, honouring `<!-- prose-check: off -->` regions. Six occurrences in the docs were rewritten. |
| Documentation: generated reference, manpages where expected | Departure | `quarters --help` and each subcommand's help are generated from the `clap` definitions and are the reference. There is no manpage yet. The real fix is a build-time `clap_mangen` page shipped in the Homebrew bottle and the npm package, about half a day; it is tracked as the next documentation item after this release. |
| Facts in two places: make drift fail the build | Fixed | Toolchain versions in workflows and docs must equal their pins (#31); release versions across the Cargo, npm and launcher manifests already must agree. |
| Licence checked; linters fatal; `.sh` check; pins in CI; updates automated; prose checks | Fixed | `LICENSE` is a required file and `cargo deny` checks licences; `.github/dependabot.yml` now automates Cargo, GitHub Actions and Bun updates weekly, beside the Drift workflow for the pins Dependabot cannot update. |
| The gate's exit status is the truth | Holds | `make check` and `make dependencies` fail on any failing step, and CI reads the exit status. |
