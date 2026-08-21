# Registry publishing

Quarters uses registry-native trusted publishing wherever it is available. The
release workflows receive short-lived OpenID Connect credentials only in their
final publish jobs; build jobs cannot publish, and no registry token is stored
in GitHub.

## Bootstrap

PyPI supports a pending trusted publisher for a new project. Configure project
`quarters` for repository `Agenxy/quarters`, workflow `publish-pypi.yml` and
environment `pypi`, then dispatch the workflow with `publish` enabled.

npm requires a package to exist before its trusted publisher can be configured.
The first versions of `quarters-cli` and its three architecture packages must
therefore be published with npm's interactive web login and hardware-backed
two-factor check. Publish the tested native packages first and the launcher
last, always with the `alpha` distribution tag. Then configure each package to
trust repository `Agenxy/quarters`, workflow `publish-npm.yml`, environment
`npm`, and the `npm publish` action. Revoke the bootstrap CLI session when the
configuration is complete.

There is intentionally no long-lived-token fallback.

crates.io releases use a newly created, short-lived token restricted to
publishing updates of `quarters-core` and `quarters`. Dry-run both crates,
publish the library before the CLI, install the exact version in a clean Cargo
root, and revoke the token immediately. The token is passed only through the
publishing process environment and is never saved in the repository or Cargo
credentials file.

Homebrew is maintained in the separate public
[`Agenxy/homebrew-tap`](https://github.com/Agenxy/homebrew-tap) repository.
After the GitHub tag exists, update the formula URL and digest, run Homebrew's
strict online audit, install from the tap and exercise the installed binary.

GitHub prereleases contain the tagged source. This alpha does not advertise
standalone GitHub binary downloads. The macOS executables inside the npm
architecture packages are unsigned and unnotarized; this limitation must remain
visible in the project and package READMEs until a complete signing and
notarization path exists.

## Release gate

Before publishing a version:

1. Keep the Cargo workspace and all four npm manifests on the same SemVer.
2. Run `make check`, `make dependencies` and both distribution workflows in
   build-only mode.
3. Install and exercise the wheel and the npm launcher with a matching native
   package in clean temporary environments.
4. Publish prereleases under registry prerelease semantics: PEP 440 handles the
   PyPI alpha and npm uses the explicit `alpha` tag.
5. Verify the public registry metadata and install the exact published version.
6. Create the GitHub prerelease only after registry verification. Publishing a
   GitHub release does not write to any package registry; each registry publish
   is a separate, explicit workflow dispatch with `publish` enabled.
7. Update and verify the separate Homebrew tap from the immutable GitHub tag.

The npm registry has no transaction spanning four packages. The workflow
dry-runs every tarball before its first write, publishes native packages before
the launcher that depends on them, and stops on the first failure. A partial
publication requires a version increment; published versions are never reused.
