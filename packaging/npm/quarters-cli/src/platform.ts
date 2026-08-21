/** Resolve host platforms to Quarters' native npm packages. */

const PACKAGES = new Map<string, string>([
  ["darwin:arm64", "quarters-cli-darwin-arm64"],
  ["darwin:x64", "quarters-cli-darwin-x64"],
  ["linux:x64", "quarters-cli-linux-x64"],
]);

/** Return the native package for a Node platform and architecture pair. */
export function packageFor(platform: string, architecture: string): string | undefined {
  return PACKAGES.get(`${platform}:${architecture}`);
}

/** Explain an unsupported platform without implying that containment exists. */
export function unsupportedPlatform(platform: string, architecture: string): string {
  return [
    `Quarters does not publish an npm binary for ${platform}/${architecture}.`,
    "Supported npm targets: macOS arm64, macOS x64 and Linux x64.",
    "Install with Homebrew or Cargo if your platform has a native build.",
  ].join(" ");
}
