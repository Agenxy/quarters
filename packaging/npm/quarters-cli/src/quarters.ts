#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import process from "node:process";

import { packageFor, unsupportedPlatform } from "./platform.js";

const packageName = packageFor(process.platform, process.arch);

if (packageName === undefined) {
  process.stderr.write(`${unsupportedPlatform(process.platform, process.arch)}\n`);
  process.exitCode = 1;
} else {
  launch(packageName);
}

function launch(nativePackage: string): void {
  const binary = resolveBinary(nativePackage);
  if (binary === undefined) {
    process.exitCode = 1;
    return;
  }

  const result = spawnSync(binary, process.argv.slice(2), { stdio: "inherit" });
  if (result.error !== undefined) {
    process.stderr.write(`Could not start the Quarters binary: ${result.error.message}\n`);
    process.exitCode = 1;
    return;
  }
  if (result.signal !== null) {
    process.kill(process.pid, result.signal);
    return;
  }
  process.exitCode = result.status ?? 1;
}

function resolveBinary(nativePackage: string): string | undefined {
  try {
    return createRequire(import.meta.url).resolve(`${nativePackage}/binary`);
  } catch {
    process.stderr.write(
      [
        `npm did not install the optional package ${nativePackage}.`,
        "Reinstall quarters-cli with optional dependencies enabled,",
        "or install Quarters with Homebrew or Cargo.\n",
      ].join(" "),
    );
    return undefined;
  }
}
