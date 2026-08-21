import assert from "node:assert/strict";
import { chmod, copyFile, mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import process from "node:process";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { packageFor } from "../src/platform.js";

const compiledSource = join(dirname(fileURLToPath(import.meta.url)), "../src");

test("launcher resolves the native package and preserves arguments and status", async (context) => {
  const nativePackage = packageFor(process.platform, process.arch);
  if (nativePackage === undefined) {
    context.skip("the test host is not an npm distribution target");
    return;
  }
  const launcher = await stageLauncher(nativePackage);
  const result = spawnSync(process.execPath, [launcher, "first", "second"], { encoding: "utf8" });

  assert.equal(result.status, 42);
  assert.equal(result.stdout, '["first","second"]');
  assert.equal(result.stderr, "");
});

test("launcher explains a missing optional native package", async (context) => {
  if (packageFor(process.platform, process.arch) === undefined) {
    context.skip("the test host is not an npm distribution target");
    return;
  }
  const launcher = await stageLauncher();
  const result = spawnSync(process.execPath, [launcher], { encoding: "utf8" });

  assert.equal(result.status, 1);
  assert.match(result.stderr, /did not install the optional package/);
});

async function stageLauncher(nativePackage?: string): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "quarters-npm-launcher-"));
  const source = join(root, "dist/src");
  await mkdir(source, { recursive: true });
  await copyFile(join(compiledSource, "platform.js"), join(source, "platform.js"));
  await copyFile(join(compiledSource, "quarters.js"), join(source, "quarters.js"));
  if (nativePackage !== undefined) {
    await stageNativePackage(root, nativePackage);
  }
  return join(source, "quarters.js");
}

async function stageNativePackage(root: string, nativePackage: string): Promise<void> {
  const packageRoot = join(root, "node_modules", nativePackage);
  const binary = join(packageRoot, "bin/quarters");
  await mkdir(dirname(binary), { recursive: true });
  await writeFile(
    join(packageRoot, "package.json"),
    JSON.stringify({ name: nativePackage, exports: { "./binary": "./bin/quarters" } }),
  );
  await writeFile(binary, '#!/usr/bin/env node\nprocess.stdout.write(JSON.stringify(process.argv.slice(2))); process.exitCode = 42;\n');
  await chmod(binary, 0o755);
}
