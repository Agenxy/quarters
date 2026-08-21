import assert from "node:assert/strict";
import test from "node:test";

import { packageFor, unsupportedPlatform } from "../src/platform.js";

test("selects every published native package", () => {
  assert.equal(packageFor("darwin", "arm64"), "quarters-cli-darwin-arm64");
  assert.equal(packageFor("darwin", "x64"), "quarters-cli-darwin-x64");
  assert.equal(packageFor("linux", "x64"), "quarters-cli-linux-x64");
});

test("rejects targets that have no published native package", () => {
  assert.equal(packageFor("linux", "arm64"), undefined);
  assert.match(unsupportedPlatform("linux", "arm64"), /does not publish/);
});
