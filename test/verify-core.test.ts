// The I/O-free path (verifyBundleFiles over an in-memory map) must produce the
// exact same report as the fs-backed verifyBundle, so the browser and Node verifiers are one
// implementation, not two.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { verifyBundle } from "../src/verify.ts";
import { verifyBundleFiles, bundleReaderFromMap } from "../src/verify-core.ts";
import { parseJsonStrict } from "../src/canonical.ts";

const here = dirname(fileURLToPath(import.meta.url));
const tv = join(here, "../test-vectors");
const scenarios = JSON.parse(readFileSync(join(tv, "verify.json"), "utf-8"));
const load = (n: string) => parseJsonStrict(readFileSync(join(tv, n), "utf-8"));

// Read every file in a bundle directory into a { name: text } map, the browser's form of input.
function bundleToMap(dir: string): Record<string, string> {
  const files: Record<string, string> = {};
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isFile()) files[name] = readFileSync(p, "utf-8");
  }
  return files;
}

for (const [name, cfg] of Object.entries<any>(scenarios)) {
  test(`I/O-free == fs-backed == golden: ${name}`, () => {
    const dir = join(tv, "bundles", cfg.bundle);
    const opts = {
      registryEntry: cfg.registry_entry ? load(cfg.registry_entry) : undefined,
      trustRegistry: cfg.trust_registry ? load(cfg.trust_registry) : undefined,
    };
    const fromDisk = verifyBundle(dir, opts);
    const fromMemory = verifyBundleFiles(bundleReaderFromMap(bundleToMap(dir)), opts);
    // The two code paths agree with each other,
    assert.deepEqual(fromMemory, fromDisk, `mem vs disk ${name}`);
    // and both agree with the Python golden report.
    assert.deepEqual(fromMemory.checks, cfg.expected.checks, `checks ${name}`);
    assert.equal(fromMemory.status, cfg.expected.status);
    assert.equal(fromMemory.exit_code, cfg.expected.exit_code);
  });
}
