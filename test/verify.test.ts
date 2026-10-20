import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { verifyBundle } from "../src/verify.ts";
import { parseJsonStrict } from "../src/canonical.ts";

const here = dirname(fileURLToPath(import.meta.url));
const tv = join(here, "../test-vectors");
const scenarios = JSON.parse(readFileSync(join(tv, "verify.json"), "utf-8"));
const load = (n: string) => parseJsonStrict(readFileSync(join(tv, n), "utf-8"));

for (const [name, cfg] of Object.entries<any>(scenarios)) {
  test(`verify == Python golden: ${name}`, () => {
    const bundleRoot = join(tv, "bundles", cfg.bundle);
    const report = verifyBundle(bundleRoot, {
      registryEntry: cfg.registry_entry ? load(cfg.registry_entry) : undefined,
      trustRegistry: cfg.trust_registry ? load(cfg.trust_registry) : undefined,
    });
    const e = cfg.expected;
    assert.equal(report.status, e.status, `status ${name}`);
    assert.equal(report.verdict, e.verdict, `verdict ${name}`);
    assert.equal(report.exit_code, e.exit_code, `exit_code ${name}`);
    assert.deepEqual(report.checks, e.checks, `checks ${name}: ${JSON.stringify(report.checks)}`);
  });
}
