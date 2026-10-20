// The checks block of a run whose input is refused as a whole (report-contract.md section 5.3,
// input_not_found to filesystem_error), as bundle-objects.md section 6 states it: no layer runs,
// every bundle check is false, the two presence flags are false, registry_signature is UNSUPPORTED
// because no signature was evaluated, and registry_link and trust_registry are false when the
// caller requested that check and null when it did not. Nothing found at the path is the host's
// (HOST_FAILURE, exit 5); a directory without manifest.json is content (OFFLINE_FAIL, exit 1).
// loquitur-verify-py holds the same rows in tests/test_refused_input_checks.py.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tempDir } from "./bundle-kit.ts";
import { verifyBundle } from "../src/verify.ts";

const vector = (name: string): unknown => JSON.parse(readFileSync(join("test-vectors", name), "utf8"));

const BUNDLE_CHECKS_FALSE = {
  manifest_sha256: false,
  manifest_files: false,
  p1_sha256: false,
  canonical_input_present: false,
  p1_input_hash: false,
  envelope_present: false,
  envelope_sha256: false,
  envelope_links: false,
  registry_signature: "UNSUPPORTED",
};

test("a refused input reports the shared checks shape whatever is requested", () => {
  const entry = vector("authorization_valid_registry_entry.json") as never;
  const trustRegistry = vector("authorization_valid_trust_registry.json") as never;
  const levels: Array<[string, Record<string, unknown>, Record<string, unknown>]> = [
    ["bundle", {}, { registry_link: null, trust_registry: null }],
    ["link", { registryEntry: entry }, { registry_link: false, trust_registry: null }],
    ["authorization", { registryEntry: entry, trustRegistry }, { registry_link: false, trust_registry: false }],
  ];
  const dir = tempDir("refused");
  try {
    const empty = join(dir, "empty");
    mkdirSync(empty);
    const inputs: Array<[string, string]> = [["input_not_found", join(dir, "absent")], ["bundle_root_invalid", empty]];
    for (const [level, options, levelChecks] of levels) {
      for (const [code, path] of inputs) {
        const report = verifyBundle(path, options);
        assert.deepEqual(report.errors.map((error) => error.code), [code], `${level} ${code}`);
        assert.deepEqual(report.checks, { ...BUNDLE_CHECKS_FALSE, ...levelChecks }, `${level} ${code}`);
        assert.deepEqual([report.status, report.exit_code], code === "input_not_found" ? ["HOST_FAILURE", 5] : ["OFFLINE_FAIL", 1], `${level} ${code}`);
        assert.deepEqual(report.checks_established, [], `${level} ${code}`);
      }
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
