// Trust authorization enforces both the asset_type and the workflow scope, fail-closed, as
// the Python verifier (verify_registry_entry_trust) does (trust-registry-authorization.md
// section 5). An entry with an authorized asset_type but an unauthorized workflow fails in
// both; checking the asset type alone would give the same evidence opposite verdicts across
// implementations. These tests pin the two implementations to identical semantics.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { verifyBundleFiles, bundleReaderFromMap } from "../src/verify.ts";
import { sibling } from "./siblings.ts";

const here = dirname(fileURLToPath(import.meta.url));
// verify-package fixtures live as a sibling repo checkout during CI, but may be
// nested (public/loquitur-verify-py) in a combined workspace. Try both.
const FIXTURES = sibling(
  "loquitur-verify-py",
  [join(here, "../../loquitur-verify-py/tests/fixtures"), join(here, "../../public/loquitur-verify-py/tests/fixtures")],
  "authorization_valid_registry_entry.json",
  "sibling loquitur-verify-py fixtures absent",
);

function bundleFiles() {
  const dir = FIXTURES.path("link_valid_bundle");
  const files: Record<string, string> = {};
  for (const f of readdirSync(dir)) files[f] = readFileSync(join(dir, f), "utf8");
  return files;
}
function trustAuthorized(registryEntry: unknown, trustRegistry: unknown): boolean {
  // The operator's evaluation time, inside the fixture windows (trust-registry-authorization.md
  // section 2).
  const report = verifyBundleFiles(bundleReaderFromMap(bundleFiles()), { registryEntry, trustRegistry, evaluationTime: "2026-05-01T00:00:00Z" } as any);
  return (report.checks as any).trust_registry === true;
}

// These vectors live in loquitur-verify-py, so that the two implementations are compared
// against one corpus rather than each keeping its own copy, which is how a consensus split
// starts. A single-repository clone does not have the sibling, so the suite skips instead of
// failing on an absence that is not a defect. A skip alone would report a check that never runs
// as one that passed, so the cross-implementation property is enforced wherever the
// repositories are assembled side by side (the `siblings` CI job once every sibling is
// published, the cross-repository gate): there LOQUITUR_REQUIRE_SIBLINGS is set, and an absent
// sibling fails every test below by name instead of skipping it (see siblings.ts).
const readFx = (name: string) => JSON.parse(readFileSync(FIXTURES.path(name), "utf8"));
const entry = () => readFx("authorization_valid_registry_entry.json");
const baseTrust = () => readFx("authorization_valid_trust_registry.json");
const clone = (o: unknown) => JSON.parse(JSON.stringify(o));

test("authorized asset_type AND workflow => authorized", FIXTURES.options, () => {
  assert.equal(trustAuthorized(entry(), baseTrust()), true);
});

test("authorized asset_type but UNAUTHORIZED workflow => rejected", FIXTURES.options, () => {
  const t = clone(baseTrust());
  t.entries[0].allowed_workflows = ["fund_nav_initial", "fund_nav_update"]; // not property_review
  assert.equal(trustAuthorized(entry(), t), false);
});

test("allowed_workflows absent => rejected, fail-closed (matches Python)", FIXTURES.options, () => {
  const t = clone(baseTrust());
  delete t.entries[0].allowed_workflows;
  assert.equal(trustAuthorized(entry(), t), false);
});

test("allowed_asset_types absent => rejected, fail-closed (matches Python)", FIXTURES.options, () => {
  const t = clone(baseTrust());
  delete t.entries[0].allowed_asset_types;
  assert.equal(trustAuthorized(entry(), t), false);
});
