// VerifyOptions: a trust registry without a registry entry is a request that cannot be honored,
// and fails without the trust registry being read (registry-link.md section 7). `registryEntry:
// null` is a supplied document that fails to parse: registry_link false, and no trust conclusion
// (registry-link.md section 5).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { Bundle, ENTRIES, FAIL, VECTORS_DIR, linkEntryFor, outcome } from "./bundle-kit.ts";
import { bundleReaderFromMap, verifyBundleFiles } from "../src/verify-core.ts";

const trust = () => JSON.parse(readFileSync(join(VECTORS_DIR, "authorization_valid_trust_registry.json"), "utf8"));
const CHECKS = ["registry_link", "trust_registry"];

for (const [entryName, verify] of ENTRIES) {
  test(`${entryName}: a trust registry without a registry entry fails; a null entry fails the link`, () => {
    const b = Bundle.linkValid().seal();
    assert.deepEqual({
      valid: outcome(verify(b, { trustRegistry: trust() }), CHECKS),
      malformed: outcome(verify(b, { trustRegistry: { object_type: "trust_registry" } }), CHECKS),
      nullWithTrust: outcome(verify(b, { registryEntry: null, trustRegistry: trust() }), CHECKS),
      nullAlone: outcome(verify(b, { registryEntry: null }), CHECKS),
    }, {
      valid: { ...FAIL, registry_link: null, trust_registry: null },
      malformed: { ...FAIL, registry_link: null, trust_registry: null },
      nullWithTrust: { ...FAIL, registry_link: false, trust_registry: null },
      nullAlone: { ...FAIL, registry_link: false, trust_registry: null },
    });
    // The control: with its entry, the same bundle links.
    assert.equal(verify(b, { registryEntry: linkEntryFor(b) }).checks.registry_link, true);
  });
}

test("a trust registry without a registry entry is never read", () => {
  const b = Bundle.linkValid().seal();
  const map: Record<string, string> = {};
  for (const [name, data] of b.files) map[name] = new TextDecoder().decode(data);
  let touched = 0;
  const spy = new Proxy({}, {
    get() { touched++; throw new Error("the trust registry was read"); },
    ownKeys() { touched++; throw new Error("the trust registry was enumerated"); },
    getOwnPropertyDescriptor() { touched++; throw new Error("the trust registry was inspected"); },
    has() { touched++; throw new Error("the trust registry was probed"); },
    getPrototypeOf() { touched++; throw new Error("the trust registry was probed"); },
  });
  const report = verifyBundleFiles(bundleReaderFromMap(map), { trustRegistry: spy as never });
  assert.equal(touched, 0);
  assert.equal(report.status, "OFFLINE_FAIL");
  assert.equal(report.checks.trust_registry, null);
});
