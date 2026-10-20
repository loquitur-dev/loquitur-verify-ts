// A trust registry says which issuers may sign registry entries. When the entry given beside it
// fails, or its link to the bundle does not hold, there is nothing for the registry to authorize:
// the Python verifier skips it (trust_registry_skipped_registry_link_failed) and reports
// trust_registry null, whatever the registry holds (registry-link.md section 7). So does this
// verifier, for a malformed registry as for a well-formed one: it does not parse the registry
// first, which would report trust_registry false where the Python verifier reports null.
import { test } from "node:test";
import assert from "node:assert/strict";
import { Bundle, ENTRIES, FAIL, ephemeralAuthorization, outcome } from "./bundle-kit.ts";

const CHECKS = ["registry_link", "trust_registry", "registry_signature"];

function malformed(trust: Record<string, unknown>): Record<string, unknown> {
  return { ...trust, object_type: "not_a_trust_registry" };
}

for (const [entryName, verify] of ENTRIES) {
  test(`${entryName}: a trust registry beside a failed entry or link reaches no trust conclusion, malformed or not`, () => {
    const b = Bundle.linkValid().seal();
    const good = ephemeralAuthorization(b);
    const unlinked = ephemeralAuthorization(b, { manifest_hash: `sha256:${"0".repeat(64)}` });
    const got = {
      unlinkedMalformedTrust: outcome(verify(b, { registryEntry: unlinked.registryEntry, trustRegistry: malformed(unlinked.trustRegistry) }), CHECKS),
      nullEntryMalformedTrust: outcome(verify(b, { registryEntry: null, trustRegistry: malformed(good.trustRegistry) }), CHECKS),
      unlinkedWellFormedTrust: outcome(verify(b, unlinked), CHECKS),
      linkedMalformedTrust: outcome(verify(b, { registryEntry: good.registryEntry, trustRegistry: malformed(good.trustRegistry) }), CHECKS),
    };
    assert.deepEqual(got, {
      unlinkedMalformedTrust: { ...FAIL, registry_link: false, trust_registry: null, registry_signature: "UNSUPPORTED" },
      nullEntryMalformedTrust: { ...FAIL, registry_link: false, trust_registry: null, registry_signature: "UNSUPPORTED" },
      // Controls: a well-formed registry over a failed link, and a malformed one over a link that
      // holds.
      unlinkedWellFormedTrust: { ...FAIL, registry_link: false, trust_registry: null, registry_signature: "UNSUPPORTED" },
      linkedMalformedTrust: { ...FAIL, registry_link: true, trust_registry: false, registry_signature: "UNSUPPORTED" },
    });
  });
}
