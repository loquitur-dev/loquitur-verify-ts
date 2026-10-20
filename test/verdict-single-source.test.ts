// The verdict of a trust-registry evaluation is the verdict the bundle run reports.
//
// TrustRegistryReport, what evaluateTrustRegistry returns, carries the three statuses of
// report-contract.md section 5.4 and no verdict. The verdict of an evaluation is trustRegistryVerdict
// (src/verify-core.ts), and the bundle run's headline reads it: a FAIL after an authorization that
// holds is the root failure, a FAIL before it the authorization failure, and the authorization check
// is established exactly for a PASS. The cryptographic review found loquitur-verify-py's result
// saying PASS beside a FAIL headline because the two were computed apart; this holds the
// TypeScript side on behaviour, over the trust-registry cases of the reviews: for the same entry,
// trust registry, roots and evaluation time beside an intact bundle, the evaluation's statuses are
// the run's, and its verdict is the run's verdict.
//
// Keys are made for the run (bundle-kit) and never written anywhere.
import { test } from "node:test";
import assert from "node:assert/strict";
import { evaluateTrustRegistry, trustRegistryVerdict } from "../src/verify-core.ts";
import { Bundle, ephemeralAuthorization, ephemeralRoot, rootDocument, verifyInMemory } from "./bundle-kit.ts";

const EVALUATION_TIME = "2026-05-10T00:00:00Z";
const bundle = Bundle.linkValid();
const { root, sign } = ephemeralRoot("root-a");
const { sign: signByStranger } = ephemeralRoot("root-a");
const { registryEntry: entry, trustRegistry } = ephemeralAuthorization(bundle);
const clone = <T>(value: T): T => structuredClone(value);
const signed = sign(clone(trustRegistry));
const altered = clone(signed) as any;
altered.entries[0].allowed_asset_types.push("equity");
const relabeled = clone(signed) as any;
relabeled.signature.key_id = "root-b";
const wide = (() => {
  const registry = clone(trustRegistry) as any;
  Object.assign(registry, { issued_at: "2025-01-01T00:00:00Z", effective_at: "2025-01-01T00:00:00Z", expires_at: "2028-01-01T00:00:00Z" });
  Object.assign(registry.entries[0], { effective_from: "2025-01-01T00:00:00Z", expires_at: "2028-01-01T00:00:00Z" });
  return sign(registry);
})();
const revokedIssuer = (() => {
  const registry = clone(trustRegistry) as any;
  Object.assign(registry.entries[0], { status: "revoked", revoked_at: "2026-05-01T00:00:00Z", revocation_reason: "key compromised" });
  return sign(registry);
})();
const pinned = rootDocument([root]);
const revokedRoot = rootDocument([{ ...root, status: "revoked" }]);

type Case = { entry: unknown; registry: unknown; roots?: unknown; time?: string };
const CASES: Record<string, Case> = {
  "root-authenticated": { entry, registry: signed, roots: pinned, time: EVALUATION_TIME },
  "root-authenticated-no-evaluation-time": { entry, registry: signed, roots: pinned },
  "no-root": { entry, registry: signed, time: EVALUATION_TIME },
  "no-root-no-evaluation-time": { entry, registry: signed },
  "no-root-altered": { entry, registry: altered, time: EVALUATION_TIME },
  "unknown-root-key-id": { entry, registry: relabeled, roots: pinned, time: EVALUATION_TIME },
  "signed-by-a-key-not-pinned": { entry, registry: signByStranger(clone(trustRegistry)), roots: pinned, time: EVALUATION_TIME },
  "pinned-root-revoked": { entry, registry: signed, roots: revokedRoot, time: EVALUATION_TIME },
  "pinned-root-revoked-no-evaluation-time": { entry, registry: signed, roots: revokedRoot },
  "altered-after-root-signed": { entry, registry: altered, roots: pinned, time: EVALUATION_TIME },
  "altered-after-root-signed-no-evaluation-time": { entry, registry: altered, roots: pinned },
  "root-window-not-yet-valid": { entry, registry: wide, roots: pinned, time: "2025-12-31T23:59:59Z" },
  "root-window-expired": { entry, registry: wide, roots: pinned, time: "2027-01-01T00:00:01Z" },
  "registry-window-expired": { entry, registry: signed, roots: pinned, time: "2026-06-01T00:00:00Z" },
  "issuer-key-revoked": { entry, registry: revokedIssuer, roots: pinned, time: EVALUATION_TIME },
  "entry-altered-after-signing": { entry: { ...(entry as object), policy_version: "1.0.1" }, registry: signed, roots: pinned, time: EVALUATION_TIME },
};
const STATUS: Record<string, string> = { PASS: "OFFLINE_OK", REVIEW: "OFFLINE_REVIEW", FAIL: "OFFLINE_FAIL" };

function options(c: Case): Record<string, unknown> {
  const opts: Record<string, unknown> = {};
  if (c.roots !== undefined) opts.trustRoots = c.roots;
  if (c.time !== undefined) opts.evaluationTime = c.time;
  return opts;
}

for (const [name, c] of Object.entries(CASES)) {
  test(`the evaluation's verdict is the run's verdict: ${name}`, () => {
    const evaluation = evaluateTrustRegistry(c.entry, c.registry, options(c));
    const verdict = trustRegistryVerdict(evaluation, c.time !== undefined);
    const report = verifyInMemory(bundle, { registryEntry: c.entry, trustRegistry: c.registry, ...options(c) });
    // The bundle and the link hold in every case, so the trust registry alone decides the run.
    assert.equal(report.checks.registry_link, true);
    assert.deepEqual(report.trust_registry, evaluation);
    assert.deepEqual([report.verdict, report.status], [verdict, STATUS[verdict]]);
    assert.equal(report.checks_established.includes("authorization"), verdict === "PASS");
  });
}

test("the cases reach every verdict", () => {
  const verdicts = new Set(
    Object.values(CASES).map((c) => trustRegistryVerdict(evaluateTrustRegistry(c.entry, c.registry, options(c)), c.time !== undefined)),
  );
  assert.deepEqual([...verdicts].sort(), ["FAIL", "PASS", "REVIEW"]);
});
