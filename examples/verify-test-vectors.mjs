// Verify the bundles in test-vectors/ through the package's public entry point, as a project
// that installed @loquitur/verify would, and compare each report with the outcome
// test-vectors/verify.json records for it.
//
// From a clone, after `npm ci` and `npm run build`:
//
//   node examples/verify-test-vectors.mjs
//
// The import below resolves to this package's own build (dist/src), through the "exports" map
// of package.json. The script prints one line per case and exits 1 if any report differs from
// the recorded outcome. An optional argument names another directory laid out as test-vectors/.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { readDocumentPath, verifyBundle } from "@loquitur/verify";

const vectors = process.argv[2] ?? fileURLToPath(new URL("../test-vectors/", import.meta.url));
const recorded = JSON.parse(readFileSync(join(vectors, "verify.json"), "utf8"));

// One case per outcome a first reader meets: integrity only, a tampered bundle, the link check,
// and authorization with and without a revoked key.
const CASES = ["valid", "tampered", "link", "authorization_valid", "authorization_revoked"];

let differing = 0;
for (const name of CASES) {
  const vector = recorded[name];
  // The documents are values: the host reads each path and passes what it found.
  const options = {};
  if (vector.registry_entry !== undefined) {
    options.registryEntry = readDocumentPath(join(vectors, vector.registry_entry));
  }
  if (vector.trust_registry !== undefined) {
    options.trustRegistry = readDocumentPath(join(vectors, vector.trust_registry));
  }
  // The operator's evaluation time the record names for an authorization case: without one,
  // authorization is not established and the run is REVIEW for that reason first.
  if (vector.evaluation_time !== undefined) options.evaluationTime = vector.evaluation_time;
  const report = verifyBundle(join(vectors, "bundles", vector.bundle), options);

  const expected = vector.expected;
  const differences = [];
  for (const key of ["status", "verdict", "exit_code"]) {
    if (report[key] !== expected[key]) differences.push(`${key} ${report[key]}, recorded ${expected[key]}`);
  }
  for (const [check, value] of Object.entries(expected.checks)) {
    if (report.checks[check] !== value) differences.push(`checks.${check} ${report.checks[check]}, recorded ${value}`);
  }

  const trust = report.trust_registry === null
    ? ""
    : ` ${report.trust_registry.authorization_status} ${report.trust_registry.signature_status}` +
      ` ${report.trust_registry.trust_registry_root_signature_status}`;
  console.log(`${name.padEnd(21)} ${report.verdict.padEnd(6)} exit ${report.exit_code}  ${report.outcome.reason}${trust}`);
  for (const difference of differences) console.log(`  differs: ${difference}`);
  if (differences.length > 0) differing += 1;
}

if (differing > 0) {
  console.log(`${differing} of ${CASES.length} reports differ from test-vectors/verify.json`);
  process.exit(1);
}
console.log(`all ${CASES.length} reports match test-vectors/verify.json`);
