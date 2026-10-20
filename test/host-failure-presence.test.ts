// A layer whose member the host fails to read is refused with its read error (report-contract.md
// section 5.3), its checks are false, and its presence flags still record what the verifier saw
// (bundle-objects.md section 6): a member the host found and could not open is present, never
// absent. Each member of link_valid_bundle is made unreadable in turn, by an open the host refuses
// while the directory listing and the entry's attributes still answer, which is what a file held
// open without sharing does on Windows. The run is HOST_FAILURE, exit 5 (report-contract.md
// section 3.1): the failure is the host's and says nothing about the evidence.
//
// The failures are injected into node:fs, which the Node reader imports, so they hold on every
// host.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { basename, dirname, join } from "node:path";
import { Bundle, linkEntryFor, tempDir } from "./bundle-kit.ts";
import { BundleReadError, verifyBundle, type VerifyReport } from "../src/verify.ts";
import { verifyBundleFiles, type BundleReader } from "../src/verify-core.ts";

/** Run `fn` while the host refuses to open the member `name` of a bundle directory named "bundle". */
function withOpenRefused<T>(name: string, fn: () => T): T {
  const module = fs as unknown as Record<"openSync", (...args: unknown[]) => unknown>;
  const original = module.openSync;
  let refused = 0;
  module.openSync = function (this: unknown, path: unknown, ...rest: unknown[]) {
    const p = String(path);
    if (basename(p) === name && basename(dirname(p)) === "bundle") {
      refused += 1;
      const err = new Error(`EBUSY: resource busy or locked, open '${p}'`) as NodeJS.ErrnoException;
      err.code = "EBUSY";
      err.syscall = "open";
      err.path = p;
      throw err;
    }
    return original.call(this, path, ...rest);
  };
  syncBuiltinESMExports();
  try {
    const out = fn();
    // A refusal that never happened would leave the test measuring nothing.
    assert.ok(refused > 0, `the host was never asked to open ${name}`);
    return out;
  } finally {
    module.openSync = original;
    syncBuiltinESMExports();
  }
}

function onDisk<T>(bundle: Bundle, fn: (root: string) => T): T {
  const dir = tempDir("host-failure-presence");
  try {
    return fn(bundle.writeTo(join(dir, "bundle")));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function surface(report: VerifyReport): Record<string, unknown> {
  return { status: report.status, reason: report.outcome.reason, errors: report.errors.map((e) => e.code), checks: report.checks };
}

const T = true;
const F = false;
/** The eleven checks, in the order the report lists them, at the integrity check. */
function integrityChecks(values: boolean[]): Record<string, unknown> {
  const [manifest_sha256, manifest_files, p1_sha256, canonical_input_present, p1_input_hash, envelope_present, envelope_sha256, envelope_links] = values;
  return {
    manifest_sha256, manifest_files, p1_sha256, canonical_input_present, p1_input_hash, envelope_present, envelope_sha256, envelope_links,
    registry_signature: "UNSUPPORTED", registry_link: null, trust_registry: null,
  };
}

// member the host fails to read -> the errors and the checks of the run at the integrity check.
// Every member exists, so both presence flags (the fourth and sixth values) are true in every row.
const ROWS: Array<[string, string[], boolean[]]> = [
  ["manifest.json", ["manifest_read_failed"], [F, F, T, T, T, T, T, F]],
  ["manifest.sha256", ["manifest_read_failed"], [F, F, T, T, T, T, T, F]],
  ["p1.json", ["manifest_read_failed", "p1_read_failed"], [F, F, F, T, F, T, T, F]],
  ["p1.sha256", ["manifest_read_failed", "p1_read_failed"], [F, F, F, T, F, T, T, F]],
  ["canonical_input.json", ["manifest_read_failed", "p1_read_failed"], [F, F, F, T, F, T, T, F]],
  ["envelope_env1.json", ["envelope_read_failed"], [T, T, T, T, T, T, F, F]],
  ["envelope.sha256", ["envelope_read_failed"], [T, T, T, T, T, T, F, F]],
  ["verification_receipt.json", ["registry_link_read_failed"], [T, T, T, T, T, T, T, T]],
];

test("the bundle every failure below is injected into verifies, with both presence flags true", () => {
  onDisk(Bundle.linkValid(), (root) => {
    assert.deepEqual(surface(verifyBundle(root)), {
      status: "OFFLINE_OK", reason: "local_integrity_checks_passed", errors: [], checks: integrityChecks([T, T, T, T, T, T, T, T]),
    });
  });
});

for (const [member, errors, values] of ROWS) {
  test(`a host failure to read ${member} refuses its layer and keeps what was seen`, () => {
    onDisk(Bundle.linkValid(), (root) => {
      assert.deepEqual(withOpenRefused(member, () => surface(verifyBundle(root))), {
        status: "HOST_FAILURE", reason: errors[0], errors, checks: integrityChecks(values),
      });
    });
  });
}

test("envelope.json is no envelope: the host is never asked to open it", () => {
  const bundle = Bundle.linkValid();
  bundle.setBytes("envelope.json", bundle.bytes("envelope_env1.json"));
  onDisk(bundle, (root) => {
    // An undeclared ordinary member: REVIEW for completeness, and no layer reads it, so a host that
    // would refuse to open it is never asked to.
    const report = verifyBundle(root);
    assert.deepEqual([report.status, report.review_reasons, report.errors], ["OFFLINE_REVIEW", ["bundle_extra_files"], []]);
    assert.throws(() => withOpenRefused("envelope.json", () => verifyBundle(root)), /the host was never asked to open envelope\.json/);
  });
});

test("an absent member stays absent beside a member the host fails to read", () => {
  // Non-vacuity of the rows above: the flag follows the member, not the failure.
  const bundle = Bundle.linkValid().delete("canonical_input.json");
  bundle.edit("manifest.json", (m) => { delete m.files["canonical_input.json"]; });
  bundle.seal();
  onDisk(bundle, (root) => {
    const report = withOpenRefused("p1.json", () => verifyBundle(root));
    assert.deepEqual(report.errors.map((e) => e.code), ["manifest_read_failed", "p1_read_failed"]);
    assert.equal(report.checks.canonical_input_present, false);
    assert.equal(report.checks.envelope_present, true);
  });
  const noEnvelope = Bundle.linkValid().delete("envelope_env1.json").delete("envelope.sha256");
  onDisk(noEnvelope, (root) => {
    const report = withOpenRefused("p1.json", () => verifyBundle(root));
    assert.equal(report.checks.canonical_input_present, true);
    assert.equal(report.checks.envelope_present, false);
  });
});

test("a canonical input the host fails to read does not unmake the P1 an envelope and a receipt name", () => {
  // The manifest does not declare canonical_input.json, so only the P1 layer reads it: P1 itself
  // verified, and the envelope's and the receipt's links to it hold, as in the Python verifier.
  const bundle = Bundle.linkValid();
  bundle.edit("manifest.json", (m) => { delete m.files["canonical_input.json"]; });
  bundle.seal();
  const entry = linkEntryFor(bundle);
  onDisk(bundle, (root) => {
    assert.deepEqual(withOpenRefused("canonical_input.json", () => surface(verifyBundle(root))), {
      status: "HOST_FAILURE", reason: "p1_read_failed", errors: ["p1_read_failed"], checks: integrityChecks([T, T, F, T, F, T, T, T]),
    });
    const linkRun = withOpenRefused("canonical_input.json", () => verifyBundle(root, { registryEntry: entry }));
    assert.deepEqual(linkRun.errors.map((e) => e.code), ["p1_read_failed"]);
    assert.equal(linkRun.checks.envelope_links, true);
    assert.equal(linkRun.checks.registry_link, true);
    // The P1 the links name is the one that verified: with its sidecar altered, they do not hold.
    const altered = Bundle.linkValid();
    altered.edit("manifest.json", (m) => { delete m.files["canonical_input.json"]; });
    altered.seal();
    altered.setBytes("p1.sha256", "0".repeat(64));
    onDisk(altered, (other) => {
      const report = withOpenRefused("canonical_input.json", () => verifyBundle(other));
      assert.equal(report.checks.envelope_links, false);
    });
  });
});

/** A reader with no listing over `bundle`, which fails to read `failing` with a BundleReadError. */
function unlistedReader(bundle: Bundle, failing: string): BundleReader {
  const read = (name: string): Uint8Array | null => {
    if (name === failing) throw new BundleReadError(`the host cannot read ${name}`);
    return bundle.has(name) ? bundle.bytes(name) : null;
  };
  return { readBytes: read, readText: (name) => { const b = read(name); return b === null ? null : new TextDecoder().decode(b); } };
}

test("a reader without a listing reports a member it failed to read as present, as the Node reader does", () => {
  // BundleReadError is a failure to read a member that exists; without a listing it is what the
  // verifier saw of the member.
  for (const [member, errors, values] of ROWS) {
    const report = verifyBundleFiles(unlistedReader(Bundle.linkValid(), member));
    assert.deepEqual(report.errors.map((e) => e.code), errors, member);
    assert.equal(report.checks.canonical_input_present, values[3], member);
    assert.equal(report.checks.envelope_present, values[5], member);
  }
});
