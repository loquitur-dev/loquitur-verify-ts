// Nothing found at the path of a supplied registry entry or trust registry refuses the run as a
// whole (report-contract.md sections 4 and 5.3): HOST_FAILURE, input_not_found, exit 5, the only
// error, nothing established, trust_registry null, whatever else is supplied, and before any
// refusal of the bundle, since input_not_found is the first row of the table. Something found that
// is not a regular file keeps its own outcome, and a trust-root document at a path that names
// nothing is refused with a TrustRootError, as one that names no regular file is.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { Bundle, ephemeralAuthorizationWith, tempDir } from "./bundle-kit.ts";
import {
  DOCUMENT_PATH_NAMES_NOTHING,
  DOCUMENT_PATH_NAMES_NO_REGULAR_FILE,
  readDocumentPath,
  verifyBundle,
  type VerifyReport,
} from "../src/verify.ts";

function surface(report: VerifyReport): Record<string, unknown> {
  return {
    status: report.status, verdict: report.verdict, exit_code: report.exit_code, reason: report.outcome.reason,
    errors: report.errors.map((e) => e.code), requested: report.checks_requested, established: report.checks_established,
    review_reasons: report.review_reasons, trust_registry: report.trust_registry,
  };
}

const NOTHING_FOUND = (requested: string[]) => ({
  status: "HOST_FAILURE", verdict: null, exit_code: 5, reason: "input_not_found", errors: ["input_not_found"],
  requested, established: [], review_reasons: [], trust_registry: null,
});

test("readDocumentPath tells nothing found from something that is not a regular file", (t) => {
  const dir = tempDir("nothing");
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  assert.equal(readDocumentPath(join(dir, "absent.json")), DOCUMENT_PATH_NAMES_NOTHING);
  assert.equal(readDocumentPath(join(dir, "absent", "entry.json")), DOCUMENT_PATH_NAMES_NOTHING);
  assert.equal(readDocumentPath(""), DOCUMENT_PATH_NAMES_NOTHING);
  mkdirSync(join(dir, "a-directory"));
  assert.equal(readDocumentPath(join(dir, "a-directory")), DOCUMENT_PATH_NAMES_NO_REGULAR_FILE);
});

test("a registry entry or trust registry at a path that names nothing refuses the run as a whole", (t) => {
  const dir = tempDir("nothing-run");
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const bundle = Bundle.linkValid().seal();
  const root = bundle.writeTo(join(dir, "bundle"));
  const { registryEntry, trustRegistry } = ephemeralAuthorizationWith(bundle);
  const nothing = readDocumentPath(join(dir, "absent.json"));
  const at = "2026-05-20T00:00:00Z";
  assert.deepEqual(surface(verifyBundle(root, { registryEntry: nothing })), NOTHING_FOUND(["structure", "integrity", "link"]));
  assert.deepEqual(surface(verifyBundle(root, { registryEntry: nothing, trustRegistry, evaluationTime: at })),
    { ...NOTHING_FOUND(["structure", "integrity", "link", "authorization"]) });
  assert.deepEqual(surface(verifyBundle(root, { registryEntry, trustRegistry: nothing, evaluationTime: at })),
    NOTHING_FOUND(["structure", "integrity", "link", "authorization"]));
  // Without a registry entry: the trust registry's path is inspected, and nothing there is
  // input_not_found, not trust_registry_requires_registry_entry.
  assert.deepEqual(surface(verifyBundle(root, { trustRegistry: nothing })), NOTHING_FOUND(["structure", "integrity", "authorization"]));
  // input_not_found is the first row: it is reported before a bundle path that is not a directory.
  assert.deepEqual(surface(verifyBundle(join(root, "manifest.json"), { registryEntry: nothing })), NOTHING_FOUND(["structure", "integrity", "link"]));
  assert.equal(verifyBundle(root, { registryEntry: nothing, evaluationTime: at }).evaluation_time, at);
});

test("something found that is not a regular file keeps its outcome", (t) => {
  const dir = tempDir("not-a-file");
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const bundle = Bundle.linkValid().seal();
  const root = bundle.writeTo(join(dir, "bundle"));
  mkdirSync(join(dir, "a-directory"));
  const directory = readDocumentPath(join(dir, "a-directory"));
  const entryRun = verifyBundle(root, { registryEntry: directory });
  assert.deepEqual([entryRun.status, entryRun.errors.map((e) => e.code)], ["OFFLINE_FAIL", ["registry_link_verification_failed"]]);
  const { registryEntry } = ephemeralAuthorizationWith(bundle);
  const trustRun = verifyBundle(root, { registryEntry, trustRegistry: directory, evaluationTime: "2026-05-20T00:00:00Z" });
  assert.equal(trustRun.status, "OFFLINE_FAIL");
  assert.equal(trustRun.trust_registry?.authorization_status, "INVALID_TRUST_REGISTRY");
});

test("a trust-root document at a path that names nothing is refused before any evidence is read", (t) => {
  const dir = tempDir("nothing-roots");
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const root = Bundle.linkValid().seal().writeTo(join(dir, "bundle"));
  assert.throws(() => verifyBundle(root, { trustRoots: DOCUMENT_PATH_NAMES_NOTHING }),
    (err: Error) => err.name === "TrustRootError" && err.message === "trust-root document unreadable: nothing is found at the path");
});
