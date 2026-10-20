// A trust registry or trust-root document the host fails to read is a host failure
// (report-contract.md sections 4 and 5.3): never a finding about bytes nobody read. The host reads
// each document with readDocumentPath and passes DOCUMENT_READ_FAILED in its place; the run reports
// trust_registry_read_failed or trust_root_read_failed, HOST_FAILURE, exit 5, as it reports
// registry_link_read_failed for the registry entry. The trust-root marker never reaches the parser,
// which would throw "trust-root document malformed: the document is not a JSON object".
//
// The conformance corpus cannot stage a host state (conformance-testing.md section 6), so the read
// is made to fail here: node:fs refuses, with EACCES, to read the one file, as a host refuses a
// file another process holds open with no sharing.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs, { rmSync, writeFileSync } from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { join, resolve } from "node:path";
import { Bundle, ephemeralAuthorizationWith, ephemeralRoot, rootDocument, tempDir } from "./bundle-kit.ts";
import { DOCUMENT_READ_FAILED, readDocumentPath, verifyBundle, type VerifyReport } from "../src/verify.ts";

const EVALUATION_TIME = "2026-05-10T00:00:00Z";

/** Run `fn` while node:fs refuses, with EACCES, to read the file at `target`. */
function hostRefusingToRead<T>(target: string, fn: () => T): T {
  const module = fs as unknown as { readFileSync: (...args: unknown[]) => unknown };
  const original = module.readFileSync;
  const held = resolve(target).toLowerCase();
  let refused = 0;
  module.readFileSync = function (this: unknown, path: unknown, ...rest: unknown[]) {
    // readDocumentPath reads the file-namespace form of the path on Windows (\\?\C:\...).
    if (typeof path === "string" && resolve(path.replace(/^\\\\\?\\/, "")).toLowerCase() === held) {
      refused += 1;
      throw Object.assign(new Error(`EACCES: permission denied, open '${path}'`), { code: "EACCES", errno: -13 });
    }
    return original.call(this, path, ...rest);
  };
  syncBuiltinESMExports();
  try {
    const out = fn();
    assert.ok(refused > 0, `${target} was never read`);
    return out;
  } finally {
    module.readFileSync = original;
    syncBuiltinESMExports();
  }
}

function surface(report: VerifyReport): Record<string, unknown> {
  return {
    status: report.status,
    exit_code: report.exit_code,
    reason: report.outcome.reason,
    errors: report.errors.map((e) => e.code),
    root: report.trust_registry?.trust_registry_root_signature_status ?? null,
  };
}

test("each document the host fails to read is a host failure, read as a host reads it", () => {
  const dir = tempDir("trust-document-host-failure");
  try {
    const bundle = Bundle.linkValid().seal();
    const bundleDir = bundle.writeTo(join(dir, "bundle"));
    const { root, sign } = ephemeralRoot("root-1");
    const m = ephemeralAuthorizationWith(bundle, { trust: (t) => { delete t.signature; } });
    sign(m.trustRegistry);
    const paths = { entry: join(dir, "entry.json"), trust: join(dir, "trust.json"), root: join(dir, "root.json") };
    writeFileSync(paths.entry, JSON.stringify(m.registryEntry));
    writeFileSync(paths.trust, JSON.stringify(m.trustRegistry));
    writeFileSync(paths.root, JSON.stringify(rootDocument([root])));
    const run = (): VerifyReport => verifyBundle(bundleDir, {
      registryEntry: readDocumentPath(paths.entry),
      trustRegistry: readDocumentPath(paths.trust),
      trustRoots: readDocumentPath(paths.root),
      evaluationTime: EVALUATION_TIME,
    });
    assert.equal(run().status, "OFFLINE_OK");
    const expected: Record<keyof typeof paths, Record<string, unknown>> = {
      entry: { status: "HOST_FAILURE", exit_code: 5, reason: "registry_link_read_failed", errors: ["registry_link_read_failed"], root: null },
      trust: { status: "HOST_FAILURE", exit_code: 5, reason: "trust_registry_read_failed", errors: ["trust_registry_read_failed"], root: null },
      root: {
        status: "HOST_FAILURE", exit_code: 5, reason: "trust_root_read_failed", errors: ["trust_root_read_failed"],
        root: "ROOT_SIGNATURE_NOT_EVALUATED",
      },
    };
    for (const name of Object.keys(paths) as (keyof typeof paths)[]) {
      const report = hostRefusingToRead(paths[name], () => {
        assert.equal(readDocumentPath(paths[name]), DOCUMENT_READ_FAILED, name);
        return run();
      });
      assert.deepEqual(surface(report), expected[name], name);
      assert.deepEqual(report.checks_established, [], name);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
