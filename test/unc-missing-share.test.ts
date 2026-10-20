// A UNC server or share that does not exist or cannot be reached is the host failing, not a path
// at which nothing is found (report-contract.md section 5.3): ERROR_BAD_NETPATH (53) and
// ERROR_BAD_NET_NAME (67), which libuv reports as UNKNOWN. The input is refused as
// filesystem_error, and a document on such a share is a failed read.
//
// The share is on this host (`\\localhost`, `\\127.0.0.1`) under a name no share has, so no other
// machine is asked. Only Windows reads such a path as a share; elsewhere it is an ordinary
// relative name, and the test is skipped there.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { randomBytes } from "node:crypto";
import { DOCUMENT_READ_FAILED, readDocumentPath, verifyBundle, type VerifyReport } from "../src/verify.ts";

function surface(report: VerifyReport): Record<string, unknown> {
  return { status: report.status, reason: report.outcome.reason, errors: report.errors.map((e) => e.code) };
}

const HOST = { status: "HOST_FAILURE", reason: "filesystem_error", errors: ["filesystem_error"] };

test("a UNC share that does not exist is a host failure, not nothing found", (t) => {
  if (process.platform !== "win32") {
    t.skip("only Windows reads a path beginning with two separators as a share");
    return;
  }
  const tag = randomBytes(6).toString("hex");
  const paths = [`\\\\localhost\\lq-no-such-share-${tag}\\bundle`, `\\\\127.0.0.1\\lq-no-such-share-${tag}\\bundle`];
  for (const path of paths) {
    // The host's own answer is none of the codes read as nothing found.
    assert.throws(() => fs.statSync(path), (err: NodeJS.ErrnoException) => !["ENOENT", "ENOTDIR", "ELOOP", "ENAMETOOLONG"].includes(err.code ?? ""), path);
    assert.deepEqual(surface(verifyBundle(path)), HOST, path);
    assert.equal(readDocumentPath(path), DOCUMENT_READ_FAILED, path);
  }
});
