// A link the host cannot follow to an entry that is there is the host failing, not absence
// (report-contract.md section 5.3): on Windows a symbolic link to the null device meets
// ERROR_INVALID_REPARSE_DATA, which the section names a host failure. Node reports ENOENT for that
// error, as it does for a link that resolves to nothing, and keeps no host error number to tell the
// two apart; CPython keeps the number, and the Python verifier reads 4392 as a host
// failure and 2 or 3 as nothing found. A link that resolves to nothing stays nothing found.
//
// The cases are real links on disk. Elsewhere than Windows the host reports the error of the
// operation itself and no link to a device fails this way, so the test is skipped there; on a
// Windows host that refuses to make symbolic links it is skipped with the host's answer.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { join } from "node:path";
import { tempDir } from "./bundle-kit.ts";
import { verifyBundle, readDocumentPath, DOCUMENT_PATH_NAMES_NOTHING, DOCUMENT_READ_FAILED, type VerifyReport } from "../src/verify.ts";

const NUL = "\\\\.\\nul";

function surface(report: VerifyReport): Record<string, unknown> {
  return { status: report.status, reason: report.outcome.reason, errors: report.errors.map((e) => e.code) };
}

/** The links below, made in a fresh directory, or why this host cannot make them. */
function makeLinks(dir: string): string | null {
  if (process.platform !== "win32") return "only a Windows host meets invalid reparse data on a link to a device";
  try {
    fs.symlinkSync(NUL, join(dir, "nulink"), "file");
  } catch (err) {
    return `the host refuses to make a symbolic link: ${(err as NodeJS.ErrnoException).code ?? String(err)}`;
  }
  fs.symlinkSync(join(dir, "nulink"), join(dir, "chain"), "file");
  fs.symlinkSync(NUL, join(dir, "nuldir"), "dir");
  fs.symlinkSync(join(dir, "nothing-here"), join(dir, "dangling"), "file");
  fs.symlinkSync(join(dir, "nothing-dir"), join(dir, "dangdir"), "dir");
  return null;
}

const HOST = { status: "HOST_FAILURE", reason: "filesystem_error", errors: ["filesystem_error"] };
const NOTHING = { status: "HOST_FAILURE", reason: "input_not_found", errors: ["input_not_found"] };

test("a link the host cannot follow to an entry that is there is a host failure, not absence", (t) => {
  const dir = tempDir("link-host-failure");
  try {
    const why = makeLinks(dir);
    if (why !== null) {
      t.skip(why);
      return;
    }
    // The host's own answer through the link is ENOENT for every case below, so only the
    // classification tells them apart.
    for (const name of ["nulink", "dangling"]) {
      assert.throws(() => fs.statSync(join(dir, name)), (err: NodeJS.ErrnoException) => err.code === "ENOENT", name);
    }
    const cases: [string, Record<string, unknown>][] = [
      ["nulink", HOST], // CPython: winerror 4392
      ["chain", HOST], // a link to that link: winerror 4392
      [join("nuldir", "bundle"), HOST], // below a directory link to the device: winerror 4392
      ["dangling", NOTHING], // a link that resolves to nothing: winerror 2
      [join("dangdir", "bundle"), NOTHING], // below a directory link to nothing: winerror 3
      ["absent", NOTHING], // no entry: winerror 2
    ];
    for (const [rel, expected] of cases) {
      assert.deepEqual(surface(verifyBundle(join(dir, rel))), expected, rel);
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("a document behind a link the host cannot follow is a failed read, not a path naming no file", (t) => {
  const dir = tempDir("link-host-failure-doc");
  try {
    const why = makeLinks(dir);
    if (why !== null) {
      t.skip(why);
      return;
    }
    assert.equal(readDocumentPath(join(dir, "nulink")), DOCUMENT_READ_FAILED);
    assert.equal(readDocumentPath(join(dir, "chain")), DOCUMENT_READ_FAILED);
    assert.equal(readDocumentPath(join(dir, "dangling")), DOCUMENT_PATH_NAMES_NOTHING);
    assert.equal(readDocumentPath(join(dir, "absent")), DOCUMENT_PATH_NAMES_NOTHING);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
