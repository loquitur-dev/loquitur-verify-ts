// A member the host found and opened, whose read then fails, is a member the host failed to read
// (report-contract.md section 5.3), whatever code the failure carries: a read that fails with
// ENOENT after the open is not the member's absence. The failure is injected into node:fs, which
// the Node reader imports, for one member at a time.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { basename, join } from "node:path";
import { Bundle, tempDir } from "./bundle-kit.ts";
import { verifyBundle } from "../src/verify.ts";

/** Run `fn` while every read of a file named `member` fails with `code` after the file was opened. */
function withReadFailing<T>(member: string, code: string, fn: () => T): T {
  const module = fs as unknown as Record<"openSync" | "readSync" | "closeSync", (...args: unknown[]) => unknown>;
  const { openSync, readSync, closeSync } = module;
  const watched = new Set<unknown>();
  let failed = 0;
  module.openSync = function (this: unknown, path: unknown, ...rest: unknown[]) {
    const fd = openSync.call(this, path, ...rest);
    if (basename(String(path)) === member) watched.add(fd);
    return fd;
  };
  module.readSync = function (this: unknown, fd: unknown, ...rest: unknown[]) {
    if (watched.has(fd)) {
      failed += 1;
      const err = new Error(`${code}: read failed`) as NodeJS.ErrnoException;
      err.code = code;
      err.syscall = "read";
      throw err;
    }
    return readSync.call(this, fd, ...rest);
  };
  module.closeSync = function (this: unknown, fd: unknown, ...rest: unknown[]) {
    watched.delete(fd);
    return closeSync.call(this, fd, ...rest);
  };
  syncBuiltinESMExports();
  try {
    const out = fn();
    assert.ok(failed > 0, `no read of ${member} was attempted`);
    return out;
  } finally {
    Object.assign(module, { openSync, readSync, closeSync });
    syncBuiltinESMExports();
  }
}

test("a read that fails with ENOENT after the open is the layer's read failure, not an absent member", () => {
  const dir = tempDir("read-failure");
  try {
    const root = Bundle.linkValid().seal().writeTo(join(dir, "bundle"));
    for (const [member, row] of [["manifest.json", "manifest_read_failed"], ["p1.json", "p1_read_failed"], ["envelope_env1.json", "envelope_read_failed"]] as const) {
      for (const code of ["ENOENT", "EIO"]) {
        const report = withReadFailing(member, code, () => verifyBundle(root));
        assert.ok(report.errors.map((e) => e.code).includes(row), `${member} ${code}: ${JSON.stringify(report.errors)}`);
      }
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
