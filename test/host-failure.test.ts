// A host failure is not an absent member (report-contract.md section 5.3). When the host fails to
// list the input directory, the input is refused as a whole with filesystem_error; when it fails to
// list a directory on a member's path, or to inspect an entry on it, the member is unread, and the
// run reports the reading layer's *_read_failed error rather than a missing member. The root marker
// is found in the input's own listing by exact code units, so a host that ignores letter case does
// not turn a directory holding MANIFEST.JSON into a bundle. A link resolving to itself is a path at
// which nothing is found, as a missing entry is.
//
// The failures are injected into node:fs, which the Node reader imports, so they hold on every
// host. The last test makes the same two listing failures real where the host can (an ACL on
// Windows, permission bits elsewhere) and says why it is skipped where it cannot.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { spawnSync } from "node:child_process";
import { basename, join } from "node:path";
import { Bundle, linkEntryFor, tempDir } from "./bundle-kit.ts";
import { verifyBundle, type VerifyReport } from "../src/verify.ts";

type FsName = "readdirSync" | "lstatSync";

function refusal(syscall: string, path: string): NodeJS.ErrnoException {
  const err = new Error(`EACCES: permission denied, ${syscall} '${path}'`) as NodeJS.ErrnoException;
  err.code = "EACCES";
  err.errno = -13;
  err.syscall = syscall;
  err.path = path;
  return err;
}

/** Run `fn` while the node:fs function `name` fails with EACCES on every path `refuse` selects. */
function withHostRefusing<T>(name: FsName, refuse: (path: string) => boolean, fn: () => T): T {
  const module = fs as unknown as Record<FsName, (...args: unknown[]) => unknown>;
  const original = module[name];
  let refused = 0;
  module[name] = function (this: unknown, path: unknown, ...rest: unknown[]) {
    if (refuse(String(path))) {
      refused += 1;
      throw refusal(name === "readdirSync" ? "scandir" : "lstat", String(path));
    }
    return original.call(this, path, ...rest);
  };
  syncBuiltinESMExports();
  try {
    const out = fn();
    // A refusal that never happened would leave the test measuring nothing.
    assert.ok(refused > 0, `the host was never asked for what ${name} refuses`);
    return out;
  } finally {
    module[name] = original;
    syncBuiltinESMExports();
  }
}

function surface(report: VerifyReport): Record<string, unknown> {
  return { status: report.status, reason: report.outcome.reason, errors: report.errors.map((e) => e.code) };
}

/** link_valid_bundle with one more declared member, sub/extra.json, in a subdirectory. */
function bundleWithSubdirectory(): Bundle {
  const b = Bundle.linkValid().setJson("sub/extra.json", { note: "declared, inside a subdirectory" });
  b.edit("manifest.json", (m) => { m.files["sub/extra.json"] = ""; });
  return b.seal();
}

function onDisk<T>(bundle: Bundle, fn: (root: string) => T): T {
  const dir = tempDir("host-failure");
  try {
    return fn(bundle.writeTo(join(dir, "bundle")));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

const isRoot = (path: string) => basename(path) === "bundle";
const isSub = (path: string) => basename(path) === "sub";
const underRoot = (path: string) => /[\\/]bundle[\\/]/.test(path);

test("a bundle whose baseline verifies is what each failure below is injected into", () => {
  onDisk(bundleWithSubdirectory(), (root) => {
    assert.deepEqual(surface(verifyBundle(root)), { status: "OFFLINE_OK", reason: "local_integrity_checks_passed", errors: [] });
  });
});

test("a host that fails to list the input directory refuses the input as filesystem_error", () => {
  const bundle = bundleWithSubdirectory();
  const entry = linkEntryFor(bundle);
  onDisk(bundle, (root) => {
    const want = { status: "HOST_FAILURE", reason: "filesystem_error", errors: ["filesystem_error"] };
    assert.deepEqual(withHostRefusing("readdirSync", isRoot, () => surface(verifyBundle(root))), want);
    assert.deepEqual(withHostRefusing("readdirSync", isRoot, () => surface(verifyBundle(root, { registryEntry: entry }))), want);
  });
});

test("a declared member in a directory the host fails to list is unread, not missing", () => {
  onDisk(bundleWithSubdirectory(), (root) => {
    assert.deepEqual(withHostRefusing("readdirSync", isSub, () => surface(verifyBundle(root))), {
      status: "HOST_FAILURE",
      reason: "bundle_inventory_failed",
      errors: ["bundle_inventory_failed", "manifest_read_failed"],
    });
  });
});

test("members the host fails to inspect are unread in every layer that reads them", () => {
  // A listable root whose entries cannot be inspected: a POSIX directory with read and no search
  // permission. Each layer that reads a member reports its own read failure, the receipt included
  // at every level, and none of them reports a member as absent or as failing its contract.
  onDisk(bundleWithSubdirectory(), (root) => {
    assert.deepEqual(withHostRefusing("lstatSync", underRoot, () => surface(verifyBundle(root))), {
      status: "HOST_FAILURE",
      reason: "bundle_inventory_failed",
      errors: ["bundle_inventory_failed", "manifest_read_failed", "p1_read_failed", "envelope_read_failed", "registry_link_read_failed"],
    });
  });
});

test("a member the host fails to inspect was not seen, and its presence flag is false", () => {
  // bundle-objects.md section 6: a presence flag records what the verifier saw. A member the host
  // found and failed to open is present (test/host-failure-presence.test.ts); one whose entry the
  // host failed to inspect was never found, and the Python verifier reports it false too.
  // Every layer is refused, so every check of the bundle is false, as bundle-objects.md section 6
  // states for a refused layer; the run reads no entry, so the link and the authorization are null.
  onDisk(bundleWithSubdirectory(), (root) => {
    const checks = withHostRefusing("lstatSync", underRoot, () => verifyBundle(root).checks);
    assert.deepEqual(checks, {
      manifest_sha256: false, manifest_files: false, p1_sha256: false, canonical_input_present: false, p1_input_hash: false,
      envelope_present: false, envelope_sha256: false, envelope_links: false,
      registry_signature: "UNSUPPORTED", registry_link: null, trust_registry: null,
    });
  });
});

test("the root marker is matched exactly in the input's listing, whatever the host's letter case", () => {
  for (const spelling of ["MANIFEST.JSON", "Manifest.json", "manifest.JSON"]) {
    const bundle = Bundle.linkValid();
    const manifest = bundle.bytes("manifest.json");
    bundle.delete("manifest.json").setBytes(spelling, manifest);
    onDisk(bundle, (root) => {
      assert.deepEqual(surface(verifyBundle(root)), {
        status: "OFFLINE_FAIL",
        reason: "bundle_root_invalid",
        errors: ["bundle_root_invalid"],
      }, spelling);
    });
  }
});

test("an input that is a link resolving to itself names nothing: input_not_found", () => {
  const dir = tempDir("host-failure-loop");
  const loop = join(dir, "loop");
  try {
    fs.symlinkSync(loop, loop, process.platform === "win32" ? "junction" : "dir");
    assert.deepEqual(surface(verifyBundle(loop)), { status: "HOST_FAILURE", reason: "input_not_found", errors: ["input_not_found"] });
  } finally {
    try { fs.rmdirSync(loop); } catch { try { fs.unlinkSync(loop); } catch { /* never made */ } }
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("an input path holding a NUL names nothing: input_not_found", () => {
  const dir = tempDir("host-failure-nul");
  try {
    assert.deepEqual(surface(verifyBundle(join(dir, "bundle\u0000name"))), {
      status: "HOST_FAILURE",
      reason: "input_not_found",
      errors: ["input_not_found"],
    });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// Host-class rows give HOST_FAILURE, exit 5 (report-contract.md section 3.1): nothing found at the
// input path, a host that fails to list a directory or to inspect an entry, a member the host
// fails to read. A content row beside them (the root marker, a device) stays OFFLINE_FAIL.
test("an input that is a device is unsupported_input, not a host failure", () => {
  // The null device exists on every host and is neither a directory nor a regular file. On
  // Windows the host will not resolve \\.\nul, and that is not filesystem_error.
  const device = process.platform === "win32" ? "\\\\.\\nul" : "/dev/null";
  assert.deepEqual(surface(verifyBundle(device)), {
    status: "OFFLINE_FAIL",
    reason: "unsupported_input",
    errors: ["unsupported_input"],
  });
});

/** Deny the current user the listing of `dir` for real, or return why this host cannot. */
function denyListing(dir: string): (() => void) | string {
  if (process.platform === "win32") {
    const user = process.env.USERNAME;
    if (!user) return "USERNAME is not set, so no access-control entry can name the current user";
    const deny = spawnSync("icacls", [dir, "/deny", `${user}:(RD)`], { encoding: "utf8" });
    if (deny.status !== 0) return `icacls cannot deny the listing here: ${deny.stderr || deny.stdout}`;
    return () => { spawnSync("icacls", [dir, "/remove:d", user]); };
  }
  fs.chmodSync(dir, 0o311);
  return () => { fs.chmodSync(dir, 0o755); };
}

test("the same two listing failures, made real on this host", (t) => {
  const cases: Array<[string, (root: string) => string, string[]]> = [
    ["the input directory", (root) => root, ["filesystem_error"]],
    ["a subdirectory holding a declared member", (root) => join(root, "sub"), ["bundle_inventory_failed", "manifest_read_failed"]],
  ];
  for (const [label, target, errors] of cases) {
    onDisk(bundleWithSubdirectory(), (root) => {
      const restore = denyListing(target(root));
      if (typeof restore === "string") {
        t.skip(restore);
        return;
      }
      try {
        let listable = true;
        try { fs.readdirSync(target(root)); } catch { listable = false; }
        if (listable) {
          t.diagnostic(`${label}: this host still lists the directory (a privileged user), so the case is not made`);
          return;
        }
        assert.deepEqual(surface(verifyBundle(root)).errors, errors, label);
      } finally {
        restore();
      }
    });
  }
});
