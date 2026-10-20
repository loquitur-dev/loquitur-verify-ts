// The filesystem reader refuses links anywhere in a directory bundle, reads declared members by
// exact on-disk names under the member-name rule, and bounds every read at 20 MiB
// (bundle-objects.md sections 1, 2 and 5). Junctions need no privilege on Windows and are made on
// every host that has them; symbolic links may need one (Developer Mode or an elevated shell), and
// that test is skipped with the reason when the host refuses to create them.
import { test } from "node:test";
import assert from "node:assert/strict";
import { linkSync, mkdirSync, rmdirSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { Bundle, ENTRIES, FAIL, PASS, outcome, sha256Hex, tempDir } from "./bundle-kit.ts";
import { verifyBundle } from "../src/verify.ts";

const OUTSIDE_TEXT = "outside the bundle root\n";

interface Scene {
  dir: string;
  outside: string;
  links: string[];
}

function scene(): Scene {
  const dir = tempDir("links");
  const outside = join(dir, "outside");
  mkdirSync(outside);
  writeFileSync(join(outside, "sentinel.txt"), OUTSIDE_TEXT);
  return { dir, outside, links: [] };
}

function cleanup(s: Scene) {
  // Links first, so nothing below ever walks into what they point at.
  for (const link of s.links.reverse()) {
    try { rmdirSync(link); } catch { try { unlinkSync(link); } catch { /* already gone */ } }
  }
  rmSync(s.dir, { recursive: true, force: true });
}

function writeBundle(s: Scene, declare?: string): string {
  const b = Bundle.linkValid();
  if (declare) b.edit("manifest.json", (m) => { m.files[declare] = `sha256:${sha256Hex(OUTSIDE_TEXT)}`; });
  return b.seal().writeTo(join(s.dir, "bundle"));
}

function link(s: Scene, target: string, path: string, type: "junction" | "file" | "dir"): boolean {
  try {
    symlinkSync(target, path, type);
    s.links.push(path);
    return true;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "EPERM") return false;
    throw err;
  }
}

const CHECKS = ["manifest_files"];

test("a junction anywhere in the bundle fails the run", () => {
  const cases: Array<[string, (s: Scene, root: string) => void, string | undefined, object]> = [
    ["a declared member reached through a junction to outside the root",
      (s, root) => { link(s, s.outside, join(root, "attached"), "junction"); }, "attached/sentinel.txt", { ...FAIL, manifest_files: false }],
    ["a junction as an intermediate directory",
      (s, root) => { mkdirSync(join(root, "sub")); link(s, s.outside, join(root, "sub", "link"), "junction"); }, "sub/link/sentinel.txt",
      { ...FAIL, manifest_files: false }],
    ["a junction to a sibling directory whose name extends the root's",
      (s, root) => {
        const evil = `${root}-evil`;
        mkdirSync(evil);
        writeFileSync(join(evil, "sentinel.txt"), OUTSIDE_TEXT);
        link(s, evil, join(root, "attached"), "junction");
      }, "attached/sentinel.txt", { ...FAIL, manifest_files: false }],
    ["a dangling junction under a declared name",
      (s, root) => { link(s, join(s.dir, "does-not-exist"), join(root, "attached"), "junction"); }, "attached/sentinel.txt",
      { ...FAIL, manifest_files: false }],
    ["an undeclared junction to outside the root",
      (s, root) => { link(s, s.outside, join(root, "attached"), "junction"); }, undefined, { ...FAIL, manifest_files: false }],
    ["an undeclared junction to the root itself",
      (s, root) => { link(s, root, join(root, "loop"), "junction"); }, undefined, { ...FAIL, manifest_files: false }],
  ];
  const got: Record<string, unknown> = {};
  const want: Record<string, unknown> = {};
  for (const [label, make, declare, expected] of cases) {
    const s = scene();
    try {
      const root = writeBundle(s, declare);
      make(s, root);
      got[label] = outcome(verifyBundle(root), CHECKS);
      want[label] = expected;
    } finally {
      cleanup(s);
    }
  }
  // An alias inside the bundle: the file exists under real/, the declared name reaches it through a
  // junction.
  const s = scene();
  try {
    const b = Bundle.linkValid();
    b.setBytes("real/sentinel.txt", OUTSIDE_TEXT);
    b.edit("manifest.json", (m) => { m.files["real/sentinel.txt"] = ""; m.files["alias/sentinel.txt"] = `sha256:${sha256Hex(OUTSIDE_TEXT)}`; });
    const root = b.seal().writeTo(join(s.dir, "bundle"));
    link(s, join(root, "real"), join(root, "alias"), "junction");
    got["an internal alias through a junction"] = outcome(verifyBundle(root), CHECKS);
    want["an internal alias through a junction"] = { ...FAIL, manifest_files: false };
  } finally {
    cleanup(s);
  }
  assert.deepEqual(got, want);
});

test("a root reached through a junction, and a hard link, verify as what they are", () => {
  const s = scene();
  try {
    const real = Bundle.linkValid().seal().writeTo(join(s.dir, "real"));
    link(s, real, join(s.dir, "via"), "junction");
    assert.deepEqual(outcome(verifyBundle(join(s.dir, "via")), CHECKS), { ...PASS, manifest_files: true });
    // A hard link is indistinguishable from a regular file (README.md, "Scope and limits") and is
    // verified as one.
    const root = writeBundle(s, "attached.txt");
    linkSync(join(s.outside, "sentinel.txt"), join(root, "attached.txt"));
    assert.deepEqual(outcome(verifyBundle(root), CHECKS), { ...PASS, manifest_files: true });
    // The control that makes these meaningful: a junction inside the root still fails.
    link(s, s.outside, join(root, "attached"), "junction");
    assert.deepEqual(outcome(verifyBundle(root), CHECKS), { ...FAIL, manifest_files: false });
  } finally {
    cleanup(s);
  }
});

// Each row carries the checks the Python verifier reports for the same bundle (harness
// links-symlink-*), beside rows that only the refusal of links catches: an undeclared link, a loop
// and an alias inside the root are never read through, and without the refusal they would be an
// undeclared member (REVIEW) or a member read in place.
test("a symbolic link anywhere in the bundle fails the run", (t) => {
  const refusedOverMembers = { ...FAIL, manifest_files: false, manifest_sha256: true, envelope_links: true };
  // A structural member that is a link is refused as a link and is then no manifest to read: both
  // errors, in the order of report-contract.md section 5.3.
  const linkedManifest = "a symbolic link to a file outside, in place of manifest.json";
  const rows: Array<[string, (s: Scene, root: string) => boolean, string | undefined, object]> = [
    [linkedManifest,
      (s, root) => {
        writeFileSync(join(s.outside, "manifest.json"), Bundle.linkValid().seal().bytes("manifest.json"));
        rmSync(join(root, "manifest.json"));
        return link(s, join(s.outside, "manifest.json"), join(root, "manifest.json"), "file");
      }, undefined, { ...FAIL, manifest_files: false, manifest_sha256: false, envelope_links: false }],
    ["a symbolic link to a directory outside, under a declared name",
      (s, root) => link(s, s.outside, join(root, "attached"), "dir"), "attached/sentinel.txt", refusedOverMembers],
    ["a symbolic link to a file outside, under a declared name",
      (s, root) => link(s, join(s.outside, "sentinel.txt"), join(root, "attached.txt"), "file"), "attached.txt", refusedOverMembers],
    ["a symbolic link as an intermediate directory",
      (s, root) => { mkdirSync(join(root, "sub")); return link(s, s.outside, join(root, "sub", "link"), "dir"); },
      "sub/link/sentinel.txt", refusedOverMembers],
    ["a dangling symbolic link under a declared name",
      (s, root) => link(s, join(s.dir, "does-not-exist.txt"), join(root, "attached.txt"), "file"), "attached.txt", refusedOverMembers],
    ["an undeclared symbolic link to a directory outside",
      (s, root) => link(s, s.outside, join(root, "attached"), "dir"), undefined, refusedOverMembers],
    ["an undeclared symbolic link to a file outside",
      (s, root) => link(s, join(s.outside, "sentinel.txt"), join(root, "attached.txt"), "file"), undefined, refusedOverMembers],
    ["an undeclared symbolic link to the root itself",
      (s, root) => link(s, root, join(root, "loop"), "dir"), undefined, refusedOverMembers],
  ];
  const got: Record<string, unknown> = {};
  const want: Record<string, unknown> = {};
  const checks = ["manifest_files", "manifest_sha256", "envelope_links"];
  for (const [label, make, declare, expected] of rows) {
    const s = scene();
    try {
      const root = writeBundle(s, declare);
      if (!make(s, root)) {
        t.skip("symbolic link could not be created on this host (EPERM: the privilege is missing)");
        return;
      }
      const report = verifyBundle(root);
      got[label] = outcome(report, checks);
      want[label] = expected;
      if (label === linkedManifest) {
        got[label + ": the errors"] = report.errors.map((error) => error.code);
        want[label + ": the errors"] = ["unsafe_bundle_member", "manifest_verification_failed"];
      }
    } finally {
      cleanup(s);
    }
  }
  // An alias inside the bundle: the file exists under real/, the declared name reaches it through a
  // symbolic link.
  const s = scene();
  try {
    const b = Bundle.linkValid();
    b.setBytes("real/sentinel.txt", OUTSIDE_TEXT);
    b.edit("manifest.json", (m) => { m.files["real/sentinel.txt"] = ""; m.files["alias/sentinel.txt"] = `sha256:${sha256Hex(OUTSIDE_TEXT)}`; });
    const root = b.seal().writeTo(join(s.dir, "bundle"));
    if (!link(s, join(root, "real"), join(root, "alias"), "dir")) {
      t.skip("symbolic link could not be created on this host (EPERM: the privilege is missing)");
      return;
    }
    got["an internal alias through a symbolic link"] = outcome(verifyBundle(root), checks);
    want["an internal alias through a symbolic link"] = refusedOverMembers;
    // The control: the root itself reached through a symbolic link verifies as the bundle it is.
    const real = Bundle.linkValid().seal().writeTo(join(s.dir, "real"));
    if (!link(s, real, join(s.dir, "via"), "dir")) {
      t.skip("symbolic link could not be created on this host (EPERM: the privilege is missing)");
      return;
    }
    got["a root reached through a symbolic link"] = outcome(verifyBundle(join(s.dir, "via")), checks);
    want["a root reached through a symbolic link"] = { ...PASS, manifest_files: true, manifest_sha256: true, envelope_links: true };
  } finally {
    cleanup(s);
  }
  assert.deepEqual(got, want);
});

test("declared names outside the grammar, or not matching an entry exactly, are not read", () => {
  const rows: Array<[string, string, string | null]> = [
    ["a case variant of a stored name", "P1.JSON", null],
    ["a leading ./", "./member.txt", "member.txt"],
    ["a backslash", "sub\\member.txt", "sub/member.txt"],
    ["an alternate data stream", "p1.json:hidden", null],
    ["the device name NUL", "NUL", null],
    ["a device name in a subdirectory", "sub/CON.txt", null],
    ["the device name com1 with an extension", "com1.txt", null],
    ["a trailing dot", "member.txt.", "member.txt"],
    ["a trailing space", "member.txt ", "member.txt"],
    ["an empty segment", "sub//member.txt", "sub/member.txt"],
    ["a parent segment", "sub/../member.txt", "member.txt"],
  ];
  const got: Record<string, unknown> = {};
  const want: Record<string, unknown> = {};
  for (const [label, declared, stored] of rows) {
    const build = () => {
      const b = Bundle.linkValid();
      if (stored) b.setBytes(stored, "member\n");
      b.edit("manifest.json", (m) => { m.files[declared] = sha256Hex(declared === "P1.JSON" ? b.bytes("p1.json") : "member\n"); });
      return b.seal();
    };
    for (const [entryName, verify] of ENTRIES) {
      got[`${entryName}: ${label}`] = outcome(verify(build()), CHECKS);
      want[`${entryName}: ${label}`] = { ...FAIL, manifest_files: false };
    }
  }
  assert.deepEqual(got, want);
});

test("a member is read up to 20 MiB and not beyond", () => {
  const withMember = (size: number) => {
    const b = Bundle.linkValid();
    b.setBytes("big.bin", new Uint8Array(size));
    b.edit("manifest.json", (m) => { m.files["big.bin"] = ""; });
    return b.seal();
  };
  const exact = withMember(20 * 1024 * 1024);
  const over = withMember(20 * 1024 * 1024 + 1);
  const got: Record<string, unknown> = {};
  for (const [entryName, verify] of ENTRIES) {
    got[`${entryName}: 20 MiB`] = outcome(verify(exact), CHECKS);
    got[`${entryName}: 20 MiB + 1`] = outcome(verify(over), CHECKS);
  }
  assert.deepEqual(got, Object.fromEntries(ENTRIES.flatMap(([name]) => [
    [`${name}: 20 MiB`, { ...PASS, manifest_files: true }],
    [`${name}: 20 MiB + 1`, { ...FAIL, manifest_files: false }],
  ])));
});
