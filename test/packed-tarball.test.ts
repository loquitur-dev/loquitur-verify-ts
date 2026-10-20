// tools/check_packed_tarball.py, which the release workflow runs over the tarball `npm pack`
// writes before the files are summed and attested, run here over planted tarballs: one that it
// clears, and one for each finding. The tarballs are written by the small ustar writer below, so
// the test needs no npm and no archive tool. The Python that runs the tool is the host's
// (LOQUITUR_PYTHON, else `python`, else `python3`); without one the tests skip.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { PACKAGE_DIR } from "./bundle-kit.ts";

const TOOL = join(PACKAGE_DIR, "tools", "check_packed_tarball.py");

function findPython(): string | null {
  const candidates = [process.env.LOQUITUR_PYTHON, "python", "python3"].filter((c): c is string => Boolean(c));
  for (const candidate of candidates) {
    const probe = spawnSync(candidate, ["--version"], { encoding: "utf8" });
    if (!probe.error && probe.status === 0) return candidate;
  }
  return null;
}

const PYTHON = findPython();
const NO_PYTHON = PYTHON === null ? "no Python interpreter on this host (LOQUITUR_PYTHON, python, python3)" : false;

interface Entry {
  name: string;
  /** "0" a regular file, "2" a symbolic link, "5" a directory. */
  type?: "0" | "2" | "5";
  body?: Buffer | string;
  link?: string;
}

/** One 512-byte ustar header for `entry`. */
function header(entry: Entry, size: number): Buffer {
  const block = Buffer.alloc(512);
  const field = (offset: number, length: number, value: string) => block.write(value, offset, length, "latin1");
  const octal = (offset: number, length: number, value: number) => field(offset, length, value.toString(8).padStart(length - 1, "0") + "\0");
  field(0, 100, entry.name);
  octal(100, 8, entry.type === "5" ? 0o755 : 0o644);
  octal(108, 8, 0);
  octal(116, 8, 0);
  octal(124, 12, size);
  octal(136, 12, 0);
  field(148, 8, "        ");
  field(156, 1, entry.type ?? "0");
  field(157, 100, entry.link ?? "");
  field(257, 6, "ustar\0");
  field(263, 2, "00");
  let sum = 0;
  for (const byte of block) sum += byte;
  field(148, 8, sum.toString(8).padStart(6, "0") + "\0 ");
  return block;
}

/** A gzip-compressed ustar archive of `entries`, in order. */
function tarball(entries: Entry[]): Buffer {
  const parts: Buffer[] = [];
  for (const entry of entries) {
    const body = entry.type === "0" || entry.type === undefined ? Buffer.from(entry.body ?? "") : Buffer.alloc(0);
    parts.push(header(entry, body.length), body, Buffer.alloc((512 - (body.length % 512)) % 512));
  }
  parts.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(parts));
}

function runTool(bytes: Buffer): { status: number | null; out: string } {
  const dir = mkdtempSync(join(tmpdir(), "lq-packed-tarball-"));
  try {
    const path = join(dir, "loquitur-verify-0.0.0.tgz");
    writeFileSync(path, bytes);
    const run = spawnSync(PYTHON!, [TOOL, path], { cwd: PACKAGE_DIR, encoding: "utf8" });
    assert.equal(run.error, undefined);
    return { status: run.status, out: run.stdout + run.stderr };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const CLEAN: Entry[] = [
  { name: "package/package.json", body: '{"name": "@loquitur/verify"}\n' },
  { name: "package/dist/src/index.js", body: "export const ok = true;\n" },
];

test("a tarball of text under package/ with no needle is cleared", { skip: NO_PYTHON }, () => {
  const run = runTool(tarball([{ name: "package/", type: "5" }, ...CLEAN]));
  assert.equal(run.status, 0, run.out);
  assert.match(run.out, /^packed_tarball_ok$/m);
});

test("every finding over a planted tarball is reported, and the run fails", { skip: NO_PYTHON }, () => {
  // The needle is assembled, as the boundary tool assembles its own: this file is scanned too.
  const needle = "BEGIN PR" + "IVATE KEY";
  const cases: [string, Entry, RegExp][] = [
    ["a disclosure needle", { name: "package/dist/src/key.js", body: "// " + needle + "\n" }, /^forbidden substring .* in package\/dist\/src\/key\.js$/m],
    ["an encoded block", { name: "package/dist/src/blob.js", body: "begin-base64 644 x\n" }, /^an encoded block is not read, so not cleared: package\/dist\/src\/blob\.js$/m],
    ["an invisible code point", { name: "package/README.md", body: "a\u200Bb\n" }, /^invisible character U\+200B at package\/README\.md:1:2/m],
    ["bytes that are not text", { name: "package/dist/src/data.bin", body: Buffer.from([0x00, 0xff, 0x01]) }, /^not text, so not cleared: package\/dist\/src\/data\.bin$/m],
    ["a member outside package/", { name: "other/index.js", body: "export {};\n" }, /^other\/index\.js: not a path under package\/$/m],
    ["a member that climbs out", { name: "package/../index.js", body: "export {};\n" }, /^package\/\.\.\/index\.js: not a path under package\/$/m],
    ["a symbolic link", { name: "package/link.js", type: "2", link: "../outside.js" }, /^package\/link\.js: not a regular file or a directory$/m],
  ];
  for (const [label, entry, finding] of cases) {
    const run = runTool(tarball([...CLEAN, entry]));
    assert.equal(run.status, 1, label + ": " + run.out);
    assert.match(run.out, finding, label + ": " + run.out);
    assert.doesNotMatch(run.out, /packed_tarball_ok/, label);
  }
});

test("a tarball that holds no file, or is no tarball, is not cleared", { skip: NO_PYTHON }, () => {
  const empty = runTool(tarball([{ name: "package/", type: "5" }]));
  assert.equal(empty.status, 1, empty.out);
  assert.match(empty.out, /holds no file; nothing was scanned/);
  const garbage = runTool(Buffer.from("not a tarball\n"));
  assert.equal(garbage.status, 2, garbage.out);
  assert.match(garbage.out, /cannot be checked/);
});
