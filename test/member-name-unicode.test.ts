// A member name that is not a Unicode string fails the run, in every reader (bundle-objects.md
// sections 1 and 2).
//
// Windows names are UTF-16 and may hold a lone surrogate; POSIX names are bytes and may be invalid
// UTF-8. Node hands both to a string-named readdirSync as U+FFFD, a name that is not the entry's,
// and a map reader could take a lone-surrogate key for an ordinary undeclared member. No manifest
// can declare such a name (a lone surrogate is refused at JSON load), so it can
// never be a verified member; the Python verifier refuses the name (bundle_member_name_invalid).
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join, sep } from "node:path";
import { Bundle, FAIL, outcome, tempDir } from "./bundle-kit.ts";
import { bundleReaderFromMap, verifyBundleFiles } from "../src/verify-core.ts";
import { verifyBundle } from "../src/verify.ts";

const CHECKS = ["manifest_sha256", "manifest_files", "p1_sha256", "envelope_links"];

/** The bytes of a name that is not Unicode on this host: a lone surrogate in WTF-8, or 0xFF. */
const NOT_UNICODE = process.platform === "win32" ? Buffer.from([0xed, 0xb0, 0x80]) : Buffer.from([0xff]);

/** A path, as bytes, under `dir` whose last name is `stem`, the non-Unicode bytes, then `suffix`. */
function pathWithNonUnicodeName(dir: string, stem: string, suffix: string): Buffer {
  return Buffer.concat([Buffer.from(dir + sep + stem), NOT_UNICODE, Buffer.from(suffix)]);
}

/**
 * The name Node reports for the entry named `NOT_UNICODE` + ".txt": its runtime decodes the bytes
 * leniently, one U+FFFD per byte it cannot decode (three on Windows, one on POSIX).
 */
const REPLACED = new TextDecoder().decode(Buffer.concat([NOT_UNICODE, Buffer.from(".txt")]));

function onDisk(build: (root: string) => void, bundle = Bundle.linkValid().seal()) {
  const dir = tempDir("unicode-names");
  try {
    const root = bundle.writeTo(join(dir, "bundle"));
    try {
      build(root);
    } catch (err) {
      return { skipped: String((err as Error).message) };
    }
    return outcome(verifyBundle(root), CHECKS);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("a name that is not Unicode, anywhere in a directory bundle, fails the run", (t) => {
  const withFffd = Bundle.linkValid();
  withFffd.setBytes(REPLACED, "declared\n").edit("manifest.json", (m) => { m.files[REPLACED] = ""; });
  withFffd.seal();
  const got = {
    rootFile: onDisk((root) => writeFileSync(pathWithNonUnicodeName(root, "x", ".txt"), "undeclared\n")),
    subdirectoryFile: onDisk((root) => {
      mkdirSync(join(root, "sub"));
      writeFileSync(pathWithNonUnicodeName(join(root, "sub"), "x", ".txt"), "undeclared\n");
    }),
    directory: onDisk((root) => {
      const dir = pathWithNonUnicodeName(root, "d", "");
      mkdirSync(dir);
      writeFileSync(Buffer.concat([dir, Buffer.from(sep + "inside.txt")]), "inside\n");
    }),
    // Beside a declared member named what Node reports for the entry: listed by that name, the
    // entry would be a second copy of the declared name, which the manifest covers, and pass.
    besideItsReplacementName: onDisk((root) => writeFileSync(pathWithNonUnicodeName(root, "", ".txt"), "lone\n"), withFffd),
  };
  if (Object.values(got).some((v) => "skipped" in v)) {
    t.skip(`this filesystem refuses names that are not Unicode: ${JSON.stringify(got)}`);
    return;
  }
  const refused = { ...FAIL, manifest_sha256: true, manifest_files: false, p1_sha256: true, envelope_links: true };
  assert.deepEqual(got, {
    rootFile: refused,
    subdirectoryFile: refused,
    directory: refused,
    besideItsReplacementName: refused,
  });
});

test("a map reader listing a name beyond the portable set fails the run instead of reviewing an undeclared member", () => {
  const b = Bundle.linkValid().seal();
  const map: Record<string, string> = {};
  for (const [name, data] of b.files) map[name] = new TextDecoder().decode(data);
  const withLone = { ...map, "x\uDC00.txt": "undeclared\n" };
  // A surrogate pair is a character, but not one of the portable set (bundle-objects.md section 2).
  const withPair = { ...map, "x\uD83D\uDE00.txt": "undeclared\n" };
  const withPortable = { ...map, "x.txt": "undeclared\n" };
  const refused = { ...FAIL, manifest_sha256: true, manifest_files: false, p1_sha256: true, envelope_links: true };
  assert.deepEqual(
    {
      lone: outcome(verifyBundleFiles(bundleReaderFromMap(withLone)), CHECKS),
      pair: outcome(verifyBundleFiles(bundleReaderFromMap(withPair)), CHECKS),
      portable: outcome(verifyBundleFiles(bundleReaderFromMap(withPortable)), ["manifest_files"]),
    },
    {
      lone: refused,
      pair: refused,
      portable: { status: "OFFLINE_REVIEW", verdict: "REVIEW", exit_code: 2, manifest_files: true },
    },
  );
});
