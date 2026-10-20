// Names and paths holding a noncharacter (bundle-objects.md sections 1 and 2, report-contract.md
// section 5.3).
//
// Node.js on Windows stops the process when a path holding U+10FFFF reaches the file system
// ("Assertion failed: code_point < 0x10FFFF"), for lstat of a path that does not exist too. A
// member name holds only the portable characters, so an entry so named is refused from its listed
// name before the host is handed it; a path the verifier is given that holds a noncharacter finds
// nothing; and a bundle root reached through a link whose target path holds one is read through the
// path given, never through the path the host resolves it to. The names are made here by a child
// process on Windows, which this process could not do itself. Every such character in this file is
// written as an escape.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, renameSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { Bundle, FAIL, outcome, tempDir } from "./bundle-kit.ts";
import { DOCUMENT_PATH_NAMES_NOTHING, bundleReaderFromMap, memberNameValid, verifyBundleFiles } from "../src/verify-core.ts";
import { readDocumentPath, verifyBundle } from "../src/verify.ts";

const CHECKS = ["manifest_sha256", "manifest_files", "p1_sha256", "envelope_links"];
const U10FFFF = String.fromCodePoint(0x10ffff);
const NONCHARACTERS = ["\uFDD0", "\uFDEF", "\uFFFE", "\uFFFF", String.fromCodePoint(0x1fffe), U10FFFF];
// Their neighbors, U+FDCF, U+FDF0, U+FFFD, U+10FFFD and the private-use U+E000, are outside the
// portable set too: the rule refuses every code point beyond it, not a list of them.
const NEIGHBORS = ["\uFDCF", "\uFDF0", "\uFFFD", String.fromCodePoint(0x10fffd), "\uE000"];

/** Run a PowerShell script handed over as UTF-16, so no path in it passes through this process. */
function powershell(script: string): void {
  const encoded = Buffer.from(script, "utf16le").toString("base64");
  const run = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-EncodedCommand", encoded], { encoding: "utf8" });
  if (run.status !== 0) throw new Error(`powershell exited ${run.status}: ${run.stderr}`);
}

/** A PowerShell expression for `text`, built from its code points. */
function psString(text: string): string {
  return "(-join (@(" + [...text].map((c) => c.codePointAt(0)!).join(",") + ") | ForEach-Object { [char]::ConvertFromUtf32($_) }))";
}

/** Make `parent`/`name` as a file, or as a directory holding one file. */
function make(parent: string, name: string, kind: "file" | "directory"): void {
  if (process.platform !== "win32") {
    const path = join(parent, name);
    if (kind === "directory") {
      mkdirSync(path);
      writeFileSync(join(path, "inside.txt"), "inside\n");
    } else {
      writeFileSync(path, "undeclared\n");
    }
    return;
  }
  const path = `[System.IO.Path]::Combine(${psString(parent)}, ${psString(name)})`;
  powershell(
    kind === "directory"
      ? `$p = ${path}; [void][System.IO.Directory]::CreateDirectory($p); [System.IO.File]::WriteAllText([System.IO.Path]::Combine($p, 'inside.txt'), 'inside')`
      : `[System.IO.File]::WriteAllText(${path}, 'undeclared')`,
  );
}

/** Move `from` to `to`, a name this process does not hand to the host on Windows. */
function move(from: string, to: string): void {
  if (process.platform !== "win32") renameSync(from, to);
  else powershell(`[System.IO.Directory]::Move(${psString(from)}, ${psString(to)})`);
}

/** Make `link` a junction (on Windows) or a symbolic link to the directory `target`. */
function linkDirectory(target: string, link: string): void {
  if (process.platform !== "win32") symlinkSync(target, link, "dir");
  else powershell(`[void](New-Item -ItemType Junction -Path ${psString(link)} -Target ${psString(target)})`);
}

/** Remove `dir`, which may hold such names, without handing them to the host from this process. */
function remove(dir: string): void {
  if (process.platform !== "win32") rmSync(dir, { recursive: true, force: true });
  else powershell(`if ([System.IO.Directory]::Exists(${psString(dir)})) { [System.IO.Directory]::Delete(${psString(dir)}, $true) }`);
}

function onDisk(build: (root: string) => void) {
  const dir = tempDir("noncharacter-names");
  try {
    const root = Bundle.linkValid().seal().writeTo(join(dir, "bundle"));
    try {
      build(root);
    } catch (err) {
      return { skipped: String((err as Error).message) };
    }
    const report = verifyBundle(root);
    return { ...outcome(report, CHECKS), errors: report.errors.map((e) => e.code) };
  } finally {
    remove(dir);
  }
}

test("a name holding a noncharacter, or any other code point beyond ASCII, is not a portable member name", () => {
  for (const c of [...NONCHARACTERS, ...NEIGHBORS]) {
    assert.equal(memberNameValid(`x${c}.json`), false, `U+${c.codePointAt(0)!.toString(16)}`);
    assert.equal(memberNameValid(`sub${c}/x.json`), false, `U+${c.codePointAt(0)!.toString(16)}`);
  }
});

test("a name holding a noncharacter, anywhere in a directory bundle, fails the run", (t) => {
  const got: Record<string, unknown> = {};
  for (const [label, c] of [["fdd0", "\uFDD0"], ["10ffff", U10FFFF]] as const) {
    got[`${label}:rootFile`] = onDisk((root) => make(root, `x${c}.txt`, "file"));
    got[`${label}:subdirectoryFile`] = onDisk((root) => {
      mkdirSync(join(root, "sub"));
      make(join(root, "sub"), `x${c}.txt`, "file");
    });
    got[`${label}:directory`] = onDisk((root) => make(root, `d${c}`, "directory"));
  }
  if (Object.values(got).some((v) => typeof v === "object" && v !== null && "skipped" in v)) {
    t.skip(`this host cannot make such names: ${JSON.stringify(got)}`);
    return;
  }
  const refused = { ...FAIL, manifest_sha256: true, manifest_files: false, p1_sha256: true, envelope_links: true, errors: ["bundle_member_name_invalid"] };
  assert.deepEqual(got, Object.fromEntries(Object.keys(got).map((k) => [k, refused])));
});

test("a map reader listing a name holding a noncharacter fails the run", () => {
  const b = Bundle.linkValid().seal();
  const map: Record<string, string> = {};
  for (const [name, data] of b.files) map[name] = new TextDecoder().decode(data);
  const got = Object.fromEntries(
    ["\uFDD0", U10FFFF].map((c) => [c.codePointAt(0)!.toString(16), outcome(verifyBundleFiles(bundleReaderFromMap({ ...map, [`x${c}.txt`]: "undeclared\n" })), CHECKS)]),
  );
  const refused = { ...FAIL, manifest_sha256: true, manifest_files: false, p1_sha256: true, envelope_links: true };
  assert.deepEqual(got, { fdd0: refused, "10ffff": refused });
});

test("a bundle or document path holding a noncharacter finds nothing", (t) => {
  const dir = tempDir("noncharacter-path");
  try {
    const plain = join(dir, "plain");
    Bundle.linkValid().seal().writeTo(join(plain, "bundle"));
    writeFileSync(join(plain, "doc.json"), "{}");
    const parent = join(dir, `in${U10FFFF}`);
    try {
      move(plain, parent);
    } catch (err) {
      t.skip(`this host cannot make such names: ${String((err as Error).message)}`);
      return;
    }
    const report = verifyBundle(join(parent, "bundle"));
    assert.deepEqual(
      { status: report.status, errors: report.errors.map((e) => e.code), document: readDocumentPath(join(parent, "doc.json")) },
      { status: "HOST_FAILURE", errors: ["input_not_found"], document: DOCUMENT_PATH_NAMES_NOTHING },
    );
  } finally {
    remove(dir);
  }
});

test("a bundle root reached through a link whose target path holds U+10FFFF is read through the path given", (t) => {
  // bundle-objects.md section 1: the root is the path the verifier is given, and it may be reached
  // through a link. The path the host resolves it to holds U+10FFFF here; handed to lstat and
  // readdir, that path would make Node.js on Windows stop the process, where the Python
  // verifier gives OFFLINE_OK.
  const dir = tempDir("noncharacter-link-target");
  try {
    const plain = join(dir, "plain");
    Bundle.linkValid().seal().writeTo(join(plain, "bundle"));
    const target = join(dir, `t${U10FFFF}`);
    try {
      move(plain, target);
      linkDirectory(join(target, "bundle"), join(dir, "to-bundle"));
      linkDirectory(target, join(dir, "to-parent"));
    } catch (err) {
      t.skip(`this host cannot make such names or links: ${String((err as Error).message)}`);
      return;
    }
    const got = Object.fromEntries(
      [
        ["junction-root", join(dir, "to-bundle")],
        ["under-junction", join(dir, "to-parent", "bundle")],
      ].map(([label, path]) => {
        const report = verifyBundle(path!);
        return [label, { status: report.status, reason: report.outcome.reason, errors: report.errors.map((e) => e.code) }];
      }),
    );
    const ok = { status: "OFFLINE_OK", reason: "local_integrity_checks_passed", errors: [] };
    assert.deepEqual(got, { "junction-root": ok, "under-junction": ok });
  } finally {
    // The links first, as links: their names hold no noncharacter, and removing the directory
    // around them would otherwise meet them.
    for (const link of ["to-bundle", "to-parent"]) rmSync(join(dir, link), { force: true });
    remove(dir);
  }
});

test("a bundle or document path holding a lone surrogate finds nothing, and no sibling is read in its place", () => {
  // report-contract.md section 5.3: a path that is not a sequence of Unicode scalar values is not
  // handed to the host. Node.js writes U+FFFD in place of a lone surrogate, so handing the path
  // over would read the sibling named with U+FFFD here, where the Python verifier reads the path
  // given.
  const dir = tempDir("lone-surrogate-path");
  try {
    Bundle.linkValid().seal().writeTo(join(dir, "t\uFFFD"));
    writeFileSync(join(dir, "e\uFFFD.json"), "{}");
    const got: Record<string, unknown> = {};
    for (const lone of ["\uD800", "\uDFFF", "\uDC80"]) {
      const report = verifyBundle(join(dir, `t${lone}`));
      got[lone.charCodeAt(0).toString(16)] = {
        status: report.status,
        errors: report.errors.map((e) => e.code),
        document: readDocumentPath(join(dir, `e${lone}.json`)),
      };
    }
    const nothing = { status: "HOST_FAILURE", errors: ["input_not_found"], document: DOCUMENT_PATH_NAMES_NOTHING };
    assert.deepEqual(got, { d800: nothing, dfff: nothing, dc80: nothing });
    // The sibling is there and is read by its own name: the rows above are about the path.
    assert.ok(!verifyBundle(join(dir, "t\uFFFD")).errors.some((e) => e.code === "input_not_found"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a link beside a name outside the rule reports the inventory failure and not the link, whatever is listed first", (t) => {
  // bundle-objects.md section 1: which entries a verifier meets before a refused listing depends on
  // the order it lists directories in, so a link met first is not reported; a link is judged only
  // over a complete inventory. The control row, a portable name, reports the link.
  const dir = tempDir("link-beside-name");
  const links: string[] = [];
  try {
    const outside = join(dir, "outside");
    mkdirSync(outside);
    const shapes: Record<string, [string, string]> = {
      "link-at-root": ["lnk", "z/a b.json"],
      "link-listed-after": ["z/lnk", "a/a b.json"],
      "link-listed-before": ["a/lnk", "z/a b.json"],
      "name-at-root": ["z/lnk", "a b.json"],
      "control-portable-name": ["lnk", "z/ab.json"],
    };
    const got: Record<string, string[]> = {};
    for (const [label, [link, name]] of Object.entries(shapes)) {
      const root = Bundle.linkValid().seal().writeTo(join(dir, label));
      mkdirSync(join(root, link, ".."), { recursive: true });
      mkdirSync(join(root, name, ".."), { recursive: true });
      try {
        symlinkSync(outside, join(root, link), process.platform === "win32" ? "junction" : "dir");
      } catch (err) {
        t.skip(`this host cannot make the link: ${String((err as Error).message)}`);
        return;
      }
      links.push(join(root, link));
      writeFileSync(join(root, name), "undeclared\n");
      got[label] = verifyBundle(root).errors.map((e) => e.code);
    }
    const alone = ["bundle_member_name_invalid"];
    assert.deepEqual(got, {
      "link-at-root": alone,
      "link-listed-after": alone,
      "link-listed-before": alone,
      "name-at-root": alone,
      "control-portable-name": ["unsafe_bundle_member"],
    });
  } finally {
    for (const link of links) rmSync(link, { force: true });
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a failed inventory masks a link and no other error", (t) => {
  // bundle-objects.md section 1: a failed inventory takes the place of unsafe_bundle_member only.
  // Every other row of report-contract.md section 5.3 is still judged on its own, so a manifest
  // that is not JSON beside a refused name is reported beside bundle_member_name_invalid.
  const dir = tempDir("inventory-masks-link-only");
  const links: string[] = [];
  try {
    const outside = join(dir, "outside");
    mkdirSync(outside);
    const got: Record<string, string[]> = {};
    for (const label of ["name-only", "name-and-link"]) {
      const root = Bundle.linkValid().seal().writeTo(join(dir, label));
      writeFileSync(join(root, "manifest.json"), "{");
      writeFileSync(join(root, "a b.json"), "undeclared\n");
      if (label === "name-and-link") {
        try {
          symlinkSync(outside, join(root, "lnk"), process.platform === "win32" ? "junction" : "dir");
        } catch (err) {
          t.skip(`this host cannot make the link: ${String((err as Error).message)}`);
          return;
        }
        links.push(join(root, "lnk"));
      }
      got[label] = verifyBundle(root).errors.map((e) => e.code);
    }
    const both = ["bundle_member_name_invalid", "manifest_verification_failed"];
    assert.deepEqual(got, { "name-only": both, "name-and-link": both });
  } finally {
    for (const link of links) rmSync(link, { force: true });
    rmSync(dir, { recursive: true, force: true });
  }
});
