// A path is read as it is written (report-contract.md section 5.3), and readDocumentPath reads a
// document path as the Python verifier reads the path it is given (section 4).
//
// Node's file system reads a path in the file namespace, which section 5.3 gives step by step for
// Windows, except a path whose root is \\.\ and a share whose server's name begins with "." or "?",
// which it leaves to the Win32 layer. The first test holds the section's reading as this package
// takes it, and the second that Node's own is the same but for those two forms, so a Node that read
// a path otherwise would fail here rather than in a comparison with the other verifier. The rest
// hold what this package adds: the device prefix and the dotted server read as written; the empty
// path and a path longer than the host allows find nothing; on Windows a device that Node's stat
// cannot describe, and a named pipe that it reports as a regular file, are neither a directory nor
// a regular file; and readDocumentPath gives each of the four facts a host passes.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { spawn } from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import { join, parse, win32 } from "node:path";
import { Bundle, tempDir } from "./bundle-kit.ts";
import {
  DOCUMENT_NOT_STRICT_JSON,
  DOCUMENT_PATH_NAMES_NOTHING,
  DOCUMENT_PATH_NAMES_NO_REGULAR_FILE,
  DOCUMENT_READ_FAILED,
  readDocumentPath,
  verifyBundle,
  windowsReading,
} from "../src/verify.ts";
import type { WorkingDirectories } from "../src/verify.ts";

const WINDOWS = process.platform === "win32";

// The readings of loquitur-verify-py tests/test_path_reading.py that do not depend on the working
// directory: each path as section 5.3 reads it on Windows.
const READINGS: Array<[string, string]> = [
  ["C:\\data\\nul", "\\\\?\\C:\\data\\nul"],
  ["C:/data//x/./y/../z/", "\\\\?\\C:\\data\\x\\z"],
  ["C:\\", "\\\\?\\C:\\"],
  ["\\\\server\\share\\a\\..\\..\\b", "\\\\?\\UNC\\server\\share\\b"],
  ["\\\\server\\share", "\\\\?\\UNC\\server\\share\\"],
  ["\\\\?\\C:\\x\\..\\y", "\\\\?\\C:\\y"],
  ["\\\\?\\C:\\", "\\\\?\\C:"],
  ["\\\\.\\C:\\", "\\\\?\\C:"],
  ["\\\\.\\nul", "\\\\?\\nul"],
  ["\\\\.\\C:\\x\\..\\..\\y", "\\\\?\\y"],
  ["\\\\.\\C:\\d\\b ", "\\\\?\\C:\\d\\b "],
  ["\\\\.\\C:\\d\\b.", "\\\\?\\C:\\d\\b."],
  ["//./C:/d/./b ", "\\\\?\\C:\\d\\b "],
  ["\\\\.\\UNC\\server\\share\\x", "\\\\?\\UNC\\server\\share\\x"],
  ["\\\\.\\C:\\..\\..", "\\\\?\\"],
  ["\\\\.foo\\share\\x", "\\\\?\\UNC\\.foo\\share\\x"],
  ["\\\\?foo\\share\\x", "\\\\?\\UNC\\?foo\\share\\x"],
  ["//?/C:/x", "\\\\?\\C:\\x"],
  ["", ""],
];

test("a Windows path is read in the file namespace, as section 5.3 gives the reading", () => {
  for (const [path, reading] of READINGS) assert.equal(windowsReading(path), reading, path);
});

test("Node reads every path in the file namespace but a device-prefixed path and a dotted server's share", () => {
  // The two forms windowsReading reads where Node would leave them to the Win32 layer, which drops
  // a trailing dot from each name and a trailing space from the last; for every other path of the
  // table, Node's own reading is the section's.
  const leftToWin32 = (path: string) => /^[\\/][\\/][.?]/.test(path) && !/^[\\/][\\/]\?[\\/]/.test(path);
  for (const [path, reading] of READINGS) {
    if (leftToWin32(path)) {
      assert.notEqual(win32.toNamespacedPath(path), reading, path);
      // Handed to Node, the reading is read unchanged, but for the bare prefix, which names
      // nothing.
      if (reading !== "\\\\?\\") assert.equal(win32.toNamespacedPath(reading), reading, path);
    } else {
      assert.equal(win32.toNamespacedPath(path), reading, path);
    }
  }
});

test("a path Node reads as a drive's root is that directory, not the volume", { skip: WINDOWS ? false : "a Windows drive root" }, () => {
  // A path already in the file namespace is read a second time by Node: \\?\C:\ is read as \\?\C:,
  // the volume. Handing Node the reading of every path would make C:\, /\ and \\. the volume, a
  // device, unsupported_input, where they name the drive's root directory, which holds no
  // manifest.json.
  const drive = parse(process.cwd()).root.slice(0, 2);
  assert.equal(win32.toNamespacedPath("\\\\?\\" + drive + "\\"), "\\\\?\\" + drive);
  for (const root of [drive + "\\", "/\\", "\\\\.", drive + "/"]) {
    assert.deepEqual(errors(root), ["bundle_root_invalid"], root);
  }
});

test("a UNC server or share named . or .. names nothing; the host never folds it", { skip: WINDOWS ? false : "a Windows UNC path" }, () => {
  // Node reads \\?\UNC\..\C:\d as C:\d, a directory that exists here and holds a valid bundle:
  // handed to Node, each of these would verify it. Section 5.3 reads . and .. there as names of the
  // root, and no server or share has that name.
  const dir = tempDir("unc-dots");
  try {
    const bundle = Bundle.linkValid().seal().writeTo(join(dir, "bundle"));
    const rest = bundle.slice(0, 2) + "\\" + bundle.slice(3);
    for (const path of ["\\\\..\\" + rest, "\\\\?\\UNC\\..\\" + rest, "//../" + rest,
      "\\\\server\\..\\" + rest, "\\\\server\\.\\" + rest]) {
      const report = verifyBundle(path);
      assert.deepEqual([report.errors.map((e) => e.code), report.status, report.exit_code],
        [["input_not_found"], "HOST_FAILURE", 5], path);
    }
    assert.deepEqual(errors(bundle), [], "the bundle itself verifies");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

function errorsOf(report: { errors: Array<{ code: string }> }): string[] {
  return report.errors.map((e) => e.code);
}

function errors(input: string): string[] {
  return errorsOf(verifyBundle(input));
}

test("the empty input path names nothing", () => {
  // Made absolute first, the empty path would name the working directory, a directory with no
  // manifest.json in it: bundle_root_invalid, where the Python verifier finds nothing.
  assert.deepEqual(errors(""), ["input_not_found"]);
  assert.equal(readDocumentPath(""), DOCUMENT_PATH_NAMES_NOTHING);
});

test("a path longer than the host lets any path be finds nothing", () => {
  const dir = tempDir("path-reading");
  try {
    const long = join(dir, ...Array.from({ length: 200 }, () => "b".repeat(200)));
    assert.ok(long.length > 32767);
    // Node refuses it with ENAMETOOLONG, which is absence, not the host failing (filesystem_error).
    assert.deepEqual(errors(long), ["input_not_found"]);
    assert.equal(readDocumentPath(long), DOCUMENT_PATH_NAMES_NOTHING);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("a volume opened as a device is neither a directory nor a regular file", { skip: WINDOWS ? false : "a Windows device path" }, () => {
  // Node's stat of \\.\C: fails with EISDIR, the device refusing a query it does not support,
  // which is not the host failing (filesystem_error): the Python verifier asks the host
  // for the type and finds a block device.
  const volume = "\\\\.\\" + parse(process.cwd()).root.slice(0, 2);
  assert.deepEqual(errors(volume), ["unsupported_input"]);
  assert.equal(readDocumentPath(volume), DOCUMENT_PATH_NAMES_NO_REGULAR_FILE);
});

test("readDocumentPath gives the five facts a host passes in a document's place", () => {
  const dir = tempDir("path-reading");
  try {
    const write = (name: string, data: string | Uint8Array) => {
      const path = join(dir, name);
      fs.writeFileSync(path, data);
      return path;
    };
    const document = write("entry.json", '{"a": [1, 2]}');
    assert.deepEqual(readDocumentPath(document), { a: [1, 2] });
    assert.equal(readDocumentPath(join(dir, "absent.json")), DOCUMENT_PATH_NAMES_NOTHING);
    assert.equal(readDocumentPath(dir), DOCUMENT_PATH_NAMES_NO_REGULAR_FILE);
    assert.equal(readDocumentPath(join(dir, "entry\u0000.json")), DOCUMENT_PATH_NAMES_NOTHING);
    assert.equal(readDocumentPath(join(document, "x")), DOCUMENT_PATH_NAMES_NOTHING);
    assert.equal(readDocumentPath(write("twice.json", '{"a": 1, "a": 2}')), DOCUMENT_NOT_STRICT_JSON);
    assert.equal(readDocumentPath(write("bom.json", "\ufeff{}")), DOCUMENT_NOT_STRICT_JSON);
    assert.equal(readDocumentPath(write("latin1.json", new Uint8Array([0x7b, 0x22, 0xe9, 0x22, 0x3a, 0x31, 0x7d]))), DOCUMENT_NOT_STRICT_JSON);
    // A file that holds the JSON value null is a document, not a refusal of the bytes.
    assert.equal(readDocumentPath(write("null.json", "null")), null);
    const original = fs.readFileSync;
    let refused = 0;
    (fs as unknown as { readFileSync: unknown }).readFileSync = (path: unknown, ...rest: unknown[]) => {
      if (String(path) === document) {
        refused += 1;
        const err = new Error(`EACCES: permission denied, open '${document}'`) as NodeJS.ErrnoException;
        err.code = "EACCES";
        throw err;
      }
      return (original as (...a: unknown[]) => unknown)(path, ...rest);
    };
    syncBuiltinESMExports();
    try {
      assert.equal(readDocumentPath(document), DOCUMENT_READ_FAILED);
      assert.ok(refused > 0, "the host was never asked to read the document");
    } finally {
      (fs as unknown as { readFileSync: unknown }).readFileSync = original;
      syncBuiltinESMExports();
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("a document name the Win32 layer would rewrite is read as it is written", { skip: WINDOWS ? false : "the Win32 path layer exists on Windows only" }, () => {
  const dir = tempDir("path-reading");
  try {
    fs.writeFileSync("\\\\?\\" + join(dir, "entry.json."), '{"exact": true}');
    assert.deepEqual(readDocumentPath(join(dir, "entry.json.")), { exact: true });
    assert.equal(readDocumentPath(join(dir, "entry.json")), DOCUMENT_PATH_NAMES_NOTHING);
  } finally {
    fs.rmSync("\\\\?\\" + dir, { recursive: true, force: true });
  }
});

test("an input under the device prefix is read as it is written", { skip: WINDOWS ? false : "the Win32 path layer exists on Windows only" }, () => {
  // Node leaves a \\.\ path to the Win32 layer, which drops a trailing dot from each name and a
  // trailing space from the last: left to it, "plain " and "plain." would verify the directory
  // "plain", and "bundle." itself would not be found.
  const dir = tempDir("path-reading");
  try {
    const cases: Array<[string, string]> = [["bundle.", "bundle."], ["bundle ", "bundle "], ["plain", "plain "], ["plain", "plain."]];
    for (const [stored, written] of cases) {
      if (!fs.existsSync(join(dir, stored))) Bundle.linkValid().writeTo(join(dir, stored));
      const report = verifyBundle("\\\\.\\" + join(dir, written));
      if (stored === written) assert.deepEqual([report.status, errorsOf(report)], ["OFFLINE_OK", []], written);
      else assert.deepEqual(errorsOf(report), ["input_not_found"], written);
    }
  } finally {
    fs.rmSync("\\\\?\\" + dir, { recursive: true, force: true });
  }
});

test("a document under the device prefix is read as it is written", { skip: WINDOWS ? false : "the Win32 path layer exists on Windows only" }, () => {
  const dir = tempDir("path-reading");
  try {
    fs.writeFileSync("\\\\?\\" + join(dir, "entry.json."), '{"exact": true}');
    fs.writeFileSync(join(dir, "plain.json"), '{"plain": true}');
    assert.deepEqual(readDocumentPath("\\\\.\\" + join(dir, "entry.json.")), { exact: true });
    assert.deepEqual(readDocumentPath("\\\\.\\" + join(dir, "plain.json")), { plain: true });
    assert.equal(readDocumentPath("\\\\.\\" + join(dir, "plain.json ")), DOCUMENT_PATH_NAMES_NOTHING);
    assert.equal(readDocumentPath("\\\\.\\" + join(dir, "plain.json.")), DOCUMENT_PATH_NAMES_NOTHING);
  } finally {
    fs.rmSync("\\\\?\\" + dir, { recursive: true, force: true });
  }
});

test("a device prefix with no name below it names nothing", { skip: WINDOWS ? false : "a Windows device path" }, () => {
  const bare = "\\\\.\\" + parse(process.cwd()).root.slice(0, 2) + "\\..\\..";
  assert.equal(windowsReading(bare), "\\\\?\\");
  assert.deepEqual(errors(bare), ["input_not_found"]);
  assert.equal(readDocumentPath(bare), DOCUMENT_PATH_NAMES_NOTHING);
});

test("a named pipe serving a valid document names no regular file", { skip: WINDOWS ? false : "a Windows named pipe" }, async () => {
  // Node's stat reports a named pipe as a regular file on no volume (device number 0). A host
  // reading with a plain stat would read the pipe as the document it serves; the Python verifier
  // verifier asks the host for the type and finds a pipe.
  const pipe = `\\\\.\\pipe\\loquitur-verify-ts-test-${process.pid}`;
  const server = spawn(
    process.execPath,
    ["-e", `require("node:net").createServer((s) => s.end('{"a": 1}')).listen(${JSON.stringify(pipe)}, () => console.log("ready"));`],
    { stdio: ["ignore", "pipe", "inherit"] },
  );
  try {
    await new Promise<void>((resolve, reject) => {
      server.stdout!.on("data", (chunk: Buffer) => { if (chunk.toString().includes("ready")) resolve(); });
      server.on("exit", (code) => reject(new Error(`the pipe server exited with ${code}`)));
    });
    assert.equal(fs.statSync(pipe).isFile(), true, "Node's stat does not call a named pipe a regular file on this host");
    assert.equal(readDocumentPath(pipe), DOCUMENT_PATH_NAMES_NO_REGULAR_FILE);
  } finally {
    server.kill();
  }
});

test("a path in the named-pipe namespace is classified from its name, never inspected", { skip: WINDOWS ? false : "a Windows named pipe" }, () => {
  // report-contract.md section 5.3: a path whose root is \\.\pipe\ or \\?\pipe\, in any letter
  // case, names a named pipe, neither a directory nor a regular file. A pipe that does not exist,
  // or is busy, would otherwise be ENOENT or EBUSY: input_not_found, or a host failure.
  const name = `loquitur-verify-ts-absent-${process.pid}`;
  for (const pipe of ["\\\\.\\pipe\\" + name, "\\\\?\\pipe\\" + name, "\\\\.\\PIPE\\" + name, "//./pipe/" + name]) {
    const report = verifyBundle(pipe);
    assert.deepEqual([report.status, report.errors.map((e) => e.code)], ["OFFLINE_FAIL", ["unsupported_input"]], pipe);
    assert.equal(readDocumentPath(pipe), DOCUMENT_PATH_NAMES_NO_REGULAR_FILE, pipe);
  }
});

// report-contract.md section 5.3, step 1: a path that begins with a drive letter and ":" and no
// separator is taken against the working directory the host keeps for that drive, else against
// the working directory when it is on that drive, else against the drive's root. Node's own
// reading keeps such a path relative when the working directory is a share.
const SHARE_CWD = "\\\\server\\share\\work";
const DRIVE_RELATIVE_READINGS: Array<[string, string, string | undefined, string]> = [
  // [path, working directory, directory kept for the drive, reading]
  ["D:x", SHARE_CWD, undefined, "\\\\?\\D:\\x"],
  ["D:", SHARE_CWD, undefined, "\\\\?\\D:\\"],
  ["D:x\\..\\..\\y", SHARE_CWD, undefined, "\\\\?\\D:\\y"],
  ["D:x", SHARE_CWD, "D:\\kept", "\\\\?\\D:\\kept\\x"],
  ["D:x", "C:\\work", "C:\\elsewhere", "\\\\?\\D:\\x"],
  ["D:x", "D:\\work", undefined, "\\\\?\\D:\\work\\x"],
  ["d:x", "D:\\work", undefined, "\\\\?\\d:\\work\\x"],
  ["D:x", "D:\\work", "D:\\kept", "\\\\?\\D:\\kept\\x"],
  ["D:..\\..\\x", "D:\\a", undefined, "\\\\?\\D:\\x"],
  ["D:\\x", SHARE_CWD, "D:\\kept", "\\\\?\\D:\\x"],
  ["D:/x", SHARE_CWD, "D:\\kept", "\\\\?\\D:\\x"],
];

test("a drive-relative path is taken against the drive's directory, else the drive's root", () => {
  for (const [path, cwd, kept, reading] of DRIVE_RELATIVE_READINGS) {
    const host: WorkingDirectories = { cwd: () => cwd, driveCwd: (drive) => (drive.toUpperCase() === "D:" ? kept : undefined) };
    assert.equal(windowsReading(path, host), reading, `${path} under ${cwd}, kept ${kept}`);
  }
});

test("a drive-relative input under a share as working directory is read from the drive's root", { skip: WINDOWS ? false : "a Windows drive-relative path" }, (t) => {
  // Left to the Win32 layer, the drive-relative path would lose the trailing dot of its last name:
  // "plain." would verify the directory "plain", and "bundle." itself would not be found.
  const dir = tempDir("path-reading");
  const drive = dir.slice(0, 2);
  const keptName = `=${drive.toUpperCase()}`;
  const kept = process.env[keptName];
  const saved = process.cwd();
  try {
    Bundle.linkValid().writeTo("\\\\?\\" + join(dir, "bundle."));
    Bundle.linkValid().writeTo(join(dir, "plain"));
    try {
      process.chdir(`\\\\localhost\\${drive[0]}$\\`);
    } catch {
      t.skip("this host offers no administrative share to take as the working directory");
      return;
    }
    delete process.env[keptName];
    const relative = (name: string) => `${drive}${dir.slice(3)}\\${name}`;
    assert.equal(windowsReading(relative("bundle.")), "\\\\?\\" + join(dir, "bundle."));
    const report = verifyBundle(relative("bundle."));
    assert.deepEqual([report.status, errorsOf(report)], ["OFFLINE_OK", []]);
    assert.deepEqual(errors(relative("plain.")), ["input_not_found"]);
    assert.equal(verifyBundle(relative("plain")).status, "OFFLINE_OK");
  } finally {
    process.chdir(saved);
    if (kept !== undefined) process.env[keptName] = kept;
    fs.rmSync("\\\\?\\" + dir, { recursive: true, force: true });
  }
});
