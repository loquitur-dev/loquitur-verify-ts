// Host states the corpus cannot carry and a Windows host can stage, held here in this package's
// own suite (report-contract.md section 5.3; bundle-objects.md section 1):
//
// - a member carrying a reparse tag that is not a symbolic link (the WSL symlink tag here) is a
//   link like any other reparse point: unsafe_bundle_member, whether it sits at the root or below;
// - a named pipe that is busy (its one instance taken) or that nobody may open (an empty DACL) is
//   neither a directory nor a regular file, classified from its name without opening it: as the
//   input, unsupported_input; as a document, no regular file, so a registry entry read from it fails
//   the link.
//
// The states are made through the Win32 API from a Python helper (ctypes, standard library only),
// which holds the pipes open while the verifier reads them. Elsewhere, or with no Python, the tests
// skip and say why.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { Bundle, tempDir } from "./bundle-kit.ts";
import { DOCUMENT_PATH_NAMES_NO_REGULAR_FILE, readDocumentPath, verifyBundle, type VerifyReport } from "../src/verify.ts";

const HELPER = String.raw`
import ctypes, ctypes.wintypes as wt, json, struct, sys
k = ctypes.WinDLL("kernel32", use_last_error=True)
adv = ctypes.WinDLL("advapi32", use_last_error=True)
k.CreateFileW.restype = wt.HANDLE
k.CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, wt.LPVOID, wt.DWORD, wt.DWORD, wt.HANDLE]
k.DeviceIoControl.argtypes = [wt.HANDLE, wt.DWORD, wt.LPVOID, wt.DWORD, wt.LPVOID, wt.DWORD, ctypes.POINTER(wt.DWORD), wt.LPVOID]
k.CreateNamedPipeW.restype = wt.HANDLE
k.CreateNamedPipeW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, wt.DWORD, wt.DWORD, wt.DWORD, wt.DWORD, wt.LPVOID]
k.CloseHandle.argtypes = [wt.HANDLE]
INVALID = wt.HANDLE(-1).value
if sys.argv[1] == "reparse":
    # FSCTL_SET_REPARSE_POINT with IO_REPARSE_TAG_LX_SYMLINK: a reparse point that is not a
    # Windows symbolic link and not a junction.
    h = k.CreateFileW(sys.argv[2], 0x40000000, 0, None, 3, 0x00200000, None)
    data = (2).to_bytes(4, "little") + b"x.json"
    buf = struct.pack("<IHH", 0xA000001D, len(data), 0) + data
    done = wt.DWORD(0)
    ok = h != INVALID and k.DeviceIoControl(h, 0x000900A4, buf, len(buf), None, 0, ctypes.byref(done), None)
    error = ctypes.get_last_error()
    if h != INVALID:
        k.CloseHandle(h)
    print(json.dumps({"ok": bool(ok), "error": error}))
else:
    busy, denied = sys.argv[2], sys.argv[3]
    # One instance, taken by a client of this process: every further open is ERROR_PIPE_BUSY.
    server = k.CreateNamedPipeW(busy, 0x3, 0, 1, 4096, 4096, 0, None)
    client = k.CreateFileW(busy, 0x80000000, 0, None, 3, 0, None)
    # An empty DACL: no one may open it.
    sd = ctypes.c_void_p()
    adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [wt.LPCWSTR, wt.DWORD, ctypes.POINTER(ctypes.c_void_p), wt.LPVOID]
    made = adv.ConvertStringSecurityDescriptorToSecurityDescriptorW("D:", 1, ctypes.byref(sd), None)
    class SA(ctypes.Structure):
        _fields_ = [("nLength", wt.DWORD), ("lpSecurityDescriptor", ctypes.c_void_p), ("bInheritHandle", wt.BOOL)]
    sa = SA(ctypes.sizeof(SA), sd, False)
    closed = k.CreateNamedPipeW(denied, 0x3, 0, 255, 4096, 4096, 0, ctypes.byref(sa))
    print(json.dumps({"ok": server != INVALID and client != INVALID and bool(made) and closed != INVALID}), flush=True)
    sys.stdin.read()
`;

function findPython(): string | null {
  for (const candidate of [process.env.LOQUITUR_PYTHON, "python", "python3"].filter((c): c is string => Boolean(c))) {
    const run = spawnSync(candidate, ["-c", "import ctypes"], { encoding: "utf8" });
    if (run.status === 0) return candidate;
  }
  return null;
}

const PYTHON = process.platform === "win32" ? findPython() : null;
const SKIP = process.platform !== "win32"
  ? "reparse tags and named pipes of this kind are Windows host states"
  : PYTHON === null ? "no Python with ctypes on this host (LOQUITUR_PYTHON, python, python3) to stage the host state" : false;

function surface(report: VerifyReport): Record<string, unknown> {
  return { status: report.status, reason: report.outcome.reason, errors: report.errors.map((e) => e.code) };
}

test("a member carrying a reparse tag that is not a symbolic link is an unsafe member", { skip: SKIP }, (t) => {
  const dir = tempDir("reparse");
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  for (const [label, rel] of [["at the root", "rp.txt"], ["below the root", "sub/rp.txt"]] as const) {
    const root = Bundle.linkValid().seal().writeTo(join(dir, label.replace(/ /g, "-")));
    if (rel.includes("/")) mkdirSync(join(root, "sub"));
    const path = join(root, ...rel.split("/"));
    writeFileSync(path, "");
    const set = spawnSync(PYTHON!, ["-c", HELPER, "reparse", path], { encoding: "utf8" });
    const answer = JSON.parse(set.stdout || "{}") as { ok?: boolean; error?: number };
    if (answer.ok !== true) {
      t.skip(`this filesystem refused the reparse tag (Win32 error ${answer.error ?? set.stderr})`);
      return;
    }
    assert.deepEqual(surface(verifyBundle(root)), { status: "OFFLINE_FAIL", reason: "unsafe_bundle_member", errors: ["unsafe_bundle_member"] }, label);
  }
});

test("a busy named pipe and one nobody may open are neither a directory nor a regular file", { skip: SKIP }, async (t) => {
  const tag = `${process.pid}-${randomBytes(4).toString("hex")}`;
  const busy = `\\\\.\\pipe\\loquitur-verify-ts-busy-${tag}`;
  const denied = `\\\\.\\pipe\\loquitur-verify-ts-denied-${tag}`;
  const holder = spawn(PYTHON!, ["-c", HELPER, "pipes", busy, denied], { stdio: ["pipe", "pipe", "inherit"] });
  try {
    const lines = createInterface({ input: holder.stdout! });
    const first = await new Promise<string>((resolve, reject) => {
      lines.once("line", resolve);
      holder.once("exit", (code) => reject(new Error(`the pipe holder exited with ${code}`)));
    });
    assert.deepEqual(JSON.parse(first), { ok: true }, "the pipes are staged");
    const dir = tempDir("pipes");
    t.after(() => rmSync(dir, { recursive: true, force: true }));
    const root = Bundle.linkValid().seal().writeTo(join(dir, "bundle"));
    for (const pipe of [busy, denied]) {
      assert.deepEqual(surface(verifyBundle(pipe)), { status: "OFFLINE_FAIL", reason: "unsupported_input", errors: ["unsupported_input"] }, pipe);
      const document = readDocumentPath(pipe);
      assert.equal(document, DOCUMENT_PATH_NAMES_NO_REGULAR_FILE, pipe);
      assert.deepEqual(surface(verifyBundle(root, { registryEntry: document })),
        { status: "OFFLINE_FAIL", reason: "registry_link_verification_failed", errors: ["registry_link_verification_failed"] }, pipe);
    }
  } finally {
    holder.stdin!.end();
    if (holder.exitCode === null && holder.signalCode === null) await new Promise((resolve) => holder.once("exit", resolve));
  }
});

// bundle-objects.md section 1: a member is a file's default data stream. An alternate data stream
// beside a member is not a member: it is neither verified nor reported, so a valid bundle whose
// p1.json carries a 100000-byte stream named `hidden` still passes, with no undeclared member.
test("an alternate data stream beside a member is not a member", { skip: process.platform === "win32" ? false : "alternate data streams are an NTFS state of a Windows host" }, (t) => {
  const dir = tempDir("ads");
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const root = Bundle.linkValid().seal().writeTo(join(dir, "bundle"));
  try {
    writeFileSync(join(root, "p1.json") + ":hidden", "x".repeat(100000));
  } catch (err) {
    t.skip(`this filesystem refused an alternate data stream (${(err as NodeJS.ErrnoException).code})`);
    return;
  }
  const report = verifyBundle(root);
  assert.deepEqual(surface(report), { status: "OFFLINE_OK", reason: "local_integrity_checks_passed", errors: [] });
  assert.deepEqual(report.review_reasons, []);
});
