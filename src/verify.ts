// Node convenience wrapper: verify a bundle directory on disk by delegating to
// the I/O-free core. This is the only module that touches node:fs, so it is
// excluded from the browser entry point (see index.browser.ts).
import { closeSync, fstatSync, lstatSync, openSync, readdirSync, readFileSync, readlinkSync, readSync, statSync } from "node:fs";
import { win32 } from "node:path";
import { parseJsonBytesStrict } from "./canonical.js";
import { hasLoneSurrogate, hasNoncharacter, rethrowHostStackFault } from "./json-strictness.js";
import {
  BundleReadError,
  conflictingNames,
  DOCUMENT_PATH_NAMES_NOTHING,
  DOCUMENT_NOT_STRICT_JSON,
  DOCUMENT_PATH_NAMES_NO_REGULAR_FILE,
  DOCUMENT_READ_FAILED,
  MAX_MEMBER_BYTES,
  memberNameValid,
  MemberUnreachedError,
  resolveOptions,
  verifyBundleWithContainment,
  type BundleReader,
  type Containment,
  type VerifyError,
  type VerifyOptions,
  type VerifyReport,
} from "./verify-core.js";

// A directory bundle is read without following anything (bundle-objects.md sections 1 and 5).
//
// A check on the resolved path string cannot see the filesystem: a junction or symbolic link
// inside the bundle pointing anywhere passes it, so a declared member could be read from outside
// the root, an undeclared link would be invisible, and Windows' own name aliasing (letter case, a
// trailing dot, `./`, a backslash, an alternate data stream after `:`, device names) would let one
// declared name reach a file stored under another.
//
// So the root is read through the path given (it may itself be reached through a link, and the
// path the host resolves it to is never handed back to the host); each listing of the bundle is
// judged by its names before any entry in it is inspected, the bundle is inventoried with lstat
// before anything is read, and a link anywhere in it fails the run; a declared name must be a
// portable member name and resolve segment by segment to entries
// whose names match exactly, none of them a link; a read is bounded at 20 MiB and checks that
// the file it opened is the file it inspected. What remains is the race between that check and
// the read (README, "Scope and limits"): verify bundles from a location no other process writes to.

interface Inventory {
  /** Root-relative POSIX names of everything under the root that is not a directory. */
  members: string[];
  /** A symbolic link, a junction or another reparse point was found somewhere under the root. */
  linkFound: boolean;
}

/** Why an inventory could not be taken: a name of a listing (content), or the host (bundle-objects.md section 1). */
type InventoryFailure = "names" | "host";

/**
 * A member's path: the root as it was given, the host separator, and the member's portable name
 * with its `/` read as that separator. Nothing is normalized (report-contract.md section 5.3): a
 * root `lnk/..` stays `lnk/..`, which path.join would fold lexically; on a POSIX host `lnk/..`
 * is the directory above the link's target, not the directory holding the link. The separator is
 * the host's unless given, so the rule is tested for both on any host; not exported from the
 * package.
 */
export function memberPath(root: string, rel: string, sep: "/" | "\\" = process.platform === "win32" ? "\\" : "/"): string {
  if (rel.length === 0) return root;
  const base = root.endsWith("/") || root.endsWith(sep) ? root : root + sep;
  return base + (sep === "/" ? rel : rel.split("/").join(sep));
}

/** The errno of a Node filesystem error, or null when the error carries none. */
function errorCode(err: unknown): string | null {
  return typeof err === "object" && err !== null && typeof (err as { code?: unknown }).code === "string" ? (err as { code: string }).code : null;
}

/**
 * The errors of a path at which nothing is found: no entry, a path component that is not a
 * directory, a link that resolves to nothing or to itself, or a path no entry can have because it
 * is longer than the host lets a path or a name be. Every other error is the host failing an
 * operation, which is never read as absence (report-contract.md section 5.3): a UNC server or
 * share that cannot be reached or does not exist (libuv UNKNOWN for ERROR_BAD_NETPATH and
 * ERROR_BAD_NET_NAME), a denied access, a sharing violation. ENAMETOOLONG is absence, as the
 * Python verifier finds nothing at such a path. On Windows, ENOENT where a link on the
 * path names an entry that is there is the host failing to follow the link (linkReachesAnEntry).
 */
const ABSENT_CODES = new Set(["ENOENT", "ENOTDIR", "ELOOP", "ENAMETOOLONG"]);

/**
 * Whether a Windows path's root is the named-pipe namespace, `\\.\pipe\` or `\\?\pipe\` in any
 * letter case (report-contract.md section 5.3): such a path names a named pipe, neither a directory
 * nor a regular file, and is classified from its name without inspecting or opening it, so a busy
 * pipe and one that refuses to open are classified as every other pipe is.
 */
function inPipeNamespace(path: string): boolean {
  if (process.platform !== "win32") return false;
  const p = path.replace(/\//g, "\\").toLowerCase();
  return p.startsWith("\\\\.\\pipe\\") || p.startsWith("\\\\?\\pipe\\");
}

/**
 * Whether a Windows UNC path names a server or share `.` or `..` (report-contract.md section 5.3,
 * step 1): those are names of the root as written, never folded, and such a path names nothing.
 * Node would read `\\?\UNC\..\C:\d` as `C:\d`.
 */
function uncRootFolds(path: string): boolean {
  if (process.platform !== "win32") return false;
  const p = path.replace(/\//g, "\\");
  // `\\.` and `\\?` alone are the device roots, not a share: the host reads them as `\\.\`.
  if (p === "\\\\." || p === "\\\\?") return false;
  let rest: string;
  if (/^\\\\\?\\UNC\\/i.test(p)) rest = p.slice(8);
  else if (p.startsWith("\\\\") && !p.startsWith("\\\\?\\") && !p.startsWith("\\\\.\\")) rest = p.slice(2);
  else return false;
  const [server, share] = rest.split("\\");
  return server === "." || server === ".." || share === "." || share === "..";
}

/**
 * On Windows, errors with which Node's stat meets a device rather than a file-system entry:
 * EISDIR is ERROR_INVALID_FUNCTION, a query the device does not support (the console, a volume
 * opened as a device), and EINVAL an access or a parameter it does not accept (the named-pipe
 * root). Something is there, and it is neither a directory nor a regular file.
 */
const DEVICE_CODES = new Set(["EISDIR", "EINVAL"]);

type EntryKind = "directory" | "file" | "other";

/**
 * A path as a Windows host reads it in the file namespace, step by step as report-contract.md
 * section 5.3 gives the reading; the empty path stays empty, and names nothing.
 *
 * Node's `path.win32.toNamespacedPath` is that reading, except in two forms it leaves to the Win32
 * layer, which still drops a trailing dot from each name and a trailing space from the last: a
 * path whose root is `\\.\`, and a share whose server's name begins with `.` or `?`. Both are read
 * in the file namespace here too, `\\?\` in place of the `\\.\` root and `\\?\UNC\` in place of
 * the share's `\\`. Otherwise `\\.\C:\d\b `, where only `b` exists, would reach `b`, though the
 * path as written names nothing, and `\\.\C:\d\b.` would not find `b.`.
 */
export function windowsReading(path: string, host: WorkingDirectories = PROCESS_DIRECTORIES): string {
  if (path.length === 0) return path;
  return inFileNamespace(win32.toNamespacedPath(againstDriveDirectory(path, host)));
}

/** The working directories a Windows host keeps: its own, and the one it keeps for a drive (`=D:`). */
export type WorkingDirectories = { cwd: () => string; driveCwd: (drive: string) => string | undefined };

const PROCESS_DIRECTORIES: WorkingDirectories = {
  cwd: () => process.cwd(),
  driveCwd: (drive) => process.env[`=${drive.toUpperCase()}`],
};

const DRIVE_RELATIVE = /^[A-Za-z]:(?![\\/])/;

/**
 * A path that begins with a drive letter and `:` and no separator, taken against the working
 * directory the host keeps for that drive, else against the working directory when it is on that
 * drive, else against that drive's root (report-contract.md section 5.3, step 1); any other path
 * as it is. Node's own reading keeps such a path relative when the working directory is a share,
 * and leaves it to the Win32 layer.
 */
function againstDriveDirectory(path: string, host: WorkingDirectories): string {
  if (!DRIVE_RELATIVE.test(path)) return path;
  const drive = path.slice(0, 2);
  const onDrive = (dir: string | undefined): dir is string =>
    typeof dir === "string" && dir.length > 2 && dir.slice(0, 2).toLowerCase() === drive.toLowerCase()
    && (dir[2] === "\\" || dir[2] === "/");
  const kept = host.driveCwd(drive);
  const cwd = host.cwd();
  const base = onDrive(kept) ? kept : onDrive(cwd) ? cwd : `${drive}\\`;
  // The drive keeps the spelling the path gives it; the directory supplies only the names below.
  return `${drive}${base.slice(2)}\\${path.slice(2)}`;
}

/** Node's reading of a path, with the two forms it leaves to the Win32 layer read in the file namespace. */
function inFileNamespace(namespaced: string): string {
  if (namespaced.startsWith("\\\\.\\")) return "\\\\?\\" + namespaced.slice(4);
  if (namespaced.startsWith("\\\\") && !namespaced.startsWith("\\\\?\\")) return "\\\\?\\UNC\\" + namespaced.slice(2);
  return namespaced;
}

/**
 * The string handed to Node's file system for a path the verifier is given, the input or a
 * document. Node reads every path through `path.win32.toNamespacedPath` itself, and a reading
 * read a second time can name something else: `\\?\C:\` is read as `\\?\C:`, the volume, not the
 * drive's root directory. So a path Node reads as the section does is handed over as it was
 * given, and only the two forms Node leaves to the Win32 layer are handed over as their reading,
 * which Node then reads unchanged (the bare `\\?\` aside, which names nothing either way).
 */
function hostPath(path: string): string {
  if (process.platform !== "win32" || path.length === 0) return path;
  const absolute = againstDriveDirectory(path, PROCESS_DIRECTORIES);
  const namespaced = win32.toNamespacedPath(absolute);
  const reading = inFileNamespace(namespaced);
  // A drive-relative path is handed over in its absolute form, which Node reads as the section
  // does; its reading could not be: Node reads `\\?\D:\` a second time as `\\?\D:`, the volume.
  return reading === namespaced ? absolute : reading;
}

/**
 * What a path names, links followed: a directory, a regular file, something else, or null when
 * nothing is found there. Any other failure of the host to inspect it is thrown.
 *
 * The path is the one hostPath gives, read in the file namespace as it is written
 * (report-contract.md section 5.3): on Windows no name loses a trailing dot or space, NUL in a
 * directory is an entry of that name, and a path longer than MAX_PATH is found. Node's stat asks a
 * device for no type, though, so on Windows two answers are corrected here: a named pipe is
 * reported as a regular file on no volume (device number 0), and the console and a volume opened as
 * a device fail with DEVICE_CODES. The Python verifier asks the host for the type and reads both as
 * neither a directory nor a regular file; so does this reader.
 */
function inspectPath(path: string): EntryKind | null {
  // A path holding a NUL can name no entry; Node refuses it as an invalid argument before the
  // host looks, which is not a host failure. A path holding a noncharacter finds nothing either
  // and is not handed to the host (report-contract.md section 5.3): Node.js on Windows stops the
  // process on a path holding U+10FFFF. So does a path holding a lone surrogate, which is no
  // sequence of Unicode scalar values: Node.js writes U+FFFD in its place and would read the
  // entry so named, where the Python verifier reads the one given.
  if (path.includes("\u0000") || hasNoncharacter(path) || hasLoneSurrogate(path)) return null;
  if (uncRootFolds(path)) return null;
  if (inPipeNamespace(path)) return "other";
  let st;
  try {
    st = statSync(path);
  } catch (err) {
    // Stack fault: the engine's error carries no code, so it is in neither set below and is thrown.
    const code = errorCode(err) ?? "";
    if (ABSENT_CODES.has(code)) {
      if (code === "ENOENT" && process.platform === "win32" && linkReachesAnEntry(path, 0)) throw err;
      return null;
    }
    if (process.platform === "win32" && DEVICE_CODES.has(code)) return "other";
    throw err;
  }
  if (st.isDirectory()) return "directory";
  if (st.isFile()) return process.platform === "win32" && st.dev === 0 ? "other" : "file";
  return "other";
}

/** The most links a Windows host follows on one path; beyond, it finds nothing (ELOOP). */
const MAX_LINK_HOPS = 63;

/**
 * On Windows, whether a path at which Node's stat meets ENOENT runs through a link whose target is
 * there. The host then failed to follow the link, which report-contract.md section 5.3 names a
 * host failure, not absence: a symbolic link to `\\.\nul` meets ERROR_INVALID_REPARSE_DATA. Node
 * reports ENOENT for that error, as for a link that resolves to nothing, and keeps no host error
 * number to tell them apart, where the Python verifier reads the number. So the deepest
 * entry on the path that is there is found; when it is a link that stat cannot follow, the entry
 * its target names is looked for in the same way, through at most MAX_LINK_HOPS links. Asked only
 * after ENOENT, so a path that is found costs nothing more.
 */
function linkReachesAnEntry(path: string, hops: number): boolean {
  if (hops > MAX_LINK_HOPS) return false;
  // A stack that runs out inside a host call is never read as the host's answer.
  const absent = (err: unknown): boolean => {
    rethrowHostStackFault(err);
    return ABSENT_CODES.has(errorCode(err) ?? "");
  };
  let at = path;
  for (;;) {
    let st;
    try {
      st = lstatSync(at);
    } catch (err) {
      if (!absent(err)) return true;
      const parent = win32.dirname(at);
      if (parent === at) return false;
      at = parent;
      continue;
    }
    // The deepest entry that is there is no link, or a link that stat follows: nothing is found
    // below it, and that is absence.
    if (!st.isSymbolicLink()) return false;
    try {
      statSync(at);
      return false;
    } catch (err) {
      if (!absent(err)) return true;
    }
    let target: string;
    try {
      target = readlinkSync(at);
    } catch (err) {
      return !absent(err);
    }
    // Node gives a target outside the drive and UNC forms in the NT spelling `\??\`.
    if (target.startsWith("\\??\\")) target = "\\\\?\\" + target.slice(4);
    const named = win32.isAbsolute(target) ? target : win32.resolve(win32.dirname(at), target);
    try {
      statSync(named);
      return true;
    } catch (err) {
      if (!absent(err)) return true;
      return errorCode(err) === "ENOENT" && linkReachesAnEntry(named, hops + 1);
    }
  }
}

// Entry names are read as bytes. Each listing is judged by its names before any entry in it is
// inspected (bundle-objects.md section 1): a name with a byte outside the portable set, an entry
// whose path from the root is not a portable member name, or two entries whose names conflict
// under ASCII case folding refuse the inventory, as in the Python verifier, and such an entry is
// never handed to the host. That covers a name that is not Unicode, which a string-named
// readdirSync lists under U+FFFD, and a name holding a noncharacter, on which Node.js on Windows
// stops the process.
const PORTABLE_BYTE = /^[A-Za-z0-9._-]$/;

function portableName(raw: Uint8Array): string | null {
  let name = "";
  for (const byte of raw) {
    const ch = String.fromCharCode(byte);
    if (!PORTABLE_BYTE.test(ch)) return null;
    name += ch;
  }
  return name;
}

/**
 * The bundle's inventory, or why it could not be taken. Every reparse point is a link here,
 * whatever its tag (bundle-objects.md section 1): on Windows a listing gives each entry the type
 * libuv reads from its attributes, and an entry carrying FILE_ATTRIBUTE_REPARSE_POINT (a symbolic
 * link, a junction, a cloud placeholder or any other tag) is listed as a link, before anything
 * inspects it; on POSIX a symbolic link is listed as one. A listing that holds a name outside the
 * portable member names, or two names that conflict, is `names` (bundle_member_name_invalid); a
 * host that fails to list a directory or to inspect an entry is `host` (bundle_inventory_failed).
 */
function takeInventory(root: string): Inventory | InventoryFailure {
  const members: string[] = [];
  let linkFound = false;
  const pending: string[] = [""];
  while (pending.length > 0) {
    const rel = pending.pop()!;
    const children: Array<{ child: string; link: boolean }> = [];
    let listing;
    try {
      listing = readdirSync(memberPath(root, rel), { encoding: "buffer", withFileTypes: true });
    } catch (err) {
      rethrowHostStackFault(err);
      return "host";
    }
    for (const entry of listing) {
      const name = portableName(entry.name as unknown as Uint8Array);
      if (name === null) return "names";
      const child = rel ? `${rel}/${name}` : name;
      if (!memberNameValid(child)) return "names";
      children.push({ child, link: entry.isSymbolicLink() });
    }
    if (conflictingNames(children.map(({ child }) => child)).size > 0) return "names";
    for (const { child, link } of children) {
      if (link) {
        linkFound = true;
        continue;
      }
      let st;
      try {
        st = lstatSync(memberPath(root, child));
      } catch (err) {
        rethrowHostStackFault(err);
        return "host";
      }
      if (st.isSymbolicLink()) linkFound = true;
      else if (st.isDirectory()) pending.push(child);
      else members.push(child);
    }
  }
  return { members: members.sort(), linkFound };
}

/**
 * The classes of report-contract.md section 5.3 a failed host operation on a member falls in, in
 * one place for the five catches of resolveMember and readBounded. A stack the host ran out of is
 * rethrown, never classified. Then, where `absence` is "maps-to-null", nothing found (ABSENT_CODES)
 * is null: the member is absent. Every other failure is thrown: a MemberUnreachedError when the
 * host failed before it found the member (listing a directory on the way, inspecting an entry),
 * which the presence flags do not record as seen, and a BundleReadError when it found the member
 * and failed to open or read it. A read that fails after the file was opened is never absence,
 * whatever its code ("is-a-read-failure"). The message is "the host cannot <verb> <path>: <code>".
 */
function hostFailure(err: unknown, verb: "list" | "inspect" | "open" | "read", path: string, kind: "unreached" | "read", absence: "is-a-read-failure"): never;
function hostFailure(err: unknown, verb: "list" | "inspect" | "open" | "read", path: string, kind: "unreached" | "read", absence: "maps-to-null"): null;
function hostFailure(err: unknown, verb: "list" | "inspect" | "open" | "read", path: string, kind: "unreached" | "read", absence: "maps-to-null" | "is-a-read-failure"): null {
  rethrowHostStackFault(err);
  if (absence === "maps-to-null" && ABSENT_CODES.has(errorCode(err) ?? "")) return null;
  const message = `the host cannot ${verb} ${path}: ${errorCode(err) ?? "error"}`;
  throw kind === "unreached" ? new MemberUnreachedError(message) : new BundleReadError(message);
}

/**
 * The path of a declared member, found by exact entry names and refusing any link on the way:
 * null when nothing is found there, and a BundleReadError when the host fails to list a directory
 * on the way or to inspect an entry, which the core reports as the reading layer's
 * `*_read_failed` error. A directory the host cannot list does not make its members absent: a
 * declared member inside it is reported as unread, not as missing.
 */
function resolveMember(root: string, name: string, listings: Map<string, ReadonlySet<string>>): string | null {
  if (!memberNameValid(name)) return null;
  let dir = root;
  const segments = name.split("/");
  for (let i = 0; i < segments.length; i++) {
    const segment = segments[i]!;
    // Each directory is listed once per run and held as a set, so reading every member of a
    // directory of n entries costs time linear in n, not n squared. A listing the host refused is
    // not kept, and is asked for again.
    let entries = listings.get(dir);
    if (entries === undefined) {
      try {
        // A reparse point of any tag is listed as a link, and is never a member.
        entries = new Set(readdirSync(dir, { withFileTypes: true }).filter((entry) => !entry.isSymbolicLink()).map((entry) => entry.name));
      } catch (err) {
        return hostFailure(err, "list", dir, "unreached", "maps-to-null");
      }
      listings.set(dir, entries);
    }
    // Exact code units: no case folding and no trailing-dot or short-name aliasing by the OS.
    if (!entries.has(segment)) return null;
    const path = memberPath(dir, segment);
    let st;
    try {
      st = lstatSync(path);
    } catch (err) {
      return hostFailure(err, "inspect", path, "unreached", "maps-to-null");
    }
    if (st.isSymbolicLink()) return null;
    if (i < segments.length - 1) {
      if (!st.isDirectory()) return null;
      dir = path;
    } else {
      return st.isFile() ? path : null;
    }
  }
  return null;
}

/**
 * The bytes of a regular file, bounded at MAX_MEMBER_BYTES: null when the entry is absent, not a
 * regular file or over the bound; a BundleReadError when the host refuses to open or read a file
 * that is there, which the core reports as the reading layer's `*_read_failed` error. A failure to
 * inspect it, here or on the way (resolveMember), is a MemberUnreachedError: the host did not
 * find the member, so the presence flags do not record it as seen.
 */
function readBounded(path: string): Uint8Array | null {
  let before;
  try {
    before = lstatSync(path, { bigint: true });
  } catch (err) {
    return hostFailure(err, "inspect", path, "unreached", "maps-to-null");
  }
  if (!before.isFile() || before.size > BigInt(MAX_MEMBER_BYTES)) return null;
  let fd: number;
  try {
    fd = openSync(path, "r");
  } catch (err) {
    return hostFailure(err, "open", path, "read", "maps-to-null");
  }
  try {
    const opened = fstatSync(fd, { bigint: true });
    // The file opened is the file inspected: same device and file id, still a regular file.
    if (!opened.isFile() || opened.dev !== before.dev || opened.ino !== before.ino) return null;
    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      const chunk = new Uint8Array(Math.min(1024 * 1024, MAX_MEMBER_BYTES + 1 - total));
      const n = readSync(fd, chunk, 0, chunk.length, null);
      if (n === 0) break;
      total += n;
      if (total > MAX_MEMBER_BYTES) return null;
      chunks.push(chunk.subarray(0, n));
    }
    const out = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      out.set(chunk, offset);
      offset += chunk.length;
    }
    return out;
  } catch (err) {
    return hostFailure(err, "read", path, "read", "is-a-read-failure");
  } finally {
    closeSync(fd);
  }
}

const lenientUtf8 = new TextDecoder();

function fsReader(root: string | null, inventory: Inventory | null): BundleReader {
  const listings = new Map<string, ReadonlySet<string>>();
  const readBytes = (name: string): Uint8Array | null => {
    if (root === null) return null;
    const path = resolveMember(root, name, listings);
    return path === null ? null : readBounded(path);
  };
  return {
    readBytes,
    listMembers: () => (inventory === null ? null : [...inventory.members]),
    readText(name: string): string | null {
      const bytes = readBytes(name);
      return bytes === null ? null : lenientUtf8.decode(bytes);
    },
  };
}

/**
 * Read a document supplied by path, as report-contract.md section 5.3 reads the path a run is
 * given, and return what to pass in the document's place (report-contract.md section 4, "A library
 * interface that takes documents"):
 *
 * - `DOCUMENT_PATH_NAMES_NOTHING` when nothing is found at the path, the path holding a NUL or
 *   being longer than the host allows included;
 * - `DOCUMENT_PATH_NAMES_NO_REGULAR_FILE` when what is found is not a regular file: a directory, a
 *   device, a named pipe;
 * - `DOCUMENT_READ_FAILED` when the host fails to inspect the path or to read the file;
 * - `DOCUMENT_NOT_STRICT_JSON` when the bytes are not UTF-8 or the text is not strict JSON
 *   (parseJsonStrict), a leading byte-order mark, nesting deeper than 64 levels whatever the stack,
 *   a number that is not finite or an integer beyond 2^53 - 1, a lone surrogate and a noncharacter
 *   included, as canonicalization-and-hashing.md section 6 refuses each;
 * - otherwise the parsed document.
 *
 * A stack the host runs out of while the path is inspected, read, decoded or parsed is none of
 * these: it is thrown, a fault of the host (report-contract.md section 4). Caught with the rest, a
 * valid document read with little stack left would come back as `DOCUMENT_NOT_STRICT_JSON` or
 * `DOCUMENT_READ_FAILED`, and a run given that value would fail. The same holds for every member
 * read, inventory and input inspection of `verifyBundle`.
 *
 * On Windows the path is read in the file namespace, as it is written, and a named pipe, which
 * Node's stat reports as a regular file, is none. A host that reads document paths itself takes
 * the steps of this package's README: a plain stat reads a pipe serving a valid document as a
 * regular file, and a path longer than any path as a failed read, where report-contract.md
 * section 5.3 finds, in turn, no regular file and nothing.
 */
export function readDocumentPath(path: string): unknown {
  const host = hostPath(path);
  let kind: EntryKind | null;
  try {
    kind = inspectPath(host);
  } catch (err) {
    rethrowHostStackFault(err);
    return DOCUMENT_READ_FAILED;
  }
  if (kind === null) return DOCUMENT_PATH_NAMES_NOTHING;
  if (kind !== "file") return DOCUMENT_PATH_NAMES_NO_REGULAR_FILE;
  let bytes: Uint8Array;
  try {
    bytes = readFileSync(host);
  } catch (err) {
    rethrowHostStackFault(err);
    return DOCUMENT_READ_FAILED;
  }
  // Decoded strictly (no BOM, fatal UTF-8) and parsed strictly; a refusal is DOCUMENT_NOT_STRICT_JSON,
  // which a literal `null` file, a document, is not.
  try {
    return parseJsonBytesStrict(bytes);
  } catch (err) {
    rethrowHostStackFault(err);
    return DOCUMENT_NOT_STRICT_JSON;
  }
}
/**
 * Verify a bundle directory. Provide registryEntry to request the link check, and trustRegistry
 * with evaluationTime to request the authorization check.
 *
 * The input is judged before any member is read (report-contract.md section 5.3): a path that
 * names nothing is `input_not_found`; an entry that is not a directory is `unsupported_input`,
 * a regular file included, because this verifier reads directory bundles and no archive; a
 * host that refuses to resolve, inspect or list the path is `filesystem_error`; a directory
 * whose listing has no entry named exactly manifest.json is `bundle_root_invalid`. Each refuses
 * the input as a whole. A member the host fails to reach, inspect or read is that layer's
 * `*_read_failed` error, never an absent member. A directory the host fails to list, or an entry
 * of a listing it fails to inspect, is `bundle_inventory_failed`; a listing that holds an entry
 * that is not a portable member name, or two entries whose names conflict, is
 * `bundle_member_name_invalid`; a link anywhere under the root is `unsafe_bundle_member`; each
 * fails the run, and the members are still read for the report.
 *
 * The registry entry, the trust registry and the trust-root document are taken as parsed values:
 * parse each with this package's strict parser, as UntrustedRegistryEntryInput says.
 */
export function verifyBundle(bundleRoot: string, opts: VerifyOptions = {}): VerifyReport {
  // Refused with an error of the host language before the input is so much as resolved.
  const resolved = resolveOptions(opts);
  const refused = (code: VerifyError["code"], message: string): VerifyReport =>
    verifyBundleWithContainment(fsReader(null, null), opts, { refusal: { code, message } }, resolved);
  // A path holding a NUL can name no entry: nothing is found there (report-contract.md section
  // 5.3). Node refuses it as an invalid argument before the host looks, which is not
  // filesystem_error.
  if (bundleRoot.includes("\u0000")) return refused("input_not_found", "the input path does not exist");
  // The input is inspected once, links followed, before it is resolved (report-contract.md section
  // 5.3): something that is there and is not a directory is unsupported_input, a device the host
  // will not resolve (\\.\nul on Windows) included, not filesystem_error. The
  // path is handed to the host as it was given: made absolute first, the empty path would name the
  // working directory, where the host finds nothing at it. On Windows it is read in the file
  // namespace, the two forms Node leaves to the Win32 layer included (windowsReading).
  const absolute = hostPath(bundleRoot);
  let inputKind: EntryKind | null;
  try {
    inputKind = inspectPath(absolute);
  } catch (err) {
    rethrowHostStackFault(err);
    return refused("filesystem_error", `the host refuses to inspect the input: ${errorCode(err) ?? "error"}`);
  }
  if (inputKind === null) return refused("input_not_found", "the input path does not exist");
  if (inputKind !== "directory") return refused("unsupported_input", "the input is not a directory bundle");
  // The root and its members are read through the path given (bundle-objects.md section 1): the
  // root may be reached through a link, and the path the host resolves it to is never handed back
  // to the host: Node.js on Windows stops the process when a resolved path handed to lstat or
  // readdir holds U+10FFFF, and a bundle under such a path is still verified.
  const root = absolute;
  // The root marker is found in the directory's own listing, by exact code units, not by an
  // lstat of root/manifest.json: on a host that ignores letter case that call finds MANIFEST.JSON
  // too. Listing the input is an operation on the input itself: a host that refuses it refuses
  // the input as a whole.
  let rootNames: string[];
  try {
    rootNames = readdirSync(root);
  } catch (err) {
    rethrowHostStackFault(err);
    return refused("filesystem_error", `the host refuses to list the input: ${errorCode(err) ?? "error"}`);
  }
  const manifestEntry = rootNames.includes("manifest.json");
  if (!manifestEntry) return refused("bundle_root_invalid", "the directory has no member named exactly manifest.json");
  const taken = takeInventory(root);
  // A link anywhere under the root, or a root that cannot be inventoried, means what the verifier
  // would read could not be shown to be what the directory contains.
  const errors: VerifyError[] = [];
  if (taken === "host") errors.push({ code: "bundle_inventory_failed", message: "the host fails to list a directory of the bundle or to inspect an entry of a listing" });
  else if (taken === "names") errors.push({ code: "bundle_member_name_invalid", message: "a listing holds a name that is not a portable member name, or two names that conflict" });
  else if (taken.linkFound) errors.push({ code: "unsafe_bundle_member", message: "the bundle directory holds a symbolic link, a junction or another reparse point" });
  const inventory = typeof taken === "string" ? null : taken;
  const containment: Containment = { errors, manifestEntry };
  return verifyBundleWithContainment(fsReader(root, inventory), opts, containment, resolved);
}

export {
  verifyBundleFiles,
  bundleReaderFromMap,
  STATUS_OFFLINE_OK,
  STATUS_OFFLINE_REVIEW,
  STATUS_OFFLINE_FAIL,
  STATUS_UNSUPPORTED_VERSION,
  STATUS_HOST_FAILURE,
  EXIT_OFFLINE_OK,
  EXIT_OFFLINE_FAIL,
  EXIT_OFFLINE_REVIEW,
  EXIT_INTERNAL_ERROR,
  EXIT_UNSUPPORTED_VERSION,
  EXIT_HOST_FAILURE,
} from "./verify-core.js";
export { AUTHORIZATION_STATUSES, BundleReadError, CHECK_NAMES, ERROR_CODES, REVIEW_REASONS, evaluateTrustRegistry } from "./verify-core.js";
export { DOCUMENT_NOT_STRICT_JSON, DOCUMENT_PATH_NAMES_NOTHING, DOCUMENT_PATH_NAMES_NO_REGULAR_FILE, DOCUMENT_READ_FAILED } from "./verify-core.js";
export type {
  AuthorizationStatus,
  BundleReader,
  CheckName,
  ErrorCode,
  ReportStatus,
  ReportVerdict,
  ReviewReason,
  TrustRegistryReport,
  VerifyError,
  VerifyOptions,
  VerifyReport,
} from "./verify-core.js";
export {
  TrustRootError,
  ROOT_SIGNING_DOMAIN_PREFIX,
  authenticateTrustRegistry,
  parseTrustRoots,
  trustRegistryRootSigningEnvelope,
  trustRegistrySigningMessageBytes,
} from "./trust-root.js";
export type { RootSignatureStatus, TrustRoot } from "./trust-root.js";
export { EvaluationTimeError } from "./evaluation-time.js";
export type { EvaluationTime } from "./evaluation-time.js";
export { REGISTERED_VOCABULARIES, REGISTERED_VOCABULARY_SHA256 } from "./registered-vocabularies.generated.js";
export { VOCABULARY_KINDS, VocabularyError } from "./vocabulary.js";
export type { VocabularyKind, VocabularyRecord, VocabularySource } from "./vocabulary.js";
