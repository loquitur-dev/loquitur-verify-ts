// I/O-free verification core. Every filesystem touch is behind a single
// abstraction, BundleReader.readText(name), so the exact same verification
// logic runs in Node (fs-backed reader) and in a browser (in-memory map). No
// node:* imports here, so this module bundles for the browser unchanged.
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex } from "@noble/hashes/utils";
import { CanonicalizationError, JsonParseError, canonicalJsonBytes, parseJsonBytesStrict, parseJsonStrict } from "./canonical.js";
import { verifyRegistryEntrySignature } from "./signature.js";
import { sharesPoint } from "./key-point.js";
import { REASON_CODE_VOCABULARY } from "./reason-code-severity.generated.js";
import { parseRegistryEntry, parseTrustRegistry } from "./protocol-input.js";
import { receiptContractErrors } from "./receipt-contract.js";
import { nonBlankString } from "./whitespace.js";
import { defineJsonMember } from "./json-member.js";
import { isPlainObject, jsonTextTooDeep, jsonValueViolatesStrictness } from "./json-strictness.js";
import { TrustRootError, authenticateTrustRegistry, parseTrustRoots, trustRootDocumentUnsupportedVersion, type TrustRoot } from "./trust-root.js";
import { operatorEvaluationTime, type EvaluationTime } from "./evaluation-time.js";
import {
  VOCABULARY_KINDS,
  VocabularyError,
  embeddedVocabulary,
  operatorVocabulary,
  vocabulariesRecord,
  vocabularyValueStatus,
  type HeldVocabularies,
  type HeldVocabulary,
  type VocabularyKind,
  type VocabularyRecord,
} from "./vocabulary.js";
import type { ProtocolParseResult, UntrustedRegistryEntryInput, UntrustedTrustRegistryInput, ValidatedRegistryEntry } from "./types.js";

export const STATUS_OFFLINE_OK = "OFFLINE_OK";
export const STATUS_OFFLINE_REVIEW = "OFFLINE_REVIEW";
export const STATUS_OFFLINE_FAIL = "OFFLINE_FAIL";
export const STATUS_UNSUPPORTED_VERSION = "UNSUPPORTED_VERSION";
export const STATUS_HOST_FAILURE = "HOST_FAILURE";
/** The statuses of report-contract.md section 3.1; the set may grow in a minor version. */
export type ReportStatus =
  | typeof STATUS_OFFLINE_OK
  | typeof STATUS_OFFLINE_REVIEW
  | typeof STATUS_OFFLINE_FAIL
  | typeof STATUS_UNSUPPORTED_VERSION
  | typeof STATUS_HOST_FAILURE;
/** The verdict of an evidence status; a status that is not an evidence outcome has none. */
export type ReportVerdict = "PASS" | "REVIEW" | "FAIL";
// The outcome table of report-contract.md section 3.1: three evidence outcomes and the outcomes
// that are not evidence, each with its own exit code. A library interface raises its own faults
// instead of reporting INTERNAL_ERROR (3), kept here so the numbering stays the table's. It has no
// usage error: exit 64 is the command line's (report-contract.md section 4).
export const EXIT_OFFLINE_OK = 0;
export const EXIT_OFFLINE_FAIL = 1;
export const EXIT_OFFLINE_REVIEW = 2;
export const EXIT_INTERNAL_ERROR = 3;
export const EXIT_UNSUPPORTED_VERSION = 4;
export const EXIT_HOST_FAILURE = 5;

/**
 * What a host passes in place of a document when what is found at the path it was given for that
 * document is not a regular file: a directory or another kind of entry. When nothing is found there
 * it passes DOCUMENT_PATH_NAMES_NOTHING.
 *
 * The specification takes the registry entry, the trust registry and the trust roots as paths, and
 * report-contract.md section 5.3 gives a registry entry whose path names no regular file errors of
 * its own. This library takes documents, not paths, so the host that holds the path says what it
 * found there. A file whose bytes are not strict JSON is passed as DOCUMENT_NOT_STRICT_JSON, and a
 * document that is not an object as itself, a different fact with different errors. A symbol is a
 * value JSON cannot produce, so it is never read as a document.
 */
export const DOCUMENT_PATH_NAMES_NO_REGULAR_FILE: unique symbol = Symbol.for("loquitur.verify.document-path-names-no-regular-file");

/**
 * What a host passes in place of a document when nothing is found at the path it was given for
 * that document (report-contract.md section 5.3, "Nothing found"): no entry, a component that is
 * not a directory, a link that resolves to nothing, a path holding a NUL, a noncharacter or a lone
 * surrogate, or longer than the host allows. For the registry entry and the trust registry the
 * run is refused as a whole, `input_not_found`, HOST_FAILURE, exit 5, as for a bundle path that
 * names nothing (report-contract.md section 5.3), whatever else is supplied; for the trust roots it
 * is refused with a TrustRootError, as DOCUMENT_PATH_NAMES_NO_REGULAR_FILE is. Something found
 * that is not a regular file is DOCUMENT_PATH_NAMES_NO_REGULAR_FILE.
 */
export const DOCUMENT_PATH_NAMES_NOTHING: unique symbol = Symbol.for("loquitur.verify.document-path-names-nothing");

/**
 * What a host passes in place of a document when the path names a regular file and the host fails
 * to read it: a host failure, never a finding about the document (report-contract.md section 5.3).
 * For the registry entry that is `registry_link_read_failed`; for the trust registry, where the run
 * reads it, `trust_registry_read_failed`, and the registry is not evaluated; for the trust roots,
 * beside a trust registry and a registry entry, `trust_root_read_failed`, and root authentication
 * is not evaluated. Each makes the run HOST_FAILURE, exit 5, unless something else fails.
 */
export const DOCUMENT_READ_FAILED: unique symbol = Symbol.for("loquitur.verify.document-read-failed");

/**
 * What a host passes in place of a document when it read the file and the bytes are not strict
 * JSON: not UTF-8, a leading byte-order mark, or text the strict parser refuses (a lone surrogate
 * and a noncharacter included). It is a finding about the document, as a document that is not an
 * object is: a registry entry is `registry_link_verification_failed`, a trust registry is not
 * established, and the trust roots and a vocabulary are refused, each saying the document is not
 * strict JSON. `null` is still read as the document `null`, which is not an object, so a host
 * that passes it for such bytes gets the same report and a refusal that names an object instead.
 */
export const DOCUMENT_NOT_STRICT_JSON: unique symbol = Symbol.for("loquitur.verify.document-not-strict-json");

/**
 * A document of VerifyOptions as the host supplied it, told apart once where the core first reads
 * it: not supplied (`undefined`, and nothing else), a path at which nothing is found, a path that
 * names no regular file, a file the host failed to read, bytes that are not strict JSON, or a
 * document. `null` is a document, not an object, refused as such. Only documentInput compares a
 * value with the host's symbols.
 */
type DocumentInput =
  | { readonly kind: "absent" }
  | { readonly kind: "nothing-found" }
  | { readonly kind: "no-regular-file" }
  | { readonly kind: "read-failed" }
  | { readonly kind: "not-strict-json" }
  | { readonly kind: "document"; readonly value: unknown };

function documentInput(value: unknown): DocumentInput {
  if (value === undefined) return { kind: "absent" };
  if (value === DOCUMENT_PATH_NAMES_NOTHING) return { kind: "nothing-found" };
  if (value === DOCUMENT_PATH_NAMES_NO_REGULAR_FILE) return { kind: "no-regular-file" };
  if (value === DOCUMENT_READ_FAILED) return { kind: "read-failed" };
  if (value === DOCUMENT_NOT_STRICT_JSON) return { kind: "not-strict-json" };
  return { kind: "document", value };
}
const EXIT: Record<string, number> = {
  OFFLINE_OK: EXIT_OFFLINE_OK,
  OFFLINE_FAIL: EXIT_OFFLINE_FAIL,
  OFFLINE_REVIEW: EXIT_OFFLINE_REVIEW,
  UNSUPPORTED_VERSION: EXIT_UNSUPPORTED_VERSION,
  HOST_FAILURE: EXIT_HOST_FAILURE,
};

type Json = any;
const HEX64 = /^[0-9a-f]{64}$/;
/** A digest inside a JSON document: self-describing, `sha256:` and 64 lowercase hexadecimal characters (canonicalization-and-hashing.md section 2). */
const DIGEST = /^sha256:[0-9a-f]{64}$/;
/** The self-describing form of a bare SHA-256 hex digest, or null for null. */
function prefixed(hex: string | null): string | null {
  return hex === null ? null : `sha256:${hex}`;
}

/**
 * What the verifier needs from a bundle: a member's text or exact bytes by name, or null when
 * the member is absent.
 */
export interface BundleReader {
  readText(name: string): string | null;
  /**
   * Read a member's exact bytes, or null if absent.
   *
   * JSON members are decoded strictly from these bytes (UTF-8 with fatal errors, BOM kept), and
   * digests are taken over them. Optional for source compatibility, but a reader that omits it
   * hands over text its host has already decoded: invalid UTF-8 in that text was replaced before
   * the verifier saw it and cannot be detected, and a member that is not UTF-8 text (a scan, a
   * PDF) cannot be hashed faithfully. Readers backed by a filesystem must implement it.
   */
  readBytes?(name: string): Uint8Array | null;
  /**
   * Every member of the bundle, as root-relative names with `/` separators, directories not
   * included; or null when the reader cannot enumerate.
   *
   * Completeness is part of verification (bundle-objects.md): a file the manifest does not declare
   * makes the run REVIEW. A reader that omits this, or returns null, cannot show that nothing
   * undeclared is there, and the run is capped at REVIEW. The filesystem and in-memory readers
   * implement it.
   */
  listMembers?(): string[] | null;
}

/**
 * Thrown by a reader when the host fails to read a member that exists: a permission refused, a
 * device error. It is neither the member's absence (null) nor its content. The layer that was
 * reading reports its `*_read_failed` error (report-contract.md section 5.3) and computes nothing
 * from that member.
 */
export class BundleReadError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BundleReadError";
  }
}

/**
 * A BundleReadError raised before the host found the member: it failed to list a directory on
 * the way or to inspect an entry. The member is unread, as for any BundleReadError, and it was
 * also not seen, so a presence flag does not record it (bundle-objects.md section 6), as the
 * Python verifier does not. Not exported from the package.
 */
export class MemberUnreachedError extends BundleReadError {
  constructor(message: string) {
    super(message);
    this.name = "MemberUnreachedError";
  }
}

const lenientUtf8 = new TextDecoder();

/**
 * Build a reader over an in-memory { filename: contents } map (browser use).
 *
 * Pass each member's bytes as a Uint8Array to get the refusal the Node reader gives: invalid
 * UTF-8 in a JSON member is then detected, and binary members hash as they are. A string value
 * is text the host already decoded, and whatever that decoding replaced cannot be seen. Values
 * are recognized with ArrayBuffer.isView, so a Uint8Array from another realm (an iframe, a
 * worker's transfer, node:vm) is bytes too. Build the map with JSON.parse or
 * Object.defineProperty: assigning `files[name] = value` cannot create a member named __proto__.
 */
export function bundleReaderFromMap(files: Record<string, string | Uint8Array>): BundleReader {
  const valueOf = (name: string): unknown => (Object.prototype.hasOwnProperty.call(files, name) ? files[name] : undefined);
  return {
    listMembers() {
      return Object.keys(files).filter((name) => {
        const value = valueOf(name);
        return typeof value === "string" || ArrayBuffer.isView(value);
      });
    },
    readText(name) {
      const value = valueOf(name);
      if (typeof value === "string") return value;
      if (ArrayBuffer.isView(value)) return lenientUtf8.decode(new Uint8Array(value.buffer, value.byteOffset, value.byteLength));
      return null;
    },
    readBytes(name) {
      const value = valueOf(name);
      if (typeof value === "string") return enc.encode(value);
      if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
      return null;
    },
  };
}

function sha256Hex(bytes: Uint8Array): string { return bytesToHex(sha256(bytes)); }
function canonicalSha256Hex(value: Json): string { return sha256Hex(canonicalJsonBytes(value)); }
const hasOwn = (o: object, k: string) => Object.prototype.hasOwnProperty.call(o, k);

/**
 * A sidecar's digest (bundle-objects.md): the file is exactly 64 lowercase hexadecimal
 * characters and no other byte, not even a newline. Nothing is trimmed or lower-cased; a file
 * that is present but not of that form has no digest (`digest: null`), and its check fails.
 */
function readSidecar(r: BundleReader, name: string): { present: boolean; digest: string | null } {
  if (typeof r.readBytes === "function") {
    const bytes = r.readBytes(name);
    if (bytes === null) return { present: listed(r, name) === true, digest: null };
    if (bytes.length !== 64) return { present: true, digest: null };
    let text = "";
    for (const b of bytes) {
      if (!((b >= 0x30 && b <= 0x39) || (b >= 0x61 && b <= 0x66))) return { present: true, digest: null };
      text += String.fromCharCode(b);
    }
    return { present: true, digest: text };
  }
  const text = r.readText(name);
  if (text === null) return { present: listed(r, name) === true, digest: null };
  return { present: true, digest: typeof text === "string" && HEX64.test(text) ? text : null };
}
const SELF_DECLARED_MEMBERS = new Set(["manifest.json", "manifest.sha256"]);

/**
 * The per-member bound (bundle-objects.md §5), applied to every reader: a larger member is not
 * read into a digest, a declared one fails manifest_files and a structural one is invalid.
 */
export const MAX_MEMBER_BYTES = 20 * 1024 * 1024;

const WINDOWS_DEVICE_NAMES = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])$/i;
/** A segment of the POSIX portable filename character set: A-Z, a-z, 0-9, `.`, `_` and `-`. */
const PORTABLE_SEGMENT = /^[A-Za-z0-9._-]+$/;
/** A member name is at most this many bytes; a portable name holds one byte per character. */
const MAX_MEMBER_NAME_BYTES = 255;
/**
 * Whether `name` is a portable member name (bundle-objects.md section 2), the one rule for a
 * manifest.files key and for an entry of a directory bundle (section 1). A member name is a
 * `/`-separated sequence of segments; every segment is non-empty and holds only the POSIX portable
 * filename characters; no segment is `.` or `..`, ends with `.` or begins with `-`; no segment is,
 * ASCII letter case ignored, a Windows reserved device name alone or before its first `.`; and the
 * whole name is at most 255 bytes. A name outside the rule is never read.
 *
 * The rule names the characters a name may hold, not the ones it may not: every way a host reads,
 * folds or opens a name as another name through its characters (a noncharacter, a compatibility
 * form, a separator) needs one outside the portable set, so a name made only of portable
 * characters gives none of them a hold; the segment rules cover what the portable set allows.
 */
export function memberNameValid(name: unknown): boolean {
  if (typeof name !== "string" || name.length === 0 || name.length > MAX_MEMBER_NAME_BYTES) return false;
  for (const segment of name.split("/")) {
    if (!PORTABLE_SEGMENT.test(segment)) return false;
    if (segment === "." || segment === "..") return false;
    if (segment.endsWith(".") || segment.startsWith("-")) return false;
    if (WINDOWS_DEVICE_NAMES.test(segment.split(".")[0]!)) return false;
  }
  return true;
}

/**
 * `name` with A to Z read as a to z and nothing else changed (bundle-objects.md section 2). ASCII
 * letter case is the only folding of member names: String.prototype.toLowerCase would also read
 * U+212A KELVIN SIGN as `k` and U+0130 as `i` with a combining dot, folds the specification does
 * not make.
 */
export function foldMemberName(name: string): string {
  return name.replace(/[A-Z]/g, (c) => c.toLowerCase());
}

/**
 * Whether a `files` key of the manifest names the manifest or its sidecar: its ASCII fold is
 * `manifest.json` or `manifest.sha256` exactly. Any other key, `MANİFEST.JSON` (U+0130) among
 * them, is an ordinary declaration that the member-name rule then judges.
 */
export function isSelfDeclaration(name: string): boolean {
  return SELF_DECLARED_MEMBERS.has(foldMemberName(name));
}

/** The directories a member name implies: `a/b/c` implies `a` and `a/b`. Linear in the name's length. */
function impliedDirectories(name: string): string[] {
  const out: string[] = [];
  for (let at = name.indexOf("/"); at >= 0; at = name.indexOf("/", at + 1)) out.push(name.slice(0, at));
  return out;
}

/** Append `value` to the list `map` holds under `key`, in place. */
function pushTo<K, V>(map: Map<K, V[]>, key: K, value: V): void {
  const list = map.get(key);
  if (list === undefined) map.set(key, [value]);
  else list.push(value);
}

/**
 * Every name of `names`, each naming a file, that conflicts with another of them
 * (bundle-objects.md section 2): folded by ASCII letter case, two names are equal, or one is a
 * directory the other implies, or a directory they both imply is spelled two ways. Linear in the
 * total length of the names: every list grows in place.
 */
export function conflictingNames(names: readonly string[]): Set<string> {
  const byKey = new Map<string, string[]>();
  const impliedBy = new Map<string, string[]>();
  const spellings = new Map<string, Set<string>>();
  for (const name of names) {
    pushTo(byKey, foldMemberName(name), name);
    for (const directory of impliedDirectories(name)) {
      const dirKey = foldMemberName(directory);
      pushTo(impliedBy, dirKey, name);
      const spelled = spellings.get(dirKey);
      if (spelled === undefined) spellings.set(dirKey, new Set([directory]));
      else spelled.add(directory);
    }
  }
  const conflicting = new Set<string>();
  for (const [key, group] of byKey) {
    if (group.length > 1) group.forEach((name) => conflicting.add(name));
    const implying = impliedBy.get(key);
    if (implying !== undefined) {
      group.forEach((name) => conflicting.add(name));
      implying.forEach((name) => conflicting.add(name));
    }
  }
  for (const [key, spelled] of spellings) {
    if (spelled.size > 1) impliedBy.get(key)!.forEach((name) => conflicting.add(name));
  }
  return conflicting;
}
/** Canonical P1 is at most this many bytes (bundle-objects.md §3). */
const P1_MAX_BYTES = 1024;
const enc = new TextEncoder();

// ---------- strict JSON load (input strictness) and containment ----------

/**
 * The error classes a hostile document can raise from parsing or canonicalization. Only these
 * are turned into a failed check: anything else is a defect of this package and stays visible.
 *
 * RangeError and SyntaxError are not. Every document and value is held to rule 6's 64 levels by an
 * iterative walk before any recursive step, so no document runs the parser or the canonicalizer
 * out of stack; parseJsonStrict decodes with this package's own tokenizer and throws only
 * JsonParseError; and V8 raises a stack that runs out inside a regular expression as a
 * SyntaxError. Either class here is a stack the host ran out of.
 * Contained, it would turn that fault, on a value the protocol admits, into a verdict (a failed
 * check, SIGNATURE_INVALID, ROOT_SIGNATURE_INVALID) whose occurrence the stack decides, and on an
 * engine whose stack error is neither, the same run would throw. Both propagate, as the Python
 * verifier's RecursionError does (report-contract.md section 4: a fault of a library
 * interface is an exception of the host language).
 */
function isContainedError(err: unknown): boolean {
  return err instanceof JsonParseError || err instanceof CanonicalizationError;
}

/** A bundle JSON member: whether it exists, whether it loaded under input strictness, and its value if so. */
interface JsonMember {
  present: boolean;
  ok: boolean;
  value: Json;
}

/**
 * Load a bundle JSON member strictly (canonicalization-and-hashing.md, "Input strictness"). The
 * exact bytes are decoded as UTF-8 with fatal errors and the BOM kept, so invalid UTF-8 and a
 * leading BOM are refused rather than repaired; then the depth scan, the duplicate-member parse,
 * and the strictness walk. A reader without readBytes hands over text a host has already decoded,
 * and invalid UTF-8 in it cannot be seen. An invalid member is present but not ok: its check fails,
 * never throws.
 */
function readJsonMember(r: BundleReader, name: string): JsonMember {
  let parse: () => Json;
  if (typeof r.readBytes === "function") {
    const bytes = r.readBytes(name);
    // Listed but unreadable (over the size bound, say) is present and invalid, not absent.
    if (bytes === null) return { present: listed(r, name) === true, ok: false, value: null };
    if (bytes.length > MAX_MEMBER_BYTES) return { present: true, ok: false, value: null };
    parse = () => parseJsonBytesStrict(bytes) as Json;
  } else {
    const text = r.readText(name);
    if (text === null) return { present: listed(r, name) === true, ok: false, value: null };
    if (typeof text !== "string" || jsonTextTooDeep(text)) return { present: true, ok: false, value: null };
    parse = () => parseJsonStrict(text) as Json;
  }
  let value: Json;
  try {
    value = parse();
  } catch (err) {
    if (isContainedError(err)) return { present: true, ok: false, value: null };
    throw err;
  }
  if (jsonValueViolatesStrictness(value)) return { present: true, ok: false, value: null };
  return { present: true, ok: true, value };
}
/** The canonical SHA-256 of a loaded value, or null when it cannot be canonicalized. */
function tryCanonicalSha256Hex(value: Json): string | null {
  try {
    return canonicalSha256Hex(value);
  } catch (err) {
    if (isContainedError(err)) return null;
    throw err;
  }
}
function readBytes(r: BundleReader, name: string): Uint8Array | null {
  // Exact bytes first. The text fallback exists only for readers that hold text (the in-memory
  // browser reader); for anything on disk it would alter binary members without a trace, so
  // filesystem readers supply readBytes.
  if (typeof r.readBytes === "function") return r.readBytes(name);
  const t = r.readText(name);
  return t === null ? null : enc.encode(t);
}
/** Presence is a fact about the bundle (bundle-objects.md section 6): listed by the reader, or readable. */
function exists(r: BundleReader, name: string): boolean {
  if (listed(r, name) === true) return true;
  return typeof r.readBytes === "function" ? r.readBytes(name) !== null : r.readText(name) !== null;
}
/**
 * Whether the verifier saw the member, for a layer whose read failed (bundle-objects.md section
 * 6): a presence flag records what was found, and a host failure is never reported as absence
 * (report-contract.md section 5.3). The reader's listing decides when it has one; otherwise a
 * member the host failed to read exists (BundleReadError), unless the host failed to reach it.
 */
function seen(r: BundleReader, name: string): boolean {
  try {
    return exists(r, name);
  } catch (err) {
    if (err instanceof MemberUnreachedError) return false;
    if (err instanceof BundleReadError) return true;
    throw err;
  }
}

/** What a refusal judged over the members the host did read takes from one it failed to read: nothing. */
const UNREAD: unique symbol = Symbol("unread");
type Unread = typeof UNREAD;
function attempt<T>(read: () => T): T | Unread {
  try {
    return read();
  } catch (err) {
    if (err instanceof BundleReadError) return UNREAD;
    throw err;
  }
}

/**
 * The members a layer reads whatever else refuses it (bundle-objects.md section 6). The manifest
 * layer also reads every member manifest.files declares once it accepts the manifest, and
 * verifyManifest reads those itself: a manifest it refuses declares nothing it reads. The envelope
 * layer's members are chosen by envelopeReadFailure.
 */
const MANIFEST_MEMBERS = ["manifest.json", "manifest.sha256"] as const;
const P1_MEMBERS = ["p1.json", "p1.sha256", "canonical_input.json"] as const;

/**
 * The host's failure to read one of the members `names` the verifier finds, or null. Each layer
 * reads the members it finds whatever else refuses it, and a host failure on one is the layer's
 * `*_read_failed` row, judged on its own: a layer refused for what one member holds still reports
 * the host failing to read another (report-contract.md section 5.3). A member over the per-member
 * bound is judged by its size and not read, as the layers judge it.
 */
function hostReadFailure(r: BundleReader, names: readonly string[]): string | null {
  for (const name of names) {
    try {
      readBytes(r, name);
    } catch (err) {
      if (err instanceof BundleReadError) return err.message;
      throw err;
    }
  }
  return null;
}

/**
 * The host's failure to read the envelope or its sidecar, whichever of them is present. The
 * envelope's only name is envelope_env1.json (bundle-objects.md section 4); envelope.json is an
 * ordinary member name.
 */
function envelopeReadFailure(r: BundleReader): string | null {
  return hostReadFailure(r, ["envelope_env1.json", "envelope.sha256"]);
}

/**
 * manifest_verification_failed, judged over the manifest members the host did read: used when it
 * failed to read one. The row is judged on its own (report-contract.md section 5.3): a manifest
 * that is not strict JSON is refused whether or not the host could read its sidecar, and a sidecar
 * that is not a regular member whether or not it could read the manifest. The rules are
 * judgeManifest's, as for a layer that read both.
 */
function manifestRefusalOfReadMembers(r: BundleReader): string | null {
  return judgeManifest(attempt(() => readJsonMember(r, "manifest.json")), attempt(() => readSidecar(r, "manifest.sha256"))).refused;
}

/**
 * p1_verification_failed, judged over the P1 members the host did read: used when it failed to
 * read one. A P1 that breaks its contract is refused whether or not the host could read the
 * canonical input, and a canonical input that is not a strict JSON object whether or not it could
 * read P1.
 */
function p1RefusalOfReadMembers(r: BundleReader): string | null {
  const p1 = attempt(() => readJsonMember(r, "p1.json"));
  if (p1 !== UNREAD) {
    const judged = judgeP1(p1);
    if (judged.refused !== null) return judged.refused;
  }
  const input = attempt(() => readJsonMember(r, "canonical_input.json"));
  return input === UNREAD ? null : judgeCanonicalInput(input);
}

/**
 * envelope_verification_failed, judged over the envelope members the host did read: used when it
 * failed to read one. An envelope beside its sidecar that is not a strict JSON object, or
 * satisfies its contract and cannot be canonicalized, is refused whether or not the host could
 * read the sidecar. The rules are judgeEnvelope's, as for a layer that read both.
 */
function envelopeRefusalOfReadMembers(r: BundleReader): string | null {
  if (!seen(r, "envelope_env1.json") || !seen(r, "envelope.sha256")) return null;
  const member = attempt(() => readJsonMember(r, "envelope_env1.json"));
  return member === UNREAD ? null : judgeEnvelope(member).refused;
}

/**
 * The reader of one run: the host's reader, and the members it listed for this run, null when it
 * cannot enumerate. Made once at the start of a run and handed to every layer in place of the
 * host's reader, so what the run listed travels with the run.
 */
interface RunReader extends BundleReader {
  readonly members: ReadonlySet<string> | null;
}

function runReader(host: BundleReader, members: ReadonlySet<string> | null): RunReader {
  const run: { -readonly [K in keyof RunReader]: RunReader[K] } = {
    members,
    readText: (name) => host.readText(name),
  };
  if (typeof host.readBytes === "function") run.readBytes = (name) => host.readBytes!(name);
  if (typeof host.listMembers === "function") run.listMembers = () => host.listMembers!();
  return run;
}

/** Whether the run's listing holds `name`; null when the reader is not a run's or cannot enumerate. */
function listed(r: BundleReader, name: string): boolean | null {
  const members = (r as Partial<RunReader>).members;
  return members ? members.has(name) : null;
}
/** Names a bundle may carry without the manifest declaring them. */
const UNDECLARED_ALLOWED = new Set([
  "manifest.json", "manifest.sha256", "envelope_env1.json", "envelope.sha256", "verification_receipt.json",
]);

// ---------- offline: manifest ----------
// Closed contracts (bundle-objects.md sections 2 to 4). A digest proves only that an object is
// self-consistent, not that it conforms: each digest is computed over whatever the object
// happens to contain, so without these contracts a manifest with no bundle_id/schema_version,
// a P1 with no version and a smuggled field, and an envelope with v=999 and no links would
// each verify. These contracts are the Python verifier's and MUST stay in step with it.
const MANIFEST_ALLOWED_FIELDS = new Set(["bundle_id", "files", "nonce", "schema_version"]);
const MANIFEST_REQUIRED_FIELDS = ["bundle_id", "files", "nonce", "schema_version"];
/** The one manifest version this verifier supports (bundle-objects.md section 2); a well-formed other version fires the gate. */
const MANIFEST_SCHEMA_VERSION = "loquitur.bundle.v1";
/** The manifest's nonce: 256 bits written as 64 lowercase hexadecimal characters. */
const NONCE = /^[0-9a-f]{64}$/;
const P1_ALLOWED_FIELDS = new Set(["s", "v", "ih", "ik"]);
const P1_SUPPORTED_VERSIONS = new Set([1]);
const ENVELOPE_ALLOWED_FIELDS = new Set([
  "s", "v", "bundle_id", "bundle_manifest_sha256", "p1_sha256", "registry_entry",
  "ts", "network", "p1_txid", "uri", "asset_id", "asset_type", "receipt_id",
]);
const ENVELOPE_SUPPORTED_VERSIONS = new Set([1]);
// The three links are what an envelope is (bundle-objects.md §4, the `required` column of
// its member table), so they are required and not only allowed: {"s":"env1","v":1} binds no
// digest and is OFFLINE_FAIL, exit 1, in both reference verifiers, not OFFLINE_REVIEW. REVIEW
// asks a person to weigh something, and there is nothing here to weigh: an envelope without its
// links is not an env1 document. Absent and null are the same here, as they are there.
const ENVELOPE_REQUIRED_FIELDS = ["bundle_id", "bundle_manifest_sha256", "p1_sha256"];
/**
 * The optional members carry declared types (bundle-objects.md §4). No check reads them,
 * and that is why the types are written down: a member the contract leaves untyped
 * is the same silence as a member it does not name: without them `ts: {}` would be an
 * OFFLINE_OK envelope.
 */
const ENVELOPE_STRING_OR_NULL_FIELDS = ["network", "p1_txid", "uri", "asset_id", "asset_type", "receipt_id"];
/** `ts` is a time in whole seconds: an integer under the canonical numeric model, or `null`. */
const ENVELOPE_INTEGER_OR_NULL_FIELDS = ["ts"];

/**
 * The manifest's closed contract (bundle-objects.md section 2). bundle_id is a string that is not
 * blank under W; nonce is 64 lowercase hexadecimal characters; schema_version is exactly
 * `loquitur.bundle.v1`; files is an object whose every value is a self-describing digest,
 * `sha256:` and 64 lowercase hexadecimal characters. The list form of files ([{name, sha256}]) is
 * not a manifest. A manifest cannot declare itself or its sidecar, in any letter case: it changes
 * when its own list is written, so such a declaration is never a statement about the bundle, and
 * it fails the contract rather than being dropped.
 */
function manifestShapeOk(manifest: Json): boolean {
  if (!isPlainObject(manifest)) return false;
  for (const f of MANIFEST_REQUIRED_FIELDS) if (manifest[f] == null) return false;
  if (!Object.keys(manifest).every((k) => MANIFEST_ALLOWED_FIELDS.has(k))) return false;
  if (!nonBlankString(manifest.bundle_id)) return false;
  if (typeof manifest.nonce !== "string" || !NONCE.test(manifest.nonce)) return false;
  if (manifest.schema_version !== MANIFEST_SCHEMA_VERSION) return false;
  if (!isPlainObject(manifest.files)) return false;
  for (const [name, digest] of Object.entries(manifest.files)) {
    if (isSelfDeclaration(name)) return false;
    if (typeof digest !== "string" || !DIGEST.test(digest)) return false;
  }
  return true;
}
function p1ShapeOk(p1: Json): boolean {
  if (!p1 || typeof p1 !== "object") return false;
  if (p1.s !== "p1") return false;
  if (typeof p1.v !== "number" || !P1_SUPPORTED_VERSIONS.has(p1.v)) return false;
  // An explicitly empty input-key projection is refused (bundle-objects.md section 3): it can be
  // read as {} or as the whole canonical input, two mutually exclusive `ih` values, and a
  // projection over no keys commits to nothing about the input it claims to cover.
  if (Array.isArray(p1.ik) && p1.ik.length === 0) return false;
  // A present ik, null included, is a non-empty array of distinct strings. Anything else is
  // refused rather than read as the whole canonical input, so `"ik": "asset_id"` or `"ik": null`
  // never verifies against an ih over everything. Only an absent ik means the whole input.
  if (hasOwn(p1, "ik")) {
    const ik = p1.ik;
    // Each key is a free string (bundle-objects.md section 3): a key made only of W names no
    // member.
    if (!Array.isArray(ik) || ik.length === 0 || !ik.every(nonBlankString)) return false;
    if (new Set(ik).size !== ik.length) return false;
  }
  if (typeof p1.ih !== "string" || !DIGEST.test(p1.ih)) return false;
  return Object.keys(p1).every((k) => P1_ALLOWED_FIELDS.has(k));
}
function envelopeShapeOk(env: Json): boolean {
  if (!env || typeof env !== "object") return false;
  if (env.s !== "env1") return false;
  if (typeof env.v !== "number" || !ENVELOPE_SUPPORTED_VERSIONS.has(env.v)) return false;
  for (const f of ENVELOPE_REQUIRED_FIELDS) if (env[f] == null) return false;
  // The six are the envelope's free strings (bundle-objects.md section 4): a string made only of W
  // is a rejection like a value of another type.
  for (const f of ENVELOPE_STRING_OR_NULL_FIELDS) if (env[f] != null && !nonBlankString(env[f])) return false;
  for (const f of ENVELOPE_INTEGER_OR_NULL_FIELDS) {
    if (env[f] != null && (typeof env[f] !== "number" || !Number.isInteger(env[f]))) return false;
  }
  // A registry entry carried inside the envelope is a registry entry: one contract for one
  // concept (registry-link.md §2). Nothing compares it with anything here; it is validated
  // because the envelope declares it to be one.
  if (env.registry_entry != null && !parseRegistryEntry(env.registry_entry as never).ok) return false;
  return Object.keys(env).every((k) => ENVELOPE_ALLOWED_FIELDS.has(k));
}

/** A JSON member that loaded as an object: present, strict, and a plain object. */
function loadedObject(member: JsonMember): boolean {
  return member.present && member.ok && isPlainObject(member.value);
}

interface ManifestResult {
  present: boolean;
  /**
   * report-contract.md section 5.3, `manifest_verification_failed`: the manifest is not a
   * regular member, is not strict JSON, exceeds the bound or is not an object; its sidecar is
   * not a regular member; or the manifest cannot be canonicalized. A refused manifest is not
   * merely a failed layer: the run carries the error.
   */
  refused: string | null;
  manifest_sha256_ok: boolean;
  files_ok: boolean;
  shape_ok: boolean;
  ok: boolean;
  manifest: Json;
  manifest_actual: string | null;
  manifest_verified: string | null;
}

const MANIFEST_UNAVAILABLE: ManifestResult = {
  present: false, refused: null, manifest_sha256_ok: false, files_ok: false, shape_ok: false, ok: false,
  manifest: null, manifest_actual: null, manifest_verified: null,
};

/** The manifest layer of a run whose host failed to read a member it reads: refused, presence as seen. */
function manifestUnread(r: BundleReader): ManifestResult {
  return { ...MANIFEST_UNAVAILABLE, present: seen(r, "manifest.json") };
}

/**
 * manifest_verification_failed over the manifest members read, each UNREAD when the host failed to
 * read it (report-contract.md section 5.3): the manifest is not a regular member, or is not a
 * strict JSON object; its sidecar is not a regular member; or the manifest cannot be canonicalized.
 * A member the host did not read is not judged. The one rule list of the manifest layer: the layer
 * and the row judged over the members the host did read both apply it. `actual` is the manifest's
 * canonical digest when the manifest was read and is not refused.
 */
function judgeManifest(member: JsonMember | Unread, sidecar: { present: boolean } | Unread): { refused: string | null; actual: string | null } {
  if (member !== UNREAD && !loadedObject(member)) {
    return { refused: member.present ? "manifest.json is not a strict JSON object" : "manifest.json is not a regular member", actual: null };
  }
  if (sidecar !== UNREAD && !sidecar.present) return { refused: "manifest.sha256 is not a regular member", actual: null };
  const actual = member === UNREAD ? null : tryCanonicalSha256Hex(member.value);
  // Not reachable after input strictness (report-contract.md section 5.3); kept as a defense in
  // depth.
  if (member !== UNREAD && actual === null) return { refused: "manifest.json cannot be canonicalized", actual: null };
  return { refused: null, actual };
}

function verifyManifest(r: BundleReader): ManifestResult {
  const member = readJsonMember(r, "manifest.json");
  const sidecar = readSidecar(r, "manifest.sha256");
  const judged = judgeManifest(member, sidecar);
  if (judged.refused !== null) return { ...MANIFEST_UNAVAILABLE, present: member.present, refused: judged.refused };
  const manifest = member.value;
  const actual = judged.actual!;
  // The sidecar is compared as written: an upper-case or newline-terminated digest is not the
  // digest.
  const manifest_sha256_ok = sidecar.digest !== null && sidecar.digest === actual;
  // Declared digests are `sha256:` and 64 lowercase hexadecimal characters, compared as whole
  // strings; a bare digest, upper case and padding all fail. The list form of files is not read.
  const declared: Array<[string, unknown]> = isPlainObject(manifest.files) ? Object.entries(manifest.files) : [];
  // A self-declaration fails the contract (manifestShapeOk) and is not read.
  const checkable = declared.filter(([name]) => !isSelfDeclaration(name));
  // Two keys that conflict, such as `a.json` and `A.JSON`, name one file on a host that ignores
  // letter case: each fails, and neither is read (bundle-objects.md section 2).
  const conflicts = conflictingNames(checkable.map(([name]) => name).filter((name) => memberNameValid(name)));
  let files_ok = checkable.length > 0;
  for (const [name, exp] of checkable) {
    const bytes = memberNameValid(name) && !conflicts.has(name) ? readBytes(r, name) : null;
    const got = bytes !== null && bytes.length <= MAX_MEMBER_BYTES ? sha256Hex(bytes) : null;
    if (typeof exp !== "string" || !DIGEST.test(exp) || exp !== prefixed(got)) files_ok = false;
  }
  const shape_ok = manifestShapeOk(manifest);
  // What an envelope may link to (bundle-objects.md section 4): the digest of a manifest that
  // parsed, satisfied its contract and matched its sidecar. The recomputed digest of anything
  // else is not a manifest the bundle vouches for, and a link to it does not hold.
  const manifest_verified = shape_ok && manifest_sha256_ok ? actual : null;
  return {
    present: true, refused: null, manifest_sha256_ok, files_ok, shape_ok,
    ok: manifest_sha256_ok && files_ok && shape_ok, manifest, manifest_actual: actual, manifest_verified,
  };
}

// ---------- offline: p1 + canonical_input ----------
interface P1Result {
  p1_sha256_ok: boolean;
  input_hash_ok: boolean | null;
  canonical_input_present: boolean;
  status: string;
  p1_actual: string | null;
  /**
   * report-contract.md section 5.3, `p1_verification_failed`: p1.json is not a regular member, is
   * not strict JSON, exceeds the bound or is not an object; P1 breaks its closed contract, cannot
   * be canonicalized or exceeds 1024 bytes in canonical form; or canonical_input.json is present
   * and is not strict JSON, exceeds the bound or is not an object.
   */
  refused: string | null;
}

const P1_UNAVAILABLE: P1Result = {
  p1_sha256_ok: false, input_hash_ok: false, canonical_input_present: false, status: STATUS_OFFLINE_FAIL, p1_actual: null, refused: null,
};

/** P1 alone, without the canonical input: refused with why, or its canonical digest and whether its sidecar matched it. */
type P1Alone = { refused: string } | { refused: null; p1: Json; digest: string; sidecarOk: boolean };

function readP1Alone(r: BundleReader): P1Alone {
  const judged = judgeP1(readJsonMember(r, "p1.json"));
  if (judged.refused !== null) return judged;
  const expected = readSidecar(r, "p1.sha256").digest;
  return { ...judged, sidecarOk: expected !== null && expected === judged.digest };
}

/** P1 judged from its member alone: refused with why, or the P1 and its canonical digest. */
function judgeP1(member: JsonMember): { refused: string } | { refused: null; p1: Json; digest: string } {
  if (!loadedObject(member)) return { refused: member.present ? "p1.json is not a strict JSON object" : "p1.json is not a regular member" };
  const p1 = member.value;
  // A P1 that is not a conformant p1/v1 projection cannot bind anything.
  if (!p1ShapeOk(p1)) return { refused: "p1.json breaks its closed contract" };
  let p1Bytes: Uint8Array | null;
  try {
    p1Bytes = canonicalJsonBytes(p1);
  } catch (err) {
    if (!isContainedError(err)) throw err;
    p1Bytes = null;
  }
  // Canonical P1 is at most 1024 bytes (bundle-objects.md §3). Not reachable after input strictness
  // (report-contract.md section 5.3); kept as a defense in depth.
  if (p1Bytes === null) return { refused: "p1.json cannot be canonicalized" };
  if (p1Bytes.length > P1_MAX_BYTES) return { refused: "p1.json exceeds 1024 bytes in canonical form" };
  return { refused: null, p1, digest: sha256Hex(p1Bytes) };
}

/**
 * canonical_input.json judged from its member alone (report-contract.md section 5.3): present and
 * not loadable under input strictness (invalid UTF-8, a duplicate member, a non-finite or unsafe
 * number, a lone surrogate, nesting beyond the limit), or a JSON value that is not an object (1,
 * "x", true, null, [1,2]), is refused. A rejection, not an absence: only a file that is not there
 * leaves the input hash unevaluated, so a present `null` is not absent (REVIEW) and a primitive
 * never reaches the projection. The one rule of the layer and of the row judged over the members
 * the host did read.
 */
function judgeCanonicalInput(input: JsonMember): string | null {
  const value = input.value;
  const isObject = value !== null && typeof value === "object" && !Array.isArray(value);
  return input.present && (!input.ok || !isObject) ? "canonical_input.json is present and is not a strict JSON object" : null;
}

/**
 * The P1 layer of a run whose host failed to read a member it reads (p1.json, p1.sha256 or
 * canonical_input.json): refused, with the canonical input's presence as seen and the digest of
 * a P1 that verified without the canonical input, so an input the host could not read does not
 * also unmake the P1 an envelope or a receipt names (bundle-objects.md section 4). The Python
 * verifier recomputes the same digest from p1.json and p1.sha256 alone.
 */
function p1Unread(r: BundleReader): P1Result {
  let p1_actual: string | null;
  try {
    const alone = readP1Alone(r);
    p1_actual = alone.refused === null && alone.sidecarOk ? alone.digest : null;
  } catch (err) {
    if (!(err instanceof BundleReadError)) throw err;
    p1_actual = null;
  }
  return { ...P1_UNAVAILABLE, canonical_input_present: seen(r, "canonical_input.json"), p1_actual };
}

function verifyP1(r: BundleReader): P1Result {
  // canonical_input_present is a fact about the bundle (bundle-objects.md, presence flags): the
  // file exists, whatever it holds and whatever became of P1. A present `null` or unparseable
  // file reports true.
  const inputMember = readJsonMember(r, "canonical_input.json");
  const canonical_input_present = inputMember.present;
  const refusedP1 = (why: string, p1_actual: string | null = null): P1Result => ({
    p1_sha256_ok: false, input_hash_ok: false, canonical_input_present, status: STATUS_OFFLINE_FAIL, p1_actual, refused: why,
  });
  const alone = readP1Alone(r);
  if (alone.refused !== null) return refusedP1(alone.refused);
  const { p1, digest: p1Digest } = alone;
  const p1_sha256_ok = alone.sidecarOk;
  // What an envelope may link to (bundle-objects.md section 4): the digest of a P1 that parsed,
  // satisfied its contract and matched its sidecar. A P1 whose sidecar disagrees is not
  // verified, and a link to its recomputed digest does not hold. The canonical input plays no
  // part: a tampered input leaves the P1 link as it is.
  const p1_actual = p1_sha256_ok ? p1Digest : null;

  // p1_sha256 is reported false beside a refused canonical input: P1 verification did not
  // complete (bundle-objects.md section 6, "A canonical input that is present and unreadable is a
  // refusal").
  const inputRefused = judgeCanonicalInput(inputMember);
  if (inputRefused !== null) return refusedP1(inputRefused, p1_actual);
  const canonicalInput = canonical_input_present ? inputMember.value : null;
  const ihExpected: string = p1.ih;
  let input_hash_ok: boolean | null = null;
  if (canonicalInput) {
    // The contract has checked ik: present means a non-empty list of distinct strings.
    const ik: string[] = hasOwn(p1, "ik") ? p1.ik : Object.keys(canonicalInput);
    const payload: Record<string, unknown> = {};
    // Own members only. `k in canonicalInput` would also see what Object.prototype carries, so an
    // ik naming an absent "constructor" or "toString" would project a function, and the
    // canonicalizer would throw instead of hashing the null the specification prescribes for an
    // absent key (canonicalization-and-hashing.md §2).
    for (const k of ik) {
      defineJsonMember(payload, k, Object.prototype.hasOwnProperty.call(canonicalInput, k) ? canonicalInput[k] : null);
    }
    const ihActual = tryCanonicalSha256Hex(payload);
    input_hash_ok = ihActual !== null && prefixed(ihActual) === ihExpected;
  }
  let status = STATUS_OFFLINE_OK;
  if (p1_sha256_ok === false || input_hash_ok === false) status = STATUS_OFFLINE_FAIL;
  else if (input_hash_ok !== true) status = STATUS_OFFLINE_REVIEW;
  return { p1_sha256_ok, input_hash_ok, canonical_input_present, status, p1_actual, refused: null };
}

// ---------- offline: envelope ----------
interface EnvelopeResult {
  envelope_present: boolean;
  envelope_sha256_ok: boolean | null;
  links_ok: boolean | null;
  status: string;
  /** Neither the envelope nor its sidecar is present (review reason envelope_not_provided). */
  absent: boolean;
  /** The envelope, when present and read, satisfies its closed contract; true when it is absent. */
  shape_ok: boolean;
  /**
   * report-contract.md section 5.3, `envelope_verification_failed`: the envelope and its sidecar
   * are both present and the envelope is not strict JSON, exceeds the bound, is not an object, or
   * satisfies its contract and cannot be canonicalized.
   */
  refused: string | null;
}

const ENVELOPE_UNAVAILABLE: EnvelopeResult = {
  envelope_present: false, envelope_sha256_ok: false, links_ok: false, status: STATUS_OFFLINE_FAIL, absent: false, shape_ok: false, refused: null,
};

/** The envelope judged from its member alone, beside its sidecar: refused with why, or the envelope, whether it satisfies its contract and its canonical digest. */
type EnvelopeJudged = { refused: string } | { refused: null; env: Json; shapeOk: boolean; digest: string | null };

/**
 * envelope_verification_failed over the envelope read beside its sidecar (report-contract.md
 * section 5.3): the envelope is not a strict JSON object, or satisfies its contract and cannot be
 * canonicalized. The one rule list of the envelope layer: the layer and the row judged over the
 * members the host did read both apply it. An envelope that breaks its contract is not refused: its
 * layer fails, and its digest, null when it cannot be canonicalized, is still compared.
 */
function judgeEnvelope(member: JsonMember): EnvelopeJudged {
  if (!loadedObject(member)) return { refused: "the envelope is not a strict JSON object" };
  const env = member.value;
  const shapeOk = envelopeShapeOk(env);
  const digest = tryCanonicalSha256Hex(env);
  // Not reachable after input strictness (report-contract.md section 5.3); kept as a defense in
  // depth.
  if (shapeOk && digest === null) return { refused: "the envelope cannot be canonicalized" };
  return { refused: null, env, shapeOk, digest };
}

/** The envelope layer of a run whose host failed to read envelope_env1.json or envelope.sha256: refused, presence as seen. */
function envelopeUnread(r: BundleReader): EnvelopeResult {
  return { ...ENVELOPE_UNAVAILABLE, envelope_present: seen(r, "envelope_env1.json") };
}

/**
 * @param manifestDigest the digest of the manifest if it verified (bundle-objects.md section 4), else null
 * @param p1Digest the digest of P1 if it verified (bundle-objects.md section 4), else null
 * @param manifestBundleId the verified manifest's bundle_id, else null
 * @param manifestUnread the host failed to read the manifest layer: its links are not evaluated
 * @param p1Unread the host failed to read the P1 layer: the P1 link is not evaluated
 */
function verifyEnvelope(r: BundleReader, manifestDigest: string | null, p1Digest: string | null, manifestBundleId: string | null,
  manifestUnread = false, p1Unread = false): EnvelopeResult {
  const envPresent = exists(r, "envelope_env1.json");
  const shaPresent = exists(r, "envelope.sha256");
  if (!envPresent && !shaPresent) {
    return { envelope_present: false, envelope_sha256_ok: null, links_ok: null, status: STATUS_OFFLINE_REVIEW, absent: true, shape_ok: true, refused: null };
  }
  // Exactly one of the two (envelope_incomplete): the layer fails.
  if (!envPresent || !shaPresent) {
    return { envelope_present: envPresent, envelope_sha256_ok: false, links_ok: null, status: STATUS_OFFLINE_FAIL, absent: false, shape_ok: true, refused: null };
  }
  const member = readJsonMember(r, "envelope_env1.json");
  // The sidecar is read once the envelope is an object, before anything is judged from either.
  const expected = loadedObject(member) ? readSidecar(r, "envelope.sha256").digest : null;
  const judged = judgeEnvelope(member);
  if (judged.refused !== null) {
    // Present beside its sidecar and refused, not merely failed.
    return { envelope_present: true, envelope_sha256_ok: false, links_ok: false, status: STATUS_OFFLINE_FAIL, absent: false, shape_ok: loadedObject(member), refused: judged.refused };
  }
  const { env, digest: actual } = judged;
  // An envelope that is not a conformant env1 cannot be interpreted, so it
  // must not contribute a PASS.
  if (!judged.shapeOk) {
    // The refusal does not depend on the digest, but the informative per-check result does
    // (report-contract.md section 6): the stored digest is compared with the envelope's canonical
    // digest and the result reported. A malformed envelope that matches its stored digest was
    // authored wrong; one that does not was altered afterwards, and a reader is owed that
    // difference. An envelope that cannot be canonicalized has no digest to compare and stays false.
    const envelope_sha256_ok = expected !== null && actual !== null && expected === actual;
    return { envelope_present: true, envelope_sha256_ok, links_ok: false, status: STATUS_OFFLINE_FAIL, absent: false, shape_ok: false, refused: null };
  }
  const envelope_sha256_ok = expected !== null && expected === actual;
  // The contract above guarantees the three link members are present. Each is then either well
  // formed and equal to what it names, or the link is false: a malformed member (a digest that
  // is not `sha256:` and 64 lowercase hex characters, a bare, padded or upper-case one, `{}`,
  // `false`, a bundle_id that is not a string) is a link that does not hold, never "no link".
  // Nothing is trimmed or case-folded, and bundle_id 7 is not the string "7". A link to a layer
  // the host failed to read is not evaluated (null), and fails nothing.
  const bundle_id_ok = manifestUnread ? null : typeof env.bundle_id === "string" && manifestBundleId !== null && env.bundle_id === manifestBundleId;
  const manifest_link_ok = manifestUnread ? null : typeof env.bundle_manifest_sha256 === "string" && DIGEST.test(env.bundle_manifest_sha256)
    && manifestDigest !== null && env.bundle_manifest_sha256 === prefixed(manifestDigest);
  const p1_link_ok = p1Unread ? null : typeof env.p1_sha256 === "string" && DIGEST.test(env.p1_sha256)
    && p1Digest !== null && env.p1_sha256 === prefixed(p1Digest);
  const links = [bundle_id_ok, manifest_link_ok, p1_link_ok];
  const links_ok = links.includes(false) ? false : links.includes(null) ? null : true;
  const status = envelope_sha256_ok && links_ok === true ? STATUS_OFFLINE_OK : envelope_sha256_ok && links_ok === null ? STATUS_OFFLINE_REVIEW : STATUS_OFFLINE_FAIL;
  return { envelope_present: true, envelope_sha256_ok, links_ok, status, absent: false, shape_ok: true, refused: null };
}

// ---------- link: the registry link (full check set, as in the Python verifier) ----------
// The closed vocabulary, and nothing else: no alias such as `passed`, `ok` or `success` maps
// to PASS, so a receipt carrying `status: "ok"` produces no verdict.
//
// loquitur-protocol/docs/specification/verification-vocabularies.md is explicit:
// implementations MUST NOT introduce a status outside the four, and MUST NOT coerce an
// unrecognized value to PASS, WARN, REVIEW or FAIL: an unrecognized status is a
// rejection, not a downgrade. Kept byte-for-byte in step with the Python verifier: an
// alias removed in one implementation and left in the other is a cross-implementation
// disagreement, which is the one thing the conformance oracle exists to catch.
const _STATUS_TO_VERDICT: Record<string, string> = {
  pass: "PASS",
  warning: "WARN",
  review: "REVIEW",
  fail: "FAIL",
};
const _HARD_LINK_CHECKS = new Set([
  "manifest_hash", "receipt_manifest_sha256", "receipt_hash",
  "policy_id", "policy_version", "reason_code_catalog_version",
  "reason_codes", "asset_type",
  "verification_receipt_contract", "receipt_bundle_id", "receipt_p1_sha256",
]);
// The link check's field comparisons are exact (registry-link.md section 4): nothing is trimmed or
// normalized, so a receipt carrying " INTEGRITY_OK " or a policy_id with a leading space is not
// linked to an entry that carries neither.
function exactStr(v: unknown): string | null {
  return typeof v === "string" ? v : null;
}
/**
 * reason_codes as an exact multiset: the sorted array, duplicates kept, serialized with
 * JSON.stringify, which is injective over string arrays. A key that de-duplicated or joined with
 * a separator would make ["A\u0000B"] equal ["A","B"], or ["A","A"] equal ["A"].
 */
function reasonCodesKey(v: unknown): string | null {
  if (!Array.isArray(v) || !v.every((x) => typeof x === "string")) return null;
  return JSON.stringify([...(v as string[])].sort());
}
/**
 * The registry entry's policy_version is semver; the link compares its MAJOR (registry-link.md
 * section 4) as decimal text: the grammar allows no leading zero, so two MAJORs are equal exactly
 * when their digits are, and no unbounded text is converted to a number.
 */
function entryPolicyMajor(v: unknown): string | null {
  if (typeof v !== "string") return null;
  const m = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[A-Za-z0-9_.-]+)?$/.exec(v);
  return m ? m[1]! : null;
}
/** The receipt's policy_version is an integer, not a string spelling one; written in decimal to compare with the MAJOR. */
function receiptPolicyVersion(v: unknown): string | null {
  return typeof v === "number" && Number.isSafeInteger(v) && v >= 1 ? String(v) : null;
}
function fieldOk(expected: unknown, actual: unknown): boolean | null {
  if (expected === null || actual === null || expected === undefined || actual === undefined) return null;
  return expected === actual;
}
/** verification_receipt.json as loaded (input strictness) and whether it satisfies its closed schema (registry-link.md section 2). */
interface ReceiptMember extends JsonMember {
  /** Present and a strict JSON object: what the link's conditions call "an object". */
  isObject: boolean;
  contractOk: boolean;
  /** The host failed to read it (BundleReadError): present, unread, no contract decision. */
  readFailed: boolean;
}
const RECEIPT_UNREAD: ReceiptMember = { present: true, ok: false, value: null, isObject: false, contractOk: false, readFailed: true };
function readReceipt(r: BundleReader): ReceiptMember {
  const member = readJsonMember(r, "verification_receipt.json");
  const isObject = loadedObject(member);
  const contractOk = isObject && receiptContractErrors(member.value).length === 0;
  return { ...member, isObject, contractOk, readFailed: false };
}

/**
 * Whether the receipt is an object that cannot be canonicalized, for which the link is refused. Not
 * reachable after input strictness (report-contract.md section 5.3); kept as a defense in depth.
 */
function receiptCannotBeCanonicalised(receipt: ReceiptMember): boolean {
  return receipt.isObject && tryCanonicalSha256Hex(receipt.value) === null;
}

interface LinkResult {
  /** The link holds, does not hold, or was not evaluated (null). */
  ok: boolean | null;
  /** The receipt is an object that cannot be canonicalized: the link is refused for it. */
  receiptUncanonicalisable: boolean;
}

/**
 * The link check between the receipt and the registry entry (registry_link, registry-link.md
 * sections 2 and 5).
 *
 * `ok: null` means there was no receipt to link: registry_link is null and the run fails. A receipt
 * that is present but unreadable, not an object, or outside its closed schema is a failed link
 * (`ok: false`): the link is evaluated and does not hold. Beyond the field comparisons, the receipt
 * must name this bundle (receipt_bundle_id: its bundle_id equals the manifest's, and is false when
 * the manifest's bundle_id is not a valid one) and, when it names a P1 digest, this P1
 * (receipt_p1_sha256: equal to the digest of the P1 that verified, false when P1 did not).
 *
 * @param manifestBundleId the manifest's bundle_id when the manifest loaded and its bundle_id is
 *   a non-blank string (bundle-objects.md section 2), else null
 * @param p1Digest the digest of the P1 that verified (bundle-objects.md section 4), else null
 */
function verifyRegistryLink(receiptMember: ReceiptMember, entry: ValidatedRegistryEntry, manifestActual: string | null,
  manifestBundleId: string | null, p1Digest: string | null): LinkResult {
  if (!receiptMember.present) return { ok: null, receiptUncanonicalisable: false };
  if (!receiptMember.contractOk) return { ok: false, receiptUncanonicalisable: receiptCannotBeCanonicalised(receiptMember) };
  const receipt = receiptMember.value;
  const receiptSha = tryCanonicalSha256Hex(receipt);
  // Not reachable after input strictness (report-contract.md section 5.3); kept as a defense in
  // depth.
  if (receiptSha === null) return { ok: false, receiptUncanonicalisable: true };
  const receiptP1 = receipt.p1_sha256;
  // Every digest is compared as a whole string, prefix included, with the self-describing form of
  // the recomputed digest (registry-link.md sections 3 and 4): nothing is stripped.
  const checks: Array<{ name: string; ok: boolean | null }> = [
    { name: "verification_receipt_contract", ok: true },
    { name: "receipt_bundle_id", ok: manifestBundleId !== null && receipt.bundle_id === manifestBundleId },
    { name: "receipt_p1_sha256", ok: receiptP1 === null || receiptP1 === undefined || (p1Digest !== null && receiptP1 === prefixed(p1Digest)) },
    { name: "manifest_hash", ok: fieldOk(exactStr(entry.manifest_hash), prefixed(manifestActual)) },
    { name: "receipt_manifest_sha256", ok: fieldOk(exactStr(receipt.manifest_sha256), prefixed(manifestActual)) },
    { name: "receipt_hash", ok: fieldOk(exactStr(entry.receipt_hash), prefixed(receiptSha)) },
    { name: "policy_id", ok: fieldOk(exactStr(entry.policy_id), exactStr(receipt.policy_id)) },
    { name: "policy_version", ok: fieldOk(entryPolicyMajor(entry.policy_version), receiptPolicyVersion(receipt.policy_version)) },
    { name: "reason_code_catalog_version",
      ok: fieldOk(exactStr(entry.reason_code_catalog_version), exactStr(receipt.reason_code_vocabulary_version)) },
    { name: "reason_codes", ok: fieldOk(reasonCodesKey(entry.reason_codes), reasonCodesKey(receipt.reason_codes)) },
    { name: "asset_type", ok: fieldOk(exactStr(entry.asset_type), exactStr(receipt.asset_type)) },
    { name: "status_verdict",
      ok: fieldOk(exactStr(entry.verdict),
                  typeof receipt.status === "string" ? (_STATUS_TO_VERDICT[receipt.status] ?? null) : null) },
  ];
  const anyFalse = checks.some((c) => c.ok === false);
  const hardNotTrue = checks.some((c) => _HARD_LINK_CHECKS.has(c.name) && c.ok !== true);
  return { ok: !anyFalse && !hardNotTrue, receiptUncanonicalisable: false };
}

// ---------- the authorization check: the trust registry at the operator's evaluation time ----------
// trust-registry-authorization.md section 6, row by row, in the order the table gives them, and
// the statuses each row reports. The evaluation time is the operator's (section 2) and nobody
// else's: without one, the rows that read it are skipped and authorization is not established.

/** The three authorization statuses of report-contract.md section 5.4. */
export interface TrustRegistryReport {
  /** trust-registry-authorization.md section 8, decided by section 6. */
  authorization_status: AuthorizationStatus;
  /** Section 8, or null when the evaluation stopped before the signature step. */
  signature_status: ReportedSignatureStatus | null;
  /** A root signature status of trust-root.md (its evaluation-order table), or ROOT_SIGNATURE_NOT_EVALUATED on every path that stopped before root authentication. */
  trust_registry_root_signature_status: string;
}

/** The closed authorization vocabulary of trust-registry-authorization.md section 8. */
export const AUTHORIZATION_STATUSES = [
  "AUTHORIZED_ACTIVE_KEY",
  "INVALID_REGISTRY_ENTRY",
  "INVALID_TRUST_REGISTRY",
  "ISSUER_NOT_FOUND",
  "ISSUER_KEY_NOT_FOUND",
  "TRUST_REGISTRY_AMBIGUOUS_KEY",
  "ISSUER_KEY_REVOKED",
  "ISSUER_KEY_SUSPENDED",
  "TRUST_REGISTRY_NOT_YET_EFFECTIVE",
  "TRUST_REGISTRY_EXPIRED",
  "ISSUER_KEY_NOT_YET_EFFECTIVE",
  "ISSUER_KEY_EXPIRED",
  "ISSUER_KEY_SCOPE_MISMATCH",
] as const;
export type AuthorizationStatus = (typeof AUTHORIZATION_STATUSES)[number];
/** The closed signature vocabulary of the same section, as a run reports it. */
export const SIGNATURE_STATUSES = [
  "VALID_SIGNATURE",
  "MALFORMED_SIGNATURE",
  "UNSUPPORTED_SIGNING_PAYLOAD",
  "UNSUPPORTED_SIGNATURE_ALGORITHM",
  "SIGNATURE_KEY_MISMATCH",
  "SIGNATURE_INVALID",
] as const;
export type ReportedSignatureStatus = (typeof SIGNATURE_STATUSES)[number];

/** The closed review-reason vocabulary of report-contract.md section 3.3, in its order. */
export const REVIEW_REASONS = [
  "registry_entry_verdict_requires_review",
  "verification_receipt_not_provided",
  "evaluation_time_not_provided",
  "trust_registry_not_current",
  "issuer_key_outside_validity_window",
  "trust_root_outside_validity_window",
  "trust_registry_root_not_pinned",
  "bundle_reserved_member",
  "container_extra_files",
  "bundle_extra_files",
  "canonical_input_not_provided",
  "envelope_not_provided",
  "offline_review_required",
  "vocabulary_value_unknown",
] as const;
export type ReviewReason = (typeof REVIEW_REASONS)[number];

/**
 * The review reasons that withhold the integrity check (report-contract.md section 3.2): the rows
 * from bundle_reserved_member to offline_review_required. vocabulary_value_unknown follows them and
 * withholds no check (section 3.3, row 14).
 */
const INTEGRITY_REVIEW_REASONS: ReadonlySet<ReviewReason> = new Set(
  REVIEW_REASONS.slice(REVIEW_REASONS.indexOf("bundle_reserved_member"), REVIEW_REASONS.indexOf("offline_review_required") + 1),
);

/** The checks of verification-checks.md, in their dependency order; transparency and anchoring are reserved and never requested. */
export const CHECK_NAMES = ["structure", "integrity", "link", "authorization"] as const;
export type CheckName = (typeof CHECK_NAMES)[number];

const AUTHORIZED = "AUTHORIZED_ACTIVE_KEY";
const ROOT_SIGNATURE_NOT_EVALUATED = "ROOT_SIGNATURE_NOT_EVALUATED";
/** The rows whose effect is REVIEW (section 6): a window outside the operator's evaluation time. */
const WINDOW_REVIEW: Partial<Record<AuthorizationStatus, ReviewReason>> = {
  TRUST_REGISTRY_NOT_YET_EFFECTIVE: "trust_registry_not_current",
  TRUST_REGISTRY_EXPIRED: "trust_registry_not_current",
  ISSUER_KEY_NOT_YET_EFFECTIVE: "issuer_key_outside_validity_window",
  ISSUER_KEY_EXPIRED: "issuer_key_outside_validity_window",
};
/** The root statuses whose effect is REVIEW (trust-root.md section 5, rows 9 and 10). */
const ROOT_WINDOW: ReadonlySet<string> = new Set(["ROOT_KEY_NOT_YET_VALID", "ROOT_KEY_EXPIRED"]);

interface TrustEvaluation extends TrustRegistryReport {
  /** Section 9: AUTHORIZED_ACTIVE_KEY and VALID_SIGNATURE. */
  holds: boolean;
  /** The review reason of a window row the evaluation stopped at, else null. */
  review: ReviewReason | null;
}

/**
 * Whether a supplied trust registry can be read at all (section 6, row 1): a JSON object that is
 * a strict JSON document. Its contract (row 3) is a separate question, asked after the entry's.
 */
function trustRegistryReadable(input: unknown): boolean {
  return isPlainObject(input) && !jsonValueViolatesStrictness(input);
}

/**
 * The evaluation of trust-registry-authorization.md section 6 over a registry entry and a trust
 * registry, returning at the first row that holds. `time` is the operator's evaluation time, or
 * null when none was supplied: rows 9 to 12, which read it, are then skipped, and the rows that
 * do not read it still decide (a revoked key is revoked at every instant). A run that reaches
 * VALID_SIGNATURE authenticates the registry against the roots at the same time (section 7, and
 * trust-root.md section 5); every other run reports ROOT_SIGNATURE_NOT_EVALUATED.
 */
function evaluateTrust(
  entry: ProtocolParseResult<ValidatedRegistryEntry>,
  trustInput: unknown,
  time: EvaluationTime | null,
  roots: readonly TrustRoot[] | null,
  rootsUnread = false,
): TrustEvaluation {
  const stopped = (authorizationStatus: AuthorizationStatus, signature: ReportedSignatureStatus | null = null): TrustEvaluation => ({
    authorization_status: authorizationStatus,
    signature_status: signature,
    trust_registry_root_signature_status: ROOT_SIGNATURE_NOT_EVALUATED,
    holds: false,
    review: signature === null ? (WINDOW_REVIEW[authorizationStatus] ?? null) : null,
  });
  // Row 1: the trust registry cannot be read.
  if (!trustRegistryReadable(trustInput)) return stopped("INVALID_TRUST_REGISTRY");
  // Row 2: the registry entry breaks its contract.
  if (!entry.ok) return stopped("INVALID_REGISTRY_ENTRY");
  // Row 3: the trust registry breaks its contract (section 3).
  const trust = parseTrustRegistry(trustInput as never);
  if (!trust.ok) return stopped("INVALID_TRUST_REGISTRY");
  const document = entry.value as unknown as Record<string, unknown>;
  const registry = trust.value as unknown as Record<string, unknown>;
  const entries = registry.entries as Array<Record<string, unknown>>;
  // Section 5: the issuer, then the key among the issuer's entries, by exact equality of code
  // units.
  const issuer = entries.filter((item) => item.issuer_id === document.issuer_id);
  const keys = issuer.filter((item) => item.issuer_key_id === document.issuer_key_id);
  if (issuer.length === 0) return stopped("ISSUER_NOT_FOUND"); // row 4
  if (keys.length === 0) return stopped("ISSUER_KEY_NOT_FOUND"); // row 5
  if (keys.length > 1) return stopped("TRUST_REGISTRY_AMBIGUOUS_KEY"); // row 6
  const key = keys[0]!;
  // Row 6 also: the key's point under another trust entry of the registry, in any SEC1 encoding,
  // whatever the statuses, the issuers and the key types. Revocation is of the key, not of its
  // label, so a revoked point listed again as active must not authorize.
  if (sharesPoint(entries, entries.indexOf(key))) return stopped("TRUST_REGISTRY_AMBIGUOUS_KEY");
  // Rows 7 and 8: the key's status, whatever the time (section 4).
  if (key.status === "revoked") return stopped("ISSUER_KEY_REVOKED");
  if (key.status === "suspended") return stopped("ISSUER_KEY_SUSPENDED");
  // Rows 9 to 12: the registry's window, then the key's, at the operator's evaluation time; both
  // include their bounds (section 4). Skipped without one; no issuer date stands in for it.
  if (time !== null) {
    const instant = (value: unknown): number => Date.parse(value as string);
    if (time.epoch < instant(registry.effective_at)) return stopped("TRUST_REGISTRY_NOT_YET_EFFECTIVE");
    if (time.epoch > instant(registry.expires_at)) return stopped("TRUST_REGISTRY_EXPIRED");
    if (time.epoch < instant(key.effective_from)) return stopped("ISSUER_KEY_NOT_YET_EFFECTIVE");
    if (time.epoch > instant(key.expires_at)) return stopped("ISSUER_KEY_EXPIRED");
  }
  // Row 13: the scope, by exact equality; an empty list allows nothing (section 5).
  const assetTypes = key.allowed_asset_types as string[];
  const workflows = key.allowed_workflows as string[];
  if (!assetTypes.includes(document.asset_type as string) || !workflows.includes(document.workflow as string)) {
    return stopped("ISSUER_KEY_SCOPE_MISMATCH");
  }
  // Rows 14 to 20: the signature step, against the key the trust entry authorizes, with the pair
  // of algorithm and key type held to the verifier's allowlist.
  const sig = verifyRegistryEntrySignature(document, key.public_key_hex as string, {
    expectedKeyId: key.issuer_key_id as string,
    keyType: key.key_type as string,
  });
  if (!sig.valid) return stopped(AUTHORIZED, sig.status);
  return {
    authorization_status: AUTHORIZED,
    signature_status: "VALID_SIGNATURE",
    // Roots the host failed to read authenticate nothing and are not "no root pinned": root
    // authentication is not evaluated (trust-root.md section 3).
    trust_registry_root_signature_status: rootsUnread
      ? ROOT_SIGNATURE_NOT_EVALUATED
      : authenticateTrustRegistry(trust.value, roots, time === null ? null : time.value),
    holds: true,
    review: null,
  };
}

/**
 * The evaluation of trust-registry-authorization.md section 6 on its own, over a registry entry
 * and a trust registry as a host supplies them: the three statuses of report-contract.md section
 * 5.4. A bundle verification reaches this evaluation only beside an entry that satisfies its
 * contract and a link that holds (section 1); here the entry's contract is row 2 of the order.
 *
 * A trust-root document that breaks trust-root.md section 3 throws a TrustRootError, as it does
 * from verifyBundleFiles. So does a document of a well-formed later version: verifyBundleFiles
 * reports that run as UNSUPPORTED_VERSION, and this function returns no run to report it in.
 *
 * The registry entry, the trust registry and the trust-root document are taken as parsed values:
 * parse each with this package's strict parser, as UntrustedRegistryEntryInput says.
 */
export function evaluateTrustRegistry(
  registryEntry: unknown,
  trustRegistry: unknown,
  options: Pick<VerifyOptions, "trustRoots" | "evaluationTime"> = {},
): TrustRegistryReport {
  const { roots, rootsReadFailed, rootsUnsupportedVersion, time } = resolveOptions(options);
  // A run would be UNSUPPORTED_VERSION (report-contract.md section 5.5); this returns no run, so
  // the document is refused, and roots the operator pinned are never read as no root pinned.
  if (rootsUnsupportedVersion !== null) {
    throw new TrustRootError(`trust-root document of the unsupported version ${JSON.stringify(rootsUnsupportedVersion)}`);
  }
  const entry = parseHostDocument(registryEntry, parseRegistryEntry);
  const { holds: _holds, review: _review, ...report } = evaluateTrust(entry, trustRegistry, time, roots, rootsReadFailed);
  return report;
}

/** The root statuses whose effect after an authorization that holds is REVIEW, not FAIL (trust-root.md section 5). */
const ROOT_REVIEW: ReadonlySet<string> = new Set(["NO_PINNED_TRUST_ROOT", ROOT_SIGNATURE_NOT_EVALUATED, ...ROOT_WINDOW]);

/**
 * The verdict of a trust-registry evaluation, root authentication and the evaluation time
 * included: the one a bundle run's headline folds in. Not exported from the package entries:
 * TrustRegistryReport carries the three statuses of report-contract.md section 5.4 and no verdict.
 *
 * PASS only when authorization holds (trust-registry-authorization.md section 9), a root
 * authenticated the registry (ROOT_SIGNATURE_VALID) and an evaluation time was supplied
 * (trust-root.md sections 2 and 6, trust-registry-authorization.md section 2). An authorization
 * row whose effect is a failure is FAIL, a window row REVIEW. After an authorization that holds,
 * no root pinned, root authentication not evaluated and a root window that does not hold the time
 * are REVIEW; every other root status is FAIL, a status this version does not know included.
 */
export function trustRegistryVerdict(report: TrustRegistryReport, evaluationTimeSupplied: boolean): "PASS" | "REVIEW" | "FAIL" {
  const holds = report.authorization_status === AUTHORIZED && report.signature_status === "VALID_SIGNATURE";
  if (!holds) return report.signature_status === null && WINDOW_REVIEW[report.authorization_status] !== undefined ? "REVIEW" : "FAIL";
  const root = report.trust_registry_root_signature_status;
  if (root === "ROOT_SIGNATURE_VALID") return evaluationTimeSupplied ? "PASS" : "REVIEW";
  return ROOT_REVIEW.has(root) ? "REVIEW" : "FAIL";
}

export interface VerifyOptions {
  /**
   * The registry entry, supplied as a parsed value. Parse it with this package's strict parser,
   * readDocumentPath or parseJsonStrict, never with JSON.parse (UntrustedRegistryEntryInput).
   */
  registryEntry?: UntrustedRegistryEntryInput;
  /** The trust registry, supplied as a parsed value and parsed as registryEntry is. */
  trustRegistry?: UntrustedTrustRegistryInput;
  /**
   * The trust-root document (trust-root.md section 3), supplied out of band. It is validated as a
   * whole before any evidence is read and refused with a TrustRootError when it breaks that
   * section anywhere; a document of a well-formed later version gives an UNSUPPORTED_VERSION
   * report, and evaluateTrustRegistry, which returns no run, throws a TrustRootError. The roots
   * then authenticate the trust registry (section 5). Without it an authorization that holds is
   * REVIEW. Given without a trust registry it is validated and then unused. A host that read the document from a path passes DOCUMENT_PATH_NAMES_NO_REGULAR_FILE in
   * its place when the path names no regular file and DOCUMENT_NOT_STRICT_JSON when the bytes are
   * not strict JSON, each refused with a TrustRootError, and DOCUMENT_READ_FAILED when it failed to
   * read the file, which the run reports as the host failure `trust_root_read_failed`
   * (report-contract.md sections 4 and 5.3). Parse it as registryEntry is.
   */
  trustRoots?: unknown;
  /**
   * The operator's evaluation time (trust-registry-authorization.md section 2), a calendar
   * instant of the form YYYY-MM-DDTHH:MM:SSZ: the time every window of the trust registry, its
   * keys and the trust roots is judged at. Refused with an EvaluationTimeError before any
   * evidence is read when it is empty or not such an instant. Without it authorization is not
   * established (review reason evaluation_time_not_provided). Given without a trust registry it
   * is validated and then unused.
   */
  evaluationTime?: unknown;
  /**
   * The registered vocabulary documents the operator supplies, by kind
   * (verification-vocabularies.md section 8): documents, not paths, as for trustRoots. A kind not
   * supplied is judged against the version built into this package, and two documents of one kind
   * are never merged. Each supplied document is validated before any evidence is read and refused
   * with a VocabularyError when it is not a strict JSON object (`null` included), breaks section 6,
   * or registers another kind than the key it is given under; so are DOCUMENT_PATH_NAMES_NOTHING,
   * DOCUMENT_PATH_NAMES_NO_REGULAR_FILE, DOCUMENT_READ_FAILED and DOCUMENT_NOT_STRICT_JSON in a
   * document's place, and a key that is not a kind. The report records each document held in its
   * informative member `vocabularies`; a supplied one's digest is the SHA-256 of its RFC 8785
   * canonical bytes.
   */
  vocabularies?: { asset_type?: unknown; workflow?: unknown; anchoring_method?: unknown };
}

/** The inputs a run reads before any evidence, read once at the entry point. */
interface ResolvedOptions {
  roots: TrustRoot[] | null;
  /** The host failed to read the trust-root document (DOCUMENT_READ_FAILED): no roots, and none absent. */
  rootsReadFailed: boolean;
  /** The trust-root document's version when its gate fired, else null. */
  rootsUnsupportedVersion: string | null;
  time: EvaluationTime | null;
  /** The registered vocabulary held for each kind (verification-vocabularies.md section 8). */
  vocabularies: HeldVocabularies;
}

/**
 * One vocabulary per kind: the document the operator supplied for it, else the embedded version
 * (verification-vocabularies.md section 8). Every refusal is a VocabularyError, before any
 * evidence.
 */
function resolveVocabularies(supplied: unknown): HeldVocabularies {
  const held = {} as Record<VocabularyKind, HeldVocabulary>;
  if (supplied !== undefined && !isPlainObject(supplied)) throw new VocabularyError("the vocabularies option is not an object of documents by kind");
  const given = (supplied ?? {}) as Record<string, unknown>;
  for (const key of Object.keys(given)) {
    if (!(VOCABULARY_KINDS as readonly string[]).includes(key)) throw new VocabularyError(`not a kind of registered vocabulary: ${JSON.stringify(key)}`);
  }
  for (const kind of VOCABULARY_KINDS) {
    const input = documentInput(Object.prototype.hasOwnProperty.call(given, kind) ? given[kind] : undefined);
    if (input.kind === "absent") held[kind] = embeddedVocabulary(kind);
    else if (input.kind === "nothing-found") throw new VocabularyError(`the ${kind} vocabulary is unreadable: nothing is found at the path`);
    else if (input.kind === "no-regular-file") throw new VocabularyError(`the ${kind} vocabulary is unreadable: the path names no regular file`);
    else if (input.kind === "read-failed") throw new VocabularyError(`the ${kind} vocabulary is unreadable: the host failed to read the file`);
    else if (input.kind === "not-strict-json") throw new VocabularyError(`the ${kind} vocabulary breaks verification-vocabularies.md section 6: $: not a strict JSON document`);
    else held[kind] = operatorVocabulary(kind, input.value);
  }
  return held;
}

/**
 * Read the options that are refused with an error of the host language, before any evidence is
 * read: the operator's evaluation time (trust-registry-authorization.md section 2) and the
 * trust-root document (trust-root.md section 3, report-contract.md section 4), whose version gate
 * is read before its contract.
 */
export function resolveOptions(opts: Pick<VerifyOptions, "trustRoots" | "evaluationTime" | "vocabularies">): ResolvedOptions {
  const time = opts.evaluationTime === undefined ? null : operatorEvaluationTime(opts.evaluationTime);
  const vocabularies = resolveVocabularies(opts.vocabularies);
  const input = documentInput(opts.trustRoots);
  if (input.kind === "absent") return { roots: null, rootsReadFailed: false, rootsUnsupportedVersion: null, time, vocabularies };
  // What the host found when it found no document (report-contract.md section 4): a path naming no
  // regular file is refused as a malformed document is; a file it failed to read is a host
  // failure the run reports. Neither is a document, so neither reaches the parser, whose message
  // would call it "not a JSON object".
  if (input.kind === "no-regular-file") {
    throw new TrustRootError("trust-root document unreadable: the path names no regular file");
  }
  if (input.kind === "nothing-found") {
    throw new TrustRootError("trust-root document unreadable: nothing is found at the path");
  }
  if (input.kind === "read-failed") return { roots: null, rootsReadFailed: true, rootsUnsupportedVersion: null, time, vocabularies };
  // Bytes that are not strict JSON are a malformed document, refused as trust-root.md section 3
  // refuses one; passed to the parser as `null`, they would be called "not a JSON object".
  if (input.kind === "not-strict-json") throw new TrustRootError("trust-root document malformed: the document is not a strict JSON document");
  const unsupported = trustRootDocumentUnsupportedVersion(input.value);
  if (unsupported !== null) return { roots: null, rootsReadFailed: false, rootsUnsupportedVersion: unsupported, time, vocabularies };
  return { roots: parseTrustRoots(input.value), rootsReadFailed: false, rootsUnsupportedVersion: null, time, vocabularies };
}

/**
 * The error codes of report-contract.md section 5.3 this verifier can emit, in the order of that
 * table, which is the order a report lists them in. The codes of the table that are not here
 * refuse a ZIP archive, which this verifier does not read (`invalid_zip`, `archive_unsafe_member`,
 * `archive_safety_limit`, `archive_load_failed`), or name a fault of a process
 * (`internal_error`), which a library interface raises instead of reporting.
 */
export const ERROR_CODES = [
  "input_not_found",
  "bundle_root_invalid",
  "unsupported_input",
  "filesystem_error",
  "bundle_inventory_failed",
  "bundle_member_name_invalid",
  "unsafe_bundle_member",
  "manifest_verification_failed",
  "manifest_read_failed",
  "p1_verification_failed",
  "p1_read_failed",
  "envelope_verification_failed",
  "envelope_incomplete",
  "envelope_read_failed",
  "verification_receipt_contract_violation",
  "registry_link_verification_failed",
  "registry_entry_contract_violation",
  "registry_entry_verdict_fail",
  "registry_link_read_failed",
  "trust_registry_requires_registry_entry",
  "trust_registry_requires_valid_registry_entry",
  "trust_registry_read_failed",
  "trust_root_read_failed",
  "trust_registry_root_not_authenticated",
  "unsupported_version",
] as const;
export type ErrorCode = (typeof ERROR_CODES)[number];

/** The codes of section 5.3 whose class is host: the host failed an operation, or found nothing at the operator's path. */
export const HOST_ERROR_CODES: ReadonlySet<ErrorCode> = new Set<ErrorCode>([
  "input_not_found", "filesystem_error", "bundle_inventory_failed", "manifest_read_failed", "p1_read_failed",
  "envelope_read_failed", "registry_link_read_failed", "trust_registry_read_failed", "trust_root_read_failed",
]);

/** The object names of the version gates (report-contract.md section 5.5). */
export type VersionedObject = "trust_root_document" | "manifest" | "verification_receipt" | "reason_code_vocabulary" | "registry_entry" | "signing_payload" | "trust_registry";

/** An error of the report: the `code` is normative (report-contract.md section 2), and for `unsupported_version` its `object` and `version`; the message is for a reader. */
export interface VerifyError {
  code: ErrorCode;
  message: string;
  object?: VersionedObject;
  version?: string;
}

export interface VerifyReport {
  /** Section 3.1: an evidence outcome, or `UNSUPPORTED_VERSION` or `HOST_FAILURE`. */
  status: ReportStatus;
  /** `PASS`, `FAIL` or `REVIEW`, and null for a status that is not an evidence outcome. */
  verdict: ReportVerdict | null;
  exit_code: number;
  /** `reason` by report-contract.md section 5.2. */
  outcome: { reason: string };
  /** The errors of section 5.3, in the order of its table; the list of codes is normative. */
  errors: VerifyError[];
  /** Section 3.2: the checks the caller's inputs requested, in the dependency order. */
  checks_requested: CheckName[];
  /** Section 3.2: the requested checks that were established, a prefix of checks_requested. */
  checks_established: CheckName[];
  /** Informative: the requested checks the run reached. */
  checks_evaluated: CheckName[];
  /** Section 3.3: every review reason that holds, in its order; empty unless the run is OFFLINE_REVIEW. */
  review_reasons: ReviewReason[];
  /** The operator's evaluation time as supplied, or null. */
  evaluation_time: string | null;
  /** Informative detail for a reader (section 5.1). */
  notes: string[];
  /** The authorization statuses when the trust registry was evaluated (section 5.4), else null. */
  trust_registry: TrustRegistryReport | null;
  checks: Record<string, unknown>;
  /** Informative: the registered vocabulary document held for each kind (verification-vocabularies.md section 8). */
  vocabularies: Record<VocabularyKind, VocabularyRecord>;
}

const VERDICT: Record<ReportStatus, ReportVerdict | null> = {
  OFFLINE_OK: "PASS", OFFLINE_FAIL: "FAIL", OFFLINE_REVIEW: "REVIEW", UNSUPPORTED_VERSION: null, HOST_FAILURE: null,
};

/** Errors as the table lists them: in its order, and no code twice. */
function orderedErrors(found: VerifyError[]): VerifyError[] {
  const first = new Map<ErrorCode, VerifyError>();
  for (const error of found) if (!first.has(error.code)) first.set(error.code, error);
  return ERROR_CODES.filter((code) => first.has(code)).map((code) => first.get(code)!);
}

/** What the rules of report-contract.md section 5.2 read off an evidence run. */
interface RunFacts {
  status: string;
  errors: VerifyError[];
  entrySupplied: boolean;
  trustEvaluated: boolean;
  /** The trust registry stopped at a row whose effect is a failure. */
  trustFailed: boolean;
  /** The link was evaluated and does not hold. */
  linkFailed: boolean;
  reviewReasons: ReviewReason[];
  manifestFailed: boolean;
  p1Failed: boolean;
  envelopeFailed: boolean;
}

/** report-contract.md section 5.2: the value of the first rule that applies to the run. */
function outcomeReason(f: RunFacts): string {
  const ok = f.status === STATUS_OFFLINE_OK;
  if (f.errors.length > 0) return f.errors[0]!.code; // 1
  if (ok && f.trustEvaluated) return "local_integrity_registry_link_and_trust_checks_passed"; // 2
  if (ok && f.entrySupplied) return "local_integrity_and_registry_link_checks_passed"; // 3
  if (ok) return "local_integrity_checks_passed"; // 4
  if (f.trustEvaluated && f.trustFailed) return "trust_registry_verification_failed"; // 5
  if (f.entrySupplied && f.linkFailed) return "registry_link_verification_failed"; // 6
  if (f.status === STATUS_OFFLINE_REVIEW) return f.reviewReasons[0]!; // 7
  // Rules 8 to 10 name a layer whose own outcome is OFFLINE_FAIL, never one that is only
  // OFFLINE_REVIEW.
  if (f.manifestFailed) return "manifest_integrity_failed"; // 8
  if (f.p1Failed) return "p1_integrity_failed"; // 9
  if (f.envelopeFailed) return "envelope_integrity_or_link_failed"; // 10
  return "offline_verification_failed"; // 11
}

/** Section 3.2: what the caller's inputs request, and no option changes it. */
function checksRequested(opts: VerifyOptions): CheckName[] {
  const requested: CheckName[] = ["structure", "integrity"];
  if (opts.registryEntry !== undefined) requested.push("link");
  if (opts.trustRegistry !== undefined) requested.push("authorization");
  return requested;
}

/**
 * A registry entry or trust registry handed over by the host is held to the same strictness as
 * a bundle member (input strictness: depth, rules 2 to 4 and 9) before its contract is parsed.
 * The walk is iterative: an entry nested 20000 levels deep is a failed parse, not a RangeError.
 */
function parseHostDocument<T>(input: unknown, parse: (value: never) => ProtocolParseResult<T>): ProtocolParseResult<T> {
  if (jsonValueViolatesStrictness(input)) return { ok: false, errors: ["$: not a strict JSON document"] };
  return parse(input as never);
}

const DEFAULT_CHECKS = (opts: VerifyOptions): Record<string, unknown> => ({
  manifest_sha256: false,
  manifest_files: false,
  p1_sha256: false,
  canonical_input_present: false,
  p1_input_hash: false,
  envelope_present: false,
  envelope_sha256: false,
  envelope_links: false,
  registry_signature: "UNSUPPORTED",
  registry_link: opts.registryEntry === undefined ? null : false,
  trust_registry: opts.trustRegistry === undefined || opts.registryEntry === undefined ? null : false,
});

const NULL_CHECKS = (): Record<string, unknown> => ({
  manifest_sha256: null, manifest_files: null, p1_sha256: null, canonical_input_present: null, p1_input_hash: null,
  envelope_present: null, envelope_sha256: null, envelope_links: null, registry_signature: "UNSUPPORTED",
  registry_link: null, trust_registry: null,
});

/** The members every report built here shares. */
function reportOf(opts: VerifyOptions, resolved: ResolvedOptions, status: ReportStatus, exitCode: number, reason: string, errors: VerifyError[],
  checks: Record<string, unknown>, evaluated: CheckName[]): VerifyReport {
  return {
    status,
    verdict: VERDICT[status],
    exit_code: exitCode,
    outcome: { reason },
    errors,
    checks_requested: checksRequested(opts),
    checks_established: [],
    checks_evaluated: evaluated,
    review_reasons: [],
    evaluation_time: resolved.time === null ? null : resolved.time.value,
    notes: [],
    trust_registry: null,
    checks,
    vocabularies: vocabulariesRecord(resolved.vocabularies),
  };
}

/**
 * The report for content that escaped every per-check containment: a refusal, never a throw.
 * No layer reported anything, so the reason is rule 11 of report-contract.md section 5.2.
 */
function failClosedReport(opts: VerifyOptions, resolved: ResolvedOptions): VerifyReport {
  return reportOf(opts, resolved, STATUS_OFFLINE_FAIL, EXIT_OFFLINE_FAIL, "offline_verification_failed", [], DEFAULT_CHECKS(opts), ["structure"]);
}

/**
 * The report of a run whose input was refused as a whole (report-contract.md section 5.3, the
 * rows from `input_not_found` to `filesystem_error`): the one error, nothing evaluated, and the
 * per-check results bundle-objects.md section 6 states for such a run. A host-class row is
 * HOST_FAILURE, a content-class row OFFLINE_FAIL (section 3.1, rule 3).
 */
function refusedInputReport(opts: VerifyOptions, resolved: ResolvedOptions, error: VerifyError): VerifyReport {
  const host = HOST_ERROR_CODES.has(error.code);
  return reportOf(opts, resolved, host ? STATUS_HOST_FAILURE : STATUS_OFFLINE_FAIL, host ? EXIT_HOST_FAILURE : EXIT_OFFLINE_FAIL,
    error.code, [error], DEFAULT_CHECKS(opts), host ? [] : ["structure"]);
}

/** The report of a run a version gate stopped (report-contract.md section 5.5). */
function unsupportedVersionReport(opts: VerifyOptions, resolved: ResolvedOptions, object: VersionedObject, version: string): VerifyReport {
  const error: VerifyError = { code: "unsupported_version", message: `${object} carries the unsupported version ${version}`, object, version };
  return reportOf(opts, resolved, STATUS_UNSUPPORTED_VERSION, EXIT_UNSUPPORTED_VERSION, "unsupported_version", [error], NULL_CHECKS(), []);
}

/**
 * What a host that read the bundle's container tells the core before any member is read.
 *
 * `refusal` is an error of the rows that refuse the input as a whole; the run reports it alone.
 * `errors` are the container's other errors (`bundle_inventory_failed`,
 * `bundle_member_name_invalid`, `unsafe_bundle_member`); every other check is still computed on
 * what the reader returns. `manifestEntry` says whether an entry named manifest.json exists in the
 * container, of any kind; when the host does not say, the core asks the reader.
 */
export interface Containment {
  refusal?: VerifyError | null;
  errors?: VerifyError[];
  manifestEntry?: boolean;
}

/**
 * Verify a bundle from any reader (in-memory or fs-backed). I/O-free.
 *
 * No bundle member, registry entry or trust registry content makes this throw: a document the
 * parser or the canonicalizer refuses is a failed check. A trust-root or vocabulary document
 * that is not strict JSON is refused before any evidence is read, with TrustRootError or
 * VocabularyError. Only JsonParseError and CanonicalizationError are
 * contained; any other exception, a stack the host ran out of included, is a fault and
 * propagates.
 *
 * The registry entry, the trust registry and the trust-root document are taken as parsed values:
 * parse each with this package's strict parser, as UntrustedRegistryEntryInput says.
 */
export function verifyBundleFiles(reader: BundleReader, opts: VerifyOptions = {}): VerifyReport {
  return verifyBundleWithContainment(reader, opts, {}, resolveOptions(opts));
}

/**
 * verifyBundleFiles for a reader whose host has already judged the bundle's container (see
 * Containment), with the options the host resolved before it touched the input. Used by
 * verifyBundle; not exported from the package entry points.
 */
export function verifyBundleWithContainment(reader: BundleReader, opts: VerifyOptions, containment: Containment, resolved: ResolvedOptions): VerifyReport {
  // Gate 1 runs at invocation, before any evidence (report-contract.md section 5.5).
  if (resolved.rootsUnsupportedVersion !== null) return unsupportedVersionReport(opts, resolved, "trust_root_document", resolved.rootsUnsupportedVersion);
  // Nothing found at the path of a supplied registry entry or trust registry refuses the run as a
  // whole, whatever else is supplied, and input_not_found is the first row of the table, before
  // any refusal of the bundle (report-contract.md sections 4 and 5.3).
  if (documentInput(opts.registryEntry).kind === "nothing-found") return refusedInputReport(opts, resolved, error("input_not_found", "nothing is found at the registry entry's path"));
  if (documentInput(opts.trustRegistry).kind === "nothing-found") return refusedInputReport(opts, resolved, error("input_not_found", "nothing is found at the trust registry's path"));
  if (containment.refusal) return refusedInputReport(opts, resolved, containment.refusal);
  try {
    return verifyBundleFilesUncontained(reader, opts, containment, resolved);
  } catch (err) {
    if (isContainedError(err)) return failClosedReport(opts, resolved);
    throw err;
  }
}

function error(code: ErrorCode, message: string): VerifyError {
  return { code, message };
}

/**
 * Run a layer; a BundleReadError from the reader is the layer's `*_read_failed` error. The layer
 * is then refused (bundle-objects.md section 6): `unread` gives its result, whose checks are false
 * and whose presence flags still record what the verifier saw, never absence for a host failure.
 */
function layer<T>(run: () => T, unread: () => T, onReadFailure: (message: string) => void): T {
  try {
    return run();
  } catch (err) {
    if (!(err instanceof BundleReadError)) throw err;
    onReadFailure(err.message);
    return unread();
  }
}

/**
 * Run a bundle layer and judge its two rows each on its own (report-contract.md section 5.3). A
 * BundleReadError, or a host failure on a member the layer reads that it did not reach, is its read
 * row: the layer is then refused (`unread`), and its verification row is judged over the members
 * the host did read. A layer refused for what it read keeps its result, and its read row still
 * holds when the host fails to read another of its members.
 */
function judgedLayer<T extends { refused: string | null }>(
  run: () => T,
  unread: () => T,
  readFailure: () => string | null,
  refusalOfReadMembers: () => string | null,
): { result: T; readFailed: string | null; refused: string | null } {
  let readFailed: string | null;
  try {
    const result = run();
    readFailed = readFailure();
    if (readFailed === null || result.refused !== null) return { result, readFailed, refused: result.refused };
  } catch (err) {
    if (!(err instanceof BundleReadError)) throw err;
    readFailed = err.message;
  }
  return { result: unread(), readFailed, refused: refusalOfReadMembers() };
}

/** Whether the reader has a member named exactly manifest.json, without reading it into a document. */
function hasManifestMember(reader: BundleReader, members: Set<string> | null): boolean {
  if (members !== null) return members.has("manifest.json");
  try {
    return typeof reader.readBytes === "function" ? reader.readBytes("manifest.json") !== null : reader.readText("manifest.json") !== null;
  } catch (err) {
    if (err instanceof BundleReadError) return true; // it exists; the manifest layer reports the failure
    throw err;
  }
}

/** A version identifier of the form `v<n>` (document-contracts.md, "Version gate"). */
const VERSION_GRAMMAR = /^v[1-9][0-9]{0,8}$/;
const BUNDLE_VERSION_GRAMMAR = /^loquitur\.bundle\.v[1-9][0-9]{0,8}$/;
const VOCABULARY_GRAMMAR = /^loquitur\.reason_codes\.v[1-9][0-9]{0,8}$/;
const PAYLOAD_ID_GRAMMAR = /^registry_entry_signing_payload_v[1-9][0-9]{0,8}$/;

/** A gate that fires: the object and the identifier as it reads. */
type Gate = { object: VersionedObject; version: string };

/** The gate of one versioned member: well formed and not the supported value fires it. */
function gateOf(object: VersionedObject, value: unknown, grammar: RegExp, supported: string): Gate | null {
  return typeof value === "string" && grammar.test(value) && value !== supported ? { object, version: value } : null;
}

/** Gates 3 and 4 over a receipt, 5 to 7 over a registry entry, and 8 over a trust registry (document-contracts.md, "Version gate"). */
function receiptGate(receipt: unknown): Gate | null {
  if (!isPlainObject(receipt) || receipt.object_type !== "verification_receipt") return null;
  return gateOf("verification_receipt", receipt.schema_version, VERSION_GRAMMAR, "v2")
    ?? gateOf("reason_code_vocabulary", receipt.reason_code_vocabulary_version, VOCABULARY_GRAMMAR, REASON_CODE_VOCABULARY);
}
function entryGate(entry: unknown): Gate | null {
  if (!isPlainObject(entry) || jsonValueViolatesStrictness(entry) || entry.object_type !== "registry_entry") return null;
  const gate = gateOf("registry_entry", entry.schema_version, VERSION_GRAMMAR, "v1")
    ?? gateOf("reason_code_vocabulary", entry.reason_code_catalog_version, VOCABULARY_GRAMMAR, REASON_CODE_VOCABULARY);
  if (gate !== null) return gate;
  const signature = entry.signature;
  if (!isPlainObject(signature)) return null;
  const id = signature.payload_id;
  const version = signature.payload_version;
  // The canonical numeric model: 2.0 is the integer 2.
  if (typeof id !== "string" || !PAYLOAD_ID_GRAMMAR.test(id)) return null;
  if (typeof version !== "number" || !Number.isInteger(version) || version < 1 || version > 999999999) return null;
  if (id === "registry_entry_signing_payload_v2" && version === 2) return null;
  return { object: "signing_payload", version: `${id}/${version}` };
}
function trustRegistryGate(registry: unknown): Gate | null {
  if (!trustRegistryReadable(registry) || (registry as Record<string, unknown>).object_type !== "trust_registry") return null;
  return gateOf("trust_registry", (registry as Record<string, unknown>).schema_version, VERSION_GRAMMAR, "v1");
}

/** A JSON member as loaded, or nothing when the host failed to read it: a gate reads only what was read. */
function loadedValue(reader: BundleReader, name: string): unknown {
  const member = attempt(() => readJsonMember(reader, name));
  return member !== UNREAD && loadedObject(member) ? member.value : undefined;
}

/** Bundle members at a reserved name (bundle-objects.md section 1): not evidence this version defines. */
function reservedName(name: string): boolean {
  return name.startsWith("attestations/") || name === "document_index.json" || name === "claims_openings.json";
}

/** Errors whose holding means the `structure` check is not established (report-contract.md section 3.2). */
const STRUCTURE_ERRORS: ReadonlySet<ErrorCode> = new Set<ErrorCode>([
  "bundle_inventory_failed", "bundle_member_name_invalid", "unsafe_bundle_member", "manifest_verification_failed",
  "manifest_read_failed", "p1_verification_failed", "p1_read_failed", "envelope_verification_failed", "envelope_incomplete",
  "envelope_read_failed", "verification_receipt_contract_violation",
]);

function verifyBundleFilesUncontained(host: BundleReader, opts: VerifyOptions, containment: Containment, resolved: ResolvedOptions): VerifyReport {
  const errors: VerifyError[] = [...(containment.errors ?? [])];
  const listing = typeof host.listMembers === "function" ? host.listMembers() : null;
  const members = Array.isArray(listing) ? new Set(listing.filter((name) => typeof name === "string")) : null;
  const reader = runReader(host, members);
  // A listed name that is not a portable member name cannot be a member: no manifest can declare
  // it, and the Node reader and the Python verifier refuse the listing that holds one before the
  // host is handed its name (bundle-objects.md sections 1 and 2); so do two listed names that
  // conflict. Every reader is held to that rule, a map reader included.
  if (members !== null && [...members].some((name) => !memberNameValid(name))) {
    errors.push(error("bundle_member_name_invalid", "a member name is not a portable member name"));
  } else if (members !== null && conflictingNames([...members]).size > 0) {
    errors.push(error("bundle_member_name_invalid", "two member names conflict under ASCII case folding"));
  }
  // The bundle root: a directory input with no member named exactly manifest.json is refused as
  // a whole (report-contract.md section 5.3, `bundle_root_invalid`).
  const manifestEntry = containment.manifestEntry ?? hasManifestMember(reader, members);
  if (!manifestEntry) return refusedInputReport(opts, resolved, error("bundle_root_invalid", "no member named manifest.json"));

  // The version gates the bundle and the entry carry, in the table's order, read after input
  // strictness and before any contract; the first that fires stops the run.
  const entryInput = documentInput(opts.registryEntry);
  const trustInput = documentInput(opts.trustRegistry);
  const manifestValue = loadedValue(reader, "manifest.json");
  const gate = (isPlainObject(manifestValue) ? gateOf("manifest", manifestValue.schema_version, BUNDLE_VERSION_GRAMMAR, MANIFEST_SCHEMA_VERSION) : null)
    ?? receiptGate(loadedValue(reader, "verification_receipt.json"))
    ?? (entryInput.kind === "document" ? entryGate(entryInput.value) : null);
  if (gate !== null) return unsupportedVersionReport(opts, resolved, gate.object, gate.version);

  const judgedManifest = judgedLayer(
    () => verifyManifest(reader),
    () => manifestUnread(reader),
    () => hostReadFailure(reader, MANIFEST_MEMBERS),
    () => manifestRefusalOfReadMembers(reader),
  );
  const m = judgedManifest.result;
  if (judgedManifest.refused !== null) errors.push(error("manifest_verification_failed", judgedManifest.refused));
  if (judgedManifest.readFailed !== null) errors.push(error("manifest_read_failed", judgedManifest.readFailed));
  const judgedP1 = judgedLayer(
    () => verifyP1(reader),
    () => p1Unread(reader),
    () => hostReadFailure(reader, P1_MEMBERS),
    () => p1RefusalOfReadMembers(reader),
  );
  const p1 = judgedP1.result;
  if (judgedP1.refused !== null) errors.push(error("p1_verification_failed", judgedP1.refused));
  if (judgedP1.readFailed !== null) errors.push(error("p1_read_failed", judgedP1.readFailed));
  // A layer the host failed to read is unread, not failed: what depends on its digest is not
  // evaluated either, and the run is HOST_FAILURE unless something else fails.
  const manifestUnreadByHost = judgedManifest.readFailed !== null && judgedManifest.refused === null;
  const p1UnreadByHost = judgedP1.readFailed !== null && judgedP1.refused === null;
  // The P1 digest the links compare is known when p1.json and its sidecar were read and P1 verified
  // on its own, whatever the host did with canonical_input.json (bundle-objects.md section 4).
  const p1DigestUnread = p1UnreadByHost && p1.p1_actual === null;
  // The receipt is a closed contract, validated whenever the bundle carries one, whichever
  // checks are requested (registry-link.md section 2).
  const receipt = layer(() => readReceipt(reader), () => RECEIPT_UNREAD, (why) => errors.push(error("registry_link_read_failed", why)));
  if (receipt.present && !receipt.readFailed && !receipt.contractOk) {
    errors.push(error("verification_receipt_contract_violation", "verification_receipt.json is not a strict JSON object satisfying its contract"));
  }
  // The envelope layer reads the envelope and its sidecar whenever either is present
  // (bundle-objects.md section 6), also when it lacks the other and verifies neither.
  const judgedEnvelope = judgedLayer(
    () => verifyEnvelope(reader, m.manifest_verified, p1.p1_actual, m.manifest_verified === null ? null : m.manifest!.bundle_id, manifestUnreadByHost, p1DigestUnread),
    () => envelopeUnread(reader),
    () => envelopeReadFailure(reader),
    () => envelopeRefusalOfReadMembers(reader),
  );
  const env = judgedEnvelope.result;
  if (judgedEnvelope.refused !== null) errors.push(error("envelope_verification_failed", judgedEnvelope.refused));
  // Exactly one of the envelope and its sidecar (bundle-objects.md section 4), judged on its own.
  if (seen(reader, "envelope_env1.json") !== seen(reader, "envelope.sha256")) {
    errors.push(error("envelope_incomplete", "exactly one of envelope_env1.json and envelope.sha256 is present"));
  }
  if (judgedEnvelope.readFailed !== null) errors.push(error("envelope_read_failed", judgedEnvelope.readFailed));
  const envelopeUnreadByHost = judgedEnvelope.readFailed !== null && judgedEnvelope.refused === null;

  // A trust registry says which issuers may sign registry entries; without an entry there is
  // nothing for it to authorize (registry-link.md section 7). The registry is not parsed.
  const entrySupplied = entryInput.kind !== "absent";
  const trustSupplied = trustInput.kind !== "absent";
  const trustWithoutEntry = trustSupplied && !entrySupplied;
  if (trustWithoutEntry) errors.push(error("trust_registry_requires_registry_entry", "a trust registry was supplied without a registry entry"));
  // What the host found at the entry's path, when it found no document there (report-contract.md
  // section 5.3): no regular file, or a file it failed to read.
  const entryNoFile = entryInput.kind === "no-regular-file";
  const entryReadFailed = entryInput.kind === "read-failed";
  const entryUnread = entryNoFile || entryReadFailed;
  const entryDocument = entryInput.kind === "document" ? entryInput.value : undefined;
  const entryReadable = entryInput.kind === "document" && isPlainObject(entryDocument) && !jsonValueViolatesStrictness(entryDocument);
  const entryNotStrictJson = entryInput.kind === "not-strict-json" || (entryInput.kind === "document" && !entryReadable);
  const parsedEntry: ProtocolParseResult<ValidatedRegistryEntry> | null = !entrySupplied
    ? null
    : entryReadable
      ? parseRegistryEntry(entryDocument as never)
      : { ok: false, errors: [entryNoFile ? "$: the registry entry's path names no regular file" : entryReadFailed ? "$: the host failed to read the registry entry" : "$: the registry entry is not a strict JSON object"] };
  // The rows of the link result are read in order (registry-link.md section 5): a link whose input
  // is absent or unread is null whatever else holds. A bundle with no receipt has nothing to link:
  // the link is not established, which is a review reason, not an error.
  const noReceipt = !receipt.present;
  const rl: LinkResult | null = parsedEntry === null
    ? null
    : receipt.readFailed || entryUnread || noReceipt || manifestUnreadByHost || p1DigestUnread
      ? { ok: null, receiptUncanonicalisable: false }
      : parsedEntry.ok
        ? verifyRegistryLink(receipt, parsedEntry.value, m.manifest_actual,
          m.manifest !== null && nonBlankString(m.manifest.bundle_id) ? m.manifest.bundle_id : null, p1.p1_actual)
        : { ok: false, receiptUncanonicalisable: receiptCannotBeCanonicalised(receipt) };
  // The link's errors (report-contract.md section 5.3), each a predicate over the inputs, judged on
  // its own.
  const receiptUncanonicalisable = rl !== null && rl.receiptUncanonicalisable;
  const linkRefused = entrySupplied && (entryNoFile || entryNotStrictJson || receiptUncanonicalisable);
  if (linkRefused) errors.push(error("registry_link_verification_failed", entryNoFile ? "the registry entry's path names no regular file" : entryNotStrictJson ? "the registry entry is not a strict JSON object" : "the receipt cannot be canonicalized"));
  if (entryReadFailed) errors.push(error("registry_link_read_failed", "the host failed to read the registry entry"));
  if (entryReadable && receipt.isObject && parsedEntry !== null && !parsedEntry.ok) {
    errors.push(error("registry_entry_contract_violation", parsedEntry.errors.join("; ")));
  }
  const committed: string | null = parsedEntry !== null && parsedEntry.ok ? parsedEntry.value.verdict : null;
  if (committed === "FAIL" && !linkRefused) errors.push(error("registry_entry_verdict_fail", "the registry entry commits the verdict FAIL"));
  if (trustSupplied && entrySupplied && (entryNoFile || receiptUncanonicalisable)) {
    errors.push(error("trust_registry_requires_valid_registry_entry", "the registry entry's link could not be evaluated"));
  }
  // The trust registry is evaluated only beside an entry that satisfies its contract and a link
  // that holds (registry-link.md section 7), whether or not an evaluation time was supplied; its
  // version gate is read when it is read.
  const trustEvaluable = trustSupplied && !trustWithoutEntry && parsedEntry !== null && parsedEntry.ok && rl !== null && rl.ok === true;
  if (trustEvaluable) {
    const trustGate = trustRegistryGate(opts.trustRegistry);
    if (trustGate !== null) return unsupportedVersionReport(opts, resolved, trustGate.object, trustGate.version);
  }
  // A trust registry the host failed to read is not evaluated: no row of its evaluation is a
  // finding about bytes nobody read (report-contract.md section 5.3, trust_registry_read_failed).
  const trustReadFailed = trustEvaluable && trustInput.kind === "read-failed";
  if (trustReadFailed) errors.push(error("trust_registry_read_failed", "the host failed to read the trust registry"));
  // A trust-root document the host failed to read, beside a trust registry and a registry entry, is
  // a host failure judged on its own; root authentication is not evaluated (trust-root.md section
  // 3).
  if (resolved.rootsReadFailed && trustSupplied && entrySupplied) {
    errors.push(error("trust_root_read_failed", "the host failed to read the trust-root document"));
  }
  const tr = trustEvaluable && !trustReadFailed
    ? evaluateTrust(parsedEntry!, opts.trustRegistry, resolved.time, resolved.roots, resolved.rootsReadFailed)
    : null;

  // Root authentication (trust-root.md sections 5 and 6): roots supplied that stop at a status
  // whose effect is a failure fail the run with the error; a window outside the evaluation time
  // is REVIEW; no root supplied is REVIEW; roots that authenticate, no downgrade. Roots the host
  // failed to read were supplied and were not evaluated: neither a failure nor a review.
  // The run reads the trust registry's verdict, the one trustRegistryVerdict gives every caller, so
  // the headline and the evaluation never part: a FAIL after an authorization that holds is a root
  // that did not authenticate the registry, and a FAIL before it an authorization row that failed.
  const rootsSupplied = resolved.roots !== null || resolved.rootsReadFailed;
  const rootStatus = tr === null ? null : tr.trust_registry_root_signature_status;
  const trustVerdict = tr === null ? null : trustRegistryVerdict(tr, resolved.time !== null);
  const rootWindow = tr !== null && tr.holds && rootsSupplied && ROOT_WINDOW.has(rootStatus!);
  const rootFailed = tr !== null && tr.holds && trustVerdict === "FAIL";
  if (rootFailed) errors.push(error("trust_registry_root_not_authenticated", `root authentication returned ${rootStatus}`));
  const trustFailed = tr !== null && !tr.holds && trustVerdict === "FAIL";

  // Completeness (bundle-objects.md section 1). A member the manifest does not declare, other than
  // the structural names, is evidence nobody committed to (bundle_extra_files); a member at a
  // reserved name is not evidence this version defines (bundle_reserved_member), declared or not.
  // A reader that cannot list its members cannot show there is none (offline_review_required).
  let extraFiles = false;
  let reservedFound = false;
  if (members !== null) {
    reservedFound = [...members].some(reservedName);
    if (m.manifest !== null && isPlainObject(m.manifest.files)) {
      const declared = new Set(Object.keys(m.manifest.files));
      extraFiles = [...members].some((name) => !declared.has(name) && !UNDECLARED_ALLOWED.has(name) && !reservedName(name));
    }
  }

  // Row 14 of report-contract.md section 3.3 (verification-vocabularies.md section 7): the
  // receipt's asset_type when the receipt satisfies its contract, and the entry's asset_type and
  // workflow when the run judged the entry's contract (both documents are objects, section 5.3) and
  // it holds. An unknown anchor.method decides nothing: the anchor is outside the signature, and it
  // is noted.
  const vocabularyUnknown: string[] = [];
  const vocabularyNotes: string[] = [];
  const unknown = (value: unknown, kind: VocabularyKind): boolean => vocabularyValueStatus(value, resolved.vocabularies[kind]) === "unknown";
  if (receipt.present && !receipt.readFailed && receipt.contractOk && unknown((receipt.value as Record<string, unknown>).asset_type, "asset_type")) {
    vocabularyUnknown.push("verification_receipt.asset_type");
  }
  if (entryReadable && receipt.isObject && parsedEntry !== null && parsedEntry.ok) {
    const entry = parsedEntry.value as unknown as Record<string, unknown>;
    if (unknown(entry.asset_type, "asset_type")) vocabularyUnknown.push("registry_entry.asset_type");
    if (unknown(entry.workflow, "workflow")) vocabularyUnknown.push("registry_entry.workflow");
    if (isPlainObject(entry.anchor) && unknown(entry.anchor.method, "anchoring_method")) {
      vocabularyNotes.push("vocabulary_value_unknown:registry_entry.anchor.method");
    }
  }
  vocabularyNotes.push(...vocabularyUnknown.map((member) => `vocabulary_value_unknown:${member}`));

  const ordered = orderedErrors(errors);
  const contentError = ordered.some((e) => !HOST_ERROR_CODES.has(e.code));
  const hostError = ordered.some((e) => HOST_ERROR_CODES.has(e.code));
  const manifestFailed = !manifestUnreadByHost && !m.ok;
  const p1Failed = !p1UnreadByHost && p1.status === STATUS_OFFLINE_FAIL;
  const envelopeFailed = !envelopeUnreadByHost && env.status === STATUS_OFFLINE_FAIL;
  const linkFailed = rl !== null && rl.ok === false;
  const failure = contentError || manifestFailed || p1Failed || envelopeFailed || linkFailed || committed === "FAIL" || trustFailed;

  const reasons: ReviewReason[] = [];
  const reason = (holds: boolean, name: ReviewReason): void => {
    if (holds) reasons.push(name);
  };
  reason(committed === "WARN" || committed === "REVIEW", "registry_entry_verdict_requires_review");
  reason(entrySupplied && noReceipt, "verification_receipt_not_provided");
  reason(tr !== null && resolved.time === null && !trustFailed && !rootFailed, "evaluation_time_not_provided");
  reason(tr !== null && tr.review === "trust_registry_not_current", "trust_registry_not_current");
  reason(tr !== null && tr.review === "issuer_key_outside_validity_window", "issuer_key_outside_validity_window");
  reason(rootWindow, "trust_root_outside_validity_window");
  reason(tr !== null && tr.holds && !rootsSupplied, "trust_registry_root_not_pinned");
  reason(reservedFound, "bundle_reserved_member");
  // container_extra_files never holds: this verifier reads no archive.
  reason(extraFiles, "bundle_extra_files");
  reason(!p1UnreadByHost && judgedP1.refused === null && p1.status === STATUS_OFFLINE_REVIEW, "canonical_input_not_provided");
  reason(env.absent, "envelope_not_provided");
  reason(members === null, "offline_review_required");
  reason(vocabularyUnknown.length > 0, "vocabulary_value_unknown");

  const status = failure ? STATUS_OFFLINE_FAIL : hostError ? STATUS_HOST_FAILURE : reasons.length > 0 ? STATUS_OFFLINE_REVIEW : STATUS_OFFLINE_OK;
  const evidence = status !== STATUS_HOST_FAILURE;
  const reviewReasons = status === STATUS_OFFLINE_REVIEW ? reasons : [];

  const checks: Record<string, unknown> = {
    manifest_sha256: m.present ? m.manifest_sha256_ok : false,
    manifest_files: m.present && !ordered.some((e) => e.code === "bundle_inventory_failed" || e.code === "bundle_member_name_invalid" || e.code === "unsafe_bundle_member") ? m.files_ok : false,
    p1_sha256: p1.p1_sha256_ok,
    canonical_input_present: p1.canonical_input_present,
    p1_input_hash: p1.input_hash_ok,
    envelope_present: env.envelope_present,
    envelope_sha256: env.envelope_sha256_ok,
    // bundle-objects.md section 6: beside both the envelope and its sidecar, a link to a layer the
    // host failed to read does not hold (false) in the per-check results, though it fails nothing
    // in the run: the host failure decides the status (report-contract.md section 3.1).
    envelope_links: env.links_ok === null && (manifestUnreadByHost || p1DigestUnread) && env.envelope_present && env.envelope_sha256_ok !== null
      && exists(reader, "envelope.sha256") ? false : env.links_ok,
    // Only an authorization run evaluates the issuer signature.
    registry_signature: tr?.signature_status ?? "UNSUPPORTED",
    registry_link: rl ? rl.ok : null,
    trust_registry: tr ? tr.holds : null,
  };

  // Section 3.2: each check established only when every check before it is.
  const requested = checksRequested(opts);
  const structureOk = !ordered.some((e) => STRUCTURE_ERRORS.has(e.code)) && !(receipt.readFailed)
    && m.shape_ok && judgedP1.refused === null && !p1UnreadByHost && env.shape_ok;
  const integrityOk = structureOk && (["manifest_sha256", "manifest_files", "p1_sha256", "p1_input_hash", "envelope_sha256", "envelope_links"] as const).every((name) => checks[name] === true)
    && !reasons.some((name) => INTEGRITY_REVIEW_REASONS.has(name));
  const linkOk = integrityOk && rl !== null && rl.ok === true;
  const authorizationOk = linkOk && trustVerdict === "PASS";
  const holds = new Map<CheckName, boolean>([["structure", structureOk], ["integrity", integrityOk], ["link", linkOk], ["authorization", authorizationOk]]);
  const established: CheckName[] = [];
  if (evidence) for (const name of requested) {
    if (holds.get(name) !== true) break;
    established.push(name);
  }
  const evaluated: CheckName[] = !evidence ? [] : requested.filter((name) =>
    name === "structure" || name === "integrity" || (name === "link" ? rl !== null && rl.ok !== null : tr !== null));

  const notes: string[] = [];
  if (extraFiles) notes.push("bundle_extra_files");
  if (reservedFound) notes.push("bundle_reserved_member");
  if (tr !== null) {
    if (rootStatus === "ROOT_SIGNATURE_VALID") notes.push("trust_registry_root_signature_verified");
    else notes.push(`trust_registry_root_signature_not_verified:${rootStatus!.toLowerCase()}`);
    if (rootFailed) notes.push("trust_registry_root_signature_required_but_not_verified");
  }
  notes.push(...vocabularyNotes);
  const trust_registry: TrustRegistryReport | null = tr === null ? null : {
    authorization_status: tr.authorization_status,
    signature_status: tr.signature_status,
    trust_registry_root_signature_status: tr.trust_registry_root_signature_status,
  };
  const outcome = outcomeReason({
    status, errors: ordered, entrySupplied, trustEvaluated: tr !== null, trustFailed, linkFailed, reviewReasons,
    manifestFailed, p1Failed, envelopeFailed,
  });
  return {
    status,
    verdict: VERDICT[status] ?? null,
    exit_code: EXIT[status] ?? EXIT_INTERNAL_ERROR,
    outcome: { reason: outcome },
    errors: ordered,
    checks_requested: requested,
    checks_established: established,
    checks_evaluated: evaluated,
    review_reasons: reviewReasons,
    evaluation_time: resolved.time === null ? null : resolved.time.value,
    notes,
    trust_registry,
    checks,
    vocabularies: vocabulariesRecord(resolved.vocabularies),
  };
}
