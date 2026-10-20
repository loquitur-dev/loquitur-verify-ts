// Trust-registry root authentication, written from loquitur-protocol
// docs/specification/trust-root.md: the trust-root document and its whole-document validation
// (section 3), the exact signing message (section 4) and the evaluation order with its status
// vocabulary (section 5). No node:* import, so it runs in every entry point.
import { sha256 } from "@noble/hashes/sha256";
import { CanonicalizationError, canonicalJsonBytes } from "./canonical.js";
import { isCalendarInstant } from "./instant.js";
import { isPlainObject, jsonValueViolatesStrictness } from "./json-strictness.js";
import { defineJsonMember } from "./json-member.js";
import { signatureAlgorithmSupported, signaturePairSupported } from "./cryptographic-capabilities.js";
import { verifySecp256k1Sha256Digest } from "./signature.js";
import { sharesPoint } from "./key-point.js";
import { nonBlankString } from "./whitespace.js";

/**
 * The refusal of a trust-root document (trust-root.md section 3). A library interface refuses a
 * document that breaks that section anywhere with this error, before it reads any evidence and
 * before it evaluates any row of section 5, and returns no report (report-contract.md section 4).
 */
export class TrustRootError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TrustRootError";
  }
}

/** One well-formed root of the document: the closed field set of section 3, types as written. */
export interface TrustRoot {
  /** Matched against the trust registry's `signature.key_id`, code unit for code unit. */
  readonly key_id: string;
  /** The key type identifier; the verifier's allowlist decides at root authentication whether it is supported. */
  readonly key_type: string;
  /** Lowercase hexadecimal; for `secp256k1`, the uncompressed SEC1 point `04 || X || Y`, 130 characters. */
  readonly public_key_hex: string;
  /** `YYYY-MM-DDTHH:MM:SSZ`, a calendar instant. */
  readonly not_before: string;
  /** `YYYY-MM-DDTHH:MM:SSZ`, a calendar instant, strictly later than `not_before`. */
  readonly not_after: string;
  /** `active` (the default when the member is absent) or `revoked`. */
  readonly status: "active" | "revoked";
}

const ROOT_MEMBERS: ReadonlySet<string> = new Set(["key_id", "key_type", "public_key_hex", "not_before", "not_after", "status"]);
const ROOT_REQUIRED = ["key_id", "key_type", "public_key_hex", "not_before", "not_after"] as const;
const DOCUMENT_MEMBERS: ReadonlySet<string> = new Set(["object_type", "schema_version", "roots"]);
/** The trust-root document's type and the one version this verifier supports (document-contracts.md, "Version gate"). */
const TRUST_ROOT_DOCUMENT_TYPE = "trust_root_document";
const TRUST_ROOT_DOCUMENT_VERSION = "v1";
const VERSION_GRAMMAR = /^v[1-9][0-9]{0,8}$/;
/** Section 3: a key type identifier, as the signature algorithm identifiers are written. */
const KEY_TYPE = /^[a-z0-9][a-z0-9_]{0,63}$/;
/** Section 3: `public_key_hex` is lowercase hexadecimal of 1 to 512 bytes, and is not lower-cased first. */
const ROOT_PUBLIC_KEY = /^(?:[0-9a-f]{2}){1,512}$/;
/** Section 3: for the key type `secp256k1`, the uncompressed SEC1 point. */
const SECP256K1_PUBLIC_KEY = /^04[0-9a-f]{128}$/;
/** Section 3: the form of `not_before` and `not_after`; each is also a calendar instant. */
const ROOT_INSTANT = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/;
const ROOT_STATUSES: ReadonlySet<string> = new Set(["active", "revoked"]);

/** Whether `value` is an instant of the form section 3 gives, naming a calendar instant. */
function rootInstant(value: unknown): value is string {
  return typeof value === "string" && ROOT_INSTANT.test(value) && isCalendarInstant(value);
}

/**
 * The version gate of the trust-root document (document-contracts.md, "Version gate", gate 1): a
 * strict JSON object whose `object_type` is `trust_root_document` and whose `schema_version` is a
 * well-formed version identifier other than `v1` fires it, and the run is UNSUPPORTED_VERSION.
 * Anything else does not fire it and is judged by section 3. Read before the contract.
 */
export function trustRootDocumentUnsupportedVersion(document: unknown): string | null {
  if (!isPlainObject(document) || jsonValueViolatesStrictness(document)) return null;
  if (document.object_type !== TRUST_ROOT_DOCUMENT_TYPE) return null;
  const version = document.schema_version;
  if (typeof version !== "string" || !VERSION_GRAMMAR.test(version) || version === TRUST_ROOT_DOCUMENT_VERSION) return null;
  return version;
}

/**
 * Read a trust-root document, validating the whole of it against section 3: the document itself
 * and every element of its array, whatever the element's `key_id` and whether or not any trust
 * registry names it. A document that breaks the section anywhere is refused as a whole with a
 * TrustRootError; nothing is converted, defaulted or read in part. A document of a well-formed
 * later version is not malformed: the caller asks trustRootDocumentUnsupportedVersion first.
 *
 * The document is a JSON object carrying exactly `object_type` (`trust_root_document`),
 * `schema_version` (`v1`) and `roots`, a non-empty array. Each element is an object on the
 * closed field set of the section: `key_id`, a string with a code point outside the whitespace
 * set W; `key_type`, an identifier; `public_key_hex`, lowercase hexadecimal of 1 to 512 bytes and,
 * for `secp256k1`, `^04[0-9a-f]{128}$`; `not_before` and `not_after`, calendar instants of the
 * exact form with `not_after` strictly later; and `status`, absent or one of `active` and
 * `revoked`.
 *
 * It reads a value, not bytes: parse the document with readDocumentPath or parseJsonStrict, never
 * with JSON.parse, or a duplicate member or an over-precise number is gone before this sees it
 * (canonicalization-and-hashing.md section 6).
 */
export function parseTrustRoots(document: unknown): TrustRoot[] {
  const refuse: (why: string) => never = (why) => {
    throw new TrustRootError(`trust-root document malformed: ${why}`);
  };
  if (!isPlainObject(document)) refuse("the document is not a JSON object");
  if (jsonValueViolatesStrictness(document)) refuse("the document is not a strict JSON document");
  for (const name of Object.keys(document)) {
    if (!DOCUMENT_MEMBERS.has(name)) refuse(`the document carries a member outside the closed set: ${name}`);
  }
  for (const name of DOCUMENT_MEMBERS) {
    if (!Object.prototype.hasOwnProperty.call(document, name)) refuse(`the document has no ${name}`);
  }
  if (document.object_type !== TRUST_ROOT_DOCUMENT_TYPE) refuse(`object_type is not ${TRUST_ROOT_DOCUMENT_TYPE}`);
  if (document.schema_version !== TRUST_ROOT_DOCUMENT_VERSION) refuse(`schema_version is not ${TRUST_ROOT_DOCUMENT_VERSION}`);
  const elements = document.roots;
  if (!Array.isArray(elements)) refuse("roots is not an array");
  if (elements.length === 0) refuse("roots is empty");
  return elements.map((element, index) => parseRoot(element, `roots[${index}]`, refuse));
}

function parseRoot(element: unknown, where: string, refuse: (why: string) => never): TrustRoot {
  if (!isPlainObject(element)) refuse(`${where} is not an object`);
  for (const name of Object.keys(element)) {
    if (!ROOT_MEMBERS.has(name)) refuse(`${where} carries a member outside the closed field set: ${name}`);
  }
  for (const name of ROOT_REQUIRED) {
    if (!Object.prototype.hasOwnProperty.call(element, name)) refuse(`${where} has no ${name}`);
  }
  const { key_id, key_type, public_key_hex, not_before, not_after } = element;
  if (typeof key_id !== "string") refuse(`${where}.key_id is not a string`);
  if (!nonBlankString(key_id)) refuse(`${where}.key_id is empty: no code point outside the whitespace set W`);
  if (typeof key_type !== "string" || !KEY_TYPE.test(key_type)) refuse(`${where}.key_type is not a key type identifier`);
  if (typeof public_key_hex !== "string" || !ROOT_PUBLIC_KEY.test(public_key_hex)) {
    refuse(`${where}.public_key_hex is not lowercase hexadecimal of 1 to 512 bytes`);
  }
  if (key_type === "secp256k1" && !SECP256K1_PUBLIC_KEY.test(public_key_hex)) {
    refuse(`${where}.public_key_hex is not an uncompressed SEC1 point of 130 lowercase hexadecimal characters`);
  }
  if (!rootInstant(not_before)) refuse(`${where}.not_before is not a calendar instant of the form YYYY-MM-DDTHH:MM:SSZ`);
  if (!rootInstant(not_after)) refuse(`${where}.not_after is not a calendar instant of the form YYYY-MM-DDTHH:MM:SSZ`);
  if (!(Date.parse(not_after) > Date.parse(not_before))) refuse(`${where}: not_after is not strictly later than not_before`);
  let status: TrustRoot["status"] = "active";
  if (Object.prototype.hasOwnProperty.call(element, "status")) {
    const value = element.status;
    if (typeof value !== "string" || !ROOT_STATUSES.has(value)) refuse(`${where}.status is not active or revoked`);
    status = value as TrustRoot["status"];
  }
  return { key_id, key_type, public_key_hex, not_before, not_after, status };
}

/**
 * Hold caller-built roots to section 3 as the document path holds them: each is re-read as an
 * element of a document, so a root with a non-calendar bound, an upper-case key or another status
 * is refused with a TrustRootError at every interface, not only when it came in a document.
 */
function validatedRoots(roots: readonly TrustRoot[]): TrustRoot[] {
  const refuse: (why: string) => never = (why) => {
    throw new TrustRootError(`trust root malformed: ${why}`);
  };
  return roots.map((root, index) => parseRoot(root, `roots[${index}]`, refuse));
}

// ---------- section 4: the exact signing message ----------

/** The segments of the ASCII prefix, each followed by a NUL byte: LOQUITUR 00 TRUST_REGISTRY 00 ROOT_SIGNATURE 00 V1 00. */
const ROOT_SIGNING_DOMAIN_SEGMENTS = ["LOQUITUR", "TRUST_REGISTRY", "ROOT_SIGNATURE", "V1"] as const;
export const ROOT_SIGNING_DOMAIN_PREFIX: Uint8Array = Uint8Array.from(
  ROOT_SIGNING_DOMAIN_SEGMENTS.map((segment) => `${segment}\u0000`).join(""),
  (character) => character.charCodeAt(0),
);
const ROOT_SIGNING_ENVELOPE_DOMAIN = "org.loquitur.protocol.trust-registry-root-signature";
const ROOT_SIGNING_ENVELOPE_SCHEMA = "loquitur.trust_registry_root_signing_envelope.v1";
const ROOT_SIGNING_ENVELOPE_VERSION = 1;
const ROOT_SIGNING_PAYLOAD_SCHEMA = "loquitur.trust_registry.v1";
const ROOT_SIGNATURE_ALGORITHM = "secp256k1_ecdsa_sha256";

/** The trust registry with its `signature` member removed and nothing else removed. */
function rootSigningPayload(registry: Record<string, unknown>): Record<string, unknown> {
  const payload: Record<string, unknown> = {};
  for (const [name, value] of Object.entries(registry)) {
    // Defined, not assigned: a member named __proto__ stays a member of the payload.
    if (name !== "signature") defineJsonMember(payload, name, value);
  }
  return payload;
}

/** The closed root signing envelope of section 4 over a trust registry. */
export function trustRegistryRootSigningEnvelope(registry: Record<string, unknown>): Record<string, unknown> {
  return {
    domain: ROOT_SIGNING_ENVELOPE_DOMAIN,
    envelope_schema: ROOT_SIGNING_ENVELOPE_SCHEMA,
    envelope_version: ROOT_SIGNING_ENVELOPE_VERSION,
    payload: rootSigningPayload(registry),
    payload_schema: ROOT_SIGNING_PAYLOAD_SCHEMA,
    signature_algorithm: ROOT_SIGNATURE_ALGORITHM,
  };
}

/** The bytes a root signs over a trust registry: the prefix, then the RFC 8785 bytes of the envelope. */
export function trustRegistrySigningMessageBytes(registry: Record<string, unknown>): Uint8Array {
  const envelope = canonicalJsonBytes(trustRegistryRootSigningEnvelope(registry));
  const message = new Uint8Array(ROOT_SIGNING_DOMAIN_PREFIX.length + envelope.length);
  message.set(ROOT_SIGNING_DOMAIN_PREFIX, 0);
  message.set(envelope, ROOT_SIGNING_DOMAIN_PREFIX.length);
  return message;
}

// ---------- section 5: the evaluation order and the status vocabulary ----------

export type RootSignatureStatus =
  | "NO_PINNED_TRUST_ROOT"
  | "MALFORMED_TRUST_REGISTRY"
  | "MALFORMED_SIGNATURE"
  | "UNSUPPORTED_SIGNATURE_ALGORITHM"
  | "UNKNOWN_ROOT_KEY"
  | "AMBIGUOUS_ROOT_KEY"
  | "ROOT_KEY_REVOKED"
  | "ROOT_KEY_NOT_YET_VALID"
  | "ROOT_KEY_EXPIRED"
  | "ROOT_SIGNATURE_INVALID"
  | "ROOT_SIGNATURE_VALID";

/** `r || s` as exactly 128 lowercase hexadecimal characters (section 4.2). */
const ROOT_SIGNATURE_HEX = /^[0-9a-f]{128}$/;

/**
 * Authenticate a trust registry against roots at the operator's evaluation time, in the order of
 * section 5, returning the status of the first condition that holds. The roots are held to
 * section 3 first, whoever built them. The evaluation time is the operator's
 * (trust-registry-authorization.md section 2), never the system clock and never an issuer's date;
 * `null` means none was supplied, and rows 9 and 10, which read it, are then skipped. The trust
 * registry is a parsed value: parse it with readDocumentPath or parseJsonStrict, never JSON.parse.
 */
export function authenticateTrustRegistry(
  registry: unknown,
  roots: readonly TrustRoot[] | null,
  evaluationTime: string | null,
): RootSignatureStatus {
  if (evaluationTime !== null && !rootInstant(evaluationTime)) throw new TrustRootError("the evaluation time is not a calendar instant of the form YYYY-MM-DDTHH:MM:SSZ");
  if (roots === null || roots.length === 0) return "NO_PINNED_TRUST_ROOT";
  const checked = validatedRoots(roots);
  if (!isPlainObject(registry)) return "MALFORMED_TRUST_REGISTRY";
  const signature = registry.signature;
  if (!isPlainObject(signature)) return "MALFORMED_SIGNATURE";
  // Row 4: the algorithm, from the verifier's own allowlist, never from the input.
  if (!signatureAlgorithmSupported(signature.algorithm)) return "UNSUPPORTED_SIGNATURE_ALGORITHM";
  const value = signature.signature;
  if (typeof value !== "string" || !ROOT_SIGNATURE_HEX.test(value)) return "MALFORMED_SIGNATURE";
  // The key is found by exact equality of code units with the roots' key_id; a key_id of another
  // type matches no root.
  const matched = checked.filter((root) => root.key_id === signature.key_id);
  if (matched.length === 0) return "UNKNOWN_ROOT_KEY";
  if (matched.length > 1) return "AMBIGUOUS_ROOT_KEY";
  const root = matched[0]!;
  // Row 7 also: the root's point under another key_id, in any SEC1 encoding, whatever the other
  // root's status or key type. signature.key_id is not signed, so a revoked root pinned again as
  // an active one with the same point would otherwise authenticate.
  if (sharesPoint(checked, checked.indexOf(root))) return "AMBIGUOUS_ROOT_KEY";
  // Revocation before the window: a root revoked inside a lapsed window is reported as revoked.
  if (root.status === "revoked") return "ROOT_KEY_REVOKED";
  // Rows 9 and 10: the window, bounds included, at the evaluation time; skipped without one.
  if (evaluationTime !== null) {
    const at = Date.parse(evaluationTime);
    if (at < Date.parse(root.not_before)) return "ROOT_KEY_NOT_YET_VALID";
    if (at > Date.parse(root.not_after)) return "ROOT_KEY_EXPIRED";
  }
  // Row 11: the pair of the signature's algorithm and the matched root's key type.
  if (!signaturePairSupported(signature.algorithm, root.key_type)) return "UNSUPPORTED_SIGNATURE_ALGORITHM";
  let message: Uint8Array;
  try {
    message = trustRegistrySigningMessageBytes(registry);
  } catch (err) {
    // A registry that cannot be canonicalized cannot be the registry that was signed. A RangeError
    // is a stack the host ran out of on a value rule 6 admits: a fault of the host, never a
    // verdict.
    if (err instanceof CanonicalizationError) return "ROOT_SIGNATURE_INVALID";
    throw err;
  }
  // Whether the point lies on the curve is decided here, not by the document's validity: a point
  // off the curve verifies nothing (section 3).
  return verifySecp256k1Sha256Digest(sha256(message), value, root.public_key_hex) ? "ROOT_SIGNATURE_VALID" : "ROOT_SIGNATURE_INVALID";
}
