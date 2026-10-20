// Domain-separated secp256k1 ECDSA-SHA256 verification for registry entries.
import { secp256k1 } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import { hexToBytes } from "@noble/hashes/utils";
import { CanonicalizationError, canonicalJsonBytes, sha256Uri } from "./canonical.js";
import { signaturePairSupported, type SupportedSignatureAlgorithm } from "./cryptographic-capabilities.js";
import { rethrowHostStackFault } from "./json-strictness.js";
import { defineJsonMember } from "./json-member.js";

export const SIGNATURE_ALGORITHM = "secp256k1_ecdsa_sha256" satisfies SupportedSignatureAlgorithm;
export const SIGNING_PAYLOAD_ID = "registry_entry_signing_payload_v2";
export const SIGNING_PAYLOAD_VERSION = 2;
export const SIGNING_ENVELOPE_DOMAIN = "org.loquitur.protocol.registry-entry-signature";
export const SIGNING_ENVELOPE_SCHEMA = "loquitur.signing_envelope.v2";
export const SIGNING_PAYLOAD_SCHEMA = "loquitur.registry_entry.v1";
// The NUL-delimited domain-separation prefix, derived from its segments rather than
// hand-typed as bytes. The Python verifier builds the same prefix from the same segments; a
// literal byte array would be an asymmetry, because a wrong integer is not a compile error: it is
// a silent failure to verify anything a conforming signer produces. Every segment is
// ASCII by construction, so one character is one byte.
const SIGNING_DOMAIN_SEGMENTS = ["LOQUITUR", "REGISTRY_ENTRY", "SIGNATURE", "V2"] as const;
export const SIGNING_DOMAIN_PREFIX = Uint8Array.from(
  SIGNING_DOMAIN_SEGMENTS.map((segment) => `${segment}\u0000`).join(""),
  (character) => character.charCodeAt(0),
);
const SIGNING_PAYLOAD_EXCLUDED_FIELDS = new Set(["signature", "anchor", "anchored_at"]);

function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0); out.set(b, a.length); return out;
}

export function registryEntrySigningPayload(entry: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(entry)) {
    // Defined, not assigned: `out[k] = v` with k === "__proto__" sets the prototype of `out`
    // and drops the member, so the payload signed would not be the payload given.
    if (!SIGNING_PAYLOAD_EXCLUDED_FIELDS.has(k)) {
      defineJsonMember(out, k, v);
    }
  }
  return out;
}

export function registryEntrySigningEnvelope(entry: Record<string, unknown>): Record<string, unknown> {
  return {
    domain: SIGNING_ENVELOPE_DOMAIN,
    envelope_schema: SIGNING_ENVELOPE_SCHEMA,
    envelope_version: SIGNING_PAYLOAD_VERSION,
    payload: registryEntrySigningPayload(entry),
    payload_id: SIGNING_PAYLOAD_ID,
    payload_schema: SIGNING_PAYLOAD_SCHEMA,
    signature_algorithm: SIGNATURE_ALGORITHM,
  };
}

export function registryEntrySigningMessageBytes(entry: Record<string, unknown>): Uint8Array {
  return concatBytes(SIGNING_DOMAIN_PREFIX, canonicalJsonBytes(registryEntrySigningEnvelope(entry)));
}

export function registryEntrySigningPayloadDigest(entry: Record<string, unknown>): Uint8Array {
  return sha256(registryEntrySigningMessageBytes(entry));
}

export function registryEntrySigningPayloadHash(entry: Record<string, unknown>): string {
  return sha256Uri(registryEntrySigningMessageBytes(entry));
}

/** The closed signature-status vocabulary of trust-registry-authorization.md section 8. */
export type SignatureStatus =
  | "VALID_SIGNATURE"
  | "SIGNATURE_INVALID"
  | "SIGNATURE_KEY_MISMATCH"
  | "UNSUPPORTED_SIGNATURE_ALGORITHM"
  | "UNSUPPORTED_SIGNING_PAYLOAD"
  | "MALFORMED_SIGNATURE";

export interface SignatureVerificationResult {
  valid: boolean;
  status: SignatureStatus;
  signingPayloadId?: string;
  signingPayloadVersion?: number;
}

export interface SignatureVerificationOptions {
  /**
   * The `issuer_key_id` of the trust entry that authorizes the key: both `signature.key_id` and
   * the entry's `issuer_key_id` must equal it (trust-registry-authorization.md section 6, rows 18
   * and 19). Required.
   *
   * `signature` is excluded from the signed payload, so `key_id` is rewritable in transit
   * by anyone: without this comparison a relabeled entry would verify. The Python
   * verifier rejects a mismatch on both fields, and so does this one; two
   * verifiers that disagree on the same signed artifact defeat the cross-implementation
   * agreement the protocol rests on. A call that supplies no string here is
   * SIGNATURE_KEY_MISMATCH, never VALID_SIGNATURE.
   */
  expectedKeyId: string;
  /**
   * The `key_type` of the same trust entry: the pair of the signature's algorithm and this key
   * type must be in the verifier's allowlist (section 6, row 16). Required. A call that supplies
   * no string here is UNSUPPORTED_SIGNATURE_ALGORITHM, never VALID_SIGNATURE.
   */
  keyType: string;
}

// The only signature encoding the protocol defines is `r || s`, 64 bytes, with low s
// (canonicalization-and-hashing.md §4, cryptographic-capabilities.md). Asking for
// `lowS` alone is not enough. Given bytes and no format, @noble/curves tries DER first
// and falls back to compact only when DER parsing fails, and a DER signature whose two
// integers are 29 bytes each is exactly 64 bytes long: it passes the length and hex checks
// above, and the Python verifier, which only ever reads the two halves as r and s,
// returns SIGNATURE_INVALID for it. Stating the format makes the library read the bytes the
// way the specification and the other verifier do.
const COMPACT_LOW_S = { lowS: true, format: "compact" } as const;
// `r || s` as 128 lowercase hex characters, and an uncompressed public key as 04 plus 128.
const SIGNATURE_HEX = /^[0-9a-f]{128}$/;
const PUBLIC_KEY_HEX = /^04[0-9a-f]{128}$/;

/**
 * Verify a registry_entry signature, in the order of trust-registry-authorization.md section 6,
 * rows 14 to 20: no signature object, then the signing payload, the pair of algorithm and key
 * type from the verifier's allowlist, the form of the value, and only then the key ids; whatever
 * is well formed and does not verify is SIGNATURE_INVALID, a public key that is not of the form
 * of its key type included. This version defines no earlier signing payload: a signature object
 * without payload_id and payload_version, or with values of another type, is
 * UNSUPPORTED_SIGNING_PAYLOAD here, and breaks the entry's contract in a bundle run. Nothing is
 * coerced: an array holding the v2 identifier is not the identifier.
 *
 * The signature object is not signed: `signature.key_id` is a label anyone can rewrite. Resolve
 * `publicKeyHex`, `options.expectedKeyId` and `options.keyType` from the one trust entry the
 * trust registry holds for the entry's (`issuer_id`, `issuer_key_id`), never from
 * `signature.key_id`. A valid result says only that this key signed this payload under that
 * label; whether the key may sign for the issuer is the trust registry's question, which
 * evaluateTrustRegistry and verifyBundle answer. Both options are required, and a call without
 * them is never VALID_SIGNATURE: no key type is UNSUPPORTED_SIGNATURE_ALGORITHM (row 16) and no
 * key id is SIGNATURE_KEY_MISMATCH (row 18).
 */
export function verifyRegistryEntrySignature(
  entry: Record<string, unknown>,
  publicKeyHex: string,
  options: SignatureVerificationOptions,
): SignatureVerificationResult {
  // Read defensively: a JavaScript caller, or a cast, can still omit the options or a member.
  const keyType: unknown = options !== null && typeof options === "object" ? options.keyType : undefined;
  const expectedKeyId: unknown = options !== null && typeof options === "object" ? options.expectedKeyId : undefined;
  const sigObj = entry["signature"];
  if (sigObj === null || typeof sigObj !== "object" || Array.isArray(sigObj)) {
    return { valid: false, status: "MALFORMED_SIGNATURE" };
  }
  const signature = sigObj as Record<string, unknown>;
  const payloadIdRaw = signature["payload_id"];
  const payloadVersionRaw = signature["payload_version"];
  const payloadId = typeof payloadIdRaw === "string" ? payloadIdRaw : undefined;
  const payloadVersion = typeof payloadVersionRaw === "number" && Number.isInteger(payloadVersionRaw) ? payloadVersionRaw : undefined;
  if (payloadId !== SIGNING_PAYLOAD_ID || payloadVersion !== SIGNING_PAYLOAD_VERSION) {
    return { valid: false, status: "UNSUPPORTED_SIGNING_PAYLOAD", signingPayloadId: payloadId, signingPayloadVersion: payloadVersion };
  }
  const described = { signingPayloadId: payloadId, signingPayloadVersion: payloadVersion };
  const algorithm = signature["algorithm"];
  // Without a key type no pair is in the allowlist: the algorithm alone is never enough.
  if (!signaturePairSupported(algorithm, keyType)) {
    return { valid: false, status: "UNSUPPORTED_SIGNATURE_ALGORITHM", ...described };
  }
  // Lowercase hexadecimal only, as every digest and signature of the protocol is written, and
  // as the Python verifiers read them. No case folding, so a value the other implementation
  // refuses is not a value this one accepts. Not a string is not a signature either (7 is not
  // the string "7").
  const sigHex = signature["signature"];
  if (typeof sigHex !== "string" || !SIGNATURE_HEX.test(sigHex)) {
    return { valid: false, status: "MALFORMED_SIGNATURE", ...described };
  }
  // Checked before any cryptography: an entry whose declared key does not match the
  // authorized one must never reach signature verification, or a valid signature by
  // an authorized key would launder an unauthorized label. Compared as written, whatever the
  // ids hold (trust-registry-authorization.md sections 5 and 6, rows 18 and 19): a key id made
  // only of the whitespace set W is compared like any other, so a signature key_id of U+00A0
  // beside an authorized key id of U+0020 is a mismatch. No authorized key id matches nothing.
  if (typeof expectedKeyId !== "string") return { valid: false, status: "SIGNATURE_KEY_MISMATCH", ...described };
  if (signature["key_id"] !== expectedKeyId) return { valid: false, status: "SIGNATURE_KEY_MISMATCH", ...described };
  if (entry["issuer_key_id"] !== expectedKeyId) return { valid: false, status: "SIGNATURE_KEY_MISMATCH", ...described };
  // A public key that cannot be used does not verify anything: SIGNATURE_INVALID, as for a key
  // that is well formed and off the curve.
  if (!PUBLIC_KEY_HEX.test(publicKeyHex)) {
    return { valid: false, status: "SIGNATURE_INVALID", ...described };
  }
  const invalid = { valid: false, status: "SIGNATURE_INVALID" as const, ...described };
  let digest: Uint8Array;
  try {
    digest = registryEntrySigningPayloadDigest(entry);
  } catch (err) {
    // A payload that cannot be canonicalized cannot be the payload that was signed. A RangeError is
    // a stack the host ran out of on a value rule 6 admits: a fault of the host, never a verdict.
    if (err instanceof CanonicalizationError) return invalid;
    throw err;
  }
  // Everything that reaches here is well formed, so whatever does not verify is SIGNATURE_INVALID
  // (trust-registry-authorization.md section 6, rows 17 and 20), as a root signature is judged
  // (trust-root.md section 5: form is row 5 (MALFORMED_SIGNATURE), verification row 12
  // (ROOT_SIGNATURE_INVALID)), and as in the Python verifier.
  // @noble/curves throws, rather than returning false, when r or s is 0 or not below the curve
  // order; that throw is SIGNATURE_INVALID too, as a high s, for which it returns false, is.
  let ok: boolean;
  try {
    ok = secp256k1.verify(hexToBytes(sigHex), digest, hexToBytes(publicKeyHex), COMPACT_LOW_S);
  } catch (err) {
    rethrowHostStackFault(err);
    ok = false;
  }
  return ok ? { valid: true, status: "VALID_SIGNATURE", ...described } : invalid;
}

export function verifySecp256k1Sha256Digest(
  digest: Uint8Array,
  signatureCompactHex: string,
  publicKeyHex: string,
): boolean {
  if (digest.length !== 32) return false;
  if (typeof signatureCompactHex !== "string" || !SIGNATURE_HEX.test(signatureCompactHex)) return false;
  if (typeof publicKeyHex !== "string" || !PUBLIC_KEY_HEX.test(publicKeyHex)) return false;
  try {
    return secp256k1.verify(hexToBytes(signatureCompactHex), digest, hexToBytes(publicKeyHex), COMPACT_LOW_S);
  } catch (err) {
    rethrowHostStackFault(err);
    return false;
  }
}
