import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { secp256k1 } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import {
  SIGNING_DOMAIN_PREFIX,
  SIGNING_ENVELOPE_DOMAIN,
  SIGNING_ENVELOPE_SCHEMA,
  SIGNING_PAYLOAD_ID,
  SIGNING_PAYLOAD_SCHEMA,
  SIGNING_PAYLOAD_VERSION,
  registryEntrySigningEnvelope,
  registryEntrySigningMessageBytes,
  registryEntrySigningPayloadDigest,
  registryEntrySigningPayload,
  registryEntrySigningPayloadHash,
  verifyRegistryEntrySignature,
  verifySecp256k1Sha256Digest,
} from "../src/signature.ts";
import { registryEntryGroundsErrors } from "../src/verdict-grounds.ts";
import { parseRegistryEntry } from "../src/protocol-input.ts";

const here = dirname(fileURLToPath(import.meta.url));
const g = JSON.parse(readFileSync(join(here, "../test-vectors/signature.json"), "utf-8"));
/** The key id and key type of the trust entry that authorizes the demo key. */
const BOUND = { expectedKeyId: g.signed_entry.issuer_key_id as string, keyType: "secp256k1" };

/** The signed demo entry with its signature object changed by `fn`, nothing else. */
function withSignature(fn: (signature: Record<string, unknown>) => void): Record<string, unknown> {
  const entry = JSON.parse(JSON.stringify(g.signed_entry));
  fn(entry.signature);
  return entry;
}

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

test("v2 constants and binary domain prefix match the canonical vector", () => {
  assert.equal(SIGNING_PAYLOAD_ID, g.payload_id);
  assert.equal(SIGNING_PAYLOAD_VERSION, g.payload_version);
  assert.equal(hex(SIGNING_DOMAIN_PREFIX), g.domain_prefix_hex);
  assert.equal(SIGNING_ENVELOPE_DOMAIN, g.signing_envelope.domain);
  assert.equal(SIGNING_ENVELOPE_SCHEMA, g.signing_envelope.envelope_schema);
  assert.equal(SIGNING_PAYLOAD_SCHEMA, g.signing_envelope.payload_schema);
});

test("v2 envelope and exact message bytes equal the Python golden", () => {
  assert.deepEqual(registryEntrySigningEnvelope(g.signed_entry), g.signing_envelope);
  assert.equal(hex(registryEntrySigningMessageBytes(g.signed_entry)), g.signing_message_hex);
  assert.equal(registryEntrySigningPayloadHash(g.signed_entry), g.signing_payload_sha256);
});

test("valid v2 demo signature verifies with bound metadata", () => {
  const r = verifyRegistryEntrySignature(g.signed_entry, g.public_key_hex, BOUND);
  assert.equal(r.valid, true);
  // The status of trust-registry-authorization.md section 8, which the vector declares.
  assert.equal(r.status, "VALID_SIGNATURE");
  assert.equal(r.status, g.expected.valid_status);
  assert.equal(r.signingPayloadId, SIGNING_PAYLOAD_ID);
  assert.equal(r.signingPayloadVersion, SIGNING_PAYLOAD_VERSION);
});

test("tampered entry fails", () => {
  const r = verifyRegistryEntrySignature(g.tampered_entry, g.public_key_hex, BOUND);
  assert.equal(r.valid, false);
  assert.equal(r.status, "SIGNATURE_INVALID");
});

// The vector's point is that a signature does not survive a change to what it covers, which
// it can only make if the changed entry is otherwise the signed one and is still a well-formed
// entry. A tampering that contradicted the entry's own grounds would describe a document a
// verifier refuses before any signature is read, and a test asking only for a refused signature
// would stay green on it.
test("the tampered entry differs in one covered field and is otherwise a well-formed entry", () => {
  const moved = Object.keys(g.signed_entry).filter(
    (field) => JSON.stringify(g.signed_entry[field]) !== JSON.stringify(g.tampered_entry[field]),
  );
  assert.deepEqual(moved, ["manifest_hash"]);
  assert.deepEqual(g.tampered_entry.signature, g.signed_entry.signature);
  assert.deepEqual(registryEntryGroundsErrors(g.tampered_entry), []);
  assert.equal(parseRegistryEntry(g.tampered_entry as never).ok, true);
});

test("wrong public key fails", () => {
  const p = g.public_key_hex;
  const flipped = p.slice(0, 30) + (p[30] === "a" ? "b" : "a") + p.slice(31);
  assert.equal(verifyRegistryEntrySignature(g.signed_entry, flipped, BOUND).valid, false);
});

// No earlier signing payload is defined (signing-envelope-v2.md): a signature object without
// payload_id and payload_version is not a payload the step reads, and breaks the entry's contract.
test("a signature without its payload members is not an earlier payload, and breaks the entry's contract", () => {
  const stripped = withSignature((signature) => { delete signature.payload_id; delete signature.payload_version; });
  const r = verifyRegistryEntrySignature(stripped, g.public_key_hex, BOUND);
  assert.deepEqual([r.valid, r.status], [false, "UNSUPPORTED_SIGNING_PAYLOAD"]);
  assert.equal(parseRegistryEntry(stripped as never).ok, false);
  // The same signature with its members verifies: the refusal is the missing members alone.
  assert.equal(verifyRegistryEntrySignature(g.signed_entry, g.public_key_hex, BOUND).valid, true);
});

// The signature object is not signed, so a key id and key type the caller did not supply bind
// nothing: a call without them is never VALID_SIGNATURE, whatever the signature proves. Without
// this, a host that resolved the key from signature.key_id would accept an entry naming any issuer
// and any issuer_key_id, signed by any key it can look up.
test("a call without the authorized key id and key type does not return VALID_SIGNATURE", () => {
  // The premise: the same call with both options verifies.
  assert.equal(verifyRegistryEntrySignature(g.signed_entry, g.public_key_hex, BOUND).status, "VALID_SIGNATURE");
  type Options = Parameters<typeof verifyRegistryEntrySignature>[2];
  const verify = verifyRegistryEntrySignature as (entry: unknown, key: string, options?: unknown) => { valid: boolean; status: string };
  const cases: Array<[string, unknown, string]> = [
    ["no options", undefined, "UNSUPPORTED_SIGNATURE_ALGORITHM"],
    ["null options", null, "UNSUPPORTED_SIGNATURE_ALGORITHM"],
    ["empty options", {}, "UNSUPPORTED_SIGNATURE_ALGORITHM"],
    ["no key type", { expectedKeyId: BOUND.expectedKeyId }, "UNSUPPORTED_SIGNATURE_ALGORITHM"],
    ["a null key type", { expectedKeyId: BOUND.expectedKeyId, keyType: null }, "UNSUPPORTED_SIGNATURE_ALGORITHM"],
    ["no key id", { keyType: "secp256k1" }, "SIGNATURE_KEY_MISMATCH"],
    ["a null key id", { expectedKeyId: null, keyType: "secp256k1" }, "SIGNATURE_KEY_MISMATCH"],
  ];
  for (const [label, options, status] of cases) {
    const r = verify(g.signed_entry, g.public_key_hex, options);
    assert.deepEqual([r.valid, r.status], [false, status], label);
  }
  // The relabel the options exist to catch: an entry naming another issuer and key, signed by a
  // key the host looked up through the unsigned signature.key_id.
  const relabeled = JSON.parse(JSON.stringify(g.signed_entry));
  relabeled.issuer_key_id = "key-of-another-issuer";
  assert.equal(verify(relabeled, g.public_key_hex).status, "UNSUPPORTED_SIGNATURE_ALGORITHM");
  // And the compiler refuses the call before it runs.
  // @ts-expect-error the options are required
  const omitted = (): unknown => verifyRegistryEntrySignature(g.signed_entry, g.public_key_hex);
  // @ts-expect-error both members are required
  const partial: Options = { keyType: "secp256k1" };
  void omitted; void partial;
});

// There is no opt-in to exercise. This asserts the surface rather than the answer:
// a test that only checked the refusal would still pass with an opt-in in place, and the
// property being locked is that no caller can ask for an earlier payload to be verified.
test("no option asks for an earlier signing payload to be verified", () => {
  for (const file of ["../src/signature.ts", "../src/verify-core.ts", "../src/index.ts", "../src/index.browser.ts"]) {
    const source = readFileSync(join(here, file), "utf-8");
    for (const name of ["allowLegacyV1", "allowLegacySigningPayloadV1", "legacyRegistryEntrySigningPayloadDigest", "LEGACY_SIGNING_PAYLOAD", "LegacyRegistryEntrySignatureV1"]) {
      assert.equal(source.includes(name), false, `${file} names ${name}, a legacy surface this version removes`);
    }
  }
  const forced = verifyRegistryEntrySignature(
    withSignature((signature) => { delete signature.payload_id; delete signature.payload_version; }),
    g.public_key_hex,
    { allowLegacyV1: true } as unknown as Parameters<typeof verifyRegistryEntrySignature>[2],
  );
  assert.equal(forced.status, "UNSUPPORTED_SIGNING_PAYLOAD");
});

test("a payload other than registry_entry_signing_payload_v2 version 2 is unsupported at the step", () => {
  const cases: Array<[string, unknown, unknown]> = [
    ["a later payload", "registry_entry_signing_payload_v3", 3],
    ["the v2 identifier, version 3", "registry_entry_signing_payload_v2", 3],
    ["an earlier identifier", "registry_entry_signing_payload_v1", 1],
    ["the version as a string", "registry_entry_signing_payload_v2", "2"],
    ["the identifier in an array", ["registry_entry_signing_payload_v2"], 2],
  ];
  for (const [label, id, version] of cases) {
    const r = verifyRegistryEntrySignature(withSignature((signature) => { signature.payload_id = id; signature.payload_version = version; }), g.public_key_hex, BOUND);
    assert.deepEqual([r.valid, r.status], [false, "UNSUPPORTED_SIGNING_PAYLOAD"], label);
  }
});

// A DER signature whose two integers are 29 bytes each is 64 bytes long, the length of the
// only encoding the protocol defines (`r || s`, canonicalization-and-hashing.md §4). Given
// bytes and no format, @noble/curves reads DER first, so such a signature would verify here and
// fail in the Python verifier, which reads the two halves as r and s. Nobody
// needs a lucky nonce to produce one: for any message and any small r whose x lies on the
// curve, the public key that makes (r, s) verify can be solved for, which is what this does.
const N = secp256k1.CURVE.n;
const mod = (a: bigint) => ((a % N) + N) % N;
function inverse(a: bigint): bigint {
  let [x, y, u, v] = [mod(a), N, 1n, 0n];
  while (x !== 0n) {
    const q = y / x;
    [x, y] = [y - q * x, x];
    [u, v] = [v - q * u, u];
  }
  return mod(v);
}
const toBig = (bytes: Uint8Array) => BigInt(`0x${hex(bytes)}`);

function sixtyFourByteDerSignature(digest: Uint8Array) {
  let rBytes = new Uint8Array(0);
  let R: InstanceType<typeof secp256k1.ProjectivePoint> | undefined;
  for (let i = 0; R === undefined; i++) {
    // Half of all x values lie on the curve, so a bound this large is never reached; it
    // exists so that a mistake here fails the test instead of hanging it.
    if (i === 256) throw new Error("no candidate r lies on the curve");
    rBytes = sha256(new TextEncoder().encode(`loquitur-der-r-${i}`)).slice(0, 29);
    rBytes[0] = 1 + (rBytes[0]! % 0x7f); // a positive DER integer with no padding byte
    rBytes[28] = rBytes[28]! % 0x7f; // keeps the second half, read as s, a low in-range s
    try {
      R = secp256k1.ProjectivePoint.fromHex(`02000000${hex(rBytes)}`);
    } catch {
      R = undefined; // x not on the curve; try the next candidate
    }
  }
  const sBytes = sha256(new TextEncoder().encode("loquitur-der-s")).slice(0, 29);
  sBytes[0] = 0x11;
  const [r, s, z] = [toBig(rBytes), toBig(sBytes), mod(toBig(digest))];
  // u1*G + u2*Q = R  with u1 = z/s, u2 = r/s  <=>  Q = (s*R - z*G) / r
  const Q = R.multiply(s).subtract(secp256k1.ProjectivePoint.BASE.multiply(z)).multiply(inverse(r));
  const der = new Uint8Array([0x30, 0x3e, 0x02, 0x1d, ...rBytes, 0x02, 0x1d, ...sBytes]);
  const compact = new Uint8Array(64);
  compact.set(rBytes, 3);
  compact.set(sBytes, 35);
  return { derHex: hex(der), compactHex: hex(compact), publicKeyHex: Q.toHex(false) };
}

test("a 64-byte DER signature is not read as a signature, only r || s is", () => {
  const digest = registryEntrySigningPayloadDigest(g.signed_entry);
  const { derHex, compactHex, publicKeyHex } = sixtyFourByteDerSignature(digest);
  assert.equal(derHex.length, 128);
  assert.ok(derHex.startsWith("303e021d"));
  // The premise: the same (r, s), encoded as the protocol encodes it, is a valid signature
  // by that key over that digest. Without this the rejections below would prove nothing.
  assert.equal(verifySecp256k1Sha256Digest(digest, compactHex, publicKeyHex), true);

  assert.equal(verifySecp256k1Sha256Digest(digest, derHex, publicKeyHex), false);
  const entry = JSON.parse(JSON.stringify(g.signed_entry));
  entry.signature.signature = derHex;
  const r = verifyRegistryEntrySignature(entry, publicKeyHex, BOUND);
  assert.equal(r.valid, false);
  // The Python verifier's status for the same bytes.
  assert.equal(r.status, "SIGNATURE_INVALID");
});

test("the signing payload keeps an own member named __proto__", () => {
  // Assignment would set the payload's prototype and sign an entry without the member.
  const payload = registryEntrySigningPayload(JSON.parse('{"__proto__":{"x":1},"a":"b","signature":null}'));
  assert.deepEqual(Object.getOwnPropertyNames(payload).sort(), ["__proto__", "a"]);
  assert.equal(Object.getPrototypeOf(payload), Object.prototype);
  assert.deepEqual(Object.getOwnPropertyDescriptor(payload, "__proto__")?.value, { x: 1 });
});
// Lowercase hexadecimal only (canonicalization-and-hashing.md §4): the Python verifiers refuse an
// upper-case signature or public key, and so does this package, so the same signed entry cannot
// verify here and fail there.
test("an upper-case signature is malformed, in both helpers", () => {
  const entry = JSON.parse(JSON.stringify(g.signed_entry));
  entry.signature.signature = entry.signature.signature.toUpperCase();
  assert.notEqual(entry.signature.signature, g.signed_entry.signature.signature);
  const r = verifyRegistryEntrySignature(entry, g.public_key_hex, BOUND);
  assert.equal(r.valid, false);
  assert.equal(r.status, "MALFORMED_SIGNATURE");
  const digest = registryEntrySigningPayloadDigest(g.signed_entry);
  assert.equal(verifySecp256k1Sha256Digest(digest, g.signed_entry.signature.signature, g.public_key_hex), true);
  assert.equal(verifySecp256k1Sha256Digest(digest, entry.signature.signature, g.public_key_hex), false);
});

// A public key that is not 04 and 128 lowercase hex characters verifies nothing: SIGNATURE_INVALID,
// the label of a key off the curve, as in the Python verifier. MALFORMED_SIGNATURE is the form of
// the signature, not of the key (trust-registry-authorization.md section 6, rows 17 and 20).
test("an upper-case public key does not verify, in both helpers", () => {
  const upper = "04" + g.public_key_hex.slice(2).toUpperCase();
  assert.notEqual(upper, g.public_key_hex);
  const r = verifyRegistryEntrySignature(g.signed_entry, upper, BOUND);
  assert.equal(r.valid, false);
  assert.equal(r.status, "SIGNATURE_INVALID");
  const digest = registryEntrySigningPayloadDigest(g.signed_entry);
  assert.equal(verifySecp256k1Sha256Digest(digest, g.signed_entry.signature.signature, upper), false);
});
