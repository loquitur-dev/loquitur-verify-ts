// The secp256k1 point a public key encodes, so two keys are compared as points, never as strings:
// trust-registry-authorization.md section 6, row 6 (TRUST_REGISTRY_AMBIGUOUS_KEY), and
// trust-root.md section 5, row 7 (AMBIGUOUS_ROOT_KEY). No node:* import, so it runs in every entry
// point.
import { secp256k1 } from "@noble/curves/secp256k1";
import { rethrowHostStackFault } from "./json-strictness.js";

// A SEC1 encoding with a point: compressed, 02 or 03 then 32 bytes, or uncompressed, 04 then 64
// bytes. Lowercase hexadecimal only, as public_key_hex is written in trust_registry.schema.json
// and trust-root.md section 3, and nothing is lower-cased first. The hybrid forms 06 and 07, the
// one-byte encoding of infinity and every other length encode no point here.
const SEC1_POINT_HEX = /^(?:0[23][0-9a-f]{64}|04[0-9a-f]{128})$/;

/**
 * The uncompressed lowercase encoding of the secp256k1 point `hex` encodes, or null when it
 * encodes none: not of a form above, a coordinate not below p, or off the curve. Whatever the
 * key type the value is listed under: the point is a property of the bytes.
 */
export function secp256k1Point(hex: unknown): string | null {
  if (typeof hex !== "string" || !SEC1_POINT_HEX.test(hex)) return null;
  try {
    // fromHex refuses a coordinate of p or above (it does not reduce it) and a point off the curve.
    return secp256k1.ProjectivePoint.fromHex(hex).toHex(false);
  } catch (err) {
    rethrowHostStackFault(err);
    return null;
  }
}

/**
 * Whether the element at `index` of `all` shares its point with another element of `all`, in any
 * SEC1 encoding, whatever their other members. A key that encodes no point shares none.
 */
export function sharesPoint(all: ReadonlyArray<{ readonly public_key_hex?: unknown }>, index: number): boolean {
  const point = secp256k1Point(all[index]?.public_key_hex);
  if (point === null) return false;
  // Only the found entry's point is decoded. Another key of a form above encodes that point exactly
  // when it spells its x coordinate and, for a compressed form, the parity of y (the other
  // parity is the negated point), or, for the uncompressed form, y as well: an x spelled the same
  // lies on the curve because the found point does, so no other decoding is needed.
  const x = point.slice(2, 66);
  const parity = (Number.parseInt(point.charAt(129), 16) & 1) === 0 ? "02" : "03";
  return all.some((other, at) => {
    if (at === index) return false;
    const hex = other.public_key_hex;
    if (typeof hex !== "string" || hex.slice(2, 66) !== x || !SEC1_POINT_HEX.test(hex)) return false;
    return hex.startsWith("04") ? hex.slice(66) === point.slice(66) : hex.startsWith(parity);
  });
}
