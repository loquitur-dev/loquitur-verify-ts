/** Closed cryptographic capability set for Loquitur protocol release 0.1. */
export const CRYPTOGRAPHIC_CAPABILITY_PROFILE = "loquitur.crypto_capabilities.v0.1" as const;
export const SUPPORTED_SIGNATURE_ALGORITHMS = ["secp256k1_ecdsa_sha256"] as const;
export const SUPPORTED_TRUST_KEY_TYPES = ["secp256k1"] as const;
export const RESERVED_UNSUPPORTED_ALGORITHMS = ["ed25519"] as const;

export type SupportedSignatureAlgorithm = typeof SUPPORTED_SIGNATURE_ALGORITHMS[number];
export type SupportedTrustKeyType = typeof SUPPORTED_TRUST_KEY_TYPES[number];

export function signatureAlgorithmSupported(value: unknown): value is SupportedSignatureAlgorithm {
  return typeof value === "string" && (SUPPORTED_SIGNATURE_ALGORITHMS as readonly string[]).includes(value);
}

export function trustKeyTypeSupported(value: unknown): value is SupportedTrustKeyType {
  return typeof value === "string" && (SUPPORTED_TRUST_KEY_TYPES as readonly string[]).includes(value);
}

/**
 * The verifier's closed allowlist of (signature algorithm, key type) pairs
 * (CRYPTOGRAPHIC_CAPABILITIES.json; canonicalization-and-hashing.md, algorithm agility). The
 * documents admit any well-formed identifier; this list, chosen by the verifier and never by the
 * input, decides at the signature step, and a pair outside it is UNSUPPORTED_SIGNATURE_ALGORITHM.
 */
export const SUPPORTED_SIGNATURE_PAIRS: ReadonlyArray<readonly [SupportedSignatureAlgorithm, SupportedTrustKeyType]> = [
  ["secp256k1_ecdsa_sha256", "secp256k1"],
];

export function signaturePairSupported(algorithm: unknown, keyType: unknown): boolean {
  return SUPPORTED_SIGNATURE_PAIRS.some(([a, k]) => a === algorithm && k === keyType);
}
