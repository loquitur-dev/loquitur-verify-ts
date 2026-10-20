// Canonical object types are generated from the exact loquitur-schemas artifact.
// Do not copy or hand-maintain those interfaces in this file.
export type * from "./generated/loquitur-protocol.js";
import type { REASON_CODE_VOCABULARY } from "./reason-code-severity.generated.js";

/**
 * A registry entry as the host supplies it: a parsed value, or one of the DOCUMENT_* markers. The
 * trust registry and the trust-root document are supplied the same way. A parsed value cannot show
 * what a lenient parser already discarded: a duplicate member name, a byte-order mark or invalid
 * UTF-8, a number with excess precision. canonicalization-and-hashing.md section 6 refuses those in
 * every document the caller supplies. Parse each document with this package's strict parser:
 * readDocumentPath (Node), which reads and parses the bytes as the verifier does, or a fatal
 * `TextDecoder` with `ignoreBOM: true` and then parseJsonStrict, passing DOCUMENT_NOT_STRICT_JSON
 * when either refuses. A value from JSON.parse is not conforming input: once JSON.parse has kept
 * the last of two duplicate members or rounded an over-precise number, the verifier cannot refuse
 * what section 6 refuses.
 */
export type UntrustedRegistryEntryInput = unknown;
/** A trust registry as the host supplies it, parsed as UntrustedRegistryEntryInput says. */
export type UntrustedTrustRegistryInput = unknown;

export interface RegistrySignatureV2 {
  /** An algorithm identifier; the verifier's allowlist decides at the signature step. */
  algorithm: string;
  key_id: string;
  payload_id: "registry_entry_signing_payload_v2";
  payload_version: 2;
  signature: string;
}

/** The only signature shape this version defines. */
export type RegistrySignature = RegistrySignatureV2;

export interface RegistryEntryWire {
  object_type: "registry_entry";
  schema_version: "v1";
  registry_entry_id: string;
  receipt_id: string;
  issuer_id: string;
  issuer_key_id: string;
  /** An identifier (verification-vocabularies.md section 7); a registered vocabulary decides whether it is known. */
  asset_type: string;
  /** An identifier (verification-vocabularies.md section 7); a registered vocabulary decides whether it is known. */
  workflow: string;
  subject_ref_hash: string;
  manifest_hash: string;
  receipt_hash: string;
  policy_id: string;
  policy_version: string;
  reason_code_catalog_version: typeof REASON_CODE_VOCABULARY;
  verdict: "PASS" | "WARN" | "REVIEW" | "FAIL";
  reason_codes: string[];
  issued_at: string;
  effective_at?: string | null;
  privacy_classification: "public_commitment";
  disclosure_profile: "minimal_public" | "issuer_controlled_bundle" | "partner_authorized_bundle";
  signature?: RegistrySignature | null;
  anchor?: Record<string, unknown> | null;
  anchored_at?: string | null;
}

export interface TrustRegistryEntryWire {
  issuer_id: string;
  issuer_display_name: string;
  issuer_key_id: string;
  key_type: string;
  public_key_hex: string;
  status: "active" | "suspended" | "revoked";
  effective_from: string;
  expires_at: string;
  /** Identifiers, compared by exact equality and never judged against a vocabulary (trust-registry-authorization.md section 5). */
  allowed_asset_types: string[];
  /** Identifiers, compared by exact equality and never judged against a vocabulary (trust-registry-authorization.md section 5). */
  allowed_workflows: string[];
  revoked_at?: string | null;
  revocation_reason?: string | null;
  notes?: string | null;
}

export interface TrustRegistrySignatureWire {
  algorithm: string;
  key_id: string;
  signature: string;
}

export interface TrustRegistryWire {
  object_type: "trust_registry";
  schema_version: "v1";
  trust_registry_id: string;
  registry_operator_id: string;
  registry_version: string;
  issued_at: string;
  effective_at: string;
  expires_at: string;
  entries: TrustRegistryEntryWire[];
  signature: TrustRegistrySignatureWire;
}

declare const VALIDATED_REGISTRY_ENTRY: unique symbol;
declare const VALIDATED_TRUST_REGISTRY: unique symbol;

export type ValidatedRegistryEntry = RegistryEntryWire & {
  readonly [VALIDATED_REGISTRY_ENTRY]: true;
};
export type ValidatedTrustRegistry = TrustRegistryWire & {
  readonly [VALIDATED_TRUST_REGISTRY]: true;
};

export type ProtocolParseResult<T> =
  | { ok: true; value: T }
  | { ok: false; errors: readonly string[] };
