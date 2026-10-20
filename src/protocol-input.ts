import { PROTOCOL_INSTANT, isCalendarInstant } from "./instant.js";
import { registryEntryGroundsErrors } from "./verdict-grounds.js";
import { REASON_CODE_SEVERITY, REASON_CODE_VOCABULARY } from "./reason-code-severity.generated.js";
import { nonBlankString } from "./whitespace.js";
import type {
  ProtocolParseResult,
  RegistrySignature,
  RegistrySignatureV2,
  TrustRegistryEntryWire,
  TrustRegistrySignatureWire,
  UntrustedRegistryEntryInput,
  UntrustedTrustRegistryInput,
  ValidatedRegistryEntry,
  ValidatedTrustRegistry,
} from "./types.js";

const REGISTRY_FIELDS = new Set([
  "anchor", "anchored_at", "asset_type", "disclosure_profile", "effective_at",
  "issued_at", "issuer_id", "issuer_key_id", "manifest_hash", "object_type",
  "policy_id", "policy_version", "privacy_classification",
  "reason_code_catalog_version", "reason_codes", "receipt_hash", "receipt_id",
  "registry_entry_id", "schema_version", "signature", "subject_ref_hash",
  "verdict", "workflow",
]);
const REGISTRY_REQUIRED = [
  "object_type", "schema_version", "registry_entry_id", "receipt_id", "issuer_id",
  "issuer_key_id", "asset_type", "workflow", "subject_ref_hash", "manifest_hash",
  "receipt_hash", "policy_id", "policy_version", "reason_code_catalog_version",
  "verdict", "reason_codes", "issued_at", "privacy_classification",
  "disclosure_profile",
] as const;
const TRUST_FIELDS = new Set([
  "object_type", "schema_version", "trust_registry_id", "registry_operator_id",
  "registry_version", "issued_at", "effective_at", "expires_at", "entries", "signature",
]);
const TRUST_ENTRY_REQUIRED = [
  "issuer_id", "issuer_display_name", "issuer_key_id", "key_type", "public_key_hex",
  "status", "effective_from", "expires_at", "allowed_asset_types", "allowed_workflows",
] as const;
const TRUST_ENTRY_FIELDS = new Set([
  "allowed_asset_types", "allowed_workflows", "effective_from", "expires_at",
  "issuer_display_name", "issuer_id", "issuer_key_id", "key_type", "notes",
  "public_key_hex", "revocation_reason", "revoked_at", "status",
]);
const HASH = /^sha256:[0-9a-f]{64}$/;
// A trust entry's public key as trust_registry.schema.json gives it: lowercase hexadecimal of 1 to
// 512 bytes. Its form for the key type is judged at the signature step (trust-registry-
// authorization.md section 6, row 20), not by the contract.
const PUBLIC_KEY = /^(?:[a-f0-9]{2}){1,512}$/;
// Algorithm and key type identifiers (canonicalization-and-hashing.md, algorithm agility): any
// well-formed identifier is admitted, and the verifier's allowlist decides at the signature step.
const ALGORITHM_ID = /^[a-z0-9][a-z0-9_]{0,63}$/;
// registry_entry.schema.json gives `signature.signature` the pattern ^[a-f0-9]{128}$ in both of its
// branches: r || s as 128 lowercase hexadecimal characters, nothing trimmed or case-folded, so an
// uppercase or padded signature is not a valid entry.
const REGISTRY_ENTRY_SIGNATURE_HEX = /^[0-9a-f]{128}$/;
// Identifier and version patterns mirror registry_entry.schema.json and
// trust_registry.schema.json, byte for byte: a pattern that differs from its schema accepts or
// refuses identifiers the schema does not.
const REGISTRY_ENTRY_ID = /^reg_[A-Za-z0-9_-]{8,128}$/;
const RECEIPT_ID = /^vr_[A-Za-z0-9_-]{8,128}$/;
const ISSUER_ID = /^issuer_[A-Za-z0-9_-]{3,128}$/;
const TRUST_REGISTRY_ID = /^tr_[A-Za-z0-9_-]{8,128}$/;
const OPERATOR_ID = /^operator_[A-Za-z0-9_-]{3,128}$/;
const SEMVER = /^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9_.-]+)?$/;
/**
 * The identifier grammar of verification-vocabularies.md section 7, the grammar of every member a
 * registered vocabulary governs: `asset_type`, `workflow`, each element of a trust entry's
 * `allowed_asset_types` and `allowed_workflows`, and `anchor.method`. It is the grammar of
 * ALGORITHM_ID. Whether a well-formed value is one the verifier knows is no part of either
 * document's contract: it is judged against a registered vocabulary after the contract holds
 * (section 8).
 */
export const IDENTIFIER = ALGORITHM_ID;
// The anchor of registry_entry.schema.json (anchor-commitment.md section 6): `method` an
// identifier, `system` and `anchor_reference` free strings.
const ANCHOR_FIELDS = ["method", "system", "anchor_reference"] as const;
/** The closed vocabulary of the registry entry's `disclosure_profile`, held to its schema by test/vocabulary-drift.test.ts. */
export const DISCLOSURE_PROFILES = ["minimal_public", "issuer_controlled_bundle", "partner_authorized_bundle"] as const;
/**
 * The codes of the reason-code catalog, which the registry entry's `reason_codes` enum names
 * exactly: the generator of the severity table refuses a catalog and a schema that differ.
 */
export const REASON_CODES: readonly string[] = Object.keys(REASON_CODE_SEVERITY);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function stringValue(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}
function optionalStringOrNull(value: unknown): boolean {
  return value === undefined || value === null || stringValue(value);
}
function exactFields(value: Record<string, unknown>, allowed: Set<string>, path: string, errors: string[]): void {
  for (const key of Object.keys(value)) if (!allowed.has(key)) errors.push(`${path}.${key}: unexpected field`);
}
function requireFields(value: Record<string, unknown>, required: readonly string[], path: string, errors: string[]): void {
  for (const key of required) if (!(key in value)) errors.push(`${path}.${key}: required`);
}
function stringEnum(value: unknown, allowed: readonly string[]): boolean {
  return typeof value === "string" && allowed.includes(value);
}
function stringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => stringValue(item));
}
function uniqueStrings(value: readonly string[]): boolean { return new Set(value).size === value.length; }
function matches(value: unknown, pattern: RegExp): boolean {
  return typeof value === "string" && pattern.test(value);
}

/**
 * The instant pattern of registry_entry.schema.json (issued_at, effective_at, anchored_at) and
 * trust_registry.schema.json (issued_at, effective_at, expires_at; effective_from, expires_at and
 * revoked_at of each entry), character for character, and then the calendar: month 00 or 13, day
 * 00 or 32, hour 24, minute 60 and second 61 break the pattern, and a value inside the pattern that
 * names no date (February 30, second 60, year 0000) breaks the calendar. Every instant of the
 * document is held to both, used or not (canonicalization-and-hashing.md section 6).
 */
function instantErrors(document: Record<string, unknown>, fields: readonly string[], path: string): string[] {
  const errors: string[] = [];
  for (const field of fields) {
    const value = document[field];
    if (typeof value !== "string") continue;
    if (!PROTOCOL_INSTANT.test(value)) errors.push(`${path}.${field}: instant outside the schema pattern`);
    else if (!isCalendarInstant(value)) errors.push(`${path}.${field}: not a calendar instant`);
  }
  return errors;
}

// The free strings of the two host documents (bundle-objects.md, "Free strings"; registry-link.md
// section 2): the members their schemas type as strings and hold to no pattern, enumeration or
// constant. The schema asks for one character only, so " " would pass, and an entry naming no key
// would be authorized when the trust registry named the same blank key. Every other string of
// either document is held to a pattern, an enumeration or a constant that no string of W matches; a
// nested member is read only when the object carrying it is present. The trust registry's
// `signature.signature` is not among them: trust-root.md holds it to its compact form when a root
// authenticates the registry.
const REGISTRY_ENTRY_FREE_STRINGS = ["issuer_key_id", "policy_id", "signature.key_id", "anchor.anchor_reference", "anchor.system"];
const TRUST_ENTRY_FREE_STRINGS = ["issuer_display_name", "issuer_key_id", "notes", "revocation_reason"];

/** `$.<path>: made only of whitespace` for every named member that is a string made only of W. */
function freeStringErrors(document: Record<string, unknown>, members: readonly string[], where = "$"): string[] {
  const errors: string[] = [];
  for (const member of members) {
    let node: unknown = document;
    for (const part of member.split(".")) {
      node = node !== null && typeof node === "object" && !Array.isArray(node) ? (node as Record<string, unknown>)[part] : undefined;
    }
    if (typeof node === "string" && !nonBlankString(node)) errors.push(`${where}.${member}: made only of whitespace`);
  }
  return errors;
}

/** True when both are calendar instants and `first` is strictly later than `second`. */
function later(first: unknown, second: unknown): boolean {
  if (typeof first !== "string" || typeof second !== "string") return false;
  if (!isCalendarInstant(first) || !isCalendarInstant(second)) return false;
  return Date.parse(first) > Date.parse(second);
}

/**
 * Contradictions between a trust registry's fields; each makes the registry malformed. Key status
 * does not decide alone: an entry marked active with a revoked_at, a suspended one carrying a
 * revocation, and a registry issued after its own expiry are malformed. Every entry counts, not
 * only the one a registry entry names. A registry issued before it takes effect is an advance
 * issue and stays valid; equal bounds are not inverted. Mirrors _trust_registry_coherence_errors
 * in the Python verifier.
 */
function trustRegistryCoherenceErrors(registry: Record<string, unknown>): string[] {
  const errors: string[] = [];
  if (later(registry.effective_at, registry.expires_at)) errors.push("$: effective_at is later than expires_at");
  if (later(registry.issued_at, registry.expires_at)) errors.push("$: issued_at is later than expires_at");
  if (!Array.isArray(registry.entries)) return errors;
  registry.entries.forEach((item, index) => {
    if (!isRecord(item)) return;
    const where = `$.entries[${index}]`;
    const carriesRevocation = item.revoked_at != null || item.revocation_reason != null;
    if (item.status === "active" && carriesRevocation) errors.push(`${where}: an active key carries a revocation`);
    // A suspension is reversible and a revocation is not: an entry that records both says two
    // things about one key (trust-registry-authorization.md section 3).
    if (item.status === "suspended" && carriesRevocation) errors.push(`${where}: a suspended key carries a revocation`);
    if (item.status === "revoked" && item.revoked_at == null) errors.push(`${where}: a revoked key has no revoked_at`);
    if (later(item.effective_from, item.expires_at)) errors.push(`${where}: effective_from is later than expires_at`);
  });
  return errors;
}
/** Key-sorted serialization that implements JSON Schema `uniqueItems` deep equality. */
function stableKey(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableKey).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const entries = Object.keys(value as Record<string, unknown>).sort()
      .map((key) => `${JSON.stringify(key)}:${stableKey((value as Record<string, unknown>)[key])}`);
    return `{${entries.join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}
function uniqueItems(value: readonly unknown[]): boolean {
  return new Set(value.map(stableKey)).size === value.length;
}
function parseAnchor(value: unknown, errors: string[]): void {
  if (value === undefined || value === null) return;
  if (!isRecord(value)) { errors.push("$.anchor: object or null required"); return; }
  exactFields(value, new Set(ANCHOR_FIELDS), "$.anchor", errors);
  requireFields(value, ANCHOR_FIELDS, "$.anchor", errors);
  if (!matches(value.method, IDENTIFIER)) errors.push("$.anchor.method: identifier required");
  if (!stringValue(value.system)) errors.push("$.anchor.system: non-empty string required");
  if (!stringValue(value.anchor_reference)) errors.push("$.anchor.anchor_reference: non-empty string required");
}

// The signing-envelope v2 signature, the only shape this version defines: a signature object
// without payload_id and payload_version breaks the entry's contract (signing-envelope-v2.md).
const SIGNATURE_FIELDS = ["algorithm", "key_id", "signature", "payload_id", "payload_version"] as const;

function parseRegistrySignature(value: unknown, errors: string[]): RegistrySignature | null | undefined {
  if (value === undefined || value === null) return value;
  if (!isRecord(value)) { errors.push("$.signature: must be object or null"); return undefined; }
  exactFields(value, new Set(SIGNATURE_FIELDS), "$.signature", errors);
  requireFields(value, SIGNATURE_FIELDS, "$.signature", errors);
  if (!matches(value.algorithm, ALGORITHM_ID)) errors.push("$.signature.algorithm: identifier required");
  if (!stringValue(value.key_id)) errors.push("$.signature.key_id: non-empty string required");
  if (!matches(value.signature, REGISTRY_ENTRY_SIGNATURE_HEX)) errors.push("$.signature.signature: 128 lowercase hex characters required");
  if (value.payload_id !== "registry_entry_signing_payload_v2") errors.push("$.signature.payload_id: invalid");
  if (value.payload_version !== 2) errors.push("$.signature.payload_version: invalid");
  return value as unknown as RegistrySignatureV2;
}

/**
 * Hold a parsed registry entry to its contract. It reads a value, not bytes: parse the document
 * with readDocumentPath or parseJsonStrict first, never with JSON.parse, or a duplicate member or
 * an over-precise number is gone before this sees it (canonicalization-and-hashing.md section 6).
 */
export function parseRegistryEntry(input: UntrustedRegistryEntryInput): ProtocolParseResult<ValidatedRegistryEntry> {
  const errors: string[] = [];
  if (!isRecord(input)) return { ok: false, errors: ["$: registry entry must be an object"] };
  exactFields(input, REGISTRY_FIELDS, "$", errors);
  requireFields(input, REGISTRY_REQUIRED, "$", errors);
  if (input.object_type !== "registry_entry") errors.push("$.object_type: registry_entry required");
  if (input.schema_version !== "v1") errors.push("$.schema_version: v1 required");
  for (const key of ["issuer_key_id", "policy_id"] as const)
    if (!stringValue(input[key])) errors.push(`$.${key}: non-empty string required`);
  if (!matches(input.registry_entry_id, REGISTRY_ENTRY_ID)) errors.push("$.registry_entry_id: reg_ identifier required");
  if (!matches(input.receipt_id, RECEIPT_ID)) errors.push("$.receipt_id: vr_ identifier required");
  if (!matches(input.issuer_id, ISSUER_ID)) errors.push("$.issuer_id: issuer_ identifier required");
  if (!matches(input.policy_version, SEMVER)) errors.push("$.policy_version: semantic version required");
  for (const key of ["subject_ref_hash", "manifest_hash", "receipt_hash"] as const)
    if (!stringValue(input[key]) || !HASH.test(input[key] as string)) errors.push(`$.${key}: sha256 URI required`);
  if (!matches(input.asset_type, IDENTIFIER)) errors.push("$.asset_type: identifier required");
  if (!matches(input.workflow, IDENTIFIER)) errors.push("$.workflow: identifier required");
  if (input.reason_code_catalog_version !== REASON_CODE_VOCABULARY) errors.push("$.reason_code_catalog_version: invalid");
  if (!stringEnum(input.verdict, ["PASS", "WARN", "REVIEW", "FAIL"])) errors.push("$.verdict: invalid");
  if (!stringArray(input.reason_codes) || input.reason_codes.length === 0 || !uniqueStrings(input.reason_codes)
    || !input.reason_codes.every((code) => REASON_CODES.includes(code)))
    errors.push("$.reason_codes: unique non-empty array of catalogued reason codes required");
  if (!stringValue(input.issued_at)) errors.push("$.issued_at: UTC instant required");
  if (!optionalStringOrNull(input.effective_at)) errors.push("$.effective_at: UTC instant or null required");
  if (input.privacy_classification !== "public_commitment") errors.push("$.privacy_classification: public_commitment required");
  if (!stringEnum(input.disclosure_profile, DISCLOSURE_PROFILES)) errors.push("$.disclosure_profile: invalid");
  if (!optionalStringOrNull(input.anchored_at)) errors.push("$.anchored_at: UTC instant or null required");
  errors.push(...instantErrors(input, ["issued_at", "effective_at", "anchored_at"], "$"));
  errors.push(...freeStringErrors(input, REGISTRY_ENTRY_FREE_STRINGS));
  // The entry's verdict must be the verdict its reason codes derive (src/verdict-grounds.ts): an
  // entry with verdict PASS citing a fail-severity code breaks its contract.
  errors.push(...registryEntryGroundsErrors(input));
  parseAnchor(input.anchor, errors);
  parseRegistrySignature(input.signature, errors);
  return errors.length ? { ok: false, errors } : { ok: true, value: input as unknown as ValidatedRegistryEntry };
}

function parseTrustEntry(value: unknown, index: number, errors: string[]): TrustRegistryEntryWire | null {
  const path = `$.entries[${index}]`;
  if (!isRecord(value)) { errors.push(`${path}: object required`); return null; }
  exactFields(value, TRUST_ENTRY_FIELDS, path, errors);
  requireFields(value, TRUST_ENTRY_REQUIRED, path, errors);
  for (const key of ["issuer_display_name", "issuer_key_id"] as const)
    if (!stringValue(value[key])) errors.push(`${path}.${key}: non-empty string required`);
  if (!matches(value.issuer_id, ISSUER_ID)) errors.push(`${path}.issuer_id: issuer_ identifier required`);
  if (!matches(value.key_type, ALGORITHM_ID)) errors.push(`${path}.key_type: identifier required`);
  if (!stringValue(value.public_key_hex) || !PUBLIC_KEY.test(value.public_key_hex)) errors.push(`${path}.public_key_hex: invalid`);
  if (!stringEnum(value.status, ["active", "suspended", "revoked"])) errors.push(`${path}.status: invalid`);
  for (const key of ["effective_from", "expires_at"] as const)
    if (!stringValue(value[key])) errors.push(`${path}.${key}: UTC instant required`);
  const assets = value.allowed_asset_types;
  if (!Array.isArray(assets) || !assets.every((item) => matches(item, IDENTIFIER)) || !uniqueStrings(assets as string[])) errors.push(`${path}.allowed_asset_types: invalid`);
  const workflows = value.allowed_workflows;
  if (!Array.isArray(workflows) || !workflows.every((item) => matches(item, IDENTIFIER)) || !uniqueStrings(workflows as string[])) errors.push(`${path}.allowed_workflows: invalid`);
  for (const key of ["revocation_reason", "notes"] as const) if (!optionalStringOrNull(value[key])) errors.push(`${path}.${key}: string or null required`);
  if (!optionalStringOrNull(value.revoked_at)) errors.push(`${path}.revoked_at: UTC instant or null required`);
  errors.push(...instantErrors(value, ["effective_from", "expires_at", "revoked_at"], path));
  errors.push(...freeStringErrors(value, TRUST_ENTRY_FREE_STRINGS, path));
  return value as unknown as TrustRegistryEntryWire;
}

function parseTrustSignature(value: unknown, errors: string[]): TrustRegistrySignatureWire | null {
  if (!isRecord(value)) { errors.push("$.signature: object required"); return null; }
  exactFields(value, new Set(["algorithm", "key_id", "signature"]), "$.signature", errors);
  if (!matches(value.algorithm, ALGORITHM_ID)) errors.push("$.signature.algorithm: identifier required");
  if (!stringValue(value.key_id)) errors.push("$.signature.key_id: non-empty string required");
  if (!stringValue(value.signature)) errors.push("$.signature.signature: non-empty string required");
  return value as unknown as TrustRegistrySignatureWire;
}

/** Hold a parsed trust registry to its contract; parse the document as for parseRegistryEntry. */
export function parseTrustRegistry(input: UntrustedTrustRegistryInput): ProtocolParseResult<ValidatedTrustRegistry> {
  const errors: string[] = [];
  if (!isRecord(input)) return { ok: false, errors: ["$: trust registry must be an object"] };
  exactFields(input, TRUST_FIELDS, "$", errors);
  requireFields(input, ["object_type", "schema_version", "trust_registry_id", "registry_operator_id", "registry_version", "issued_at", "effective_at", "expires_at", "entries", "signature"], "$", errors);
  if (input.object_type !== "trust_registry") errors.push("$.object_type: trust_registry required");
  if (input.schema_version !== "v1") errors.push("$.schema_version: v1 required");
  if (!matches(input.trust_registry_id, TRUST_REGISTRY_ID)) errors.push("$.trust_registry_id: tr_ identifier required");
  if (!matches(input.registry_operator_id, OPERATOR_ID)) errors.push("$.registry_operator_id: operator_ identifier required");
  if (!matches(input.registry_version, SEMVER)) errors.push("$.registry_version: semantic version required");
  for (const key of ["issued_at", "effective_at", "expires_at"] as const) if (!stringValue(input[key])) errors.push(`$.${key}: UTC instant required`);
  errors.push(...instantErrors(input, ["issued_at", "effective_at", "expires_at"], "$"));
  errors.push(...freeStringErrors(input, ["signature.key_id"]));
  if (!Array.isArray(input.entries)) errors.push("$.entries: array required");
  else {
    input.entries.forEach((item, index) => parseTrustEntry(item, index, errors));
    if (!uniqueItems(input.entries)) errors.push("$.entries: duplicate entries are not permitted");
  }
  errors.push(...trustRegistryCoherenceErrors(input));
  parseTrustSignature(input.signature, errors);
  return errors.length ? { ok: false, errors } : { ok: true, value: input as unknown as ValidatedTrustRegistry };
}
