// Browser / I/O-free entry point. Exports the verifier surface that runs with
// no filesystem: feed it an in-memory { filename: contents } map via
// bundleReaderFromMap. Excludes verifyBundle and readDocumentPath (which need node:fs). This is the
// entry a web page bundles to run the verifier in a browser (`npm run build:browser`).
//
// Give the map each member's bytes as a Uint8Array. A string is text the host already
// decoded: invalid UTF-8 in it was replaced before the verifier saw it, so a manifest the
// Node reader refuses can verify here. Build the map with JSON.parse or
// Object.defineProperty; assignment cannot create a member named __proto__.
export {
  verifyBundleFiles,
  bundleReaderFromMap,
  BundleReadError,
  ERROR_CODES,
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
export { AUTHORIZATION_STATUSES, CHECK_NAMES, REVIEW_REASONS, evaluateTrustRegistry } from "./verify-core.js";
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
// The registered vocabularies built into the package are embedded as text: no file is read.
export { REGISTERED_VOCABULARIES, REGISTERED_VOCABULARY_SHA256 } from "./registered-vocabularies.generated.js";
export { VOCABULARY_KINDS, VocabularyError } from "./vocabulary.js";
export type { VocabularyKind, VocabularyRecord, VocabularySource } from "./vocabulary.js";

export {
  canonicalJsonBytes,
  sha256Uri,
  canonicalHash,
  CanonicalizationError,
  parseJsonStrict,
  assertNoDuplicateJsonKeys,
  JsonParseError,
} from "./canonical.js";
export {
  verifyRegistryEntrySignature,
  registryEntrySigningPayload,
  registryEntrySigningEnvelope,
  registryEntrySigningMessageBytes,
  registryEntrySigningPayloadDigest,
  registryEntrySigningPayloadHash,
  verifySecp256k1Sha256Digest,
  SIGNATURE_ALGORITHM,
  SIGNING_PAYLOAD_ID,
  SIGNING_PAYLOAD_VERSION,
  SIGNING_ENVELOPE_DOMAIN,
  SIGNING_ENVELOPE_SCHEMA,
  SIGNING_PAYLOAD_SCHEMA,
  SIGNING_DOMAIN_PREFIX,
} from "./signature.js";
export type { SignatureVerificationResult, SignatureStatus, SignatureVerificationOptions } from "./signature.js";
export type * from "./types.js";

export {
  CRYPTOGRAPHIC_CAPABILITY_PROFILE,
  SUPPORTED_SIGNATURE_ALGORITHMS,
  SUPPORTED_TRUST_KEY_TYPES,
  RESERVED_UNSUPPORTED_ALGORITHMS,
  signatureAlgorithmSupported,
  trustKeyTypeSupported,
} from "./cryptographic-capabilities.js";
export type { SupportedSignatureAlgorithm, SupportedTrustKeyType } from "./cryptographic-capabilities.js";

export { parseRegistryEntry, parseTrustRegistry } from "./protocol-input.js";
export { summaryViolatedRules } from "./verdict-grounds.js";
export type { SummaryRule } from "./verdict-grounds.js";
export type {
  ProtocolParseResult,
  RegistryEntryWire,
  TrustRegistryWire,
  UntrustedRegistryEntryInput,
  UntrustedTrustRegistryInput,
  ValidatedRegistryEntry,
  ValidatedTrustRegistry,
} from "./types.js";
