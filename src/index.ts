// Public entry point for the Loquitur offline verifier (`@loquitur/verify`).
// This package verifies Loquitur evidence locally, with no server and no network, and gives
// the checks, verdict and exit code that the specification's report contract defines.
// It ships no HTTP client: fetching evidence is the host application's concern.
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

export {
  verifyBundle,
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
} from "./verify.js";
export { AUTHORIZATION_STATUSES, BundleReadError, CHECK_NAMES, ERROR_CODES, REVIEW_REASONS, evaluateTrustRegistry } from "./verify.js";
export { DOCUMENT_NOT_STRICT_JSON, DOCUMENT_PATH_NAMES_NOTHING, DOCUMENT_PATH_NAMES_NO_REGULAR_FILE, DOCUMENT_READ_FAILED, readDocumentPath } from "./verify.js";
export type {
  VerifyReport,
  VerifyOptions,
  BundleReader,
  ErrorCode,
  TrustRegistryReport,
  VerifyError,
  AuthorizationStatus,
  CheckName,
  ReportStatus,
  ReportVerdict,
  ReviewReason,
} from "./verify.js";
export {
  TrustRootError,
  ROOT_SIGNING_DOMAIN_PREFIX,
  authenticateTrustRegistry,
  parseTrustRoots,
  trustRegistryRootSigningEnvelope,
  trustRegistrySigningMessageBytes,
} from "./verify.js";
export type { RootSignatureStatus, TrustRoot } from "./verify.js";
export { EvaluationTimeError } from "./verify.js";
export type { EvaluationTime } from "./verify.js";
export { REGISTERED_VOCABULARIES, REGISTERED_VOCABULARY_SHA256, VOCABULARY_KINDS, VocabularyError } from "./verify.js";
export type { VocabularyKind, VocabularyRecord, VocabularySource } from "./verify.js";

export { LOQUITUR_VERIFY_STATUS } from "./status.js";
export type { LoquiturVerifyStatus } from "./status.js";

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
