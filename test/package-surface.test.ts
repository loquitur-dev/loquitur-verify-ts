// The names the two package entries export at run time, exactly. The package is a 0.x preview whose
// surface is the names README.md, the example and the specification use; a name added to or removed
// from an entry fails this test until the list below changes with it, so a widening or a narrowing
// of the surface is a reviewed change, never a side effect of an edit inside a module. Types are
// not in the list: they have no run-time name, and test/type-contract.ts holds the ones a caller
// uses.
import { test } from "node:test";
import assert from "node:assert/strict";
import * as main from "../src/index.ts";
import * as browser from "../src/index.browser.ts";

/** The browser entry's names: everything that needs no file system. */
const BROWSER = [
  "AUTHORIZATION_STATUSES", "BundleReadError", "CHECK_NAMES", "CRYPTOGRAPHIC_CAPABILITY_PROFILE", "CanonicalizationError",
  "DOCUMENT_NOT_STRICT_JSON", "DOCUMENT_PATH_NAMES_NOTHING", "DOCUMENT_PATH_NAMES_NO_REGULAR_FILE", "DOCUMENT_READ_FAILED", "ERROR_CODES", "EXIT_HOST_FAILURE", "EXIT_INTERNAL_ERROR", "EXIT_OFFLINE_FAIL", "EXIT_OFFLINE_OK",
  "EXIT_OFFLINE_REVIEW", "EXIT_UNSUPPORTED_VERSION", "EvaluationTimeError",
  "JsonParseError", "REGISTERED_VOCABULARIES", "REGISTERED_VOCABULARY_SHA256", "RESERVED_UNSUPPORTED_ALGORITHMS", "REVIEW_REASONS",
  "ROOT_SIGNING_DOMAIN_PREFIX",
  "SIGNATURE_ALGORITHM", "SIGNING_DOMAIN_PREFIX", "SIGNING_ENVELOPE_DOMAIN", "SIGNING_ENVELOPE_SCHEMA",
  "SIGNING_PAYLOAD_ID", "SIGNING_PAYLOAD_SCHEMA", "SIGNING_PAYLOAD_VERSION", "STATUS_HOST_FAILURE", "STATUS_OFFLINE_FAIL",
  "STATUS_OFFLINE_OK", "STATUS_OFFLINE_REVIEW", "STATUS_UNSUPPORTED_VERSION", "SUPPORTED_SIGNATURE_ALGORITHMS",
  "SUPPORTED_TRUST_KEY_TYPES", "TrustRootError", "VOCABULARY_KINDS", "VocabularyError", "assertNoDuplicateJsonKeys",
  "authenticateTrustRegistry", "bundleReaderFromMap", "canonicalHash", "canonicalJsonBytes",
  "evaluateTrustRegistry", "parseJsonStrict", "parseRegistryEntry", "parseTrustRegistry",
  "parseTrustRoots", "registryEntrySigningEnvelope", "registryEntrySigningMessageBytes",
  "registryEntrySigningPayload", "registryEntrySigningPayloadDigest",
  "registryEntrySigningPayloadHash", "sha256Uri", "signatureAlgorithmSupported",
  "summaryViolatedRules", "trustKeyTypeSupported", "trustRegistryRootSigningEnvelope",
  "trustRegistrySigningMessageBytes", "verifyBundleFiles", "verifyRegistryEntrySignature",
  "verifySecp256k1Sha256Digest",
];
/** The names only the Node entry adds: the readers of a path on disk and the status record. */
const NODE_ONLY = ["LOQUITUR_VERIFY_STATUS", "readDocumentPath", "verifyBundle"];

test("the browser entry exports exactly the names listed", () => {
  assert.deepEqual(Object.keys(browser).sort(), [...BROWSER].sort());
});

test("the Node entry exports the browser entry's names and its own, exactly", () => {
  assert.deepEqual(Object.keys(main).sort(), [...BROWSER, ...NODE_ONLY].sort());
});
