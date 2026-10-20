// Differential adapter: answers the seeded differential harness of loquitur-conformance, a
// repository that is not published, one JSON line at a time, through this package's own functions.
// A reader runs it as test/differential-adapter.test.ts does: compile src/ into a directory, name
// that directory in LOQUITUR_CONFORMANCE_BUILD, and write requests to standard input. A test-only
// tool: it is outside package.json `files`, so the published package never carries it.
//
// Transport: one request per line on stdin (UTF-8, `\n`-terminated), exactly one response line per
// request on stdout, in order, and exit 0 at the end of input. A response is compact JSON with its
// members sorted and every character outside printable ASCII written as a lowercase \u escape, the
// bytes Python's json.dumps(..., sort_keys=True, separators=(",", ":")) writes.
//
//   load             input_b64 -> accepted: the bytes are a document the strict loader accepts
//   jcs              input_b64 -> accepted, output_b64: the RFC 8785 bytes of the loaded value
//   signing_message  kind ("registry_entry" | "trust_registry"), input_b64 -> accepted, output_b64
//   instant          value -> accepted: an operator evaluation time
//   member_name      value -> portable, folded, self_declaration
//
// The public-API operations, one or more per pair of scripts/public-api-parity.json; the protocol
// is the one loquitur-verify-py tools/differential_adapter.py states, member for member. A document
// travels as bytes in a `*_b64` member and is parsed as a host parses one it read, with the strict
// parser, DOCUMENT_NOT_STRICT_JSON in its place when the parser refuses it; a member marked `?` may
// be absent. The operator's inputs are refused first, in this order, with {refused} alone:
// "evaluation_time" (not a calendar instant), then "trust_roots_version" (a trust-root document of a
// later version) or "trust_roots" (one that is not strict JSON or breaks trust-root.md section 3).
//
//   trust_registry   entry_b64, trust_registry_b64, trust_roots_b64?, evaluation_time?
//                    -> authorization_status, signature_status, root_signature_status, verdict
//                       | entry_strict: false | refused
//                       evaluateTrustRegistry; verdict is trustRegistryVerdict of its report, the
//                       function the bundle run's headline reads
//   root_signature   trust_registry_b64, trust_roots_b64?, evaluation_time? -> status | registry_strict: false | refused
//   trust_roots      input_b64 -> accepted, unsupported_version
//   signature        entry_b64, public_key_hex, key_id, key_type -> status | entry_strict: false | entry_object: false
//   ecdsa            digest_hex, signature_hex, public_key_hex -> valid
//   summary_rules    input_b64 -> accepted, rules
//   parse            kind ("registry_entry" | "trust_registry"), input_b64 -> accepted, valid
//   capability       algorithm, key_type -> algorithm_supported, key_type_supported, pair_supported
//   verify           bundle, entry_b64?, trust_registry_b64?, trust_roots_b64?, evaluation_time?
//                    -> status, verdict, exit_code, reason, errors, checks_requested, checks_established,
//                       review_reasons, evaluation_time, trust_registry, checks | refused
//                       verifyBundle over the directory `bundle`; trust_registry is the three statuses
//                       of report-contract.md section 5.4 or null, checks the per-check results
//                       registry_link, trust_registry and registry_signature
//
// Any other op answers {"error": "unknown_op"}; a request that throws answers the class name of
// what it threw, and the adapter goes on; a line that is not a JSON object with a string `id`
// answers {"id": null, "error": "bad_request"}.
//
// Documents are read as the verifier reads a bundle member or a document named by path: the exact
// bytes, decoded as UTF-8 with fatal errors and the BOM kept, then the strict parser
// (parseJsonBytesStrict). Nothing is decoded leniently first.
//
// Like scripts/conformance-adapter.mjs, it loads the compiled package from the build directory
// LOQUITUR_CONFORMANCE_BUILD names, by default the in-tree, ignored directory .conformance-build/.
import { pathToFileURL } from "node:url";

const buildDir = process.env.LOQUITUR_CONFORMANCE_BUILD
  ? pathToFileURL(process.env.LOQUITUR_CONFORMANCE_BUILD + "/").href
  : new URL("../.conformance-build/", import.meta.url).href;

const { CanonicalizationError, JsonParseError, canonicalJsonBytes, parseJsonBytesStrict } = await import(buildDir + "canonical.js");
const { registryEntrySigningMessageBytes, verifyRegistryEntrySignature, verifySecp256k1Sha256Digest } = await import(buildDir + "signature.js");
const {
  TrustRootError, authenticateTrustRegistry, parseTrustRoots, trustRegistrySigningMessageBytes, trustRootDocumentUnsupportedVersion,
} = await import(buildDir + "trust-root.js");
const { EvaluationTimeError, operatorEvaluationTime } = await import(buildDir + "evaluation-time.js");
const {
  DOCUMENT_NOT_STRICT_JSON, evaluateTrustRegistry, foldMemberName, isSelfDeclaration, memberNameValid, trustRegistryVerdict,
} = await import(buildDir + "verify-core.js");
const { verifyBundle } = await import(buildDir + "verify.js");
const { isPlainObject } = await import(buildDir + "json-strictness.js");
const { summaryViolatedRules } = await import(buildDir + "verdict-grounds.js");
const { parseRegistryEntry, parseTrustRegistry } = await import(buildDir + "protocol-input.js");
const { signatureAlgorithmSupported, signaturePairSupported, trustKeyTypeSupported } = await import(buildDir + "cryptographic-capabilities.js");

/** JSON with members sorted, no spaces, and every character outside printable ASCII escaped, as Python's ensure_ascii does. */
function dumps(value) {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value).replace(/[^\x20-\x7e]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);
  }
  if (Array.isArray(value)) return `[${value.map(dumps).join(",")}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${dumps(k)}:${dumps(value[k])}`).join(",")}}`;
}

const STANDARD_BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

/** The bytes of the member `member` (by default `input_b64`), which must be standard base64 with padding. */
function bytesOf(request, member) {
  const text = request[member];
  if (typeof text !== "string" || !STANDARD_BASE64.test(text)) throw new TypeError(`${member} is not standard base64`);
  return new Uint8Array(Buffer.from(text, "base64"));
}

const inputBytes = (request) => bytesOf(request, "input_b64");

const toBase64 = (bytes) => Buffer.from(bytes).toString("base64");

/** The loaded value, or `undefined` when the strict loader refuses the bytes. */
function load(bytes) {
  try {
    return { value: parseJsonBytesStrict(bytes) };
  } catch (err) {
    if (err instanceof JsonParseError) return undefined;
    throw err;
  }
}

/** `build()`, or null when canonicalization refuses the value. */
function canonicalOrNull(build) {
  try {
    return build();
  } catch (err) {
    if (err instanceof CanonicalizationError) return null;
    throw err;
  }
}

function requireString(request, member) {
  const value = request[member];
  if (typeof value !== "string") throw new TypeError(`${member} is not a string`);
  return value;
}

const OPS = {
  load(request) {
    return { accepted: load(inputBytes(request)) !== undefined };
  },
  jcs(request) {
    const loaded = load(inputBytes(request));
    const output = loaded === undefined ? null : canonicalOrNull(() => canonicalJsonBytes(loaded.value));
    return { accepted: output !== null, output_b64: output === null ? null : toBase64(output) };
  },
  signing_message(request) {
    const kind = request.kind;
    if (kind !== "registry_entry" && kind !== "trust_registry") throw new TypeError("kind is not registry_entry or trust_registry");
    const loaded = load(inputBytes(request));
    if (loaded === undefined || !isPlainObject(loaded.value)) return { accepted: false, output_b64: null };
    const build = kind === "registry_entry" ? registryEntrySigningMessageBytes : trustRegistrySigningMessageBytes;
    const output = canonicalOrNull(() => build(loaded.value));
    return { accepted: output !== null, output_b64: output === null ? null : toBase64(output) };
  },
  instant(request) {
    const value = requireString(request, "value");
    try {
      operatorEvaluationTime(value);
      return { accepted: true };
    } catch (err) {
      if (err instanceof EvaluationTimeError) return { accepted: false };
      throw err;
    }
  },
  member_name(request) {
    const value = requireString(request, "value");
    return { portable: memberNameValid(value), folded: foldMemberName(value), self_declaration: isSelfDeclaration(value) };
  },
};

/** The strictly parsed document of `member`, or DOCUMENT_NOT_STRICT_JSON when the strict parser refuses its bytes. */
function documentOf(request, member) {
  const loaded = load(bytesOf(request, member));
  return loaded === undefined ? DOCUMENT_NOT_STRICT_JSON : loaded.value;
}

class Refused extends Error {
  constructor(what) {
    super(what);
    this.what = what;
  }
}

/** The evaluation time and the trust-root document, each refused as the verifier refuses it, in that order. */
function operatorInputs(request) {
  let evaluationTime;
  if (Object.hasOwn(request, "evaluation_time")) {
    try {
      operatorEvaluationTime(request.evaluation_time);
    } catch (err) {
      if (err instanceof EvaluationTimeError) throw new Refused("evaluation_time");
      throw err;
    }
    evaluationTime = request.evaluation_time;
  }
  let trustRoots;
  if (Object.hasOwn(request, "trust_roots_b64")) {
    const document = documentOf(request, "trust_roots_b64");
    if (document === DOCUMENT_NOT_STRICT_JSON) throw new Refused("trust_roots");
    if (trustRootDocumentUnsupportedVersion(document) !== null) throw new Refused("trust_roots_version");
    try {
      parseTrustRoots(document);
    } catch (err) {
      if (err instanceof TrustRootError) throw new Refused("trust_roots");
      throw err;
    }
    trustRoots = document;
  }
  return { evaluationTime, trustRoots };
}

function refusable(operation) {
  return (request) => {
    try {
      return operation(request);
    } catch (err) {
      if (err instanceof Refused) return { refused: err.what };
      throw err;
    }
  };
}

/** The options of the operator's inputs, with the members absent that were not supplied. */
function options({ evaluationTime, trustRoots }) {
  const opts = {};
  if (evaluationTime !== undefined) opts.evaluationTime = evaluationTime;
  if (trustRoots !== undefined) opts.trustRoots = trustRoots;
  return opts;
}

const VERIFY_CHECKS = ["registry_link", "trust_registry", "registry_signature"];

const API_OPS = {
  trust_registry: refusable((request) => {
    const inputs = operatorInputs(request);
    const entry = documentOf(request, "entry_b64");
    if (entry === DOCUMENT_NOT_STRICT_JSON) return { entry_strict: false };
    const report = evaluateTrustRegistry(entry, documentOf(request, "trust_registry_b64"), options(inputs));
    return {
      authorization_status: report.authorization_status,
      signature_status: report.signature_status,
      root_signature_status: report.trust_registry_root_signature_status,
      verdict: trustRegistryVerdict(report, inputs.evaluationTime !== undefined),
    };
  }),
  root_signature: refusable((request) => {
    const inputs = operatorInputs(request);
    const registry = documentOf(request, "trust_registry_b64");
    if (registry === DOCUMENT_NOT_STRICT_JSON) return { registry_strict: false };
    const roots = inputs.trustRoots === undefined ? null : parseTrustRoots(inputs.trustRoots);
    return { status: authenticateTrustRegistry(registry, roots, inputs.evaluationTime ?? null) };
  }),
  trust_roots(request) {
    const document = documentOf(request, "input_b64");
    if (document === DOCUMENT_NOT_STRICT_JSON) return { accepted: false, unsupported_version: null };
    const version = trustRootDocumentUnsupportedVersion(document);
    if (version !== null) return { accepted: false, unsupported_version: version };
    try {
      parseTrustRoots(document);
    } catch (err) {
      if (err instanceof TrustRootError) return { accepted: false, unsupported_version: null };
      throw err;
    }
    return { accepted: true, unsupported_version: null };
  },
  signature(request) {
    const entry = documentOf(request, "entry_b64");
    if (entry === DOCUMENT_NOT_STRICT_JSON) return { entry_strict: false };
    if (!isPlainObject(entry)) return { entry_object: false };
    const publicKeyHex = requireString(request, "public_key_hex");
    const result = verifyRegistryEntrySignature(entry, publicKeyHex, { expectedKeyId: request.key_id, keyType: request.key_type });
    return { status: result.status };
  },
  ecdsa(request) {
    const digestHex = requireString(request, "digest_hex");
    if (!/^(?:[0-9a-f]{2})*$/.test(digestHex)) throw new TypeError("digest_hex is not lowercase hex");
    const digest = new Uint8Array(Buffer.from(digestHex, "hex"));
    return { valid: verifySecp256k1Sha256Digest(digest, request.signature_hex, request.public_key_hex) };
  },
  summary_rules(request) {
    const summary = documentOf(request, "input_b64");
    if (summary === DOCUMENT_NOT_STRICT_JSON) return { accepted: false, rules: null };
    return { accepted: true, rules: summaryViolatedRules(summary) };
  },
  parse(request) {
    const kind = request.kind;
    if (kind !== "registry_entry" && kind !== "trust_registry") throw new TypeError("kind is not registry_entry or trust_registry");
    const document = documentOf(request, "input_b64");
    if (document === DOCUMENT_NOT_STRICT_JSON) return { accepted: false, valid: null };
    const parsed = kind === "registry_entry" ? parseRegistryEntry(document) : parseTrustRegistry(document);
    return { accepted: true, valid: parsed.ok };
  },
  capability(request) {
    const { algorithm, key_type: keyType } = request;
    return {
      algorithm_supported: signatureAlgorithmSupported(algorithm),
      key_type_supported: trustKeyTypeSupported(keyType),
      pair_supported: signaturePairSupported(algorithm, keyType),
    };
  },
  verify: refusable((request) => {
    const inputs = operatorInputs(request);
    const bundle = requireString(request, "bundle");
    const opts = options(inputs);
    if (Object.hasOwn(request, "entry_b64")) opts.registryEntry = documentOf(request, "entry_b64");
    if (Object.hasOwn(request, "trust_registry_b64")) opts.trustRegistry = documentOf(request, "trust_registry_b64");
    const report = verifyBundle(bundle, opts);
    const tr = report.trust_registry;
    return {
      status: report.status,
      verdict: report.verdict,
      exit_code: report.exit_code,
      reason: report.outcome.reason,
      errors: report.errors.map((error) => error.code),
      checks_requested: report.checks_requested,
      checks_established: report.checks_established,
      review_reasons: report.review_reasons,
      evaluation_time: report.evaluation_time,
      trust_registry: tr === null ? null : {
        authorization_status: tr.authorization_status,
        signature_status: tr.signature_status,
        trust_registry_root_signature_status: tr.trust_registry_root_signature_status,
      },
      checks: Object.fromEntries(VERIFY_CHECKS.map((name) => [name, Object.hasOwn(report.checks, name) ? report.checks[name] : null])),
    };
  }),
};

Object.assign(OPS, API_OPS);

const strictUtf8 = new TextDecoder("utf-8", { fatal: true });

/** The response to one request line. */
function answer(line) {
  let request;
  try {
    request = JSON.parse(strictUtf8.decode(line));
  } catch {
    return { id: null, error: "bad_request" };
  }
  if (request === null || typeof request !== "object" || Array.isArray(request) || typeof request.id !== "string") {
    return { id: null, error: "bad_request" };
  }
  const id = request.id;
  if (typeof request.op !== "string" || !Object.hasOwn(OPS, request.op)) return { id, error: "unknown_op" };
  try {
    return { id, ...OPS[request.op](request) };
  } catch (err) {
    const name = err !== null && typeof err === "object" && typeof err.constructor === "function" ? err.constructor.name : typeof err;
    return { id, error: name || "Error" };
  }
}

function respond(line) {
  process.stdout.write(dumps(answer(line)) + "\n");
}

let pending = Buffer.alloc(0);
process.stdin.on("data", (chunk) => {
  pending = Buffer.concat([pending, chunk]);
  for (let end = pending.indexOf(0x0a); end >= 0; end = pending.indexOf(0x0a)) {
    respond(pending.subarray(0, end));
    pending = pending.subarray(end + 1);
  }
});
process.stdin.on("end", () => {
  // A last line without its `\n` is still a request.
  if (pending.length > 0) respond(pending);
});
