// Conformance adapter: exposes this package's verification surface to the cross-repository gate,
// which is in loquitur-conformance, a repository that is not published. It answers one JSON
// request on standard input. A reader verifies the corpus the gate runs with
// test/corpus-roots.test.ts, which verifies each run as this adapter does.
//
// The build directory is configurable (LOQUITUR_CONFORMANCE_BUILD) so the gate can compile
// into a temporary location and leave the working tree byte-identical. It defaults to the
// in-tree, ignored directory .conformance-build/.
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const buildDir = process.env.LOQUITUR_CONFORMANCE_BUILD
  ? pathToFileURL(process.env.LOQUITUR_CONFORMANCE_BUILD + "/").href
  : new URL("../.conformance-build/", import.meta.url).href;

const request = JSON.parse(readFileSync(0, "utf8"));

if (request.operation === "parse_registry" || request.operation === "parse_trust") {
  const { parseRegistryEntry, parseTrustRegistry } = await import(buildDir + "protocol-input.js");
  const parser = request.operation === "parse_registry" ? parseRegistryEntry : parseTrustRegistry;
  const results = request.cases.map((item) => {
    const parsed = parser(item.input);
    return { id: item.id, accepted: parsed.ok, errors: parsed.ok ? [] : parsed.errors };
  });
  process.stdout.write(JSON.stringify({ operation: request.operation, results }));
} else if (request.operation === "check_summary") {
  // A summary run (conformance-testing.md section 4.1, surface "summary"): the rules of
  // verdict-grounds.md section 3 the verification summary violates, in rule order.
  const { summaryViolatedRules } = await import(buildDir + "verdict-grounds.js");
  process.stdout.write(JSON.stringify({ operation: request.operation, violated_rules: summaryViolatedRules(request.summary) }));
} else if (request.operation === "verify_bundle") {
  // Exercised through verifyBundle, the entry point this package exports, so the gate
  // measures shipped behavior rather than an internal helper.
  const { verifyBundle } = await import(buildDir + "verify.js");
  const { resolveOptions, DOCUMENT_PATH_NAMES_NOTHING, DOCUMENT_PATH_NAMES_NO_REGULAR_FILE, DOCUMENT_READ_FAILED } = await import(buildDir + "verify-core.js");
  const opts = {};
  if (request.registryEntry !== undefined) opts.registryEntry = request.registryEntry;
  if (request.trustRegistry !== undefined) opts.trustRegistry = request.trustRegistry;
  // The two inputs an operator supplies out of band: the trust-root document of
  // trust-root.md section 3 and the evaluation time of trust-registry-authorization.md
  // section 2. They are on the adapter contract so that a vector can reach a pinned root: without
  // them the root surface would be unreachable from the corpus and an authorization run could
  // only be REVIEW.
  if (request.trustRoots !== undefined) opts.trustRoots = request.trustRoots;
  if (request.evaluationTime !== undefined) opts.evaluationTime = request.evaluationTime;
  // A document the host did not read: nothing is found at the path it was given, what is found
  // there is not a regular file, or reading the file failed. The request cannot carry the
  // package's markers, which are not JSON values, so it names the fact and the markers are put in
  // the document's place here. A document and a fact about the same document in one request
  // contradict each other and end the process.
  const UNREAD = { nothing_found: DOCUMENT_PATH_NAMES_NOTHING, no_regular_file: DOCUMENT_PATH_NAMES_NO_REGULAR_FILE, read_failed: DOCUMENT_READ_FAILED };
  for (const name of ["registryEntry", "trustRegistry", "trustRoots"]) {
    const fact = request[name + "Unread"];
    if (fact === undefined) continue;
    if (!Object.hasOwn(UNREAD, fact) || request[name] !== undefined) {
      throw new Error(`${name}Unread must be one of ${Object.keys(UNREAD).join(", ")}, beside no ${name}`);
    }
    opts[name] = UNREAD[fact];
  }
  // The registered vocabulary documents a run names, by kind (conformance-testing.md section 4.1):
  // documents, as the others are. `vocabulariesUnread` names, by kind, what the host found in a
  // document's place, as the facts above do; a kind named in both contradicts itself.
  if (request.vocabularies !== undefined) opts.vocabularies = request.vocabularies;
  if (request.vocabulariesUnread !== undefined) {
    const vocabularies = opts.vocabularies === undefined ? {} : opts.vocabularies;
    const facts = request.vocabulariesUnread;
    if (vocabularies === null || typeof vocabularies !== "object" || Array.isArray(vocabularies)
      || facts === null || typeof facts !== "object" || Array.isArray(facts)) {
      throw new Error("vocabularies and vocabulariesUnread must be objects by kind");
    }
    for (const [kind, fact] of Object.entries(facts)) {
      if (!Object.hasOwn(UNREAD, fact) || Object.hasOwn(vocabularies, kind)) {
        throw new Error(`vocabulariesUnread.${kind} must be one of ${Object.keys(UNREAD).join(", ")}, beside no vocabularies.${kind}`);
      }
      vocabularies[kind] = UNREAD[fact];
    }
    opts.vocabularies = vocabularies;
  }
  // Refused before any evidence is read, and a refusal writes no report: the run reached no
  // verdict, and an empty report would be read as one. Exit 64 is the code the Python
  // verifier uses for the same refusals (trust roots, an evaluation time, a registered
  // vocabulary document), so one declaration covers both.
  try {
    resolveOptions(opts);
  } catch (refusal) {
    process.stderr.write(String(refusal && refusal.message ? refusal.message : refusal) + "\n");
    process.exit(64);
  }
  let report;
  try {
    report = verifyBundle(request.bundle, opts);
  } catch (err) {
    // A crash is not a verdict. Report it as one so the gate records a disagreement
    // instead of failing the run and hiding which side broke.
    report = { status: "ADAPTER_THREW", verdict: "ADAPTER_THREW", exit_code: null,
               checks: {}, error: String(err && err.message ? err.message : err) };
  }
  process.stdout.write(JSON.stringify(report));
} else {
  throw new Error("unsupported operation");
}
