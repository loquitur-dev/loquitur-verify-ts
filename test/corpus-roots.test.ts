// The declared runs of every corpus root named by LOQUITUR_CORPUS_ROOTS, reproduced by this
// verifier.
//
// LOQUITUR_CORPUS_ROOTS names corpus roots separated by the host's path separator (`;` on Windows,
// `:` elsewhere): an extraction of the pinned conformance archive, or any tree laid out as one,
// with `vectors/verify.json` and optionally `vectors/additional-negatives/expected.json` and
// `vectors/bundles/manifest.json`. Each run is verified as scripts/conformance-adapter.mjs verifies
// it, each document read by readDocumentPath from the path the run names (the registered
// vocabularies the run names included, and the corpus's baseline for a kind it names none of), and
// the members conformance-testing.md section 6 item 1 compares are compared: status, verdict, exit
// code, reason, error codes, the checks requested and established, the review reasons, the
// evaluation time, the trust-registry statuses and the object and version a version gate names, or,
// for a run declared refused, the refusal and its exit code; a run declared per intake is
// reproduced by either declaration. Without the variable the corpus test skips, saying why.
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import test from "node:test";

import { readDocumentPath, verifyBundle } from "../src/verify.ts";
import { resolveOptions } from "../src/verify-core.ts";
import { VOCABULARY_KINDS } from "../src/vocabulary.ts";

const ROOTS = (process.env.LOQUITUR_CORPUS_ROOTS ?? "")
  .split(delimiter)
  .map((part) => part.trim())
  .filter((part) => part.length > 0);
const COMPARED = [
  "status",
  "verdict",
  "exit_code",
  "reason",
  "errors",
  "checks_requested",
  "checks_established",
  "review_reasons",
  "evaluation_time",
  "unsupported_version",
] as const;

type Run = Record<string, any>;

function declaredRuns(root: string): Map<string, Run> {
  const vectors = join(root, "vectors");
  const runs = new Map<string, Run>();
  const sources: Array<[string, string | null]> = [
    ["verify.json", null],
    ["additional-negatives/expected.json", "cases"],
    ["bundles/manifest.json", "cases"],
  ];
  for (const [relative, member] of sources) {
    const path = join(vectors, relative);
    if (!existsSync(path)) {
      if (relative === "verify.json") throw new Error(`${path} is not a corpus declaration file`);
      continue;
    }
    const document = JSON.parse(readFileSync(path, "utf8"));
    const items: Array<[string, Run]> =
      member === null ? Object.entries(document) : document[member].map((run: Run) => [run.id, run]);
    for (const [name, run] of items) {
      if (runs.has(name)) throw new Error(`${root}: the run ${name} is declared twice`);
      runs.set(name, run);
    }
  }
  return runs;
}

function surface(report: Run): Run {
  return {
    status: report.status,
    verdict: report.verdict,
    exit_code: report.exit_code,
    reason: report.outcome?.reason,
    errors: (report.errors ?? []).map((error: Run) => error.code),
    trust_registry: report.trust_registry ?? null,
    checks_requested: report.checks_requested,
    checks_established: report.checks_established,
    review_reasons: report.review_reasons,
    evaluation_time: report.evaluation_time ?? null,
    unsupported_version: unsupportedVersion(report),
  };
}

function unsupportedVersion(report: Run): Run | null {
  const gate = (report.errors ?? []).find((error: Run) => error.code === "unsupported_version");
  return gate === undefined ? null : { object: gate.object, version: gate.version };
}

function differences(expected: Run, actual: Run): string[] {
  const found: string[] = [];
  for (const member of COMPARED) {
    if (member in expected && JSON.stringify(actual[member]) !== JSON.stringify(expected[member])) {
      found.push(`${member} is ${JSON.stringify(actual[member])}, declared ${JSON.stringify(expected[member])}`);
    }
  }
  for (const [member, value] of Object.entries(expected.trust_registry ?? {})) {
    const got = (actual.trust_registry ?? {})[member];
    if (got !== value) found.push(`trust_registry.${member} is ${JSON.stringify(got)}, declared ${JSON.stringify(value)}`);
  }
  return found;
}

function runOnce(vectors: string, run: Run): { report: Run | null; code: number } {
  const target = "bundle" in run ? join(vectors, "bundles", run.bundle) : join(vectors, run.input);
  const opts: Run = {};
  if (run.registry_entry) opts.registryEntry = readDocumentPath(join(vectors, run.registry_entry));
  if (run.trust_registry) opts.trustRegistry = readDocumentPath(join(vectors, run.trust_registry));
  if (run.trust_root) opts.trustRoots = readDocumentPath(join(vectors, run.trust_root));
  if (run.evaluation_time !== undefined && run.evaluation_time !== null) opts.evaluationTime = run.evaluation_time;
  // conformance-testing.md section 4.1: the vocabulary a run names for a kind, else the corpus's
  // baseline for it; a corpus that carries no vocabularies leaves the verifier's own.
  const vocabularies: Run = {};
  for (const kind of VOCABULARY_KINDS) {
    const named = run.vocabularies?.[kind];
    const baseline = join(vectors, "vocabularies", "baseline", `${kind}.json`);
    if (named) vocabularies[kind] = readDocumentPath(join(vectors, named));
    else if (existsSync(baseline)) vocabularies[kind] = readDocumentPath(baseline);
  }
  if (Object.keys(vocabularies).length > 0) opts.vocabularies = vocabularies;
  // A refused trust-root document, evaluation time or vocabulary (VocabularyError) is exit 64.
  try {
    resolveOptions(opts);
  } catch {
    return { report: null, code: 64 };
  }
  return { report: verifyBundle(target, opts) as unknown as Run, code: 0 };
}

function disagreements(root: string): { count: number; found: string[] } {
  const vectors = join(root, "vectors");
  const runs = declaredRuns(root);
  const found: string[] = [];
  for (const [name, run] of runs) {
    const { report, code } = runOnce(vectors, run);
    const expected = run.expected;
    if (expected !== undefined && expected.report === null) {
      if (report !== null || code !== expected.exit_code) found.push(`${name}: declared a refusal with exit ${expected.exit_code}`);
      continue;
    }
    if (report === null) {
      found.push(`${name}: refused with exit ${code}, declared a report`);
      continue;
    }
    const actual = surface(report);
    if (expected !== undefined) {
      for (const difference of differences(expected, actual)) found.push(`${name}: ${difference}`);
    } else if (!Object.values(run.expected_by_intake as Record<string, Run>).some((declared) => differences(declared, actual).length === 0)) {
      found.push(`${name}: matches no declared intake`);
    }
  }
  return { count: runs.size, found };
}

for (const root of ROOTS) {
  test(`every declared run under ${root} is reproduced`, () => {
    const { count, found } = disagreements(root);
    assert.deepEqual(found, [], `${found.length} of ${count} runs disagree:\n${found.join("\n")}`);
  });
}

test("the corpus roots are named", { skip: ROOTS.length === 0 ? "LOQUITUR_CORPUS_ROOTS names no corpus root" : false }, () => {
  assert.ok(ROOTS.length > 0);
});

test("a changed declaration is a disagreement", () => {
  const root = mkdtempSync(join(tmpdir(), "corpus-roots-"));
  try {
    const vectors = join(root, "vectors");
    mkdirSync(join(vectors, "bundles", "empty_bundle"), { recursive: true });
    const { report } = runOnce(vectors, { bundle: "empty_bundle" });
    const declared = Object.fromEntries(Object.entries(surface(report!)).filter(([key]) => (COMPARED as readonly string[]).includes(key)));
    for (const changed of [false, true]) {
      const expected = { ...declared, ...(changed ? { exit_code: 99 } : {}) };
      writeFileSync(join(vectors, "verify.json"), JSON.stringify({ r: { bundle: "empty_bundle", expected } }));
      const { count, found } = disagreements(root);
      assert.equal(count, 1);
      assert.equal(found.length > 0, changed, found.join("\n"));
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
