// The verification report, held to loquitur-protocol docs/specification/report-contract.md.
//
// The report contract states which members of a report are normative and their exact values: the
// status, verdict and exit code (section 3), the checks requested and established (section 3.2),
// the review reasons (section 3.3), the rules that derive outcome.reason (section 5.2), the error
// codes in their order of emission (section 5.3), the authorization statuses (section 5.4), the
// unsupported-version report (section 5.5) and the eleven informative per-check results (section
// 6). Each table is read from the sibling checkout and every row is produced by a run: a bundle
// built for it, or, for a condition only the host can cause (a read that fails, a directory that
// cannot be listed), a reader raising what the host would make it raise.
//
// The rules of section 5.2 are held by a model of their conditions: every run, built for one rule
// or for several that hold together, must report the first rule the table lists among those it
// meets, and every two neighboring rules lead some run or cannot hold together. The set of error
// codes this package can emit, read from its source, must be exactly the table's rows this
// package can reach, and the rows it cannot are named with the reason.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs, { mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { basename, join } from "node:path";
import {
  Bundle, ENTRIES, PACKAGE_DIR, ephemeralAuthorizationWith, ephemeralRoot, linkEntryFor, rootDocument, tempDir, verifyWithByteReader,
} from "./bundle-kit.ts";
import { code, codes, readSpecification, specification, table } from "./spec-tables.ts";
import {
  BundleReadError, CHECK_NAMES, DOCUMENT_PATH_NAMES_NO_REGULAR_FILE, DOCUMENT_READ_FAILED, ERROR_CODES, EXIT_HOST_FAILURE,
  EXIT_INTERNAL_ERROR, EXIT_OFFLINE_FAIL, EXIT_OFFLINE_OK, EXIT_OFFLINE_REVIEW, EXIT_UNSUPPORTED_VERSION, HOST_ERROR_CODES,
  REVIEW_REASONS, bundleReaderFromMap, verifyBundleFiles, type BundleReader, type VerifyReport,
} from "../src/verify-core.ts";
import { TrustRootError } from "../src/trust-root.ts";
import { verifyBundle } from "../src/verify.ts";

const DOCUMENT = "report-contract.md";
/** The operator's evaluation time of the runs that reach the trust registry: the fixture windows hold it. */
const EVALUATION_TIME = "2026-05-10T00:00:00Z";
const SPEC = specification(DOCUMENT);
type Doc = Record<string, any>;
type Verify = (b: Bundle, o?: any) => VerifyReport;

// ---- bundles and material ------------------------------------------------------------------------

const WARN_CODES = ["INTEGRITY_OK", "FRESHNESS_WARNING"];
const FAIL_CODES = ["INTEGRITY_OK", "INTEGRITY_OFFLINE_FAIL"];

const undeclareCanonicalInput = (b: Bundle) => { b.edit("manifest.json", (m) => { delete m.files["canonical_input.json"]; }).delete("canonical_input.json"); };
const dropEnvelope = (b: Bundle) => { b.delete("envelope_env1.json").delete("envelope.sha256"); };
const undeclared = (b: Bundle) => { b.setBytes("undeclared.txt", "x"); };
const wrongManifestSidecar = (b: Bundle) => { b.setBytes("manifest.sha256", "0".repeat(64)); };
const wrongP1Sidecar = (b: Bundle) => { b.setBytes("p1.sha256", "0".repeat(64)); };
const wrongEnvelopeSidecar = (b: Bundle) => { b.setBytes("envelope.sha256", "0".repeat(64)); };

/** The link fixture bundle, changed before sealing. */
function sealed(change?: (b: Bundle) => void, seal: Parameters<Bundle["seal"]>[0] = {}): Bundle {
  const b = Bundle.linkValid();
  change?.(b);
  return b.seal(seal);
}
/** The link fixture bundle sealed, then changed. */
function afterSealing(change: (b: Bundle) => void, before?: (b: Bundle) => void): Bundle {
  const b = sealed(before);
  change(b);
  return b;
}
/** A link run over `bundle`: its receipt changed before sealing, its entry with `overrides`. */
function linkRun(receipt?: (r: Doc) => void, overrides: Doc = {}, change?: (b: Bundle) => void) {
  const b = Bundle.linkValid();
  if (receipt) b.edit("verification_receipt.json", receipt);
  change?.(b);
  b.seal();
  return { bundle: b, options: { registryEntry: linkEntryFor(b, overrides) } };
}
const warningReceipt = (r: Doc) => { r.status = "warning"; r.reason_codes = [...WARN_CODES]; };
const warned = (e: Doc) => { e.verdict = "WARN"; e.reason_codes = [...WARN_CODES]; };
const revoked = (t: Doc) => { Object.assign(t.entries[0], { status: "revoked", revoked_at: "2026-05-01T00:00:00Z" }); };

/**
 * Authorization material over `bundle`: the entry signed by a fresh issuer key, the registry signed
 * by a fresh root, and the operator's evaluation time.
 */
function authRun(bundle: Bundle, changes: { entry?: (e: Doc) => void; trust?: (t: Doc) => void } = {}, withRoots = false) {
  const { root, sign } = ephemeralRoot("root-1");
  const m = ephemeralAuthorizationWith(bundle, { entry: changes.entry, trust: (t: Doc) => { delete t.signature; changes.trust?.(t); } });
  sign(m.trustRegistry);
  const material = { ...m, evaluationTime: EVALUATION_TIME };
  return withRoots ? { ...material, trustRoots: rootDocument([root]) } : material;
}

/** A reader over the bundle whose host fails to read `name`. */
function readerFailingOn(bundle: Bundle, name: string): BundleReader {
  const files: Record<string, Uint8Array> = {};
  for (const [member, data] of bundle.files) Object.defineProperty(files, member, { value: data, enumerable: true });
  const inner = bundleReaderFromMap(files);
  const failing = (member: string) => { if (member === name) throw new BundleReadError(`the host refuses ${member}`); };
  return {
    readText(member) { failing(member); return inner.readText(member); },
    readBytes(member) { failing(member); return inner.readBytes!(member); },
    listMembers() { return inner.listMembers!(); },
  };
}

// ---- section 3 -----------------------------------------------------------------------------------

const unsupportedManifest = (b: Bundle) => { b.edit("manifest.json", (m) => { m.schema_version = "loquitur.bundle.v2"; }); };

for (const [entryName, verify] of ENTRIES) {
  test(`${entryName}: status, verdict and exit code move together, section 3`, SPEC.options, () => {
    const rows = table(readSpecification(SPEC, DOCUMENT), ["`status`", "`verdict`", "`exit_code`", "class", "meaning"]);
    const verdictOf = (cell: string) => (code(cell) === "null" ? null : code(cell));
    const specified = Object.fromEntries(rows.map((row) => [code(row["`status`"]!), [verdictOf(row["`verdict`"]!), Number(code(row["`exit_code`"]!))]]));
    assert.deepEqual(
      Object.fromEntries(Object.entries(specified).map(([status, [, exit]]) => [status, exit])),
      {
        OFFLINE_OK: EXIT_OFFLINE_OK, OFFLINE_FAIL: EXIT_OFFLINE_FAIL, OFFLINE_REVIEW: EXIT_OFFLINE_REVIEW,
        INTERNAL_ERROR: EXIT_INTERNAL_ERROR, UNSUPPORTED_VERSION: EXIT_UNSUPPORTED_VERSION, HOST_FAILURE: EXIT_HOST_FAILURE,
      },
    );
    assert.deepEqual(rows.map((row) => row["class"]), ["evidence", "evidence", "evidence", "not evidence", "not evidence", "not evidence"]);
    const runs = {
      OFFLINE_OK: verify(sealed()),
      OFFLINE_FAIL: verify(afterSealing(wrongManifestSidecar)),
      OFFLINE_REVIEW: verify(sealed(undeclareCanonicalInput)),
      UNSUPPORTED_VERSION: verify(sealed(unsupportedManifest)),
      HOST_FAILURE: verifyBundleFiles(readerFailingOn(sealed(), "p1.json")),
    };
    for (const [status, report] of Object.entries(runs)) {
      assert.deepEqual([report.status, report.verdict, report.exit_code], [status, ...specified[status]!]);
    }
    // A library interface returns no INTERNAL_ERROR report (section 4): a fault is an exception.
    assert.ok(specified["INTERNAL_ERROR"]);
  });

  test(`${entryName}: the first status that applies, and the failure conditions, section 3.1`, SPEC.options, () => {
    const text = readSpecification(SPEC, DOCUMENT).replace(/\s+/g, " ");
    assert.ok(text.includes("The status of a run is the first of these that applies:"));
    assert.ok(text.includes("- the report carries an error whose class is *content* (§5.3);"));
    const l2run = (receipt?: (r: Doc) => void, overrides: Doc = {}) => { const m = linkRun(receipt, overrides); return verify(m.bundle, m.options); };
    const withTrust = authRun(sealed());
    const { evaluationTime: _time, ...withoutTime } = withTrust;
    const got = {
      "unsupported version beside a content failure": verify(sealed((b) => { unsupportedManifest(b); b.setBytes("p1.json", "{"); })).status,
      "content error": verify(afterSealing((b) => b.setBytes("manifest.json", "{"))).status,
      "host error beside a content error": verifyBundleFiles(readerFailingOn(afterSealing((b) => b.setBytes("envelope_env1.json", "{")), "p1.json")).status,
      "host error alone": verifyBundleFiles(readerFailingOn(sealed(), "p1.json")).status,
      "link does not hold": l2run(undefined, { policy_id: "loquitur.policy.other" }).status,
      "entry commits FAIL": l2run((r) => { r.status = "fail"; r.reason_codes = [...FAIL_CODES]; }, { verdict: "FAIL", reason_codes: [...FAIL_CODES] }).status,
      "trust registry does not hold": verify(sealed(), authRun(sealed(), { trust: revoked })).status,
      "roots do not authenticate": verify(sealed(), { ...withTrust, trustRoots: rootDocument([ephemeralRoot("root-1").root]) }).status,
      "undeclared member": verify(sealed(undeclared)).status,
      "canonical input absent and undeclared": verify(sealed(undeclareCanonicalInput)).status,
      "neither envelope nor sidecar": verify(sealed(dropEnvelope)).status,
      "entry commits WARN": l2run(warningReceipt, { verdict: "WARN", reason_codes: [...WARN_CODES] }).status,
      "trust registry holds, no root": verify(sealed(), withTrust).status,
      "trust registry holds, no evaluation time": verify(sealed(), withoutTime).status,
      "otherwise": l2run().status,
    };
    assert.deepEqual(got, {
      "unsupported version beside a content failure": "UNSUPPORTED_VERSION",
      "content error": "OFFLINE_FAIL",
      "host error beside a content error": "OFFLINE_FAIL",
      "host error alone": "HOST_FAILURE",
      "link does not hold": "OFFLINE_FAIL",
      "entry commits FAIL": "OFFLINE_FAIL",
      "trust registry does not hold": "OFFLINE_FAIL",
      "roots do not authenticate": "OFFLINE_FAIL",
      "undeclared member": "OFFLINE_REVIEW",
      "canonical input absent and undeclared": "OFFLINE_REVIEW",
      "neither envelope nor sidecar": "OFFLINE_REVIEW",
      "entry commits WARN": "OFFLINE_REVIEW",
      "trust registry holds, no root": "OFFLINE_REVIEW",
      "trust registry holds, no evaluation time": "OFFLINE_REVIEW",
      "otherwise": "OFFLINE_OK",
    });
  });

  test(`${entryName}: the checks requested and established, section 3.2`, SPEC.options, () => {
    const text = readSpecification(SPEC, DOCUMENT).replace(/\s+/g, " ");
    assert.ok(text.includes("A run is `OFFLINE_OK` exactly when `checks_established` equals `checks_requested`, no review reason holds (§3.3) and no failure condition holds."));
    const named = codes(readSpecification(SPEC, "verification-checks.md").split("\n").filter((line) => /^\| [1-4] \|/.test(line)).map((line) => line.split("|")[2]!).join(" "));
    assert.deepEqual(named, [...CHECK_NAMES]);
    const l2m = linkRun();
    const withTrust = authRun(sealed(), {}, true);
    const { evaluationTime: _time, ...withoutTime } = withTrust;
    const run = (report: VerifyReport) => [report.status, report.checks_requested, report.checks_established, report.review_reasons];
    assert.deepEqual({
      "bundle": run(verify(sealed())),
      "bundle in review": run(verify(sealed(undeclared))),
      "bundle that fails": run(verify(afterSealing(wrongManifestSidecar))),
      "entry": run(verify(l2m.bundle, l2m.options)),
      "entry without receipt": run(verify(sealed((b) => { b.delete("verification_receipt.json"); }), { registryEntry: linkEntryFor(sealed()) })),
      "trust registry and roots": run(verify(sealed(), withTrust)),
      "trust registry and roots, no evaluation time": run(verify(sealed(), withoutTime)),
      "unsupported version": run(verify(sealed(unsupportedManifest), l2m.options)),
    }, {
      "bundle": ["OFFLINE_OK", ["structure", "integrity"], ["structure", "integrity"], []],
      "bundle in review": ["OFFLINE_REVIEW", ["structure", "integrity"], ["structure"], ["bundle_extra_files"]],
      "bundle that fails": ["OFFLINE_FAIL", ["structure", "integrity"], ["structure"], []],
      "entry": ["OFFLINE_OK", ["structure", "integrity", "link"], ["structure", "integrity", "link"], []],
      "entry without receipt": ["OFFLINE_REVIEW", ["structure", "integrity", "link"], ["structure", "integrity"], ["verification_receipt_not_provided"]],
      "trust registry and roots": ["OFFLINE_OK", ["structure", "integrity", "link", "authorization"], ["structure", "integrity", "link", "authorization"], []],
      "trust registry and roots, no evaluation time": ["OFFLINE_REVIEW", ["structure", "integrity", "link", "authorization"], ["structure", "integrity", "link"], ["evaluation_time_not_provided"]],
      "unsupported version": ["UNSUPPORTED_VERSION", ["structure", "integrity", "link"], [], []],
    });
  });
}

test("the review reasons are the closed list of section 3.3, reported in its order", SPEC.options, () => {
  const rows = table(readSpecification(SPEC, DOCUMENT), ["#", "review reason", "holds when"]);
  assert.deepEqual(rows.map((row) => code(row["review reason"]!)), [...REVIEW_REASONS]);
  const b = sealed((x) => { undeclareCanonicalInput(x); dropEnvelope(x); undeclared(x); x.setBytes("document_index.json", "{}"); x.delete("verification_receipt.json"); });
  const report = verifyBundleFiles(bundleReaderFromMap(mapOf(b)), { registryEntry: linkEntryFor(b, { verdict: "WARN", reason_codes: [...WARN_CODES] }) });
  // Every reason that holds, in the table's order, whatever order the run met them in; the first is
  // outcome.reason.
  assert.deepEqual(report.review_reasons, ["registry_entry_verdict_requires_review", "verification_receipt_not_provided", "bundle_reserved_member", "bundle_extra_files", "canonical_input_not_provided", "envelope_not_provided"]);
  assert.equal(report.outcome.reason, report.review_reasons[0]);
  assert.deepEqual(report.review_reasons, [...report.review_reasons].sort((x, y) => REVIEW_REASONS.indexOf(x) - REVIEW_REASONS.indexOf(y)));
});

test("a reader that cannot list the bundle's members is OFFLINE_REVIEW, section 3", SPEC.options, () => {
  assert.equal(verifyWithByteReader(sealed()).status, "OFFLINE_REVIEW");
});

// ---- section 5.2 ---------------------------------------------------------------------------------
//
// Each rule of the table is a condition on the run. A model of those conditions, written from the
// table and read off the report's other members and the run's inputs, says which rules a run meets;
// the run must report the value of the first rule the table lists among them. Every run is declared
// with the rules it was built to meet, which must be among those the model finds.

interface ReasonRun {
  report: VerifyReport;
  builtFor: Set<string>;
  entry?: boolean;
  committed?: string | null;
  roots?: boolean;
  /** False for a report made without reading a bundle: its per-check results are defaults, not observations. */
  bundleRead?: boolean;
}

function reasonRows(): Array<[string, string]> {
  return table(readSpecification(SPEC, DOCUMENT), ["#", "the run", "`outcome.reason`"]).map((row) => [row["#"]!, row["`outcome.reason`"]!]);
}

/** The layers' own outcomes, read off the informative per-check results as bundle-objects.md section 6 defines them. */
function layerOutcomes(checks: Record<string, unknown>) {
  const three = (a: unknown, b: unknown): string => (a === false || b === false ? "OFFLINE_FAIL" : a === null || b === null ? "OFFLINE_REVIEW" : "OFFLINE_OK");
  return {
    manifestOk: checks.manifest_sha256 === true && checks.manifest_files === true,
    p1: three(checks.p1_sha256, checks.p1_input_hash),
    envelope: three(checks.envelope_sha256, checks.envelope_links),
  };
}

const WINDOW_STATUSES = new Set(["TRUST_REGISTRY_NOT_YET_EFFECTIVE", "TRUST_REGISTRY_EXPIRED", "ISSUER_KEY_NOT_YET_EFFECTIVE", "ISSUER_KEY_EXPIRED"]);

/** The rules of section 5.2 whose condition the run meets. */
function rulesMet(run: ReasonRun): Set<string> {
  const { report } = run;
  const status = report.status;
  const checks = report.checks;
  const trustEvaluated = report.trust_registry !== null;
  const review = status === "OFFLINE_REVIEW";
  const failed = status === "OFFLINE_FAIL";
  const read = run.bundleRead ?? true;
  const layers = layerOutcomes(checks);
  const conditions: Record<string, boolean> = {
    "1": report.errors.length > 0,
    "2": status === "OFFLINE_OK" && trustEvaluated,
    "3": status === "OFFLINE_OK" && run.entry === true,
    "4": status === "OFFLINE_OK",
    // The evaluation stopped at a row whose effect is a failure: neither the row that holds nor a
    // window.
    "5": trustEvaluated && checks.trust_registry !== true && !WINDOW_STATUSES.has(report.trust_registry!.authorization_status),
    "6": run.entry === true && checks.registry_link === false,
    "7": review,
    "8": failed && read && !layers.manifestOk,
    "9": failed && read && layers.p1 === "OFFLINE_FAIL",
    "10": failed && read && layers.envelope === "OFFLINE_FAIL",
    "11": true,
  };
  return new Set(Object.entries(conditions).filter(([, holds]) => holds).map(([rule]) => rule));
}

function expectedReason(run: ReasonRun, rows: Map<string, string>): string {
  const listed = [...rows.keys()];
  const rule = [...rulesMet(run)].sort((a, b) => listed.indexOf(a) - listed.indexOf(b))[0]!;
  if (rule === "1") {
    assert.equal(rows.get("1"), "the `code` of its first error");
    return run.report.errors[0]!.code;
  }
  if (rule === "7") {
    assert.equal(rows.get("7"), "the first entry of `review_reasons`");
    return run.report.review_reasons[0]!;
  }
  return code(rows.get(rule)!);
}

/** Runs built for each rule alone, and for rules that hold together. */
function reasonRuns(verify: Verify): Map<string, ReasonRun> {
  const run = (builtFor: string, report: VerifyReport, context: Omit<ReasonRun, "report" | "builtFor"> = {}): [string, ReasonRun] =>
    [builtFor, { report, builtFor: new Set(builtFor.split("+")), ...context }];
  const l2run = (receipt?: (r: Doc) => void, overrides: Doc = {}, change?: (b: Bundle) => void) => { const m = linkRun(receipt, overrides, change); return verify(m.bundle, m.options); };
  const linkFails = linkRun((r) => { r.policy_id = "loquitur.policy.other"; });
  wrongManifestSidecar(linkFails.bundle);
  const grounded = (change?: (b: Bundle) => void) => l2run(warningReceipt, { verdict: "WARN", reason_codes: [...WARN_CODES] }, change);
  const authorizationOver = (options: { before?: (b: Bundle) => void; after?: (b: Bundle) => void; trust?: (t: Doc) => void; entry?: (e: Doc) => void; receipt?: (r: Doc) => void } = {}) => {
    const b = Bundle.linkValid();
    if (options.receipt) b.edit("verification_receipt.json", options.receipt);
    options.before?.(b);
    b.seal();
    const m = authRun(b, { entry: options.entry, trust: options.trust });
    options.after?.(b);
    return verify(b, m);
  };
  const { evaluationTime: _time, ...noTime } = authRun(sealed());
  const runs: Array<[string, ReasonRun]> = [
    run("1", verify(afterSealing((b) => b.setBytes("manifest.json", "{")))),
    run("2+3+4", verify(sealed(), authRun(sealed(), {}, true)), { entry: true, committed: "PASS", roots: true }),
    run("3+4", l2run(), { entry: true, committed: "PASS" }),
    run("4", verify(sealed())),
    run("5", verify(sealed(), authRun(sealed(), { trust: revoked })), { entry: true, committed: "PASS" }),
    run("6", l2run((r) => { r.policy_id = "loquitur.policy.other"; }), { entry: true, committed: "PASS" }),
    // Rule 7, one run per kind of review reason.
    run("7", grounded(), { entry: true, committed: "WARN" }),
    run("7 no root", verify(sealed(), authRun(sealed())), { entry: true, committed: "PASS" }),
    run("7 no time", verify(sealed(), noTime), { entry: true, committed: "PASS" }),
    run("7 window", verify(sealed(), authRun(sealed(), { trust: (t) => { t.entries[0].expires_at = "2026-05-09T23:59:59Z"; } })), { entry: true, committed: "PASS" }),
    run("7 no receipt", verify(sealed((b) => { b.delete("verification_receipt.json"); }), { registryEntry: linkEntryFor(sealed()) }), { entry: true, committed: "PASS" }),
    run("7 undeclared", verify(sealed(undeclared))),
    run("7 canonical input", verify(sealed(undeclareCanonicalInput))),
    run("7 envelope", verify(sealed(dropEnvelope))),
    run("7 no listing", verifyWithByteReader(sealed()), { bundleRead: false }),
    run("8", verify(afterSealing(wrongManifestSidecar))),
    // The P1 sidecar is wrong and the manifest declares the wrong bytes: P1 fails, and so does the
    // envelope's link to it.
    run("9+10", verify(sealed(wrongP1Sidecar, { p1: false }))),
    run("10+11", verify(afterSealing(wrongEnvelopeSidecar))),
    // Rules that hold together.
    run("1+5", authorizationOver({ receipt: (r) => { r.status = "fail"; r.reason_codes = [...FAIL_CODES]; }, entry: (e) => { e.verdict = "FAIL"; e.reason_codes = [...FAIL_CODES]; }, trust: revoked }), { entry: true, committed: "FAIL" }),
    run("1+6", l2run((r) => { r.smuggled = 1; }), { entry: true, committed: "PASS" }),
    run("1+8", verify(afterSealing((b) => b.setBytes("manifest.json", "{")))),
    run("5+8", authorizationOver({ after: wrongManifestSidecar, trust: revoked }), { entry: true, committed: "PASS" }),
    run("6+8", verify(linkFails.bundle, linkFails.options), { entry: true, committed: "PASS" }),
    run("7 two reasons", authorizationOver({ receipt: warningReceipt, entry: warned }), { entry: true, committed: "WARN" }),
    run("8+9", verify(afterSealing((b) => { wrongP1Sidecar(b); wrongManifestSidecar(b); }))),
  ];
  const labeled = new Map<string, ReasonRun>();
  for (const [label, item] of runs) {
    assert.ok(!labeled.has(label), label);
    labeled.set(label, { ...item, builtFor: new Set(label.split(" ")[0]!.split("+")) });
  }
  return labeled;
}

/** Rules no run here can meet, with the reason. */
const UNREACHABLE_RULES: Record<string, string> = {};

// Neighboring rules whose conditions cannot hold together, so that no run can show which comes
// first.
const EXCLUSIVE_RULES: Record<string, string> = {
  "1+2": "a run that carries an error is not OFFLINE_OK (section 3)",
  "4+5": "a trust registry that stops at a failure makes the run OFFLINE_FAIL",
  "5+6": "the trust registry is evaluated only beside a link that holds",
  "6+7": "a link that does not hold makes the run OFFLINE_FAIL, and rule 7 needs OFFLINE_REVIEW",
  "7+8": "rule 7 needs OFFLINE_REVIEW, and rule 8 a failed manifest, which fails the run",
};

const pairKey = (a: string, b: string) => [a, b].sort((x, y) => Number(x) - Number(y)).join("+");

for (const [entryName, verify] of ENTRIES) {
  test(`${entryName}: every run reports the first rule it meets, section 5.2`, SPEC.options, () => {
    const rows = new Map(reasonRows());
    assert.deepEqual(new Set(rows.keys()), new Set(Array.from({ length: 11 }, (_, i) => String(i + 1))));
    const runs = reasonRuns(verify);
    // Every reachable rule has a run built for it, alone or among others, and every run meets what
    // it was built for.
    const builtFor = new Set([...runs.values()].flatMap((run) => [...run.builtFor]));
    assert.deepEqual(builtFor, new Set([...rows.keys()].filter((rule) => !(rule in UNREACHABLE_RULES))));
    const unmet = Object.fromEntries([...runs].map(([label, run]) => [label, [...run.builtFor].filter((rule) => !rulesMet(run).has(rule))]).filter(([, rules]) => (rules as string[]).length > 0));
    assert.deepEqual(unmet, {});
    const got = Object.fromEntries([...runs].map(([label, run]) => [label, run.report.outcome.reason]));
    const expected = Object.fromEntries([...runs].map(([label, run]) => [label, expectedReason(run, rows)]));
    assert.deepEqual(got, expected);
    const reasons = new Set([...rows].filter(([number]) => number !== "1" && number !== "7").map(([, cell]) => code(cell)));
    assert.equal(reasons.size, rows.size - 2);
  });

  test(`${entryName}: every two neighboring rules lead a run, or cannot hold together, section 5.2`, SPEC.options, () => {
    const listed = reasonRows().map(([rule]) => rule);
    const decided = new Set<string>();
    for (const run of reasonRuns(verify).values()) {
      const leading = [...rulesMet(run)].sort((a, b) => listed.indexOf(a) - listed.indexOf(b)).slice(0, 2);
      if (leading.length === 2) decided.add(pairKey(leading[0]!, leading[1]!));
    }
    const neighbors = listed.slice(0, -1).map((rule, i) => pairKey(rule, listed[i + 1]!));
    const undecided = neighbors.filter((pair) => !decided.has(pair) && !(pair in EXCLUSIVE_RULES));
    assert.deepEqual(undecided, []);
    for (const pair of Object.keys(EXCLUSIVE_RULES)) assert.ok(neighbors.includes(pair), `${pair} are not neighbors`);
  });

  test(`${entryName}: rules 9 and 10 name only a layer that failed, section 5.2`, SPEC.options, () => {
    const text = readSpecification(SPEC, DOCUMENT).replace(/\s+/g, " ");
    assert.ok(text.includes("Each names a layer whose outcome is `OFFLINE_FAIL`, and never a layer that is only `OFFLINE_REVIEW`"));
    const rows = new Map(reasonRows());
    const runs = {
      "p1-in-review-envelope-fails": verify(afterSealing(wrongEnvelopeSidecar, undeclareCanonicalInput)),
      "p1-fails-envelope-absent": verify(sealed((b) => { wrongP1Sidecar(b); dropEnvelope(b); }, { p1: false })),
    };
    const layers = Object.fromEntries(Object.entries(runs).map(([label, report]) => {
      const outcomes = layerOutcomes(report.checks);
      return [label, [report.status, report.errors, outcomes.p1, outcomes.envelope]];
    }));
    assert.deepEqual(layers, {
      "p1-in-review-envelope-fails": ["OFFLINE_FAIL", [], "OFFLINE_REVIEW", "OFFLINE_FAIL"],
      "p1-fails-envelope-absent": ["OFFLINE_FAIL", [], "OFFLINE_FAIL", "OFFLINE_REVIEW"],
    });
    assert.deepEqual(Object.fromEntries(Object.entries(runs).map(([label, report]) => [label, report.outcome.reason])), {
      "p1-in-review-envelope-fails": code(rows.get("10")!),
      "p1-fails-envelope-absent": code(rows.get("9")!),
    });
  });
}

// ---- section 5.3 ---------------------------------------------------------------------------------

const ERROR_HEADER = ["code", "class", "condition"];

function errorRows(): string[] {
  return table(readSpecification(SPEC, DOCUMENT), ERROR_HEADER).map((row) => code(row["code"]!));
}

/** The class of every row of the table: content, host or not evidence. */
function errorClasses(): Map<string, string> {
  return new Map(table(readSpecification(SPEC, DOCUMENT), ERROR_HEADER).map((row) => [code(row["code"]!), row["class"]!]));
}

/** Codes of the table no run of this package emits, with the reason. */
const UNREACHABLE_CODES: Record<string, string> = {
  invalid_zip: "this verifier reads no ZIP archive",
  archive_unsafe_member: "this verifier reads no ZIP archive",
  archive_safety_limit: "this verifier reads no ZIP archive",
  archive_load_failed: "this verifier reads no ZIP archive",
  internal_error: "a library interface raises a fault instead of reporting it (section 4)",
};

const INPUT_REFUSALS = ["input_not_found", "invalid_zip", "archive_unsafe_member", "archive_safety_limit", "bundle_root_invalid", "archive_load_failed", "unsupported_input", "filesystem_error"];

/** Run `fn` while node:fs refuses, with EACCES, to list every directory named `name`. */
function hostRefusingToList<T>(name: string, fn: () => T): T {
  const module = fs as unknown as { readdirSync: (...args: unknown[]) => unknown };
  const original = module.readdirSync;
  let refused = 0;
  module.readdirSync = function (this: unknown, path: unknown, ...rest: unknown[]) {
    if (basename(String(path)) === name) {
      refused += 1;
      throw Object.assign(new Error(`EACCES: permission denied, scandir '${String(path)}'`), { code: "EACCES" });
    }
    return original.call(this, path, ...rest);
  };
  syncBuiltinESMExports();
  try {
    const out = fn();
    assert.ok(refused > 0, `no directory named ${name} was listed`);
    return out;
  } finally {
    module.readdirSync = original;
    syncBuiltinESMExports();
  }
}

/** A directory holding the bundle plus `arrange`, verified with the Node entry, then removed. */
function onDisk(bundle: Bundle | null, arrange: (dir: string) => string, options: Doc = {}): VerifyReport {
  const dir = tempDir("report");
  try {
    const root = bundle === null ? join(dir, "bundle") : bundle.writeTo(join(dir, "bundle"));
    return verifyBundle(arrange(root), options);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function errorRuns(): Record<string, () => VerifyReport> {
  const noReceipt = (b: Bundle) => { b.delete("verification_receipt.json"); };
  const failing = (name: string, options: Doc = {}) => () => verifyBundleFiles(readerFailingOn(sealed(), name), options);
  const trust = () => authRun(sealed());
  return {
    input_not_found: () => onDisk(null, (root) => join(root, "nothing-here")),
    bundle_root_invalid: () => onDisk(null, (root) => { mkdirSync(root, { recursive: true }); return root; }),
    unsupported_input: () => onDisk(null, (root) => { mkdirSync(root, { recursive: true }); const file = join(root, "plain.txt"); writeFileSync(file, "not a directory"); return file; }),
    // The host refusing to list the input directory, one of the operations on the input itself.
    // A path holding a NUL cannot stand for it: section 5.3 counts that path as one at which
    // nothing is found.
    filesystem_error: () => hostRefusingToList("bundle", () => onDisk(sealed(), (root) => root)),
    // The host refusing to list a directory of the bundle.
    bundle_inventory_failed: () => hostRefusingToList("sub", () => onDisk(sealed((b) => { b.setBytes("sub/extra.txt", "x"); }), (root) => root)),
    bundle_member_name_invalid: () => {
      const files: Record<string, string> = {};
      for (const [name, data] of sealed().files) Object.defineProperty(files, name, { value: new TextDecoder().decode(data), enumerable: true });
      Object.defineProperty(files, "lone-\ud800.txt", { value: "x", enumerable: true });
      return verifyBundleFiles(bundleReaderFromMap(files));
    },
    unsafe_bundle_member: () => onDisk(sealed(), (root) => { symlinkSync(join(root, "p1.json"), join(root, "link.json"), "file"); return root; }),
    manifest_verification_failed: () => verifyBundleFiles(bundleReaderFromMap(mapOf(afterSealing((b) => b.setBytes("manifest.json", "{"))))),
    manifest_read_failed: failing("manifest.json"),
    p1_verification_failed: () => verifyBundleFiles(bundleReaderFromMap(mapOf(sealed((b) => b.edit("p1.json", (p) => { p.smuggled = 1; }))))),
    p1_read_failed: failing("p1.json"),
    envelope_verification_failed: () => verifyBundleFiles(bundleReaderFromMap(mapOf(afterSealing((b) => b.setBytes("envelope_env1.json", "{"))))),
    envelope_incomplete: () => verifyBundleFiles(bundleReaderFromMap(mapOf(afterSealing((b) => b.delete("envelope.sha256"))))),
    envelope_read_failed: failing("envelope_env1.json"),
    verification_receipt_contract_violation: () => verifyBundleFiles(bundleReaderFromMap(mapOf(sealed((b) => b.edit("verification_receipt.json", (r) => { r.smuggled = 1; }))))),
    registry_link_verification_failed: () => verifyBundleFiles(bundleReaderFromMap(mapOf(sealed())), { registryEntry: null }),
    registry_entry_contract_violation: () => { const m = linkRun(undefined, { smuggled: 1 }); return verifyBundleFiles(bundleReaderFromMap(mapOf(m.bundle)), m.options); },
    registry_entry_verdict_fail: () => { const m = linkRun((r) => { r.status = "fail"; r.reason_codes = [...FAIL_CODES]; }, { verdict: "FAIL", reason_codes: [...FAIL_CODES] }); return verifyBundleFiles(bundleReaderFromMap(mapOf(m.bundle)), m.options); },
    registry_link_read_failed: () => { const b = sealed(); return verifyBundleFiles(readerFailingOn(b, "verification_receipt.json"), { registryEntry: linkEntryFor(b) }); },
    trust_registry_requires_registry_entry: () => verifyBundleFiles(bundleReaderFromMap(mapOf(sealed())), { trustRegistry: trust().trustRegistry }),
    trust_registry_requires_valid_registry_entry: () => { const b = sealed(noReceipt); return verifyBundleFiles(bundleReaderFromMap(mapOf(b)), { ...authRun(b), registryEntry: DOCUMENT_PATH_NAMES_NO_REGULAR_FILE }); },
    trust_registry_read_failed: () => { const b = sealed(); return verifyBundleFiles(bundleReaderFromMap(mapOf(b)), { ...authRun(b), trustRegistry: DOCUMENT_READ_FAILED }); },
    trust_root_read_failed: () => { const b = sealed(); return verifyBundleFiles(bundleReaderFromMap(mapOf(b)), { ...authRun(b), trustRoots: DOCUMENT_READ_FAILED }); },
    trust_registry_root_not_authenticated: () => { const b = sealed(); return verifyBundleFiles(bundleReaderFromMap(mapOf(b)), { ...authRun(b), trustRoots: rootDocument([ephemeralRoot("root-1").root]) }); },
    unsupported_version: () => verifyBundleFiles(bundleReaderFromMap(mapOf(sealed((b) => { b.edit("manifest.json", (m) => { m.schema_version = "loquitur.bundle.v2"; }); })))),
  };
}

function mapOf(bundle: Bundle): Record<string, Uint8Array> {
  const files: Record<string, Uint8Array> = {};
  for (const [name, data] of bundle.files) Object.defineProperty(files, name, { value: data, enumerable: true });
  return files;
}

test("every error code this package can emit, and its condition, section 5.3", SPEC.options, () => {
  const rows = errorRows();
  const classes = errorClasses();
  const runs = errorRuns();
  assert.deepEqual(rows.filter((row) => !(row in UNREACHABLE_CODES)), Object.keys(runs), "the reachable rows of the table and this test's runs name the same codes in the same order");
  assert.deepEqual([...ERROR_CODES], Object.keys(runs));
  for (const [code_, run] of Object.entries(runs)) {
    const report = run();
    const emitted = report.errors.map((error) => error.code);
    assert.ok(emitted.includes(code_ as never), `${code_}: ${JSON.stringify(emitted)}`);
    assert.equal(new Set(emitted).size, emitted.length, code_);
    assert.deepEqual(emitted, [...emitted].sort((a, b) => rows.indexOf(a) - rows.indexOf(b)), code_);
    const kind = classes.get(code_);
    const status = kind === "not evidence" ? "UNSUPPORTED_VERSION" : kind === "host" && emitted.every((c) => HOST_ERROR_CODES.has(c)) ? "HOST_FAILURE" : "OFFLINE_FAIL";
    assert.equal(report.status, status, code_);
    assert.equal(report.verdict, status === "OFFLINE_FAIL" ? "FAIL" : null, code_);
    assert.equal(report.outcome.reason, emitted[0], code_);
    assert.equal(HOST_ERROR_CODES.has(code_ as never), kind === "host", `${code_}: class ${kind}`);
    if (INPUT_REFUSALS.includes(code_)) {
      // The input is refused as a whole: the only error, and nothing else evaluated.
      assert.deepEqual(emitted, [code_], code_);
      assert.deepEqual(Object.values(report.checks).filter((value) => value === true), [], code_);
    }
  }
  // The rows that refuse the input as a whole are the table's first eight.
  assert.deepEqual(rows.slice(0, INPUT_REFUSALS.length), INPUT_REFUSALS);
});

test("errors are emitted in the order of the table, each condition judged on its own, section 5.3", SPEC.options, () => {
  const rows = errorRows();
  const text = readSpecification(SPEC, DOCUMENT).replace(/\s+/g, " ");
  assert.ok(text.includes("A condition that holds is not masked by another that also holds, earlier in the table or not"));
  const noReceipt = (b: Bundle) => { b.delete("verification_receipt.json"); };
  const halfEnvelope = (b: Bundle) => { b.delete("envelope.sha256"); };
  const smuggledReceipt = (b: Bundle) => { b.edit("verification_receipt.json", (r) => { r.smuggled = 1; }); };
  const runs: Record<string, VerifyReport> = {
    "links-then-manifest": onDisk(afterSealing((b) => b.setBytes("manifest.json", "{")), (root) => { symlinkSync(join(root, "p1.json"), join(root, "link.json"), "file"); return root; }),
    "manifest-then-p1": verifyBundleFiles(bundleReaderFromMap(mapOf(afterSealing((b) => { b.delete("manifest.sha256"); b.setBytes("p1.json", "{"); })))),
    "p1-then-envelope": verifyBundleFiles(bundleReaderFromMap(mapOf(afterSealing((b) => { b.setBytes("p1.json", "{"); halfEnvelope(b); })))),
    "envelope-then-receipt": verifyBundleFiles(bundleReaderFromMap(mapOf(afterSealing(halfEnvelope, smuggledReceipt)))),
    "receipt-then-entry": (() => { const m = linkRun((r) => { r.smuggled = 1; }, { smuggled: 1 }); return verifyBundleFiles(bundleReaderFromMap(mapOf(m.bundle)), m.options); })(),
    "link-then-trust": (() => { const b = sealed(); return verifyBundleFiles(bundleReaderFromMap(mapOf(b)), { ...authRun(b), registryEntry: DOCUMENT_PATH_NAMES_NO_REGULAR_FILE }); })(),
    // Section 5.3: each condition is judged on the inputs on its own. An entry whose path names no
    // regular file is refused for the entry, and leaves the trust registry's condition holding,
    // whatever the bundle carries: both errors, not the first refusal alone.
    "no-file-entry-without-receipt": (() => { const b = sealed(noReceipt); return verifyBundleFiles(bundleReaderFromMap(mapOf(b)), { registryEntry: DOCUMENT_PATH_NAMES_NO_REGULAR_FILE, trustRegistry: authRun(b).trustRegistry }); })(),
    "receipt-then-trust-without-entry": (() => { const b = sealed(smuggledReceipt); return verifyBundleFiles(bundleReaderFromMap(mapOf(b)), { trustRegistry: authRun(b).trustRegistry }); })(),
  };
  const got = Object.fromEntries(Object.entries(runs).map(([label, report]) => [label, report.errors.map((error) => error.code)]));
  for (const [label, codes_] of Object.entries(got)) assert.equal(codes_.length, 2, `${label}: ${JSON.stringify(codes_)}`);
  assert.deepEqual(got["no-file-entry-without-receipt"], ["registry_link_verification_failed", "trust_registry_requires_valid_registry_entry"]);
  assert.deepEqual(got, Object.fromEntries(Object.entries(got).map(([label, codes_]) => [label, [...codes_].sort((a, b) => rows.indexOf(a) - rows.indexOf(b))])));
});

// A parity row: a host that refuses verification_receipt.json must not make a verifier drop any
// error the link layer contributes, or report two of them out of the table's order. Neither row
// here depends on the receipt (registry_link_verification_failed holds on the entry alone, and
// registry_entry_verdict_fail on an entry that satisfies its contract and was not refused), and
// registry_link_read_failed is not one of the rows that refuse the input as a whole, so it masks
// nothing.
test("a document the host cannot read masks no other condition, section 5.3", SPEC.options, () => {
  const rows = errorRows();
  const text = readSpecification(SPEC, DOCUMENT).replace(/\s+/g, " ");
  assert.ok(text.includes("The rows from `input_not_found` to `filesystem_error` refuse the input as a whole"));
  assert.ok(text.includes("A condition that holds is not masked by another that also holds, earlier in the table or not"));
  assert.ok(!text.includes("| `registry_link_read_failed` | the host fails to read a document the link reads | the only error"));
  const refused = (bundle: Bundle, options: Record<string, unknown>) =>
    verifyBundleFiles(readerFailingOn(bundle, "verification_receipt.json"), options);
  const fail = (r: Doc) => { r.status = "fail"; r.reason_codes = [...FAIL_CODES]; };
  const entryCommittingFail = { verdict: "FAIL", reason_codes: [...FAIL_CODES] };
  const plain = sealed();
  const committing = sealed((b) => b.edit("verification_receipt.json", fail));
  const authorizationRegistry = authRun(plain).trustRegistry;
  assert.ok(!text.includes("the host fails to read a document the link reads; or the entry and the receipt"));
  const runs: Record<string, VerifyReport> = {
    "entry-not-an-object": refused(plain, { registryEntry: null }),
    "entry-commits-fail": refused(committing, { registryEntry: linkEntryFor(committing, entryCommittingFail) }),
    "entry-valid": refused(plain, { registryEntry: linkEntryFor(plain) }),
    "authorization-entry-not-an-object": refused(plain, { registryEntry: null, trustRegistry: authorizationRegistry }),
    "authorization-entry-valid": refused(plain, { registryEntry: linkEntryFor(plain), trustRegistry: authorizationRegistry }),
  };
  const got = Object.fromEntries(Object.entries(runs).map(([label, report]) => [label, report.errors.map((error) => error.code)]));
  assert.deepEqual(got, {
    "entry-not-an-object": ["registry_link_verification_failed", "registry_link_read_failed"],
    "entry-commits-fail": ["registry_entry_verdict_fail", "registry_link_read_failed"],
    "entry-valid": ["registry_link_read_failed"],
    // A host failure to read the receipt is registry_link_read_failed alone, also beside a trust
    // registry.
    "authorization-entry-not-an-object": ["registry_link_verification_failed", "registry_link_read_failed"],
    "authorization-entry-valid": ["registry_link_read_failed"],
  });
  assert.deepEqual(Object.fromEntries(Object.entries(runs).map(([label, report]) => [label, report.status])), {
    "entry-not-an-object": "OFFLINE_FAIL",
    "entry-commits-fail": "OFFLINE_FAIL",
    "entry-valid": "HOST_FAILURE",
    "authorization-entry-not-an-object": "OFFLINE_FAIL",
    "authorization-entry-valid": "HOST_FAILURE",
  });
  for (const [label, report] of Object.entries(runs)) {
    const codes_ = report.errors.map((error) => error.code);
    assert.deepEqual(codes_, [...codes_].sort((a, b) => rows.indexOf(a) - rows.indexOf(b)), label);
    // outcome.reason is the first code (section 5.2, rule 1), so the order decides it.
    assert.equal(report.outcome.reason, codes_[0], label);
    // The link reached no conclusion: it says so rather than reporting false.
    assert.equal(report.checks["registry_link"], null, label);
  }
});

// The registry entry's path as the host found it. The specification takes the entry as a path, and
// section 5.3 decides two rows on what the path names; this package takes documents, so the host
// passes DOCUMENT_PATH_NAMES_NO_REGULAR_FILE or DOCUMENT_READ_FAILED in place of one. A path at
// which something that is not a regular file is found refuses the link for the entry and, beside a
// trust registry, leaves the entry unevaluable; a file the host fails to read is a read failure of
// the link, with the same consequence at the authorization check; a document that is not strict
// JSON is neither, which is why `null` stays apart. Without the markers a host could pass only
// `null` for all three, and the report would lack trust_registry_requires_valid_registry_entry
// where the Python verifier, given the path, reports it.
test("a registry entry whose path names no regular file, or which the host fails to read, section 5.3", SPEC.options, () => {
  const text = readSpecification(SPEC, DOCUMENT).replace(/\s+/g, " ");
  assert.ok(text.includes("something that is not a regular file is found at the entry's path"));
  const plain = sealed();
  const noReceipt = sealed((b) => { b.delete("verification_receipt.json"); });
  const { trustRegistry } = authRun(plain);
  const run = (bundle: Bundle, options: Record<string, unknown>) => verifyBundleFiles(bundleReaderFromMap(mapOf(bundle)), options);
  const NO_FILE = DOCUMENT_PATH_NAMES_NO_REGULAR_FILE;
  const runs: Record<string, VerifyReport> = {
    "no-file": run(plain, { registryEntry: NO_FILE }),
    "no-file-authorization": run(plain, { registryEntry: NO_FILE, trustRegistry }),
    "no-file-without-receipt-authorization": run(noReceipt, { registryEntry: NO_FILE, trustRegistry }),
    "read-failed": run(plain, { registryEntry: DOCUMENT_READ_FAILED }),
    "read-failed-authorization": run(plain, { registryEntry: DOCUMENT_READ_FAILED, trustRegistry }),
    "read-failed-without-receipt": run(noReceipt, { registryEntry: DOCUMENT_READ_FAILED }),
    "not-strict-json-authorization": run(plain, { registryEntry: null, trustRegistry }),
  };
  const got = Object.fromEntries(Object.entries(runs).map(([label, report]) => [label, report.errors.map((error) => error.code)]));
  assert.deepEqual(got, {
    "no-file": ["registry_link_verification_failed"],
    "no-file-authorization": ["registry_link_verification_failed", "trust_registry_requires_valid_registry_entry"],
    "no-file-without-receipt-authorization": ["registry_link_verification_failed", "trust_registry_requires_valid_registry_entry"],
    "read-failed": ["registry_link_read_failed"],
    "read-failed-authorization": ["registry_link_read_failed"],
    "read-failed-without-receipt": ["registry_link_read_failed"],
    "not-strict-json-authorization": ["registry_link_verification_failed"],
  });
  for (const [label, report] of Object.entries(runs)) {
    assert.equal(report.status, label.startsWith("read-failed") ? "HOST_FAILURE" : "OFFLINE_FAIL", label);
    assert.equal(report.outcome.reason, report.errors[0]!.code, label);
    assert.equal(report.trust_registry, null, label);
    assert.ok(report.checks_requested.includes("link"), `${label}: a supplied entry requests the link`);
    assert.ok(!report.checks_established.includes("link"), label);
    // registry-link.md section 5: no conclusion for an entry the host found nothing to read in;
    // false for a document it read that is not an entry.
    assert.equal(report.checks["registry_link"], label.startsWith("not-strict-json") ? false : null, label);
  }
});

test("a trust registry or trust roots whose path names no regular file, or which the host fails to read", SPEC.options, () => {
  // The same two markers in the other document places (report-contract.md section 4). A trust
  // registry whose path names no regular file is row 1 of the evaluation order
  // (trust-registry-authorization.md section 6), INVALID_TRUST_REGISTRY, and trust roots whose path
  // names no regular file are refused before any evidence is read. A file the host failed to read
  // is neither: it is a host failure, never a finding about bytes nobody read (section 5.3).
  const text = readSpecification(SPEC, DOCUMENT).replace(/\s+/g, " ");
  assert.ok(text.includes("a regular file the host failed to read with the error `trust_registry_read_failed`"));
  assert.ok(text.includes("a regular file the host failed to read with the error `trust_root_read_failed`"));
  const plain = sealed();
  const material = authRun(plain, {}, true);
  const run = (options: Record<string, unknown>) => verifyBundleFiles(bundleReaderFromMap(mapOf(plain)), { ...material, ...options });
  assert.equal(run({}).status, "OFFLINE_OK");

  const noFile = run({ trustRegistry: DOCUMENT_PATH_NAMES_NO_REGULAR_FILE });
  assert.equal(noFile.trust_registry?.authorization_status, "INVALID_TRUST_REGISTRY");
  assert.equal(noFile.status, "OFFLINE_FAIL");

  const registryUnread = run({ trustRegistry: DOCUMENT_READ_FAILED });
  assert.deepEqual(
    { status: registryUnread.status, exit: registryUnread.exit_code, reason: registryUnread.outcome.reason, errors: registryUnread.errors.map((e) => e.code) },
    { status: "HOST_FAILURE", exit: EXIT_HOST_FAILURE, reason: "trust_registry_read_failed", errors: ["trust_registry_read_failed"] },
  );
  // Not evaluated: no authorization status at all, rather than INVALID_TRUST_REGISTRY.
  assert.equal(registryUnread.trust_registry, null);
  assert.equal(registryUnread.checks["trust_registry"], null);
  assert.deepEqual(registryUnread.checks_established, []);

  assert.throws(() => run({ trustRoots: DOCUMENT_PATH_NAMES_NO_REGULAR_FILE }), (err: Error) =>
    err instanceof TrustRootError && /names no regular file/.test(err.message) && !/not a JSON object/.test(err.message));

  const rootsUnread = run({ trustRoots: DOCUMENT_READ_FAILED });
  assert.deepEqual(
    { status: rootsUnread.status, exit: rootsUnread.exit_code, reason: rootsUnread.outcome.reason, errors: rootsUnread.errors.map((e) => e.code) },
    { status: "HOST_FAILURE", exit: EXIT_HOST_FAILURE, reason: "trust_root_read_failed", errors: ["trust_root_read_failed"] },
  );
  // The registry holds, and root authentication was not evaluated: neither pinned nor absent.
  assert.deepEqual(rootsUnread.trust_registry, {
    authorization_status: "AUTHORIZED_ACTIVE_KEY",
    signature_status: "VALID_SIGNATURE",
    trust_registry_root_signature_status: "ROOT_SIGNATURE_NOT_EVALUATED",
  });
  assert.deepEqual(rootsUnread.review_reasons, []);

  // Judged on its own: beside a registry that fails, the run fails and still reports the host
  // failure.
  const revoked = authRun(plain, { trust: (t: Doc) => { t.entries[0].status = "revoked"; t.entries[0].revoked_at = t.entries[0].effective_from; } });
  const failing = verifyBundleFiles(bundleReaderFromMap(mapOf(plain)), { ...revoked, trustRoots: DOCUMENT_READ_FAILED });
  assert.equal(failing.status, "OFFLINE_FAIL");
  assert.deepEqual(failing.errors.map((e) => e.code), ["trust_root_read_failed"]);
  assert.equal(failing.trust_registry?.trust_registry_root_signature_status, "ROOT_SIGNATURE_NOT_EVALUATED");

  // A trust registry beside a link that does not hold is not read, so a failed read changes
  // nothing.
  const noReceipt = sealed((b) => { b.delete("verification_receipt.json"); });
  const unlinked = (trustRegistry: unknown) => verifyBundleFiles(bundleReaderFromMap(mapOf(noReceipt)), { ...authRun(noReceipt), trustRegistry });
  assert.deepEqual(unlinked(DOCUMENT_READ_FAILED).errors, unlinked(authRun(noReceipt).trustRegistry).errors);
});

test("the error vocabulary is what this package can emit, section 5.3", SPEC.options, () => {
  const rows = errorRows();
  assert.deepEqual([...ERROR_CODES], rows.filter((row) => !(row in UNREACHABLE_CODES)));
  for (const unreachable of Object.keys(UNREACHABLE_CODES)) assert.ok(rows.includes(unreachable), unreachable);
  const reasons = reasonRows().filter(([number]) => number !== "1" && number !== "7").map(([, cell]) => code(cell));
  assert.equal(new Set(reasons).size, reasons.length);
});

// README.md tells a reader which codes of section 5.3 this package never reports. A sentence that
// scopes a normative table to a subset of verifiers must name a subset the table agrees with: "the
// error codes that refuse a ZIP archive never occur here" is false of `bundle_root_invalid`, a row
// whose condition names a ZIP archive and also a directory input with no `manifest.json`, which is
// what this verifier reports for one. Prose cannot be trusted to stay true of the codes, so the
// list the README gives is read from the file and held to what this package can emit (ERROR_CODES,
// its own source, and UNREACHABLE_CODES, which the test above holds to the table), and the two runs
// the sentence describes are executed rather than restated. The test needs no sibling: a
// single-repository clone, and the published package, hold their README the same way.
test("the README names as absent exactly the codes this package cannot emit, section 5.3", () => {
  const readme = readFileSync(join(PACKAGE_DIR, "README.md"), "utf8").replace(/\s+/g, " ");
  const scope = /so the codes of section 5\.3 whose condition is about a ZIP archive alone \(([^)]+)\) never occur here\./.exec(readme);
  assert.ok(scope !== null, "README.md does not scope the codes it says never occur, so nothing below is held");
  const named = [...scope[1]!.matchAll(/`([a-z_]+)`/g)].map((match) => match[1]!);
  const unreachable = Object.keys(UNREACHABLE_CODES).filter((row) => row !== "internal_error");
  assert.ok(named.length > 0 && unreachable.length > 0, "an empty scope would hold vacuously");
  assert.deepEqual(named, unreachable, "the README's list and the rows out of reach name different codes");
  for (const row of named) assert.ok(!(ERROR_CODES as readonly string[]).includes(row), `README.md says ${row} never occurs, but this package emits it`);
  // internal_error is the other row out of reach; the README gives it its own clause, section 4.
  assert.ok(readme.includes("a fault of the library is an exception rather than an `internal_error` report"), "README.md does not state the internal_error clause");
  // The row the exemption does not cover, and the runs behind the sentence.
  assert.ok(readme.includes("`bundle_root_invalid` is not one of them"), "README.md does not name the row its exemption does not cover");
  assert.ok((ERROR_CODES as readonly string[]).includes("bundle_root_invalid"));
  assert.ok(!readme.includes("the error codes that refuse a ZIP archive never occur here"), "README.md states a scope that bundle_root_invalid contradicts");
  assert.deepEqual(
    {
      "a directory with no manifest.json": onDisk(null, (root) => { mkdirSync(root, { recursive: true }); return root; }).outcome.reason,
      "a regular file": onDisk(null, (root) => { mkdirSync(root, { recursive: true }); const file = join(root, "plain.txt"); writeFileSync(file, "not a directory"); return file; }).outcome.reason,
    },
    { "a directory with no manifest.json": "bundle_root_invalid", "a regular file": "unsupported_input" },
  );
});

// A regular file is an input of a kind this package does not read, and section 5.3 gives that kind
// one row. The row is the rule and not a property of this implementation: archive intake is
// optional, the invalid_zip row belongs to a verifier that reads archives, and the two never hold
// together. The bytes of the file decide nothing here: a readable ZIP archive is refused by the
// same row as a file that is not one, which is what separates this rule from invalid_zip.
test("a regular file is unsupported_input for a verifier without archive intake, section 5.3", SPEC.options, () => {
  const text = readSpecification(SPEC, DOCUMENT);
  const conditions = new Map(table(text, ERROR_HEADER).map((row) => [code(row["code"]!), row["condition"]!]));
  assert.ok(text.replace(/\s+/g, " ").includes("Archive intake is optional: a verifier **MAY** read directory bundles only"));
  assert.ok(conditions.get("unsupported_input")!.includes("is of a kind the verifier does not read (a verifier without archive intake given a regular file)"), conditions.get("unsupported_input"));
  assert.ok(conditions.get("invalid_zip")!.startsWith("the verifier reads ZIP archives and"), conditions.get("invalid_zip"));
  assert.equal(UNREACHABLE_CODES["invalid_zip"], "this verifier reads no ZIP archive");
  const regularFile = (name: string, bytes: string | Uint8Array) => onDisk(null, (root) => {
    mkdirSync(root, { recursive: true });
    const file = join(root, name);
    writeFileSync(file, bytes);
    return file;
  });
  // An empty ZIP archive: 22 bytes, an end-of-central-directory record and nothing else.
  const emptyZip = Uint8Array.from([0x50, 0x4b, 0x05, 0x06, ...new Array(18).fill(0)]);
  const runs: Record<string, VerifyReport> = {
    "not-a-zip-archive": regularFile("plain.txt", "not a directory"),
    "a-readable-zip-archive": regularFile("bundle.zip", emptyZip),
  };
  for (const [label, report] of Object.entries(runs)) {
    assert.deepEqual(
      [report.status, report.verdict, report.exit_code, report.outcome.reason, report.errors.map((error) => error.code)],
      ["OFFLINE_FAIL", "FAIL", EXIT_OFFLINE_FAIL, "unsupported_input", ["unsupported_input"]],
      label,
    );
  }
});

// ---- sections 2, 5.4 and 6 ------------------------------------------------------------------------

for (const [entryName, verify] of ENTRIES) {
  test(`${entryName}: the members a report carries, sections 2, 5.4 and 6`, SPEC.options, () => {
    const text = readSpecification(SPEC, DOCUMENT);
    const section = text.split("## 6. The informative per-check results")[1]!.split("\n## ")[0]!;
    const eleven = codes(section.split("results:")[1]!.split(".")[0]!);
    assert.equal(eleven.length, 11);
    const structureRun = verify(sealed());
    assert.deepEqual(Object.keys(structureRun.checks), eleven);
    assert.equal(structureRun.trust_registry, null);
    assert.deepEqual(structureRun.errors, []);
    const members = table(text, ["member", "domain", "class"]).map((row) => code(row["member"]!));
    const report = verify(sealed(), authRun(sealed()));
    for (const member of members) {
      let value: any = report;
      for (const part of member.split(".")) {
        assert.ok(value !== null && typeof value === "object" && part in value, member);
        value = value[part];
      }
    }
    // The reason surface of section 5.1 on its standing example: the run with an evaluation time
    // and no trust root supplied.
    assert.deepEqual([report.status, report.verdict, report.outcome.reason, report.errors, report.review_reasons, report.trust_registry?.authorization_status, report.trust_registry?.signature_status, report.trust_registry?.trust_registry_root_signature_status],
      ["OFFLINE_REVIEW", "REVIEW", "trust_registry_root_not_pinned", [], ["trust_registry_root_not_pinned"], "AUTHORIZED_ACTIVE_KEY", "VALID_SIGNATURE", "NO_PINNED_TRUST_ROOT"]);
    assert.equal(report.evaluation_time, EVALUATION_TIME);
    // No member names a level (section 2).
    assert.ok(!/implemented_levels|verification_level|"L[0-5]"/.test(JSON.stringify(report)));
  });
}
