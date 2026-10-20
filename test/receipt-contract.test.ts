// verification_receipt.json is a closed contract, validated whenever a bundle carries it, at the
// structure check as at the link check (registry-link.md section 2); at the link check it must also
// name this bundle and, when it names a P1 digest, this P1. A receipt that is present but invalid
// fails the run; at the link check it is a failed link (registry_link false), and only an absent
// receipt leaves the link unevaluated (null, registry-link.md section 5).
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { Bundle, ENTRIES, FAIL, PACKAGE_DIR, PASS, REVIEW, TEST_DIR, ephemeralAuthorization, jcsText, linkEntryFor, outcome } from "./bundle-kit.ts";
import { sibling, siblingsRequired } from "./siblings.ts";
import { receiptContractErrors } from "../src/receipt-contract.ts";
// @ts-ignore: a plain .mjs script; its one export is typed by use below
import { renderReceiptContract } from "../scripts/generate-receipt-contract.mjs";

type Row = [label: string, build: () => { bundle: Bundle; opts: object }, expected: Record<string, unknown>];

function runRows(rows: Row[]) {
  const got: Record<string, unknown> = {};
  const want: Record<string, unknown> = {};
  for (const [label, build, expected] of rows) {
    const checks = Object.keys(expected).filter((k) => !["status", "verdict", "exit_code"].includes(k));
    for (const [entryName, verify] of ENTRIES) {
      want[`${entryName}: ${label}`] = expected;
      const { bundle, opts } = build();
      try {
        got[`${entryName}: ${label}`] = outcome(verify(bundle, opts), checks);
      } catch (err) {
        got[`${entryName}: ${label}`] = `threw ${(err as Error).name}`;
      }
    }
  }
  assert.deepEqual(got, want);
}

/** Structure: the receipt changed after sealing (its manifest digest is resealed), no entry. */
const atStructure = (change: (b: Bundle) => void) => () => {
  const bundle = Bundle.linkValid().seal();
  change(bundle);
  return { bundle, opts: {} };
};
/** Link: the receipt changed, then an entry built for the bundle as it is, so only the receipt is wrong. */
const atLink = (change: (b: Bundle) => void) => () => {
  const bundle = Bundle.linkValid().seal();
  change(bundle);
  return { bundle, opts: { registryEntry: linkEntryFor(bundle) } };
};
const editReceipt = (fn: (r: any) => void) => (b: Bundle) => { b.edit("verification_receipt.json", fn); };
const rawReceipt = (text: string | Uint8Array) => (b: Bundle) => { b.setBytes("verification_receipt.json", text); };

test("at the structure check a receipt outside its closed schema fails the run and leaves registry_link null", () => {
  const STRUCTURE_FAIL = { ...FAIL, registry_link: null };
  runRows([
    ["not JSON", atStructure(rawReceipt("not valid JSON")), STRUCTURE_FAIL],
    ["[]", atStructure(rawReceipt("[]")), STRUCTURE_FAIL],
    ["an unknown member", atStructure(editReceipt((r) => { r.unauthenticated_interpretation = "x"; })), STRUCTURE_FAIL],
    ["no object_type", atStructure(editReceipt((r) => { delete r.object_type; })), STRUCTURE_FAIL],
    ["policy_version \"1\"", atStructure(editReceipt((r) => { r.policy_version = "1"; })), STRUCTURE_FAIL],
    ["invalid UTF-8", atStructure((b) => {
      const text = new TextDecoder().decode(b.bytes("verification_receipt.json"));
      const at = text.indexOf('"pass"') + 3;
      const bytes = new TextEncoder().encode(text);
      b.setBytes("verification_receipt.json", new Uint8Array([...bytes.slice(0, at), 0xff, ...bytes.slice(at)]));
    }), STRUCTURE_FAIL],
    // Control: a conforming receipt passes, and its bundle_id is not compared below the link check.
    ["the fixture receipt", atStructure(() => {}), { ...PASS, registry_link: null }],
    ["a receipt naming another bundle", atStructure(editReceipt((r) => { r.bundle_id = "unrelated-bundle"; })), { ...PASS, registry_link: null }],
  ]);
});

test("at the link check a receipt outside its closed schema is a failed link", () => {
  const LINK_FAIL = { ...FAIL, registry_link: false };
  runRows([
    ["an unknown member", atLink(editReceipt((r) => { r.unauthenticated_interpretation = "x"; })), LINK_FAIL],
    ["policy_version \"1\" with the entry resealed", atLink(editReceipt((r) => { r.policy_version = "1"; })), LINK_FAIL],
    // A well-formed later version fires the receipt's version gate (exit 4); any other value is a
    // refusal.
    ["schema_version v9", atLink(editReceipt((r) => { r.schema_version = "v9"; })), { status: "UNSUPPORTED_VERSION", verdict: null, exit_code: 4, registry_link: null }],
    ["schema_version V2", atLink(editReceipt((r) => { r.schema_version = "V2"; })), LINK_FAIL],
    ["reason_code_vocabulary_version loquitur.reason_codes.v2", atLink(editReceipt((r) => { r.reason_code_vocabulary_version = "loquitur.reason_codes.v2"; })),
      { status: "UNSUPPORTED_VERSION", verdict: null, exit_code: 4, registry_link: null }],
    ["a bare manifest_sha256", atLink(editReceipt((r) => { r.manifest_sha256 = r.manifest_sha256.slice("sha256:".length); })), LINK_FAIL],
    ["verified_at \"not-an-instant\"", atLink(editReceipt((r) => { r.verified_at = "not-an-instant"; })), LINK_FAIL],
    ["object_type \"arbitrary\"", atLink(editReceipt((r) => { r.object_type = "arbitrary"; })), LINK_FAIL],
    ["reason_codes naming an uncatalogued code", atLink(editReceipt((r) => { r.reason_codes = ["NOT_A_CODE"]; })), LINK_FAIL],
    ["the number 1", () => {
      const bundle = Bundle.linkValid().seal();
      const registryEntry = linkEntryFor(bundle);
      bundle.setBytes("verification_receipt.json", "1");
      return { bundle, opts: { registryEntry } };
    }, LINK_FAIL],
    ["600 levels of nesting", () => {
      const bundle = Bundle.linkValid().seal();
      const registryEntry = linkEntryFor(bundle);
      const body = jcsText(bundle.json("verification_receipt.json"));
      bundle.setBytes("verification_receipt.json", `${body.slice(0, -1)},"x":${"[".repeat(600)}0${"]".repeat(600)}}`);
      return { bundle, opts: { registryEntry } };
    }, LINK_FAIL],
    // Control: at the authorization check a broken link leaves trust unevaluated and the signature
    // unreported.
    ["an authorization entry whose receipt_hash is wrong", () => {
      const bundle = Bundle.linkValid().seal();
      return { bundle, opts: ephemeralAuthorization(bundle, { receipt_hash: `sha256:${"0".repeat(64)}` }) };
    }, { ...FAIL, registry_link: false, trust_registry: null, registry_signature: "UNSUPPORTED" }],
    // Control: an absent receipt leaves the link unevaluated, a question
    // (verification_receipt_not_provided).
    ["no receipt", () => {
      const bundle = Bundle.linkValid().seal();
      const registryEntry = linkEntryFor(bundle);
      return { bundle: bundle.delete("verification_receipt.json"), opts: { registryEntry } };
    }, { ...REVIEW, registry_link: null }],
  ]);
});

test("at the link check the receipt must name this bundle and, when it names one, this P1", () => {
  runRows([
    ["bundle_id of another bundle", atLink(editReceipt((r) => { r.bundle_id = "unrelated-bundle"; })), { ...FAIL, registry_link: false }],
    ["a p1_sha256 that is not this P1's", atLink(editReceipt((r) => { r.p1_sha256 = `sha256:${"a".repeat(64)}`; })), { ...FAIL, registry_link: false }],
    ["this P1's p1_sha256", atLink((b) => { b.edit("verification_receipt.json", (r) => { r.p1_sha256 = `sha256:${b.p1Digest()}`; }); }), { ...PASS, registry_link: true }],
    ["this P1's p1_sha256, bare", atLink((b) => { b.edit("verification_receipt.json", (r) => { r.p1_sha256 = b.p1Digest(); }); }), { ...FAIL, registry_link: false }],
    ["every optional member null", atLink(editReceipt((r) => {
      for (const name of ["anchor_provider", "anchor_type", "asset_id", "network", "p1_sha256", "policy_pack_sha256", "primary_anchor"]) r[name] = null;
    })), { ...PASS, registry_link: true }],
    ["a manifest whose bundle_id is blank, sealed everywhere", () => {
      const bundle = Bundle.linkValid();
      bundle.edit("manifest.json", (m) => { m.bundle_id = " "; });
      bundle.edit("verification_receipt.json", (r) => { r.bundle_id = " "; });
      bundle.seal();
      return { bundle, opts: { registryEntry: linkEntryFor(bundle) } };
    }, { ...FAIL, registry_link: false }],
  ]);
});

// ---------------------------------------------------------------- the generated rules
const PROTOCOL = sibling(
  "loquitur-protocol",
  [join(PACKAGE_DIR, "../loquitur-protocol/docs/specification/schemas"), join(PACKAGE_DIR, "../public/loquitur-protocol/docs/specification/schemas")],
  "verification_receipt.schema.json",
  "sibling loquitur-protocol schema absent",
);

test("src/receipt-contract.generated.ts is what the protocol's receipt schema generates", PROTOCOL.options, () => {
  const schema = JSON.parse(readFileSync(PROTOCOL.path("verification_receipt.schema.json"), "utf8"));
  const committed = readFileSync(join(PACKAGE_DIR, "src/receipt-contract.generated.ts"), "utf8");
  assert.equal(committed, renderReceiptContract(schema));
  // A keyword the validator does not enforce stops the generation instead of being skipped.
  assert.throws(() => renderReceiptContract({ ...schema, maxProperties: 30 }), /unsupported keyword maxProperties/);
  assert.throws(() => renderReceiptContract({ ...schema, properties: { ...schema.properties, bundle_id: { type: "string", format: "uuid" } } }),
    /unsupported keyword format/);
});

// One table of documents, judged by this validator and by the Python schema validator of
// loquitur-schemas (validate_instance), which must accept and reject the same ones.
const PARITY_DOCUMENTS: Array<[string, (r: any) => unknown]> = [
  ["the fixture", (r) => r],
  ["an unknown member", (r) => ({ ...r, extra: 1 })],
  ["no bundle_id", (r) => { const { bundle_id: _, ...rest } = r; return rest; }],
  ["bundle_id \"\"", (r) => ({ ...r, bundle_id: "" })],
  ["policy_version \"1\"", (r) => ({ ...r, policy_version: "1" })],
  ["policy_version 0", (r) => ({ ...r, policy_version: 0 })],
  ["policy_version true", (r) => ({ ...r, policy_version: true })],
  ["status \"ok\"", (r) => ({ ...r, status: "ok" })],
  ["reason_codes []", (r) => ({ ...r, reason_codes: [] })],
  ["reason_codes duplicated", (r) => ({ ...r, reason_codes: ["INTEGRITY_OK", "INTEGRITY_OK"] })],
  ["reason_codes uncatalogued", (r) => ({ ...r, reason_codes: ["NOT_A_CODE"] })],
  ["manifest_sha256 upper case", (r) => ({ ...r, manifest_sha256: r.manifest_sha256.toUpperCase() })],
  ["manifest_sha256 with a newline", (r) => ({ ...r, manifest_sha256: `${r.manifest_sha256}\n` })],
  ["verified_at 2026-13-01", (r) => ({ ...r, verified_at: "2026-13-01T00:00:00Z" })],
  ["verified_at with a newline", (r) => ({ ...r, verified_at: `${r.verified_at}\n` })],
  ["schema_version v9", (r) => ({ ...r, schema_version: "v9" })],
  ["reason_code_vocabulary_version other", (r) => ({ ...r, reason_code_vocabulary_version: "loquitur.reason_codes.v2" })],
  ["verification_mode \"\"", (r) => ({ ...r, verification_mode: "" })],
  ["storage [1]", (r) => ({ ...r, storage: [1] })],
  ["storage [{}]", (r) => ({ ...r, storage: [{}] })],
  ["primary_anchor []", (r) => ({ ...r, primary_anchor: [] })],
  ["p1_sha256 null", (r) => ({ ...r, p1_sha256: null })],
  ["p1_sha256 \"sha256:...\"", (r) => ({ ...r, p1_sha256: `sha256:${"a".repeat(64)}` })],
  ["asset_type \"car\"", (r) => ({ ...r, asset_type: "car" })],
  ["a string, not an object", () => "receipt"],
];

const SCHEMAS = sibling(
  "loquitur-schemas",
  [join(PACKAGE_DIR, "../loquitur-schemas"), join(PACKAGE_DIR, "../public/loquitur-schemas")],
  "src/loquitur/schemas/validator.py",
  "sibling loquitur-schemas absent",
);

const VERIFY_PY = sibling(
  "loquitur-verify-py",
  [join(PACKAGE_DIR, "../loquitur-verify-py"), join(PACKAGE_DIR, "../public/loquitur-verify-py")],
  "src/loquitur/verify/contract_validation.py",
  "sibling loquitur-verify-py absent",
);

// Three validators of one closed schema must agree row for row: this package's generated
// receiptContractErrors, the Python verifier's generated contract (contract_errors, which decides
// the receipt at the structure check and link there) and the loquitur-schemas validator. Comparing
// each verifier with the third validator only would let the two verifiers' receipt rules drift
// apart.
test("the receipt validator accepts and rejects what the Python verifier's contract and schema validator do", {
  skip: SCHEMAS.options.skip || VERIFY_PY.options.skip,
}, (t) => {
  const base = JSON.parse(readFileSync(join(PACKAGE_DIR, "test-vectors/bundles/link_valid_bundle/verification_receipt.json"), "utf8"));
  const documents = PARITY_DOCUMENTS.map(([label, make]) => [label, make(structuredClone(base))] as const);
  const python = process.env.LOQUITUR_PYTHON || "python";
  const script = [
    "import json, sys",
    "from loquitur.schemas.validator import validate_instance",
    "from loquitur.verify.contract_validation import contract_errors",
    "docs = json.loads(sys.stdin.read())",
    "print(json.dumps([[validate_instance('verification_receipt', d).ok, not contract_errors('verification_receipt', d)] for d in docs]))",
  ].join("\n");
  const child = spawnSync(python, ["-c", script], {
    input: JSON.stringify(documents.map(([, doc]) => doc)), encoding: "utf8", cwd: TEST_DIR,
    env: {
      ...process.env,
      PYTHONPATH: [join(SCHEMAS.dir, "src"), join(VERIFY_PY.dir, "src"), process.env.PYTHONPATH].filter(Boolean).join(process.platform === "win32" ? ";" : ":"),
    },
  });
  if (child.error || child.status !== 0) {
    const why = `no Python able to import loquitur.schemas and loquitur.verify (${python}): ${child.error?.message ?? child.stderr.trim().split("\n").pop()}`;
    if (siblingsRequired()) assert.fail(why);
    t.skip(why);
    return;
  }
  const pythonOk: Array<[schemas: boolean, verifyPy: boolean]> = JSON.parse(child.stdout);
  assert.equal(pythonOk.length, documents.length);
  const disagreements = documents
    .map(([label, doc], i) => ({
      label,
      ts: receiptContractErrors(doc).length === 0,
      schemas: pythonOk[i]![0],
      verifyPy: pythonOk[i]![1],
    }))
    .filter((row) => row.ts !== row.schemas || row.ts !== row.verifyPy);
  assert.deepEqual(disagreements, []);
  // The table is not vacuous: it holds documents all three accept and documents all three reject.
  const verdicts = pythonOk.map(([, verifyPy]) => verifyPy);
  assert.ok(verdicts.includes(true) && verdicts.includes(false));
});

// The calendar is part of both verifiers' receipt contracts and of no JSON Schema keyword:
// verified_at in the instant pattern but naming no instant is refused by this validator, by the
// Python verifier's contract and by the loquitur-schemas validator, which holds every instant to
// the calendar beside the schema (canonicalization-and-hashing.md, "Input strictness", rule 8).
test("the receipt validator refuses a verified_at that is not a date, as the Python verifier's contract does", {
  skip: SCHEMAS.options.skip || VERIFY_PY.options.skip,
}, (t) => {
  const base = JSON.parse(readFileSync(join(PACKAGE_DIR, "test-vectors/bundles/link_valid_bundle/verification_receipt.json"), "utf8"));
  const values = ["2026-02-30T12:00:00Z", "2026-04-31T12:00:00Z", "2026-02-29T12:00:00Z", "2026-04-29T12:00:60Z", "0000-01-01T00:00:00Z", "2028-02-29T12:00:00Z"];
  const documents = values.map((value) => ({ ...base, verified_at: value }));
  const python = process.env.LOQUITUR_PYTHON || "python";
  const script = [
    "import json, sys",
    "from loquitur.schemas.validator import validate_instance",
    "from loquitur.verify.contract_validation import contract_errors",
    "docs = json.loads(sys.stdin.read())",
    "print(json.dumps([[validate_instance('verification_receipt', d).ok, not contract_errors('verification_receipt', d)] for d in docs]))",
  ].join("\n");
  const child = spawnSync(python, ["-c", script], {
    input: JSON.stringify(documents), encoding: "utf8", cwd: TEST_DIR,
    env: {
      ...process.env,
      PYTHONPATH: [join(SCHEMAS.dir, "src"), join(VERIFY_PY.dir, "src"), process.env.PYTHONPATH].filter(Boolean).join(process.platform === "win32" ? ";" : ":"),
    },
  });
  if (child.error || child.status !== 0) {
    const why = `no Python able to import loquitur.schemas and loquitur.verify (${python}): ${child.error?.message ?? child.stderr.trim().split("\n").pop()}`;
    if (siblingsRequired()) assert.fail(why);
    t.skip(why);
    return;
  }
  const pythonOk: Array<[schemas: boolean, verifyPy: boolean]> = JSON.parse(child.stdout);
  const got = values.map((value, i) => ({ value, ts: receiptContractErrors(documents[i]).length === 0, verifyPy: pythonOk[i]![1], schema: pythonOk[i]![0] }));
  assert.deepEqual(got, values.map((value) => {
    const instant = value === "2028-02-29T12:00:00Z";
    return { value, ts: instant, verifyPy: instant, schema: instant };
  }));
});

test("the receipt validator refuses what the schema refuses", () => {
  const base = JSON.parse(readFileSync(join(PACKAGE_DIR, "test-vectors/bundles/link_valid_bundle/verification_receipt.json"), "utf8"));
  assert.deepEqual(receiptContractErrors(base), []);
  assert.deepEqual(receiptContractErrors({ ...base, extra: 1 }), ["$.extra:additionalProperties"]);
  assert.deepEqual(receiptContractErrors({ ...base, policy_version: "1" }), ["$.policy_version:type"]);
  assert.deepEqual(receiptContractErrors({ ...base, reason_codes: ["INTEGRITY_OK", "INTEGRITY_OK"] }), ["$.reason_codes:uniqueItems"]);
});
