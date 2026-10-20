// Every row of the member appendix, executed against this verifier.
//
// loquitur-protocol docs/specification/document-contracts.md lists every member of every document
// a verifier loads: whether it is required, its type, the values it may take, example values that
// break it, and the outcome a run reports. The rows are read from the sibling checkout and run
// here: the member is removed when it is required, each refused value is put in its place, and the
// report's status, verdict, exit code, outcome.reason and error codes (the normative surface of
// a run without a trust registry, report-contract.md section 2) are compared with the
// appendix's outcome. The documents whose contract has its own parser here (the receipt, the
// registry entry and the trust registry) are also compared as documents, so a contract the two
// implementations read differently fails even where the status agrees.
//
// The locks matter as much as the refusals: an optional member is removed, a nullable one is set
// to `null`, and the run must be unchanged. Without them a verifier that refused everything would
// pass.
//
// The trust-root document (§11) is run as the library refuses it: a document that breaks a row
// is refused with a TrustRootError before any evidence is read, which is the library's form of
// the appendix's `input-refused`. The registered vocabulary document (§15) is run the same way,
// refused with a VocabularyError. The command line's own inputs (§12) are not run here: this
// package has no command line. The test below names that section, so the omission is a statement
// rather than a silence.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Bundle, jcsText, sha256Hex, verifyOnDisk, linkEntryFor, ephemeralAuthorizationWith, ephemeralRoot, refusal } from "./bundle-kit.ts";
import { REGISTERED_VOCABULARIES } from "../src/registered-vocabularies.generated.ts";
import { VOCABULARY_KINDS, operatorVocabulary } from "../src/vocabulary.ts";
import { DOCUMENT_NOT_STRICT_JSON, readDocumentPath } from "../src/verify.ts";
import { parseRegistryEntry, parseTrustRegistry } from "../src/protocol-input.ts";
import { parseTrustRoots } from "../src/trust-root.ts";
import { receiptContractErrors } from "../src/receipt-contract.ts";
import { code, codes, readSpecification, sections, specification, tablesWithHeader } from "./spec-tables.ts";

const DOCUMENT = "document-contracts.md";
const SPEC = specification(DOCUMENT);
const MEMBER_HEADER = ["member", "required", "type", "value", "refused", "outcome", "rule"];
const CASE_HEADER = ["case", "outcome", "rule"];
const OUTCOME_HEADER = ["outcome", "`status`", "`verdict`", "`outcome.reason`", "`errors`", "exit", "rule"];
const ABSENT = Symbol("absent");

/** The section of the appendix each document's rows live in, by the start of the section title. */
const DOCUMENTS: Array<[string, string]> = [
  ["`manifest.json`", "manifest"],
  ["`p1.json`", "p1"],
  ["`canonical_input.json`", "canonical_input"],
  ["The digest sidecars", "sidecar"],
  ["`envelope_env1.json`", "envelope"],
  ["`verification_receipt.json`", "receipt"],
  ["The registry entry", "entry"],
  ["The trust registry", "trust"],
  ["The trust-root document", "roots"],
  ["The registered vocabulary document", "vocabulary"],
];
/** The section this package cannot run, and why: it has no command line. Named so that the omission is checked, not assumed. */
const NOT_RUN_HERE = "The verifier's own inputs";
// A well-formed parent for the members nested under one: examples, not rules.
const VALID_ANCHOR = { method: "blockchain_transaction", system: "testnet-v1.0", anchor_reference: "tx-1" };
const VALID_SIGNATURE = {
  algorithm: "secp256k1_ecdsa_sha256",
  key_id: "demo-key-link",
  payload_id: "registry_entry_signing_payload_v2",
  payload_version: 2,
  signature: "ab".repeat(64),
};

const appendix = () => readSpecification(SPEC, DOCUMENT);

function sectionRows(header: string[]): Array<[string, Record<string, string>]> {
  const out: Array<[string, Record<string, string>]> = [];
  for (const [title, body] of sections(appendix())) {
    for (const row of tablesWithHeader(body, header)) out.push([title, row]);
  }
  return out;
}

function documentOf(title: string): string | null {
  const name = title.includes(". ") ? title.slice(title.indexOf(". ") + 2) : title;
  for (const [prefix, key] of DOCUMENTS) if (name.startsWith(prefix)) return key;
  return null;
}

interface Outcome { status: string; verdict: string | null; exit_code: number; "outcome.reason": string; "errors[].code": string[] }
/** An input the library refuses with an error of the host language, before any evidence is read. */
interface Refused { refused: string }
type Result = Outcome | Refused;

function outcomes(): Map<string, Result> {
  const found = new Map<string, Result>();
  for (const [, row] of sectionRows(OUTCOME_HEADER)) {
    // A command line's refusal (exit 64, no report) is, in a library, a TrustRootError before any
    // read.
    if (row["`status`"] === "none") {
      found.set(code(row["outcome"]!), { refused: "TrustRootError" });
      continue;
    }
    found.set(code(row["outcome"]!), {
      status: code(row["`status`"]!),
      verdict: code(row["`verdict`"]!) === "null" ? null : code(row["`verdict`"]!),
      exit_code: Number(code(row["exit"]!)),
      "outcome.reason": code(row["`outcome.reason`"]!),
      "errors[].code": row["`errors`"] === "none" ? [] : codes(row["`errors`"]!),
    });
  }
  return found;
}

// Read on first use, never at module load: without the protocol sibling the tests below skip,
// and a module that read the appendix while loading would fail the whole file instead.
let OUTCOMES_CACHE: Map<string, Result> | null = null;
const OUTCOMES = () => (OUTCOMES_CACHE ??= outcomes());

function refusedValues(row: Record<string, string>): unknown[] {
  if (row["refused"] === "-") return [];
  return codes(row["refused"]!).map((span) => (span.startsWith("<") ? span : JSON.parse(span)));
}

function pathOf(row: Record<string, string>): string {
  return row["member"]!.replace(/`/g, "").replace("[i]", "[0]");
}

// One value of each JSON type, for the `type` column of a row (document-contracts.md section 1).
// The column is a rule: a value whose type the cell does not admit is refused with the row's
// outcome, and a row whose `value` cell is `-` states no rule beyond its type, so a value of a
// type it admits is accepted. Reading the cell rather than the `refused` examples is what makes
// widening a cell fail: the value moves to the accepted side, where this verifier refuses it.
const TYPE_SAMPLE: Array<[string, unknown]> = [
  ["null", null],
  ["boolean", true],
  ["integer", 1],
  ["number", 1.5],
  ["string", "x"],
  ["array", []],
  ["object", {}],
];

/** The JSON types the row's `type` cell admits; `number` admits `integer` as well. */
function admittedTypes(row: Record<string, string>): Set<string> {
  const names = new Set(TYPE_SAMPLE.map(([name]) => name));
  const found = new Set(codes(row["type"]!).filter((name) => names.has(name)));
  if (found.has("number")) found.add("integer");
  return found;
}

function setPath(node: any, path: string, value: unknown): void {
  const parts = (path.match(/[^.\[\]]+|\[\d+\]/g) ?? []).map((token) =>
    token.startsWith("[") ? Number(token.slice(1, -1)) : token,
  );
  for (const part of parts.slice(0, -1)) node = node[part];
  const last = parts[parts.length - 1]!;
  if (value === ABSENT) {
    if (Array.isArray(node)) node.splice(last as number, 1);
    else delete node[last];
  } else if (typeof last === "string") {
    Object.defineProperty(node, last, { value, enumerable: true, writable: true, configurable: true });
  } else {
    node[last] = value;
  }
}

function report(bundle: Bundle, options: Record<string, unknown> = {}): Result {
  let r;
  try {
    r = verifyOnDisk(bundle, options as any);
  } catch (err) {
    if (err instanceof Error && (err.name === "TrustRootError" || err.name === "VocabularyError")) return { refused: err.name };
    throw err;
  }
  return { status: r.status, verdict: r.verdict, exit_code: r.exit_code, "outcome.reason": r.outcome.reason, "errors[].code": r.errors.map((error) => error.code) };
}

/** Recompute what commits to the manifest, leaving the manifest's own members as they are. */
function resealOverManifest(bundle: Bundle): Bundle {
  const manifest = bundle.json("manifest.json");
  const digest = bundle.manifestDigest();
  bundle.setBytes("manifest.sha256", digest);
  if (bundle.has("envelope_env1.json")) {
    bundle.edit("envelope_env1.json", (env: any) => {
      env.bundle_manifest_sha256 = `sha256:${digest}`;
      // A manifest that names no bundle leaves the envelope nothing to link to: `null`, as the
      // Python verifier writes it, so that the case under test is the manifest's own member.
      if (manifest && typeof manifest === "object" && !Array.isArray(manifest)) env.bundle_id = manifest.bundle_id ?? null;
    });
    bundle.setBytes("envelope.sha256", sha256Hex(jcsText(bundle.json("envelope_env1.json"))));
  }
  if (bundle.has("verification_receipt.json")) {
    bundle.edit("verification_receipt.json", (receipt: any) => {
      receipt.manifest_sha256 = `sha256:${digest}`;
    });
  }
  return bundle;
}

/** The test bundle with one member of `document` changed, every other digest recomputed. */
function bundleWith(document: string, path: string, value: unknown): Bundle {
  const bundle = Bundle.linkValid();
  if (document === "p1") {
    const p1 = bundle.json("p1.json");
    setPath(p1, path, value);
    bundle.setJson("p1.json", p1);
    if (path === "ik") {
      // An honest producer that changes the projection recomputes the input hash over it; a
      // projection no producer could hash keeps the digest it had.
      const keys = p1.ik;
      if (!("ik" in p1) || (Array.isArray(keys) && keys.every((key: unknown) => typeof key === "string"))) {
        const updated = bundle.json("p1.json");
        updated.ih = bundle.inputHashFor(updated);
        bundle.setJson("p1.json", updated);
      }
    }
    return bundle.seal();
  }
  if (document === "canonical_input") {
    bundle.setJson("canonical_input.json", value);
    return bundle.seal();
  }
  bundle.seal();
  if (document === "manifest") {
    const manifest = bundle.json("manifest.json");
    setPath(manifest, path, value);
    bundle.setJson("manifest.json", manifest);
    return resealOverManifest(bundle);
  }
  if (document === "envelope") {
    const envelope = bundle.json("envelope_env1.json");
    setPath(envelope, path, value);
    bundle.setJson("envelope_env1.json", envelope);
    bundle.setBytes("envelope.sha256", sha256Hex(jcsText(bundle.json("envelope_env1.json"))));
    return bundle;
  }
  if (document === "receipt") {
    const receipt = bundle.json("verification_receipt.json");
    setPath(receipt, path, value);
    return bundle.setJson("verification_receipt.json", receipt);
  }
  if (document === "sidecar") {
    const digest = new TextDecoder().decode(bundle.bytes(path));
    const replacement: Record<string, string> = {
      "<upper>": digest.toUpperCase(),
      "<newline>": `${digest}\n`,
      "<other>": sha256Hex("another object"),
    };
    // `value` is a marker of the `refused` column, or, for a `bytes` row's type run, a value
    // whose canonical form becomes the whole file.
    const marker = typeof value === "string" ? replacement[value] : undefined;
    bundle.setBytes(path, marker ?? jcsText(value));
    // A sidecar may itself be a declared member (`p1.sha256` is): the manifest's digests are
    // recomputed over the changed bytes, and the sidecar under test is never resealed.
    const manifest = bundle.json("manifest.json");
    for (const name of Object.keys(manifest.files)) {
      if (bundle.has(name)) manifest.files[name] = `sha256:${sha256Hex(bundle.bytes(name))}`;
    }
    bundle.setJson("manifest.json", manifest);
    const manifestDigest = bundle.manifestDigest();
    if (path !== "manifest.sha256") bundle.setBytes("manifest.sha256", manifestDigest);
    bundle.edit("envelope_env1.json", (env: any) => {
      env.bundle_manifest_sha256 = `sha256:${manifestDigest}`;
    });
    if (path !== "envelope.sha256") bundle.setBytes("envelope.sha256", sha256Hex(jcsText(bundle.json("envelope_env1.json"))));
    bundle.edit("verification_receipt.json", (receipt: any) => {
      receipt.manifest_sha256 = `sha256:${manifestDigest}`;
    });
    return bundle;
  }
  throw new Error(`no builder for ${document}`);
}

function preparedEntry(bundle: Bundle, path: string): any {
  const entry = linkEntryFor(bundle);
  if (path.startsWith("anchor.")) entry.anchor = { ...VALID_ANCHOR };
  if (path.startsWith("signature.")) entry.signature = { ...VALID_SIGNATURE };
  return entry;
}

/** Authorization material for this bundle: the entry signed by a key made for this run, and the registry. */
function authRun(change?: (registry: any) => any) {
  const bundle = Bundle.linkValid().seal();
  const material = ephemeralAuthorizationWith(bundle, {});
  const registry = change ? change(material.trustRegistry) : material.trustRegistry;
  return { bundle, options: { registryEntry: material.registryEntry, trustRegistry: registry } };
}

/**
 * Authorization material with a trust-root document: the entry signed by a key made for this run,
 * the registry authorizing it and signed by the root N, and the document {"roots":[N]}.
 */
function authorizationWithRoots() {
  const bundle = Bundle.linkValid().seal();
  const { root, sign } = ephemeralRoot("root-1");
  const { registryEntry, trustRegistry } = ephemeralAuthorizationWith(bundle, { trust: (t: any) => { delete t.signature; } });
  sign(trustRegistry);
  return { bundle, registryEntry, trustRegistry, document: { roots: [root] } as any };
}

/** The trust-root document with one member changed, or replaced as a whole for the row "the document". */
function rootsDocument(document: any, path: string, value: unknown): unknown {
  if (path === "the document") return value;
  setPath(document, path, value);
  return document;
}

function runMember(document: string, path: string, value: unknown): Result {
  if (document === "roots") {
    const { bundle, registryEntry, trustRegistry, document: roots } = authorizationWithRoots();
    return report(bundle, { registryEntry, trustRegistry, trustRoots: rootsDocument(roots, path, value) });
  }
  if (document === "entry") {
    const bundle = Bundle.linkValid().seal();
    const entry = preparedEntry(bundle, path);
    setPath(entry, path, value);
    return report(bundle, { registryEntry: entry });
  }
  if (document === "trust") {
    const { bundle, options } = authRun((registry) => {
      setPath(registry, path, value);
      return registry;
    });
    return report(bundle, options);
  }
  return report(bundleWith(document, path, value));
}

function validOutcome(document: string): Result {
  if (document === "roots") {
    const { bundle, registryEntry, trustRegistry, document: roots } = authorizationWithRoots();
    return report(bundle, { registryEntry, trustRegistry, trustRoots: roots });
  }
  if (document === "entry") {
    const bundle = Bundle.linkValid().seal();
    return report(bundle, { registryEntry: linkEntryFor(bundle) });
  }
  if (document === "trust") {
    const { bundle, options } = authRun();
    return report(bundle, options);
  }
  return report(Bundle.linkValid().seal());
}

/** The contract decision of this package's own parser, for the documents that have one. */
function contractRefuses(document: string, value: unknown): boolean | null {
  if (document === "entry") return !parseRegistryEntry(value as never).ok;
  if (document === "trust") return !parseTrustRegistry(value as never).ok;
  if (document === "receipt") return receiptContractErrors(value).length > 0;
  if (document === "roots") return refusal(() => parseTrustRoots(value)) !== null;
  if (document === "vocabulary") return refusal(() => operatorVocabulary("workflow", value)) !== null;
  return null;
}

// A test per row, so a failure names the member. Enumerating the rows means reading the
// appendix, which a single-repository clone does not carry: there the list is empty and the
// standalone tests below carry the skip, or the failure when the workspace requires siblings.
const MEMBER_ROWS = SPEC.present ? sectionRows(MEMBER_HEADER).filter(([title]) => documentOf(title) !== null) : [];

// A refused example of the appendix that is a well-formed later version: the version gate of the
// signing payload (section 1, gate 7) fires for the pair registry_entry_signing_payload_v2 / 3
// before the contract row is read, so the run is an unsupported version, not a refused entry.
// Such an example is run as the gate it fires, not as the row.
const FIRES_A_GATE: Array<[string, string, unknown]> = [["entry", "signature.payload_version", 3]];

for (const [title, row] of MEMBER_ROWS) {
  const document = documentOf(title)!;
  // The rows of §15 have their own runner below: their members are paths over every value.
  if (document === "vocabulary") continue;
  const path = pathOf(row);
  const expected = OUTCOMES().get(code(row["outcome"]!))!;

  test(`${document}: ${row["member"]} is refused as the appendix says`, SPEC.options, () => {
    assert.ok(expected, `no outcome ${row["outcome"]} in the appendix`);
    for (const value of refusedValues(row)) {
      const gated = FIRES_A_GATE.some(([d, m, v]) => d === document && m === path && v === value);
      assert.deepEqual(runMember(document, path, value), gated ? OUTCOMES().get("unsupported-version") : expected, `${path} = ${JSON.stringify(value)}`);
    }
    // A required member that is absent has its row's outcome. The row "the document" of the
    // trust-root section is required in the sense of a command line's path that names no readable
    // document; a library is given the document itself, and not giving it is the run without roots,
    // so that one absence is not a mutation of a member and is not run here.
    if (row["required"] === "yes" && row["type"] !== "bytes" && !(document === "roots" && path === "the document")) {
      assert.deepEqual(runMember(document, path, ABSENT), expected, `${path} absent`);
    }
  });

  if ((row["required"] === "no" || row["type"]!.includes("`null`")) && row["member"] !== "the document") {
    test(`${document}: ${row["member"]} may be absent or null`, SPEC.options, () => {
      const valid = validOutcome(document);
      if (row["required"] === "no" && row["type"] !== "bytes") {
        assert.deepEqual(runMember(document, path, ABSENT), valid, `${path} may be absent`);
      }
      if (row["required"] === "no" && row["type"]!.includes("`null`")) {
        assert.deepEqual(runMember(document, path, null), valid, `${path} may be null`);
      }
    });
  }

  if (row["type"] !== "bytes") {
    test(`${document}: ${row["member"]} takes the types its cell admits and no others`, SPEC.options, () => {
      const admitted = admittedTypes(row);
      assert.ok(admitted.size > 0, `${row["member"]}: the type cell names no JSON type`);
      const valid = row["value"] === "-" ? validOutcome(document) : null;
      let compared = 0;
      for (const [name, value] of TYPE_SAMPLE) {
        if (!admitted.has(name)) {
          assert.deepEqual(runMember(document, path, value), expected, `${path} = ${JSON.stringify(value)} (${name})`);
          compared += 1;
        } else if (valid !== null && !(name === "null" && row["required"] === "yes")) {
          const got = runMember(document, path, value);
          assert.deepEqual(got, valid, `${path} = ${JSON.stringify(value)} (${name}) is a type the row admits`);
          compared += 1;
        }
      }
      // A loop over the types a cell refuses runs nothing for a cell that refuses none. Without
      // this a cell widened to admit every JSON type passes having compared nothing, which is a
      // claim of coverage that is not coverage.
      assert.ok(compared > 0, `${path}: its type cell decided no value, so this compared nothing`);
    });
  } else {
    // A `bytes` cell admits no JSON type, and this runs that rule rather than exempting the
    // row from it: a `bytes` row describes a file, and the file is not JSON at all, so the
    // canonical form of a value of any JSON type, written as the whole file, carries the row's
    // outcome. It keeps every member row of the appendix under the second check of §1, and it
    // is a comparison the `refused` column does not make: that column holds three
    // digest-shaped byte strings.
    test(`${document}: ${row["member"]} is not JSON of any type`, SPEC.options, () => {
      assert.equal(admittedTypes(row).size, 0, `${row["member"]}: a \`bytes\` cell names no JSON type`);
      let compared = 0;
      for (const [name, value] of TYPE_SAMPLE) {
        assert.deepEqual(
          runMember(document, path, value),
          expected,
          `${path} holds the bytes of ${JSON.stringify(value) ?? "null"} (${name})`,
        );
        compared += 1;
      }
      assert.equal(compared, TYPE_SAMPLE.length, `${path}: not every JSON type was written`);
    });
  }
}

test("the documents this package reads as documents refuse what the appendix refuses", SPEC.options, () => {
  let compared = 0;
  for (const [title, row] of MEMBER_ROWS) {
    const document = documentOf(title)!;
    if (!["entry", "trust", "receipt", "roots", "vocabulary"].includes(document)) continue;
    const path = pathOf(row);
    for (const value of refusedValues(row)) {
      if (FIRES_A_GATE.some(([d, m, v]) => d === document && m === path && v === value)) continue;
      const built = documentFor(document, path, value);
      assert.equal(contractRefuses(document, built), true, `${document}.${path} = ${JSON.stringify(value)}`);
      compared += 1;
    }
    if (row["required"] === "yes") {
      assert.equal(contractRefuses(document, documentFor(document, path, ABSENT)), true, `${document}.${path} absent`);
      compared += 1;
    }
  }
  assert.ok(compared >= 100, `${compared} documents compared`);
});

/** The document itself, with one member changed: what the contract parsers are given. */
function documentFor(document: string, path: string, value: unknown): unknown {
  if (document === "roots") return rootsDocument(authorizationWithRoots().document, path, value);
  if (document === "vocabulary") return vocabularyDocument(vocabularyRowOf(path), value);
  if (document === "receipt") {
    const receipt = Bundle.linkValid().json("verification_receipt.json");
    setPath(receipt, path, value);
    return receipt;
  }
  if (document === "entry") {
    const bundle = Bundle.linkValid().seal();
    const entry = preparedEntry(bundle, path);
    setPath(entry, path, value);
    return entry;
  }
  const { options } = authRun((registry) => {
    setPath(registry, path, value);
    return registry;
  });
  return options.trustRegistry;
}

// ---------------------------------------------------------------- the registered vocabulary document

/** A §15 row by its member, for documentFor, which is given a path. */
function vocabularyRowOf(path: string): Record<string, string> {
  return { member: path };
}

/**
 * The protocol's workflow vocabulary, the one kind whose values carry every member (§15), with the
 * row's member set to `value`, or removed, in the document or in every one of its values.
 */
function vocabularyDocument(vocabularyRow: Record<string, string>, value: unknown): Record<string, unknown> {
  const document = JSON.parse(REGISTERED_VOCABULARIES.workflow);
  const member = vocabularyRow["member"]!.replace(/`/g, "");
  const targets: any[] = member.startsWith("values.*.") ? Object.values(document.values) : [document];
  const name = member.startsWith("values.*.") ? member.slice("values.*.".length) : member;
  for (const target of targets) {
    if (value === ABSENT) delete target[name];
    else Object.defineProperty(target, name, { value, enumerable: true, writable: true, configurable: true });
  }
  return document;
}

/**
 * A run given `document` as the operator's vocabulary of `kind`: the library refuses a refused one
 * before any evidence is read. `document` is what a host passes: a parsed document, or, for bytes
 * that are not strict JSON, what readDocumentPath returns for them.
 */
function runVocabulary(kind: string, document: unknown): Result {
  return report(Bundle.linkValid().seal(), { vocabularies: { [kind]: document } });
}

/** The outcome of §15 in a library: input-refused is a VocabularyError before any evidence. */
function vocabularyExpected(vocabularyRow: Record<string, string>): Result {
  const outcome = OUTCOMES().get(code(vocabularyRow["outcome"]!))!;
  assert.ok(outcome !== undefined && "refused" in outcome, `${vocabularyRow["member"]}: not an input refusal`);
  return { refused: "VocabularyError" };
}

const VOCABULARY_ROWS = MEMBER_ROWS.filter(([title]) => documentOf(title) === "vocabulary").map(([, row]) => row);

for (const vocabularyRow of VOCABULARY_ROWS) {
  const member = vocabularyRow["member"]!;
  test(`vocabulary: ${member} is refused as the appendix says`, SPEC.options, () => {
    const expected = vocabularyExpected(vocabularyRow);
    for (const value of refusedValues(vocabularyRow)) {
      assert.deepEqual(runVocabulary("workflow", vocabularyDocument(vocabularyRow, value)), expected, `${member} = ${JSON.stringify(value)}`);
    }
    // A member required, or required for the kind workflow the rows are run against, that is
    // absent.
    if (vocabularyRow["required"] !== "no") {
      assert.deepEqual(runVocabulary("workflow", vocabularyDocument(vocabularyRow, ABSENT)), expected, `${member} absent`);
    }
  });

  test(`vocabulary: ${member} takes the types its cell admits and no others`, SPEC.options, () => {
    const expected = vocabularyExpected(vocabularyRow);
    const admitted = admittedTypes(vocabularyRow);
    assert.ok(admitted.size > 0, `${member}: the type cell names no JSON type`);
    let compared = 0;
    for (const [name, value] of TYPE_SAMPLE) {
      if (admitted.has(name)) continue;
      assert.deepEqual(runVocabulary("workflow", vocabularyDocument(vocabularyRow, value)), expected, `${member} = ${JSON.stringify(value)} (${name})`);
      compared += 1;
    }
    assert.ok(compared > 0, `${member}: its type cell decided no value, so this compared nothing`);
  });
}

test("a well-formed vocabulary document is read, for every kind", SPEC.options, () => {
  // The lock under the rows above: the protocol's own documents are accepted and recorded.
  for (const kind of VOCABULARY_KINDS) {
    const r = verifyOnDisk(Bundle.linkValid().seal(), { vocabularies: { [kind]: JSON.parse(REGISTERED_VOCABULARIES[kind]) } });
    assert.equal(r.status, "OFFLINE_OK", kind);
    assert.equal(r.vocabularies[kind].source, "operator", kind);
  }
});

/** What a host passes for the bytes `text`, read from a file as readDocumentPath reads it. */
function hostRead(text: string): unknown {
  const dir = mkdtempSync(join(tmpdir(), "lq-ts-vocabulary-"));
  try {
    writeFileSync(join(dir, "vocabulary.json"), text);
    return readDocumentPath(join(dir, "vocabulary.json"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** The §15 cases: the kind each is supplied for and the document a host passes for it. */
function vocabularyCase(name: string): [string, unknown] {
  const document = JSON.parse(REGISTERED_VOCABULARIES.workflow);
  const first: any = Object.values(document.values)[0];
  switch (name) {
    case "vocabulary-not-an-object":
      return ["workflow", [document]];
    case "vocabulary-registers-another-kind":
      return ["asset_type", document];
    case "vocabulary-schema-version-is-a-later-version":
      return ["workflow", { ...document, schema_version: "v2" }];
    case "vocabulary-carries-a-member-the-format-does-not-name":
      return ["workflow", { ...document, note: "x" }];
    case "vocabulary-value-carries-a-member-the-format-does-not-name":
      first.note = "x";
      return ["workflow", document];
    case "vocabulary-names-a-value-twice": {
      // A value named twice is a duplicate member name: the bytes are not strict JSON, and the host
      // that read them passes what readDocumentPath gives for them.
      const valueName = Object.keys(document.values)[0]!;
      const text = REGISTERED_VOCABULARIES.workflow.replace(`"${valueName}": {`, `"${valueName}": ${JSON.stringify(first)},\n    "${valueName}": {`);
      assert.notEqual(text, REGISTERED_VOCABULARIES.workflow);
      const read = hostRead(text);
      assert.equal(read, DOCUMENT_NOT_STRICT_JSON, "a duplicate member name is not strict JSON");
      return ["workflow", read];
    }
    case "vocabulary-asset-types-on-a-value-of-another-kind": {
      const assetTypes = JSON.parse(REGISTERED_VOCABULARIES.asset_type);
      (Object.values(assetTypes.values)[0] as any).asset_types = ["fund_nav"];
      return ["asset_type", assetTypes];
    }
    default:
      throw new Error(`no builder for ${name}`);
  }
}

const VOCABULARY_CASES = new Set([
  "vocabulary-not-an-object",
  "vocabulary-registers-another-kind",
  "vocabulary-schema-version-is-a-later-version",
  "vocabulary-carries-a-member-the-format-does-not-name",
  "vocabulary-value-carries-a-member-the-format-does-not-name",
  "vocabulary-names-a-value-twice",
  "vocabulary-asset-types-on-a-value-of-another-kind",
]);

// ---------------------------------------------------------------- the case tables

function caseBundle(name: string): Bundle {
  const bundle = Bundle.linkValid();
  const undeclare = (member: string) => {
    const manifest = bundle.json("manifest.json");
    delete manifest.files[member];
    bundle.setJson("manifest.json", manifest);
  };
  switch (name) {
    case "manifest-not-an-object":
      bundle.seal();
      bundle.setJson("manifest.json", [1]);
      return bundle;
    case "manifest-declares-a-member-the-bundle-does-not-carry": {
      const manifest = bundle.json("manifest.json");
      manifest.files["absent.json"] = "a".repeat(64);
      bundle.setJson("manifest.json", manifest);
      bundle.seal();
      return resealOverManifest(bundle);
    }
    case "manifest-declares-a-digest-that-is-not-the-members": {
      bundle.seal();
      const manifest = bundle.json("manifest.json");
      manifest.files["p1.json"] = "a".repeat(64);
      bundle.setJson("manifest.json", manifest);
      return resealOverManifest(bundle);
    }
    case "manifest-files-map-is-empty": {
      bundle.seal();
      const manifest = bundle.json("manifest.json");
      manifest.files = {};
      bundle.setJson("manifest.json", manifest);
      return resealOverManifest(bundle);
    }
    case "manifest-files-map-declares-some-of-the-members":
      // The member stays in the bundle and leaves the map: the file check still holds over what
      // is declared, and completeness is what the run reports.
      bundle.seal();
      undeclare("canonical_input.json");
      return resealOverManifest(bundle);
    case "p1-not-an-object":
      bundle.setJson("p1.json", [1]);
      return bundle.seal();
    case "p1-over-the-canonical-size-bound": {
      const input = bundle.json("canonical_input.json");
      for (let index = 0; index < 40; index++) input[`member_with_a_long_name_${String(index).padStart(3, "0")}`] = index;
      bundle.setJson("canonical_input.json", input);
      const p1 = bundle.json("p1.json");
      p1.ik = Object.keys(input).sort();
      p1.ih = bundle.inputHashFor(p1);
      bundle.setJson("p1.json", p1);
      return bundle.seal();
    }
    case "p1-ih-is-not-the-digest-of-the-projection": {
      const p1 = bundle.json("p1.json");
      p1.ih = `sha256:${"a".repeat(64)}`;
      bundle.setJson("p1.json", p1);
      return bundle.seal();
    }
    case "p1-absent":
      bundle.delete("p1.json");
      undeclare("p1.json");
      return bundle.seal();
    case "canonical-input-declared-and-absent":
      bundle.delete("canonical_input.json");
      return bundle.seal();
    case "canonical-input-undeclared-and-absent":
      bundle.delete("canonical_input.json");
      undeclare("canonical_input.json");
      return bundle.seal();
    case "manifest-sidecar-absent":
      bundle.seal();
      bundle.delete("manifest.sha256");
      return bundle;
    case "p1-sidecar-absent":
      bundle.seal();
      bundle.delete("p1.sha256");
      undeclare("p1.sha256");
      return resealOverManifest(bundle);
    case "envelope-sidecar-absent":
      bundle.seal();
      bundle.delete("envelope.sha256");
      return bundle;
    case "envelope-and-sidecar-absent":
      bundle.seal();
      bundle.delete("envelope.sha256");
      bundle.delete("envelope_env1.json");
      return bundle;
    case "envelope-not-an-object":
      bundle.seal();
      bundle.setJson("envelope_env1.json", [1]);
      bundle.setBytes("envelope.sha256", sha256Hex(jcsText([1])));
      return bundle;
    case "envelope-absent-sidecar-present":
      bundle.seal();
      bundle.delete("envelope_env1.json");
      return bundle;
    case "envelope-json-is-an-ordinary-member":
      bundle.seal();
      bundle.setBytes("envelope.json", bundle.bytes("envelope_env1.json"));
      return bundle;
    case "manifest-schema-version-is-a-later-version": {
      bundle.seal();
      const manifest = bundle.json("manifest.json");
      manifest.schema_version = "loquitur.bundle.v2";
      bundle.setJson("manifest.json", manifest);
      return resealOverManifest(bundle);
    }
    case "receipt-not-an-object":
      bundle.seal();
      bundle.setJson("verification_receipt.json", [1]);
      return bundle;
    case "receipt-carries-a-member-the-schema-does-not-name": {
      bundle.seal();
      const receipt = bundle.json("verification_receipt.json");
      receipt.spare = 1;
      return bundle.setJson("verification_receipt.json", receipt);
    }
    default:
      throw new Error(`no builder for ${name}`);
  }
}

const BUNDLE_CASES = new Set([
  "manifest-not-an-object",
  "manifest-declares-a-member-the-bundle-does-not-carry",
  "manifest-declares-a-digest-that-is-not-the-members",
  "manifest-files-map-is-empty",
  "manifest-files-map-declares-some-of-the-members",
  "p1-not-an-object",
  "p1-over-the-canonical-size-bound",
  "p1-ih-is-not-the-digest-of-the-projection",
  "p1-absent",
  "canonical-input-declared-and-absent",
  "canonical-input-undeclared-and-absent",
  "manifest-sidecar-absent",
  "p1-sidecar-absent",
  "envelope-sidecar-absent",
  "envelope-and-sidecar-absent",
  "envelope-not-an-object",
  "envelope-absent-sidecar-present",
  "envelope-json-is-an-ordinary-member",
  "manifest-schema-version-is-a-later-version",
  "receipt-not-an-object",
  "receipt-carries-a-member-the-schema-does-not-name",
]);
const ENTRY_CASES: Record<string, unknown> = {
  "entry-not-an-object": [1],
  "entry-is-json-null": null,
  "entry-carries-a-member-the-schema-does-not-name": { spare: 1 },
  "entry-verdict-is-not-the-verdict-its-reason-codes-derive": { verdict: "WARN" },
};
const TRUST_CASES: Record<string, (registry: any) => any> = {
  "trust-registry-not-an-object": () => [1],
  "trust-registry-carries-a-member-the-schema-does-not-name": (registry) => {
    registry.spare = 1;
    return registry;
  },
  "trust-registry-entry-is-not-an-object": (registry) => {
    registry.entries[0] = "x";
    return registry;
  },
};

const CASE_ROWS = SPEC.present ? sectionRows(CASE_HEADER) : [];

test("every case of the appendix is executed here", SPEC.options, () => {
  const named = new Set(CASE_ROWS.map(([, row]) => code(row["case"]!)));
  const built = new Set([...BUNDLE_CASES, ...Object.keys(ENTRY_CASES), ...Object.keys(TRUST_CASES), ...VOCABULARY_CASES]);
  assert.deepEqual([...named].sort(), [...built].sort());
});

for (const [, row] of CASE_ROWS) {
  const name = code(row["case"]!);
  test(`case ${name} has its outcome`, SPEC.options, () => {
    const expected = OUTCOMES().get(code(row["outcome"]!))!;
    assert.ok(expected, `no outcome ${row["outcome"]} in the appendix`);
    if (BUNDLE_CASES.has(name)) {
      assert.deepEqual(report(caseBundle(name)), expected);
      return;
    }
    if (VOCABULARY_CASES.has(name)) {
      // input-refused: in a library, a VocabularyError before any evidence is read.
      assert.ok("refused" in expected, `${name}: not an input refusal`);
      const [kind, document] = vocabularyCase(name);
      assert.deepEqual(runVocabulary(kind, document), { refused: "VocabularyError" });
      return;
    }
    if (name in ENTRY_CASES) {
      const bundle = Bundle.linkValid().seal();
      const value = ENTRY_CASES[name];
      const entry = value !== null && !Array.isArray(value) ? Object.assign(linkEntryFor(bundle), value) : value;
      assert.deepEqual(report(bundle, { registryEntry: entry }), expected);
      return;
    }
    const { bundle, options } = authRun(TRUST_CASES[name]!);
    assert.deepEqual(report(bundle, options), expected);
  });
}

test("every section with member rows is run here, and the section this package does not run is named", SPEC.options, () => {
  const named = (title: string) => (title.includes(". ") ? title.slice(title.indexOf(". ") + 2) : title);
  const titles = [...sections(appendix())].map(([title]) => named(title));
  const withMembers = [...sections(appendix())]
    .filter(([, body]) => tablesWithHeader(body, MEMBER_HEADER).length > 0)
    .map(([title]) => named(title));
  assert.deepEqual(withMembers.filter((title) => documentOf(title) === null), []);
  // The command line's inputs have no command line here: they are run in the Python verifier's
  // suite.
  assert.ok(titles.includes(NOT_RUN_HERE), `${NOT_RUN_HERE} is not a section of the appendix`);
  assert.equal(documentOf(NOT_RUN_HERE), null);
});

// ---------------------------------------------------------------- what this suite covers

const COVERAGE_HEADER = ["suite", "member rows", "case rows", "input rows", "report surface compared"];
const THIS_SUITE = "test/spec-document-contracts.test.ts";

test("this suite runs what section 14 says it runs", SPEC.options, () => {
  // §14 is where the appendix states its own coverage, and this holds this package's row of
  // it. Every number is compared with what this file runs (the member rows it drives, the
  // case rows, the input rows it does not run, and the fields a run is compared on, read off a
  // real outcome rather than from a list written twice), so a sentence claiming a coverage
  // this suite does not have fails the build instead of being believed.
  const rows = sectionRows(COVERAGE_HEADER).map(([, row]) => row);
  const mine = rows.filter((row) => codes(row["suite"]!).includes(THIS_SUITE));
  assert.equal(mine.length, 1, `section 14 names ${mine.length} suites at ${THIS_SUITE}`);
  const row = mine[0]!;
  assert.equal(MEMBER_ROWS.length, Number(row["member rows"]));
  assert.equal(CASE_ROWS.length, Number(row["case rows"]));
  assert.equal(row["input rows"], "-");
  const ran = validOutcome("bundle");
  assert.deepEqual(Object.keys(ran).sort(), codes(row["report surface compared"]!).slice().sort());
});
