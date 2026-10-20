// The registered vocabularies built into this package, the validator of
// verification-vocabularies.md section 6, and row 14 of report-contract.md section 3.3.
//
// src/registered-vocabularies.generated.ts embeds loquitur-protocol's `vocabularies/<kind>.json` as
// their exact text with the SHA-256 of their bytes (section 8). This regenerates the module from a
// sibling protocol checkout and compares, as test/receipt-contract.test.ts does for the receipt
// contract, and holds each embedded document to the section it is read under.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { Bundle, ENTRIES, PACKAGE_DIR, REVIEW, PASS, linkEntryFor, outcome, rootDocument } from "./bundle-kit.ts";
import { sibling } from "./siblings.ts";
import { REGISTERED_VOCABULARIES, REGISTERED_VOCABULARY_SHA256 } from "../src/registered-vocabularies.generated.ts";
import {
  VOCABULARY_KINDS,
  VocabularyError,
  embeddedVocabulary,
  operatorVocabulary,
  vocabularyDocumentProblems,
  vocabularyValueStatus,
} from "../src/vocabulary.ts";
import {
  DOCUMENT_PATH_NAMES_NOTHING,
  DOCUMENT_PATH_NAMES_NO_REGULAR_FILE,
  DOCUMENT_READ_FAILED,
  bundleReaderFromMap,
  verifyBundleFiles,
  type BundleReader,
} from "../src/verify-core.ts";
// @ts-ignore: a plain .mjs script; its exports are typed by use below
import { KINDS, readVocabularies, renderRegisteredVocabularies } from "../scripts/generate-registered-vocabularies.mjs";

const PROTOCOL = sibling(
  "loquitur-protocol",
  [join(PACKAGE_DIR, "../loquitur-protocol"), join(PACKAGE_DIR, "../public/loquitur-protocol")],
  "vocabularies/asset_type.json",
  "sibling loquitur-protocol vocabularies absent",
);

const document = (kind: (typeof VOCABULARY_KINDS)[number]): any => JSON.parse(REGISTERED_VOCABULARIES[kind]);

// ---------------------------------------------------------------- the embedded documents
test("src/registered-vocabularies.generated.ts is what the protocol's vocabularies generate", PROTOCOL.options, () => {
  const committed = readFileSync(join(PACKAGE_DIR, "src/registered-vocabularies.generated.ts"), "utf8");
  assert.equal(committed, renderRegisteredVocabularies(readVocabularies(PROTOCOL.path("vocabularies"))));
  assert.deepEqual(KINDS, [...VOCABULARY_KINDS]);
  for (const kind of VOCABULARY_KINDS) {
    const bytes = readFileSync(PROTOCOL.path(`vocabularies/${kind}.json`));
    assert.deepEqual(new TextEncoder().encode(REGISTERED_VOCABULARIES[kind]), new Uint8Array(bytes), kind);
  }
  // A file that is not UTF-8, or that begins with a byte-order mark, stops the generation.
  const files = readVocabularies(PROTOCOL.path("vocabularies"));
  assert.throws(() => renderRegisteredVocabularies({ ...files, workflow: Buffer.from([0xef, 0xbb, 0xbf, 0x7b, 0x7d]) }), /byte-order mark/);
  assert.throws(() => renderRegisteredVocabularies({ ...files, workflow: Buffer.from([0x7b, 0xff, 0x7d]) }));
});

test("each recorded digest is the SHA-256 of the embedded bytes", () => {
  assert.deepEqual(Object.keys(REGISTERED_VOCABULARIES), [...VOCABULARY_KINDS]);
  assert.deepEqual(Object.keys(REGISTERED_VOCABULARY_SHA256), [...VOCABULARY_KINDS]);
  for (const kind of VOCABULARY_KINDS) {
    const digest = createHash("sha256").update(new TextEncoder().encode(REGISTERED_VOCABULARIES[kind])).digest("hex");
    assert.equal(REGISTERED_VOCABULARY_SHA256[kind], digest, kind);
  }
});

test("each embedded vocabulary satisfies section 6 and is held as embedded", () => {
  for (const kind of VOCABULARY_KINDS) {
    assert.deepEqual(vocabularyDocumentProblems(document(kind)), [], kind);
    const held = embeddedVocabulary(kind);
    assert.equal(held.kind, kind);
    assert.equal(held.source, "embedded");
    assert.equal(held.sha256, REGISTERED_VOCABULARY_SHA256[kind]);
    assert.ok(held.values.size > 0);
  }
});

// ---------------------------------------------------------------- the validator against the schema
test("the validator admits exactly the members and the required members the schema names", PROTOCOL.options, () => {
  const schema = JSON.parse(readFileSync(PROTOCOL.path("docs/specification/registered-vocabularies/schema.json"), "utf8"));
  const value = schema.$defs.RegisteredValue;
  assert.equal(schema.additionalProperties, false);
  assert.equal(value.additionalProperties, false);
  for (const name of Object.keys(schema.properties)) {
    const changed = document("workflow");
    delete changed[name];
    assert.equal(vocabularyDocumentProblems(changed).length > 0, schema.required.includes(name), name);
  }
  for (const name of Object.keys(value.properties)) {
    const changed = document("workflow");
    for (const entry of Object.values(changed.values) as any[]) delete entry[name];
    // asset_types is not required by the schema, but present exactly for a workflow (section 6).
    assert.equal(vocabularyDocumentProblems(changed).length > 0, value.required.includes(name) || name === "asset_types", name);
  }
  // The patterns of the schema decide every sample as the validator does.
  const version = new RegExp(schema.properties.version.pattern);
  const names = new RegExp(schema.properties.values.propertyNames.pattern);
  for (const sample of ["1.0.0", "0.0.0", "999999999.0.1", "1.0", "01.0.0", "1.0.0-rc1", "1000000000.0.0", " 1.0.0", "1.0.0\n"]) {
    const changed = document("asset_type");
    changed.version = sample;
    for (const entry of Object.values(changed.values) as any[]) entry.since = "0.0.0";
    assert.equal(vocabularyDocumentProblems(changed).length === 0, version.test(sample), sample);
  }
  for (const sample of ["vessel", "a", "0x", "a".repeat(64), "a".repeat(65), "Vessel", "vessel-class", "_x", "", "x\n"]) {
    const changed = document("asset_type");
    changed.values[sample] = { since: "1.0.0", status: "active", title: "t", profile: null };
    assert.equal(vocabularyDocumentProblems(changed).length === 0, names.test(sample), JSON.stringify(sample));
  }
});

test("the two rules the schema cannot state, and the whitespace set W", () => {
  const later = document("asset_type");
  later.values.property.since = "1.0.1";
  assert.ok(vocabularyDocumentProblems(later).some((problem) => problem.includes("later than")));
  const equalIsNotLater = document("asset_type");
  equalIsNotLater.version = "10.0.0";
  equalIsNotLater.values.property.since = "9.0.0";
  assert.deepEqual(vocabularyDocumentProblems(equalIsNotLater), [], "compared as integers, not as text");
  const withoutTypes = document("workflow");
  delete withoutTypes.values.fund_nav_update.asset_types;
  assert.notDeepEqual(vocabularyDocumentProblems(withoutTypes), []);
  const typesOnAsset = document("asset_type");
  typesOnAsset.values.property.asset_types = ["property"];
  assert.notDeepEqual(vocabularyDocumentProblems(typesOnAsset), []);
  for (const blank of ["", " ", "\u3000", "\ufeff"]) {
    const title = document("asset_type");
    title.values.property.title = blank;
    assert.notDeepEqual(vocabularyDocumentProblems(title), [], `title ${JSON.stringify(blank)}`);
    const profile = document("asset_type");
    profile.values.property.profile = blank;
    assert.notDeepEqual(vocabularyDocumentProblems(profile), [], `profile ${JSON.stringify(blank)}`);
  }
});

test("a value is known, unknown or invalid", () => {
  const held = embeddedVocabulary("asset_type");
  assert.equal(vocabularyValueStatus("property", held), "known");
  assert.equal(vocabularyValueStatus("vessel", held), "unknown");
  for (const value of ["Vessel", "vessel-class", " ", "", 7, null, "a".repeat(65), "constructor", "__proto__"]) {
    const expected = typeof value === "string" && /^[a-z0-9][a-z0-9_]{0,63}$/.test(value) ? "unknown" : "invalid";
    assert.equal(vocabularyValueStatus(value, held), expected, String(value));
  }
  const deprecated = document("asset_type");
  deprecated.version = "1.1.0";
  deprecated.values.property.status = "deprecated";
  assert.equal(vocabularyValueStatus("property", operatorVocabulary("asset_type", deprecated)), "known");
});

// ---------------------------------------------------------------- the library's refusals
/** A reader that fails the test when any member is read: a refusal comes before any evidence. */
const UNTOUCHED: BundleReader = {
  readText: () => assert.fail("a member was read"),
  readBytes: () => assert.fail("a member was read"),
  listMembers: () => assert.fail("the members were listed"),
};

test("a refused vocabulary is a VocabularyError before any evidence is read", () => {
  const refused: Array<[string, unknown]> = [
    ["null", { workflow: null }],
    ["an array", { workflow: [document("workflow")] }],
    ["another kind", { asset_type: document("workflow") }],
    ["a later schema_version", { workflow: { ...document("workflow"), schema_version: "v2" } }],
    ["nothing found", { workflow: DOCUMENT_PATH_NAMES_NOTHING }],
    ["no regular file", { workflow: DOCUMENT_PATH_NAMES_NO_REGULAR_FILE }],
    ["a failed read", { workflow: DOCUMENT_READ_FAILED }],
    ["a key that is not a kind", { vessel_type: document("asset_type") }],
    ["an option that is not an object", [document("asset_type")]],
    ["a value with a lone surrogate", { workflow: { ...document("workflow"), version: "\ud800" } }],
  ];
  for (const [label, vocabularies] of refused) {
    assert.throws(() => verifyBundleFiles(UNTOUCHED, { vocabularies } as never), VocabularyError, label);
  }
});

// ---------------------------------------------------------------- the report member
test("every report the library returns records the vocabularies it held", () => {
  const embedded = Object.fromEntries(VOCABULARY_KINDS.map((kind) => [kind, {
    version: embeddedVocabulary(kind).version, sha256: `sha256:${REGISTERED_VOCABULARY_SHA256[kind]}`, source: "embedded",
  }]));
  const bundle = Bundle.linkValid().seal();
  for (const [entryName, verify] of ENTRIES) {
    assert.deepEqual(verify(bundle).vocabularies, embedded, `${entryName}: a run`);
  }
  // A refusal of the input as a whole, and a version gate, carry it too.
  assert.deepEqual(verifyBundleFiles(bundleReaderFromMap({})).vocabularies, embedded);
  const gated = verifyBundleFiles(bundleReaderFromMap({}), { trustRoots: { ...rootDocument([]), schema_version: "v2" } });
  assert.equal(gated.status, "UNSUPPORTED_VERSION");
  assert.deepEqual(gated.vocabularies, embedded);
  // A supplied document is recorded as the operator's, with the digest of its canonical bytes.
  const supplied = document("workflow");
  const report = verifyBundleFiles(bundleReaderFromMap({}), { vocabularies: { workflow: supplied } });
  assert.equal(report.vocabularies.workflow.source, "operator");
  assert.equal(report.vocabularies.workflow.version, "1.0.0");
  assert.match(report.vocabularies.workflow.sha256, /^sha256:[0-9a-f]{64}$/);
  assert.deepEqual(report.vocabularies.asset_type, embedded.asset_type);
});

// ---------------------------------------------------------------- row 14
test("an entry's unknown workflow is a review that withholds no check", () => {
  const bundle = Bundle.linkValid().seal();
  for (const [entryName, verify] of ENTRIES) {
    const report = verify(bundle, { registryEntry: linkEntryFor(bundle, { workflow: "vessel_review" }) });
    assert.deepEqual(
      { ...outcome(report), review_reasons: report.review_reasons, established: report.checks_established, reason: report.outcome.reason },
      { ...REVIEW, review_reasons: ["vocabulary_value_unknown"], established: ["structure", "integrity", "link"], reason: "vocabulary_value_unknown" },
      entryName,
    );
    assert.ok(report.notes.includes("vocabulary_value_unknown:registry_entry.workflow"), entryName);
    // Under a vocabulary that registers the value, the same run is OFFLINE_OK.
    const extended = document("workflow");
    extended.version = "1.1.0";
    extended.values.vessel_review = { since: "1.1.0", status: "active", title: "Vessel review", profile: null, asset_types: ["property"] };
    const accepted = verify(bundle, { registryEntry: linkEntryFor(bundle, { workflow: "vessel_review" }), vocabularies: { workflow: extended } });
    assert.deepEqual(outcome(accepted), PASS, `${entryName}: extended`);
  }
});

test("an unknown anchoring method has no effect on a run", () => {
  const bundle = Bundle.linkValid().seal();
  const anchor = { method: "carrier_pigeon", system: "loft-1", anchor_reference: "ring-7" };
  for (const [entryName, verify] of ENTRIES) {
    const report = verify(bundle, { registryEntry: linkEntryFor(bundle, { anchor }) });
    assert.deepEqual(outcome(report), PASS, entryName);
    assert.deepEqual(report.review_reasons, []);
    assert.ok(report.notes.includes("vocabulary_value_unknown:registry_entry.anchor.method"), entryName);
  }
});

test("an entry whose contract does not hold is not judged against a vocabulary", () => {
  const bundle = Bundle.linkValid().seal();
  const report = verifyBundleFiles(bundleReaderFromMap(Object.fromEntries(bundle.files)), {
    registryEntry: linkEntryFor(bundle, { workflow: "vessel_review", verdict: 7 }),
  });
  assert.equal(report.status, "OFFLINE_FAIL");
  assert.ok(!report.review_reasons.includes("vocabulary_value_unknown"));
  assert.ok(!report.notes.some((note) => note.startsWith("vocabulary_value_unknown")));
});
