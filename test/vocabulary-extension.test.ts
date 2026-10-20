// A value registered after this verifier was built is a review, until the operator supplies it.
//
// verification-vocabularies.md sections 8 and 9: the verifier holds one vocabulary per kind, its
// own unless the operator supplies one, and a well-formed value it does not hold at a receipt's
// asset_type, or an entry's asset_type or workflow, is the review reason vocabulary_value_unknown
// (report-contract.md section 3.3, row 14). A copy of the embedded asset_type vocabulary gains a
// value; a bundle whose receipt carries it is OFFLINE_REVIEW with the embedded vocabulary and
// OFFLINE_OK with the extended one, the checks established in both, and nothing the verifier ships
// is written.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { Bundle, ENTRIES, PACKAGE_DIR, refusal } from "./bundle-kit.ts";
import { REGISTERED_VOCABULARIES, REGISTERED_VOCABULARY_SHA256, VOCABULARY_KINDS, VocabularyError } from "../src/index.ts";
import { canonicalJsonBytes } from "../src/canonical.ts";

/** The embedded asset_type vocabulary, gaining `example_asset` at 1.1.0. */
function extended(): Record<string, any> {
  const document = JSON.parse(REGISTERED_VOCABULARIES.asset_type);
  document.version = "1.1.0";
  document.values.example_asset = { since: "1.1.0", status: "active", title: "Example asset", profile: null };
  return document;
}

/** A bundle whose receipt carries `assetType`, resealed. */
function bundle(assetType: string): Bundle {
  return Bundle.linkValid().edit("verification_receipt.json", (receipt) => { receipt.asset_type = assetType; }).seal();
}

/** The SHA-256 and modification time of every file under src/, to show that nothing there is written. */
function sourceState(): Map<string, string> {
  const state = new Map<string, string>();
  const walk = (dir: string) => {
    for (const name of readdirSync(dir)) {
      const path = join(dir, name);
      const st = statSync(path);
      if (st.isDirectory()) walk(path);
      else state.set(path, `${createHash("sha256").update(readFileSync(path)).digest("hex")}:${st.mtimeMs}`);
    }
  };
  walk(join(PACKAGE_DIR, "src"));
  return state;
}

test("a registered value is a review until the operator supplies its vocabulary", () => {
  const before = sourceState();
  const b = bundle("example_asset");
  const document = extended();
  for (const [entryName, verify] of ENTRIES) {
    const embedded = verify(b);
    assert.deepEqual([embedded.status, embedded.review_reasons], ["OFFLINE_REVIEW", ["vocabulary_value_unknown"]], entryName);
    assert.deepEqual(embedded.checks_established, ["structure", "integrity"], entryName);
    assert.equal(embedded.outcome.reason, "vocabulary_value_unknown", entryName);
    assert.equal(embedded.vocabularies.asset_type.source, "embedded", entryName);
    assert.ok(embedded.notes.includes("vocabulary_value_unknown:verification_receipt.asset_type"), entryName);

    const supplied = verify(b, { vocabularies: { asset_type: document } });
    assert.deepEqual([supplied.status, supplied.review_reasons], ["OFFLINE_OK", []], entryName);
    assert.deepEqual(supplied.checks_established, ["structure", "integrity"], entryName);
    assert.deepEqual(supplied.vocabularies.asset_type, {
      version: "1.1.0",
      sha256: `sha256:${createHash("sha256").update(canonicalJsonBytes(document)).digest("hex")}`,
      source: "operator",
    }, entryName);
    // The kinds not supplied stay the embedded ones; nothing is merged.
    assert.equal(supplied.vocabularies.workflow.source, "embedded", entryName);
  }
  // The embedded documents are unchanged, and so is every file of the package's source.
  for (const kind of VOCABULARY_KINDS) {
    assert.equal(createHash("sha256").update(REGISTERED_VOCABULARIES[kind]).digest("hex"), REGISTERED_VOCABULARY_SHA256[kind], kind);
  }
  assert.deepEqual(sourceState(), before);
});

test("a known value is no review, and a deprecated value is known", () => {
  for (const [entryName, verify] of ENTRIES) {
    assert.equal(verify(bundle("fund_nav")).status, "OFFLINE_OK", entryName);
    const deprecated = JSON.parse(REGISTERED_VOCABULARIES.asset_type);
    deprecated.version = "1.1.0";
    deprecated.values.fund_nav.status = "deprecated";
    assert.equal(verify(bundle("fund_nav"), { vocabularies: { asset_type: deprecated } }).status, "OFFLINE_OK", entryName);
  }
});

test("a supplied document of another kind is refused", () => {
  const workflow = JSON.parse(REGISTERED_VOCABULARIES.workflow);
  for (const [entryName, verify] of ENTRIES) {
    assert.equal(refusal(() => verify(bundle("property"), { vocabularies: { asset_type: workflow } })), VocabularyError.name, entryName);
  }
});
