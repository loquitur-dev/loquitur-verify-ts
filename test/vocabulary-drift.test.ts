// The vocabularies src/protocol-input.ts applies, held to where they are defined: the schemas and
// the reason-code catalog of loquitur-protocol. The members a registered vocabulary governs are
// identifiers in every schema and enumerate no value (verification-vocabularies.md sections 5 and
// 7); the closed vocabularies the parser writes out are the schema's and the catalog's. A value
// deleted from, or added to, one of the lists here and not there fails this test, so the contract
// the verifier applies cannot drift from the published one without the build saying so.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { PACKAGE_DIR } from "./bundle-kit.ts";
import { sibling } from "./siblings.ts";
import { DISCLOSURE_PROFILES, IDENTIFIER, REASON_CODES } from "../src/protocol-input.ts";

const PROTOCOL = sibling(
  "loquitur-protocol",
  [join(PACKAGE_DIR, "../loquitur-protocol/docs/specification"), join(PACKAGE_DIR, "../public/loquitur-protocol/docs/specification")],
  "schemas/registry_entry.schema.json",
  "sibling loquitur-protocol specification absent",
);

const read = (name: string) => JSON.parse(readFileSync(PROTOCOL.path(name), "utf8"));
const sorted = (values: readonly string[]) => [...values].sort();

/** The node a JSON Pointer names in a document, or undefined. */
function at(document: unknown, pointer: string): unknown {
  let node: unknown = document;
  for (const part of pointer.split("/").slice(1)) {
    node = node !== null && typeof node === "object" ? (node as Record<string, unknown>)[part] : undefined;
  }
  return node;
}

// verification-vocabularies.md section 5: every member a registered vocabulary governs, by the
// schema that declares it and its JSON Pointer there.
const GOVERNED: ReadonlyArray<readonly [string, string]> = [
  ["registry_entry", "/properties/asset_type"],
  ["registry_entry", "/properties/workflow"],
  ["registry_entry", "/properties/anchor/properties/method"],
  ["trust_registry", "/properties/entries/items/properties/allowed_asset_types/items"],
  ["trust_registry", "/properties/entries/items/properties/allowed_workflows/items"],
  ["verification_receipt", "/properties/asset_type"],
  ["verification_summary", "/properties/asset_type"],
  ["coverage_summary", "/properties/asset_type"],
  ["change_summary", "/properties/asset_type"],
  ["lineage_summary", "/properties/asset_type"],
];

test("every governed member is an identifier and enumerates no value", PROTOCOL.options, () => {
  assert.equal(GOVERNED.length, 10);
  for (const [schema, pointer] of GOVERNED) {
    const node = at(read(`schemas/${schema}.schema.json`), pointer) as Record<string, unknown> | undefined;
    assert.ok(node !== undefined && node !== null && typeof node === "object", `${schema}${pointer}: absent`);
    assert.ok(!("enum" in node) && !("const" in node), `${schema}${pointer}: a governed member enumerates its values`);
    assert.equal(node.pattern, IDENTIFIER.source, `${schema}${pointer}: not the identifier grammar`);
  }
});

test("the anchor names exactly the method, the system and the reference", PROTOCOL.options, () => {
  const anchor = read("schemas/registry_entry.schema.json").properties.anchor;
  assert.deepEqual(sorted(Object.keys(anchor.properties)), ["anchor_reference", "method", "system"]);
  assert.deepEqual(sorted(anchor.required), ["anchor_reference", "method", "system"]);
  assert.equal(anchor.additionalProperties, false);
});

test("the registry entry's closed vocabularies are the schema's", PROTOCOL.options, () => {
  const properties = read("schemas/registry_entry.schema.json").properties;
  assert.deepEqual(sorted(DISCLOSURE_PROFILES), sorted(properties.disclosure_profile.enum));
  assert.deepEqual(sorted(REASON_CODES), sorted(properties.reason_codes.items.enum));
});

test("the reason codes are the catalog's, no more and no fewer", PROTOCOL.options, () => {
  const catalog = read("reason-codes/v2.0/catalog.json");
  const codes = Object.keys(catalog.entries as Record<string, unknown>);
  assert.equal(new Set(REASON_CODES).size, REASON_CODES.length, "a code is listed twice");
  assert.deepEqual(sorted(REASON_CODES), sorted(codes));
  assert.equal(REASON_CODES.length, 57);
});
