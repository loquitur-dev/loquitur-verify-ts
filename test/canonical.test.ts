import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { canonicalJsonBytes, parseJsonStrict, sha256Uri, CanonicalizationError } from "../src/canonical.ts";

const here = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(readFileSync(join(here, "../test-vectors/canonicalization.json"), "utf-8"));

// Cross-language golden: every canonical byte string and hash must match the
// Python verifier exactly. A divergence here makes the two verifiers disagree on a digest.
for (const v of vectors.canonicalize_ok as Array<any>) {
  test(`JCS bytes == Python golden: ${v.name}`, () => {
    const bytes = canonicalJsonBytes(v.input);
    const hex = Buffer.from(bytes).toString("hex");
    assert.equal(hex, v.canonical_hex, `canonical bytes diverge for ${v.name}`);
    assert.equal(sha256Uri(bytes), v.sha256, `sha256 diverges for ${v.name}`);
  });
}

// Input strictness rule 6: depth 64 canonicalizes and 65 is refused, by the protocol's bound and
// not the stack's, exactly as loquitur-verify's canonical_json_bytes answers, so no stack size
// and no Python version decides whether a deep value canonicalizes.
function deepList(depth: number): unknown {
  let value: unknown = [];
  for (let i = 1; i < depth; i++) value = [value];
  return value;
}
function deepObject(depth: number): unknown {
  let value: unknown = {};
  for (let i = 1; i < depth; i++) value = { k: value };
  return value;
}
test("the nesting bound is rule 6's: depth 64 canonicalizes, 65 is refused", () => {
  const loop: unknown[] = [];
  loop.push(loop);
  const rows: Record<string, unknown> = {
    "list-64": deepList(64),
    "object-64": deepObject(64),
    "list-65": deepList(65),
    "object-65": deepObject(65),
    "list-700": deepList(700),
    "contains-itself": loop,
  };
  const got: Record<string, string> = {};
  for (const [label, value] of Object.entries(rows)) {
    try {
      canonicalJsonBytes(value);
      got[label] = "serialized";
    } catch (err) {
      got[label] = err instanceof CanonicalizationError ? "refused" : `escaped ${(err as Error).name}`;
    }
  }
  assert.deepEqual(got, {
    "list-64": "serialized",
    "object-64": "serialized",
    "list-65": "refused",
    "object-65": "refused",
    "list-700": "refused",
    "contains-itself": "refused",
  });
  assert.equal(Buffer.from(canonicalJsonBytes(deepList(64))).toString(), "[".repeat(64) + "]".repeat(64));
});

test("guard rejects a JS-unsafe integer (2**53)", () => {
  assert.throws(() => canonicalJsonBytes({ n: 2 ** 53 }), CanonicalizationError);
});

// A member named __proto__ is an ordinary JSON member (RFC 8259, RFC 8785). The expected bytes
// below are rfc8785.dumps(json.loads(text)) from the Python `rfc8785` package. Copying members by
// assignment would set the prototype of the output object instead of creating the member, and hash
// {"__proto__":{"hidden":"A"}} as {}.
const PROTO_CASES: Array<[string, string]> = [
  ['{"__proto__":{"hidden":"A"}}', "7b225f5f70726f746f5f5f223a7b2268696464656e223a2241227d7d"],
  ['{"x":{"__proto__":1,"value":1}}', "7b2278223a7b225f5f70726f746f5f5f223a312c2276616c7565223a317d7d"],
  ['[{"__proto__":null}]', "5b7b225f5f70726f746f5f5f223a6e756c6c7d5d"],
  ['{"__proto__":"s","a":1}', "7b225f5f70726f746f5f5f223a2273222c2261223a317d"],
];
for (const [text, expectedHex] of PROTO_CASES) {
  test(`a member named __proto__ keeps its canonical bytes: ${text}`, () => {
    assert.equal(Buffer.from(canonicalJsonBytes(parseJsonStrict(text))).toString("hex"), expectedHex);
  });
}
