// The exported helpers hold their inputs to the same rules as the bundle path does.
//
// authenticateTrustRegistry is given roots a caller built, not only roots parseTrustRoots read: it
// validates them against trust-root.md section 3 before any row of section 5, and refuses a set
// that breaks it, as the Python verifier does at every interface.
//
// canonicalJsonBytes canonicalizes JSON values only: a Date, Map, Set, typed array or boxed
// primitive is refused, not serialized as an object of its enumerable members.
import { test } from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import { Bundle, ephemeralAuthorizationWith, ephemeralRoot, refusal } from "./bundle-kit.ts";
import { CanonicalizationError, canonicalJsonBytes } from "../src/canonical.ts";
import { authenticateTrustRegistry, type TrustRoot } from "../src/trust-root.ts";

function signedRegistry() {
  const bundle = Bundle.linkValid().seal();
  const { root, sign } = ephemeralRoot("root-1");
  const { trustRegistry } = ephemeralAuthorizationWith(bundle, { trust: (t: Record<string, unknown>) => { delete t.signature; } });
  sign(trustRegistry);
  return { root: root as TrustRoot, trustRegistry };
}

test("authenticateTrustRegistry refuses built roots that break trust-root.md section 3", () => {
  const { root, trustRegistry } = signedRegistry();
  assert.equal(authenticateTrustRegistry(trustRegistry, [root], "2026-05-10T00:00:00Z"), "ROOT_SIGNATURE_VALID");
  const broken: Record<string, unknown> = {
    "status suspended": { ...root, status: "suspended" },
    "public key in upper case": { ...root, public_key_hex: `04${root.public_key_hex.slice(2).toUpperCase()}` },
    "bounds not calendar instants": { ...root, not_before: "2026-02-30T00:00:00Z" },
    "an empty window": { ...root, not_after: root.not_before },
    "no key type": (({ key_type: _k, ...rest }) => rest)(root as unknown as Record<string, unknown>),
    "a member outside the set": { ...root, comment: "spare" },
    "a blank key id": { ...root, key_id: " " },
  };
  const got = Object.fromEntries(Object.entries(broken).map(([label, value]) =>
    [label, refusal(() => authenticateTrustRegistry(trustRegistry, [value as TrustRoot], "2026-05-10T00:00:00Z"))]));
  assert.deepEqual(got, Object.fromEntries(Object.keys(broken).map((label) => [label, "TrustRootError"])));
  // A broken root that the registry does not name is refused too: the set is validated as a whole.
  const other = { ...root, key_id: "root-9", status: "suspended" } as unknown as TrustRoot;
  assert.equal(refusal(() => authenticateTrustRegistry(trustRegistry, [root, other], "2026-05-10T00:00:00Z")), "TrustRootError");
});

// A trust registry that cannot be canonicalized cannot be the registry that was signed: the root
// signature is invalid (trust-root.md section 5, row 12 (ROOT_SIGNATURE_INVALID)), never an
// exception, as the Python verifier answers. A host that hands the library a document holding a
// noncharacter or a lone surrogate reaches this row; strict JSON intake refuses such a document
// before any run does.
test("authenticateTrustRegistry answers ROOT_SIGNATURE_INVALID for a registry that cannot be canonicalized", () => {
  for (const [label, notes] of [["a noncharacter", `x${String.fromCodePoint(0xfffe)}`], ["a lone surrogate", "x\ud800"]]) {
    const { root, trustRegistry } = signedRegistry();
    (trustRegistry.entries as Array<Record<string, unknown>>)[0]!.notes = notes;
    assert.equal(authenticateTrustRegistry(trustRegistry, [root], "2026-05-10T00:00:00Z"), "ROOT_SIGNATURE_INVALID", label);
  }
});

test("canonicalJsonBytes refuses values that are not JSON, whatever their members", () => {
  const notJson: Record<string, unknown> = {
    date: new Date(0),
    map: new Map([["a", 1]]),
    set: new Set([1]),
    "typed array": new Uint8Array([1, 2]),
    "boxed number": new Number(1),
    "boxed string": new String("a"),
    "class instance": new (class Point { x = 1; })(),
    "nested date": { at: new Date(0) },
  };
  const got = Object.fromEntries(Object.entries(notJson).map(([label, value]) => [label, refusal(() => canonicalJsonBytes(value))]));
  assert.deepEqual(got, Object.fromEntries(Object.keys(notJson).map((label) => [label, CanonicalizationError.name])));
  // JSON objects canonicalize: a literal, one without a prototype, and one made in another realm.
  const bare = Object.create(null) as Record<string, unknown>;
  bare.b = 2;
  bare.a = 1;
  const foreign = vm.runInNewContext('({"b": 2, "a": 1})');
  for (const value of [{ b: 2, a: 1 }, bare, foreign]) {
    assert.equal(new TextDecoder().decode(canonicalJsonBytes(value)), '{"a":1,"b":2}');
  }
});
