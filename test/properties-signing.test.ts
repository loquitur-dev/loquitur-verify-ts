// Properties of the two signing messages (signing-envelope-v2.md section 1, trust-root.md section
// 4), built by registryEntrySigningMessageBytes and trustRegistrySigningMessageBytes over generated
// documents: each starts with its own domain prefix; an entry's message ignores exactly
// `signature`, `anchor` and `anchored_at`, and a trust registry's exactly `signature`; any other
// member, added, removed or changed, changes the message.
//
// Seed, budget and generators: test/property-kit.ts.
import { test } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";
import { canonicalJsonBytes } from "../src/canonical.ts";
import { SIGNING_DOMAIN_PREFIX, registryEntrySigningMessageBytes } from "../src/signature.ts";
import { ROOT_SIGNING_DOMAIN_PREFIX, trustRegistrySigningMessageBytes } from "../src/trust-root.ts";
import { check, jsonValue, memberName, objectOf } from "./property-kit.ts";

const ENTRY_EXCLUDED = ["signature", "anchor", "anchored_at"];
const REGISTRY_EXCLUDED = ["signature"];

/** Member names a document may carry: the protocol's own, the excluded ones, and generated ones. */
const documentMemberName = fc.oneof(
  memberName,
  fc.constantFrom("signature", "anchor", "anchored_at", "manifest_hash", "receipt_hash", "issuer_id", "entries", "issued_at", "Signature", "signature "),
);

const document = fc
  .uniqueArray(fc.tuple(documentMemberName, jsonValue), { selector: (e) => e[0], maxLength: 8 })
  .map(objectOf);

const startsWith = (bytes: Uint8Array, prefix: Uint8Array) =>
  bytes.length >= prefix.length && prefix.every((b, i) => bytes[i] === b);

const same = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);

const canonicalEqual = (a: unknown, b: unknown) => same(canonicalJsonBytes(a), canonicalJsonBytes(b));

/** A copy of `doc` with `name` set to `value`, or removed when `value` is undefined. */
function withMember(doc: Record<string, unknown>, name: string, value: unknown): Record<string, unknown> {
  const entries = Object.entries(doc).filter(([k]) => k !== name);
  if (value !== undefined) entries.push([name, value]);
  return objectOf(entries);
}

type Kind = { label: string; message: (doc: Record<string, unknown>) => Uint8Array; prefix: Uint8Array; excluded: string[] };

const KINDS: Kind[] = [
  { label: "registry entry", message: registryEntrySigningMessageBytes, prefix: SIGNING_DOMAIN_PREFIX, excluded: ENTRY_EXCLUDED },
  { label: "trust registry", message: trustRegistrySigningMessageBytes, prefix: ROOT_SIGNING_DOMAIN_PREFIX, excluded: REGISTRY_EXCLUDED },
];

for (const kind of KINDS) {
  test(`the ${kind.label} signing message starts with its domain prefix`, () => {
    check(fc.property(document, (doc) => assert.ok(startsWith(kind.message(doc), kind.prefix))), 400);
  });

  test(`the ${kind.label} signing message ignores exactly ${kind.excluded.join(", ")}`, () => {
    const excludedName = fc.constantFrom(...kind.excluded);
    const newValue = fc.option(jsonValue, { nil: undefined });
    check(
      fc.property(document, excludedName, newValue, (doc, name, value) => {
        assert.ok(same(kind.message(withMember(doc, name, value)), kind.message(doc)));
      }),
      400,
    );
  });

  test(`the ${kind.label} signing message changes when any other member is added, removed or changed`, () => {
    const other = documentMemberName.filter((name) => !kind.excluded.includes(name));
    const newValue = fc.option(jsonValue, { nil: undefined });
    check(
      fc.property(document, other, newValue, (doc, name, value) => {
        const had = Object.prototype.hasOwnProperty.call(doc, name);
        const old = had ? doc[name] : undefined;
        // Skip the cases that change nothing: absent stays absent, or the same value again.
        fc.pre(had || value !== undefined);
        fc.pre(!(had && value !== undefined && canonicalEqual(old, value)));
        assert.ok(!same(kind.message(withMember(doc, name, value)), kind.message(doc)), name);
      }),
      400,
    );
  });
}

test("a trust registry's signing message covers anchor and anchored_at, which an entry's leaves out", () => {
  check(
    fc.property(document, fc.constantFrom("anchor", "anchored_at"), jsonValue, (doc, name, value) => {
      const had = Object.prototype.hasOwnProperty.call(doc, name);
      fc.pre(!had || !canonicalEqual(doc[name], value));
      assert.ok(!same(trustRegistrySigningMessageBytes(withMember(doc, name, value)), trustRegistrySigningMessageBytes(doc)));
    }),
    200,
  );
});

test("the two domain prefixes differ and neither is a prefix of the other", () => {
  assert.ok(!same(SIGNING_DOMAIN_PREFIX, ROOT_SIGNING_DOMAIN_PREFIX));
  assert.ok(!startsWith(SIGNING_DOMAIN_PREFIX, ROOT_SIGNING_DOMAIN_PREFIX));
  assert.ok(!startsWith(ROOT_SIGNING_DOMAIN_PREFIX, SIGNING_DOMAIN_PREFIX));
  // So no message of one kind starts with the other kind's prefix.
  check(
    fc.property(document, (doc) => {
      assert.ok(!startsWith(registryEntrySigningMessageBytes(doc), ROOT_SIGNING_DOMAIN_PREFIX));
      assert.ok(!startsWith(trustRegistrySigningMessageBytes(doc), SIGNING_DOMAIN_PREFIX));
    }),
    200,
  );
});
