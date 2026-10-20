// Properties of the strict loader and the canonicalizer, on the byte path the verifier reads a
// member or a document by (canonicalization-and-hashing.md sections 1 and 6): parseJsonBytesStrict
// decodes UTF-8 with fatal errors and the BOM kept, then parseJsonStrict; canonicalJsonBytes is
// RFC 8785. Generated values carry BMP, astral and combining characters, control characters,
// member names such as __proto__, safe integers and finite floats, nested within the depth bound.
//
// Seed, budget and generators: test/property-kit.ts.
import { test } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";
import { JsonParseError, canonicalJsonBytes, parseJsonBytesStrict } from "../src/canonical.ts";
import { check, jsonValue, memberName, safeInteger, text } from "./property-kit.ts";

const utf8 = new TextEncoder();

/** A small deterministic choice stream, so one generated seed spells a value one way. */
function chooser(seed: number) {
  let state = seed >>> 0 || 1;
  return (n: number) => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state % n;
  };
}

/** `s` as a JSON string, each UTF-16 unit written as itself or as a \u escape, as `pick` chooses. */
function spellString(s: string, pick: (n: number) => number): string {
  const escape = (unit: number) => {
    const hex = unit.toString(16).padStart(4, "0");
    return `\\u${pick(2) ? hex : hex.toUpperCase()}`;
  };
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const unit = s.charCodeAt(i);
    const mustEscape = unit < 0x20 || unit === 0x22 || unit === 0x5c;
    // A surrogate pair is written as itself or as two escapes, never half and half: a half
    // written as itself is not text, and the encoder would replace it.
    const width = unit >= 0xd800 && unit <= 0xdbff ? 2 : 1;
    if (mustEscape || pick(3) === 0) {
      for (let k = 0; k < width; k++) out += escape(s.charCodeAt(i + k));
    } else {
      out += s.slice(i, i + width);
    }
    i += width - 1;
  }
  return `${out}"`;
}

/** `value` as JSON text that is not canonical: members in another order, whitespace, escapes. */
function spell(value: unknown, pick: (n: number) => number): string {
  const ws = () => ["", " ", "\n", "\t", "\r\n  "][pick(5)]!;
  if (typeof value === "string") return spellString(value, pick);
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${ws()}${value.map((v) => spell(v, pick)).join(`${ws()},${ws()}`)}${ws()}]`;
  const keys = Object.keys(value);
  for (let i = keys.length - 1; i > 0; i--) {
    const j = pick(i + 1);
    [keys[i], keys[j]] = [keys[j]!, keys[i]!];
  }
  const members = keys.map((k) => `${ws()}${spellString(k, pick)}${ws()}:${ws()}${spell((value as Record<string, unknown>)[k], pick)}`);
  return `{${members.join(",")}${ws()}}`;
}

function refused(bytes: Uint8Array): boolean {
  try {
    parseJsonBytesStrict(bytes);
    return false;
  } catch (err) {
    if (err instanceof JsonParseError) return true;
    throw err;
  }
}

test("canonical bytes are a fixed point of load then canonicalize", () => {
  check(
    fc.property(jsonValue, (value) => {
      const bytes = canonicalJsonBytes(value);
      const again = canonicalJsonBytes(parseJsonBytesStrict(bytes));
      assert.deepEqual(again, bytes);
    }),
    1000,
  );
});

test("canonicalization is idempotent over any strict spelling of a value", () => {
  check(
    fc.property(jsonValue, fc.integer(), (value, seed) => {
      const spelled = utf8.encode(spell(value, chooser(seed)));
      const canonical = canonicalJsonBytes(parseJsonBytesStrict(spelled));
      assert.deepEqual(canonical, canonicalJsonBytes(value));
      assert.deepEqual(canonicalJsonBytes(parseJsonBytesStrict(canonical)), canonical);
    }),
    1000,
  );
});

test("a member name that repeats after escape decoding is refused", () => {
  check(
    fc.property(memberName, jsonValue, jsonValue, fc.integer(), (name, first, second, seed) => {
      const pick = chooser(seed);
      // The second spelling escapes every unit, so a non-empty name is spelled two ways.
      const escaped = `"${[...Array(name.length).keys()].map((i) => `\\u${name.charCodeAt(i).toString(16).padStart(4, "0")}`).join("")}"`;
      const doc = `{${spellString(name, pick)}:${spell(first, pick)},"other":0,${escaped}:${spell(second, pick)}}`;
      assert.ok(refused(utf8.encode(doc)), doc);
      assert.ok(refused(utf8.encode(`[1,{"wrap":${doc}}]`)));
    }),
    600,
  );
});

const highSurrogate = fc.integer({ min: 0xd800, max: 0xdbff });
const lowSurrogate = fc.integer({ min: 0xdc00, max: 0xdfff });
const hex4 = (unit: number) => unit.toString(16).padStart(4, "0");

test("a lone surrogate escape is refused, in a string or a member name", () => {
  check(
    fc.property(fc.oneof(highSurrogate, lowSurrogate), text, text, fc.boolean(), fc.integer(), (unit, before, after, asName, seed) => {
      const pick = chooser(seed);
      // `after` is scalar values, so a high surrogate is followed by no low one and a low one
      // follows no high one.
      const inner = `${spellString(before, pick).slice(0, -1)}\\u${hex4(unit)}${spellString(after, () => 1).slice(1)}`;
      const doc = asName ? `{${inner}:1}` : `{"a":${inner}}`;
      assert.ok(refused(utf8.encode(doc)), doc);
    }),
    600,
  );
});

const noncharacter = fc.oneof(
  fc.integer({ min: 0xfdd0, max: 0xfdef }),
  fc.tuple(fc.integer({ min: 0, max: 16 }), fc.boolean()).map(([plane, last]) => plane * 0x10000 + (last ? 0xffff : 0xfffe)),
);

test("a noncharacter is refused, written as itself or escaped, in a string or a member name", () => {
  check(
    fc.property(noncharacter, text, fc.boolean(), fc.boolean(), (c, around, escape, asName) => {
      const ch = String.fromCodePoint(c);
      const spelled = escape ? [...Array(ch.length).keys()].map((i) => `\\u${hex4(ch.charCodeAt(i))}`).join("") : ch;
      const inner = `${spellString(around, () => 1).slice(0, -1)}${spelled}"`;
      const doc = asName ? `{${inner}:true}` : `[${inner}]`;
      assert.ok(refused(utf8.encode(doc)), doc);
    }),
    600,
  );
});

test("a BOM before the document is refused; the same bytes without it are accepted", () => {
  check(
    fc.property(jsonValue, (value) => {
      const bytes = canonicalJsonBytes(value);
      const withBom = new Uint8Array(bytes.length + 3);
      withBom.set([0xef, 0xbb, 0xbf], 0);
      withBom.set(bytes, 3);
      assert.ok(refused(withBom));
      assert.ok(!refused(bytes));
    }),
    500,
  );
});

/** Byte sequences that are not UTF-8 when they start at a character boundary. */
const INVALID_UTF8: number[][] = [
  [0x80], [0xbf], [0xc0, 0x80], [0xc1, 0xbf], [0xe0, 0x80, 0x80], [0xed, 0xa0, 0x80], [0xed, 0xbf, 0xbf],
  [0xf0, 0x80, 0x80, 0x80], [0xf4, 0x90, 0x80, 0x80], [0xf5], [0xf8], [0xfe], [0xff], [0xc3], [0xe2, 0x82], [0xf0, 0x9f, 0x98],
];

test("bytes that are not UTF-8 are refused wherever they stand", () => {
  check(
    fc.property(jsonValue, fc.constantFrom(...INVALID_UTF8), fc.nat(), (value, bad, at) => {
      const bytes = canonicalJsonBytes(value);
      const boundaries = [...bytes.keys(), bytes.length].filter((i) => i === bytes.length || (bytes[i]! & 0xc0) !== 0x80);
      const cut = boundaries[at % boundaries.length]!;
      const broken = new Uint8Array([...bytes.subarray(0, cut), ...bad, ...bytes.subarray(cut)]);
      assert.ok(refused(broken));
    }),
    600,
  );
});

test("an integer beyond 2^53 - 1 is refused; 2^53 - 1 is accepted", () => {
  const limit = 2n ** 53n;
  check(
    fc.property(fc.bigInt({ min: limit, max: 10n ** 40n }), fc.boolean(), fc.boolean(), (n, negative, asMember) => {
      const literal = `${negative ? "-" : ""}${n}`;
      assert.ok(refused(utf8.encode(asMember ? `{"n":${literal}}` : `[${literal}]`)), literal);
    }),
    600,
  );
  for (const literal of ["9007199254740991", "-9007199254740991"]) assert.ok(!refused(utf8.encode(`[${literal}]`)), literal);
});

test("nesting to depth 64 is accepted and canonicalizes; depth 65 and beyond is refused", () => {
  const leaf = fc.oneof(fc.constant("null"), fc.constant("[]"), fc.constant("{}"), safeInteger.map(String), text.map((s) => JSON.stringify(s)));
  check(
    fc.property(fc.integer({ min: 1, max: 80 }), fc.array(fc.boolean(), { minLength: 80, maxLength: 80 }), leaf, (depth, kinds, inner) => {
      // `inner` adds a level when it is [] or {}; the depth counted is the whole document's.
      const total = depth + (inner === "[]" || inner === "{}" ? 1 : 0);
      let doc = inner;
      for (let level = 0; level < depth; level++) doc = kinds[level] ? `[${doc}]` : `{"k":${doc}}`;
      const bytes = utf8.encode(doc);
      if (total <= 64) {
        const loaded = parseJsonBytesStrict(bytes);
        assert.deepEqual(canonicalJsonBytes(parseJsonBytesStrict(canonicalJsonBytes(loaded))), canonicalJsonBytes(loaded));
      } else {
        assert.ok(refused(bytes), `depth ${total}`);
      }
    }),
    600,
  );
});
