// The seed, the number of examples and the shared generators of the property tests
// (test/properties-*.test.ts).
//
// `npm test` runs every property with one fixed seed and a bounded number of examples, so a run is
// repeatable and the properties stay within a minute together. LOQUITUR_PROPERTY_EXAMPLES, a
// positive integer, raises the number of examples of every property for a longer run by hand; the
// seed stays fixed, so a failure found that way is replayed by setting the same number again.
//
// Not a test file: `npm test` runs test/*.test.ts, and this is imported by them.
import fc from "fast-check";

export const PROPERTY_SEED = 20261016;

function requested(): number | null {
  const raw = process.env.LOQUITUR_PROPERTY_EXAMPLES;
  if (raw === undefined || raw === "") return null;
  const n = Number(raw);
  if (!Number.isSafeInteger(n) || n < 1) throw new Error(`LOQUITUR_PROPERTY_EXAMPLES must be a positive integer, not ${JSON.stringify(raw)}`);
  return n;
}

/**
 * The parameters of one property: the fixed seed, and `ciRuns` examples, or, when
 * LOQUITUR_PROPERTY_EXAMPLES is set, that number scaled by `scale` (a property that runs a whole
 * verification takes a fraction of it), never fewer than `ciRuns`.
 */
export function budget(ciRuns: number, scale = 1): fc.Parameters<unknown> {
  const n = requested();
  const numRuns = n === null ? ciRuns : Math.max(ciRuns, Math.ceil(n * scale));
  return { seed: PROPERTY_SEED, numRuns };
}

/** Run one property under `budget(ciRuns, scale)`. */
export function check<Ts extends [unknown, ...unknown[]]>(property: fc.IProperty<Ts>, ciRuns: number, scale = 1): void {
  fc.assert(property, budget(ciRuns, scale) as fc.Parameters<Ts>);
}

// ---------- generators ----------

export const isNoncharacter = (c: number) => (c >= 0xfdd0 && c <= 0xfdef) || (c & 0xfffe) === 0xfffe;

/** One Unicode scalar value that is not a noncharacter, from the ranges the properties cover. */
export const scalar = fc
  .oneof(
    fc.integer({ min: 0x00, max: 0x7f }),
    fc.integer({ min: 0x80, max: 0xd7ff }),
    fc.integer({ min: 0xe000, max: 0xfffd }),
    fc.integer({ min: 0x0300, max: 0x036f }),
    fc.integer({ min: 0x10000, max: 0x10ffff }),
  )
  .filter((c) => !isNoncharacter(c))
  .map((c) => String.fromCodePoint(c));

export const text = fc.string({ unit: scalar, maxLength: 10 });
export const memberName = fc.oneof(text, fc.constantFrom("__proto__", "constructor", "", "a", "A", "\u00e9", "e\u0301", "\u{1f600}"));
export const safeInteger = fc.oneof(fc.integer(), fc.maxSafeInteger());
/** A finite binary64 that canonicalizes: an integral value beyond 2^53 - 1 is refused (rule 2). */
export const finiteFloat = fc.double({ noNaN: true, noDefaultInfinity: true }).filter((n) => !Number.isInteger(n) || Number.isSafeInteger(n));

/** An object holding exactly `entries` as own members, defined so that __proto__ is a member. */
export function objectOf(entries: Array<[string, unknown]>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of entries) Object.defineProperty(out, k, { value: v, enumerable: true, writable: true, configurable: true });
  return out;
}

export const { value: jsonValue } = fc.letrec<{ value: unknown; array: unknown[]; object: Record<string, unknown> }>((tie) => ({
  value: fc.oneof(
    { depthSize: "small", maxDepth: 6 },
    fc.constant(null),
    fc.boolean(),
    safeInteger,
    finiteFloat,
    text,
    tie("array"),
    tie("object"),
  ),
  array: fc.array(tie("value"), { maxLength: 4 }),
  object: fc.uniqueArray(fc.tuple(memberName, tie("value")), { selector: (e) => e[0], maxLength: 4 }).map(objectOf),
}));
