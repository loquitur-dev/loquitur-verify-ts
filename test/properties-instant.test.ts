// Properties of the operator's evaluation time (trust-registry-authorization.md section 2;
// canonicalization-and-hashing.md section 6, rule 8): isCalendarInstant and operatorEvaluationTime
// accept exactly YYYY-MM-DDTHH:MM:SSZ naming a real UTC second of years 0001 to 9999. The calendar
// below is written in this file from the Gregorian rules, not taken from Date.
//
// Seed, budget and generators: test/property-kit.ts.
import { test } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";
import { isCalendarInstant } from "../src/instant.ts";
import { EvaluationTimeError, operatorEvaluationTime } from "../src/evaluation-time.ts";
import { check } from "./property-kit.ts";

const isLeap = (y: number) => (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0;
const daysIn = (y: number, m: number) => [31, isLeap(y) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][m - 1]!;
const pad = (n: number, width = 2) => String(n).padStart(width, "0");

type Parts = { y: number; m: number; d: number; h: number; mi: number; s: number };
const format = ({ y, m, d, h, mi, s }: Parts) => `${pad(y, 4)}-${pad(m)}-${pad(d)}T${pad(h)}:${pad(mi)}:${pad(s)}Z`;

/** Seconds since 1970 of a calendar instant, from the Gregorian rules alone. */
function epochSeconds({ y, m, d, h, mi, s }: Parts): number {
  let days = 0;
  if (y >= 1970) for (let year = 1970; year < y; year++) days += isLeap(year) ? 366 : 365;
  else for (let year = y; year < 1970; year++) days -= isLeap(year) ? 366 : 365;
  for (let month = 1; month < m; month++) days += daysIn(y, month);
  days += d - 1;
  return ((days * 24 + h) * 60 + mi) * 60 + s;
}

const year = fc.integer({ min: 1, max: 9999 });
const parts = fc
  .record({ y: year, m: fc.integer({ min: 1, max: 12 }), d: fc.integer({ min: 1, max: 31 }), h: fc.integer({ min: 0, max: 23 }), mi: fc.integer({ min: 0, max: 59 }), s: fc.integer({ min: 0, max: 59 }) })
  .map((p) => ({ ...p, d: Math.min(p.d, daysIn(p.y, p.m)) }));

/** Whether operatorEvaluationTime accepts `value`; any refusal other than EvaluationTimeError fails. */
function operatorAccepts(value: unknown): boolean {
  try {
    operatorEvaluationTime(value);
    return true;
  } catch (err) {
    if (err instanceof EvaluationTimeError) return false;
    throw err;
  }
}

test("every calendar instant of years 0001 to 9999 is accepted, as the second it names", () => {
  check(
    fc.property(parts, (p) => {
      const value = format(p);
      assert.ok(isCalendarInstant(value), value);
      const time = operatorEvaluationTime(value);
      assert.equal(time.value, value);
      assert.equal(time.epoch, epochSeconds(p) * 1000, value);
    }),
    1000,
  );
});

test("February 29 is accepted in a leap year and only there", () => {
  check(
    fc.property(year, fc.integer({ min: 0, max: 23 }), (y, h) => {
      const value = format({ y, m: 2, d: 29, h, mi: 0, s: 0 });
      assert.equal(isCalendarInstant(value), isLeap(y), value);
      assert.equal(operatorAccepts(value), isLeap(y), value);
    }),
    1000,
  );
  for (const y of [1600, 2000, 2400, 2024]) assert.ok(isCalendarInstant(format({ y, m: 2, d: 29, h: 0, mi: 0, s: 0 })), String(y));
  for (const y of [1700, 1800, 1900, 2100, 2023]) assert.ok(!isCalendarInstant(format({ y, m: 2, d: 29, h: 0, mi: 0, s: 0 })), String(y));
});

test("second 60, a day past the month's end, month 00 or 13, hour 24, minute 60 and year 0000 are refused", () => {
  const broken = fc.oneof(
    parts.map((p) => format({ ...p, s: 60 })),
    parts.filter((p) => daysIn(p.y, p.m) < 31).chain((p) => fc.integer({ min: daysIn(p.y, p.m) + 1, max: 31 }).map((d) => format({ ...p, d }))),
    parts.map((p) => format({ ...p, d: 0 })),
    parts.chain((p) => fc.constantFrom(0, 13, 99).map((m) => `${pad(p.y, 4)}-${pad(m)}-01T00:00:00Z`)),
    parts.map((p) => format({ ...p, h: 24 })),
    parts.map((p) => format({ ...p, mi: 60 })),
    parts.map((p) => format({ ...p, y: 0 })),
  );
  check(
    fc.property(broken, (value) => {
      assert.ok(!isCalendarInstant(value), value);
      assert.ok(!operatorAccepts(value), value);
    }),
    1000,
  );
});

/** Changes to the shape of a valid instant that no value of the form survives. */
const SHAPE_CHANGES: Array<(v: string, at: number, ch: string) => string> = [
  (v, at) => v.slice(0, at % v.length) + v.slice((at % v.length) + 1), // one character fewer
  (v, at, ch) => v.slice(0, at % (v.length + 1)) + ch + v.slice(at % (v.length + 1)), // one more
  (v) => v.replace("T", "t"),
  (v) => v.replace("T", " "),
  (v) => v.replace("Z", "z"),
  (v) => v.replace("Z", "+00:00"),
  (v) => v.slice(0, -1) + ".000Z",
  (v) => v.slice(0, -1),
  (v) => ` ${v}`,
  (v) => `${v}\n`,
  (v) => `+0${v}`,
  (v) => v.replace(/-/g, ""),
  (v, at, ch) => {
    // A digit replaced by a character that is not an ASCII digit.
    const digits = [...Array(v.length).keys()].filter((i) => /[0-9]/.test(v[i]!));
    const i = digits[at % digits.length]!;
    return v.slice(0, i) + (/[0-9]/.test(ch) ? String.fromCodePoint(0x0660 + Number(ch)) : ch) + v.slice(i + 1);
  },
];

test("any other shape is refused, a valid instant with one change among them", () => {
  check(
    fc.property(parts, fc.nat(), fc.constantFrom(...SHAPE_CHANGES), fc.string({ unit: "binary", minLength: 1, maxLength: 1 }), (p, at, change, ch) => {
      const value = change(format(p), at, ch);
      assert.ok(!isCalendarInstant(value), JSON.stringify(value));
      assert.ok(!operatorAccepts(value), JSON.stringify(value));
    }),
    1000,
  );
  check(
    fc.property(fc.string({ unit: "binary", maxLength: 24 }), (value) => {
      // Arbitrary text is accepted only when it is a calendar instant of the form.
      if (isCalendarInstant(value)) assert.match(value, /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/);
      assert.equal(operatorAccepts(value), isCalendarInstant(value));
    }),
    1000,
  );
  for (const value of [undefined, null, 0, "", ["2026-01-01T00:00:00Z"], { value: "2026-01-01T00:00:00Z" }]) {
    assert.ok(!operatorAccepts(value), JSON.stringify(value));
  }
});
