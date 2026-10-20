// sharesPoint decodes only the found entry's key and compares every other key by its spelling of
// the x coordinate and the parity or y, which must agree with decoding every key (the first
// implementation, kept below as the reference): the same answer for the same entries, over
// thousands of random registries built from every spelling of a point the forms and their near
// misses give.
import { test } from "node:test";
import assert from "node:assert/strict";
import { secp256k1 } from "@noble/curves/secp256k1";
import { secp256k1Point, sharesPoint } from "../src/key-point.ts";

type Keyed = { public_key_hex?: unknown };

/** The implementation sharesPoint replaced: it decodes every other key as well. */
function referenceSharesPoint(all: ReadonlyArray<Keyed>, index: number): boolean {
  const point = secp256k1Point(all[index]?.public_key_hex);
  if (point === null) return false;
  return all.some((other, at) => at !== index && secp256k1Point(other.public_key_hex) === point);
}

/** A seeded generator, so a failing case can be run again. */
function generator(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const P = secp256k1.CURVE.Fp.ORDER;
const hex64 = (n: bigint): string => n.toString(16).padStart(64, "0");

/** Every spelling of the point of private key `d`, and the near misses, as values of public_key_hex. */
function spellings(d: bigint): unknown[] {
  const point = secp256k1.ProjectivePoint.BASE.multiply(d).toAffine();
  const x = hex64(point.x);
  const y = hex64(point.y);
  const even = point.y % 2n === 0n;
  const right = even ? "02" : "03";
  const wrong = even ? "03" : "02";
  const out: unknown[] = [
    right + x, wrong + x, `04${x}${y}`, `04${x}${hex64(P - point.y)}`, `04${x}${hex64((point.y + 1n) % P)}`,
    (right + x).toUpperCase(), `04${x}${y}`.toUpperCase(), `${right}${x.toUpperCase()}`,
    `06${x}${y}`, `07${x}${y}`, `00${x}`, x, `${right}${x}00`, ` ${right}${x}`, `0x${right}${x}`, `04${x}${x}`, `04${y}${x}`, `${right}${y}`,
    "", "02", right + x.slice(0, 62), `04${x}${y.slice(2)}`,
    null, undefined, 7, {}, [right + x], true,
  ];
  if (point.x + P < 1n << 256n) out.push(right + hex64(point.x + P), wrong + hex64(point.x + P));
  return out;
}

test("sharesPoint answers as decoding every key does, over random registries", () => {
  const random = generator(20261020);
  const below = (n: number): number => Math.floor(random() * n);
  const keys = Array.from({ length: 12 }, (_, i) => BigInt(i + 1) * 0x1234567890abcdefn + 7n);
  const pool = keys.map(spellings);
  let sharing = 0;
  let cases = 0;
  for (; cases < 6000; cases++) {
    const size = 1 + below(6);
    const entries: Keyed[] = Array.from({ length: size }, () => {
      // Few distinct points, so that some registries repeat one and most do not.
      const spelling = pool[below(1 + below(3))]!;
      const value = spelling[random() < 0.6 ? below(3) : below(spelling.length)];
      return random() < 0.1 ? {} : { public_key_hex: value };
    });
    const index = below(size);
    const expected = referenceSharesPoint(entries, index);
    assert.equal(sharesPoint(entries, index), expected, JSON.stringify({ entries, index }));
    if (expected) sharing++;
  }
  // The generator reaches both answers often, so an always-false or always-true result fails.
  assert.ok(sharing > cases / 20 && sharing < cases * 0.95, `${sharing} of ${cases} registries share a point`);
});

test("sharesPoint on the forms that matter", () => {
  const point = secp256k1.ProjectivePoint.BASE.multiply(5n).toAffine();
  const x = hex64(point.x);
  const y = hex64(point.y);
  const right = point.y % 2n === 0n ? "02" : "03";
  const wrong = right === "02" ? "03" : "02";
  const found = { public_key_hex: right + x };
  assert.equal(sharesPoint([found, { public_key_hex: `04${x}${y}` }], 0), true);
  assert.equal(sharesPoint([{ public_key_hex: `04${x}${y}` }, found], 0), true);
  assert.equal(sharesPoint([found, { public_key_hex: wrong + x }], 0), false);
  assert.equal(sharesPoint([found, { public_key_hex: (right + x).toUpperCase() }], 0), false);
  assert.equal(sharesPoint([found, { public_key_hex: `06${x}${y}` }], 0), false);
  assert.equal(sharesPoint([found, { public_key_hex: `04${x}${hex64(P - point.y)}` }], 0), false);
  assert.equal(sharesPoint([{ public_key_hex: wrong + x }, found, found], 1), true);
  assert.equal(sharesPoint([{ public_key_hex: wrong + x }, found], 1), false);
  assert.equal(sharesPoint([{ public_key_hex: "00" }, { public_key_hex: "00" }], 0), false);
});
