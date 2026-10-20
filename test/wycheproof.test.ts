// Wycheproof P1363 known-answer corpus, applied to this package's secp256k1
// primitive with the same low-S mapping as the Python verifier's suite:
//   expected ACCEPT <=> result == "valid" AND 0 < s <= n/2 ; else REJECT.
// The vector file is pinned by its SHA-256, so a changed file fails the test. It is the Wycheproof
// project's (C2SP/wycheproof) testvectors_v1/ecdsa_secp256k1_sha256_p1363_test.json, retrieved on
// 2026-07-02 and used unmodified under the Apache License, Version 2.0; NOTICE credits it.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { verifySecp256k1Sha256Digest } from "../src/signature.js";

const here = dirname(fileURLToPath(import.meta.url));
const path = join(here, "../test-vectors/ecdsa_secp256k1_sha256_p1363_test.json");
const PINNED = "7a339efc7134fb2495cd32afdbd692e0f86427d3c24e9073f6a7d858bb8788d2";
const N = BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");

function isLowS(sigHex: string): boolean {
  if (sigHex.length !== 128 || !/^[0-9a-fA-F]+$/.test(sigHex)) return false;
  const s = BigInt("0x" + sigHex.slice(64));
  return s > 0n && s <= N / 2n;
}

test("vector file integrity is pinned", () => {
  const raw = readFileSync(path);
  assert.equal(bytesToHex(sha256(raw)), PINNED);
});

test("Wycheproof P1363 corpus == low-S expectations (full corpus)", () => {
  const data = JSON.parse(readFileSync(path, "utf-8"));
  const totals = { valid_low_s: 0, valid_high_s: 0, invalid: 0, acceptable: 0 };
  const failures: string[] = [];
  for (const g of data.testGroups) {
    const pub: string = (g.key ?? g.publicKey).uncompressed;
    for (const t of g.tests) {
      let expectAccept: boolean;
      if (t.result === "valid") {
        if (isLowS(t.sig)) { totals.valid_low_s++; expectAccept = true; }
        else { totals.valid_high_s++; expectAccept = false; }
      } else if (t.result === "invalid") { totals.invalid++; expectAccept = false; }
      else { totals.acceptable++; continue; }
      const digest = sha256(t.msg === "" ? new Uint8Array(0) : hexToBytes(t.msg));
      const got = verifySecp256k1Sha256Digest(digest, t.sig, pub);
      if (got !== expectAccept) failures.push(`tcId=${t.tcId} expected ${expectAccept} got ${got} [${t.comment}]`);
    }
  }
  assert.deepEqual(failures, [], failures.slice(0, 10).join("; "));
  const total = totals.valid_low_s + totals.valid_high_s + totals.invalid + totals.acceptable;
  assert.ok(total >= 250 && totals.valid_low_s >= 90 && totals.valid_high_s >= 70 && totals.invalid >= 80,
    JSON.stringify(totals));
});
