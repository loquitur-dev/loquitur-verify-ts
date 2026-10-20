// Cross-language canonicalization parity on adversarial Unicode: astral keys
// (where UTF-16 code-unit order != code-point order), Arabic/emoji values,
// control chars, and combining-vs-precomposed. Byte-identical to the Python
// rfc8785 package. Holds the canonical bytes against a change in the canonicalize
// dependency, for non-ASCII data such as Arabic issuer names.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { canonicalJsonBytes } from "../src/canonical.ts";
import { bytesToHex } from "@noble/hashes/utils";

const here = dirname(fileURLToPath(import.meta.url));
const golden = JSON.parse(readFileSync(join(here, "../test-vectors/canonicalization_unicode.json"), "utf-8"));

for (const g of golden) {
  test(`canonical bytes == Python rfc8785: ${g.name}`, () => {
    assert.equal(bytesToHex(canonicalJsonBytes(g.value)), g.canonical_utf8_hex);
  });
}
