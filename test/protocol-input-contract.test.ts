// The contract the two host-document parsers hold, asked of the parsers this package exports.
//
// The rules live in src/protocol-input.ts, in the exported parsers themselves, and not in an
// internal wrapper around them: `@loquitur/verify`'s exported parsers, and the conformance adapter,
// which imports them directly, must refuse what the verifier and the Python verifier refuse.
// This module asks the exported parsers for every rule.
//
// Each case is one deviation from a corpus document that parses, so what it measures is the rule
// and not a broken base; the first test is the lock that makes that true.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { parseRegistryEntry, parseTrustRegistry } from "../src/protocol-input.ts";
import { VECTORS_DIR } from "./bundle-kit.ts";

function entry(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const base = JSON.parse(readFileSync(join(VECTORS_DIR, "authorization_valid_registry_entry.json"), "utf-8"));
  return { ...base, ...overrides };
}

function registry(mutate: (value: Record<string, unknown>) => void = () => {}): Record<string, unknown> {
  const base = JSON.parse(readFileSync(join(VECTORS_DIR, "authorization_valid_trust_registry.json"), "utf-8"));
  mutate(base);
  return base;
}

function refusedFor(result: { ok: boolean; errors?: readonly string[] }, needle: string): void {
  assert.equal(result.ok, false);
  const errors = result.errors ?? [];
  assert.ok(
    errors.some((message) => message.includes(needle)),
    `no error naming ${JSON.stringify(needle)} among ${JSON.stringify(errors)}`,
  );
}

// U+00A0 is a member of the whitespace set W (src/whitespace.ts). It is built from its code
// point rather than written out, so no tracked file carries an invisible character.
const BLANK = String.fromCharCode(0x00a0);

test("the exported parsers accept the corpus documents that parse", () => {
  assert.equal(parseRegistryEntry(entry() as never).ok, true);
  assert.equal(parseTrustRegistry(registry() as never).ok, true);
});

test("a registry entry signature outside the schema's 128 lowercase hex is refused", () => {
  const signed = entry().signature as Record<string, unknown>;
  const upper = (signed.signature as string).toUpperCase();
  assert.notEqual(upper, signed.signature);
  refusedFor(parseRegistryEntry(entry({ signature: { ...signed, signature: upper } }) as never), "$.signature.signature");
});

test("an instant outside the schema pattern is refused wherever it stands", () => {
  refusedFor(parseRegistryEntry(entry({ issued_at: "2026-13-01T00:00:00Z" }) as never), "$.issued_at: instant outside the schema pattern");
  refusedFor(
    parseTrustRegistry(registry((r) => { (r.entries as Record<string, unknown>[])[0]!.revoked_at = "2026-01-32T00:00:00Z"; }) as never),
    "$.entries[0].revoked_at: instant outside the schema pattern",
  );
});

test("an instant inside the pattern that names no date is refused", () => {
  refusedFor(parseRegistryEntry(entry({ issued_at: "2026-02-30T00:00:00Z" }) as never), "$.issued_at: not a calendar instant");
  refusedFor(
    parseTrustRegistry(registry((r) => { (r.entries as Record<string, unknown>[])[0]!.revoked_at = "2026-02-30T00:00:00Z"; }) as never),
    "$.entries[0].revoked_at: not a calendar instant",
  );
});

test("a free string made only of the whitespace set W is refused", () => {
  refusedFor(parseRegistryEntry(entry({ issuer_key_id: BLANK }) as never), "$.issuer_key_id: made only of whitespace");
  refusedFor(
    parseTrustRegistry(registry((r) => { (r.entries as Record<string, unknown>[])[0]!.issuer_display_name = BLANK; }) as never),
    "$.entries[0].issuer_display_name: made only of whitespace",
  );
});

test("a registry entry whose verdict is not the verdict its reason codes derive is refused", () => {
  refusedFor(parseRegistryEntry(entry({ verdict: "FAIL" }) as never), "$.verdict: verdict_contradicts_grounds");
});

test("a trust entry public key is lowercase hexadecimal of 1 to 512 bytes; its key type's form is the signature step's", () => {
  // The contract admits any key type's encoding (canonicalization-and-hashing.md section 4): a
  // 32-byte value is well formed here, and a secp256k1 key in that form verifies nothing at the
  // signature step (trust-registry-authorization.md section 6, row 20).
  const withKey = (value: unknown) =>
    parseTrustRegistry(registry((r) => { (r.entries as Record<string, unknown>[])[0]!.public_key_hex = value; }) as never);
  assert.equal(withKey("a".repeat(64)).ok, true);
  assert.equal(withKey("ab".repeat(512)).ok, true);
  for (const value of ["", "a".repeat(63), "A".repeat(64), "ab".repeat(513), "zz", 7]) {
    refusedFor(withKey(value), "$.entries[0].public_key_hex");
  }
});

test("a trust registry that contradicts itself is refused", () => {
  refusedFor(
    parseTrustRegistry(registry((r) => { (r.entries as Record<string, unknown>[])[0]!.revoked_at = "2026-01-01T00:00:00Z"; }) as never),
    "$.entries[0]: an active key carries a revocation",
  );
  refusedFor(
    parseTrustRegistry(registry((r) => { r.effective_at = r.expires_at; r.expires_at = "2026-01-01T00:00:00Z"; }) as never),
    "$: effective_at is later than expires_at",
  );
});
