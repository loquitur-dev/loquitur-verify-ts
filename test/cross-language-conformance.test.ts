// Cross-language conformance locks, TypeScript side.
//
// Each test pins a case where two implementations can disagree on the same evidence, one
// saying PASS where the other says FAIL. Agreement between implementations is only as strong
// as the weakest of them.
//
// The paired Python assertions live in
// loquitur-verify-py/tests/test_cross_language_conformance_locks.py. Keep the two in step.
//
//   - the canonicalizer refuses lone UTF-16 surrogates, as Python does
//   - digest self-consistency is not protocol conformance (closed contracts)
//   - a duplicate issuer/key cannot make the verdict depend on array order
//   - an expired trust registry or issuer key does not authorize
//   - a declared key_type is enforced (no algorithm confusion)
//   - a validly-signed but schema-invalid entry does not authorize (no side channel)
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex } from "@noble/hashes/utils";
import { sibling } from "./siblings.ts";
import { canonicalJsonBytes, CanonicalizationError } from "../src/canonical.ts";
import {
  verifyBundleFiles,
  bundleReaderFromMap,
  STATUS_OFFLINE_OK,
  STATUS_OFFLINE_FAIL,
} from "../src/verify.ts";

const here = dirname(fileURLToPath(import.meta.url));
const FIXTURES = sibling(
  "loquitur-verify-py",
  [join(here, "../../loquitur-verify-py/tests/fixtures"), join(here, "../../public/loquitur-verify-py/tests/fixtures")],
  "authorization_valid_registry_entry.json",
  "sibling loquitur-verify-py fixtures absent",
);

// These vectors live in loquitur-verify-py, so that the two implementations are compared
// against one corpus rather than each keeping its own copy, which is how a consensus split
// starts. A single-repository clone does not have the sibling, so the suite skips instead of
// failing on an absence that is not a defect. A skip alone would report a check that never runs
// as one that passed, so the cross-implementation property is enforced wherever the
// repositories are assembled side by side (the `siblings` CI job once every sibling is
// published, the cross-repository gate): there LOQUITUR_REQUIRE_SIBLINGS is set, and an absent
// sibling fails every test below by name instead of skipping it (see siblings.ts).
const clone = <T,>(o: T): T => JSON.parse(JSON.stringify(o));
const readFx = (name: string) => JSON.parse(readFileSync(FIXTURES.path(name), "utf8"));
const entry = () => readFx("authorization_valid_registry_entry.json");
const trust = () => readFx("authorization_valid_trust_registry.json");

function bundleFiles(): Record<string, string> {
  const dir = FIXTURES.path("link_valid_bundle");
  const files: Record<string, string> = {};
  for (const f of readdirSync(dir)) files[f] = readFileSync(join(dir, f), "utf8");
  return files;
}
/** The operator's evaluation time: inside every window of the fixtures (trust-registry-authorization.md section 2). */
const EVALUATION_TIME = "2026-05-01T00:00:00Z";

function authorized(registryEntry: unknown, trustRegistry: unknown): boolean {
  const report = verifyBundleFiles(bundleReaderFromMap(bundleFiles()), { registryEntry, trustRegistry, evaluationTime: EVALUATION_TIME } as never);
  return (report.checks as Record<string, unknown>).trust_registry === true;
}

// -------------------------------------------------------------------
test("canonicalizer rejects lone UTF-16 surrogates, as Python does", () => {
  // A lone surrogate encodes no Unicode scalar value. Python rejects it; serialized as a
  // \\ud800 escape, the same object would canonicalize here and fail in Python. Canonical
  // bytes are signed, so the two implementations would compute different bytes for one value.
  assert.throws(() => canonicalJsonBytes({ k: "\uD800" }), CanonicalizationError);
  assert.throws(() => canonicalJsonBytes({ k: "\uDC00" }), CanonicalizationError);
  assert.throws(() => canonicalJsonBytes({ "\uD800": 1 }), CanonicalizationError);
  // A valid surrogate pair is accepted and produces the Python bytes.
  assert.equal(bytesToHex(canonicalJsonBytes({ k: "\u{1F600}" })), "7b226b223a22f09f9880227d");
});

// ------------------------------------------------------------ validity windows

test("expired issuer key is not authorized", FIXTURES.options, () => {
  const t = trust();
  t.entries[0].expires_at = "2021-01-01T00:00:00Z"; // entry is issued 2026
  assert.equal(authorized(entry(), t), false);
});

test("expired trust registry is not authorized", FIXTURES.options, () => {
  const t = trust();
  t.expires_at = "2021-01-01T00:00:00Z";
  assert.equal(authorized(entry(), t), false);
});

test("valid time window still authorizes", FIXTURES.options, () => {
  assert.equal(authorized(entry(), trust()), true);
});

// An instant the calendar does not have must not authorize an expired key that Python rejects.
// `Date.parse("2026-05-99")` is NaN and V8 rolls "2026-04-31" over to May 1; a parser that
// mapped either to null, read by the window check as "field absent", would skip the check.
// Two characters in a trust registry (a file that is distributed and is not signed by the
// entry payload) would then turn FAIL into PASS on one implementation only.
// A present instant that does not conform is refused, never ignored.
for (const bad of [
  "2026-05-99T00:00:00Z",   // impossible day
  "2026-99-01T00:00:00Z",   // impossible month
  "2026-04-31T00:00:00Z",   // V8 rolls this over to 2026-05-01
  "2026-05-01T25:00:00Z",   // impossible hour
  "2026-05-01",             // date only: not the schema shape
  "2026-05-01T00:00:00.500Z", // fractional seconds: Python's regex forbids them
  "2026-05-01T00:00:00+02:00", // offset instead of Z
  // Year 0000 survives both the regex and the toISOString round-trip: JavaScript
  // accepts it and re-serializes it unchanged, while Python's MINYEAR is 1. It is the
  // one member of this family the round-trip structurally cannot catch.
  "0000-01-01T00:00:00Z",
  "",
]) {
  test(`issuer key expires_at ${JSON.stringify(bad)} is not authorized (malformed instant must reject)`,
    FIXTURES.options, () => {
      const t = trust();
      t.entries[0].expires_at = bad;
      assert.equal(authorized(entry(), t), false);
    });

  test(`trust registry expires_at ${JSON.stringify(bad)} is not authorized (malformed instant must reject)`,
    FIXTURES.options, () => {
      const t = trust();
      t.expires_at = bad;
      assert.equal(authorized(entry(), t), false);
    });
}

for (const keyType of ["ed25519", "", null]) {
  test(`key_type ${JSON.stringify(keyType)} is not authorized (only secp256k1 is verified)`, FIXTURES.options, () => {
    const t = trust();
    if (keyType === null) delete t.entries[0].key_type;
    else t.entries[0].key_type = keyType;
    assert.equal(authorized(entry(), t), false);
  });
}

// -------------------------------------------------------------------
for (const activeFirst of [true, false]) {
  test(`duplicate issuer/key rejected regardless of order (active first: ${activeFirst})`, FIXTURES.options, () => {
    // A revoked key must not become authorized just because an `active` duplicate
    // happens to be earlier in the array.
    const t = trust();
    const active = clone(t.entries[0]);
    active.status = "active";
    const revoked = clone(t.entries[0]);
    revoked.status = "revoked";
    t.entries = activeFirst ? [active, revoked] : [revoked, active];
    assert.equal(authorized(entry(), t), false);
  });
}

// -------------------------------------------------------------------
test("registry entry with an unexpected public field is not authorized", FIXTURES.options, () => {
  // registry_entry is a closed contract. A "verified" entry must not be able to carry
  // an unbounded side channel, even if the issuer's signature covers it.
  const e = entry();
  e.secret_side_channel = "smuggled";
  assert.equal(authorized(e, trust()), false);
});

// -------------------------------------------------------------------
// A signature is `r || s`, 64 bytes (canonicalization-and-hashing.md §4). These 64 bytes are
// a DER encoding of a valid signature over the fixture entry, by a key solved for so that it
// verifies: 30 3e, then two 29-byte integers. @noble/curves, given bytes and no format, reads
// DER first, so a verifier that hands it the bytes alone would return OFFLINE_REVIEW, exit 2, with
// the trust registry authorized, where one that reads the halves as r and s, as the specification
// says, returns OFFLINE_FAIL, exit 1, SIGNATURE_INVALID.
// The same values are pinned in loquitur-verify-py/tests/test_signature_encoding.py.
const DER_SIGNATURE_HEX =
  "303e021d2e43787471f7543fc08bfd2a4545665ce1c05e3c1dd7d93ed524873173" +
  "021d11443e1eba922cb77d8bc4f41992fe8292fd635ad05366b69e6de7dc78";
const SAME_SIGNATURE_AS_R_S_HEX =
  "0000002e43787471f7543fc08bfd2a4545665ce1c05e3c1dd7d93ed524873173" +
  "00000011443e1eba922cb77d8bc4f41992fe8292fd635ad05366b69e6de7dc78";
const DER_SOLVED_PUBLIC_KEY_HEX =
  "04a7f98e2d747f760bef34adf11e1a92335dd2ff5a1c33d0aa0c0eb5706f16029b" +
  "63216d761bcd05ccfaa4ba01bcee0fc7ca9a74dd5d6bb4ff817687e81099ba3a";

test("a 64-byte DER signature fails as it does in Python; the same (r, s) as r || s is authorized", FIXTURES.options, () => {
  const t = trust();
  t.entries[0].public_key_hex = DER_SOLVED_PUBLIC_KEY_HEX;
  // The premise, so the failure below is about the encoding and nothing else.
  const rs = entry();
  rs.signature.signature = SAME_SIGNATURE_AS_R_S_HEX;
  assert.equal(authorized(rs, t), true);

  const der = entry();
  der.signature.signature = DER_SIGNATURE_HEX;
  const report = verifyBundleFiles(bundleReaderFromMap(bundleFiles()), { registryEntry: der, trustRegistry: t, evaluationTime: EVALUATION_TIME } as never);
  assert.equal(report.status, STATUS_OFFLINE_FAIL);
  assert.equal(report.exit_code, 1);
  assert.equal((report.checks as Record<string, unknown>).registry_signature, "SIGNATURE_INVALID");
  assert.equal((report.checks as Record<string, unknown>).trust_registry, false);
});

// -------------------------------------------------------------------
const sha = (b: Uint8Array) => bytesToHex(sha256(b));
/** A digest as a JSON document writes it (canonicalization-and-hashing.md section 2). */
const psha = (b: Uint8Array) => `sha256:${sha(b)}`;
const NONCE = "5f".repeat(32);
const dec = new TextDecoder();
const encText = new TextEncoder();

function buildBundle(mode: string): Record<string, string> {
  const ci = { asset_id: "x", asset_type: "property", external_mark: 1, policy_id: "p" };
  const ciB = canonicalJsonBytes(ci);

  let p1: Record<string, unknown> = { ih: psha(ciB), ik: Object.keys(ci).sort(), s: "p1", v: 1 };
  if (mode === "p1_malformed") p1 = { ih: psha(ciB), ik: Object.keys(ci).sort(), s: "p1", garbage: "smuggled" };
  // A present ik that is not a non-empty list of distinct strings does not fall back to the
  // whole input: ih below is the whole-input digest, so only the ik form is wrong.
  if (mode === "p1_ik_malformed") p1 = { ih: psha(ciB), ik: "asset_id", s: "p1", v: 1 };
  const p1B = canonicalJsonBytes(p1);
  // A P1 sidecar that disowns the P1 it sits next to; every other digest is consistent.
  const p1Sidecar = mode === "p1_sidecar_mismatch" ? "0".repeat(64) : sha(p1B);

  const files = {
    "canonical_input.json": psha(ciB),
    "p1.json": psha(p1B),
    "p1.sha256": psha(encText.encode(p1Sidecar)),
  };
  let manifest: Record<string, unknown> = { bundle_id: "b", nonce: NONCE, schema_version: "loquitur.bundle.v1", files };
  if (mode === "manifest_malformed") manifest = { files, nonce: NONCE, schema_version: "loquitur.bundle.v1" };
  if (mode === "manifest_type") manifest = { bundle_id: 7, nonce: NONCE, schema_version: "loquitur.bundle.v1", files };
  if (mode === "manifest_digest_case") {
    manifest = { bundle_id: "b", nonce: NONCE, schema_version: "loquitur.bundle.v1", files: { ...files, "p1.json": files["p1.json"].toUpperCase() } };
  }
  if (mode === "manifest_self_declared") manifest = { bundle_id: "b", nonce: NONCE, schema_version: "loquitur.bundle.v1", files: { ...files, "manifest.json": "0".repeat(64) } };
  if (mode === "manifest_files_list") {
    manifest = { bundle_id: "b", nonce: NONCE, schema_version: "loquitur.bundle.v1", files: Object.entries(files).map(([name, sha256]) => ({ name, sha256 })) };
  }
  const manB = canonicalJsonBytes(manifest);

  let env: Record<string, unknown> = {
    s: "env1", v: 1, bundle_id: "b",
    bundle_manifest_sha256: psha(manB), p1_sha256: psha(p1B), registry_entry: null,
  };
  if (mode === "envelope_bad_version") env = { s: "env1", v: 999, unexpected: "smuggled" };
  if (mode === "envelope_no_links") env = { s: "env1", v: 1 };
  const envB = canonicalJsonBytes(env);

  return {
    "canonical_input.json": dec.decode(ciB),
    "p1.json": dec.decode(p1B),
    "p1.sha256": p1Sidecar,
    "manifest.json": dec.decode(manB),
    "manifest.sha256": sha(manB),
    "envelope_env1.json": dec.decode(envB),
    "envelope.sha256": sha(envB),
  };
}

const BUNDLE_EXPECTATIONS: Array<[string, string]> = [
  ["good", STATUS_OFFLINE_OK],
  ["manifest_malformed", STATUS_OFFLINE_FAIL],
  ["p1_malformed", STATUS_OFFLINE_FAIL],
  ["envelope_bad_version", STATUS_OFFLINE_FAIL],
  // bundle-objects.md §4 makes bundle_id, bundle_manifest_sha256 and p1_sha256 required
  // members of an envelope: {"s":"env1","v":1} is not an envelope missing an optional
  // detail, it is not an env1 document, and an unconformant envelope is a rejection, exit 1,
  // as the Python half of the pair expects. REVIEW would ask a person to weigh something
  // there is nothing to weigh. The conformant "good" case above passes.
  ["envelope_no_links", STATUS_OFFLINE_FAIL],
  // Closed contracts of offline-verification-v1 (bundle-objects.md sections 2 and 3), each
  // case self-consistent by construction: a non-string bundle_id, an upper-case declared
  // digest, a manifest declaring itself, files in list form, and a P1 whose ik is a string.
  ["manifest_type", STATUS_OFFLINE_FAIL],
  ["manifest_digest_case", STATUS_OFFLINE_FAIL],
  ["manifest_self_declared", STATUS_OFFLINE_FAIL],
  ["manifest_files_list", STATUS_OFFLINE_FAIL],
  ["p1_ik_malformed", STATUS_OFFLINE_FAIL],
];
const EXIT_FOR_STATUS: Record<string, number> = { [STATUS_OFFLINE_OK]: 0, [STATUS_OFFLINE_FAIL]: 1 };

for (const [mode, expected] of BUNDLE_EXPECTATIONS) {
  test(`self-consistent but malformed bundle does not pass: ${mode}`, () => {
    // Every digest in these bundles is internally consistent by construction. Because each
    // digest is computed over whatever the object contains, a malformed object is
    // self-consistent. Digest self-consistency is not
    // protocol conformance, and the verifier must not conflate the two.
    const report = verifyBundleFiles(bundleReaderFromMap(buildBundle(mode)), {});
    assert.equal(report.status, expected, `${mode}: got ${report.status}`);
    // The Python lock asserts the exit code; assert the same one here.
    assert.equal(report.exit_code, EXIT_FOR_STATUS[expected], `${mode}: exit ${report.exit_code}`);
  });
}

test("p1_malformed_links: an envelope link to a P1 that did not verify does not hold", () => {
  // bundle-objects.md section 4: the P1 link holds only to a P1 that parsed, satisfied its contract
  // and matched its sidecar. The envelope in each bundle links to the P1 bytes as they are.
  for (const mode of ["p1_malformed", "p1_ik_malformed", "p1_sidecar_mismatch"]) {
    const report = verifyBundleFiles(bundleReaderFromMap(buildBundle(mode)), {});
    assert.equal(report.status, STATUS_OFFLINE_FAIL, mode);
    assert.equal((report.checks as Record<string, unknown>).envelope_links, false, mode);
  }
});

for (const mode of ["envelope_bad_version", "envelope_no_links"]) {
  test(`a malformed envelope that matches its stored digest reports the digest as held: ${mode}`, () => {
    // These envelopes are refused for their shape, and each still matches envelope.sha256,
    // because the bundle builder computed it. Python reports envelope_sha256 true and
    // envelope_links false for the same bytes, and so does this report.
    const checks = verifyBundleFiles(bundleReaderFromMap(buildBundle(mode)), {}).checks as Record<string, unknown>;
    assert.equal(checks.envelope_sha256, true);
    assert.equal(checks.envelope_links, false);
  });
}
