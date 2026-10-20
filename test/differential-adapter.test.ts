// scripts/differential-adapter.mjs, run with node as the differential harness of
// loquitur-conformance runs it: a handful of requests per op, the malformed lines and an unknown
// op, each answered on its own line, in order. The package is compiled for the run into a throwaway
// directory inside the package tree (Node resolves @noble/* by walking up to node_modules), as the
// cross-repository gate builds it for scripts/conformance-adapter.mjs, and removed afterwards.
//
// The expected signing messages are written out here from signing-envelope-v2.md section 1 and
// trust-root.md section 4, not computed with the package.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readdirSync, rmSync, statSync } from "node:fs";
import { createRequire } from "node:module";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { Bundle, ephemeralAuthorization, ephemeralRoot, jcsText, PACKAGE_DIR, rootDocument, rootSigningMessage, VECTORS_DIR } from "./bundle-kit.ts";

const BACKSLASH = String.fromCharCode(92);
const utf8 = new TextEncoder();
const b64 = (data: string | Uint8Array) => Buffer.from(typeof data === "string" ? utf8.encode(data) : data).toString("base64");
const concat = (...parts: Uint8Array[]) => Uint8Array.from(parts.flatMap((p) => [...p]));

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? sources(path) : name.endsWith(".ts") && !name.endsWith(".d.ts") ? [path] : [];
  });
}

/** Run the adapter over `lines` (each sent with its `\n`, the last one optionally without). */
function runAdapter(input: string): { status: number | null; stdout: string; stderr: string } {
  const build = mkdtempSync(join(PACKAGE_DIR, ".conformance-build-"));
  try {
    const esbuild = createRequire(join(PACKAGE_DIR, "package.json"))("esbuild");
    esbuild.buildSync({
      entryPoints: sources(join(PACKAGE_DIR, "src")), outdir: build, outbase: join(PACKAGE_DIR, "src"),
      format: "esm", platform: "node", target: "es2022", bundle: false, logLevel: "silent",
    });
    const result = spawnSync(process.execPath, [join(PACKAGE_DIR, "scripts", "differential-adapter.mjs")], {
      cwd: PACKAGE_DIR, input, encoding: "utf8", env: { ...process.env, LOQUITUR_CONFORMANCE_BUILD: build },
    });
    return { status: result.status, stdout: result.stdout, stderr: result.stderr };
  } finally {
    rmSync(build, { recursive: true, force: true });
  }
}

const ENTRY_PREFIX = utf8.encode("LOQUITUR\u0000REGISTRY_ENTRY\u0000SIGNATURE\u0000V2\u0000");
const ENTRY_ENVELOPE =
  '{"domain":"org.loquitur.protocol.registry-entry-signature","envelope_schema":"loquitur.signing_envelope.v2",' +
  '"envelope_version":2,"payload":{"z":[1,"x"]},"payload_id":"registry_entry_signing_payload_v2",' +
  '"payload_schema":"loquitur.registry_entry.v1","signature_algorithm":"secp256k1_ecdsa_sha256"}';

const nested = (depth: number) => "[".repeat(depth) + "]".repeat(depth);
const DOTTED_CAPITAL_I = String.fromCodePoint(0x130);
const KELVIN = String.fromCodePoint(0x212a);

/** Each request line, and the response it must get. */
const CASES: Array<[request: unknown, response: Record<string, unknown>]> = [
  [{ id: "load-ok", op: "load", input_b64: b64('{"a":1}') }, { accepted: true }],
  [{ id: "load-bom", op: "load", input_b64: b64(concat(Uint8Array.of(0xef, 0xbb, 0xbf), utf8.encode("{}"))) }, { accepted: false }],
  [{ id: "load-utf8", op: "load", input_b64: b64(Uint8Array.of(0x22, 0xff, 0x22)) }, { accepted: false }],
  [{ id: "load-dup", op: "load", input_b64: b64(`{"a":1,"${BACKSLASH}u0061":2}`) }, { accepted: false }],
  [{ id: "load-int", op: "load", input_b64: b64("[9007199254740992]") }, { accepted: false }],
  [{ id: "load-64", op: "load", input_b64: b64(nested(64)) }, { accepted: true }],
  [{ id: "load-65", op: "load", input_b64: b64(nested(65)) }, { accepted: false }],
  [{ id: "jcs-ok", op: "jcs", input_b64: b64('{ "b": 1.0, "a": ["\u00e9", 1e2] }') }, { accepted: true, output_b64: b64('{"a":["\u00e9",100],"b":1}') }],
  [{ id: "jcs-surrogate", op: "jcs", input_b64: b64(`{"a":"${BACKSLASH}ud800"}`) }, { accepted: false, output_b64: null }],
  [{ id: "jcs-nonfinite", op: "jcs", input_b64: b64("[1e400]") }, { accepted: false, output_b64: null }],
  [
    { id: "sig-entry", op: "signing_message", kind: "registry_entry", input_b64: b64('{"anchor":null,"signature":{"x":1},"anchored_at":"t","z":[1,"x"]}') },
    { accepted: true, output_b64: b64(concat(ENTRY_PREFIX, utf8.encode(ENTRY_ENVELOPE))) },
  ],
  [
    { id: "sig-trust", op: "signing_message", kind: "trust_registry", input_b64: b64('{"signature":1,"anchor":2}') },
    { accepted: true, output_b64: b64(rootSigningMessage({ anchor: 2 })) },
  ],
  [{ id: "sig-array", op: "signing_message", kind: "registry_entry", input_b64: b64("[1]") }, { accepted: false, output_b64: null }],
  [{ id: "sig-refused", op: "signing_message", kind: "trust_registry", input_b64: b64('{"a":1,"a":2}') }, { accepted: false, output_b64: null }],
  [{ id: "sig-kind", op: "signing_message", kind: "receipt", input_b64: b64("{}") }, { error: "TypeError" }],
  [{ id: "instant-leap", op: "instant", value: "2024-02-29T00:00:00Z" }, { accepted: true }],
  [{ id: "instant-common", op: "instant", value: "2023-02-29T00:00:00Z" }, { accepted: false }],
  [{ id: "instant-60", op: "instant", value: "2026-01-01T00:00:60Z" }, { accepted: false }],
  [{ id: "instant-offset", op: "instant", value: "2026-01-01T00:00:00+00:00" }, { accepted: false }],
  [{ id: "instant-number", op: "instant", value: 5 }, { error: "TypeError" }],
  [{ id: "name-upper", op: "member_name", value: "MANIFEST.JSON" }, { portable: true, folded: "manifest.json", self_declaration: true }],
  [{ id: "name-sidecar", op: "member_name", value: "Manifest.Sha256" }, { portable: true, folded: "manifest.sha256", self_declaration: true }],
  [
    { id: "name-dotted", op: "member_name", value: `MAN${DOTTED_CAPITAL_I}FEST.JSON` },
    { portable: false, folded: `man${DOTTED_CAPITAL_I}fest.json`, self_declaration: false },
  ],
  [{ id: "name-kelvin", op: "member_name", value: `${KELVIN}EY` }, { portable: false, folded: `${KELVIN}ey`, self_declaration: false }],
  [{ id: "name-device", op: "member_name", value: "sub/Con.txt" }, { portable: false, folded: "sub/con.txt", self_declaration: false }],
  [{ id: "unknown", op: "frobnicate" }, { error: "unknown_op" }],
  [{ id: "no-op" }, { error: "unknown_op" }],
  [{ id: "bad-base64", op: "load", input_b64: "***" }, { error: "TypeError" }],
  [{ id: "no-base64", op: "jcs" }, { error: "TypeError" }],
];

/** Lines that are not a JSON object with a string id. */
const BAD_LINES = ["not json", '{"op":"load"}', '{"id":1,"op":"load"}', "[1]", "null", ""];

test("the differential adapter answers every request line, in order, and exits 0", () => {
  const lines = [...CASES.map(([request]) => JSON.stringify(request)), ...BAD_LINES];
  // The last request is sent without its newline: it is still a request.
  const last = JSON.stringify({ id: "last", op: "instant", value: "2026-10-16T00:00:00Z" });
  const { status, stdout, stderr } = runAdapter(lines.map((line) => `${line}\n`).join("") + last);
  assert.equal(status, 0, stderr);
  assert.equal(stderr, "");
  assert.ok(stdout.endsWith("\n"));
  const out = stdout.slice(0, -1).split("\n");
  const expected = [
    ...CASES.map(([request, response]) => ({ id: (request as { id: string }).id, ...response })),
    ...BAD_LINES.map(() => ({ id: null, error: "bad_request" })),
    { id: "last", accepted: true },
  ];
  assert.equal(out.length, expected.length);
  assert.deepEqual(out.map((line) => JSON.parse(line)), expected);

  // The bytes: compact, members sorted, everything outside printable ASCII as a lowercase escape.
  for (const line of out) {
    assert.match(line, /^[\x20-\x7e]+$/);
    const parsed = JSON.parse(line);
    const keys = Object.keys(parsed);
    assert.deepEqual(keys, [...keys].sort());
    assert.ok(!/[:,] /.test(line.replace(/"(?:[^"\\]|\\.)*"/g, '""')), line);
  }
  const dotted = out[CASES.findIndex(([request]) => (request as { id: string }).id === "name-dotted")]!;
  assert.equal(dotted, `{"folded":"man${BACKSLASH}u0130fest.json","id":"name-dotted","portable":false,"self_declaration":false}`);
});

// ---------- the public-API operations ----------
//
// A chain made for the run (bundle-kit's ephemeral keys, never written anywhere): an issuer key
// signs the authorization fixture entry, a root key signs the trust registry, and a trust-root
// document pins the root. Every expected answer is the row of trust-registry-authorization.md
// section 6 or trust-root.md section 5 the case stops at, and the verdict trust-root.md sections 2
// and 6 give it, written here, not read from the package.

const docB64 = (value: unknown) => b64(JSON.stringify(value));
const EVALUATION_TIME = "2026-05-10T00:00:00Z";
const AUTHORIZED = { authorization_status: "AUTHORIZED_ACTIVE_KEY", signature_status: "VALID_SIGNATURE" };

test("the differential adapter answers every public-API operation", () => {
  const bundle = Bundle.linkValid();
  const { root, sign } = ephemeralRoot("root-a");
  const { registryEntry: entry, trustRegistry } = ephemeralAuthorization(bundle);
  const signed = sign(structuredClone(trustRegistry));
  const altered = structuredClone(signed) as any;
  altered.entries[0].allowed_asset_types.push("equity");
  const roots = rootDocument([root]);
  const revoked = rootDocument([{ ...root, status: "revoked" }]);
  const relabeled = sign(structuredClone(trustRegistry));
  (relabeled.signature as any).key_id = "root-b";
  const chain = { trust_registry_b64: docB64(signed), trust_roots_b64: docB64(roots), evaluation_time: EVALUATION_TIME };
  const issuerKey = (trustRegistry as any).entries[0].public_key_hex as string;
  const key = { public_key_hex: issuerKey, key_id: (entry as any).issuer_key_id, key_type: "secp256k1" };
  const unsigned = Object.fromEntries(Object.entries(entry).filter(([name]) => name !== "signature"));
  const digestHex = Buffer.from(entryDigest(entry)).toString("hex");
  const notAnEntry = { authorization_status: "INVALID_REGISTRY_ENTRY", signature_status: null, root_signature_status: "ROOT_SIGNATURE_NOT_EVALUATED", verdict: "FAIL" };
  const verified = {
    status: "OFFLINE_OK", verdict: "PASS", exit_code: 0, reason: "local_integrity_registry_link_and_trust_checks_passed", errors: [],
    checks_requested: ["structure", "integrity", "link", "authorization"], checks_established: ["structure", "integrity", "link", "authorization"],
    review_reasons: [], evaluation_time: EVALUATION_TIME,
    trust_registry: { ...AUTHORIZED, trust_registry_root_signature_status: "ROOT_SIGNATURE_VALID" },
    checks: { registry_link: true, trust_registry: true, registry_signature: "VALID_SIGNATURE" },
  };
  const cases: Array<[Record<string, unknown>, Record<string, unknown>]> = [
    [{ id: "t1", op: "trust_registry", entry_b64: docB64(entry), ...chain }, { ...AUTHORIZED, root_signature_status: "ROOT_SIGNATURE_VALID", verdict: "PASS" }],
    [{ id: "t2", op: "trust_registry", entry_b64: docB64(entry), trust_registry_b64: docB64(signed) }, { ...AUTHORIZED, root_signature_status: "NO_PINNED_TRUST_ROOT", verdict: "REVIEW" }],
    [{ id: "t3", op: "trust_registry", entry_b64: docB64(entry), ...chain, trust_registry_b64: docB64(altered) }, { ...AUTHORIZED, root_signature_status: "ROOT_SIGNATURE_INVALID", verdict: "FAIL" }],
    [{ id: "t4", op: "trust_registry", entry_b64: docB64(entry), ...chain, trust_roots_b64: docB64(revoked) }, { ...AUTHORIZED, root_signature_status: "ROOT_KEY_REVOKED", verdict: "FAIL" }],
    [{ id: "t5", op: "trust_registry", entry_b64: docB64(entry), trust_registry_b64: docB64(signed), trust_roots_b64: docB64(roots) }, { ...AUTHORIZED, root_signature_status: "ROOT_SIGNATURE_VALID", verdict: "REVIEW" }],
    [{ id: "t6", op: "trust_registry", entry_b64: docB64([entry]), ...chain }, notAnEntry],
    [{ id: "t7", op: "trust_registry", entry_b64: b64('{"a":1,"a":2}'), ...chain }, { entry_strict: false }],
    [{ id: "t8", op: "trust_registry", entry_b64: docB64(entry), ...chain, evaluation_time: "2026-05-10" }, { refused: "evaluation_time" }],
    [{ id: "t9", op: "trust_registry", entry_b64: docB64(entry), ...chain, trust_roots_b64: docB64({ ...roots, schema_version: "v2" }) }, { refused: "trust_roots_version" }],
    [{ id: "t10", op: "trust_registry", entry_b64: docB64(entry), ...chain, trust_roots_b64: docB64({ roots: [] }) }, { refused: "trust_roots" }],
    [{ id: "r1", op: "root_signature", ...chain }, { status: "ROOT_SIGNATURE_VALID" }],
    [{ id: "r2", op: "root_signature", ...chain, trust_registry_b64: docB64(relabeled) }, { status: "UNKNOWN_ROOT_KEY" }],
    [{ id: "r3", op: "root_signature", ...chain, evaluation_time: "2027-01-01T00:00:01Z" }, { status: "ROOT_KEY_EXPIRED" }],
    [{ id: "r4", op: "root_signature", trust_registry_b64: docB64(signed) }, { status: "NO_PINNED_TRUST_ROOT" }],
    [{ id: "r5", op: "root_signature", ...chain, trust_registry_b64: b64(concat(Uint8Array.of(0xef, 0xbb, 0xbf), utf8.encode("{}"))) }, { registry_strict: false }],
    [{ id: "o1", op: "trust_roots", input_b64: docB64(roots) }, { accepted: true, unsupported_version: null }],
    [{ id: "o2", op: "trust_roots", input_b64: docB64({ ...roots, schema_version: "v2" }) }, { accepted: false, unsupported_version: "v2" }],
    [{ id: "g1", op: "signature", entry_b64: docB64(entry), ...key }, { status: "VALID_SIGNATURE" }],
    [{ id: "g2", op: "signature", entry_b64: docB64(entry), ...key, key_id: "other" }, { status: "SIGNATURE_KEY_MISMATCH" }],
    [{ id: "g3", op: "signature", entry_b64: docB64(entry), ...key, key_type: "ed25519" }, { status: "UNSUPPORTED_SIGNATURE_ALGORITHM" }],
    [{ id: "g4", op: "signature", entry_b64: docB64({ ...entry, policy_version: "9.9.9" }), ...key }, { status: "SIGNATURE_INVALID" }],
    [{ id: "g5", op: "signature", entry_b64: docB64(unsigned), ...key }, { status: "MALFORMED_SIGNATURE" }],
    [{ id: "g6", op: "signature", entry_b64: docB64([entry]), ...key }, { entry_object: false }],
    [{ id: "e1", op: "ecdsa", digest_hex: digestHex, signature_hex: (entry as any).signature.signature, public_key_hex: issuerKey }, { valid: true }],
    [{ id: "e2", op: "ecdsa", digest_hex: "00".repeat(32), signature_hex: (entry as any).signature.signature, public_key_hex: issuerKey }, { valid: false }],
    [{ id: "u1", op: "summary_rules", input_b64: b64('{"status":"pass","reason_codes":[1,1.0]}') }, { accepted: true, rules: ["VG-1"] }],
    [{ id: "u2", op: "summary_rules", input_b64: b64("[]") }, { accepted: true, rules: ["VG-1"] }],
    [{ id: "u3", op: "summary_rules", input_b64: b64('{"a":1,"a":1}') }, { accepted: false, rules: null }],
    [{ id: "p1", op: "parse", kind: "registry_entry", input_b64: docB64(entry) }, { accepted: true, valid: true }],
    [{ id: "p2", op: "parse", kind: "trust_registry", input_b64: docB64({ ...signed, extra: 1 }) }, { accepted: true, valid: false }],
    [{ id: "p3", op: "parse", kind: "trust_registry", input_b64: docB64([signed]) }, { accepted: true, valid: false }],
    [{ id: "c1", op: "capability", algorithm: "secp256k1_ecdsa_sha256", key_type: "ed25519" }, { algorithm_supported: true, key_type_supported: false, pair_supported: false }],
    [{ id: "v1", op: "verify", bundle: join(VECTORS_DIR, "bundles", "link_valid_bundle"), entry_b64: docB64(entry), ...chain }, verified],
    [{ id: "v2", op: "verify", bundle: join(VECTORS_DIR, "bundles", "link_valid_bundle"), entry_b64: docB64(entry), ...chain, evaluation_time: 5 }, { refused: "evaluation_time" }],
  ];
  const { status, stdout, stderr } = runAdapter(cases.map(([request]) => `${JSON.stringify(request)}\n`).join(""));
  assert.equal(status, 0, stderr);
  assert.equal(stderr, "");
  const out = stdout.trimEnd().split("\n").map((line) => JSON.parse(line));
  assert.deepEqual(out, cases.map(([request, response]) => ({ id: request.id, ...response })));
});

/** The SHA-256 of the v2 signing message of an entry, written out from signing-envelope-v2.md section 1. */
function entryDigest(entry: Record<string, unknown>): Uint8Array {
  const payload = Object.fromEntries(Object.entries(entry).filter(([name]) => !["signature", "anchor", "anchored_at"].includes(name)));
  const envelope = {
    domain: "org.loquitur.protocol.registry-entry-signature",
    envelope_schema: "loquitur.signing_envelope.v2",
    envelope_version: 2,
    payload,
    payload_id: "registry_entry_signing_payload_v2",
    payload_schema: "loquitur.registry_entry.v1",
    signature_algorithm: "secp256k1_ecdsa_sha256",
  };
  return createHash("sha256").update(concat(ENTRY_PREFIX, utf8.encode(jcsText(envelope)))).digest();
}
