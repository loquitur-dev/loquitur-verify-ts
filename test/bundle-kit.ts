// A bundle held as bytes, resealed and verified through each of this package's entries.
//
// The digests are computed with an RFC 8785 serializer written in this file, not with
// src/canonical.ts. A test that seals its bundle with the code under test cannot see a
// canonicalization defect: were canonicalJsonBytes to drop a member named __proto__, the
// seal would drop it too and the bundle would verify. The serializer below covers what the fixtures
// carry (objects, arrays, strings, safe integers, booleans, null), which is where RFC 8785
// is ECMAScript's JSON.stringify with member names sorted by UTF-16 code unit.
//
// Not a test file: `npm test` runs test/*.test.ts, and this is imported by them.
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import vm from "node:vm";
import { secp256k1 } from "@noble/curves/secp256k1";
import { bytesToHex } from "@noble/hashes/utils";
import { verifyBundle } from "../src/verify.ts";
import { registryEntrySigningPayloadDigest } from "../src/signature.ts";
import { bundleReaderFromMap, verifyBundleFiles, type VerifyReport } from "../src/verify-core.ts";

export const TEST_DIR = dirname(fileURLToPath(import.meta.url));
export const PACKAGE_DIR = join(TEST_DIR, "..");
export const VECTORS_DIR = join(PACKAGE_DIR, "test-vectors");

/** RFC 8785 text of a JSON value, independent of src/canonical.ts. */
export function jcsText(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "number" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(jcsText).join(",")}]`;
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((k) => `${JSON.stringify(k)}:${jcsText(record[k])}`).join(",")}}`;
  }
  throw new Error(`bundle-kit: not a JSON value: ${typeof value}`);
}

export function sha256Hex(data: Uint8Array | string): string {
  return createHash("sha256").update(data).digest("hex");
}

const utf8 = new TextEncoder();
const strictUtf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/** Define, never assign: `o[k] = v` cannot create a member named __proto__. */
export function defineMember(target: object, key: string, value: unknown): void {
  Object.defineProperty(target, key, { value, enumerable: true, writable: true, configurable: true });
}

export class Bundle {
  readonly files = new Map<string, Uint8Array>();
  readonly dirs: string[] = [];

  static fromDir(dir: string): Bundle {
    const bundle = new Bundle();
    const walk = (rel: string) => {
      for (const name of readdirSync(join(dir, rel))) {
        const child = rel ? `${rel}/${name}` : name;
        if (statSync(join(dir, child)).isDirectory()) walk(child);
        else bundle.files.set(child, new Uint8Array(readFileSync(join(dir, child))));
      }
    };
    walk("");
    return bundle;
  }

  /** test-vectors/bundles/link_valid_bundle: every member, a receipt, and a link entry that matches. */
  static linkValid(): Bundle {
    return Bundle.fromDir(join(VECTORS_DIR, "bundles", "link_valid_bundle"));
  }

  has(name: string): boolean {
    return this.files.has(name);
  }
  bytes(name: string): Uint8Array {
    const data = this.files.get(name);
    if (data === undefined) throw new Error(`bundle-kit: no member ${name}`);
    return data;
  }
  json(name: string): any {
    return JSON.parse(new TextDecoder().decode(this.bytes(name)));
  }
  setJson(name: string, value: unknown): this {
    this.files.set(name, utf8.encode(jcsText(value)));
    return this;
  }
  setBytes(name: string, data: Uint8Array | string): this {
    this.files.set(name, typeof data === "string" ? utf8.encode(data) : data);
    return this;
  }
  delete(name: string): this {
    this.files.delete(name);
    return this;
  }
  /** Parse a member, let `fn` change it in place, and store it back in canonical form. */
  edit(name: string, fn: (value: any) => void): this {
    const value = this.json(name);
    fn(value);
    return this.setJson(name, value);
  }

  manifestDigest(): string {
    return sha256Hex(jcsText(this.json("manifest.json")));
  }
  receiptDigest(): string {
    return sha256Hex(jcsText(this.json("verification_receipt.json")));
  }
  p1Digest(): string {
    return sha256Hex(jcsText(this.json("p1.json")));
  }

  /**
   * Recompute every digest from the members as they are, the way an honest producer would:
   * declared file digests, the manifest and P1 sidecars, the envelope links and sidecar,
   * and the receipt's manifest digest. Pass false to leave one of them as it is.
   */
  seal(options: { p1?: boolean; files?: boolean; manifest?: boolean; envelope?: boolean; receipt?: boolean } = {}): this {
    const { p1 = true, files = true, manifest = true, envelope = true, receipt = true } = options;
    let p1Digest: string | null = null;
    try {
      if (this.has("p1.json")) p1Digest = this.p1Digest();
    } catch {
      p1Digest = null; // a P1 that is not JSON has no digest to seal; the case under test broke it
    }
    if (p1 && p1Digest !== null) this.setBytes("p1.sha256", p1Digest);
    const man = this.json("manifest.json");
    if (files && man.files && typeof man.files === "object" && !Array.isArray(man.files)) {
      for (const name of Object.keys(man.files)) {
        if (this.has(name)) man.files[name] = `sha256:${sha256Hex(this.bytes(name))}`;
      }
      this.setJson("manifest.json", man);
    }
    const manifestDigest = sha256Hex(jcsText(man));
    if (manifest) this.setBytes("manifest.sha256", manifestDigest);
    if (envelope && this.has("envelope_env1.json")) {
      const env = this.json("envelope_env1.json");
      env.bundle_id = man.bundle_id;
      env.bundle_manifest_sha256 = `sha256:${manifestDigest}`;
      if (p1Digest !== null) env.p1_sha256 = `sha256:${p1Digest}`;
      this.setJson("envelope_env1.json", env);
      this.setBytes("envelope.sha256", sha256Hex(jcsText(env)));
    }
    if (receipt && this.has("verification_receipt.json")) {
      this.edit("verification_receipt.json", (r) => {
        r.manifest_sha256 = `sha256:${manifestDigest}`;
        if (typeof r.p1_sha256 === "string" && p1Digest !== null) r.p1_sha256 = `sha256:${p1Digest}`;
      });
    }
    return this;
  }

  /** The projection digest P1 must carry over `canonical_input.json` for its current `ik`. */
  inputHashFor(p1: { ik?: string[] }): string {
    const input = this.json("canonical_input.json");
    if (p1.ik === undefined) return `sha256:${sha256Hex(jcsText(input))}`;
    const payload = {};
    for (const key of p1.ik) defineMember(payload, key, Object.prototype.hasOwnProperty.call(input, key) ? input[key] : null);
    return `sha256:${sha256Hex(jcsText(payload))}`;
  }

  writeTo(root: string): string {
    mkdirSync(root, { recursive: true });
    for (const [name, data] of this.files) {
      mkdirSync(dirname(join(root, name)), { recursive: true });
      writeFileSync(join(root, name), data);
    }
    for (const dir of this.dirs) mkdirSync(join(root, dir), { recursive: true });
    return root;
  }
}

/** A registry entry for `bundle` built from the link fixture, with its two digests resealed. */
export function linkEntryFor(bundle: Bundle, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const entry = JSON.parse(readFileSync(join(VECTORS_DIR, "link_valid_registry_entry.json"), "utf8"));
  entry.manifest_hash = `sha256:${bundle.manifestDigest()}`;
  if (bundle.has("verification_receipt.json")) entry.receipt_hash = `sha256:${bundle.receiptDigest()}`;
  return Object.assign(entry, overrides);
}

/** A trust-root document of trust-root.md section 3 over `roots`. */
export function rootDocument(roots: unknown[]): Record<string, unknown> {
  return { object_type: "trust_root_document", schema_version: "v1", roots };
}

/**
 * A host document given as JSON text. JSON.parse reads any depth, but JSON.stringify recurses,
 * so a document too deep to serialize is handed to each entry as text and parsed in its realm.
 */
export class JsonText {
  constructor(readonly text: string) {}
}

type HostOptions = { registryEntry?: unknown; trustRegistry?: unknown; trustRoots?: unknown; evaluationTime?: unknown; vocabularies?: unknown };

function resolveOptions(opts: HostOptions, parse: (text: string) => unknown, copy: (value: unknown) => unknown): any {
  const out: Record<string, unknown> = {};
  for (const key of ["registryEntry", "trustRegistry", "trustRoots", "evaluationTime", "vocabularies"] as const) {
    if (!(key in opts)) continue;
    const value = opts[key];
    out[key] = value instanceof JsonText ? parse(value.text) : copy(value);
  }
  return out;
}

export function tempDir(label = "bundle"): string {
  return mkdtempSync(join(tmpdir(), `lq-ts-${label}-`));
}

/** The Node entry: the bundle written to a fresh directory and verified with verifyBundle. */
export function verifyOnDisk(bundle: Bundle, opts: HostOptions = {}): VerifyReport {
  const dir = tempDir();
  try {
    return verifyBundle(bundle.writeTo(join(dir, "bundle")), resolveOptions(opts, JSON.parse, (v) => v));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** The in-memory entry, with the byte-faithful map a browser host builds: text where the bytes are UTF-8. */
export function verifyInMemory(bundle: Bundle, opts: HostOptions = {}): VerifyReport {
  return verifyInMemoryAs(bundle, opts, false);
}

/** The in-memory entry with every member given as a Uint8Array, as the README asks hosts to do. */
export function verifyInMemoryBytes(bundle: Bundle, opts: HostOptions = {}): VerifyReport {
  return verifyInMemoryAs(bundle, opts, true);
}

function verifyInMemoryAs(bundle: Bundle, opts: HostOptions, allBytes: boolean): VerifyReport {
  const map = {};
  for (const [name, data] of bundle.files) {
    let value: string | Uint8Array = data;
    if (!allBytes) {
      try {
        value = strictUtf8.decode(data);
      } catch {
        value = data;
      }
    }
    defineMember(map, name, value);
  }
  return verifyBundleFiles(bundleReaderFromMap(map as Record<string, string>), resolveOptions(opts, JSON.parse, (v) => v));
}

let browserContext: vm.Context | null = null;

/**
 * The browser entry: src/index.browser.ts built as the IIFE `npm run build:browser` produces
 * (in memory, nothing written), evaluated in a separate realm. Map values and option objects
 * are created in that realm, as a page would create them.
 */
export function verifyInBrowserBuild(bundle: Bundle, opts: HostOptions = {}): VerifyReport {
  return verifyInBrowserBuildAs(bundle, opts, false);
}

/** The browser entry with every member given as a Uint8Array of that realm. */
export function verifyInBrowserBuildBytes(bundle: Bundle, opts: HostOptions = {}): VerifyReport {
  return verifyInBrowserBuildAs(bundle, opts, true);
}

function verifyInBrowserBuildAs(bundle: Bundle, opts: HostOptions, allBytes: boolean): VerifyReport {
  if (browserContext === null) {
    const esbuild = createRequire(join(PACKAGE_DIR, "package.json"))("esbuild");
    const built = esbuild.buildSync({
      entryPoints: [join(PACKAGE_DIR, "src/index.browser.ts")], bundle: true, format: "iife",
      globalName: "LoquiturVerifier", platform: "browser", target: "es2020", write: false, logLevel: "silent",
    });
    browserContext = vm.createContext({ TextEncoder, TextDecoder });
    vm.runInContext(built.outputFiles[0].text, browserContext);
  }
  const ctx = browserContext;
  const realmObject = vm.runInContext("Object", ctx);
  const realmU8 = vm.runInContext("Uint8Array", ctx);
  const realmJson = vm.runInContext("JSON", ctx);
  const map = realmObject.create(realmObject.prototype);
  for (const [name, data] of bundle.files) {
    let value: unknown;
    try {
      if (allBytes) throw new Error("bytes requested");
      value = strictUtf8.decode(data);
    } catch {
      const copy = new realmU8(data.length);
      copy.set(data);
      value = copy;
    }
    realmObject.defineProperty(map, name, { value, enumerable: true, writable: true, configurable: true });
  }
  const resolved = resolveOptions(opts, (text) => realmJson.parse(text),
    (value) => (value === undefined ? undefined : realmJson.parse(JSON.stringify(value))));
  const realmOpts = realmObject.create(realmObject.prototype);
  for (const key of Object.keys(resolved)) realmOpts[key] = resolved[key];
  const lib = vm.runInContext("LoquiturVerifier", ctx);
  let report;
  try {
    report = lib.verifyBundleFiles(lib.bundleReaderFromMap(map), realmOpts);
  } catch (err) {
    // An error of the other realm is not an instance of this realm's classes: rethrow it as one
    // of the same name, so a caller can recognize a refusal the way it recognizes the Node entry's.
    throw new RealmError(err);
  }
  return JSON.parse(JSON.stringify(report));
}

/** An error thrown inside the browser realm, carried across with its name and message. */
export class RealmError extends Error {
  constructor(err: unknown) {
    super(String((err as { message?: unknown })?.message ?? err));
    this.name = String((err as { name?: unknown })?.name ?? "Error");
  }
}

/** The name of the error a thunk throws, or null when it returns. */
export function refusal(run: () => unknown): string | null {
  try {
    run();
    return null;
  } catch (err) {
    return err instanceof Error ? err.name : String(err);
  }
}

/** The three entries a caller can reach, by name. */
export const ENTRIES: Array<[string, (b: Bundle, o?: any) => VerifyReport]> = [
  ["fs", verifyOnDisk],
  ["map", verifyInMemory],
  ["browser", verifyInBrowserBuild],
];

/** Status, verdict, exit code and the named checks of a report, for one deepEqual. */
export function outcome(report: VerifyReport, checks: string[] = []): Record<string, unknown> {
  const out: Record<string, unknown> = { status: report.status, verdict: report.verdict, exit_code: report.exit_code };
  for (const name of checks) out[name] = report.checks[name];
  return out;
}

/**
 * The outcome of an authorization run: status, verdict, exit code, the trust_registry and
 * registry_signature results, and the three authorization statuses of report-contract.md section
 * 5.4 (null when the trust registry was not evaluated), for one deepEqual.
 */
export function authorizationOutcome(report: VerifyReport): Record<string, unknown> {
  const trust = report.trust_registry;
  return {
    ...outcome(report, ["trust_registry", "registry_signature"]),
    authorization_status: trust === null ? null : trust.authorization_status,
    signature_status: trust === null ? null : trust.signature_status,
    root_signature_status: trust === null ? null : trust.trust_registry_root_signature_status,
  };
}

export const PASS = { status: "OFFLINE_OK", verdict: "PASS", exit_code: 0 };
export const REVIEW = { status: "OFFLINE_REVIEW", verdict: "REVIEW", exit_code: 2 };
export const FAIL = { status: "OFFLINE_FAIL", verdict: "FAIL", exit_code: 1 };

/**
 * A host's own reader with readText and readBytes and nothing else: exact bytes, no enumeration.
 */
export function verifyWithByteReader(bundle: Bundle, opts: HostOptions = {}): VerifyReport {
  const reader = {
    readText: (name: string) => (bundle.files.has(name) ? new TextDecoder().decode(bundle.files.get(name)) : null),
    readBytes: (name: string) => bundle.files.get(name) ?? null,
  };
  return verifyBundleFiles(reader, resolveOptions(opts, JSON.parse, (v) => v));
}
/** The prefix of trust-root.md section 4, as the document writes it in hexadecimal. */
export const ROOT_SIGNING_PREFIX_HEX = "4c4f5155495455520054525553545f524547495354525900524f4f545f5349474e415455524500563100";

/**
 * The message a root signs over a trust registry, built here from trust-root.md section 4 and
 * independently of src/trust-root.ts: the prefix, then the RFC 8785 bytes of the closed envelope
 * whose payload is the registry without its `signature` member.
 */
export function rootSigningMessage(registry: Record<string, unknown>): Uint8Array {
  const payload: Record<string, unknown> = {};
  for (const [name, value] of Object.entries(registry)) if (name !== "signature") defineMember(payload, name, value);
  const envelope = {
    domain: "org.loquitur.protocol.trust-registry-root-signature",
    envelope_schema: "loquitur.trust_registry_root_signing_envelope.v1",
    envelope_version: 1,
    payload,
    payload_schema: "loquitur.trust_registry.v1",
    signature_algorithm: "secp256k1_ecdsa_sha256",
  };
  const prefix = Uint8Array.from(ROOT_SIGNING_PREFIX_HEX.match(/../g)!.map((pair) => parseInt(pair, 16)));
  const body = utf8.encode(jcsText(envelope));
  const message = new Uint8Array(prefix.length + body.length);
  message.set(prefix, 0);
  message.set(body, prefix.length);
  return message;
}

/**
 * A root key made for one test run and never written anywhere: a well-formed root of trust-root.md
 * section 3 under `keyId`, and a signer that puts this root's signature on a trust registry.
 */
export function ephemeralRoot(keyId = "root-1") {
  const privateKey = secp256k1.utils.randomPrivateKey();
  const publicKeyHex = bytesToHex(secp256k1.getPublicKey(privateKey, false));
  const root = { key_id: keyId, key_type: "secp256k1", public_key_hex: publicKeyHex, not_before: "2026-01-01T00:00:00Z", not_after: "2027-01-01T00:00:00Z" };
  const sign = (registry: Record<string, unknown>): Record<string, unknown> => {
    const digest = createHash("sha256").update(rootSigningMessage(registry)).digest();
    registry.signature = {
      algorithm: "secp256k1_ecdsa_sha256",
      key_id: keyId,
      signature: secp256k1.sign(digest, privateKey, { lowS: true }).toCompactHex(),
    };
    return registry;
  };
  return { root, sign };
}

/**
 * An issuer key made for one test run and never written anywhere: the authorization fixture entry
 * for `bundle`, re-signed with it, and the authorization fixture trust registry authorizing its
 * public key.
 */
export function ephemeralAuthorization(bundle: Bundle, overrides: Record<string, unknown> = {}) {
  const privateKey = secp256k1.utils.randomPrivateKey();
  const publicKeyHex = bytesToHex(secp256k1.getPublicKey(privateKey, false));
  const entry = JSON.parse(readFileSync(join(VECTORS_DIR, "authorization_valid_registry_entry.json"), "utf8"));
  entry.manifest_hash = `sha256:${bundle.manifestDigest()}`;
  if (bundle.has("verification_receipt.json")) entry.receipt_hash = `sha256:${bundle.receiptDigest()}`;
  Object.assign(entry, overrides);
  entry.signature.signature = secp256k1.sign(registryEntrySigningPayloadDigest(entry), privateKey, { lowS: true }).toCompactHex();
  const trust = JSON.parse(readFileSync(join(VECTORS_DIR, "authorization_valid_trust_registry.json"), "utf8"));
  trust.entries[0].public_key_hex = publicKeyHex;
  return { registryEntry: entry, trustRegistry: trust };
}

/**
 * ephemeralAuthorization with changes anywhere in the two documents: `entry` changes the
 * authorization fixture entry before it is signed (nested members included, so the signature covers
 * them), `afterSigning` changes it after, and `trust` changes the trust registry once the key's
 * public half is in it. The private key is made here and never leaves this function.
 */
export function ephemeralAuthorizationWith(
  bundle: Bundle,
  changes: { entry?: (e: any) => void; afterSigning?: (e: any) => void; trust?: (t: any) => void } = {},
) {
  const privateKey = secp256k1.utils.randomPrivateKey();
  const publicKeyHex = bytesToHex(secp256k1.getPublicKey(privateKey, false));
  const entry = JSON.parse(readFileSync(join(VECTORS_DIR, "authorization_valid_registry_entry.json"), "utf8"));
  entry.manifest_hash = `sha256:${bundle.manifestDigest()}`;
  if (bundle.has("verification_receipt.json")) entry.receipt_hash = `sha256:${bundle.receiptDigest()}`;
  changes.entry?.(entry);
  if (entry.signature !== null && typeof entry.signature === "object") {
    entry.signature.signature = secp256k1.sign(registryEntrySigningPayloadDigest(entry), privateKey, { lowS: true }).toCompactHex();
  }
  changes.afterSigning?.(entry);
  const trust = JSON.parse(readFileSync(join(VECTORS_DIR, "authorization_valid_trust_registry.json"), "utf8"));
  trust.entries[0].public_key_hex = publicKeyHex;
  changes.trust?.(trust);
  return { registryEntry: entry, trustRegistry: trust };
}

// ---- public keys as secp256k1 points: trust-registry-authorization.md section 6, row 6, and
// trust-root.md section 5, row 7 (AMBIGUOUS_ROOT_KEY) ------------------------------------------

/** The field prime p of secp256k1. */
const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const hex32 = (n: bigint): string => n.toString(16).padStart(64, "0");

/** The compressed SEC1 encoding of the point an uncompressed `04 || X || Y` encodes. */
export function compressedKey(uncompressed: string): string {
  return (BigInt(`0x${uncompressed.slice(66)}`) % 2n === 0n ? "02" : "03") + uncompressed.slice(2, 66);
}

/** The hybrid SEC1 encoding (06 or 07 by the parity of Y) of the same point, which encodes no point here. */
export function hybridKey(uncompressed: string): string {
  return (BigInt(`0x${uncompressed.slice(66)}`) % 2n === 0n ? "06" : "07") + uncompressed.slice(2);
}

// Two points with one coordinate below 2^32 + 977, so that the coordinate plus p still fits in 32
// bytes: (1, Y1) and (X1, 1), both on y^2 = x^3 + 7. Written with the coordinate plus p, each is the
// same point only if a reader reduced the coordinate modulo p.
const Y1 = 0x4218f20ae6c646b363db68605822fb14264ca8d2587fdd6fbc750d587e76a7een;
const X1 = 0x1fe1e5ef3fceb5c135ab7741333ce5a6e80d68167653f6b2b24bcbcfaaaff507n;
export const SMALL_X_POINT = `04${hex32(1n)}${hex32(Y1)}`;
export const SMALL_X_PLUS_P = `04${hex32(1n + P)}${hex32(Y1)}`;
export const SMALL_X_PLUS_P_COMPRESSED = `${Y1 % 2n === 0n ? "02" : "03"}${hex32(1n + P)}`;
export const SMALL_Y_POINT = `04${hex32(X1)}${hex32(1n)}`;
export const SMALL_Y_PLUS_P = `04${hex32(X1)}${hex32(1n + P)}`;

/**
 * The point a public key encodes, as the rules of row 6 and row 7 compare keys, written from the
 * specification's definition and not from the package's code: lowercase SEC1, compressed or
 * uncompressed, coordinates below p, on the curve. Null when the value encodes no point.
 */
export function pointOf(hex: unknown): string | null {
  if (typeof hex !== "string" || !/^(?:0[23][0-9a-f]{64}|04[0-9a-f]{128})$/.test(hex)) return null;
  const x = BigInt(`0x${hex.slice(2, 66)}`);
  if (x >= P) return null;
  const rhs = (x ** 3n + 7n) % P;
  let y: bigint;
  if (hex.startsWith("04")) {
    y = BigInt(`0x${hex.slice(66)}`);
    if (y >= P || (y * y) % P !== rhs) return null;
  } else {
    // p is 3 mod 4, so a square root of rhs, when there is one, is rhs^((p + 1) / 4).
    let root = 1n;
    for (let base = rhs, e = (P + 1n) / 4n; e > 0n; e >>= 1n, base = (base * base) % P) if (e & 1n) root = (root * base) % P;
    if ((root * root) % P !== rhs) return null;
    y = (root % 2n === BigInt(hex[1] === "3" ? 1 : 0)) ? root : P - root;
  }
  return `${hex32(x)}${hex32(y)}`;
}
