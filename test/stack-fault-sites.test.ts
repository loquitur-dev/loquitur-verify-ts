// Every catch that must let a stack the host ran out of through is proved to, site by site. A
// stack fault is a fault of the host, never a verdict (report-contract.md section 4), and the
// end-to-end climb of stack-fault-is-not-a-verdict.test.ts reaches only the steps where the end of
// the stack happens to fall. Here each guarded call is made to raise the engine's own error, a
// RangeError with no code, exactly where its catch stands, and the test requires that very error
// to come out of the entry point. A catch that turned it into a failed check, a null document or a
// read failure would hand back a report or a value instead, and the test fails.
//
// The faults are injected from outside: node:fs functions through syncBuiltinESMExports, as
// host-failure.test.ts injects refusals; TextDecoder, JSON.parse and the curve's verify on the
// objects the package calls; and a host object whose getter raises the fault while the package
// canonicalizes it. A fault is raised only when the call comes from the function that holds the
// catch, read from the stack trace, so one test reaches one site.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { join } from "node:path";
import { secp256k1 } from "@noble/curves/secp256k1";
import { Bundle, ephemeralAuthorization, ephemeralRoot, tempDir, verifyInMemoryBytes } from "./bundle-kit.ts";
import { DOCUMENT_READ_FAILED, readDocumentPath, verifyBundle } from "../src/verify.ts";
import { isHostStackFault } from "../src/json-strictness.ts";
import { verifyBundleFiles, type BundleReader } from "../src/verify-core.ts";
import { registryEntrySigningPayloadDigest, verifyRegistryEntrySignature, verifySecp256k1Sha256Digest } from "../src/signature.ts";
import { parseJsonStrict } from "../src/canonical.ts";
import { authenticateTrustRegistry, type TrustRoot } from "../src/trust-root.ts";

// The frame that names a catch's function can lie deeper than V8's default ten frames.
Error.stackTraceLimit = Infinity;

function stackFault(): RangeError {
  return new RangeError("Maximum call stack size exceeded");
}

/** The form V8 gives the same fault while it compiles or runs a regular expression. */
function regexStackFault(): SyntaxError {
  return new SyntaxError("Invalid regular expression: /(a)/: Stack overflow");
}

/** Whether the current call comes, at any depth, from every function named. */
function from(...names: string[]): boolean {
  const stack = new Error().stack ?? "";
  return names.every((name) => stack.includes(`at ${name} `) || stack.includes(`.${name} `));
}

type Method = (...args: unknown[]) => unknown;

/**
 * Run `run` while `holder[method]` raises one stack fault on the first call `when` selects, and
 * require that fault, the same object, to come out of `run`.
 */
function faultPropagates(
  holder: object,
  method: string,
  when: () => boolean,
  run: () => unknown,
  builtin = false,
  fault: () => Error = stackFault,
): void {
  const target = holder as Record<string, Method>;
  const original = target[method]!;
  let raised: Error | null = null;
  target[method] = function (this: unknown, ...args: unknown[]) {
    if (raised === null && when()) {
      raised = fault();
      throw raised;
    }
    return original.apply(this, args);
  };
  if (builtin) syncBuiltinESMExports();
  let outcome: { threw: boolean; value: unknown };
  try {
    try {
      outcome = { threw: false, value: run() };
    } catch (err) {
      outcome = { threw: true, value: err };
    }
  } finally {
    target[method] = original;
    if (builtin) syncBuiltinESMExports();
  }
  // A fault that was never raised would leave the test measuring nothing.
  assert.ok(raised !== null, `${method} was never called from the site under test`);
  assert.ok(outcome.threw, `the stack fault was contained: the call returned ${JSON.stringify(outcome.value)?.slice(0, 200)}`);
  assert.equal(outcome.value, raised, `another error came out instead of the stack fault: ${String(outcome.value)}`);
}

function onDisk(fn: (root: string) => void): void {
  const dir = tempDir("stack-fault-sites");
  try {
    fn(Bundle.linkValid().seal().writeTo(join(dir, "bundle")));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function documentOnDisk(text: string, fn: (path: string) => void): void {
  const dir = tempDir("stack-fault-document");
  try {
    const path = join(dir, "document.json");
    fs.writeFileSync(path, text);
    fn(path);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

const notReading = () => !from("takeInventory") && !from("resolveMember") && !from("readBounded");

// --- verify.ts: verifyBundle's input inspection, inventory and member reads ----------------------

test("a stack fault while verifyBundle inspects its input propagates", () => {
  onDisk((root) => faultPropagates(fs, "statSync", () => from("inspectPath", "verifyBundle"), () => verifyBundle(root), true));
});

// On Windows, ENOENT at the input is asked whether a link on the path names an entry that is
// there (report-contract.md section 5.3); elsewhere the host's error is its own answer, and the
// question is never asked.
function behindLinks(t: { skip: (why: string) => void }, fn: (missing: string, nulink: string) => void): void {
  if (process.platform !== "win32") {
    t.skip("the link question is asked only on Windows");
    return;
  }
  const dir = tempDir("stack-fault-links");
  try {
    const nulink = join(dir, "nulink");
    try {
      fs.symlinkSync("\\\\.\\nul", nulink, "file");
    } catch (err) {
      t.skip(`the host refuses to make a symbolic link: ${(err as NodeJS.ErrnoException).code ?? String(err)}`);
      return;
    }
    fn(join(dir, "missing", "bundle"), nulink);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test("a stack fault while the entries on a path stat cannot find are inspected propagates", (t) => {
  behindLinks(t, (missing) => faultPropagates(fs, "lstatSync", () => from("linkReachesAnEntry"), () => verifyBundle(missing), true));
});

test("a stack fault while a link on such a path is followed propagates", (t) => {
  behindLinks(t, (_, nulink) => faultPropagates(fs, "statSync", () => from("linkReachesAnEntry"), () => verifyBundle(nulink), true));
});

test("a stack fault while such a link's target is read propagates", (t) => {
  behindLinks(t, (_, nulink) => faultPropagates(fs, "readlinkSync", () => from("linkReachesAnEntry"), () => verifyBundle(nulink), true));
});

test("a stack fault while verifyBundle lists its input propagates", () => {
  onDisk((root) => faultPropagates(fs, "readdirSync", () => from("verifyBundle") && notReading(), () => verifyBundle(root), true));
});

test("a stack fault while the inventory lists a directory propagates", () => {
  onDisk((root) => faultPropagates(fs, "readdirSync", () => from("takeInventory"), () => verifyBundle(root), true));
});

test("a stack fault while a member's directory is listed propagates", () => {
  onDisk((root) => faultPropagates(fs, "readdirSync", () => from("resolveMember"), () => verifyBundle(root), true));
});

test("a stack fault while a member's entry is inspected on its path propagates", () => {
  onDisk((root) => faultPropagates(fs, "lstatSync", () => from("resolveMember"), () => verifyBundle(root), true));
});

test("a stack fault while a member is inspected before it is opened propagates", () => {
  onDisk((root) => faultPropagates(fs, "lstatSync", () => from("readBounded"), () => verifyBundle(root), true));
});

test("a stack fault while a member is opened propagates", () => {
  onDisk((root) => faultPropagates(fs, "openSync", () => from("readBounded"), () => verifyBundle(root), true));
});

test("a stack fault while a member is read propagates", () => {
  onDisk((root) => faultPropagates(fs, "readSync", () => from("readBounded"), () => verifyBundle(root), true));
});

// --- verify.ts: readDocumentPath ------------------------------------------------------------

test("a stack fault while readDocumentPath inspects the path propagates", () => {
  documentOnDisk('{"a": 1}', (path) => faultPropagates(fs, "statSync", () => from("readDocumentPath"), () => readDocumentPath(path), true));
});

test("a stack fault while readDocumentPath reads the file propagates", () => {
  documentOnDisk('{"a": 1}', (path) => faultPropagates(fs, "readFileSync", () => from("readDocumentPath"), () => readDocumentPath(path), true));
});

test("a stack fault while readDocumentPath decodes the bytes propagates", () => {
  documentOnDisk('{"a": 1}', (path) =>
    faultPropagates(TextDecoder.prototype, "decode", () => from("readDocumentPath"), () => readDocumentPath(path)),
  );
});

// The strict parser decodes with the package's own tokenizer (no JSON.parse): the faults below are
// raised from the string methods the tokenizer calls, at the site under test.
test("a stack fault while readDocumentPath parses the text propagates", () => {
  documentOnDisk('{"a": "b"}', (path) =>
    faultPropagates(String.prototype, "charCodeAt", () => from("readDocumentPath", "decodeJson"), () => readDocumentPath(path)),
  );
});

test("a stack fault V8 raises as a regular-expression error while readDocumentPath parses propagates", () => {
  // The parse catch contains an ordinary SyntaxError as a parse failure. V8's stack fault in its
  // regular-expression form is a SyntaxError too, and it must come through.
  documentOnDisk('{"a": "b"}', (path) =>
    faultPropagates(String.prototype, "charCodeAt", () => from("readDocumentPath", "decodeJson"), () => readDocumentPath(path), false, regexStackFault),
  );
});

// --- canonical.ts: the strict parser's string decoding ---------------------------------------

test("a stack fault while the strict parser decodes a string propagates", () => {
  faultPropagates(String, "fromCharCode", () => from("parseJsonStrict", "decodeJson"), () => parseJsonStrict('{"a": "\\u0062"}'));
});

// --- verify-core.ts: member loading and the containment of the run -----------------------------

test("a stack fault while a member's bytes are decoded propagates out of the in-memory run", () => {
  faultPropagates(TextDecoder.prototype, "decode", () => from("readJsonMember"), () => verifyInMemoryBytes(Bundle.linkValid().seal()));
});

test("a stack fault while a member is parsed is not contained as a parse failure", () => {
  faultPropagates(String.prototype, "charCodeAt", () => from("readJsonMember", "decodeJson"), () => verifyInMemoryBytes(Bundle.linkValid().seal()));
});

test("a stack fault while a loaded value is digested is not a canonicalization failure", () => {
  faultPropagates(TextEncoder.prototype, "encode", () => from("tryCanonicalSha256Hex", "canonicalJsonBytes"), () =>
    verifyInMemoryBytes(Bundle.linkValid().seal()),
  );
});

test("a stack fault while P1 is canonicalized is not a canonicalization failure", () => {
  faultPropagates(
    TextEncoder.prototype,
    "encode",
    () => from("verifyP1", "canonicalJsonBytes") && !from("tryCanonicalSha256Hex"),
    () => verifyInMemoryBytes(Bundle.linkValid().seal()),
  );
});

test("a stack fault while a reader with no listing is asked for the manifest propagates", () => {
  const bundle = Bundle.linkValid().seal();
  const files = new Map(bundle.files);
  const bytesOf = (name: string): Uint8Array | null => {
    const data = files.get(name);
    return data === undefined ? null : typeof data === "string" ? new TextEncoder().encode(data) : data;
  };
  // No listMembers: whether manifest.json exists is asked of the reader itself.
  const reader: BundleReader = {
    readBytes: (name: string) => bytesOf(name),
    readText(name: string) {
      const data = bytesOf(name);
      return data === null ? null : new TextDecoder().decode(data);
    },
  };
  faultPropagates(reader, "readBytes", () => from("hasManifestMember"), () => verifyBundleFiles(reader));
});

test("a stack fault a reader raises is not contained as a read failure", () => {
  const bundle = Bundle.linkValid().seal();
  const files = new Map(bundle.files);
  let raised: RangeError | null = null;
  const reader: BundleReader = {
    listMembers: () => [...files.keys()],
    readBytes(name: string) {
      if (name === "manifest.json" && raised === null) {
        raised = stackFault();
        throw raised;
      }
      const data = files.get(name);
      return data === undefined ? null : typeof data === "string" ? new TextEncoder().encode(data) : data;
    },
    readText(name: string) {
      const data = files.get(name);
      return data === undefined ? null : typeof data === "string" ? data : new TextDecoder().decode(data);
    },
  };
  assert.throws(() => verifyBundleFiles(reader), (err) => err === raised && raised !== null);
});

// --- signature.ts: the issuer signature -----------------------------------------------------

test("a stack fault while the curve verifies an entry's signature propagates", () => {
  const { registryEntry, trustRegistry } = ephemeralAuthorization(Bundle.linkValid().seal());
  const key = trustRegistry.entries[0].public_key_hex as string;
  const bound = { expectedKeyId: trustRegistry.entries[0].issuer_key_id as string, keyType: trustRegistry.entries[0].key_type as string };
  assert.equal(verifyRegistryEntrySignature(registryEntry, key, bound).valid, true, "the baseline signature verifies");
  faultPropagates(secp256k1, "verify", () => from("verifyRegistryEntrySignature"), () => verifyRegistryEntrySignature(registryEntry, key, bound));
});

test("a stack fault while the curve verifies a digest propagates", () => {
  const { registryEntry, trustRegistry } = ephemeralAuthorization(Bundle.linkValid().seal());
  const key = trustRegistry.entries[0].public_key_hex as string;
  const digest = registryEntrySigningPayloadDigest(registryEntry);
  const signature = (registryEntry.signature as { signature: string }).signature;
  assert.equal(verifySecp256k1Sha256Digest(digest, signature, key), true, "the baseline digest verifies");
  faultPropagates(secp256k1, "verify", () => from("verifySecp256k1Sha256Digest"), () => verifySecp256k1Sha256Digest(digest, signature, key));
});

test("a stack fault while an entry's signing payload is canonicalized is not a canonicalization failure", () => {
  const { registryEntry, trustRegistry } = ephemeralAuthorization(Bundle.linkValid().seal());
  const key = trustRegistry.entries[0].public_key_hex as string;
  const bound = { expectedKeyId: trustRegistry.entries[0].issuer_key_id as string, keyType: trustRegistry.entries[0].key_type as string };
  const value = registryEntry.manifest_hash;
  let raised: RangeError | null = null;
  Object.defineProperty(registryEntry, "manifest_hash", {
    enumerable: true,
    configurable: true,
    get() {
      if (raised === null && from("registryEntrySigningPayloadDigest")) {
        raised = stackFault();
        throw raised;
      }
      return value;
    },
  });
  assert.throws(() => verifyRegistryEntrySignature(registryEntry, key, bound), (err) => err === raised && raised !== null);
});

// --- trust-root.ts: the root signature over a trust registry ------------------------------------

test("a stack fault while a trust registry's signing message is canonicalized is not a canonicalization failure", () => {
  const { root, sign } = ephemeralRoot();
  const { trustRegistry } = ephemeralAuthorization(Bundle.linkValid().seal());
  delete trustRegistry.signature;
  sign(trustRegistry);
  const roots: TrustRoot[] = [{ ...root, status: "active" }];
  const instant = "2026-06-01T00:00:00Z";
  assert.equal(authenticateTrustRegistry(trustRegistry, roots, instant), "ROOT_SIGNATURE_VALID", "the baseline root signature verifies");
  const value = trustRegistry.trust_registry_id;
  let raised: RangeError | null = null;
  Object.defineProperty(trustRegistry, "trust_registry_id", {
    enumerable: true,
    configurable: true,
    get() {
      if (raised === null && from("trustRegistrySigningMessageBytes")) {
        raised = stackFault();
        throw raised;
      }
      return value;
    },
  });
  assert.throws(() => authenticateTrustRegistry(trustRegistry, roots, instant), (err) => err === raised && raised !== null);
});

// --- the other direction: what is not a stack fault --------------------------------------------

test("only the engine's uncoded RangeError and its regular-expression SyntaxError are stack faults", () => {
  const coded = Object.assign(new RangeError("File size (3221225472) is greater than 2 GiB"), { code: "ERR_FS_FILE_TOO_LARGE" });
  assert.equal(isHostStackFault(stackFault()), true);
  assert.equal(isHostStackFault(regexStackFault()), true);
  assert.equal(isHostStackFault(coded), false);
  assert.equal(isHostStackFault(new SyntaxError("Unexpected token } in JSON at position 7")), false);
  assert.equal(isHostStackFault(new Error("Maximum call stack size exceeded")), false);
  assert.equal(isHostStackFault("Maximum call stack size exceeded"), false);
});

test("a RangeError the host gives a code is a failed read, not a stack fault", () => {
  // Node gives each RangeError of its own a code, ERR_FS_FILE_TOO_LARGE for a file too large to
  // read; that is the host refusing the read (report-contract.md section 5.3).
  documentOnDisk('{"a": "b"}', (path) => {
    const original = fs.readFileSync;
    let refused = 0;
    (fs as unknown as { readFileSync: unknown }).readFileSync = (file: unknown, ...rest: unknown[]) => {
      if (String(file) === path) {
        refused += 1;
        throw Object.assign(new RangeError("File size (3221225472) is greater than 2 GiB"), { code: "ERR_FS_FILE_TOO_LARGE" });
      }
      return (original as (...a: unknown[]) => unknown)(file, ...rest);
    };
    syncBuiltinESMExports();
    try {
      assert.equal(readDocumentPath(path), DOCUMENT_READ_FAILED);
      assert.ok(refused > 0, "the host was never asked to read the document");
    } finally {
      (fs as unknown as { readFileSync: unknown }).readFileSync = original;
      syncBuiltinESMExports();
    }
  });
});
