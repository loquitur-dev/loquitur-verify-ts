// A document file whose bytes are not strict JSON, read with readDocumentPath, comes back as
// DOCUMENT_NOT_STRICT_JSON, never as `null`, which a file holding the JSON value null gives. Each
// option then says what was wrong with the bytes: the trust roots and a vocabulary are refused as
// not strict JSON (trust-root.md section 3, verification-vocabularies.md section 8), where `null`
// would have them refused as not an object, and a registry entry or a trust registry gives the
// report a document that is not a strict JSON object gives (report-contract.md section 5.3).
//
// The corpus run authorization_trust_root_lone_surrogate pins only the exit code and the absent
// report of the trust-root refusal; the message is held here.
import { test } from "node:test";
import assert from "node:assert/strict";
import { rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { Bundle, ephemeralAuthorization, tempDir } from "./bundle-kit.ts";
import { DOCUMENT_NOT_STRICT_JSON, TrustRootError, VocabularyError, readDocumentPath, verifyBundle, type VerifyOptions } from "../src/index.ts";

const EVALUATION_TIME = "2026-05-10T00:00:00Z";
// A lone surrogate, written as the JSON escape the strict loader refuses.
const LONE_SURROGATE = '{"object_type": "\\ud800"}';

/** `fn` given the path of a file that holds `text`, in a directory removed afterwards. */
function withFile<T>(text: string, fn: (path: string, dir: string) => T): T {
  const dir = tempDir("not-strict-json");
  try {
    const path = join(dir, "document.json");
    writeFileSync(path, text);
    return fn(path, dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("readDocumentPath gives DOCUMENT_NOT_STRICT_JSON for bytes the strict loader refuses, and null for a null file", () => {
  withFile(LONE_SURROGATE, (path) => assert.equal(readDocumentPath(path), DOCUMENT_NOT_STRICT_JSON));
  withFile("null", (path) => assert.equal(readDocumentPath(path), null));
});

test("a trust-root document that is not strict JSON is refused as one, not as a document that is no object", () => {
  withFile(LONE_SURROGATE, (path, dir) => {
    const bundle = Bundle.linkValid().seal().writeTo(join(dir, "bundle"));
    assert.throws(
      () => verifyBundle(bundle, { trustRoots: readDocumentPath(path), evaluationTime: EVALUATION_TIME }),
      (err: unknown) => err instanceof TrustRootError && err.message === "trust-root document malformed: the document is not a strict JSON document",
    );
    // The JSON value null is a document, refused as not an object.
    assert.throws(
      () => verifyBundle(bundle, { trustRoots: null, evaluationTime: EVALUATION_TIME }),
      (err: unknown) => err instanceof TrustRootError && err.message === "trust-root document malformed: the document is not a JSON object",
    );
  });
});

test("a vocabulary that is not strict JSON is refused as one", () => {
  withFile(LONE_SURROGATE, (path, dir) => {
    const bundle = Bundle.linkValid().seal().writeTo(join(dir, "bundle"));
    assert.throws(
      () => verifyBundle(bundle, { vocabularies: { workflow: readDocumentPath(path) } }),
      (err: unknown) => err instanceof VocabularyError && err.message === "the workflow vocabulary breaks verification-vocabularies.md section 6: $: not a strict JSON document",
    );
  });
});

test("a registry entry or a trust registry that is not strict JSON gives the report of a document that is no strict JSON object", () => {
  const bundle = Bundle.linkValid().seal();
  const { registryEntry, trustRegistry } = ephemeralAuthorization(bundle);
  const dir = tempDir("not-strict-json");
  try {
    const path = bundle.writeTo(join(dir, "bundle"));
    const cases: [string, VerifyOptions, VerifyOptions, VerifyOptions][] = [
      ["registry entry", { registryEntry: DOCUMENT_NOT_STRICT_JSON }, { registryEntry: null }, { registryEntry }],
      ["trust registry", { registryEntry, trustRegistry: DOCUMENT_NOT_STRICT_JSON }, { registryEntry, trustRegistry: null }, { registryEntry, trustRegistry }],
    ];
    for (const [label, sentinel, asNull, readable] of cases) {
      const options = { evaluationTime: EVALUATION_TIME };
      const report = verifyBundle(path, { ...options, ...sentinel });
      assert.deepEqual(report, verifyBundle(path, { ...options, ...asNull }), label);
      // The document itself, readable, gives another report: the comparison above is about it.
      assert.notDeepEqual(report, verifyBundle(path, { ...options, ...readable }), label);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
