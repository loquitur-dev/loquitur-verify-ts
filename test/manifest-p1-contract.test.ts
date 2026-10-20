// The manifest and P1 contracts, and the exact form of every digest they carry (bundle-objects.md
// sections 2, 3 and 5). Each row edits one thing in the link fixture bundle, reseals every digest
// the edit touches, and runs through verifyBundle on disk, the in-memory map and the browser
// build. Control rows that pass ride along with the rows that fail.
import { test } from "node:test";
import assert from "node:assert/strict";
import { Bundle, ENTRIES, FAIL, PASS, jcsText, outcome, sha256Hex } from "./bundle-kit.ts";

type Row = [label: string, build: () => Bundle, expected: Record<string, unknown>];

function runRows(rows: Row[]) {
  const got: Record<string, unknown> = {};
  const want: Record<string, unknown> = {};
  for (const [label, build, expected] of rows) {
    const checks = Object.keys(expected).filter((k) => !["status", "verdict", "exit_code"].includes(k));
    for (const [entryName, verify] of ENTRIES) {
      const key = `${entryName}: ${label}`;
      want[key] = expected;
      try {
        got[key] = outcome(verify(build()), checks);
      } catch (err) {
        got[key] = `threw ${(err as Error).name}: ${(err as Error).message}`;
      }
    }
  }
  assert.deepEqual(got, want);
}

const manifestWith = (fn: (m: any) => void) => () => {
  const b = Bundle.linkValid();
  b.edit("manifest.json", fn);
  return b.seal();
};

const UNSUPPORTED = { status: "UNSUPPORTED_VERSION", verdict: null, exit_code: 4 };

test("manifest schema_version is exactly loquitur.bundle.v1; a later well-formed version is unsupported (bundle-objects.md section 2)", () => {
  runRows([
    ["schema_version loquitur.bundle.v1", manifestWith((m) => { m.schema_version = "loquitur.bundle.v1"; }), PASS],
    ["schema_version loquitur.bundle.v2", manifestWith((m) => { m.schema_version = "loquitur.bundle.v2"; }), UNSUPPORTED],
    ["schema_version loquitur.bundle.v999999999", manifestWith((m) => { m.schema_version = "loquitur.bundle.v999999999"; }), UNSUPPORTED],
    ["schema_version loquitur.bundle.v1000000000", manifestWith((m) => { m.schema_version = "loquitur.bundle.v1000000000"; }), FAIL],
    ["schema_version loquitur.bundle.v01", manifestWith((m) => { m.schema_version = "loquitur.bundle.v01"; }), FAIL],
    ["schema_version loquitur.bundle.v0", manifestWith((m) => { m.schema_version = "loquitur.bundle.v0"; }), FAIL],
    ["schema_version bundle-v1", manifestWith((m) => { m.schema_version = "bundle-v1"; }), FAIL],
    ["schema_version LOQUITUR.BUNDLE.V1", manifestWith((m) => { m.schema_version = "LOQUITUR.BUNDLE.V1"; }), FAIL],
    ["schema_version padded", manifestWith((m) => { m.schema_version = " loquitur.bundle.v1"; }), FAIL],
    ["schema_version absent", manifestWith((m) => { delete m.schema_version; }), FAIL],
    ["schema_version 1", manifestWith((m) => { m.schema_version = 1; }), FAIL],
    ["schema_version true", manifestWith((m) => { m.schema_version = true; }), FAIL],
    ["schema_version [..]", manifestWith((m) => { m.schema_version = ["manifest.fixture.v1"]; }), FAIL],
    ["schema_version {..}", manifestWith((m) => { m.schema_version = { v: 1 }; }), FAIL],
    ["schema_version \"\"", manifestWith((m) => { m.schema_version = ""; }), FAIL],
    ["schema_version \"   \"", manifestWith((m) => { m.schema_version = "   "; }), FAIL],
    ["schema_version \"\\u3000\"", manifestWith((m) => { m.schema_version = "\u3000"; }), FAIL],
    ["schema_version \"\\u200b\"", manifestWith((m) => { m.schema_version = "\u200b"; }), FAIL],
  ]);
});

test("manifest bundle_id must be a string", () => {
  runRows([
    ["bundle_id 7", manifestWith((m) => { m.bundle_id = 7; }), FAIL],
    ["bundle_id false", manifestWith((m) => { m.bundle_id = false; }), FAIL],
    ["bundle_id true", manifestWith((m) => { m.bundle_id = true; }), FAIL],
    ["bundle_id {..}", manifestWith((m) => { m.bundle_id = { id: "x" }; }), FAIL],
    ["bundle_id [..]", manifestWith((m) => { m.bundle_id = ["x"]; }), FAIL],
  ]);
});

test("manifest bundle_id must carry a code point outside the whitespace set W; U+200B is outside it", () => {
  const blank = ["", "   ", "\t\n", "\u001f", "\u0085", "\u00a0", "\u1680", "\u2000\u200a", "\u2028", "\u2029", "\u202f",
    "\u205f", "\u3000", "\ufeff"];
  runRows([
    ...blank.map((id): Row => [`bundle_id ${JSON.stringify(id)}`, manifestWith((m) => { m.bundle_id = id; }), FAIL]),
    ["bundle_id \"\\u200b\"", manifestWith((m) => { m.bundle_id = "\u200b"; }), PASS],
    ["bundle_id \"\\u180e\"", manifestWith((m) => { m.bundle_id = "\u180e"; }), PASS],
  ]);
});

/** Change the declared digest of p1.json after sealing, leaving the manifest sidecar consistent. */
const declaredDigest = (fn: (d: string) => string) => () => {
  const b = Bundle.linkValid().seal();
  b.edit("manifest.json", (m) => { m.files["p1.json"] = fn(m.files["p1.json"]); });
  return b.seal({ files: false, p1: false });
};

test("declared file digests are 64 lowercase hex characters, compared exactly", () => {
  runRows([
    ["an upper-case declared digest", declaredDigest((d) => d.toUpperCase()), { ...FAIL, manifest_files: false }],
    ["a padded declared digest", declaredDigest((d) => `  ${d}\n`), { ...FAIL, manifest_files: false }],
    ["a sha256:-prefixed declared digest, twice", declaredDigest((d) => `sha256:${d}`), { ...FAIL, manifest_files: false }],
    ["a bare declared digest", declaredDigest((d) => d.slice("sha256:".length)), { ...FAIL, manifest_files: false }],
    ["an upper-case SHA256: label", declaredDigest((d) => `SHA256:${d.slice("sha256:".length)}`), { ...FAIL, manifest_files: false }],
  ]);
});

test("a manifest may not declare itself or its sidecar, in any letter case", () => {
  runRows([
    ["files naming manifest.json", manifestWith((m) => { m.files["manifest.json"] = "0".repeat(64); }), FAIL],
    ["files naming MANIFEST.JSON", manifestWith((m) => { m.files["MANIFEST.JSON"] = "0".repeat(64); }), FAIL],
    ["files naming manifest.sha256", manifestWith((m) => { m.files["manifest.sha256"] = "0".repeat(64); }), FAIL],
    ["files naming ./manifest.json", manifestWith((m) => { m.files["./manifest.json"] = "0".repeat(64); }), FAIL],
    ["files naming sub/manifest.json, present", () => {
      const b = Bundle.linkValid();
      b.setBytes("sub/manifest.json", "{}");
      b.edit("manifest.json", (m) => { m.files["sub/manifest.json"] = ""; });
      return b.seal();
    }, { ...PASS, manifest_files: true }],
  ]);
});

test("files in list form is not a manifest", () => {
  runRows([["files as [{name, sha256}]", () => {
    const b = Bundle.linkValid().seal();
    b.edit("manifest.json", (m) => { m.files = Object.entries(m.files).map(([name, sha256]) => ({ name, sha256 })); });
    return b.seal({ files: false, p1: false });
  }, FAIL]]);
});

const withIk = (ik: unknown, drop = false) => () => {
  const b = Bundle.linkValid();
  const whole = sha256Hex(jcsText(b.json("canonical_input.json")));
  b.edit("p1.json", (p) => {
    if (drop) delete p.ik;
    else p.ik = ik;
    p.ih = `sha256:${whole}`;
  });
  return b.seal();
};

test("a present ik is a non-empty list of distinct strings; only an absent ik hashes the whole input", () => {
  const ci = Bundle.linkValid().json("canonical_input.json");
  runRows([
    ["ik \"asset_id\"", withIk("asset_id"), { ...FAIL, envelope_links: false }],
    ["ik 42", withIk(42), { ...FAIL, envelope_links: false }],
    ["ik null", withIk(null), { ...FAIL, envelope_links: false }],
    ["ik [\"asset_id\", 42]", withIk(["asset_id", 42]), { ...FAIL, envelope_links: false }],
    ["ik {..}", withIk({ asset_id: 1 }), { ...FAIL, envelope_links: false }],
    ["ik []", withIk([]), { ...FAIL, envelope_links: false }],
    ["ik with a duplicate", () => {
      const b = Bundle.linkValid();
      b.edit("p1.json", (p) => {
        p.ik = ["asset_type", "asset_type"];
        p.ih = `sha256:${sha256Hex(jcsText({ asset_type: ci.asset_type }))}`;
      });
      return b.seal();
    }, { ...FAIL, envelope_links: false }],
    ["ik absent", withIk(undefined, true), { ...PASS, p1_input_hash: true, envelope_links: true }],
  ]);
});

test("ih and the sidecars are exact lowercase digests", () => {
  runRows([
    ["a bare ih", () => {
      const b = Bundle.linkValid();
      b.edit("p1.json", (p) => { p.ih = p.ih.slice("sha256:".length); });
      return b.seal();
    }, { ...FAIL, p1_input_hash: false }],
    ["a sha256:-prefixed p1.sha256", () => {
      const b = Bundle.linkValid().seal();
      b.setBytes("p1.sha256", `sha256:${b.p1Digest()}`);
      return b.seal({ p1: false });
    }, { ...FAIL, p1_sha256: false }],
    ["an upper-case ih", () => {
      const b = Bundle.linkValid();
      b.edit("p1.json", (p) => { p.ih = p.ih.toUpperCase(); });
      return b.seal();
    }, { ...FAIL, p1_input_hash: false }],
    ["an upper-case manifest.sha256", () => {
      const b = Bundle.linkValid().seal();
      return b.setBytes("manifest.sha256", b.manifestDigest().toUpperCase());
    }, { ...FAIL, manifest_sha256: false }],
    ["a newline after p1.sha256", () => {
      const b = Bundle.linkValid().seal();
      b.setBytes("p1.sha256", `${b.p1Digest()}\n`);
      return b.seal({ p1: false });
    }, { ...FAIL, p1_sha256: false }],
    ["an upper-case envelope.sha256", () => {
      const b = Bundle.linkValid().seal();
      return b.setBytes("envelope.sha256", sha256Hex(jcsText(b.json("envelope_env1.json"))).toUpperCase());
    }, { ...FAIL, envelope_sha256: false }],
  ]);
});

/** A P1 whose canonical form is exactly `size` bytes, with ih correct for its projection. */
const p1OfSize = (size: number) => () => {
  const b = Bundle.linkValid();
  const p1 = b.json("p1.json");
  const base = jcsText({ ...p1, ik: [...p1.ik, "k"] }).length;
  b.edit("p1.json", (p) => {
    p.ik = [...p.ik, "k" + "x".repeat(size - base)];
    p.ih = b.inputHashFor(p);
  });
  assert.equal(jcsText(b.json("p1.json")).length, size);
  return b.seal();
};

test("canonical P1 is at most 1024 bytes", () => {
  runRows([
    ["P1 of 1024 bytes", p1OfSize(1024), { ...PASS, p1_sha256: true }],
    ["P1 of 1025 bytes", p1OfSize(1025), { ...FAIL, p1_sha256: false, p1_input_hash: false }],
  ]);
});

test("the manifest nonce is 64 lowercase hex characters (bundle-objects.md section 2)", () => {
  runRows([
    ["nonce of the fixture", manifestWith(() => {}), PASS],
    ["nonce absent", manifestWith((m) => { delete m.nonce; }), FAIL],
    ["nonce upper-case", manifestWith((m) => { m.nonce = m.nonce.toUpperCase().replace(/[0-9]/g, "A"); }), FAIL],
    ["nonce of 63 characters", manifestWith((m) => { m.nonce = m.nonce.slice(1); }), FAIL],
    ["nonce of 65 characters", manifestWith((m) => { m.nonce = `${m.nonce}0`; }), FAIL],
    ["nonce not hex", manifestWith((m) => { m.nonce = "g".repeat(64); }), FAIL],
    ["nonce a number", manifestWith((m) => { m.nonce = 7; }), FAIL],
    ["nonce null", manifestWith((m) => { m.nonce = null; }), FAIL],
  ]);
});
