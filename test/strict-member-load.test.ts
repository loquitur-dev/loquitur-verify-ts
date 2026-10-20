// Every bundle JSON member, and the registry entry and trust registry a host passes in, is loaded
// strictly (canonicalization-and-hashing.md, "Input strictness"): exact bytes decoded as UTF-8 with
// fatal errors and the BOM kept, no duplicate member names, nesting at most 64 levels, and
// input-strictness rules 2 to 4 (canonicalization-and-hashing.md) over the whole document,
// projected or not, member names included. A member that fails is present but invalid: its check is
// false and the run fails. Nothing a bundle carries makes the verifier throw.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  Bundle, ENTRIES, FAIL, JsonText, PASS, VECTORS_DIR, jcsText, linkEntryFor, outcome, sha256Hex, verifyOnDisk, verifyWithByteReader,
} from "./bundle-kit.ts";

const BYTE_ENTRIES: Array<[string, (b: Bundle, o?: any) => any]> = [["fs", verifyOnDisk], ["byte-reader", verifyWithByteReader]];
const utf8 = new TextEncoder();

function expectEach(entries: typeof BYTE_ENTRIES, build: () => Bundle, expected: Record<string, unknown>, opts?: () => object) {
  const failures: string[] = [];
  for (const [entryName, verify] of entries) {
    let got: Record<string, unknown>;
    try {
      got = outcome(verify(build(), opts?.()), Object.keys(expected).filter((k) => !["status", "verdict", "exit_code"].includes(k)));
    } catch (err) {
      failures.push(`${entryName}: threw ${(err as Error).name}: ${(err as Error).message}`);
      continue;
    }
    try {
      assert.deepEqual(got, expected);
    } catch {
      failures.push(`${entryName}: ${JSON.stringify(got)}`);
    }
  }
  assert.deepEqual(failures, [], `expected ${JSON.stringify(expected)}`);
}

/** Replace the bytes of `text` inside a member with `bytes`, after the bundle was sealed. */
function spliceBytes(b: Bundle, name: string, text: string, bytes: number[]): Bundle {
  const data = b.bytes(name);
  const needle = utf8.encode(text);
  let at = -1;
  for (let i = 0; i + needle.length <= data.length && at < 0; i++) {
    if (needle.every((v, j) => data[i + j] === v)) at = i;
  }
  assert.ok(at >= 0, `${text} not found in ${name}`);
  return b.setBytes(name, new Uint8Array([...data.slice(0, at), ...bytes, ...data.slice(at + needle.length)]));
}

/** The member re-serialized with `key` carrying the raw JSON text `valueText`. */
function withRawMember(b: Bundle, name: string, key: string, valueText: string): Bundle {
  const obj = b.json(name);
  delete obj[key];
  const body = jcsText(obj);
  return b.setBytes(name, `${body.slice(0, -1)}${body === "{}" ? "" : ","}${JSON.stringify(key)}:${valueText}}`);
}

/** canonical_input.json with a strict-rule value under `key`, then resealed. */
function inputCase(key: string, valueText: string, mode: "projected" | "unprojected" | "no-ik"): () => Bundle {
  return () => {
    const b = Bundle.linkValid();
    const original = b.json("canonical_input.json");
    withRawMember(b, "canonical_input.json", key, valueText);
    if (mode === "no-ik") {
      b.edit("p1.json", (p) => { delete p.ik; });
    } else if (mode === "unprojected") {
      // The value sits outside the projection and ih covers what remains, so the strictness
      // violation is the only thing wrong with the bundle.
      b.edit("p1.json", (p) => {
        p.ik = p.ik.filter((k: string) => k !== key);
        const payload: Record<string, unknown> = {};
        for (const k of p.ik) payload[k] = k in original ? original[k] : null;
        p.ih = `sha256:${sha256Hex(jcsText(payload))}`;
      });
    }
    return b.seal();
  };
}

const INPUT_REJECTED = { ...FAIL, canonical_input_present: true, p1_input_hash: false };
const MANIFEST_REJECTED = { ...FAIL, manifest_sha256: false, manifest_files: false };
const ENVELOPE_REJECTED = { ...FAIL, envelope_present: true, envelope_sha256: false, envelope_links: false };

const nested = (depth: number) => "[".repeat(depth) + "0" + "]".repeat(depth);

// ---------------------------------------------------------------- invalid UTF-8 and the BOM
test("invalid UTF-8 in manifest.json is refused, not repaired to U+FFFD", () => {
  expectEach(BYTE_ENTRIES, () => {
    const b = Bundle.linkValid();
    b.edit("manifest.json", (m) => { m.schema_version = "manifest.fixture.v1\uFFFD"; });
    return spliceBytes(b.seal(), "manifest.json", "\uFFFD", [0xff]);
  }, { ...MANIFEST_REJECTED, envelope_links: false });
});

test("invalid UTF-8 in canonical_input.json is a rejected input, not an absent one", () => {
  expectEach(BYTE_ENTRIES, () => spliceBytes(Bundle.linkValid().seal(), "canonical_input.json", "asset-private-001", [...utf8.encode("asset-private-"), 0xc3, 0x28])
    .seal({ p1: false }), INPUT_REJECTED);
});

test("invalid UTF-8 in p1.json fails the P1 checks and the envelope links", () => {
  expectEach(BYTE_ENTRIES, () => {
    // An ik key spelled with U+FFFD, every digest taken over that spelling, then the character
    // replaced by the invalid byte a lenient decoder turns back into it. Only the encoding is
    // wrong.
    const b = Bundle.linkValid();
    b.edit("p1.json", (p) => {
      p.ik = [...p.ik, "k\uFFFD"];
      p.ih = b.inputHashFor(p);
    });
    return spliceBytes(b.seal(), "p1.json", "\uFFFD", [0xff]).seal({ p1: false });
  }, { ...FAIL, p1_sha256: false, p1_input_hash: false, envelope_links: false });
});

test("invalid UTF-8 in the envelope fails the envelope checks", () => {
  expectEach(BYTE_ENTRIES, () => {
    const b = Bundle.linkValid().seal();
    b.edit("envelope_env1.json", (v) => { v.asset_id = "asset\uFFFD"; });
    b.setBytes("envelope.sha256", sha256Hex(jcsText(b.json("envelope_env1.json"))));
    return spliceBytes(b, "envelope_env1.json", "\uFFFD", [0xff]);
  }, ENVELOPE_REJECTED);
});

test("a UTF-8 BOM before manifest.json is refused", () => {
  expectEach(BYTE_ENTRIES, () => {
    const b = Bundle.linkValid().seal();
    return b.setBytes("manifest.json", new Uint8Array([0xef, 0xbb, 0xbf, ...b.bytes("manifest.json")]));
  }, MANIFEST_REJECTED);
});

// ---------------------------------------------------------------- rules 2 to 4 in canonical_input.json
const STRICT_INPUT_ROWS: Array<[string, () => Bundle]> = [
  ["1e400 in a projected member", inputCase("external_mark", "1e400", "projected")],
  ["-1e400 in a projected member", inputCase("external_mark", "-1e400", "projected")],
  ["1e400 outside the projection", inputCase("external_mark", "1e400", "unprojected")],
  ["9007199254740993 in a projected member", inputCase("external_mark", "9007199254740993", "projected")],
  ["1e16 outside the projection", inputCase("external_mark", "1e16", "unprojected")],
  ["9007199254740992.0 in a projected member", inputCase("external_mark", "9007199254740992.0", "projected")],
  ["a lone surrogate in a projected value", inputCase("currency", '"\\ud800"', "projected")],
  ["a lone surrogate in a member name, no ik", inputCase("\udc00x", "1", "no-ik")],
];
for (const [label, build] of STRICT_INPUT_ROWS) {
  test(`canonical_input.json with ${label} fails, in every entry`, () => {
    expectEach(ENTRIES, build, INPUT_REJECTED);
  });
}

test("2^53-1 and a surrogate pair are inside the rules and pass; 2^53+1 is not", () => {
  const safe = () => {
    const b = Bundle.linkValid();
    b.edit("canonical_input.json", (c) => { c.external_mark = 9007199254740991; c.currency = "EUR\u{1F600}"; });
    b.edit("p1.json", (p) => { p.ih = b.inputHashFor(p); });
    return b.seal();
  };
  expectEach(ENTRIES, safe, { ...PASS, p1_input_hash: true });
  expectEach(ENTRIES, inputCase("external_mark", "9007199254740993", "projected"), INPUT_REJECTED);
});

// ---------------------------------------------------------------- manifest and envelope metadata
for (const [label, valueText] of [["1e400", "1e400"], ["9007199254740993", "9007199254740993"], ["a lone surrogate", '"\\ud800"'], ["600 levels of nesting", nested(600)]] as Array<[string, string]>) {
  test(`manifest.json carrying ${label} fails its checks without throwing`, () => {
    expectEach(ENTRIES, () => withRawMember(Bundle.linkValid().seal(), "manifest.json", "schema_version", valueText), MANIFEST_REJECTED);
  });
  test(`an envelope carrying ${label} fails its checks without throwing`, () => {
    expectEach(ENTRIES, () => withRawMember(Bundle.linkValid().seal(), "envelope_env1.json", "asset_id", valueText), ENVELOPE_REJECTED);
  });
}

test("a lone surrogate in a manifest.files member name fails the manifest without throwing", () => {
  expectEach(ENTRIES, () => {
    const b = Bundle.linkValid().seal();
    const text = new TextDecoder().decode(b.bytes("manifest.json")).replace('"p1.sha256":', `"\\udc00.txt":"${"0".repeat(64)}","p1.sha256":`);
    return b.setBytes("manifest.json", text);
  }, MANIFEST_REJECTED);
});

// ---------------------------------------------------------------- depth 64
function deepInput(depth: number, projected: boolean): () => Bundle {
  return () => {
    const b = Bundle.linkValid();
    const body = jcsText(b.json("canonical_input.json"));
    // `deep` sits at depth 1 inside the object, so `depth - 1` brackets make the document `depth`
    // deep.
    b.setBytes("canonical_input.json", `${body.slice(0, -1)},"deep":${nested(depth - 1)}}`);
    b.edit("p1.json", (p) => {
      if (projected) p.ik = [...p.ik, "deep"];
      p.ih = b.inputHashFor(p);
    });
    return b.seal();
  };
}

test("a canonical input 64 levels deep passes, 65 levels fails, projected or not", () => {
  expectEach(ENTRIES, deepInput(64, true), { ...PASS, p1_input_hash: true });
  expectEach(ENTRIES, deepInput(65, true), INPUT_REJECTED);
  expectEach(ENTRIES, deepInput(65, false), INPUT_REJECTED);
});

test("a canonical input 500 levels deep fails", () => {
  expectEach(ENTRIES, deepInput(500, true), INPUT_REJECTED);
});

test("a canonical input 20000 levels deep fails rather than counting as absent", () => {
  expectEach(ENTRIES, () => {
    const b = Bundle.linkValid();
    b.setBytes("canonical_input.json", `{"asset_type":"property","deep":${nested(20000)}}`);
    return b.seal();
  }, INPUT_REJECTED);
});

// ---------------------------------------------------------------- host documents
test("a registry entry breaking the strictness rules fails the registry link", () => {
  const withSystem = (system: string) => () => {
    const b = Bundle.linkValid().seal();
    return { registryEntry: linkEntryFor(b, { anchor: { anchor_reference: "ref", method: "blockchain_transaction", system } }) };
  };
  // The control: the same anchor with a well-formed system string links.
  expectEach(ENTRIES, () => Bundle.linkValid().seal(), { ...PASS, registry_link: true }, withSystem("mainnet"));
  expectEach(ENTRIES, () => Bundle.linkValid().seal(), { ...FAIL, registry_link: false }, withSystem("main\ud800net"));
  for (const depth of [65, 20000]) {
    const deep = () => {
      const text = JSON.stringify(linkEntryFor(Bundle.linkValid().seal()));
      return { registryEntry: new JsonText(`${text.slice(0, -1)},"x":${nested(depth - 1)}}`) };
    };
    expectEach(ENTRIES, () => Bundle.linkValid().seal(), { ...FAIL, registry_link: false }, deep);
  }
});

test("a trust registry nested 20000 levels deep fails the trust check instead of throwing", () => {
  const trust = () => {
    const t = JSON.parse(readFileSync(join(VECTORS_DIR, "authorization_valid_trust_registry.json"), "utf8"));
    t.entries[0].notes = "NOTES";
    return new JsonText(JSON.stringify(t).replace('"NOTES"', nested(20000)));
  };
  expectEach(ENTRIES, () => Bundle.linkValid().seal(), { ...FAIL, trust_registry: false }, () => {
    const b = Bundle.linkValid().seal();
    return { registryEntry: linkEntryFor(b), trustRegistry: trust() };
  });
});

// ---------------------------------------------------------------- containment
const HOSTILE_TEXTS = [
  "", "{", "[", "]", "}", "nul", "\"x", "{\"a\":1,\"a\":2}", "1e400", "-1e400", "9007199254740993", "\"\\ud800\"",
  "{\"\\udc00\":1}", "[".repeat(100000), "{\"a\":".repeat(30000), nested(3000), "{\"s\":\"env1\",\"v\":1e400}",
  "{\"s\":\"p1\",\"v\":1,\"ih\":" + nested(2000) + "}", "{\"files\":{\"x\":" + nested(2000) + "}}", "\u0000", "{}",
];
const HOSTILE_MEMBERS = ["manifest.json", "p1.json", "envelope_env1.json", "envelope.json", "verification_receipt.json",
  "manifest.sha256", "p1.sha256", "envelope.sha256"];

test("no hostile member content makes verifyBundleFiles throw", () => {
  const thrown: string[] = [];
  for (const name of HOSTILE_MEMBERS) {
    for (const text of HOSTILE_TEXTS) {
      for (const bytes of [utf8.encode(text), new Uint8Array([0xef, 0xbb, 0xbf, ...utf8.encode(text)]), new Uint8Array([0xff, ...utf8.encode(text)])]) {
        const b = Bundle.linkValid().seal();
        const entry = linkEntryFor(b);
        b.setBytes(name, bytes);
        for (const [entryName, verify] of [["byte-reader", verifyWithByteReader], ENTRIES[1]!] as const) {
          for (const opts of [{}, { registryEntry: entry }]) {
            try {
              const report = verify(b, opts);
              if (![0, 1, 2].includes(report.exit_code)) thrown.push(`${entryName} ${name} ${JSON.stringify(text.slice(0, 20))}: exit ${report.exit_code}`);
            } catch (err) {
              thrown.push(`${entryName} ${name} ${JSON.stringify(text.slice(0, 20))}: ${(err as Error).name}`);
            }
          }
        }
      }
    }
  }
  assert.deepEqual(thrown.slice(0, 20), []);
});
