// The link check, held to loquitur-protocol docs/specification/registry-link.md.
//
// The specification states the link check as tables: the entry's grounds (section 2), the
// comparisons (section 3), the exact spellings each comparison reads (section 4), the three values
// of the link result (section 5) and the effect of the committed verdict (section 6). Every row is
// read from the sibling checkout and run through the three entries (fs, map, browser build) over a
// sealed copy of the link test bundle. This verifier reports status, verdict, exit code and checks,
// so the rows are asserted on those; the Python verifier's suite asserts the same tables on its
// reason surface too.
import { test } from "node:test";
import assert from "node:assert/strict";
import { Bundle, ENTRIES, FAIL, PASS, REVIEW, ephemeralAuthorizationWith, linkEntryFor, outcome } from "./bundle-kit.ts";
import { MAX_MEMBER_BYTES } from "../src/verify-core.ts";
import { code, readSpecification, specification, table } from "./spec-tables.ts";

const DOCUMENT = "registry-link.md";
const SPEC = specification(DOCUMENT);
const RECEIPT_STATUS: Record<string, string> = { PASS: "pass", WARN: "warning", REVIEW: "review", FAIL: "fail" };
const GROUNDS: Record<string, string[]> = {
  PASS: ["INTEGRITY_OK"],
  WARN: ["INTEGRITY_OK", "FRESHNESS_WARNING"],
  REVIEW: ["INTEGRITY_OK", "NEEDS_REVIEW"],
  FAIL: ["INTEGRITY_OK", "INTEGRITY_OFFLINE_FAIL"],
};

type Case = { bundle: Bundle; entry: Record<string, unknown> | unknown[] | null | undefined };

/** The sealed link bundle and a bound entry, the receipt and the entry each changed as given. */
function linkRun(changes: { receipt?: (r: any) => void; rawReceipt?: [string, string]; entry?: (e: any) => void; bundle?: (b: Bundle) => void } = {}): Case {
  const bundle = Bundle.linkValid();
  if (changes.receipt) bundle.edit("verification_receipt.json", changes.receipt);
  changes.bundle?.(bundle);
  bundle.seal();
  if (changes.rawReceipt) {
    const [key, text] = changes.rawReceipt;
    const receipt = bundle.json("verification_receipt.json");
    delete receipt[key];
    const body = JSON.stringify(receipt);
    bundle.setBytes("verification_receipt.json", `${body.slice(0, -1)},${JSON.stringify(key)}:${text}}`);
  }
  const entry = linkEntryFor(bundle);
  changes.entry?.(entry);
  return { bundle, entry };
}

function grounded(verdict: string, reasonCodes: string[]): Case {
  return linkRun({
    receipt: (r) => { r.status = RECEIPT_STATUS[verdict]; r.reason_codes = reasonCodes; },
    entry: (e) => { e.verdict = verdict; e.reason_codes = reasonCodes; },
  });
}

for (const [entryName, verify] of ENTRIES) {
  const run = (c: Case, checks = ["registry_link"]) =>
    outcome(verify(c.bundle, c.entry === undefined ? {} : { registryEntry: c.entry }), checks);

  test(`${entryName}: the grounds table of registry-link.md section 2`, SPEC.options, () => {
    const rows = table(readSpecification(SPEC, DOCUMENT), ["verdict", "reason codes", "grounds hold"]);
    const got: Record<string, unknown> = {};
    const expected: Record<string, unknown> = {};
    for (const row of rows) {
      const verdict = code(row["verdict"]!);
      const reasonCodes = JSON.parse(code(row["reason codes"]!)) as string[];
      const holds = row["grounds hold"] === "yes";
      const label = `${verdict} ${reasonCodes.join(",")}`;
      got[label] = run(grounded(verdict, reasonCodes));
      const committed = { PASS, WARN: REVIEW, REVIEW, FAIL }[verdict as "PASS"]!;
      expected[label] = holds ? { ...committed, registry_link: true } : { ...FAIL, registry_link: false };
    }
    assert.deepEqual(got, expected);
  });

  // Section 2: issuer_key_id and policy_id are not empty under the whitespace set W, at the link
  // and authorization checks alike. A value made only of W satisfies the schema's minLength and
  // names nothing: the entry breaks its contract, the link does not hold and no trust registry is
  // read beside it.
  test(`${entryName}: an entry names a key and a policy, registry-link.md section 2`, SPEC.options, () => {
    const rows = table(readSpecification(SPEC, DOCUMENT), ["member", "value", "contract holds"]);
    assert.deepEqual(
      new Set(rows.map((row) => code(row["member"]!))),
      new Set(["issuer_key_id", "policy_id", "signature.key_id", "anchor.system", "anchor.anchor_reference"]),
    );
    assert.deepEqual(new Set(rows.map((row) => row["contract holds"])), new Set(["yes", "no"]));
    const got: Record<string, unknown> = {};
    const expected: Record<string, unknown> = {};
    for (const row of rows) {
      const member = code(row["member"]!);
      const value = JSON.parse(code(row["value"]!)) as string;
      const holds = row["contract holds"] === "yes";
      const entry = (e: any) => {
        if (member.startsWith("anchor.")) {
          // The anchor is outside the signing payload; a complete one carries the value.
          e.anchor = { method: "blockchain_transaction", system: "testnet", anchor_reference: "tx-1" };
          e.anchor[member.slice("anchor.".length)] = value;
          return;
        }
        if (member === "signature.key_id") {
          // The link fixture carries no signature; the rule reads the object when present.
          if (e.signature === null || typeof e.signature !== "object") {
            e.signature = { algorithm: "secp256k1_ecdsa_sha256", key_id: e.issuer_key_id, payload_id: "registry_entry_signing_payload_v2", payload_version: 2, signature: "0".repeat(128) };
          }
          e.signature.key_id = value;
          return;
        }
        e[member] = value;
        if (member === "issuer_key_id" && e.signature !== null && typeof e.signature === "object") e.signature.key_id = value;
      };
      // The receipt's policy_id follows the entry's where the row holds, so the comparison holds
      // too; where it does not hold, the receipt keeps its own (such a receipt breaks its own
      // contract).
      const receipt = member === "policy_id" && holds ? (r: any) => { r.policy_id = value; } : undefined;
      const atLink = linkRun({ receipt, entry });
      const atAuthorization = ephemeralAuthorizationWith(atLink.bundle, {
        entry,
        trust: member === "issuer_key_id" ? (t: any) => { t.entries[0].issuer_key_id = value; } : undefined,
      });
      const label = `${member} ${JSON.stringify(value)}`;
      got[label] = [run(atLink), outcome(verify(atLink.bundle, atAuthorization), ["registry_link", "trust_registry"])];
      expected[label] = holds
        ? [{ ...PASS, registry_link: true }, { ...REVIEW, registry_link: true, trust_registry: true }]
        : [{ ...FAIL, registry_link: false }, { ...FAIL, registry_link: false, trust_registry: null }];
    }
    assert.deepEqual(got, expected);
  });

  test(`${entryName}: each comparison of registry-link.md section 3 fails the link on its own`, SPEC.options, () => {
    const rows = table(readSpecification(SPEC, DOCUMENT), ["check", "hard", "registry-entry operand", "other operand", "holds when"]);
    // Another digest, spelled as every digest of a JSON document is (registry-link.md section 4).
    const other = "0".repeat(64);
    const onlyThisCheck: Record<string, Case> = {
      registry_entry_contract: linkRun({ entry: (e) => { e.smuggled = "x"; } }),
      verification_receipt_contract: linkRun({ receipt: (r) => { r.smuggled = "x"; } }),
      manifest_hash: linkRun({ entry: (e) => { e.manifest_hash = `sha256:${other}`; } }),
      receipt_manifest_sha256: linkRun({ rawReceipt: ["manifest_sha256", JSON.stringify(`sha256:${other}`)] }),
      receipt_hash: linkRun({ entry: (e) => { e.receipt_hash = `sha256:${other}`; } }),
      receipt_bundle_id: linkRun({ receipt: (r) => { r.bundle_id = "another_bundle"; } }),
      receipt_p1_sha256: linkRun({ rawReceipt: ["p1_sha256", JSON.stringify(`sha256:${other}`)] }),
      policy_id: linkRun({ receipt: (r) => { r.policy_id = "loquitur.policy.other"; } }),
      policy_version: linkRun({ receipt: (r) => { r.policy_version = 2; } }),
      reason_code_catalog_version: linkRun({ entry: (e) => { e.reason_code_catalog_version = "other.v1"; } }),
      reason_codes: linkRun({ receipt: (r) => { r.reason_codes = ["INTEGRITY_OK", "FRESHNESS_OK"]; } }),
      asset_type: linkRun({ receipt: (r) => { r.asset_type = "fund_nav"; } }),
      status_verdict: linkRun({ receipt: (r) => { r.status = "review"; } }),
    };
    assert.deepEqual(rows.map((row) => code(row["check"]!)).sort(), Object.keys(onlyThisCheck).sort());
    const got = Object.fromEntries(Object.entries(onlyThisCheck).map(([name, c]) => [name, run(c)]));
    assert.deepEqual(got, Object.fromEntries(Object.keys(onlyThisCheck).map((name) => [name, { ...FAIL, registry_link: false }])));
    assert.deepEqual(run(linkRun()), { ...PASS, registry_link: true });
  });

  test(`${entryName}: the spelling cases of registry-link.md section 4`, SPEC.options, () => {
    const rows = table(readSpecification(SPEC, DOCUMENT), ["case", "field", "registry entry", "receipt", "link holds"]);
    const digest = Bundle.linkValid().seal().manifestDigest();
    const LONG_MAJOR = "`\"1\"` followed by 4400 `\"0\"`, then `\".0.0\"`";
    const value = (cell: string) => {
      if (cell === "none") return undefined;
      if (cell === LONG_MAJOR) return `1${"0".repeat(4400)}.0.0`;
      return JSON.parse(code(cell).replace("<manifest digest>", digest).replace("<MANIFEST DIGEST>", digest.toUpperCase()));
    };
    const raw = (cell: string) => code(cell).replace("<manifest digest>", digest);
    const got: Record<string, unknown> = {};
    const expected: Record<string, unknown> = {};
    for (const row of rows) {
      const name = code(row["case"]!);
      const field = code(row["field"]!);
      const entryValue = value(row["registry entry"]!);
      let c: Case;
      if (field === "status") {
        const status = JSON.parse(code(row["receipt"]!));
        const reasonCodes = GROUNDS[entryValue] ?? ["INTEGRITY_OK"];
        c = linkRun({
          receipt: (r) => { r.status = status; r.reason_codes = reasonCodes; },
          entry: (e) => { e.verdict = entryValue; e.reason_codes = reasonCodes; },
        });
      } else if (field === "manifest_hash") {
        assert.equal(row["receipt"], "none", name);
        c = linkRun({ entry: (e) => { e.manifest_hash = entryValue; } });
      } else if (entryValue === undefined) {
        // A receipt member the entry does not carry: only the receipt is changed.
        c = linkRun({ rawReceipt: [field, raw(row["receipt"]!)] });
      } else {
        c = linkRun({ rawReceipt: [field, raw(row["receipt"]!)], entry: (e) => { e[field] = entryValue; } });
      }
      got[name] = verify(c.bundle, { registryEntry: c.entry }).checks.registry_link;
      expected[name] = row["link holds"] === "yes";
    }
    assert.deepEqual(got, expected);
  });

  test(`${entryName}: the three values of the link result, registry-link.md section 5`, SPEC.options, () => {
    const rows = table(readSpecification(SPEC, DOCUMENT), ["`registry_link`", "when"]);
    assert.deepEqual(rows.map((row) => row["`registry_link`"]), ["`null`", "`false`", "`true`"]);
    const noReceipt = linkRun({ bundle: (b) => { b.delete("verification_receipt.json"); } });
    const got = {
      null: [run({ ...linkRun(), entry: undefined }), run(noReceipt)],
      false: [
        run({ ...linkRun(), entry: null }),
        run(linkRun({ rawReceipt: ["policy_version", '"1"'] })),
        run(linkRun({ entry: (e) => { e.verdict = "BANANA"; } })),
        run(linkRun({ receipt: (r) => { r.policy_id = "another"; } })),
      ],
      true: [run(linkRun())],
    };
    assert.deepEqual(got, {
      // A bundle without a receipt has nothing to link: not established, a question (section 5).
      null: [{ ...PASS, registry_link: null }, { ...REVIEW, registry_link: null }],
      false: Array(4).fill({ ...FAIL, registry_link: false }),
      true: [{ ...PASS, registry_link: true }],
    });
  });

  test(`${entryName}: the rows of the link result are read in order, registry-link.md section 5`, SPEC.options, () => {
    assert.match(readSpecification(SPEC, DOCUMENT).replace(/\s+/g, " "), /the first whose condition holds gives the value/);
    const noReceipt = (changes: Parameters<typeof linkRun>[0] = {}) =>
      linkRun({ ...changes, bundle: (b) => { b.delete("verification_receipt.json"); } });
    const got = {
      "bundle alone, receipt breaks its contract": run({ ...linkRun({ rawReceipt: ["policy_version", '"1"'] }), entry: undefined }),
      "entry JSON null, no receipt": run({ ...noReceipt(), entry: null }),
      "entry an array, no receipt": run({ ...noReceipt(), entry: [] }),
      "entry breaks its contract, no receipt": run(noReceipt({ entry: (e) => { e.verdict = "BANANA"; } })),
    };
    // An entry document that is not an object is refused whatever the bundle carries; an entry
    // object beside no receipt is not compared with anything, and the run is the question of the
    // receipt it lacks.
    assert.deepEqual(got, {
      "bundle alone, receipt breaks its contract": { ...FAIL, registry_link: null },
      "entry JSON null, no receipt": { ...FAIL, registry_link: null },
      "entry an array, no receipt": { ...FAIL, registry_link: null },
      "entry breaks its contract, no receipt": { ...REVIEW, registry_link: null },
    });
  });

  test(`${entryName}: the committed verdict, registry-link.md section 6`, SPEC.options, () => {
    const rows = table(readSpecification(SPEC, DOCUMENT), ["entry verdict", "effect on the run"]);
    const effect: Record<string, object> = { "none": PASS, "at least `OFFLINE_REVIEW`": REVIEW, "`OFFLINE_FAIL`": FAIL };
    const got: Record<string, unknown> = {};
    const expected: Record<string, unknown> = {};
    for (const row of rows) {
      const verdict = code(row["entry verdict"]!);
      got[verdict] = run(grounded(verdict, GROUNDS[verdict]!));
      expected[verdict] = { ...effect[row["effect on the run"]!], registry_link: true };
    }
    assert.deepEqual(Object.keys(got).sort(), Object.keys(RECEIPT_STATUS).sort());
    assert.deepEqual(got, expected);
  });

  test(`${entryName}: a trust registry beside a link that does not hold reaches no conclusion, section 7`, SPEC.options, () => {
    assert.match(readSpecification(SPEC, DOCUMENT).replace(/\s+/g, " "), /the trust registry reaches no conclusion/);
    const checks = ["registry_link", "trust_registry", "registry_signature"];
    const got: Record<string, unknown> = {};
    for (const [label, changes] of Object.entries({
      "entry-contract": { entry: (e: any) => { e.smuggled = "x"; } },
      "link-does-not-hold": { afterSigning: (e: any) => { e.policy_id = "another"; } },
    })) {
      const bundle = Bundle.linkValid().seal();
      const material = ephemeralAuthorizationWith(bundle, changes);
      got[label] = outcome(verify(bundle, material), checks);
    }
    const bundle = Bundle.linkValid().seal();
    got["trust-registry-without-entry"] = outcome(verify(bundle, { trustRegistry: ephemeralAuthorizationWith(bundle).trustRegistry }), checks);
    const refused = { ...FAIL, trust_registry: null, registry_signature: "UNSUPPORTED" };
    assert.deepEqual(got, {
      "entry-contract": { ...refused, registry_link: false },
      "link-does-not-hold": { ...refused, registry_link: false },
      "trust-registry-without-entry": { ...refused, registry_link: null },
    });
  });

  test(`${entryName}: the manifest digest is recomputed, not read from the sidecar, section 4`, SPEC.options, () => {
    const sidecars: Record<string, Uint8Array | string | null> = {
      "another-digest": "a".repeat(64),
      "sixty-five-characters": "0".repeat(65),
      "not-utf-8": new Uint8Array(64).fill(0xff),
      absent: null,
    };
    if (entryName === "fs") sidecars["over-the-bound"] = "0".repeat(MAX_MEMBER_BYTES + 1);
    const got: Record<string, unknown> = {};
    for (const [label, sidecar] of Object.entries(sidecars)) {
      const c = linkRun();
      if (sidecar === null) c.bundle.delete("manifest.sha256");
      else c.bundle.setBytes("manifest.sha256", sidecar);
      got[label] = run(c, ["manifest_sha256", "registry_link"]);
    }
    const mismatch = { ...FAIL, manifest_sha256: false, registry_link: true };
    assert.deepEqual(got, {
      ...Object.fromEntries(Object.keys(sidecars).map((label) => [label, mismatch])),
      absent: { ...FAIL, manifest_sha256: false, registry_link: false },
    });
  });
}
