// The envelope's three links, its selection and its form (bundle-objects.md sections 2 and 4). A
// link member that is present but malformed is a failed link, never "no link"; nothing is trimmed
// or case-folded; bundle_id is a string compared exactly; envelope_env1.json is the only envelope
// name, and an envelope without its sidecar, or a sidecar without its envelope, is
// envelope_incomplete.
import { test } from "node:test";
import assert from "node:assert/strict";
import { Bundle, ENTRIES, FAIL, PASS, REVIEW, jcsText, outcome, sha256Hex } from "./bundle-kit.ts";

type Row = [label: string, build: () => Bundle, expected: Record<string, unknown>];

function runRows(rows: Row[]) {
  const got: Record<string, unknown> = {};
  const want: Record<string, unknown> = {};
  for (const [label, build, expected] of rows) {
    const checks = Object.keys(expected).filter((k) => !["status", "verdict", "exit_code"].includes(k));
    for (const [entryName, verify] of ENTRIES) {
      want[`${entryName}: ${label}`] = expected;
      try {
        got[`${entryName}: ${label}`] = outcome(verify(build()), checks);
      } catch (err) {
        got[`${entryName}: ${label}`] = `threw ${(err as Error).name}`;
      }
    }
  }
  assert.deepEqual(got, want);
}

/** Seal the fixture (optionally after a manifest edit), then change the envelope and reseal only its sidecar. */
const envelopeWith = (fn: (v: any) => void, manifest?: (m: any) => void) => () => {
  const b = Bundle.linkValid();
  if (manifest) b.edit("manifest.json", manifest);
  b.seal();
  b.edit("envelope_env1.json", fn);
  return b.setBytes("envelope.sha256", sha256Hex(jcsText(b.json("envelope_env1.json"))));
};
const LINK_FAILED = { ...FAIL, envelope_sha256: true, envelope_links: false };

test("a malformed link member is a failed link", () => {
  runRows([
    ["bundle_manifest_sha256 \"not-a-digest\"", envelopeWith((v) => { v.bundle_manifest_sha256 = "not-a-digest"; }), LINK_FAILED],
    ["p1_sha256 {}", envelopeWith((v) => { v.p1_sha256 = {}; }), LINK_FAILED],
    ["bundle_manifest_sha256 false", envelopeWith((v) => { v.bundle_manifest_sha256 = false; }), LINK_FAILED],
    ["bundle_manifest_sha256 sha256:-prefixed twice", envelopeWith((v) => { v.bundle_manifest_sha256 = `sha256:${v.bundle_manifest_sha256}`; }), LINK_FAILED],
    ["a bare bundle_manifest_sha256", envelopeWith((v) => { v.bundle_manifest_sha256 = v.bundle_manifest_sha256.slice("sha256:".length); }), LINK_FAILED],
    ["a bare p1_sha256", envelopeWith((v) => { v.p1_sha256 = v.p1_sha256.slice("sha256:".length); }), LINK_FAILED],
    ["an upper-case SHA256: label", envelopeWith((v) => { v.p1_sha256 = `SHA256:${v.p1_sha256.slice("sha256:".length)}`; }), LINK_FAILED],
    ["all three links malformed", envelopeWith((v) => { v.bundle_id = 7; v.bundle_manifest_sha256 = "x"; v.p1_sha256 = []; }), LINK_FAILED],
  ]);
});

test("envelope link digests are compared as written", () => {
  runRows([
    ["an upper-case p1_sha256", envelopeWith((v) => { v.p1_sha256 = v.p1_sha256.toUpperCase(); }), LINK_FAILED],
    ["a padded p1_sha256", envelopeWith((v) => { v.p1_sha256 = ` ${v.p1_sha256} `; }), LINK_FAILED],
  ]);
});

test("the envelope bundle_id is a string equal to the manifest's, exactly", () => {
  runRows([
    ["7 against \"7\"", envelopeWith((v) => { v.bundle_id = 7; }, (m) => { m.bundle_id = "7"; }), LINK_FAILED],
    ["true against \"True\"", envelopeWith((v) => { v.bundle_id = true; }, (m) => { m.bundle_id = "True"; }), LINK_FAILED],
    ["\"\" against the fixture", envelopeWith((v) => { v.bundle_id = ""; }), LINK_FAILED],
    ["\"   \" against the fixture", envelopeWith((v) => { v.bundle_id = "   "; }), LINK_FAILED],
    ["padded against the fixture", envelopeWith((v) => { v.bundle_id = ` ${v.bundle_id} `; }), LINK_FAILED],
    ["upper-cased against the fixture", envelopeWith((v) => { v.bundle_id = v.bundle_id.toUpperCase(); }), LINK_FAILED],
    ["the same padded id on both sides", () => {
      const b = Bundle.linkValid();
      b.edit("manifest.json", (m) => { m.bundle_id = " padded-id "; });
      return b.seal();
    }, { ...PASS, envelope_links: true }],
  ]);
});

test("envelope_env1.json is the only envelope name; envelope.json is an ordinary member", () => {
  runRows([
    ["an unreadable envelope_env1.json beside a valid envelope.json", () => {
      const b = Bundle.linkValid().seal();
      b.setBytes("envelope.json", b.bytes("envelope_env1.json"));
      return b.setBytes("envelope_env1.json", "not valid JSON");
    }, { ...FAIL, envelope_present: true }],
    // The second name is an undeclared member like any other: the envelope holds, the run is
    // REVIEW.
    ["both names, identical", () => {
      const b = Bundle.linkValid().seal();
      return b.setBytes("envelope.json", b.bytes("envelope_env1.json"));
    }, { ...REVIEW, envelope_present: true, envelope_sha256: true, envelope_links: true }],
    ["envelope_env1.json beside an unreadable envelope.json", () => Bundle.linkValid().seal().setBytes("envelope.json", "not valid JSON"),
      { ...REVIEW, envelope_present: true, envelope_sha256: true, envelope_links: true }],
    ["an unreadable envelope_env1.json alone", () => Bundle.linkValid().seal().setBytes("envelope_env1.json", "not valid JSON"),
      { ...FAIL, envelope_present: true, envelope_sha256: false, envelope_links: false }],
    // envelope.json names no envelope: envelope.sha256 stands alone (envelope_incomplete).
    ["envelope.json alone", () => {
      const b = Bundle.linkValid().seal();
      b.setBytes("envelope.json", b.bytes("envelope_env1.json"));
      return b.delete("envelope_env1.json");
    }, { ...FAIL, envelope_present: false, envelope_sha256: false, envelope_links: null }],
    ["no envelope at all", () => Bundle.linkValid().seal().delete("envelope_env1.json").delete("envelope.sha256"),
      { ...REVIEW, envelope_present: false, envelope_sha256: null, envelope_links: null }],
  ]);
});

// An envelope that breaks its contract, beside a sidecar that is present but not a bare digest:
// the stored digest compares unequal, so envelope_sha256 is false, not null; null is for a digest
// whose input is absent (bundle-objects.md section 6), and the sidecar is there.
test("a broken envelope beside a sidecar that is not a bare digest reports envelope_sha256 false", () => {
  const brokenWith = (sidecar: (digest: string) => string) => () => {
    const b = Bundle.linkValid().seal();
    b.edit("envelope_env1.json", (v) => { v.spare = 1; });
    return b.setBytes("envelope.sha256", sidecar(sha256Hex(jcsText(b.json("envelope_env1.json")))));
  };
  const BROKEN = { ...FAIL, envelope_present: true, envelope_sha256: false, envelope_links: false };
  runRows([
    ["the digest in upper case", brokenWith((digest) => digest.toUpperCase()), BROKEN],
    ["the digest with a sha256: label", brokenWith((digest) => `sha256:${digest}`), BROKEN],
    ["not a digest", brokenWith(() => "not a digest"), BROKEN],
  ]);
});

test("exactly one of the envelope and envelope.sha256 is envelope_incomplete, both ways", () => {
  const cases: Array<[string, () => Bundle]> = [
    ["envelope without sidecar", () => Bundle.linkValid().seal().delete("envelope.sha256")],
    ["sidecar without envelope", () => Bundle.linkValid().seal().delete("envelope_env1.json")],
  ];
  for (const [label, build] of cases) {
    for (const [entryName, verify] of ENTRIES) {
      const report = verify(build());
      assert.deepEqual(
        { ...outcome(report), codes: report.errors.map((e) => e.code), reason: report.outcome.reason },
        { ...FAIL, codes: ["envelope_incomplete"], reason: "envelope_incomplete" },
        `${entryName}: ${label}`,
      );
    }
  }
});
