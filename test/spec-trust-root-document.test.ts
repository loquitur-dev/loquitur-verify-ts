// Trust-registry root authentication, held to loquitur-protocol docs/specification/trust-root.md.
//
// The trust-root document is validated as a whole when it is read (section 3): the document and
// every element of its array, whether or not the trust registry names the element, before any
// evidence is read and before any row of the evaluation order. Section 3's two tables, the exact
// signing message of section 4, the evaluation order of section 5 and the verdict table of
// section 6 are read from the sibling checkout and run here: the document table and the element
// table through every entry of this package, the order through authenticateTrustRegistry alone
// and in every pair of its conditions, and the signing message against a construction written in
// the test kit from the section's own text. The keys are made for the run and never written.
import { test } from "node:test";
import assert from "node:assert/strict";
import { bytesToHex } from "@noble/hashes/utils";
import {
  Bundle, ENTRIES, FAIL, PASS, REVIEW, ephemeralAuthorizationWith, ephemeralRoot, authorizationOutcome, outcome, refusal, rootDocument,
  rootSigningMessage, ROOT_SIGNING_PREFIX_HEX, compressedKey, hybridKey, pointOf, SMALL_X_POINT, SMALL_X_PLUS_P, SMALL_X_PLUS_P_COMPRESSED,
  SMALL_Y_POINT, SMALL_Y_PLUS_P,
} from "./bundle-kit.ts";
import { code, codes, readSpecification, sections, specification, table } from "./spec-tables.ts";
import { bundleReaderFromMap, evaluateTrustRegistry, verifyBundleFiles } from "../src/verify-core.ts";
import {
  ROOT_SIGNING_DOMAIN_PREFIX,
  TrustRootError,
  authenticateTrustRegistry,
  parseTrustRoots,
  trustRootDocumentUnsupportedVersion,
  trustRegistryRootSigningEnvelope,
  trustRegistrySigningMessageBytes,
} from "../src/trust-root.ts";

const DOCUMENT = "trust-root.md";
const SPEC = specification(DOCUMENT);
type Doc = Record<string, any>;

const flat = (text: string) => text.replace(/\s+/g, " ");

/**
 * The material of one run: a bundle, an entry signed by an issuer key made for the run, and the
 * trust registry authorizing it, signed by the root `N` (key_id root-1), whose window holds the
 * operator's evaluation time of every run below, INSTANT.
 */
function material() {
  const bundle = Bundle.linkValid().seal();
  const { root: N, sign } = ephemeralRoot("root-1");
  const { registryEntry, trustRegistry } = ephemeralAuthorizationWith(bundle, { trust: (t: Doc) => { delete t.signature; } });
  sign(trustRegistry);
  return { bundle, registryEntry, trustRegistry, N };
}

/** The trust registry as the element table's column describes it. */
function registryVariant(signed: Doc, variant: string): Doc {
  const registry = structuredClone(signed);
  switch (variant) {
    case "signed by `N`":
      return registry;
    case "signature not lowercase hex":
      registry.signature.signature = registry.signature.signature.toUpperCase();
      return registry;
    case "names a key no root has":
      registry.signature.key_id = "root-7";
      return registry;
    case "altered after signing":
      registry.entries[0].notes = "altered after signing";
      return registry;
    default:
      throw new Error(`the trust registry column has a value this test does not know: ${variant}`);
  }
}

/** {"roots":[N]}, with the row's change applied to N or to an added root-9. */
function rootsDocument(N: Doc, row: Record<string, string>): Doc {
  const named = structuredClone(N);
  const elements: unknown[] = [named];
  if (row["root"] === "—") {
    assert.equal(row["member"], "—");
    assert.equal(row["value"], "—");
    return rootDocument(elements);
  }
  let target: Doc;
  if (row["root"] === "`N`") {
    target = named;
  } else {
    assert.equal(code(row["root"]!), "root-9", JSON.stringify(row));
    target = { ...named, key_id: "root-9" };
    elements.push(target);
  }
  if (row["member"] === "—") {
    elements[elements.indexOf(target)] = JSON.parse(code(row["value"]!));
  } else if (row["value"] === "absent") {
    delete target[code(row["member"]!)];
  } else {
    // A member cell names one member, or several as a list of code spans.
    const members = codes(row["member"]!);
    assert.equal(row["member"], members.map((member) => `\`${member}\``).join(", "), JSON.stringify(row));
    const values = cellValues(N, row["value"]!, members, target);
    members.forEach((member, index) => { target[member] = values[index]; });
  }
  return rootDocument(elements);
}

/**
 * The compressed SEC1 encoding of the point -P, for the uncompressed encoding of P: P's x and the
 * other y, so a secp256k1 point that P does not share, differing from P's key by no more than the
 * parity of y.
 */
function negatedKey(uncompressed: string): string {
  assert.match(uncompressed, /^04[0-9a-f]{128}$/);
  return (BigInt(`0x${uncompressed.slice(66)}`) % 2n === 0n ? "03" : "02") + uncompressed.slice(2, 66);
}

/** The values a row's value cell gives its members, in the order the member cell names them. */
function cellValues(N: Doc, cell: string, members: string[], target: Doc): unknown[] {
  switch (cell) {
    case "`N`'s `key_id` in upper case":
      assert.deepEqual(members, ["key_id"]);
      return [String(N.key_id).toUpperCase()];
    case "`\"ed25519\"`, and a key of its own that shares no point with `N`'s":
      assert.deepEqual(members, ["key_type", "public_key_hex"]);
      return ["ed25519", negatedKey(N.public_key_hex)];
    case "`\"ed25519\"`, `root-9` still carrying `N`'s key":
      assert.deepEqual(members, ["key_type"]);
      assert.equal(target.key_id, "root-9");
      assert.equal(target.public_key_hex, N.public_key_hex);
      return ["ed25519"];
    default:
      assert.equal(members.length, 1, cell);
      return [JSON.parse(code(cell))];
  }
}

test("section 3 states the whole-document rule, and the report contract the library refusal", SPEC.options, () => {
  const text = flat(readSpecification(SPEC, DOCUMENT));
  for (const sentence of [
    "A verifier **MUST** validate the trust-root document against this section when it reads it, before it evaluates any row of §5: the document itself, and every element of its array, whatever the element's `key_id` and whether or not the trust registry names it.",
    "A document that breaks this section anywhere is malformed, and a malformed document is refused as a whole. It is never evaluated in part, and no status of §5 reports it",
    "refuses a set that has any root breaking this section with an error of the host language, before it evaluates any row of §5 or reads any evidence, and returns no report.",
    "The roots were validated as a whole when they were read (§3): a malformed set was refused then, and the rows below are evaluated only against a well-formed one.",
  ]) {
    assert.ok(text.includes(sentence), sentence);
  }
  const contract = flat(readSpecification(SPEC, "report-contract.md"));
  assert.ok(contract.includes("Given trust roots that break `trust-root.md` §3, any one of them, it returns no report"));
});

test("the signing message is the prefix and the canonical envelope, section 4", SPEC.options, () => {
  const text = readSpecification(SPEC, DOCUMENT);
  const section = sections(text).get("4. Exact signing message")!;
  // The prefix bytes the section writes in hexadecimal are the prefix this package signs under.
  assert.ok(section.includes(ROOT_SIGNING_PREFIX_HEX));
  assert.equal(bytesToHex(ROOT_SIGNING_DOMAIN_PREFIX), ROOT_SIGNING_PREFIX_HEX);
  // The closed envelope names the section's constants, and the payload is the registry without its
  // signature.
  const { trustRegistry } = material();
  const envelope = trustRegistryRootSigningEnvelope(trustRegistry);
  for (const [member, value] of Object.entries(envelope)) {
    if (member === "payload") continue;
    assert.ok(section.includes(`"${member}": ${JSON.stringify(value)}`), `${member}: ${JSON.stringify(value)}`);
  }
  const { signature: _signature, ...payload } = trustRegistry;
  assert.deepEqual(envelope.payload, payload);
  // The bytes this package signs over are the bytes the test kit builds from the section alone.
  assert.equal(bytesToHex(trustRegistrySigningMessageBytes(trustRegistry)), bytesToHex(rootSigningMessage(trustRegistry)));
  // A signature made under the registry-entry prefix does not verify here (section 4.1): the
  // registry-entry construction starts with another segment, so the two prefixes differ.
  assert.ok(!ROOT_SIGNING_PREFIX_HEX.startsWith(Buffer.from("LOQUITUR\u0000REGISTRY_ENTRY", "utf8").toString("hex")));
});

// ---------------------------------------------------------------- section 3, the two tables

for (const [entryName, verify] of ENTRIES) {
  test(`${entryName}: the document table, section 3`, SPEC.options, () => {
    const rows = table(readSpecification(SPEC, DOCUMENT), ["document", "document is"]);
    const { bundle, registryEntry, trustRegistry, N } = material();
    const got: Record<string, unknown> = {};
    const expected: Record<string, unknown> = {};
    for (const row of rows) {
      const written = code(row["document"]!);
      const H = '"object_type":"trust_root_document","schema_version":"v1"';
      const document = JSON.parse(written.replace(/R/g, JSON.stringify(N)).replace(/H/g, H));
      const reader = trustRootDocumentUnsupportedVersion(document) !== null ? "an unsupported version"
        : refusal(() => parseTrustRoots(document)) === null ? "well-formed" : "malformed";
      let run: string;
      try {
        const report = verify(bundle, { registryEntry, trustRegistry, trustRoots: document, evaluationTime: INSTANT });
        run = report.status === "UNSUPPORTED_VERSION"
          ? `an unsupported version ${report.exit_code} ${JSON.stringify(report.errors.map(({ code: c, object, version }) => ({ code: c, object, version })))}`
          : `well-formed ${report.trust_registry?.trust_registry_root_signature_status}`;
      } catch (err) {
        run = err instanceof Error && err.name === "TrustRootError" ? "malformed" : `threw ${String(err)}`;
      }
      got[written] = [reader, run];
      const unsupported = `an unsupported version 4 ${JSON.stringify([{ code: "unsupported_version", object: "trust_root_document", version: document?.schema_version }])}`;
      expected[written] = [row["document is"], row["document is"] === "well-formed" ? "well-formed ROOT_SIGNATURE_VALID"
        : row["document is"] === "an unsupported version" ? unsupported : "malformed"];
    }
    assert.deepEqual(got, expected);
    assert.deepEqual(new Set(rows.map((row) => row["document is"])), new Set(["well-formed", "an unsupported version", "malformed"]));
  });

  test(`${entryName}: the element table, section 3`, SPEC.options, () => {
    const rows = table(readSpecification(SPEC, DOCUMENT), ["case", "root", "member", "value", "trust registry", "outcome"]);
    const { bundle, registryEntry, trustRegistry: signed, N } = material();
    const got: Record<string, unknown> = {};
    const expected: Record<string, unknown> = {};
    for (const row of rows) {
      const name = code(row["case"]!);
      const trustRoots = rootsDocument(N, row);
      const trustRegistry = registryVariant(signed, row["trust registry"]!);
      const outcome = row["outcome"] === "refused" ? "refused" : code(row["outcome"]!);
      try {
        const report = verify(bundle, { registryEntry, trustRegistry, trustRoots, evaluationTime: INSTANT });
        const status = report.trust_registry?.trust_registry_root_signature_status;
        got[name] = [status, report.status, report.exit_code];
        expected[name] = [outcome, ...(outcome === "ROOT_SIGNATURE_VALID" ? ["OFFLINE_OK", 0] : ["OFFLINE_FAIL", 1])];
      } catch (err) {
        got[name] = err instanceof Error && err.name === "TrustRootError" ? "refused" : `threw ${String(err)}`;
        expected[name] = outcome;
      }
    }
    assert.deepEqual(got, expected);
    const outcomes = new Set(rows.map((row) => row["outcome"]));
    assert.ok(outcomes.has("refused") && outcomes.size > 1);
    // A refused row sits beside an earlier row of section 5 that would otherwise hold.
    assert.ok(rows.some((row) => row["trust registry"] === "signature not lowercase hex" && row["outcome"] === "refused"));
    assert.ok(rows.some((row) => row["trust registry"] === "names a key no root has" && row["outcome"] === "refused"));
  });
}

test("a malformed document is refused before any evidence is read, and roots are read whatever the other inputs", SPEC.options, () => {
  const { bundle, registryEntry, trustRegistry, N } = material();
  const files: Record<string, Uint8Array> = {};
  for (const [name, data] of bundle.files) Object.defineProperty(files, name, { value: data, enumerable: true });
  const calls: string[] = [];
  const inner = bundleReaderFromMap(files);
  const recording = {
    readText(name: string) { calls.push(`readText ${name}`); return inner.readText(name); },
    readBytes(name: string) { calls.push(`readBytes ${name}`); return inner.readBytes!(name); },
    listMembers() { calls.push("listMembers"); return inner.listMembers!(); },
  };
  const malformed = rootDocument([{ ...N, status: "suspended" }]);
  assert.throws(() => verifyBundleFiles(recording, { registryEntry, trustRegistry, trustRoots: malformed }), TrustRootError);
  // Without a trust registry, and without a registry entry, the document is still read as a whole.
  assert.throws(() => verifyBundleFiles(recording, { trustRoots: malformed }), TrustRootError);
  assert.throws(() => verifyBundleFiles(recording, { registryEntry, trustRoots: malformed }), TrustRootError);
  assert.deepEqual(calls, []);
  // A well-formed document beside no trust registry is validated and then unused: the report is
  // the report of the run without it.
  const alone = verifyBundleFiles(recording, { trustRoots: rootDocument([N]) });
  assert.deepEqual(outcome(alone), PASS);
  assert.equal(alone.trust_registry, null);
  assert.ok(calls.length > 0);
});

test("evaluateTrustRegistry, which returns no run, refuses a document of a later version", SPEC.options, () => {
  const { bundle, registryEntry, trustRegistry, N } = material();
  const later = { ...rootDocument([N]), schema_version: "v2" };
  // verifyBundleFiles reports the run as UNSUPPORTED_VERSION; with no run to report it in, the
  // evaluation on its own throws, and the pinned roots are never read as no root pinned.
  const reader = bundleReaderFromMap(Object.fromEntries(bundle.files));
  assert.equal(verifyBundleFiles(reader, { registryEntry, trustRegistry, trustRoots: later }).status, "UNSUPPORTED_VERSION");
  const refused = { name: "TrustRootError", message: 'trust-root document of the unsupported version "v2"' };
  assert.throws(() => evaluateTrustRegistry(registryEntry, trustRegistry, { trustRoots: later, evaluationTime: INSTANT }), refused);
  // Before any evaluation: an entry and a registry that are not documents do not change it.
  assert.throws(() => evaluateTrustRegistry(null, null, { trustRoots: later }), refused);
  assert.equal(
    evaluateTrustRegistry(registryEntry, trustRegistry, { trustRoots: rootDocument([N]), evaluationTime: INSTANT }).trust_registry_root_signature_status,
    "ROOT_SIGNATURE_VALID",
  );
});

test("the rules of section 3 the tables do not reach: W decides emptiness, the key is not lower-cased, the window is not empty", SPEC.options, () => {
  const text = flat(readSpecification(SPEC, DOCUMENT));
  assert.ok(text.includes("`key_id` is not empty in the sense of `bundle-objects.md`: it has at least one code point outside the whitespace set W."));
  assert.ok(text.includes("when `key_type` is `secp256k1` it matches `^04[0-9a-f]{128}$`. It is not lower-cased first."));
  assert.ok(text.includes("An empty or inverted window is malformed, not merely unsatisfiable."));
  const { N } = material();
  const refused = (root: Doc): string | null => refusal(() => parseTrustRoots(rootDocument([root])));
  assert.deepEqual({
    // U+001C and U+0085 are in W and are not removed by ECMAScript's trim: a key id made of them is
    // empty.
    "key_id of W outside trim": refused({ ...N, key_id: "\u001C\u0085" }),
    "key_id of W inside trim": refused({ ...N, key_id: " \t\uFEFF" }),
    "key_id with one code point outside W": refused({ ...N, key_id: "\u001C-" }),
    "public key in upper case": refused({ ...N, public_key_hex: "04" + N.public_key_hex.slice(2).toUpperCase() }),
    "public key as written": refused(N),
    "equal bounds": refused({ ...N, not_after: N.not_before }),
    "one second": refused({ ...N, not_after: "2026-01-01T00:00:01Z" }),
    "key_type absent": refused((({ key_type: _k, ...rest }) => rest)(N)),
    "key_type upper case": refused({ ...N, key_type: "SECP256K1" }),
    "key_type unsupported, well formed": refused({ ...N, key_type: "ed25519", public_key_hex: "ab".repeat(32) }),
    "secp256k1 key not a point encoding": refused({ ...N, public_key_hex: "ab".repeat(32) }),
  }, {
    "key_id of W outside trim": "TrustRootError",
    "key_id of W inside trim": "TrustRootError",
    "key_id with one code point outside W": null,
    "public key in upper case": "TrustRootError",
    "public key as written": null,
    "equal bounds": "TrustRootError",
    "one second": null,
    "key_type absent": "TrustRootError",
    "key_type upper case": "TrustRootError",
    "key_type unsupported, well formed": null,
    "secp256k1 key not a point encoding": "TrustRootError",
  });
});

// ---------------------------------------------------------------- section 5, the evaluation order

type Change = { registry?: (r: Doc) => void; roots?: (roots: Doc[]) => void; noRoots?: boolean; afterSigning?: (r: Doc) => void };
const INSTANT = "2026-05-10T00:00:00Z";

// The change that makes each row's condition hold, over a registry signed by N and the document
// {"roots":[N]}.
const ROWS: Record<string, Change> = {
  "1": { noRoots: true },
  "2": { registry: () => {}, afterSigning: () => {} }, // replaced by a non-object below
  "3": { afterSigning: (r) => { r.signature = null; } },
  "4": { afterSigning: (r) => { if (r.signature) r.signature.algorithm = "ed25519"; } },
  "5": { afterSigning: (r) => { if (r.signature) r.signature.signature = r.signature.signature.toUpperCase(); } },
  "6": { afterSigning: (r) => { if (r.signature) r.signature.key_id = "root-7"; } },
  "7": { roots: (roots) => { roots.push({ ...roots[0] }); } },
  "8": { roots: (roots) => { roots[0]!.status = "revoked"; } },
  "9": { roots: (roots) => { roots[0]!.not_before = "2026-06-01T00:00:00Z"; } },
  "10": { roots: (roots) => { roots[0]!.not_after = "2026-04-01T00:00:00Z"; } },
  "11": { roots: (roots) => { roots[0]!.key_type = "ed25519"; } },
  "12": { afterSigning: (r) => { r.entries[0].notes = "altered after signing"; } },
  "—": {},
};
/** Rows a bundle verification cannot reach: the trust registry's contract refuses them first. */
const UNREACHABLE_IN_A_RUN = new Set(["2", "3"]);

/** The rows of section 5 whose condition the documents meet, by a model written from the section. */
function rowsMet(registry: unknown, roots: Doc[] | null, tampered: boolean): Set<string> {
  const met = new Set<string>();
  if (roots === null || roots.length === 0) met.add("1");
  const r = registry as Doc;
  // Rows 3 to 7 are questions about the registry's signature object, and rows 4 to 7 about its
  // members; a registry that is not an object, or carries no signature object, leaves nothing to
  // ask.
  if (r === null || typeof r !== "object" || Array.isArray(r)) return met.add("2");
  const signature = r.signature;
  if (signature === null || typeof signature !== "object" || Array.isArray(signature)) return met.add("3");
  if (signature.algorithm !== "secp256k1_ecdsa_sha256") met.add("4");
  if (typeof signature.signature !== "string" || !/^[0-9a-f]{128}$/.test(signature.signature)) met.add("5");
  // Rows 6 to 10 are questions about the pinned roots; with none pinned there is nothing to ask.
  if (roots !== null && roots.length > 0) {
    const matched = roots.filter((root) => root.key_id === signature?.key_id);
    if (matched.length === 0) met.add("6");
    // Row 7: the key id found twice, or the matched root's point under another pinned root.
    const point = matched.length === 1 ? pointOf(matched[0]!.public_key_hex) : null;
    if (matched.length > 1 || (point !== null && roots.some((root) => root !== matched[0] && pointOf(root.public_key_hex) === point))) met.add("7");
    if (matched.some((root) => root.status === "revoked")) met.add("8");
    const at = Date.parse(INSTANT);
    if (matched.some((root) => at < Date.parse(root.not_before))) met.add("9");
    if (matched.some((root) => at > Date.parse(root.not_after))) met.add("10");
    // Row 11 is the pair: an algorithm outside every pair already met row 4, which comes first.
    if (matched.some((root) => root.key_type !== "secp256k1")) met.add("11");
  }
  if (tampered) met.add("12");
  return met;
}

const ORDER_HEADER = ["#", "condition", "status", "effect"];

function order(): Array<[string, string]> {
  return table(readSpecification(SPEC, DOCUMENT), ORDER_HEADER).map((row) => [row["#"]!, code(row["status"]!)]);
}

/** The run a row's effect gives when everything else holds and an evaluation time was supplied. */
function effectRun(row: string): Record<string, unknown> {
  const effect = table(readSpecification(SPEC, DOCUMENT), ORDER_HEADER).find((r) => r["#"] === row)!["effect"]!;
  if (effect === "holds") return { ...PASS, review_reasons: [] };
  if (effect === "failure") return { ...FAIL, review_reasons: [] };
  assert.ok(effect.startsWith("review: "), effect);
  return { ...REVIEW, review_reasons: codes(effect) };
}

/** The registry, the roots and the tampering flag a set of changes produces, from fresh material. */
function build(changes: Change[]): { registry: unknown; roots: Doc[] | null; tampered: boolean } {
  const { trustRegistry, N } = material();
  let roots: Doc[] | null = [structuredClone(N)];
  let registry: unknown = structuredClone(trustRegistry);
  let tampered = false;
  // The later row's change is applied first, so an earlier row's change is not undone by it.
  for (const change of [...changes].reverse()) {
    if (change.noRoots) roots = null;
    if (change.roots && roots !== null) change.roots(roots);
    if (change.afterSigning && registry !== null && typeof registry === "object") {
      change.afterSigning(registry as Doc);
      if (change === ROWS["12"]) tampered = true;
    }
    if (change === ROWS["2"]) registry = "not an object";
  }
  return { registry, roots, tampered };
}

/** The status this package reports for the documents, through roots read as a document when they are one. */
function authenticate(registry: unknown, roots: Doc[] | null): string {
  const parsed = roots === null ? null : parseTrustRoots(rootDocument(roots));
  return authenticateTrustRegistry(registry, parsed, INSTANT);
}

const pairs = <T,>(items: T[]): Array<[T, T]> => items.flatMap((a, i) => items.slice(i + 1).map((b) => [a, b] as [T, T]));
const first = (met: Set<string>, listed: string[]): string => [...met, "—"].sort((a, b) => listed.indexOf(a) - listed.indexOf(b))[0]!;
const pairKey = (a: string, b: string): string => [a, b].sort((x, y) => (x === "—" ? 99 : Number(x)) - (y === "—" ? 99 : Number(y))).join("+");

// Neighboring rows whose conditions cannot hold together in a well-formed document.
const EXCLUSIVE: Record<string, string> = {
  "2+3": "row 3 reads the registry's signature member, which row 2 finds no registry object to carry",
  "3+4": "row 4 reads the signature's algorithm, which row 3 finds no signature object to carry",
  "6+7": "row 7 needs the key found twice, which row 6 finds absent",
  "9+10": "both hold only for an inverted window, which section 3 refuses when the document is read",
};

test("every row of the evaluation order, alone and in every pair, section 5", SPEC.options, () => {
  const rows = order();
  const listed = rows.map(([row]) => row);
  const statuses = new Map(rows);
  assert.deepEqual(new Set(listed), new Set(Object.keys(ROWS)));
  const got: Record<string, unknown> = {};
  const expected: Record<string, unknown> = {};
  const decided = new Set<string>();
  const runs: Array<[string, Change[]]> = [
    ...Object.keys(ROWS).map((row) => [row, [ROWS[row]!]] as [string, Change[]]),
    ...pairs(listed.filter((row) => row !== "—")).map(([a, b]) => [`${a}+${b}`, [ROWS[a]!, ROWS[b]!]] as [string, Change[]]),
  ];
  for (const [label, changes] of runs) {
    const { registry, roots, tampered } = build(changes);
    const met = rowsMet(registry, roots, tampered);
    if (label in ROWS) assert.deepEqual(met, new Set(label === "—" ? [] : [label]), `the change of row ${label} makes exactly its row hold`);
    let reported: string;
    try {
      reported = authenticate(registry, roots);
    } catch (err) {
      if (!(err instanceof TrustRootError)) throw err;
      assert.ok(pairKey(...(label.split("+") as [string, string])) in EXCLUSIVE, `${label}: refused when read, and not listed as exclusive`);
      continue;
    }
    got[label] = reported;
    expected[label] = statuses.get(first(met, listed));
    const leading = [...met, "—"].sort((a, b) => listed.indexOf(a) - listed.indexOf(b));
    if (leading.length >= 2) decided.add(pairKey(leading[0]!, leading[1]!));
  }
  assert.deepEqual(got, expected);
  const neighbors = listed.slice(0, -1).map((row, i) => pairKey(row, listed[i + 1]!));
  assert.deepEqual(neighbors.filter((pair) => !decided.has(pair) && !(pair in EXCLUSIVE)), []);
  for (const pair of Object.keys(EXCLUSIVE)) assert.ok(neighbors.includes(pair), `${pair} are not neighbors`);
});

for (const [entryName, verify] of ENTRIES) {
  test(`${entryName}: root authentication is judged at the operator's evaluation time, and skips the window without one, section 5`, SPEC.options, () => {
    const text = flat(readSpecification(SPEC, DOCUMENT));
    assert.ok(text.includes("The time the decision is evaluated against is the operator's evaluation time (`trust-registry-authorization.md` §2), never read from the system clock and never taken from a date the issuer wrote"));
    assert.ok(text.includes("Without an evaluation time, rows 9 and 10 are not evaluated, and authorization is not established"));
    const { bundle, registryEntry, trustRegistry, N } = material();
    // N's window is the year 2026, and the registry's is 2026-04-29 12:00 to 2026-05-29 12:00.
    const options = { registryEntry, trustRegistry, trustRoots: rootDocument([N]) };
    const run = (time?: string) => {
      const report = verify(bundle, time === undefined ? options : { ...options, evaluationTime: time });
      return [report.trust_registry?.trust_registry_root_signature_status, report.status, report.review_reasons];
    };
    assert.deepEqual({
      "no evaluation time": run(),
      "inside the root's window": run("2026-05-20T00:00:00Z"),
    }, {
      "no evaluation time": ["ROOT_SIGNATURE_VALID", "OFFLINE_REVIEW", ["evaluation_time_not_provided"]],
      "inside the root's window": ["ROOT_SIGNATURE_VALID", "OFFLINE_OK", []],
    });
    // An evaluation time outside the root's window, with the registry and key windows widened to
    // hold it, so that the root is the only thing the time decides: a question, not a failure.
    const widened = ephemeralRoot("root-1");
    const { registryEntry: entry2, trustRegistry: registry2 } = ephemeralAuthorizationWith(bundle, {
      trust: (t: Doc) => {
        delete t.signature;
        t.effective_at = "2025-01-01T00:00:00Z";
        t.expires_at = "2030-01-01T00:00:00Z";
        t.entries[0].effective_from = "2025-01-01T00:00:00Z";
        t.entries[0].expires_at = "2030-01-01T00:00:00Z";
      },
    });
    widened.sign(registry2);
    const lateOptions = { registryEntry: entry2, trustRegistry: registry2, trustRoots: rootDocument([widened.root]) };
    const late = verify(bundle, { ...lateOptions, evaluationTime: "2027-06-01T00:00:00Z" });
    assert.deepEqual([late.trust_registry?.trust_registry_root_signature_status, late.status, late.review_reasons, late.evaluation_time],
      ["ROOT_KEY_EXPIRED", "OFFLINE_REVIEW", ["trust_root_outside_validity_window"], "2027-06-01T00:00:00Z"]);
    // The bounds belong to the window: each is inside it.
    for (const bound of [widened.root.not_before, widened.root.not_after]) {
      const at = verify(bundle, { ...lateOptions, evaluationTime: bound });
      assert.deepEqual([at.trust_registry?.trust_registry_root_signature_status, at.status], ["ROOT_SIGNATURE_VALID", "OFFLINE_OK"], bound);
    }
    // A revoked root is revoked at every time, and without one.
    const revoked = { ...options, trustRoots: rootDocument([{ ...N, status: "revoked" }]) };
    assert.deepEqual([verify(bundle, revoked).status, verify(bundle, { ...revoked, evaluationTime: INSTANT }).status], ["OFFLINE_FAIL", "OFFLINE_FAIL"]);
  });
}

// Row 7 also stops a matched root whose point another pinned root carries, in any SEC1 encoding,
// whatever the other root's status or key type: signature.key_id is outside the signed bytes, so a
// registry signed under a revoked key_id can be relabeled to an active one carrying the same key.
// A value that encodes no point shares none.
test("a matched root's point under another pinned root is ambiguous; a value that encodes no point shares none, section 5", () => {
  const { trustRegistry, N } = material();
  const at = (roots: Doc[]) => authenticateTrustRegistry(trustRegistry, parseTrustRoots(rootDocument(roots)), INSTANT);
  const other = (fields: Doc): Doc => ({ ...N, key_id: "root-9", ...fields });
  const named = (fields: Doc): Doc => ({ ...N, ...fields });
  const key: string = N.public_key_hex;
  assert.deepEqual({
    "two roots, one point": at([N, other({})]),
    "the other root revoked": at([N, other({ status: "revoked" })]),
    "the matched root revoked, the other active": at([named({ status: "revoked" }), other({})]),
    "another key type, compressed": at([N, other({ key_type: "ed25519", public_key_hex: compressedKey(key) })]),
    "another key type, uncompressed": at([N, other({ key_type: "ed25519" })]),
    "another key type, hybrid": at([N, other({ key_type: "ed25519", public_key_hex: hybridKey(key) })]),
    "another key type, X with no Y": at([N, other({ key_type: "ed25519", public_key_hex: key.slice(0, 66) })]),
    "another key type, the point at infinity": at([N, other({ key_type: "ed25519", public_key_hex: "00" })]),
    "another root with a key of its own, revoked": at([N, { ...ephemeralRoot("root-9").root, status: "revoked" }]),
    "two other roots sharing a point not N's": at([N, other({ public_key_hex: SMALL_Y_POINT }), { ...other({ public_key_hex: SMALL_Y_POINT }), key_id: "root-8" }]),
    // No private key is known for the small points: a run that passes row 7 stops at row 12. A
    // reader that reduced a coordinate modulo p would stop at row 7.
    "X plus p beside X": at([named({ public_key_hex: SMALL_X_POINT }), other({ key_type: "ed25519", public_key_hex: SMALL_X_PLUS_P })]),
    "X plus p compressed beside X": at([named({ public_key_hex: SMALL_X_POINT }), other({ key_type: "ed25519", public_key_hex: SMALL_X_PLUS_P_COMPRESSED })]),
    "Y plus p beside Y": at([named({ public_key_hex: SMALL_Y_POINT }), other({ key_type: "ed25519", public_key_hex: SMALL_Y_PLUS_P })]),
    "two values that encode no point, written alike": at([named({ key_type: "ed25519", public_key_hex: "ab".repeat(32) }), other({ key_type: "ed25519", public_key_hex: "ab".repeat(32) })]),
  }, {
    "two roots, one point": "AMBIGUOUS_ROOT_KEY",
    "the other root revoked": "AMBIGUOUS_ROOT_KEY",
    "the matched root revoked, the other active": "AMBIGUOUS_ROOT_KEY",
    "another key type, compressed": "AMBIGUOUS_ROOT_KEY",
    "another key type, uncompressed": "AMBIGUOUS_ROOT_KEY",
    "another key type, hybrid": "ROOT_SIGNATURE_VALID",
    "another key type, X with no Y": "ROOT_SIGNATURE_VALID",
    "another key type, the point at infinity": "ROOT_SIGNATURE_VALID",
    "another root with a key of its own, revoked": "ROOT_SIGNATURE_VALID",
    "two other roots sharing a point not N's": "ROOT_SIGNATURE_VALID",
    "X plus p beside X": "ROOT_SIGNATURE_INVALID",
    "X plus p compressed beside X": "ROOT_SIGNATURE_INVALID",
    "Y plus p beside Y": "ROOT_SIGNATURE_INVALID",
    "two values that encode no point, written alike": "UNSUPPORTED_SIGNATURE_ALGORITHM",
  });
  // Upper case never reaches the comparison: section 3 refuses the document when it is read.
  assert.equal(refusal(() => parseTrustRoots(rootDocument([N, other({ key_type: "ed25519", public_key_hex: key.toUpperCase() })]))), "TrustRootError");
});

for (const [entryName, verify] of ENTRIES) {
  test(`${entryName}: a revoked root's point pinned again under an active key_id fails the run, section 5`, () => {
    const { bundle, registryEntry, trustRegistry, N } = material();
    const run = (roots: Doc[]) => {
      const report = verify(bundle, { registryEntry, trustRegistry, trustRoots: rootDocument(roots), evaluationTime: INSTANT });
      return [report.trust_registry?.trust_registry_root_signature_status, report.status, report.exit_code];
    };
    assert.deepEqual(run([N, { ...N, key_id: "root-9", status: "revoked" }]), ["AMBIGUOUS_ROOT_KEY", "OFFLINE_FAIL", 1]);
    assert.deepEqual(run([N, { ...N, key_id: "root-9", key_type: "ed25519", public_key_hex: compressedKey(N.public_key_hex) }]), ["AMBIGUOUS_ROOT_KEY", "OFFLINE_FAIL", 1]);
  });
}

test("the three load-bearing points of the order are stated, section 5", SPEC.options, () => {
  const text = flat(readSpecification(SPEC, DOCUMENT));
  const rows = order();
  const number = new Map(rows.filter(([row]) => row !== "—").map(([row, status]) => [status, row]));
  const revoked = number.get("ROOT_KEY_REVOKED")!;
  const notYet = number.get("ROOT_KEY_NOT_YET_VALID")!;
  const expired = number.get("ROOT_KEY_EXPIRED")!;
  assert.ok(text.includes(`**Revocation is checked before the validity window (${revoked} before ${notYet} and ${expired}).**`));
  assert.ok(text.includes(`**\`AMBIGUOUS_ROOT_KEY\` is not \`UNKNOWN_ROOT_KEY\` (${number.get("AMBIGUOUS_ROOT_KEY")}, not ${number.get("UNKNOWN_ROOT_KEY")}).**`));
  assert.ok(text.includes("**A run that never reached root authentication reports `ROOT_SIGNATURE_NOT_EVALUATED`.**"));
  assert.ok(text.includes(`reaches \`ROOT_SIGNATURE_INVALID\` (§5, row ${number.get("ROOT_SIGNATURE_INVALID")})`));
  // The revocation signal survives a lapsed window: revoked and expired together is revoked.
  const { registry, roots } = build([ROWS["10"]!, ROWS["8"]!]);
  assert.equal(authenticate(registry, roots), "ROOT_KEY_REVOKED");
});

for (const [entryName, verify] of ENTRIES) {
  test(`${entryName}: the rows of the order a bundle verification reaches, section 5`, SPEC.options, () => {
    const rows = order();
    const statuses = new Map(rows);
    const got: Record<string, unknown> = {};
    const expected: Record<string, unknown> = {};
    for (const row of Object.keys(ROWS)) {
      if (UNREACHABLE_IN_A_RUN.has(row)) continue;
      const { bundle, registryEntry, trustRegistry, N } = material();
      const roots: Doc[] = [structuredClone(N)];
      const change = ROWS[row]!;
      change.roots?.(roots);
      change.afterSigning?.(trustRegistry);
      const options = change.noRoots ? { registryEntry, trustRegistry, evaluationTime: INSTANT } : { registryEntry, trustRegistry, trustRoots: rootDocument(roots), evaluationTime: INSTANT };
      const report = verify(bundle, options);
      got[row] = { ...authorizationOutcome(report), review_reasons: report.review_reasons };
      const status = statuses.get(row)!;
      expected[row] = { ...effectRun(row), trust_registry: true, registry_signature: "VALID_SIGNATURE", authorization_status: "AUTHORIZED_ACTIVE_KEY", signature_status: "VALID_SIGNATURE", root_signature_status: status };
      const { review_reasons: reasons, ...head } = expected[row] as Record<string, unknown>;
      expected[row] = { ...head, review_reasons: reasons };
    }
    assert.deepEqual(got, expected);
  });

  test(`${entryName}: the effect on the verdict, section 6`, SPEC.options, () => {
    const rows = table(readSpecification(SPEC, DOCUMENT), ["roots supplied", "root authentication", "verdict"]);
    assert.equal(rows.length, 4);
    const { bundle, registryEntry, trustRegistry, N } = material();
    const stranger = ephemeralRoot("root-1").root;
    // N with a window that has not begun at INSTANT: rows 9 and 10.
    const early = { ...N, not_before: "2026-05-10T00:00:01Z" };
    const roots: Record<string, Doc | null> = {
      "—": null,
      "stops at a row whose effect is a failure": stranger,
      "stops at row 9 or 10: the matched root's window does not hold the evaluation time": early,
      "`ROOT_SIGNATURE_VALID`": N,
    };
    const got: Record<string, unknown> = {};
    const expected: Record<string, unknown> = {};
    for (const row of rows) {
      const label = `${row["roots supplied"]}/${row["root authentication"]}`;
      assert.ok(row["root authentication"]! in roots, label);
      const root = roots[row["root authentication"]!]!;
      assert.equal(root === null, row["roots supplied"] === "no", label);
      const options = root === null
        ? { registryEntry, trustRegistry, evaluationTime: INSTANT }
        : { registryEntry, trustRegistry, trustRoots: rootDocument([root]), evaluationTime: INSTANT };
      const report = verify(bundle, options);
      got[label] = [report.verdict, report.review_reasons];
      const spans = codes(row["verdict"]!);
      expected[label] = [spans[0], spans[0] === "REVIEW" ? [spans[1]] : []];
    }
    assert.deepEqual(got, expected);
  });
}
