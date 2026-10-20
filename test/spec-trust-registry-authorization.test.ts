// The authorization check, held to loquitur-protocol
// docs/specification/trust-registry-authorization.md.
//
// The specification states the check as tables: the evaluation time (section 2), the trust
// registry's coherence (section 3), lifecycle states and inclusive windows (section 4) and the
// evaluation order with the authorization status, signature status and effect of every row
// (section 6). Each table is read from the sibling checkout, and every row is asserted on the
// report's trust_registry member: its authorization_status and signature_status are the row's, and
// its root signature status is NO_PINNED_TRUST_ROOT when the row reaches VALID_SIGNATURE and
// ROOT_SIGNATURE_NOT_EVALUATED on every row that stops earlier (section 7). Beside them, status,
// verdict, exit code, the review reasons and the two per-check results the run reports.
//
// Every run that reaches the trust registry is given the operator's evaluation time, except where a
// case of the specification gives none: issuer dates never decide (section 2).
//
// Every pair of the changes that make one row hold is run combined. A model of each row's
// condition, written from the specification, says which rows the combined documents meet, and the
// run must report the row the table lists first among them. Row 2, an entry that breaks its
// contract, is refused by the link before a bundle verification reaches the trust registry; it is
// run through evaluateTrustRegistry, the section-6 evaluation on its own, with its neighbors.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  Bundle, ENTRIES, FAIL, PASS, REVIEW, ephemeralAuthorizationWith, authorizationOutcome, outcome, pointOf,
  compressedKey, hybridKey, SMALL_X_POINT, SMALL_X_PLUS_P, SMALL_X_PLUS_P_COMPRESSED, SMALL_Y_POINT, SMALL_Y_PLUS_P,
} from "./bundle-kit.ts";
import { code, codes, readSpecification, specification, table } from "./spec-tables.ts";
import { verifyRegistryEntrySignature } from "../src/signature.ts";
import { AUTHORIZATION_STATUSES, SIGNATURE_STATUSES, bundleReaderFromMap, evaluateTrustRegistry, verifyBundleFiles } from "../src/verify-core.ts";
import { EvaluationTimeError } from "../src/evaluation-time.ts";
import { secp256k1Point } from "../src/key-point.ts";

const DOCUMENT = "trust-registry-authorization.md";
const SPEC = specification(DOCUMENT);
const AUTHORIZED = "AUTHORIZED_ACTIVE_KEY";
const AUTHORIZED_KEY_ID = "demo-key-2";
/** The operator's evaluation time of every run below: the fixture windows hold it. */
const EVALUATION_TIME = "2026-05-10T00:00:00Z";
type Doc = Record<string, any>;
type Change = { entry?: (e: Doc) => void; afterSigning?: (e: Doc) => boolean; trust?: (t: Doc) => void; trustRegistry?: unknown };
type Row = [string | null, string | null, string];

const status = (cell: string): string | null => (code(cell) === "null" ? null : code(cell));

function order(): Array<[string, Row]> {
  return table(readSpecification(SPEC, DOCUMENT), ["#", "condition", "`authorization_status`", "`signature_status`", "effect"])
    .map((row) => [row["#"]!, [status(row["`authorization_status`"]!), status(row["`signature_status`"]!), row["effect"]!]]);
}

const key = (fields: Doc) => (t: Doc) => { Object.assign(t.entries[0], fields); };
const registry = (fields: Doc) => (t: Doc) => { Object.assign(t, fields); };
const signature = (fields: Doc) => (e: Doc) => { if (e.signature !== null && typeof e.signature === "object") Object.assign(e.signature, fields); };
/** Change the last character of the signature value; false when there is no value to change. */
const flip = (e: Doc): boolean => {
  if (e.signature === null || typeof e.signature !== "object" || typeof e.signature.signature !== "string") return false;
  const v: string = e.signature.signature;
  e.signature.signature = v.slice(0, -1) + (v.endsWith("0") ? "1" : "0");
  return true;
};
const upperCase = (e: Doc): boolean => {
  if (e.signature === null || typeof e.signature !== "object" || typeof e.signature.signature !== "string") return false;
  e.signature.signature = e.signature.signature.toUpperCase();
  return true;
};

const PATH_ROWS: Record<string, Change> = {
  "1": { trustRegistry: null },
  "3": { trust: registry({ object_type: "not_a_trust_registry" }) },
  "4": { trust: key({ issuer_id: "issuer_someone_else" }) },
  "5": { trust: key({ issuer_key_id: "another-key" }) },
  "6": { trust: (t) => { t.entries.push({ ...structuredClone(t.entries[0]), notes: "the same issuer and key, listed twice" }); } },
  "7": { trust: key({ status: "revoked", revoked_at: "2026-05-01T00:00:00Z", revocation_reason: "compromised" }) },
  "8": { trust: key({ status: "suspended" }) },
  "9": { trust: registry({ effective_at: "2026-05-10T00:00:01Z" }) },
  "10": { trust: registry({ expires_at: "2026-05-09T23:59:59Z" }) },
  "11": { trust: key({ effective_from: "2026-05-10T00:00:01Z" }) },
  "12": { trust: key({ expires_at: "2026-05-09T23:59:59Z" }) },
  "13": { trust: key({ allowed_asset_types: ["fund_nav"] }) },
  "14": { entry: (e) => { e.signature = null; } },
  // The entry admits any well-formed algorithm identifier; the verifier's allowlist decides.
  "16": { entry: signature({ algorithm: "ed25519" }) },
  "18": { entry: signature({ key_id: "another-key" }) },
  "20": { afterSigning: flip },
  "—": {},
};
// The changes of rows 14 to 20 for the signature step on its own: "before" runs before the entry is
// signed, "after" after. Rows 15, 17 and 19 are reached only here: the version gate of the signing
// payload, the entry's contract and the key lookup refuse them earlier in a bundle verification.
const STEP_CHANGES: Record<string, ["before" | "after", (e: Doc) => unknown]> = {
  "14": ["before", (e) => { e.signature = null; }],
  "15": ["before", signature({ payload_version: 3 })],
  "16": ["before", signature({ algorithm: "ed25519" })],
  "17": ["after", upperCase],
  "18": ["before", signature({ key_id: "another-key" })],
  "19": ["before", (e) => { e.issuer_key_id = "another-key"; }],
  "20": ["after", flip],
};
const UNREACHABLE_IN_A_BUNDLE = new Set(["15", "17", "19"]);
// Row 2 (an entry that breaks its contract) is refused by the link before any trust conclusion in a
// bundle verification; the section-6 evaluation on its own reaches it.
const EVALUATION_ONLY = new Set(["2"]);

// ---- the conditions of the order table, as the specification states them ----------------------
// A model of each row's condition over the documents a run reads, written from sections 2 to 6 of
// the specification and not from either implementation: which rows the documents meet.

const instant = (value: string): number => Date.parse(value);

/** Section 3, for the fields the changes of this module reach: object type and coherence. */
function contradictsItself(trust: Doc): boolean {
  if (trust.object_type !== "trust_registry") return true;
  const expiresAt = instant(trust.expires_at);
  if (instant(trust.effective_at) > expiresAt || instant(trust.issued_at) > expiresAt) return true;
  return trust.entries.some((item: Doc) => {
    const revocation = item.revoked_at != null || item.revocation_reason != null;
    return ((item.status === "active" || item.status === "suspended") && revocation)
      || (item.status === "revoked" && item.revoked_at == null)
      || instant(item.effective_from) > instant(item.expires_at);
  });
}

/** Rows 14 to 20: the signature step, against the key the trust entry authorizes. */
function signatureRows(entry: Doc, authorizedKeyId: string | null, keyType: string | null, tampered: boolean): Set<string> {
  const sig = entry.signature;
  if (sig === null || typeof sig !== "object" || Array.isArray(sig)) return new Set(["14"]);
  const met = new Set<string>();
  if (sig.payload_id !== "registry_entry_signing_payload_v2" || sig.payload_version !== 2) met.add("15");
  if (sig.algorithm !== "secp256k1_ecdsa_sha256" || (keyType !== null && keyType !== "secp256k1")) met.add("16");
  if (typeof sig.signature !== "string" || !/^[0-9a-f]{128}$/.test(sig.signature)) met.add("17");
  if (authorizedKeyId !== null && sig.key_id !== authorizedKeyId) met.add("18");
  if (authorizedKeyId !== null && entry.issuer_key_id !== authorizedKeyId) met.add("19");
  if (tampered) met.add("20");
  return met;
}

/** Every row whose condition the entry and the trust registry of a bundle verification meet. */
function pathRows(entry: Doc, trust: Doc | null, tampered: boolean): Set<string> {
  if (trust === null) return new Set(["1", ...signatureRows(entry, null, null, tampered)]);
  const met = new Set<string>();
  if (contradictsItself(trust)) met.add("3");
  const issuer = trust.entries.filter((item: Doc) => item.issuer_id === entry.issuer_id);
  const keys = issuer.filter((item: Doc) => item.issuer_key_id === entry.issuer_key_id);
  if (issuer.length === 0) met.add("4");
  else if (keys.length === 0) met.add("5");
  // Row 6: the key found twice, or its point under another trust entry, whoever's and whatever its
  // status or key type.
  else if (keys.length > 1) met.add("6");
  else if (pointOf(keys[0].public_key_hex) !== null
    && trust.entries.some((item: Doc) => item !== keys[0] && pointOf(item.public_key_hex) === pointOf(keys[0].public_key_hex))) met.add("6");
  const at = instant(EVALUATION_TIME);
  const conditions: Record<string, boolean> = {
    "7": keys.some((item: Doc) => item.status === "revoked"),
    "8": keys.some((item: Doc) => item.status === "suspended"),
    "9": at < instant(trust.effective_at),
    "10": at > instant(trust.expires_at),
    "11": keys.some((item: Doc) => at < instant(item.effective_from)),
    "12": keys.some((item: Doc) => at > instant(item.expires_at)),
    "13": keys.some((item: Doc) => !item.allowed_asset_types.includes(entry.asset_type) || !item.allowed_workflows.includes(entry.workflow)),
  };
  for (const [row, holds] of Object.entries(conditions)) if (holds) met.add(row);
  const found = keys.length > 0 ? keys[0] : null;
  for (const row of signatureRows(entry, found ? found.issuer_key_id : null, found ? found.key_type : null, tampered)) met.add(row);
  return met;
}

function combine(...changes: Change[]): Change {
  const out: Change = {};
  for (const change of changes) {
    for (const kind of ["entry", "trust"] as const) {
      const next = change[kind];
      if (!next) continue;
      const previous = out[kind];
      out[kind] = previous ? (doc: Doc) => { previous(doc); next(doc); } : next;
    }
    if (change.afterSigning) out.afterSigning = change.afterSigning;
    if ("trustRegistry" in change) out.trustRegistry = change.trustRegistry;
  }
  return out;
}

/** The entry and trust registry a change produces, and whether the signed value was changed. */
function build(bundle: Bundle, change: Change) {
  let tampered = false;
  const m = ephemeralAuthorizationWith(bundle, {
    entry: change.entry,
    afterSigning: change.afterSigning ? (e: Doc) => { tampered = change.afterSigning!(e); } : undefined,
    trust: change.trust,
  });
  const trustRegistry = "trustRegistry" in change ? change.trustRegistry : m.trustRegistry;
  return { m: { registryEntry: m.registryEntry, trustRegistry, evaluationTime: EVALUATION_TIME }, tampered };
}

const material = (bundle: Bundle, change: Change) => build(bundle, change).m;

/** The review reason a row's effect names, or null for a failure and for "holds". */
const reviewReason = (effect: string): string | null => (effect.startsWith("review") ? codes(effect)[0]! : null);

/** What this verifier reports for a row: its statuses, the root status of section 7 and the row's effect (section 9). */
function expectedFor([authorization, signatureStatus, effect]: Row) {
  const holds = authorization === AUTHORIZED && signatureStatus === "VALID_SIGNATURE";
  const statuses = { authorization_status: authorization, signature_status: signatureStatus };
  if (holds) {
    assert.equal(effect, "holds");
    return { ...REVIEW, trust_registry: true, registry_signature: "VALID_SIGNATURE", ...statuses, root_signature_status: "NO_PINNED_TRUST_ROOT", review_reasons: ["trust_registry_root_not_pinned"] };
  }
  const reason = reviewReason(effect);
  const run = reason === null ? { ...FAIL, review_reasons: [] } : { ...REVIEW, review_reasons: [reason] };
  const { review_reasons, ...head } = run;
  return { ...head, trust_registry: false, registry_signature: signatureStatus ?? "UNSUPPORTED", ...statuses, root_signature_status: "ROOT_SIGNATURE_NOT_EVALUATED", review_reasons };
}

const reported = (report: ReturnType<typeof verifyBundleFiles>) => ({ ...authorizationOutcome(report), review_reasons: report.review_reasons });

/** The three statuses of the section-6 evaluation on its own, over host documents. */
function evaluated(entry: unknown, trust: unknown): [string, string | null, string] {
  const result = evaluateTrustRegistry(entry, trust, { evaluationTime: EVALUATION_TIME });
  return [result.authorization_status, result.signature_status, result.trust_registry_root_signature_status];
}

/** The fixture entry with the step changes of `rows`, signed between the two phases. */
function stepEntry(bundle: Bundle, rows: string[]) {
  let tampered = false;
  const m = ephemeralAuthorizationWith(bundle, {
    entry: (e) => { for (const row of rows) if (STEP_CHANGES[row]![0] === "before") STEP_CHANGES[row]![1](e); },
    afterSigning: (e) => {
      for (const row of rows) {
        if (STEP_CHANGES[row]![0] !== "after") continue;
        const applied = STEP_CHANGES[row]![1](e);
        if (row === "20") tampered = applied === true;
      }
    },
  });
  return { entry: m.registryEntry as Doc, publicKeyHex: m.trustRegistry.entries[0].public_key_hex as string, tampered };
}

function step(entry: Doc, publicKeyHex: string): [string, string] {
  const result = verifyRegistryEntrySignature(entry, publicKeyHex, { expectedKeyId: AUTHORIZED_KEY_ID, keyType: "secp256k1" });
  // The helper names the row's signature status itself: VALID_SIGNATURE for a signature that
  // verifies.
  assert.equal(result.valid, result.status === "VALID_SIGNATURE");
  return [AUTHORIZED, result.status];
}

const statusesOf = (row: Row): [string | null, string | null] => [row[0], row[1]];

// The last row, "—", is the table's "otherwise": its condition holds for every run, so it takes
// part in the order like any row, and a row listed after it would never decide anything.
const withOtherwise = (met: Set<string>) => [...met, "—"];
const first = (met: Set<string>, listed: string[]): string =>
  withOtherwise(met).sort((a, b) => listed.indexOf(a) - listed.indexOf(b))[0]!;

/** A pair of rows named in table order of the unmutated specification: numbers first, "—" last. */
const pairKey = (a: string, b: string): string =>
  [a, b].sort((x, y) => (x === "—" ? 99 : Number(x)) - (y === "—" ? 99 : Number(y))).join("+");

const pairs = <T>(items: T[]): Array<[T, T]> => items.flatMap((a, i) => items.slice(i + 1).map((b) => [a, b] as [T, T]));

// Neighboring rows of the table whose conditions cannot hold together without an earlier row
// holding too, so that no run can show which of the two comes first.
const EXCLUSIVE: Record<string, string> = {
  "4+5": "row 5 looks among the issuer's entries, which row 4 finds absent",
  "5+6": "row 6 needs the key found, which row 5 finds absent",
  "7+8": "a key found once has one status; found twice, row 6 decides first",
  "9+10": "both hold only for an inverted registry window, which row 3 refuses first",
  "11+12": "both hold only for an inverted key window, which row 3 refuses first",
  "14+15": "row 15 reads a signature object, which row 14 finds absent",
};

/** Every step change alone and every pair, as the rows its entry meets and the statuses the step reports. */
function stepRuns(listed: string[]): Record<string, [Set<string>, [string, string]]> {
  const bundle = Bundle.linkValid().seal();
  const runs: Record<string, [Set<string>, [string, string]]> = {};
  const rows = Object.keys(STEP_CHANGES).sort((a, b) => listed.indexOf(a) - listed.indexOf(b));
  for (const row of rows) {
    const { entry, publicKeyHex, tampered } = stepEntry(bundle, [row]);
    runs[`step ${row}`] = [signatureRows(entry, AUTHORIZED_KEY_ID, "secp256k1", tampered), step(entry, publicKeyHex)];
  }
  for (const [a, b] of pairs(rows)) {
    const { entry, publicKeyHex, tampered } = stepEntry(bundle, [a, b]);
    runs[`step ${a}+${b}`] = [signatureRows(entry, AUTHORIZED_KEY_ID, "secp256k1", tampered), step(entry, publicKeyHex)];
  }
  return runs;
}

/** Every path change alone and every pair, as the rows its documents meet; the run is left to the caller. */
function pathCombinations(bundle: Bundle): Record<string, { met: Set<string>; m: ReturnType<typeof material> }> {
  const combos: Record<string, { met: Set<string>; m: ReturnType<typeof material> }> = {};
  const rows = Object.keys(PATH_ROWS).filter((row) => row !== "—");
  for (const row of [...rows, "—"]) {
    const { m, tampered } = build(bundle, PATH_ROWS[row]!);
    combos[`path ${row}`] = { met: pathRows(m.registryEntry as Doc, m.trustRegistry as Doc | null, tampered), m };
  }
  for (const [a, b] of pairs(rows)) {
    // The later row's change is applied first, so a duplicate copies a revoked key, and so on.
    const { m, tampered } = build(bundle, combine(PATH_ROWS[b]!, PATH_ROWS[a]!));
    combos[`path ${a}+${b}`] = { met: pathRows(m.registryEntry as Doc, m.trustRegistry as Doc | null, tampered), m };
  }
  return combos;
}

test("every row of the signature step, and the first row among those a step run meets, section 6", SPEC.options, () => {
  const rows = order();
  const listed = rows.map(([row]) => row);
  const statuses = new Map(rows.map(([row, r]) => [row, statusesOf(r)]));
  const bundle = Bundle.linkValid().seal();
  const got: Record<string, unknown> = {};
  const expected: Record<string, unknown> = {};
  for (const row of UNREACHABLE_IN_A_BUNDLE) {
    const { entry, publicKeyHex, tampered } = stepEntry(bundle, [row]);
    assert.deepEqual(signatureRows(entry, AUTHORIZED_KEY_ID, "secp256k1", tampered), new Set([row]), row);
    got[row] = step(entry, publicKeyHex);
    expected[row] = statuses.get(row);
  }
  for (const [label, [met, reportedStatuses]] of Object.entries(stepRuns(listed))) {
    got[label] = reportedStatuses;
    expected[label] = statuses.get(first(met, listed));
  }
  assert.deepEqual(got, expected);
});

test("every two neighboring rows lead a combined run, or cannot hold together, section 6", SPEC.options, () => {
  const rows = order();
  const listed = rows.map(([row]) => row);
  const decided = new Set<string>();
  const lead = (met: Set<string>) => {
    const sorted = withOtherwise(met).sort((a, b) => listed.indexOf(a) - listed.indexOf(b));
    if (sorted.length >= 2) decided.add(pairKey(sorted[0]!, sorted[1]!));
  };
  for (const { met } of Object.values(pathCombinations(Bundle.linkValid().seal()))) lead(met);
  for (const [met] of Object.values(stepRuns(listed))) lead(met);
  for (const [met] of Object.values(evaluationRuns())) lead(met);
  const neighbors = listed.slice(0, -1).map((row, i) => pairKey(row, listed[i + 1]!));
  const undecided = neighbors.filter((pair) => !decided.has(pair) && !(pair in EXCLUSIVE));
  assert.deepEqual(undecided, []);
  for (const pair of Object.keys(EXCLUSIVE)) assert.ok(neighbors.includes(pair), `${pair} are not neighbors`);
});

// Rows 1 to 3 through the section-6 evaluation on its own, alone and in neighboring pairs: the rows
// each run meets, by the model, and the statuses it reports. A trust registry that cannot be read
// (row 1) is `null`; an entry that breaks its contract (row 2) carries a member outside its schema;
// a trust registry that breaks its contract (row 3) names another object type.
function evaluationRuns(): Record<string, [Set<string>, [string, string | null, string]]> {
  const bundle = Bundle.linkValid().seal();
  const valid = ephemeralAuthorizationWith(bundle, {});
  const broken = ephemeralAuthorizationWith(bundle, { entry: (e) => { e.smuggled = 1; } });
  const malformed = ephemeralAuthorizationWith(bundle, { trust: registry({ object_type: "not_a_trust_registry" }) });
  return {
    "evaluation 1": [new Set(["1"]), evaluated(valid.registryEntry, null)],
    "evaluation 2": [new Set(["2"]), evaluated(broken.registryEntry, valid.trustRegistry)],
    "evaluation 3": [new Set(["3"]), evaluated(valid.registryEntry, malformed.trustRegistry)],
    "evaluation 1+2": [new Set(["1", "2"]), evaluated(broken.registryEntry, null)],
    "evaluation 2+3": [new Set(["2", "3"]), evaluated(broken.registryEntry, malformed.trustRegistry)],
    "evaluation —": [new Set(), evaluated(valid.registryEntry, valid.trustRegistry)],
  };
}

test("the section-6 evaluation on its own reaches row 2 and orders it with its neighbors", SPEC.options, () => {
  const rows = order();
  const listed = rows.map(([row]) => row);
  const statuses = new Map(rows);
  const got: Record<string, unknown> = {};
  const expected: Record<string, unknown> = {};
  for (const [label, [met, reportedStatuses]] of Object.entries(evaluationRuns())) {
    got[label] = reportedStatuses;
    const [authorization, signatureStatus] = statuses.get(first(met, listed))!;
    expected[label] = [authorization, signatureStatus, signatureStatus === "VALID_SIGNATURE" ? "NO_PINNED_TRUST_ROOT" : "ROOT_SIGNATURE_NOT_EVALUATED"];
  }
  assert.deepEqual(got, expected);
});

for (const [entryName, verify] of ENTRIES) {
  test(`${entryName}: every row of the evaluation order, section 6`, SPEC.options, () => {
    const rows = order();
    assert.deepEqual(new Set(rows.map(([row]) => row)), new Set([...Object.keys(PATH_ROWS), ...UNREACHABLE_IN_A_BUNDLE, ...EVALUATION_ONLY]));
    const statuses = new Map(rows);
    const bundle = Bundle.linkValid().seal();
    const got: Record<string, unknown> = {};
    const expected: Record<string, unknown> = {};
    for (const [row, change] of Object.entries(PATH_ROWS)) {
      const { m, tampered } = build(bundle, change);
      // Each change makes exactly its own row's condition hold: the model and the fixtures agree.
      assert.deepEqual(pathRows(m.registryEntry as Doc, m.trustRegistry as Doc | null, tampered), new Set(row === "—" ? [] : [row]), row);
      got[row] = reported(verify(bundle, m));
      expected[row] = expectedFor(statuses.get(row)!);
    }
    assert.deepEqual(got, expected);
  });

  test(`${entryName}: the first row among those a combined run meets decides, section 6`, SPEC.options, () => {
    const rows = order();
    const listed = rows.map(([row]) => row);
    const statuses = new Map(rows);
    const bundle = Bundle.linkValid().seal();
    const got: Record<string, unknown> = {};
    const expected: Record<string, unknown> = {};
    for (const [label, { met, m }] of Object.entries(pathCombinations(bundle))) {
      got[label] = reported(verify(bundle, m));
      expected[label] = expectedFor(statuses.get(first(met, listed))!);
    }
    assert.deepEqual(got, expected);
  });

  test(`${entryName}: a trust key type outside the allowlist reaches row 16, section 6`, SPEC.options, () => {
    const statuses = new Map(order());
    const bundle = Bundle.linkValid().seal();
    const got: Record<string, unknown> = {};
    const expected: Record<string, unknown> = {};
    for (const keyType of ["ed25519", "unknown_alg"]) {
      got[keyType] = reported(verify(bundle, material(bundle, { trust: key({ key_type: keyType }) })));
      expected[keyType] = expectedFor(statuses.get("16")!);
    }
    assert.deepEqual(got, expected);
  });

  test(`${entryName}: the trust registry is evaluated only beside an entry that satisfies its contract and a link that holds, section 1`, SPEC.options, () => {
    const bundle = Bundle.linkValid().seal();
    const valid = ephemeralAuthorizationWith(bundle, {});
    const broken = ephemeralAuthorizationWith(bundle, { entry: (e) => { e.smuggled = 1; } });
    const unlinked = ephemeralAuthorizationWith(bundle, { entry: (e) => { e.policy_id = "loquitur.policy.other"; } });
    const got = {
      "no trust registry": verify(bundle, { registryEntry: valid.registryEntry }).trust_registry,
      "no registry entry": verify(bundle, { trustRegistry: valid.trustRegistry }).trust_registry,
      "entry breaks its contract": verify(bundle, { registryEntry: broken.registryEntry, trustRegistry: valid.trustRegistry }).trust_registry,
      "link does not hold": verify(bundle, { registryEntry: unlinked.registryEntry, trustRegistry: valid.trustRegistry }).trust_registry,
      "evaluated": Object.keys(verify(bundle, valid).trust_registry ?? {}).sort(),
    };
    assert.deepEqual(got, {
      "no trust registry": null,
      "no registry entry": null,
      "entry breaks its contract": null,
      "link does not hold": null,
      "evaluated": ["authorization_status", "signature_status", "trust_registry_root_signature_status"],
    });
  });

  test(`${entryName}: the coherence of a trust registry, section 3`, SPEC.options, () => {
    const cases: Record<string, (t: Doc) => void> = {
      "active-with-revoked-at": key({ revoked_at: "2026-05-01T00:00:00Z" }),
      "active-with-revocation-reason": key({ revocation_reason: "compromised" }),
      "suspended-with-revoked-at": key({ status: "suspended", revoked_at: "2026-05-01T00:00:00Z" }),
      "suspended-with-revocation-reason": key({ status: "suspended", revocation_reason: "compromised" }),
      "revoked-without-revoked-at": key({ status: "revoked", revoked_at: null }),
      "key-window-inverted": key({ effective_from: "2026-06-01T00:00:00Z" }),
      "key-window-one-second": key({ effective_from: "2026-05-10T00:00:00Z", expires_at: "2026-05-10T00:00:00Z" }),
      "registry-window-inverted": registry({ effective_at: "2026-06-01T00:00:00Z" }),
      "registry-issued-after-expiry": registry({ issued_at: "2026-06-01T00:00:00Z" }),
      "registry-issued-in-advance": registry({ issued_at: "2026-04-01T00:00:00Z" }),
      "second-entry-contradicts": (t) => { t.entries.push({ ...structuredClone(t.entries[0]), issuer_key_id: "another-key", revoked_at: "2026-05-01T00:00:00Z" }); },
      // The registry's free strings, not empty under W (section 3; bundle-objects.md, "Free
      // strings").
      "entry-issuer-key-id-blank": key({ issuer_key_id: " " }),
      "entry-display-name-blank": key({ issuer_display_name: "\u00a0" }),
      "entry-notes-blank": key({ notes: "\u3000" }),
      "entry-revocation-reason-blank": key({ status: "revoked", revoked_at: "2026-05-01T00:00:00Z", revocation_reason: " " }),
      "signature-key-id-blank": (t) => { t.signature.key_id = "\t"; },
      "entry-notes-zero-width-space": key({ notes: "\u200b" }),
    };
    const rows = table(readSpecification(SPEC, DOCUMENT), ["case", "trust registry", "contract holds"]);
    assert.deepEqual(new Set(rows.map((row) => code(row["case"]!))), new Set(Object.keys(cases)));
    const bundle = Bundle.linkValid().seal();
    const got = Object.fromEntries(rows.map((row) => [code(row["case"]!), verify(bundle, material(bundle, { trust: cases[code(row["case"]!)] })).checks.trust_registry]));
    assert.deepEqual(got, Object.fromEntries(rows.map((row) => [code(row["case"]!), row["contract holds"] === "yes"])));
  });

  test(`${entryName}: lifecycle states and inclusive windows, section 4`, SPEC.options, () => {
    const text = readSpecification(SPEC, DOCUMENT);
    const bundle = Bundle.linkValid().seal();
    const states: Record<string, Change> = {
      active: {},
      suspended: { trust: key({ status: "suspended" }) },
      revoked: { trust: key({ status: "revoked", revoked_at: "2026-06-01T00:00:00Z" }) },
    };
    const lifecycle = table(text, ["status", "meaning", "may authorize"]);
    assert.deepEqual(lifecycle.map((row) => code(row["status"]!)), Object.keys(states));
    assert.deepEqual(
      Object.fromEntries(lifecycle.map((row) => [code(row["status"]!), verify(bundle, material(bundle, states[code(row["status"]!)]!)).checks.trust_registry])),
      Object.fromEntries(lifecycle.map((row) => [code(row["status"]!), row["may authorize"]!.startsWith("yes")])),
    );
    const windows: Record<string, (t: Doc) => void> = {
      "key-effective-from-equal": key({ effective_from: EVALUATION_TIME }),
      "key-expires-at-equal": key({ expires_at: EVALUATION_TIME }),
      "registry-effective-at-equal": registry({ effective_at: EVALUATION_TIME }),
      "registry-expires-at-equal": registry({ expires_at: EVALUATION_TIME }),
      "key-expires-at-one-second-after": key({ expires_at: "2026-05-09T23:59:59Z" }),
    };
    const bounds = table(text, ["case", "evaluation time", "authorized"]);
    assert.deepEqual(new Set(bounds.map((row) => code(row["case"]!))), new Set(Object.keys(windows)));
    const run = (row: Record<string, string>) => verify(bundle, material(bundle, { trust: windows[code(row["case"]!)] }));
    assert.deepEqual(
      Object.fromEntries(bounds.map((row) => { const r = run(row); return [code(row["case"]!), [r.checks.trust_registry, r.status]]; })),
      Object.fromEntries(bounds.map((row) => [code(row["case"]!), row["authorized"] === "yes"
        ? [true, "OFFLINE_REVIEW"] // no trust root is pinned: trust_registry_root_not_pinned
        : [false, row["authorized"]!.includes("`OFFLINE_REVIEW`") ? "OFFLINE_REVIEW" : "OFFLINE_FAIL"]])),
    );
  });

  test(`${entryName}: the operator's evaluation time, and none, section 2`, SPEC.options, () => {
    const header = ["case", "operator evaluation time", "key window holds it", "outcome"];
    const rows = table(readSpecification(SPEC, DOCUMENT), header);
    const bundle = Bundle.linkValid().seal();
    // The fixture key is in effect from 2026-04-29 12:00:00 and expires 2026-05-29 12:00:00.
    const cases: Record<string, [string | undefined, Change]> = {
      "operator-time": ["2026-05-20T00:00:00Z", {}],
      "no-time-active-key": [undefined, {}],
      "no-time-revoked-key": [undefined, { trust: key({ status: "revoked", revoked_at: "2026-05-01T00:00:00Z" }) }],
      "operator-time-key-expired": ["2026-05-20T00:00:01Z", { trust: key({ expires_at: "2026-05-20T00:00:00Z" }) }],
    };
    assert.deepEqual(new Set(rows.map((row) => code(row["case"]!))), new Set(Object.keys(cases)));
    const got: Record<string, unknown> = {};
    const expected: Record<string, unknown> = {};
    for (const row of rows) {
      const name = code(row["case"]!);
      const [time, change] = cases[name]!;
      const { evaluationTime: _unused, ...documents } = material(bundle, change);
      const report = verify(bundle, time === undefined ? documents : { ...documents, evaluationTime: time });
      const spans = codes(row["outcome"]!);
      got[name] = { evaluation_time: report.evaluation_time, ...(row["outcome"]!.startsWith("authorization judged at")
        ? { trust_registry: report.checks.trust_registry }
        : { status: report.status, decided_by: report.status === "OFFLINE_FAIL" ? report.trust_registry?.authorization_status : report.outcome.reason }) };
      expected[name] = { evaluation_time: time ?? null, ...(row["outcome"]!.startsWith("authorization judged at")
        ? { trust_registry: true }
        : { status: spans[0], decided_by: spans[1] }) };
      if (row["operator evaluation time"] === "none") assert.equal(time, undefined, name);
      else if (row["operator evaluation time"]!.startsWith("`")) assert.equal(code(row["operator evaluation time"]!), time, name);
    }
    assert.deepEqual(got, expected);
  });

  test(`${entryName}: the operator's time judges every window and root authentication; issuer dates decide nothing, section 2`, SPEC.options, () => {
    const text = flatText();
    assert.ok(text.includes("The evaluation time is the operator's, and only the operator's."));
    assert.ok(text.includes("The same evaluation time is the time of root authentication (`trust-root.md` §5)."));
    assert.ok(text.includes("**Issuer dates never decide authorization.**"));
    const bundle = Bundle.linkValid().seal();
    // The fixture registry and key are in effect from 2026-04-29 12:00:00 and expire 2026-05-29
    // 12:00:00.
    const m = material(bundle, {});
    const statuses = new Map(order());
    const at = (time: string) => reported(verify(bundle, { ...m, evaluationTime: time }));
    assert.deepEqual({
      "after the registry expires": at("2026-05-29T12:00:01Z"),
      "before the registry takes effect": at("2026-04-29T11:59:59Z"),
      "inside both windows": at("2026-05-20T00:00:00Z"),
    }, {
      "after the registry expires": expectedFor(statuses.get("10")!),
      "before the registry takes effect": expectedFor(statuses.get("9")!),
      "inside both windows": expectedFor(statuses.get("—")!),
    });
    // An entry whose own dates fall outside every window changes nothing: they are not a time.
    const outside = material(bundle, { entry: (e) => { e.effective_at = "2030-01-01T00:00:00Z"; e.issued_at = "2030-01-01T00:00:00Z"; } });
    assert.deepEqual(reported(verify(bundle, { ...outside, evaluationTime: "2026-05-20T00:00:00Z" })), expectedFor(statuses.get("—")!));
    // The report names the operator's time and nothing else.
    const report = verify(bundle, { ...m, evaluationTime: "2026-05-20T00:00:00Z" });
    assert.equal(report.evaluation_time, "2026-05-20T00:00:00Z");
    assert.deepEqual(Object.keys(report.trust_registry ?? {}).sort(), ["authorization_status", "signature_status", "trust_registry_root_signature_status"]);
  });
}

const flatText = () => readSpecification(SPEC, DOCUMENT).replace(/\s+/g, " ");

test("the vocabularies of section 8 are the statuses this verifier reports", SPEC.options, () => {
  const text = readSpecification(SPEC, DOCUMENT);
  const authorization = table(text, ["`authorization_status`"]).map((row) => code(row["`authorization_status`"]!));
  const signature = table(text, ["`signature_status`"]).map((row) => code(row["`signature_status`"]!));
  assert.deepEqual(new Set(authorization), new Set(AUTHORIZATION_STATUSES));
  assert.equal(new Set(authorization).size, authorization.length);
  assert.deepEqual(new Set(signature), new Set(SIGNATURE_STATUSES));
  assert.equal(new Set(signature).size, signature.length);
  // Every status of the order table is a value of its vocabulary.
  for (const [, [authorizationStatus, signatureStatus]] of order()) {
    assert.ok(authorization.includes(authorizationStatus!), authorizationStatus!);
    assert.ok(signatureStatus === null || signature.includes(signatureStatus), String(signatureStatus));
  }
  assert.ok(codes(text).includes("ROOT_SIGNATURE_NOT_EVALUATED"));
});

test("a supplied evaluation time is the operator's bare instant, refused before any evidence is read when it is not one, section 2", SPEC.options, () => {
  const text = flatText();
  assert.ok(text.includes("It **MUST** be a calendar instant of the form `YYYY-MM-DDTHH:MM:SSZ`"));
  assert.ok(text.includes("a verifier refuses any other value before evaluating anything"));
  const bundle = Bundle.linkValid().seal();
  const m = ephemeralAuthorizationWith(bundle, {});
  const files: Record<string, Uint8Array> = {};
  for (const [name, data] of bundle.files) Object.defineProperty(files, name, { value: data, enumerable: true });
  const calls: string[] = [];
  const inner = bundleReaderFromMap(files);
  const recording = {
    readText(name: string) { calls.push(name); return inner.readText(name); },
    readBytes(name: string) { calls.push(name); return inner.readBytes!(name); },
    listMembers() { calls.push("listMembers"); return inner.listMembers!(); },
  };
  const refused = ["", "2026-02-30T00:00:00Z", "2026-04-29T12:00:60Z", "2026-05-10T00:00:00+00:00", "2026-05-10T00:00:00.000Z", "2026-05-10 00:00:00Z", "2026-05-10", "2026-05-10T00:00:00z", 7, null];
  for (const value of refused) {
    assert.throws(() => verifyBundleFiles(recording, { registryEntry: m.registryEntry, trustRegistry: m.trustRegistry, evaluationTime: value }), EvaluationTimeError, JSON.stringify(value));
    // Given without a trust registry, the time is still refused, before any read.
    assert.throws(() => verifyBundleFiles(recording, { evaluationTime: value }), EvaluationTimeError, JSON.stringify(value));
    assert.throws(() => evaluateTrustRegistry(m.registryEntry, m.trustRegistry, { evaluationTime: value }), EvaluationTimeError, JSON.stringify(value));
  }
  assert.deepEqual(calls, []);
  // A well-formed time given without a trust registry is validated, reported and otherwise unused.
  const alone = verifyBundleFiles(recording, { evaluationTime: "2026-05-20T00:00:00Z" });
  assert.deepEqual(outcome(alone), PASS);
  assert.equal(alone.trust_registry, null);
  assert.ok(calls.length > 0);
});

// Rows 18 and 19 compare the key identifiers exactly (section 5), whatever they hold. A key id made
// only of the whitespace set W is still a value, compared as written: whether the entry's contract
// accepts one is a question for the contract (row 2), not a reason to skip the comparison here.
test("the key identifiers of rows 18 and 19 are compared as written, sections 5 and 6", SPEC.options, () => {
  const flat = readSpecification(SPEC, DOCUMENT).replace(/\s+/g, " ");
  assert.ok(flat.includes("are exact equality of code units: nothing is trimmed, case-folded or normalised"));
  const statuses = new Map(order());
  const bundle = Bundle.linkValid().seal();
  // [authorized issuer_key_id, entry issuer_key_id, signature key_id] -> the row that decides
  const cases: Record<string, [[string, string, string], string]> = {
    "whitespace-ids-differ-in-the-signature": [[" ", " ", "\u00a0"], "18"],
    "whitespace-ids-differ-in-the-entry": [[" ", "\u00a0", " "], "19"],
    "whitespace-ids-agree": [[" ", " ", " "], "—"],
    "signature-id-with-a-trailing-space": [["demo-key-2", "demo-key-2", "demo-key-2 "], "18"],
    "signature-id-in-another-case": [["demo-key-2", "demo-key-2", "DEMO-KEY-1"], "18"],
    "signature-id-in-another-normalization-form": [["caf\u00e9", "caf\u00e9", "cafe\u0301"], "18"],
  };
  const got: Record<string, unknown> = {};
  const expected: Record<string, unknown> = {};
  for (const [label, [[authorized, entryId, signatureId], row]] of Object.entries(cases)) {
    const m = ephemeralAuthorizationWith(bundle, { entry: (e) => { e.issuer_key_id = entryId; e.signature.key_id = signatureId; } });
    const result = verifyRegistryEntrySignature(m.registryEntry, m.trustRegistry.entries[0].public_key_hex, { expectedKeyId: authorized, keyType: "secp256k1" });
    got[label] = result.status;
    expected[label] = statuses.get(row)![1];
  }
  assert.deepEqual(got, expected);
});

// Row 6 also stops a key whose point another trust entry carries, in any SEC1 encoding, whatever the
// statuses, the issuers and the key types of the entries: revocation is of the key, not of its
// label. A value that encodes no point shares none, and the comparison is of points, not strings.
test("a key's point under another trust entry is ambiguous; a value that encodes no point shares none, section 6", () => {
  const bundle = Bundle.linkValid().seal();
  const revoked = { status: "revoked", revoked_at: "2026-05-01T00:00:00Z", revocation_reason: "compromised" };
  /** The found entry (entries[0], demo-key-2), and a second trust entry made from it by `other`. */
  const run = (other: (found: Doc) => Doc, found: (t: Doc) => void = () => {}) => {
    const { registryEntry, trustRegistry } = ephemeralAuthorizationWith(bundle, {
      trust: (t) => { t.entries.push(other(structuredClone(t.entries[0]))); found(t); },
    });
    const result = evaluateTrustRegistry(registryEntry, trustRegistry, { evaluationTime: EVALUATION_TIME });
    return [result.authorization_status, result.signature_status];
  };
  const as = (fields: Doc) => (copy: Doc): Doc => Object.assign(copy, { issuer_key_id: "demo-key-9", notes: "the same key under another id" }, fields);
  const key = (hex: string) => (t: Doc) => { t.entries[0].public_key_hex = hex; };
  const AMBIGUOUS = ["TRUST_REGISTRY_AMBIGUOUS_KEY", null];
  const SIGNED = [AUTHORIZED, "VALID_SIGNATURE"];
  const UNVERIFIED = [AUTHORIZED, "SIGNATURE_INVALID"];
  assert.deepEqual({
    "two ids, one key, the other revoked": run(as(revoked)),
    "two ids, one key, the found one revoked": run(as({}), (t) => Object.assign(t.entries[0], revoked)),
    "two ids, one key, both active": run(as({})),
    "compressed beside uncompressed": run((copy) => as({ public_key_hex: compressedKey(copy.public_key_hex) })(copy)),
    "two issuers, one key, one key id": run((copy) => Object.assign(copy, { issuer_id: "issuer_someone_else" })),
    "two issuers, one key, two key ids": run(as({ issuer_id: "issuer_someone_else" })),
    "another key type with the same point": run((copy) => as({ key_type: "ed25519", public_key_hex: compressedKey(copy.public_key_hex) })(copy)),
    "a hybrid encoding of the same point": run((copy) => as({ public_key_hex: hybridKey(copy.public_key_hex) })(copy)),
    "the same X with no Y": run((copy) => as({ public_key_hex: copy.public_key_hex.slice(0, 66) })(copy)),
    "the point at infinity": run(as({ public_key_hex: "00" })),
    "another key": run(as({ public_key_hex: SMALL_Y_POINT })),
    // Row 7 reads the found entry's status, not any entry's.
    "another key, revoked": run(as({ public_key_hex: SMALL_Y_POINT, ...revoked })),
    // The same issuer_key_id under another issuer_id is not a label duplicate (row 6 counts the
    // issuer's entries), and with a key of its own it shares no point.
    "one key id under another issuer, another key": run((copy) => Object.assign(copy, { issuer_id: "issuer_someone_else", public_key_hex: SMALL_Y_POINT })),
    // Two other entries sharing a point with each other leave the found entry, which names
    // neither, authorized: the rule compares the found entry's point and no other pair.
    "two other entries sharing a point, neither the found one's": run(as({ public_key_hex: SMALL_Y_POINT }), (t) => {
      t.entries.push(as({ public_key_hex: SMALL_Y_POINT, issuer_key_id: "demo-key-8", issuer_id: "issuer_someone_else" })(structuredClone(t.entries[0])));
    }),
    // The found key is the one below; no private key is known for it, so a run that passes row 6
    // stops at the signature. A reader that reduced a coordinate modulo p would stop at row 6.
    "X plus p beside X": run(as({ public_key_hex: SMALL_X_PLUS_P }), key(SMALL_X_POINT)),
    "X plus p compressed beside X": run(as({ public_key_hex: SMALL_X_PLUS_P_COMPRESSED }), key(SMALL_X_POINT)),
    "Y plus p beside Y": run(as({ public_key_hex: SMALL_Y_PLUS_P }), key(SMALL_Y_POINT)),
    "a small point compressed beside it": run(as({ public_key_hex: compressedKey(SMALL_X_POINT) }), key(SMALL_X_POINT)),
    "two values that encode no point, written alike": run(as({ public_key_hex: "ab".repeat(32) }), key("ab".repeat(32))),
  }, {
    "two ids, one key, the other revoked": AMBIGUOUS,
    "two ids, one key, the found one revoked": AMBIGUOUS,
    "two ids, one key, both active": AMBIGUOUS,
    "compressed beside uncompressed": AMBIGUOUS,
    "two issuers, one key, one key id": AMBIGUOUS,
    "two issuers, one key, two key ids": AMBIGUOUS,
    "another key type with the same point": AMBIGUOUS,
    "a hybrid encoding of the same point": SIGNED,
    "the same X with no Y": SIGNED,
    "the point at infinity": SIGNED,
    "another key": SIGNED,
    "another key, revoked": SIGNED,
    "one key id under another issuer, another key": SIGNED,
    "two other entries sharing a point, neither the found one's": SIGNED,
    "X plus p beside X": UNVERIFIED,
    "X plus p compressed beside X": UNVERIFIED,
    "Y plus p beside Y": UNVERIFIED,
    "a small point compressed beside it": AMBIGUOUS,
    "two values that encode no point, written alike": UNVERIFIED,
  });
  // Upper case: the trust registry's contract refuses it before any key is compared (section 3,
  // public_key_hex is lowercase), and the comparison, which never lower-cases, finds no point in it.
  const { registryEntry, trustRegistry } = ephemeralAuthorizationWith(bundle, {
    trust: (t) => { t.entries.push(as({ public_key_hex: t.entries[0].public_key_hex.toUpperCase() })(structuredClone(t.entries[0]))); },
  });
  assert.equal(evaluateTrustRegistry(registryEntry, trustRegistry, { evaluationTime: EVALUATION_TIME }).authorization_status, "INVALID_TRUST_REGISTRY");
  const lower: string = trustRegistry.entries[0].public_key_hex;
  assert.deepEqual([secp256k1Point(lower)?.length, secp256k1Point(lower.toUpperCase()), secp256k1Point(`04${lower.slice(2).toUpperCase()}`)], [130, null, null]);
  // The package's reading of a point is the model's, over every value above.
  for (const hex of [lower, compressedKey(lower), hybridKey(lower), SMALL_X_POINT, SMALL_X_PLUS_P, SMALL_X_PLUS_P_COMPRESSED, SMALL_Y_POINT, SMALL_Y_PLUS_P, "00", "ab".repeat(32)]) {
    const point = pointOf(hex);
    assert.equal(secp256k1Point(hex), point === null ? null : `04${point}`, hex);
  }
});
