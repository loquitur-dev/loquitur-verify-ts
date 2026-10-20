// scripts/public-api-parity.json, the public API parity map, against what this package exports.
//
// The map lists every name src/index.ts and src/index.browser.ts export, values and types, every
// member of a result an exported function returns, and every per-check result a run writes that
// carries a verdict, a status, an authorization, a signature, a root or a trust result, each with
// its counterpart in loquitur-verify-py or none and the reason. A member carries one when the last
// segment of its name matches the map's carrier_pattern. These tests fail when such a member or an
// export is missing from the map, when the map names something this package no longer has, and,
// where the sibling is checked out, when the map differs from loquitur-verify-py
// tools/public_api_parity.json, which must be the same file byte for byte (LOQUITUR_REQUIRE_SIBLINGS
// makes the sibling required).
//
// The exports and the members are read with the TypeScript compiler from the sources, so a type
// export, which has no run-time name, is held to the map as a value is.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import ts from "typescript";
import { Bundle, ephemeralAuthorization, ephemeralRoot, PACKAGE_DIR, rootDocument, verifyInMemory } from "./bundle-kit.ts";
import { sibling } from "./siblings.ts";

interface Pair {
  id: string;
  carries: string[];
  py: string[];
  ts: string[];
  ts_reason?: string;
  py_reason?: string;
  ops: string[];
}
interface ParityMap {
  schema_version: string;
  carrier_pattern: string;
  pairs: Pair[];
  ts_not_carrying: { names: string[] };
  py_not_carrying: { names: string[] };
}

const MAP_PATH = join(PACKAGE_DIR, "scripts", "public-api-parity.json");
const PARITY: ParityMap = JSON.parse(readFileSync(MAP_PATH, "utf8"));
const CARRIER = new RegExp(PARITY.carrier_pattern);
const INTERNAL = "internal:";
const TS_NAMES = PARITY.pairs.flatMap((pair) => pair.ts);
const NOT_CARRYING = PARITY.ts_not_carrying.names;

/** Whether a member name carries a result: its last segment, camelCase read as snake_case, matches the pattern. */
const carries = (name: string): boolean =>
  CARRIER.test(name.split(".").at(-1)!.replace(/[A-Z]/g, (c) => `_${c.toLowerCase()}`));

const program = ts.createProgram([join(PACKAGE_DIR, "src", "index.ts"), join(PACKAGE_DIR, "src", "index.browser.ts")], {
  module: ts.ModuleKind.NodeNext,
  moduleResolution: ts.ModuleResolutionKind.NodeNext,
  target: ts.ScriptTarget.ES2022,
  strict: true,
  skipLibCheck: true,
  noEmit: true,
});
const checker = program.getTypeChecker();
const SRC = join(PACKAGE_DIR, "src").replace(/\\/g, "/");

function entryExports(entry: string): ts.Symbol[] {
  const file = program.getSourceFile(join(PACKAGE_DIR, "src", entry))!;
  return checker.getExportsOfModule(checker.getSymbolAtLocation(file)!);
}
const EXPORTS = [...entryExports("index.ts"), ...entryExports("index.browser.ts")];
const EXPORT_NAMES = new Set(EXPORTS.map((symbol) => symbol.name));

const resolved = (symbol: ts.Symbol): ts.Symbol => (symbol.flags & ts.SymbolFlags.Alias ? checker.getAliasedSymbol(symbol) : symbol);
const inSrc = (declarations: readonly ts.Declaration[] | undefined): boolean =>
  (declarations ?? []).some((d) => d.getSourceFile().fileName.replace(/\\/g, "/").startsWith(SRC));

/**
 * Every member path reachable from the results of the exported functions and from the exported
 * types: TYPE.MEMBER, and TYPE.MEMBER.MEMBER through an anonymous object type. A named type of the
 * package met inside another starts its own paths.
 */
function memberPaths(): Map<string, ts.Type> {
  const found = new Map<string, ts.Type>();
  const visited = new Set<string>();
  const objectOfSrc = (type: ts.Type): boolean =>
    type.isUnion() ? type.types.some(objectOfSrc)
    : checker.isArrayType(type) ? objectOfSrc(checker.getTypeArguments(type as ts.TypeReference)[0]!)
    : !!(type.flags & ts.TypeFlags.Object) && inSrc((type.aliasSymbol ?? type.getSymbol())?.declarations);
  const walk = (type: ts.Type, path: string): void => {
    // A named type of the package (an interface, or an alias such as ProtocolParseResult) starts
    // its own paths, once.
    const alias = type.aliasSymbol && inSrc(type.aliasSymbol.declarations) ? type.aliasSymbol.name : null;
    if (alias !== null) {
      if (visited.has(alias)) return;
      visited.add(alias);
      path = alias;
    }
    if (type.isUnion()) {
      for (const part of type.types) walk(part, path);
      return;
    }
    if (checker.isArrayType(type)) {
      walk(checker.getTypeArguments(type as ts.TypeReference)[0]!, path);
      return;
    }
    if (!(type.flags & ts.TypeFlags.Object)) return;
    const symbol = type.getSymbol();
    if (!symbol || !inSrc(symbol.declarations)) return;
    const named = alias === null && symbol.name !== "__type" && symbol.name !== "__object" ? symbol.name : null;
    if (named !== null) {
      if (visited.has(named)) return;
      visited.add(named);
    }
    const base = named ?? path;
    for (const property of checker.getPropertiesOfType(type)) {
      if (!inSrc(property.declarations)) continue;
      const name = `${base}.${property.name}`;
      const propertyType = checker.getNonNullableType(checker.getTypeOfSymbol(property));
      // A member that holds a section of the package's own types is walked, not listed: its
      // members are.
      if (objectOfSrc(propertyType)) walk(propertyType, name);
      else found.set(name, propertyType);
    }
  };
  for (const symbol of EXPORTS) {
    const target = resolved(symbol);
    if (target.flags & ts.SymbolFlags.Function) {
      for (const signature of checker.getTypeOfSymbol(target).getCallSignatures()) walk(signature.getReturnType(), symbol.name);
    }
    // An exported type is walked unless the map says it carries no result: the wire types of the
    // documents and the options are inputs.
    if (target.flags & (ts.SymbolFlags.Interface | ts.SymbolFlags.TypeAlias) && !NOT_CARRYING.includes(symbol.name)) {
      walk(checker.getDeclaredTypeOfSymbol(target), symbol.name);
    }
  }
  return found;
}
const MEMBERS = memberPaths();

/** The per-check results of a run that evaluated every check: VerifyReport.checks.NAME. */
function runChecks(): string[] {
  const bundle = Bundle.linkValid();
  const { root, sign } = ephemeralRoot();
  const { registryEntry, trustRegistry } = ephemeralAuthorization(bundle);
  sign(trustRegistry);
  const report = verifyInMemory(bundle, {
    registryEntry,
    trustRegistry,
    trustRoots: rootDocument([root]),
    evaluationTime: "2026-05-10T00:00:00Z",
  });
  assert.equal(report.status, "OFFLINE_OK", JSON.stringify(report.errors));
  return Object.keys(report.checks).map((name) => `VerifyReport.checks.${name}`);
}
const CHECKS = runChecks();

test("the map is one document with disjoint, unique names", () => {
  assert.equal(PARITY.schema_version, "loquitur.public_api_parity.v1");
  const ids = PARITY.pairs.map((pair) => pair.id);
  assert.equal(new Set(ids).size, ids.length);
  const names = [...TS_NAMES, ...NOT_CARRYING];
  assert.equal(new Set(names).size, names.length, "a name of this package is listed twice");
  for (const pair of PARITY.pairs) {
    assert.ok(pair.carries.length > 0, pair.id);
    assert.ok(pair.ts.length > 0 || pair.ts_reason, pair.id);
    assert.ok(pair.py.length > 0 || pair.py_reason, pair.id);
  }
  const raw = readFileSync(MAP_PATH);
  assert.ok(raw[0] !== 0xef && raw.at(-1) === 0x0a && !raw.includes(0x0d));
});

test("every name either entry exports, value or type, is in the map", () => {
  const listed = new Set([...TS_NAMES, ...NOT_CARRYING]);
  const missing = [...EXPORT_NAMES].filter((name) => !listed.has(name)).sort();
  assert.deepEqual(missing, [], `exported and not in scripts/public-api-parity.json: ${missing.join(", ")}`);
});

test("every name the map lists is still there", async () => {
  const gone: string[] = [];
  for (const name of [...TS_NAMES, ...NOT_CARRYING]) {
    if (name.startsWith(INTERNAL)) {
      const [file, member] = name.slice(INTERNAL.length).split("#") as [string, string];
      const module = await import(pathToFileURL(join(PACKAGE_DIR, file)).href);
      if (typeof module[member] !== "function") gone.push(name);
      // An internal function is not an export of either entry.
      if (EXPORT_NAMES.has(member)) gone.push(`${name} (exported)`);
    } else if (!name.includes(".")) {
      if (!EXPORT_NAMES.has(name)) gone.push(name);
    } else if (!MEMBERS.has(name) && !CHECKS.includes(name)) {
      gone.push(name);
    }
  }
  assert.deepEqual(gone, [], `scripts/public-api-parity.json names what this package no longer has: ${gone.join(", ")}`);
});

test("every member of a returned result or an exported type that carries a result is in the map", () => {
  const listed = new Set([...TS_NAMES, ...NOT_CARRYING]);
  const missing = [...MEMBERS.keys(), ...CHECKS].filter((name) => carries(name) && !listed.has(name)).sort();
  assert.deepEqual(missing, [], `members that carry a result and are not in the map: ${missing.join(", ")}`);
  // The walk reached the results the review was about.
  for (const name of ["TrustRegistryReport.authorization_status", "VerifyReport.verdict", "SignatureVerificationResult.status", "VerifyReport.checks.trust_registry"]) {
    assert.ok(MEMBERS.has(name) || CHECKS.includes(name), name);
  }
});

test("the trust registry's verdict has a counterpart: trustRegistryVerdict", () => {
  const pair = PARITY.pairs.find((p) => p.id === "trust_registry_verdict")!;
  assert.deepEqual(pair.ts, ["internal:src/verify-core.ts#trustRegistryVerdict"]);
  assert.ok(pair.py.includes("loquitur.verify.trust_registry.TrustRegistryVerificationResult.verdict"));
});

const py = sibling(
  "loquitur-verify-py",
  [join(PACKAGE_DIR, "..", "loquitur-verify-py")],
  join("tools", "public_api_parity.json"),
  "loquitur-verify-py is not checked out beside this package",
);

test("the map is loquitur-verify-py's map, byte for byte", py.options, () => {
  const theirs = readFileSync(py.path(join("tools", "public_api_parity.json")));
  assert.ok(readFileSync(MAP_PATH).equals(theirs), "scripts/public-api-parity.json and loquitur-verify-py tools/public_api_parity.json differ");
});
