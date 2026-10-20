// The verdict path contains no network access and no AI: enforced, and shown to be able to
// fail. scripts/check-verdict-path-isolation.mjs is the gate and its header states the rule
// it applies, an allow-list of three clauses, and what it does not read. These tests run it on
// this package, then feed it each form of import, global and dependency it exists to refuse
// (under names nobody enumerated, because an allow-list needs no list of what it refuses), and
// require each to be named. A check that has only ever been seen passing has not been shown
// to check anything.
import { test } from "node:test";
import assert from "node:assert/strict";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  REVIEWED_RUNTIME_CLOSURE,
  checkDependencies,
  checkPackage,
  disallowedReason,
  scanSource,
} from "../scripts/check-verdict-path-isolation.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const manifest = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const lock = JSON.parse(readFileSync(join(root, "package-lock.json"), "utf8"));
const clone = <T,>(o: T): T => JSON.parse(JSON.stringify(o));

test("this package passes: sources, runtime closure and lockfile", () => {
  const { violations, files, closure } = checkPackage(root);
  assert.deepEqual(violations, []);
  assert.ok(files >= 10, `only ${files} source files read`);
  assert.deepEqual(closure, ["@noble/curves", "@noble/hashes", "canonicalize"]);
  assert.deepEqual([...REVIEWED_RUNTIME_CLOSURE].sort(), closure);
});

test("the allow-list is the rule the header states", () => {
  for (const name of ["node:net", "net", "node:tls", "node:http", "node:https", "node:dgram", "node:http2", "node:dns/promises", "cluster", "node:inspector", "_http_client"]) {
    assert.equal(disallowedReason(name), "network", name);
  }
  // Packages outside the closure are refused whether or not they exist: the names below are
  // invented, and `typescript` and `fast-check` are development dependencies installed wherever
  // this runs.
  for (const name of ["some-model-sdk", "@example/model-client", "@example/model-client/chat", "an-http-client", "typescript", "undici-types", "fast-check", "pure-rand"]) {
    assert.match(disallowedReason(name) ?? "", /^outside the runtime dependency closure \[/, name);
  }
  assert.equal(disallowedReason("node:some-future-module"), "not a built-in module");
  for (const name of ["./verify.js", "../src/types.js", "node:fs", "fs", "node:path", "node:crypto", "@noble/curves/secp256k1", "@noble/hashes/sha256", "canonicalize"]) {
    assert.equal(disallowedReason(name), null, name);
  }
  // The closure the sources are judged against is the one the lockfile resolves.
  assert.equal(disallowedReason("some-model-sdk", ["some-model-sdk"]), null);
});

const PLANTED: Array<[string, string]> = [
  ['import { connect } from "node:net";', "import of node:net (network)"],
  ['import * as tls from "tls";', "import of tls (network)"],
  ['export { request } from "node:https";', "export-from of node:https (network)"],
  ['import http = require("http");', "import-require of http (network)"],
  ['const dgram = require("node:dgram");', "require of node:dgram (network)"],
  ['async function later() { return import("node:http2"); }', "dynamic import of node:http2 (network)"],
  ['const response = await fetch("https://example.invalid/entry.json");', "use of fetch"],
  ["const request = new XMLHttpRequest();", "use of XMLHttpRequest"],
  ["export function open(url: string) { return new WebSocket(url); }", "use of WebSocket"],
  ['const f = (globalThis as Record<string, unknown>)["fetch"];', '"fetch" as a key'],
  ['import Model from "some-model-sdk";', "import of some-model-sdk (outside the runtime dependency closure"],
  ['import { Client } from "@example/model-client";', "import of @example/model-client (outside the runtime dependency closure"],
  ['import type { Options } from "@example/model-client/options";', "import of @example/model-client/options (outside"],
  ['import ts from "typescript";', "import of typescript (outside the runtime dependency closure"],
  ['const name = "no" + "de:net"; await import(name);', "not a literal"],
  ['eval("1");', "eval() cannot be checked"],
];

for (const [planted, named] of PLANTED) {
  test(`the source check names a planted ${named}`, () => {
    const violations = scanSource("src/planted.ts", `export const x = 1;\n${planted}\n`);
    assert.ok(violations.some((v) => v.includes(named) && v.startsWith("src/planted.ts:2")), JSON.stringify(violations));
  });
}

test("the source check reads syntax, not words", () => {
  const text = [
    "// This file does not fetch anything and does not import node:net or some-model-sdk.",
    'import { sha256 } from "@noble/hashes/sha256";',
    'export const note = "no network, no fetch() call, no model SDK";',
  ].join("\n");
  assert.deepEqual(scanSource("src/benign.ts", text), []);
});

test("a source that does not parse is a failure, not a pass", () => {
  assert.ok(scanSource("src/broken.ts", "import { from").length > 0);
});

test("a package the lockfile reaches from no declared dependency, or a network built-in named as a dependency, fails", () => {
  const l = clone(lock);
  l.packages["node_modules/some-model-client"] = { version: "1.0.0" };
  l.packages["node_modules/@example/sdk"] = { version: "0.30.0", dev: true };
  const { violations } = checkDependencies(manifest, l);
  assert.ok(violations.includes("lockfile contains some-model-client, which no runtime or development dependency reaches"), JSON.stringify(violations));
  assert.ok(violations.includes("lockfile contains @example/sdk, which no runtime or development dependency reaches"), JSON.stringify(violations));

  const m = clone(manifest);
  m.dependencies.net = "^1.0.0";
  assert.ok(checkDependencies(m, lock).violations.includes("package.json names net (network)"));
});

test("a runtime closure that is not the reviewed one fails, whether it grows through package.json or through a transitive requirement", () => {
  const m = clone(manifest);
  const l = clone(lock);
  m.dependencies["some-model-sdk"] = "^1.0.0";
  l.packages[""].dependencies["some-model-sdk"] = "^1.0.0";
  l.packages["node_modules/some-model-sdk"] = { version: "1.0.0" };
  const direct = checkDependencies(m, l);
  assert.ok(direct.violations.some((v) => v.startsWith("the runtime dependency closure is [@noble/curves, @noble/hashes, canonicalize, some-model-sdk], not the reviewed closure")), JSON.stringify(direct.violations));

  const t = clone(lock);
  t.packages["node_modules/@noble/curves"].dependencies = { ...t.packages["node_modules/@noble/curves"].dependencies, "some-transitive-package": "^1.0.0" };
  t.packages["node_modules/some-transitive-package"] = { version: "1.0.0" };
  const transitive = checkDependencies(manifest, t);
  assert.ok(transitive.violations.some((v) => v.includes("some-transitive-package], not the reviewed closure")), JSON.stringify(transitive.violations));
  // The package is in the resolved closure and so would be admitted by the source check; the
  // closure violation is what refuses it, which is why the closure is pinned.
  assert.ok(transitive.closure.includes("some-transitive-package"));
});

test("a closure the lockfile cannot resolve, or a lockfile out of step with package.json, fails", () => {
  const l = clone(lock);
  delete l.packages["node_modules/canonicalize"];
  assert.ok(checkDependencies(manifest, l).violations.some((v) => v.includes("canonicalize") && v.includes("not in the lockfile")));
  const m = clone(manifest);
  m.dependencies["left-pad"] = "^1.0.0";
  assert.ok(checkDependencies(m, lock).violations.some((v) => v.includes("lockfile root declares")));
  assert.ok(checkDependencies(manifest, {}).violations.length > 0);
});

test("the whole check fails on a scratch copy with a planted import, and passes once it is removed", () => {
  const scratch = mkdtempSync(join(tmpdir(), "lqts-isolation-"));
  try {
    cpSync(join(root, "src"), join(scratch, "src"), { recursive: true });
    cpSync(join(root, "package.json"), join(scratch, "package.json"));
    cpSync(join(root, "package-lock.json"), join(scratch, "package-lock.json"));
    assert.deepEqual(checkPackage(scratch).violations, []);
    const target = join(scratch, "src", "verify.ts");
    const original = readFileSync(target, "utf8");
    writeFileSync(target, `import { connect } from "node:net";\n${original}`);
    assert.ok(checkPackage(scratch).violations.some((v) => v.includes("src/verify.ts:1: import of node:net (network)")));
    writeFileSync(target, `import { Client } from "@example/model-client";\n${original}`);
    assert.ok(checkPackage(scratch).violations.some((v) => v.includes("src/verify.ts:1: import of @example/model-client (outside the runtime dependency closure [@noble/curves, @noble/hashes, canonicalize])")));
    writeFileSync(target, original);
    assert.deepEqual(checkPackage(scratch).violations, []);
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});
