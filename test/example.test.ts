// examples/verify-test-vectors.mjs is the example README.md tells a reader to run. It imports the
// package by name, which resolves to the build in dist/src; here it runs against the source this
// suite tests, with that one import pointed at src/index.ts, and its output and exit status are
// held. CI's packaging job runs it unchanged against the build, and against the packed tarball
// installed into a new project.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import test from "node:test";

const PACKAGE_DIR = fileURLToPath(new URL("..", import.meta.url));
const EXAMPLE = join(PACKAGE_DIR, "examples", "verify-test-vectors.mjs");
const VECTORS = join(PACKAGE_DIR, "test-vectors");
const README = join(PACKAGE_DIR, "README.md");
const IMPORT = 'from "@loquitur/verify";';

/** The lines of the output block README.md's "Try it" section shows for the example. */
function readmeOutputBlock(): string[] {
  const text = readFileSync(README, "utf8").replace(/\r\n/g, "\n");
  const section = text.split("\n## Try it\n")[1];
  assert.ok(section !== undefined, "README.md has no \"## Try it\" section");
  const block = /^```text\n([\s\S]*?)^```$/m.exec(section.split("\n## ")[0]!);
  assert.ok(block !== null, "the \"Try it\" section shows no text block");
  return block[1]!.replace(/\n$/, "").split("\n");
}

function runExample(vectorsDir: string): { status: number | null; stdout: string; stderr: string } {
  const text = readFileSync(EXAMPLE, "utf8");
  assert.equal(text.split(IMPORT).length, 2, "the example does not import the package by name exactly once");
  const source = pathToFileURL(join(PACKAGE_DIR, "src", "index.ts")).href;
  const dir = mkdtempSync(join(tmpdir(), "loquitur-example-"));
  try {
    const copy = join(dir, "verify-test-vectors.mjs");
    writeFileSync(copy, text.replace(IMPORT, `from ${JSON.stringify(source)};`));
    const run = spawnSync(process.execPath, ["--import", "tsx", copy, vectorsDir], { cwd: PACKAGE_DIR, encoding: "utf8" });
    return { status: run.status, stdout: run.stdout, stderr: run.stderr };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("the README example verifies every case it names as test-vectors/verify.json records", () => {
  const run = runExample(VECTORS);
  assert.equal(run.status, 0, run.stdout + run.stderr);
  const lines = run.stdout.trim().split(/\r?\n/);
  assert.deepEqual(
    lines.map((line) => line.split(/\s+/).slice(0, 4).join(" ")),
    [
      "valid PASS exit 0",
      "tampered FAIL exit 1",
      "link PASS exit 0",
      "authorization_valid REVIEW exit 2",
      "authorization_revoked FAIL exit 1",
      "all 5 reports match",
    ],
  );
  assert.ok(!run.stdout.includes("differs"), run.stdout);
});

test("the README shows exactly what the example prints, every line and every token", () => {
  // Whole lines, not their first tokens: a reason or a status the README names and the example
  // does not print (evaluation_time_not_provided in place of trust_registry_root_not_pinned) is a
  // README that does not run as written.
  const run = runExample(VECTORS);
  assert.equal(run.status, 0, run.stdout + run.stderr);
  assert.deepEqual(run.stdout.replace(/\r\n/g, "\n").replace(/\n$/, "").split("\n"), readmeOutputBlock());
  // The authorization cases are judged at the evaluation time the record names, as the quickstart
  // passes it, so the README's REVIEW is for the missing trust root alone.
  const recorded = JSON.parse(readFileSync(join(VECTORS, "verify.json"), "utf8"));
  for (const name of ["authorization_valid", "authorization_revoked"]) {
    assert.equal(recorded[name].evaluation_time, "2026-05-20T00:00:00Z", name);
  }
  assert.match(run.stdout, /^authorization_valid +REVIEW +exit 2 +trust_registry_root_not_pinned /m);
});

test("the README example exits 1 and names the difference when a report differs from the record", () => {
  const dir = mkdtempSync(join(tmpdir(), "loquitur-example-vectors-"));
  try {
    cpSync(VECTORS, dir, { recursive: true });
    // One byte of the valid bundle's P1 changes, so its report differs from the PASS recorded for
    // it.
    const p1 = join(dir, "bundles", "valid_bundle", "p1.json");
    const bytes = readFileSync(p1);
    const at = bytes.indexOf(0x22, 1);
    bytes[at + 1] = bytes[at + 1] === 0x61 ? 0x62 : 0x61;
    writeFileSync(p1, bytes);
    const run = runExample(dir);
    assert.equal(run.status, 1, run.stdout + run.stderr);
    assert.match(run.stdout, /^valid +FAIL +exit 1 /m);
    assert.match(run.stdout, /^ {2}differs: verdict FAIL, recorded PASS$/m);
    assert.match(run.stdout, /^1 of 5 reports differ from test-vectors\/verify\.json$/m);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
