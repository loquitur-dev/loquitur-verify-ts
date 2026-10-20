// A stack the host runs out of is a fault of the host, never a verdict. Every document and value is
// held to input strictness rule 6's 64 levels by an iterative walk before any recursive step, so
// the verifier only recurses on values the protocol admits, and a RangeError there says the host's
// stack is too small, not that the evidence is wrong. It propagates, as the Python verifier's
// RecursionError does (report-contract.md section 4). Contained, it would turn the same valid
// authorization run with trust roots, run with little stack left, into OFFLINE_FAIL,
// SIGNATURE_INVALID or ROOT_SIGNATURE_INVALID, depending on where the stack ran out.
//
// The run is tried with less and less of the stack left, one frame at a time, from the deepest
// point at which it starts at all up to where it completes, so each step of the verifier meets the
// end of the stack somewhere. Each try either gives the report the run gives with the whole stack,
// or throws the stack's own error: a RangeError, or the SyntaxError V8 raises when the stack runs
// out inside a regular expression.
//
// The climbs of a run are made in a child process, test/stack-climb.ts, one after another as in a
// single process: the first meets the run cold, and each later one meets it as the climbs before it
// have left the engine, so the end of the stack falls on a different step from one climb to the
// next. The child writes each try as soon as it is made. On some V8 builds, compiling a regular
// expression with no stack left ends the process: the engine writes its fatal error report and
// aborts where it would otherwise throw. Nothing in the verifier can catch that, and it gives no
// report, so it is a fault of the host and never a verdict: the try is counted as a host abort, and
// the climbs go on in a fresh child from the next depth. A child that ends any other way, without
// that report, fails the test.
//
// The same holds where the package reads from the file system: readDocumentPath, which a host uses
// to read the entry, the trust registry and the trust roots, and verifyBundle's inventory, member
// reads and input inspection. Their catches classify what the host refuses; one that caught the
// stack's own error with the rest would give a valid document read with little stack left as null
// or DOCUMENT_READ_FAILED, and a run given that value would give OFFLINE_FAIL or a TrustRootError.
// verifyBundle's are tried on inputs whose run ends at the inspection of its input: a missing path,
// a file, an empty directory and a manifest.json that is not JSON. On a valid bundle a later step
// of the run needs more stack than any read, so the end of the stack is met there first; on these
// the inspection's catches are the deepest step, and one that caught the stack's own error would
// give filesystem_error.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { verifyBundle } from "../src/verify.ts";
import { Bundle, ephemeralAuthorizationWith, ephemeralRoot, authorizationOutcome, PACKAGE_DIR, rootDocument, TEST_DIR, tempDir } from "./bundle-kit.ts";
import type { Climbs, Run } from "./stack-climb.ts";

/** The flags this file runs under, its tsx import and any stack flag among them, less the test runner's own. */
const FLAGS = process.execArgv.filter((flag) => !flag.startsWith("--test"));

/** The most host aborts one climb may meet; one more fails it. */
const HOST_ABORTS = 100;

/** How long one child may run: one that hangs fails the test, and climbs of a stack many times Node's default still fit. */
const CHILD_TIMEOUT_MS = 1_800_000;

/** How a child process ended, and what it wrote. */
interface Ended {
  code: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
}

/** test/stack-climb.ts run on `climbs` in a child process, with the flags this file runs under. */
function child(climbs: Climbs): Promise<Ended> {
  return new Promise((resolve, reject) => {
    const proc = spawn(process.execPath, [...FLAGS, join(TEST_DIR, "stack-climb.ts"), JSON.stringify(climbs)], {
      cwd: PACKAGE_DIR, env: { ...process.env, NODE_OPTIONS: "" }, stdio: ["ignore", "pipe", "pipe"], timeout: CHILD_TIMEOUT_MS,
    });
    let stdout = "";
    let stderr = "";
    proc.stdout.setEncoding("utf8").on("data", (chunk: string) => { stdout += chunk; });
    proc.stderr.setEncoding("utf8").on("data", (chunk: string) => { stderr += chunk; });
    proc.on("error", reject);
    proc.on("close", (code, signal) => resolve({ code, signal, stdout, stderr }));
  });
}

/** Whether a try got to the end of the run: it was neither a stack fault nor a host abort. */
const completes = (outcome: string) => outcome !== "stack fault" && outcome !== "host abort";

/** What the climbs of a run gave: its outcome with the whole stack, and what each try gave, in order. */
interface Climbed {
  expected: string;
  seen: string[];
}

/**
 * Try `run` at the end of the stack, then with one more frame of it at a time, until it completes,
 * `climbs` times over, one climb after another in one child process.
 *
 * Each try gives "expected" when the run gives the outcome it has with the whole stack, "stack
 * fault" when the stack ran out inside the run, "host abort" when the engine ended the process in
 * the middle of the try, and otherwise the outcome itself.
 *
 * Each climb runs the attempt at the bottom of a recursion `depth` frames deep. The deepest depth
 * at which it still starts is found first, with an attempt that does nothing, so the run itself is
 * first tried at the end of the stack rather than after a search has warmed it up. Every depth from
 * there up is then tried, one frame at a time, so the deepest frames are each tried. The climb goes
 * on until the run completes, and then for as many tries again as it took to get there, so the
 * band where the stack ran out is covered twice over.
 *
 * When the engine ends the child in the middle of a try, with its fatal error report on stderr, the
 * try is a host abort, and a fresh child, which finds the deepest depth again, goes on with that
 * climb from the depth after it, counted from there, and then with the climbs after it. One climb
 * may meet HOST_ABORTS of them. A child that ends any other way, or outside a climb's tries, fails
 * here, by name, with what it wrote to stderr.
 *
 * No count of frames is fixed in advance: how much stack a run takes, and how far above the end of
 * the stack a recursion is stopped, differ from one engine, version and tier to the next, and a
 * fixed count that reaches both ends on one host misses one of them on another. The cost is bounded
 * by the stack itself: a climb ends at depth 0, the whole stack the child has, and if the run has
 * not completed there the stack never sufficed, which fails here, by name.
 */
async function atTheEndOfTheStack(run: Run, climbs: number): Promise<Climbed> {
  let expected: string | undefined;
  const seen: string[][] = Array.from({ length: climbs }, () => []);
  let climb = 0;
  let from = 0;
  for (;;) {
    const first = seen[climb]!.findIndex(completes);
    const ended = await child({ run, climbs, climb, from, tried: seen[climb]!.length, completed: first === -1 ? null : first + 1 });
    // The climb whose tries the child was making when it ended, if any, and the offset of its next
    // depth.
    let current: number | undefined;
    let next = 0;
    let done = false;
    // Only whole lines: the last may have been cut short when the engine ended the child.
    for (const text of ended.stdout.split("\n").slice(0, -1)) {
      const line = JSON.parse(text);
      if ("boundary" in line) {
        current = line.climb;
        next = line.climb === climb ? from : 0;
        expected ??= line.expected as string;
        assert.equal(line.expected, expected, "two children gave the run different outcomes with the whole stack");
      } else if ("offset" in line) {
        next = line.offset + 1;
        if (line.outcome !== "not started") seen[line.climb]!.push(line.outcome);
      } else {
        current = undefined;
        done = line.climb === climbs - 1;
      }
    }
    if (done && ended.code === 0) break;
    const how = ended.signal ?? `exit code ${ended.code}`;
    assert.ok(ended.code !== 0 && ended.stderr.includes("FATAL ERROR:"),
      `a climb's child ended with ${how}${done ? "" : " before its climbs ended"}, without the engine's report of an abort; its stderr:\n${ended.stderr}`);
    assert.ok(current !== undefined,
      `the engine ended a climb's child with ${how} outside a climb's tries; its stderr:\n${ended.stderr}`);
    seen[current]!.push("host abort");
    const aborts = seen[current]!.filter((outcome) => outcome === "host abort").length;
    assert.ok(aborts <= HOST_ABORTS,
      `the engine ended climb ${current}'s children ${aborts} times, more than the ${HOST_ABORTS} one climb may meet; the last stderr:\n${ended.stderr}`);
    climb = current;
    from = next + 1;
  }
  for (const [index, tries] of seen.entries()) {
    assert.ok(tries.some(completes),
      `climb ${index}: the attempt never completed: it met the end of the stack at each of ${tries.length} depths, the whole stack included`);
  }
  return { expected: expected!, seen: seen.flat() };
}

/** The tries in `seen` that gave neither the run's outcome with the whole stack, a stack fault nor a host abort. */
function others(seen: string[]): string[] {
  return [...new Set(seen.filter((outcome) => outcome !== "expected" && outcome !== "stack fault" && outcome !== "host abort"))];
}

const PASSING_AUTHORIZATION = {
  status: "OFFLINE_OK", verdict: "PASS", exit_code: 0, trust_registry: true, registry_signature: "VALID_SIGNATURE",
  authorization_status: "AUTHORIZED_ACTIVE_KEY", signature_status: "VALID_SIGNATURE", root_signature_status: "ROOT_SIGNATURE_VALID",
};

test("a stack the host runs out of on a valid authorization run is an exception, never a verdict", async () => {
  // The child builds the run, with keys made for it, and gives its outcome with the whole stack.
  const { expected, seen } = await atTheEndOfTheStack({ kind: "authorization" }, 1);
  assert.deepEqual(JSON.parse(expected), PASSING_AUTHORIZATION);
  assert.deepEqual(others(seen), []);
  // Both ends were reached: the stack ran out inside the run, and the run completed.
  assert.ok(seen.includes("stack fault"));
  assert.ok(seen.includes("expected"));
});

/** A valid authorization run with trust roots, its bundle and documents written to a fresh directory. */
function authorizationOnDisk() {
  const bundle = Bundle.linkValid().seal();
  const { root, sign } = ephemeralRoot("root-1");
  const material = ephemeralAuthorizationWith(bundle, { trust: (t) => { delete t.signature; } });
  sign(material.trustRegistry);
  const dir = tempDir("stack");
  const documents = {
    registryEntry: join(dir, "entry.json"),
    trustRegistry: join(dir, "trust_registry.json"),
    trustRoots: join(dir, "trust_roots.json"),
    // A document at input strictness rule 6's bound, which the protocol admits.
    deepest: join(dir, "depth_64.json"),
  };
  writeFileSync(documents.registryEntry, JSON.stringify(material.registryEntry));
  writeFileSync(documents.trustRegistry, JSON.stringify(material.trustRegistry));
  writeFileSync(documents.trustRoots, JSON.stringify(rootDocument([root])));
  writeFileSync(documents.deepest, "[".repeat(64) + "]".repeat(64));
  return { bundleRoot: bundle.writeTo(join(dir, "bundle")), documents, dir };
}

test("a document read with little stack left is the document or an exception, never null or a failed read", async () => {
  const { bundleRoot, documents, dir } = authorizationOnDisk();
  try {
    // The end of the stack falls on a different step from one climb to the next, so the climb is
    // made four times over.
    const { expected, seen } = await atTheEndOfTheStack({ kind: "documents", documents }, 4);
    assert.deepEqual(others(seen), []);
    assert.ok(seen.includes("stack fault"));
    assert.ok(seen.includes("expected"));
    // Read near the end of the stack, verified with the whole of it: the run passes.
    const read = JSON.parse(expected);
    const options = { registryEntry: read.registryEntry, trustRegistry: read.trustRegistry, trustRoots: read.trustRoots, evaluationTime: "2026-05-10T00:00:00Z" };
    assert.deepEqual(authorizationOutcome(verifyBundle(bundleRoot, options)), PASSING_AUTHORIZATION);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a bundle run that ends at its input's inspection, with little stack left, is the report or an exception", async () => {
  const dir = tempDir("stack-inspection");
  try {
    writeFileSync(join(dir, "file.json"), "{}");
    mkdirSync(join(dir, "empty"));
    mkdirSync(join(dir, "manifest-not-json"));
    writeFileSync(join(dir, "manifest-not-json", "manifest.json"), "not json");
    const inputs: Record<string, string> = {
      "a missing path": join(dir, "missing"),
      "a file": join(dir, "file.json"),
      "an empty directory": join(dir, "empty"),
      "a manifest.json that is not JSON": join(dir, "manifest-not-json"),
    };
    // The end of the stack falls on a different step from one climb to the next, so the climb is
    // made four times over. The four inputs are climbed at once, each in its own child; the first
    // that fails fails the test, once all have ended.
    const climbs = await Promise.allSettled(Object.values(inputs).map((input) => atTheEndOfTheStack({ kind: "inspection", input }, 4)));
    for (const [index, label] of Object.keys(inputs).entries()) {
      const climbed = climbs[index]!;
      if (climbed.status === "rejected") throw climbed.reason;
      const { expected, seen } = climbed.value;
      // Nothing found at the path is the host's (HOST_FAILURE); the other three are content.
      assert.equal(JSON.parse(expected).status, label === "a missing path" ? "HOST_FAILURE" : "OFFLINE_FAIL", label);
      assert.deepEqual(others(seen), [], label);
      assert.ok(seen.includes("stack fault"), label);
      assert.ok(seen.includes("expected"), label);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
