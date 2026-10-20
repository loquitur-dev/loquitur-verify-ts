// Run by stack-independent-depth.test.ts in a child process with a small stack. Prints, as JSON,
// the outcome of verifyBundleFiles on canonical inputs nested 64, 65 and 20000 levels deep, and
// what readDocumentPath and parseJsonStrict give for documents nested 64, 65, 5000 and 20000
// levels deep.
//
// Not a test file: `npm test` runs test/*.test.ts, and this is started by one of them.
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DOCUMENT_NOT_STRICT_JSON, JsonParseError, parseJsonStrict, readDocumentPath } from "../src/index.ts";
import { Bundle, jcsText, outcome, verifyInMemory } from "./bundle-kit.ts";

const nested = (depth: number) => "[".repeat(depth) + "0" + "]".repeat(depth);

function run(depth: number) {
  const b = Bundle.linkValid();
  const body = jcsText(b.json("canonical_input.json"));
  b.setBytes("canonical_input.json", `${body.slice(0, -1)},"deep":${nested(depth - 1)}}`);
  if (depth <= 64) {
    b.edit("p1.json", (p) => {
      p.ik = [...p.ik, "deep"];
      p.ih = b.inputHashFor(p);
    });
  }
  try {
    return outcome(verifyInMemory(b.seal()), ["canonical_input_present", "p1_input_hash"]);
  } catch (err) {
    return { threw: `${(err as Error).name}` };
  }
}

/** What a host document of `depth` levels gives: "document", "not strict JSON", or the class it threw. */
function hostDocument(dir: string, depth: number) {
  const path = join(dir, `depth-${depth}.json`);
  writeFileSync(path, nested(depth));
  let read: string;
  try {
    read = readDocumentPath(path) === DOCUMENT_NOT_STRICT_JSON ? "not strict JSON" : "document";
  } catch (err) {
    read = `threw ${(err as Error).name}`;
  }
  let parsed: string;
  try {
    parseJsonStrict(nested(depth));
    parsed = "parsed";
  } catch (err) {
    parsed = err instanceof JsonParseError ? "JsonParseError" : `threw ${(err as Error).name}`;
  }
  return { read, parsed };
}

const dir = mkdtempSync(join(tmpdir(), "depth-probe-"));
try {
  const documents = Object.fromEntries([64, 65, 5000, 20000].map((depth) => [depth, hostDocument(dir, depth)]));
  process.stdout.write(JSON.stringify({ bundles: { 64: run(64), 65: run(65), 20000: run(20000) }, documents }));
} finally {
  rmSync(dir, { recursive: true, force: true });
}
