// scripts/check-pack-maps.mjs, which `prepack` runs after the build: the source maps under dist/src
// carry the text of src/ files and nothing else, byte for byte, and every compiled module imports
// only modules under dist/src. Each finding is planted once in a tree built here, and a tree with
// none passes.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { checkPackMaps } from "../scripts/check-pack-maps.mjs";

const SOURCE = "export const answer = 42;\n";

type Plant = { map?: Record<string, unknown> | null; module?: string; source?: string };

function tree(plant: Plant): string {
  const root = mkdtempSync(join(tmpdir(), "pack-maps-"));
  const write = (rel: string, text: string) => {
    mkdirSync(dirname(join(root, rel)), { recursive: true });
    writeFileSync(join(root, rel), text, "utf8");
  };
  write("src/answer.ts", plant.source ?? SOURCE);
  write("test/helper.ts", "export const helper = 1;\n");
  write("dist/src/answer.js", plant.module ?? 'import { other } from "./other.js";\nexport const answer = 42;\n//# sourceMappingURL=answer.js.map\n');
  write("dist/src/other.js", "export const other = 1;\n");
  const map = plant.map === undefined
    ? { version: 3, file: "answer.js", sourceRoot: "", sources: ["../../src/answer.ts"], sourcesContent: [SOURCE], mappings: "AAAA" }
    : plant.map;
  if (map !== null) write("dist/src/answer.js.map", JSON.stringify(map));
  return root;
}

function findings(plant: Plant): string[] {
  const root = tree(plant);
  try {
    return checkPackMaps(root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

const GOOD = { version: 3, file: "answer.js", sourceRoot: "", sources: ["../../src/answer.ts"], sourcesContent: [SOURCE], mappings: "AAAA" };

test("a build whose maps carry src/ text only and whose imports stay in dist/src passes", () => {
  assert.deepEqual(findings({}), []);
});

test("each way a map or a module leaves the published tree is a finding", () => {
  const cases: Array<[string, Plant, RegExp]> = [
    ["a source outside src/", { map: { ...GOOD, sources: ["../../test/helper.ts"], sourcesContent: ["export const helper = 1;\n"] } }, /not under src\//],
    ["text that is not the file's", { map: { ...GOOD, sourcesContent: ["export const answer = 43;\n"] } }, /is not that file's/],
    ["no text carried (inlineSources off)", { map: { ...GOOD, sourcesContent: undefined } }, /does not carry the text/],
    ["a source the repository does not hold", { map: { ...GOOD, sources: ["../../src/gone.ts"] } }, /does not hold/],
    ["a module importing from test/", { module: 'import { helper } from "../../test/helper.js";\nexport const answer = helper;\n' }, /not under dist\/src/],
    ["no source map at all", { map: null }, /no source map/],
  ];
  for (const [label, plant, expected] of cases) {
    const got = findings(plant);
    assert.ok(got.some((finding) => expected.test(finding)), `${label}: ${JSON.stringify(got)}`);
  }
});
