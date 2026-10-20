// tools/public_boundary.json is the data the boundary checker reads for this repository: which
// needle lists apply, and which roots, archive member lists, reviewed digests and corpus lock it
// holds. Every row this repository fills is planted once here and the checker must name the plant;
// a row this repository leaves empty must stay empty until a plant for it is added below. The
// plants are put in a scratch tree carrying this repository's configuration and governance note,
// and the checker is run there through the host's Python, as test/public-boundary.test.ts runs it.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const PACKAGE_DIR = join(dirname(fileURLToPath(import.meta.url)), "..");
const TOOL = join(PACKAGE_DIR, "tools", "check_public_boundary.py");
const CONFIG = JSON.parse(readFileSync(join(PACKAGE_DIR, "tools", "public_boundary.json"), "utf8")) as Record<string, unknown>;

function findPython(): string | null {
  for (const candidate of [process.env.LOQUITUR_PYTHON, "python", "python3"].filter((c): c is string => Boolean(c))) {
    const probe = spawnSync(candidate, ["--version"], { encoding: "utf8" });
    if (!probe.error && probe.status === 0) return candidate;
  }
  return null;
}
const PYTHON = findPython();
const NO_PYTHON = PYTHON === null ? "no Python interpreter on this host (LOQUITUR_PYTHON, python, python3)" : false;

// For each needle list the configuration names: plant its first needle in a note, check the tree,
// and print the checker's findings; then the tree with no plant.
const SCRIPT = [
  "import importlib.util, json, pathlib, sys",
  "spec = importlib.util.spec_from_file_location('check_public_boundary', sys.argv[1])",
  "tool = importlib.util.module_from_spec(spec)",
  "spec.loader.exec_module(tool)",
  "root = pathlib.Path(sys.argv[2])",
  "config = json.loads((root / 'tools' / 'public_boundary.json').read_text(encoding='utf-8'))",
  "out = {'clean': tool.check(root), 'planted': {}}",
  "for name in config['needle_lists']:",
  "    note = root / 'docs' / 'note.md'",
  "    note.parent.mkdir(exist_ok=True)",
  "    needle = tool.NEEDLE_LISTS[name][0]",
  "    note.write_text('see ' + needle + ' here' + chr(10), encoding='utf-8')",
  "    out['planted'][name] = {'needle': needle, 'findings': tool.check(root)}",
  "    note.unlink()",
  "print(json.dumps(out))",
].join("\n");

test("the configuration's rows are the ones planted here", () => {
  assert.deepEqual(Object.keys(CONFIG).sort(), ["archive_member_lists", "corpus_lock", "forbidden_roots", "needle_lists", "reviewed", "schema_version"]);
  assert.equal(CONFIG.schema_version, "loquitur.public_boundary.v1");
  // Rows this repository leaves empty: a value here needs its own plant in the test below.
  assert.deepEqual([CONFIG.archive_member_lists, CONFIG.corpus_lock, CONFIG.forbidden_roots, CONFIG.reviewed], [[], null, [], []]);
  assert.ok(Array.isArray(CONFIG.needle_lists) && CONFIG.needle_lists.length > 0);
});

test("each needle list the configuration names is planted once, and the checker names the plant", { skip: NO_PYTHON }, () => {
  const root = mkdtempSync(join(tmpdir(), "boundary-config-"));
  try {
    mkdirSync(join(root, "tools"));
    copyFileSync(join(PACKAGE_DIR, "tools", "public_boundary.json"), join(root, "tools", "public_boundary.json"));
    copyFileSync(join(PACKAGE_DIR, "GOVERNANCE.md"), join(root, "GOVERNANCE.md"));
    const run = spawnSync(PYTHON!, ["-c", SCRIPT, TOOL, root], { encoding: "utf8" });
    assert.equal(run.status, 0, run.stderr);
    const result = JSON.parse(run.stdout) as { clean: string[]; planted: Record<string, { needle: string; findings: string[] }> };
    assert.deepEqual(result.clean, [], "the tree with no plant passes");
    assert.deepEqual(Object.keys(result.planted), CONFIG.needle_lists);
    for (const [name, { needle, findings }] of Object.entries(result.planted)) {
      assert.equal(findings.length, 1, `${name}: ${JSON.stringify(findings)}`);
      assert.ok(findings[0]!.startsWith("forbidden substring ") && findings[0]!.includes(needle) && findings[0]!.endsWith(" in docs/note.md"), name);
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
