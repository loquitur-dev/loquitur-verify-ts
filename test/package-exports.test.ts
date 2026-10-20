// Every subpath package.json exports must be a file the published tarball carries.
//
// The `./browser` subpath lets a browser caller import this package's browser entry. A test that
// builds src/index.browser.ts with esbuild from source proves the code runs in a browser and says
// nothing about whether `@loquitur/verify/browser` resolves for anyone who installs the package:
// narrowing the `files` whitelist, renaming the entry, or excluding the compiled browser output
// would leave every other suite green and ship a subpath that resolves to nothing.
//
// This test reads the map, asks npm for the exact file list of the tarball it would publish, and
// loads each import target through the built file, so the three ways the subpath can be broken
// (not whitelisted, not built, not the entry it claims) are each a failure here. It is also the
// caller of the `pack:json` script.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { pathToFileURL, fileURLToPath } from "node:url";

const PACKAGE_DIR = join(dirname(fileURLToPath(import.meta.url)), "..");
const manifest = JSON.parse(readFileSync(join(PACKAGE_DIR, "package.json"), "utf-8"));

/** Every path the exports map names, as `<subpath> <condition>` -> path. */
function exportTargets(): Array<{ where: string; target: string }> {
  const out: Array<{ where: string; target: string }> = [];
  for (const [subpath, conditions] of Object.entries(manifest.exports as Record<string, unknown>)) {
    if (typeof conditions === "string") {
      out.push({ where: subpath, target: conditions });
      continue;
    }
    for (const [condition, target] of Object.entries(conditions as Record<string, string>)) {
      out.push({ where: `${subpath} (${condition})`, target });
    }
  }
  return out;
}

/** `npm pack --dry-run --json`: the exact contents of the tarball this package would publish. */
function packedFiles(): string[] {
  // One command string through a shell: npm is a shell script on every platform this runs on, and
  // an argument vector to a .cmd is refused by newer Node on Windows. No value here is
  // interpolated.
  const result = spawnSync("npm run --silent pack:json", { cwd: PACKAGE_DIR, encoding: "utf-8", shell: true });
  assert.equal(result.status, 0, `npm run pack:json failed: ${result.stdout}${result.stderr}`);
  const start = result.stdout.indexOf("[");
  assert.ok(start >= 0, `no JSON in pack output: ${result.stdout}`);
  return (JSON.parse(result.stdout.slice(start)) as Array<{ files: Array<{ path: string }> }>)[0]!
    .files.map((file) => file.path);
}

const PACKED = packedFiles();

test("the exports map names at least the two entries this package offers", () => {
  const subpaths = Object.keys(manifest.exports as Record<string, unknown>);
  assert.deepEqual(subpaths.sort(), [".", "./browser"]);
  assert.ok(exportTargets().length > 0);
});

test("every export target is whitelisted by the files list", () => {
  const whitelist = manifest.files as string[];
  for (const { where, target } of exportTargets()) {
    const path = target.replace(/^\.\//, "");
    const covered = whitelist.some((entry) => path === entry || path.startsWith(entry.replace(/\/$/, "") + "/"));
    assert.ok(covered, `${where} names ${target}, which no files entry whitelists: ${whitelist.join(", ")}`);
  }
});

test("every export target is a file the published tarball carries", () => {
  for (const { where, target } of exportTargets()) {
    const path = target.replace(/^\.\//, "");
    assert.ok(PACKED.includes(path), `${where} names ${target}, absent from the tarball's ${PACKED.length} files`);
  }
});

// The adapters the conformance gate and the differential harness run are test tools, not the
// package: the tarball carries none of scripts/, the differential adapter by name included.
test("the published tarball carries no script, and not the differential adapter", () => {
  assert.ok(!PACKED.includes("scripts/differential-adapter.mjs"), "scripts/differential-adapter.mjs is in the tarball");
  assert.deepEqual(PACKED.filter((path) => path.startsWith("scripts/")), []);
});

test("every import target loads and offers the verifier", async () => {
  for (const { where, target } of exportTargets()) {
    if (!where.includes("(import)")) continue;
    const loaded = await import(pathToFileURL(join(PACKAGE_DIR, target)).href);
    // Both entries verify; only their input differs, which is what the next test pins.
    assert.equal(typeof loaded.verifyBundleFiles, "function", `${where} loads without verifyBundleFiles`);
    assert.equal(typeof loaded.bundleReaderFromMap, "function", `${where} loads without bundleReaderFromMap`);
  }
});

// The two entries are not the same surface, and that is pinned rather than smoothed over. The
// default entry reads a bundle from a directory; the browser entry omits that function because it
// needs node:fs, and says so in its own header. The browser subpath does not offer `verifyBundle`,
// and cannot.
test("the browser entry omits the filesystem reader the default entry offers", async () => {
  const targets = new Map(exportTargets().map(({ where, target }) => [where, target]));
  const node = await import(pathToFileURL(join(PACKAGE_DIR, targets.get(". (import)")!)).href);
  const browser = await import(pathToFileURL(join(PACKAGE_DIR, targets.get("./browser (import)")!)).href);
  assert.equal(typeof node.verifyBundle, "function");
  assert.equal(browser.verifyBundle, undefined, "the browser entry must not offer a filesystem reader");
});
