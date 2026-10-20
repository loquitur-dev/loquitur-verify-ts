// What the packed tarball carries besides the compiled code: the source maps under dist/src.
//
// tsconfig.json sets sourceMap and inlineSources, so every dist/src/**/*.js.map carries the text
// of the source it maps in `sourcesContent`. That is on purpose: a stack trace from the package
// maps to source a reader can see, and the text is this repository's own src/, under the same
// license. This script, run by `prepack` after the build, holds the maps to that and nothing more:
//
// - each map names in `sources` only files under src/, and carries a `sourcesContent` entry for
//   each, byte-equal to that file as the repository holds it, so a map never carries text the
//   repository does not publish in its own tree (test/, scripts/, a generated or local file);
// - each compiled module under dist/src imports, by relative path, only modules under dist/src,
//   so the tarball, which ships dist/src alone, is complete.
//
// Run directly: `node scripts/check-pack-maps.mjs [packageDir]`. Exit 0 when every map and module
// holds, 1 with one line per finding otherwise. test/pack-maps.test.ts runs checkPackMaps over
// planted trees, one per finding.
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

function filesUnder(dir, suffix) {
  const out = [];
  const pending = [dir];
  while (pending.length > 0) {
    const current = pending.pop();
    for (const entry of readdirSync(current, { withFileTypes: true })) {
      const path = join(current, entry.name);
      if (entry.isDirectory()) pending.push(path);
      else if (entry.isFile() && entry.name.endsWith(suffix)) out.push(path);
    }
  }
  return out.sort();
}

function inside(parent, child) {
  const rel = relative(parent, child);
  return rel !== "" && !rel.startsWith("..") && !rel.includes(":") && !rel.startsWith(sep);
}

const RELATIVE_SPECIFIER = /(?:\bfrom\s*|\bimport\s*\(\s*|\bimport\s+)["'](\.{1,2}\/[^"']*)["']/g;

/** Every finding about the source maps and relative imports of `<packageDir>/dist/src`; empty when they hold. */
export function checkPackMaps(packageDir) {
  const root = resolve(packageDir);
  const srcDir = join(root, "src");
  const distSrc = join(root, "dist", "src");
  const findings = [];
  if (!existsSync(distSrc) || !statSync(distSrc).isDirectory()) return [`no build output at dist/src: run the build first`];
  const maps = filesUnder(distSrc, ".js.map");
  if (maps.length === 0) findings.push("dist/src holds no source map, though tsconfig.json asks for one per module");
  for (const mapPath of maps) {
    const label = relative(root, mapPath).split(sep).join("/");
    let map;
    try {
      map = JSON.parse(readFileSync(mapPath, "utf8"));
    } catch {
      findings.push(`${label}: not a JSON source map`);
      continue;
    }
    const sources = map.sources;
    const contents = map.sourcesContent;
    if (!Array.isArray(sources) || sources.length === 0) {
      findings.push(`${label}: names no source`);
      continue;
    }
    if (!Array.isArray(contents) || contents.length !== sources.length) {
      findings.push(`${label}: does not carry the text of each source it names (sourcesContent)`);
      continue;
    }
    const base = resolve(dirname(mapPath), typeof map.sourceRoot === "string" ? map.sourceRoot : "");
    sources.forEach((source, index) => {
      if (typeof source !== "string") {
        findings.push(`${label}: a source that is not a path`);
        return;
      }
      const path = resolve(base, source);
      if (!inside(srcDir, path)) {
        findings.push(`${label}: names ${source}, which is not under src/`);
        return;
      }
      if (!existsSync(path)) {
        findings.push(`${label}: names ${source}, which the repository does not hold`);
        return;
      }
      const tracked = readFileSync(path);
      const carried = Buffer.from(typeof contents[index] === "string" ? contents[index] : "", "utf8");
      if (typeof contents[index] !== "string" || !tracked.equals(carried)) {
        findings.push(`${label}: the text it carries for ${source} is not that file's`);
      }
    });
  }
  for (const modulePath of filesUnder(distSrc, ".js")) {
    const label = relative(root, modulePath).split(sep).join("/");
    const text = readFileSync(modulePath, "utf8");
    for (const match of text.matchAll(RELATIVE_SPECIFIER)) {
      const target = resolve(dirname(modulePath), match[1]);
      if (!inside(distSrc, target)) findings.push(`${label}: imports ${match[1]}, which is not under dist/src`);
    }
  }
  return findings;
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  const packageDir = process.argv[2] ?? join(dirname(fileURLToPath(import.meta.url)), "..");
  const findings = checkPackMaps(packageDir);
  if (findings.length > 0) {
    console.error("pack maps: BLOCKED");
    for (const finding of findings) console.error(`  - ${finding}`);
    process.exit(1);
  }
  console.error("pack maps: OK (every map under dist/src carries only src/ text, every import stays in dist/src)");
}
