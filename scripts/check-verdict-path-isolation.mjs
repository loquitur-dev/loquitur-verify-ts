// Enforce that the verdict path contains no network access and no AI.
//
// README.md says this package "makes no network calls" and src/index.ts says it verifies "locally,
// with no server and no network". The product commitment behind those sentences is that a verdict
// involves no AI and no network access. A source file importing node:net, or calling fetch, would
// typecheck and pass every test; this script is what refuses it, in two parts, and it fails closed:
// a file it cannot parse, an import it cannot resolve to a literal name, a dependency it cannot
// find in the lockfile, is a failure, never a pass.
//
// The rule is an allow-list with three clauses. A module specifier may be imported by a
// source of this package when it is
//   1. relative: a file of this package;
//   2. a built-in module of Node (with or without the `node:` scheme) that is not one of
//      NETWORK_BUILTIN_MODULES, the built-ins through which Node reaches a network; or
//   3. a package in the runtime dependency closure: package.json's dependencies,
//      optionalDependencies and peerDependencies, followed through package-lock.json the way
//      Node resolves them, which must be the reviewed closure REVIEWED_RUNTIME_CLOSURE.
// Everything else is refused, whatever it is called (a model SDK, an HTTP client, a package
// that does not exist yet), so the script needs no list of the packages it refuses and carries
// none: a deny-list of named packages could refuse only what someone had remembered to
// enumerate. The platform's network globals (fetch, XMLHttpRequest, WebSocket, EventSource,
// sendBeacon, RTCPeerConnection, WebTransport) are not modules and stay listed by name.
//
//   sources       Every .ts file under src/ is parsed with the TypeScript compiler, and
//                 every import and export declaration, `import x = require(...)`,
//                 `require(...)` call and dynamic `import(...)` is held to the allow-list.
//                 So are uses of the network globals, as identifiers or as string keys
//                 (`globalThis["fetch"]`). Reading the syntax tree means a word in a comment
//                 is not a use and a use is not missed for its spelling. An import whose
//                 target is not a literal, `createRequire`, `eval` and `new Function` cannot be
//                 checked and are reported as such.
//   dependencies  The runtime dependency closure is resolved through package-lock.json and
//                 must equal the reviewed closure; the development closure is resolved the
//                 same way from devDependencies; and every package anywhere in the lockfile
//                 must belong to one of the two, so nothing is installed that no declared
//                 dependency reaches. The lockfile's root must declare the same dependencies
//                 as package.json, or the closure read is not the one installed.
//
// What it does not cover: it forbids modules, globals and packages, not every conceivable
// channel; the scripts/ and test/ directories are not the verdict path and are not read;
// and the TypeScript package runs on whatever host embeds it, whose own network access this
// cannot see.
//
// Usage: node scripts/check-verdict-path-isolation.mjs [--root DIR]   (exit 0 pass, 1 fail)
// CI calls the script directly; it has no npm script.
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { builtinModules } from "node:module";
import { join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

// The built-ins through which Node reaches a network, each covering its subpaths
// (`dns/promises`, `inspector/promises`) and the internal `_http_*` / `_tls_*` modules
// behind them. `cluster` forks workers over a listening socket and `inspector` opens a
// debugging server, so both are on the list.
export const NETWORK_BUILTIN_MODULES = ["net", "tls", "http", "https", "http2", "dgram", "dns", "cluster", "inspector"];

// The runtime dependency closure as reviewed. A package that arrives through a new
// transitive requirement is a change to this file, not a silent widening of what the
// verifier may load.
export const REVIEWED_RUNTIME_CLOSURE = ["@noble/curves", "@noble/hashes", "canonicalize"];

export const FORBIDDEN_GLOBALS = [
  "fetch", "XMLHttpRequest", "WebSocket", "EventSource", "sendBeacon", "RTCPeerConnection", "WebTransport",
];

const BUILTINS = new Set(builtinModules.map((name) => (name.startsWith("node:") ? name.slice(5) : name)));

/** The package a module specifier names: `node:net` -> `net`, `@a/b/c` -> `@a/b`, `x/y` -> `x`. */
export function packageName(specifier) {
  const bare = specifier.startsWith("node:") ? specifier.slice("node:".length) : specifier;
  const parts = bare.split("/");
  return bare.startsWith("@") ? parts.slice(0, 2).join("/") : parts[0];
}

function isNetworkBuiltin(name) {
  return NETWORK_BUILTIN_MODULES.includes(name) || /^_(http|tls)_/.test(name);
}

/**
 * Why the allow-list refuses `specifier` given `closure` (the runtime closure's package
 * names), or null when it admits it. A `node:`-prefixed name is a built-in or nothing.
 */
export function disallowedReason(specifier, closure = REVIEWED_RUNTIME_CLOSURE) {
  if (specifier.startsWith(".")) return null; // a file of this package
  const name = packageName(specifier);
  const bare = specifier.startsWith("node:") ? specifier.slice("node:".length) : specifier;
  if (specifier.startsWith("node:") || BUILTINS.has(bare) || BUILTINS.has(name)) {
    if (isNetworkBuiltin(name)) return "network";
    if (BUILTINS.has(bare) || BUILTINS.has(name)) return null;
    return `not a built-in module`;
  }
  if (closure.includes(name)) return null;
  return `outside the runtime dependency closure [${closure.join(", ")}]`;
}

function literalText(node) {
  return node && (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) ? node.text : null;
}

/** Violations in one source text, as strings `file:line: what`. */
export function scanSource(fileName, text, closure = REVIEWED_RUNTIME_CLOSURE) {
  const violations = [];
  const source = ts.createSourceFile(fileName, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const diagnostics = source.parseDiagnostics ?? [];
  if (diagnostics.length) {
    violations.push(`${fileName}: cannot be parsed, so cannot be checked`);
    return violations;
  }
  const at = (node) => `${fileName}:${source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1}`;
  const checkSpecifier = (node, how, specifierNode) => {
    const specifier = literalText(specifierNode);
    if (specifier === null) {
      violations.push(`${at(node)}: ${how} with a target that is not a literal cannot be checked`);
      return;
    }
    const reason = disallowedReason(specifier, closure);
    if (reason) violations.push(`${at(node)}: ${how} of ${specifier} (${reason})`);
  };
  const visit = (node) => {
    if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier) {
      checkSpecifier(node, ts.isImportDeclaration(node) ? "import" : "export-from", node.moduleSpecifier);
    } else if (ts.isImportEqualsDeclaration(node) && ts.isExternalModuleReference(node.moduleReference)) {
      checkSpecifier(node, "import-require", node.moduleReference.expression);
    } else if (ts.isImportTypeNode(node) && ts.isLiteralTypeNode(node.argument)) {
      checkSpecifier(node, "import type", node.argument.literal);
    } else if (ts.isCallExpression(node)) {
      if (node.expression.kind === ts.SyntaxKind.ImportKeyword) {
        checkSpecifier(node, "dynamic import", node.arguments[0]);
      } else if (ts.isIdentifier(node.expression) && node.expression.text === "require") {
        checkSpecifier(node, "require", node.arguments[0]);
      } else if (ts.isIdentifier(node.expression) && ["eval", "createRequire"].includes(node.expression.text)) {
        violations.push(`${at(node)}: ${node.expression.text}() cannot be checked`);
      }
    } else if (ts.isNewExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === "Function") {
      violations.push(`${at(node)}: new Function() cannot be checked`);
    } else if (ts.isIdentifier(node) && FORBIDDEN_GLOBALS.includes(node.text)) {
      violations.push(`${at(node)}: use of ${node.text} (network)`);
    } else if (literalText(node) !== null && FORBIDDEN_GLOBALS.includes(literalText(node))) {
      // `globalThis["fetch"]`; a module specifier is judged above, not here.
      violations.push(`${at(node)}: "${literalText(node)}" as a key (network)`);
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return violations;
}

function sourceFiles(dir) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) out.push(...sourceFiles(path));
    else if (/\.(ts|mts|cts|tsx)$/.test(entry)) out.push(path);
  }
  return out.sort();
}

export function scanSourceTree(root, closure = REVIEWED_RUNTIME_CLOSURE) {
  const src = join(root, "src");
  if (!existsSync(src)) return { violations: [`${src}: no source directory; nothing was checked`], files: 0 };
  const files = sourceFiles(src);
  if (!files.length) return { violations: [`${src}: no TypeScript sources; nothing was checked`], files: 0 };
  const violations = [];
  for (const file of files) {
    violations.push(...scanSource(relative(root, file).split("\\").join("/"), readFileSync(file, "utf8"), closure));
  }
  return { violations, files: files.length };
}

function lockName(key) {
  const index = key.lastIndexOf("node_modules/");
  return key.slice(index + "node_modules/".length);
}

/** Resolve `name` as required from the package at lockfile key `from`, the way Node looks it up. */
function resolveInLock(packages, from, name) {
  let base = from;
  for (;;) {
    const candidate = `${base ? `${base}/` : ""}node_modules/${name}`;
    if (packages[candidate]) return candidate;
    if (!base) return null;
    const cut = base.lastIndexOf("/node_modules/");
    base = cut === -1 ? "" : base.slice(0, cut);
  }
}

const RUNTIME_FIELDS = ["dependencies", "optionalDependencies", "peerDependencies"];
const declared = (object, fields) => fields.flatMap((field) => Object.keys(object?.[field] ?? {})).sort();

/** The lockfile keys reachable from `roots` (names required by the root package). */
function resolveClosure(manifest, packages, roots, violations, label) {
  const closure = new Set();
  const queue = roots.map((name) => ["", name]);
  while (queue.length) {
    const [from, name] = queue.shift();
    const key = resolveInLock(packages, from, name);
    if (key === null) {
      const optional = from === "" ? Object.keys(manifest?.optionalDependencies ?? {}).includes(name)
        : Object.keys(packages[from]?.optionalDependencies ?? {}).includes(name);
      if (!optional) violations.push(`${label} dependency ${name} (required from ${from || "the root"}) is not in the lockfile`);
      continue;
    }
    if (closure.has(key)) continue;
    closure.add(key);
    for (const next of declared(packages[key], RUNTIME_FIELDS)) queue.push([key, next]);
  }
  return closure;
}

export function checkDependencies(manifest, lock) {
  const violations = [];
  const packages = lock?.packages;
  if (!packages || typeof packages !== "object" || !packages[""]) {
    return { violations: ["package-lock.json has no v2/v3 `packages` table; the closure cannot be read"], closure: [] };
  }
  const fromManifest = declared(manifest, RUNTIME_FIELDS);
  const fromLock = declared(packages[""], RUNTIME_FIELDS);
  if (JSON.stringify(fromManifest) !== JSON.stringify(fromLock)) {
    violations.push(`package.json declares ${fromManifest} but the lockfile root declares ${fromLock}`);
  }
  for (const name of [...fromManifest, ...Object.keys(manifest?.devDependencies ?? {})]) {
    if (isNetworkBuiltin(packageName(name))) violations.push(`package.json names ${name} (network)`);
  }

  const runtime = resolveClosure(manifest, packages, fromManifest, violations, "runtime");
  const closure = [...runtime].map(lockName).sort();
  if (JSON.stringify(closure) !== JSON.stringify([...REVIEWED_RUNTIME_CLOSURE].sort())) {
    violations.push(
      `the runtime dependency closure is [${closure.join(", ")}], not the reviewed closure [${REVIEWED_RUNTIME_CLOSURE.join(", ")}]`,
    );
  }
  const development = resolveClosure(manifest, packages, Object.keys(manifest?.devDependencies ?? {}), violations, "development");
  for (const key of Object.keys(packages)) {
    if (!key || runtime.has(key) || development.has(key)) continue;
    violations.push(`lockfile contains ${lockName(key)}, which no runtime or development dependency reaches`);
  }
  return { violations, closure };
}

export function checkPackage(root) {
  let dependencies;
  try {
    dependencies = checkDependencies(
      JSON.parse(readFileSync(join(root, "package.json"), "utf8")),
      JSON.parse(readFileSync(join(root, "package-lock.json"), "utf8")),
    );
  } catch (error) {
    dependencies = { violations: [`package.json or package-lock.json cannot be read: ${error.message}`], closure: [] };
  }
  // The sources are held to the closure the lockfile resolves, which the line above holds
  // to the reviewed one; a source importing a package the lockfile does not reach is named
  // whichever of the two lists it is missing from.
  const sources = scanSourceTree(root, dependencies.closure);
  return {
    violations: [...sources.violations, ...dependencies.violations],
    files: sources.files,
    closure: dependencies.closure,
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const flag = process.argv.indexOf("--root");
  const root = resolve(flag === -1 ? join(fileURLToPath(import.meta.url), "..", "..") : process.argv[flag + 1]);
  const { violations, files, closure } = checkPackage(root);
  for (const violation of violations) console.log(`FORBIDDEN ${violation}`);
  if (violations.length) {
    console.log(`verdict path isolation FAILED: ${violations.length} violation(s) in ${root}`);
    process.exit(1);
  }
  console.log(
    `verdict path isolation OK: ${files} source files importing only their own files, Node built-ins outside the ` +
      `network modules and the runtime dependency closure [${closure.join(", ")}], with no network global; ` +
      `the closure is the reviewed one and every lockfile package is reached by a declared dependency`,
  );
}
