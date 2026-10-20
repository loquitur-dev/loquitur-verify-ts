// Every catch under src/, read from the source, lets a stack the host ran out of through. A stack
// fault is a fault of the host, never a verdict (report-contract.md section 4), and
// stack-fault-sites.test.ts proves the sites it knows of one by one; this test finds a catch it
// does not know of. A catch passes when its body takes one of these forms:
//
// - it calls rethrowHostStackFault(err), or a helper that does so first (hostFailure, and the
//   `absent` test of linkReachesAnEntry), before it decides anything;
// - it is narrow: each statement before a final `throw err;` is `if (GUARD) return ...;` or
//   `if (GUARD) throw ...;`, or its first statement is `if (!GUARD) throw err;`, where GUARD is
//   `err instanceof C` for an error class this package declares, or isContainedError(err), which
//   is JsonParseError or CanonicalizationError. The engine's RangeError and SyntaxError are
//   neither, so they reach the `throw err`;
// - it opens with a comment that starts `Stack fault:` and says why the fault passes.
//
// The body is found by counting braces from `catch (err) {`, `catch (err: unknown) {` or
// `catch {`, which holds for the code under src/: a brace inside a string there is balanced or
// inside `${...}`. A `catch` outside a comment that opens none of these is not read past: the test
// fails on it.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { PACKAGE_DIR } from "./bundle-kit.ts";

const SRC = join(PACKAGE_DIR, "src");

/** Every TypeScript file under src/, as a path relative to src/ with forward slashes. */
function sources(dir = SRC, prefix = ""): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    if (entry.isDirectory()) return sources(join(dir, entry.name), prefix + entry.name + "/");
    return entry.name.endsWith(".ts") ? [prefix + entry.name] : [];
  });
}

interface Catch {
  line: number;
  binding: string | null;
  body: string;
}

/** A `catch` clause as the code under src/ opens one: a binding, typed or not, or none. */
const CATCH_CLAUSE = /\bcatch\s*(?:\(\s*(\w+)\s*(?::\s*\w+\s*)?\))?\s*\{/g;

/** Whether the `catch` at `index` of `text` is in a comment that names a catch. */
function inComment(text: string, index: number): boolean {
  return /^\s*(?:\/\/|\*)/.test(text.slice(text.lastIndexOf("\n", index) + 1, index));
}

/** Every `catch` clause of `text`, with its binding and its body between the braces. */
function catchesOf(text: string): Catch[] {
  const found: Catch[] = [];
  for (const match of text.matchAll(CATCH_CLAUSE)) {
    if (inComment(text, match.index)) continue;
    let depth = 1;
    let at = match.index + match[0].length;
    const start = at;
    for (; at < text.length && depth > 0; at++) {
      if (text[at] === "{") depth += 1;
      else if (text[at] === "}") depth -= 1;
    }
    assert.equal(depth, 0, "a catch body does not close");
    found.push({ line: text.slice(0, match.index).split("\n").length, binding: match[1] ?? null, body: text.slice(start, at - 1) });
  }
  return found;
}

/** The line of each `catch` of `text` outside a comment that opens no clause catchesOf reads. */
function unreadCatches(text: string): number[] {
  const read = new Set([...text.matchAll(CATCH_CLAUSE)].map((match) => match.index));
  return [...text.matchAll(/\bcatch\b/g)]
    .filter((match) => !inComment(text, match.index) && !read.has(match.index))
    .map((match) => text.slice(0, match.index).split("\n").length);
}

const RETHROWING_HELPERS = ["rethrowHostStackFault", "hostFailure", "absent"];

/** Why a catch lets a stack fault through, or null when it may not. */
function passes(entry: Catch, declaredErrors: ReadonlySet<string>): string | null {
  const lines = entry.body.split("\n").map((line) => line.trim()).filter((line) => line !== "");
  if (lines[0]?.startsWith("// Stack fault:")) return "exempt";
  if (entry.binding === null) return null;
  const err = entry.binding;
  const code = lines.filter((line) => !line.startsWith("//")).map((line) => line.replace(/\s*\/\/.*$/, ""));
  const first = code[0] ?? "";
  for (const helper of RETHROWING_HELPERS) {
    if (first.includes(`${helper}(${err}`)) return "rethrows";
  }
  const guard = `(?:${err} instanceof (\\w+)|isContainedError\\(${err}\\))`;
  const classesOk = (statements: string[], pattern: RegExp) =>
    statements.every((statement) => {
      const m = pattern.exec(statement);
      return m !== null && (m[1] === undefined || declaredErrors.has(m[1]));
    });
  const negative = new RegExp(`^if \\(!(?:\\(${err} instanceof (\\w+)\\)|isContainedError\\(${err}\\))\\) throw ${err};$`);
  if (classesOk([first], negative)) return "narrow";
  const positive = new RegExp(`^if \\(${guard}\\) (?:return\\b|throw\\b).*;$`);
  if (code.length >= 2 && code.at(-1) === `throw ${err};` && classesOk(code.slice(0, -1), positive)) return "narrow";
  return null;
}

/** The error classes src/ declares: the only ones a narrow catch may swallow. */
function declaredErrorClasses(texts: string[]): Set<string> {
  const names = new Set<string>();
  for (const text of texts) {
    for (const match of text.matchAll(/\bclass (\w+) extends (\w+)/g)) names.add(match[1]!);
  }
  for (const engine of ["Error", "RangeError", "SyntaxError", "TypeError"]) names.delete(engine);
  return names;
}

test("every catch under src/ lets a stack fault through", () => {
  const files = sources();
  const texts = files.map((file) => readFileSync(join(SRC, file), "utf8").replace(/\r\n/g, "\n"));
  const declared = declaredErrorClasses(texts);
  const failing: string[] = [];
  const unread: string[] = [];
  let count = 0;
  files.forEach((file, index) => {
    for (const line of unreadCatches(texts[index]!)) unread.push(`src/${file}:${line}`);
    for (const entry of catchesOf(texts[index]!)) {
      count += 1;
      if (passes(entry, declared) === null) failing.push(`src/${file}:${entry.line}`);
    }
  });
  assert.deepEqual(unread, [], "a catch the reader of catches cannot read");
  assert.ok(count >= 30, "fewer catches than src/ is written with: " + count);
  assert.deepEqual(failing, [], "a catch that may turn a stack fault into a verdict, a value or a read failure");
});

test("each helper a catch relies on rethrows a stack fault before anything else", () => {
  const verify = readFileSync(join(SRC, "verify.ts"), "utf8").replace(/\r\n/g, "\n");
  assert.match(verify, /\nfunction hostFailure\([^\n]*\): null \{\n\s*rethrowHostStackFault\(err\);\n/);
  assert.match(verify, /\n\s*const absent = \(err: unknown\): boolean => \{\n\s*rethrowHostStackFault\(err\);\n/);
  const strictness = readFileSync(join(SRC, "json-strictness.ts"), "utf8").replace(/\r\n/g, "\n");
  assert.match(strictness, /\nexport function rethrowHostStackFault\(err: unknown\): void \{\n\s*if \(isHostStackFault\(err\)\) throw err;\n\}/);
  const core = readFileSync(join(SRC, "verify-core.ts"), "utf8").replace(/\r\n/g, "\n");
  assert.match(core, /\nfunction isContainedError\(err: unknown\): boolean \{\n\s*return err instanceof JsonParseError \|\| err instanceof CanonicalizationError;\n\}/);
});

test("the reader of catches refuses a catch that swallows what it does not name", () => {
  const declared = new Set(["BundleReadError"]);
  const judge = (source: string) => catchesOf(source).map((entry) => passes(entry, declared));
  assert.deepEqual(judge("try { a(); } catch (err) {\n  return null;\n}"), [null]);
  assert.deepEqual(judge("try { a(); } catch {\n  return null;\n}"), [null]);
  assert.deepEqual(judge("try { a(); } catch (err) {\n  if (err instanceof RangeError) return null;\n  throw err;\n}"), [null]);
  assert.deepEqual(judge("try { a(); } catch (err) {\n  if (err instanceof BundleReadError) return null;\n  log(err);\n}"), [null]);
  assert.deepEqual(judge("try { a(); } catch (err) {\n  rethrowHostStackFault(err);\n  return null;\n}"), ["rethrows"]);
  assert.deepEqual(judge("try { a(); } catch (err) {\n  if (err instanceof BundleReadError) return null; // read\n  throw err;\n}"), ["narrow"]);
  assert.deepEqual(judge("try { a(); } catch (err) {\n  if (!(err instanceof BundleReadError)) throw err;\n  x = null;\n}"), ["narrow"]);
  assert.deepEqual(judge("try { a(); } catch (err) {\n  // Stack fault: a reason.\n  return null;\n}"), ["exempt"]);
  // A typed binding is read as the binding it annotates.
  assert.deepEqual(judge("try { a(); } catch (err: unknown) {\n  return null;\n}"), [null]);
  assert.deepEqual(judge("try { a(); } catch (e: unknown) {\n  rethrowHostStackFault(e);\n  return null;\n}"), ["rethrows"]);
});

test("the reader of catches fails on a catch it cannot read", () => {
  assert.deepEqual(unreadCatches("try { a(); } catch (err) {\n}\ntry { b(); } catch (err: unknown) {\n}\n// a comment may catch\n"), []);
  assert.deepEqual(unreadCatches("try { a(); } catch ({ code }) {\n}"), [1]);
  assert.deepEqual(unreadCatches("a();\npromise.catch((err) => null);\n"), [2]);
  assert.deepEqual(unreadCatches("try { a(); } catch (err: Error | null) {\n}"), [1]);
});
