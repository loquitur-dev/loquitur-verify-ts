// The include markers of README.md, which other documentation reads sections by.
//
// A block between `<!-- lq-include: NAME -->` and `<!-- lq-include-end: NAME -->` is included
// whole, by name, into pages built from the documentation of several repositories, so the text
// exists once. tools/readme_includes.py holds the rules such a block keeps: it opens a section
// under a `## ` heading and stays inside it, closes every code fence it opens, and neither links to
// an anchor of its own page nor names that page. The module is loquitur-schemas'
// tests/readme_includes.py, byte for byte, the one loquitur-verify-py holds its README to as well,
// so the READMEs answer to one reading of the markers and not to a port of it. This package has no
// Python suite, so the module runs here through the host's Python (LOQUITUR_PYTHON, else `python`,
// else `python3`), as test/public-boundary.test.ts runs tools/check_public_boundary.py. Without a
// Python, or without loquitur-schemas for the byte comparison, the tests skip; under
// LOQUITUR_REQUIRE_SIBLINGS they fail, naming what is missing.
//
// Every check the module defines is run, so a rule added there applies here with the next copy,
// and each one is shown refusing a block that breaks it; the rules that read headings and links
// are also shown accepting a block that only resembles a break. The cases are those of
// loquitur-schemas' tests/test_readme_include_markers.py. The names this README gives its blocks
// are its own concern and are held below: the shared names that a page composing the packages
// reads in each.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { PACKAGE_DIR } from "./bundle-kit.ts";
import { REQUIRE_SIBLINGS_ENV, sibling, siblingsRequired } from "./siblings.ts";

const MODULE = join(PACKAGE_DIR, "tools", "readme_includes.py");

const SCHEMAS = sibling(
  "loquitur-schemas",
  [join(PACKAGE_DIR, "..", "loquitur-schemas")],
  "tests/readme_includes.py",
  "loquitur-schemas is not checked out beside this repository",
);

/** The first interpreter on the host that answers `--version`, or null. */
function findPython(): string | null {
  const candidates = [process.env.LOQUITUR_PYTHON, "python", "python3"].filter((c): c is string => Boolean(c));
  for (const candidate of candidates) {
    const probe = spawnSync(candidate, ["--version"], { encoding: "utf8" });
    if (!probe.error && probe.status === 0) return candidate;
  }
  return null;
}

const PYTHON = findPython();
const NO_PYTHON = PYTHON === null ? "no Python interpreter on this host (LOQUITUR_PYTHON, python, python3)" : false;
if (NO_PYTHON && siblingsRequired()) {
  throw new Error(`${REQUIRE_SIBLINGS_ENV} is set, but there is ${NO_PYTHON}; tools/readme_includes.py cannot run`);
}

/** A README with one block named `name` under `heading`, holding `body`. */
const readme = (body: string[], heading = "## Section", name = "a-block") => [heading, "", `<!-- lq-include: ${name} -->`, ...body, `<!-- lq-include-end: ${name} -->`];

// Each check of the module, with READMEs whose one block breaks it.
const REFUSED: [string, string[]][] = [
  ["pairing", readme(["text"]).slice(0, -1)],
  ["pairing", ["## Section", "", "<!-- lq-include:a-block -->", "text"]],
  ["pairing", readme(["<!-- lq-include: inner -->", "text", "<!-- lq-include-end: inner -->"])],
  ["names", readme(["text"], "## Section", "A_Block")],
  ["names", [...readme(["text"]), ...readme(["text"])]],
  ["placement", readme(["text"], "### Section")],
  ["placement", ["## Section", "<!-- lq-include: a-block -->", "text", "<!-- lq-include-end: a-block -->"]],
  ["sections", readme([])],
  ["sections", readme(["text", "## Another section", "text"])],
  ["sections", readme(["text", "", "   # Another section"])],
  ["sections", readme(["text", "", " ##"])],
  ["sections", readme(["text", "", "Another section", "==="])],
  ["sections", readme(["text", "", "Another section", "  ---  "])],
  ["fences", readme(["```bash", "command"])],
  ["fences", readme(["~~~~", "command", "~~~"])],
  ["anchor_links", readme(["See [Install](#install)."])],
  ["anchor_links", [...readme(["See [Install][install]."]), "", "[install]: #install"]],
  ["anchor_links", [...readme(["See [Install][]."]), "", "[install]: #install"]],
  ["anchor_links", [...readme(["See [Install]."]), "", "[Install]: <#install>"]],
  ["anchor_links", readme(["See [the steps][install].", "", "[install]: #install"])],
  ["anchor_links", readme(['See <a href="#install">Install</a>.'])],
  ["anchor_links", readme(["See <a href='#install'>Install</a>."])],
  ["anchor_links", readme(["See <a HREF=#install>Install</a>."])],
  ["self_reference", readme(["As this README says."])],
  ["self_reference", readme(["Clone this repository."])],
  ["section_references", readme(['See "Install" for the steps.'])],
];

// Checks with READMEs whose one block only resembles a break of them, which they accept.
const ACCEPTED: [string, string[]][] = [
  ["sections", readme(["text", "", "### A subsection", "text"])],
  ["sections", readme(["text", "", "    # indented code"])],
  ["sections", readme(["text", "", "---", "", "text"])],
  ["sections", readme(["- an item", "---"])],
  ["sections", readme(["```text", "Not a heading", "===", "```"])],
  ["anchor_links", [...readme(["See [the guide][guide]."]), "", "[guide]: https://example.org/guide"]],
  ["anchor_links", readme(["See [the guide](https://example.org/guide#part)."])],
  ["anchor_links", readme(["Run `[ -f x ]` first."])],
  ["anchor_links", readme(["```html", '<a href="#x">x</a>', "```"])],
];

type Answer = { blocks: string[]; problems: Record<string, string[]>; refused: boolean[]; accepted: boolean[] };

/** Every check of the module over README.md, and each check over its REFUSED and ACCEPTED cases. */
function ask(): Answer {
  const script = [
    "import importlib.util, inspect, json, sys",
    "spec = importlib.util.spec_from_file_location('readme_includes', sys.argv[1])",
    "module = importlib.util.module_from_spec(spec)",
    // A dataclass looks its module up in sys.modules while it is defined.
    "sys.modules[spec.name] = module",
    "spec.loader.exec_module(module)",
    "checks = sorted(name for name, function in inspect.getmembers(module, inspect.isfunction)",
    "                if function.__module__ == module.__name__ and not name.startswith('_') and name != 'blocks')",
    "cases = json.loads(sys.stdin.read())",
    "print(json.dumps({",
    "    'blocks': [block.name for block in module.blocks()],",
    "    'problems': {name: getattr(module, name)() for name in checks},",
    "    'refused': [bool(getattr(module, name)(lines)) for name, lines in cases['refused']],",
    "    'accepted': [getattr(module, name)(lines) == [] for name, lines in cases['accepted']],",
    "}))",
  ].join("\n");
  const run = spawnSync(PYTHON!, ["-c", script, MODULE], { input: JSON.stringify({ refused: REFUSED, accepted: ACCEPTED }), encoding: "utf8" });
  assert.equal(run.error, undefined);
  assert.equal(run.status, 0, run.stderr);
  return JSON.parse(run.stdout) as Answer;
}

test("README.md keeps every rule of the shared include checker", { skip: NO_PYTHON }, () => {
  const { blocks, problems } = ask();
  assert.ok(blocks.length > 0, "README.md has no include markers, so this file would check nothing");
  assert.ok(Object.keys(problems).length >= 7, "the module defines fewer checks than it is written with: " + JSON.stringify(Object.keys(problems)));
  for (const [check, found] of Object.entries(problems)) {
    assert.deepEqual(found, [], check);
  }
});

test("each rule of the include checker refuses a block that breaks it", { skip: NO_PYTHON }, () => {
  const { problems, refused } = ask();
  const untested = Object.keys(problems).filter((check) => !REFUSED.some(([name]) => name === check));
  assert.deepEqual(untested, [], "a check of the module has no README here that it refuses");
  REFUSED.forEach(([check, lines], index) => {
    assert.ok(refused[index], check + " accepts " + JSON.stringify(lines));
  });
});

test("each rule of the include checker accepts a block that only resembles a break", { skip: NO_PYTHON }, () => {
  const { accepted } = ask();
  ACCEPTED.forEach(([check, lines], index) => {
    assert.ok(accepted[index], check + " refuses " + JSON.stringify(lines));
  });
});

test("the include checker is the one loquitur-schemas carries, byte for byte", SCHEMAS.options, () => {
  assert.ok(
    readFileSync(SCHEMAS.path("tests/readme_includes.py")).equals(readFileSync(MODULE)),
    "tools/readme_includes.py differs from loquitur-schemas' tests/readme_includes.py",
  );
});

// The names every package README gives the same content, so that a page composing the packages
// reads one name in each; loquitur-verify-py holds its README to the same list. A block with
// another name is named after its section's anchor.
const SHARED_NAMES = ["status", "installation", "quickstart", "what-it-verifies", "does-not-verify", "scope-and-limits"];

/** The anchor GitHub gives a heading: lower case, punctuation other than hyphens dropped, spaces as hyphens. */
const anchor = (heading: string) => heading.replace(/^#+/, "").trim().toLowerCase().replace(/[^a-z0-9 -]/g, "").replace(/ /g, "-");

test("README.md gives each shared name a block, and every other block its section's anchor", () => {
  const lines = readFileSync(join(PACKAGE_DIR, "README.md"), "utf8").replace(/\r\n/g, "\n").split("\n");
  const opened = lines
    .map((line, index) => ({ name: /^<!-- lq-include: (\S+) -->$/.exec(line)?.[1], heading: lines[index - 2] ?? "" }))
    .filter((block): block is { name: string; heading: string } => block.name !== undefined);
  const names = opened.map((block) => block.name);
  assert.deepEqual(SHARED_NAMES.filter((name) => !names.includes(name)), [], "README.md has no block for a shared name");
  for (const { name, heading } of opened) {
    assert.ok(SHARED_NAMES.includes(name) || name === anchor(heading), name + " is neither a shared name nor the anchor of " + JSON.stringify(heading));
  }
});
