// tools/check_public_boundary.py is one file kept in three published repositories: this one,
// loquitur-schemas and loquitur-verify-py. Its needle lists and its maintainer rule are the
// protocol checker's, tools/check_public_spec_boundary.py in loquitur-protocol. The two Python
// repositories hold both facts in their suites; this package has no Python suite, so this file
// holds them here: the tool passes over this repository, the copy here is the other copies byte
// for byte, and its constants and every decision its team_claim makes are the protocol checker's,
// compared over the same sentences the Python suites use. The Python that runs the tool is the
// host's (LOQUITUR_PYTHON, else `python`, else `python3`); the tool needs only the standard
// library. Without a Python, or without a sibling, the tests skip; under
// LOQUITUR_REQUIRE_SIBLINGS they fail, naming what is missing.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { REQUIRE_SIBLINGS_ENV, sibling, siblingsRequired } from "./siblings.js";

const PACKAGE_DIR = join(dirname(fileURLToPath(import.meta.url)), "..");
const WORKSPACE = join(PACKAGE_DIR, "..");
const TOOL = join(PACKAGE_DIR, "tools", "check_public_boundary.py");

const PROTOCOL = sibling(
  "loquitur-protocol",
  [join(WORKSPACE, "loquitur-protocol")],
  "tools/check_public_spec_boundary.py",
  "loquitur-protocol is not checked out beside this repository",
);
const SCHEMAS = sibling(
  "loquitur-schemas",
  [join(WORKSPACE, "loquitur-schemas")],
  "tools/check_public_boundary.py",
  "loquitur-schemas is not checked out beside this repository",
);
const VERIFY_PY = sibling(
  "loquitur-verify-py",
  [join(WORKSPACE, "loquitur-verify-py")],
  "tools/check_public_boundary.py",
  "loquitur-verify-py is not checked out beside this repository",
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
  throw new Error(`${REQUIRE_SIBLINGS_ENV} is set, but there is ${NO_PYTHON}; tools/check_public_boundary.py cannot run`);
}

test("the tool passes over this repository", { skip: NO_PYTHON }, () => {
  const run = spawnSync(PYTHON!, [TOOL], { cwd: PACKAGE_DIR, encoding: "utf8" });
  assert.equal(run.error, undefined);
  assert.equal(run.status, 0, run.stdout + run.stderr);
  assert.ok(run.stdout.split(/\r?\n/).includes("public_boundary_ok"), run.stdout);
});

test("the copy here is the copy in every other published repository, byte for byte", {
  skip: SCHEMAS.options.skip || VERIFY_PY.options.skip,
}, () => {
  const here = readFileSync(TOOL);
  const differing = [SCHEMAS, VERIFY_PY]
    .map((copy) => copy.path("tools/check_public_boundary.py"))
    .filter((path) => !readFileSync(path).equals(here));
  assert.deepEqual(differing, []);
});

// The sentences the Python suites give both rules; the answers must agree on each one.
const CLAIMS = [
  "This repository is maintained by the Loquitur " + "core team.\n",
  "This repository is maintained by a small team of maintainers.\n",
  "This repository is maintained by its owner, one person, not a team.\n",
  "Governance is preserved.\n",
];

test("the needle lists and the maintainer rule are the protocol checker's", {
  skip: NO_PYTHON || PROTOCOL.options.skip,
}, () => {
  const protocol = PROTOCOL.path("tools/check_public_spec_boundary.py");
  const script = [
    "import importlib.util, json, sys",
    "def load(path, name):",
    "    spec = importlib.util.spec_from_file_location(name, path)",
    "    module = importlib.util.module_from_spec(spec)",
    "    spec.loader.exec_module(module)",
    "    return module",
    "tool = load(sys.argv[1], 'check_public_boundary')",
    "protocol = load(sys.argv[2], 'check_public_spec_boundary')",
    "claims = json.loads(sys.stdin.read())",
    "def surface(module):",
    "    return {",
    "        'GOVERNANCE': module.GOVERNANCE,",
    "        'MAINTAINED_BY_A_TEAM': [module.MAINTAINED_BY_A_TEAM.pattern, module.MAINTAINED_BY_A_TEAM.flags],",
    "        'MAINTAINED_BY_ONE_PERSON': module.MAINTAINED_BY_ONE_PERSON,",
    "        'DISCLOSURE_SUBSTRINGS': list(module.DISCLOSURE_SUBSTRINGS),",
    "        'PRIVATE_PERIMETER_SUBSTRINGS': list(module.PRIVATE_PERIMETER_SUBSTRINGS),",
    "        'team_claim': [module.team_claim(text) for text in claims],",
    "    }",
    "print(json.dumps({'tool': surface(tool), 'protocol': surface(protocol)}))",
  ].join("\n");
  const run = spawnSync(PYTHON!, ["-c", script, TOOL, protocol], { input: JSON.stringify(CLAIMS), encoding: "utf8" });
  assert.equal(run.error, undefined);
  assert.equal(run.status, 0, run.stderr);
  const { tool, protocol: checker } = JSON.parse(run.stdout);
  assert.deepEqual(tool, checker);
  // Not vacuous: the sentences draw both answers, a team claim and none.
  assert.ok(tool.team_claim.some((claim: string | null) => claim !== null));
  assert.ok(tool.team_claim.some((claim: string | null) => claim === null));
  for (const key of ["DISCLOSURE_SUBSTRINGS", "PRIVATE_PERIMETER_SUBSTRINGS"]) {
    assert.ok(tool[key].length > 0, key);
  }
});
