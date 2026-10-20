// The release workflow, .github/workflows/release.yml, held to the rules
// docs/maintainers/releasing.md states for it.
//
// A release workflow is the one place in this repository that holds a token able to write: it
// stores attestations and creates a release. Each rule below is one a later edit could break
// without any other check noticing, because the workflow runs only on a version tag:
//
// - it runs on a vX.Y.Z tag push and on a manual run, and on nothing else;
// - every action it uses is pinned by a full commit SHA with its tag in a comment, and pinned to the
//   same SHA as in ci.yml, which it calls;
// - the workflow grants nothing at the top, each job declares its own permissions, and the only
//   writes are the attestation pair in `attest` and `contents: write` in `release`;
// - `attest`, which holds the attestation token, checks out nothing and installs nothing, and the
//   files it attests are checked against SHA256SUMS first; a dry run in a private repository
//   attests nothing and says so;
// - a manual run on a tag is refused: a tag is released by pushing it;
// - the tag is checked through GitHub's API, which alone reports GitHub's verification of its
//   signature and answers for the tag as GitHub holds it, not through the clone, and every refusal
//   of the check, an API that does not answer included, ends in an error line;
// - the CHANGELOG section is found by the one heading rule, `## [X.Y.Z]` or
//   `## [X.Y.Z] - YYYY-MM-DD`, and has text in it;
// - the build runs on the newest Node.js 22, and the SBOM's root component is named after the
//   package, not after the folder npm ran in;
// - the build searches the packed tarball for disclosure needles before it sums the files;
// - CI runs only once `verify` passes, and every later job takes the version `verify` read;
// - no step publishes to npm or to any other registry, and no secret is read;
// - the release it creates is a draft, for an existing tag, on a tag push only, with the files
//   checked against SHA256SUMS first;
// - every `gh attestation verify` that releasing.md gives a reader names the release workflow and
//   the tag, so that it does not accept an attestation from another workflow or ref;
// - ci.yml stays callable by release.yml: it keeps `workflow_call`, asks for no permission the
//   caller does not grant, and its concurrency group is not one the caller could hold, while
//   release.yml sets no group at all;
// - ci.yml installs the packed tarball into a new project and runs the README example against it,
//   so the files a release attaches are tested as a consumer installs them;
// - ci.yml's probe of the siblings skips a sibling that is not found, asks again after any other
//   failure, and on a tag, which a release runs it for, fails rather than skip a sibling it
//   could not probe;
// - no `run:` script of either workflow pastes a `${{ ... }}` expression into its text.
//
// The files are read as text, line by line, by indentation: the repository has no YAML parser,
// and these rules are about the shape GitHub reads, which the indentation is. The steps whose
// shell decides a refusal are also run, by bash, with gh, git and npm stood in for; without a bash
// those tests skip.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PACKAGE_DIR } from "./bundle-kit.ts";

const read = (name: string) => readFileSync(join(PACKAGE_DIR, name), "utf8").replace(/\r\n/g, "\n");
const RELEASE = read(".github/workflows/release.yml");
const CI = read(".github/workflows/ci.yml");

/** The lines of a workflow with every whole-line comment and every blank line dropped. */
const codeLines = (text: string) => text.split("\n").filter((line) => line.trim() !== "" && !/^\s*#/.test(line));

const indentOf = (line: string) => line.length - line.trimStart().length;

/** The lines under `key:` at `indent` spaces, inside `lines`; null when there is no such key. */
function blockOf(lines: string[], key: string, indent: number): string[] | null {
  const head = lines.findIndex((line) => indentOf(line) === indent && line.trimStart().startsWith(key + ":"));
  if (head === -1) return null;
  const body: string[] = [];
  for (const line of lines.slice(head + 1)) {
    if (indentOf(line) <= indent) break;
    body.push(line);
  }
  return body;
}

/** The keys at exactly `indent` spaces in a block. */
const keysAt = (lines: string[], indent: number) =>
  lines.filter((line) => indentOf(line) === indent && /^[\w-]+:/.test(line.trimStart())).map((line) => line.trimStart().split(":")[0]!);

const LINES = codeLines(RELEASE);
const JOBS = blockOf(LINES, "jobs", 0) ?? [];
const job = (name: string) => {
  const body = blockOf(JOBS, name, 2);
  assert.ok(body !== null, "release.yml has no job " + name);
  return body;
};

test("release.yml runs on a vX.Y.Z tag push and on a manual run, and on nothing else", () => {
  const on = blockOf(LINES, "on", 0);
  assert.ok(on !== null, "release.yml has no `on:` block");
  assert.deepEqual(keysAt(on, 2).sort(), ["push", "workflow_dispatch"]);
  const push = blockOf(on, "push", 2)!;
  assert.deepEqual(keysAt(push, 4), ["tags"], "the push trigger names something besides tags");
  const tags = blockOf(push, "tags", 4)!.map((line) => line.trim());
  assert.deepEqual(tags, ['- "v[0-9]+.[0-9]+.[0-9]+"'], "the tag filter is not vX.Y.Z alone");
  assert.deepEqual(blockOf(on, "workflow_dispatch", 2), [], "the manual run takes inputs, which nothing reads");
});

test("every action release.yml uses is pinned by full commit SHA with its tag, as in ci.yml", () => {
  const usesOf = (text: string) =>
    codeLines(text)
      .map((line) => /^\s*(?:-\s+)?uses:\s*(\S+)(.*)$/.exec(line))
      .filter((match) => match !== null)
      .map((match) => ({ target: match[1]!, rest: match[2]! }));
  const pinned = new Map<string, string>();
  for (const { target } of usesOf(CI)) {
    const [action, sha] = target.split("@");
    pinned.set(action!, sha!);
  }
  const uses = usesOf(RELEASE);
  assert.ok(uses.length >= 7, "release.yml uses fewer actions than it is written with: " + uses.length);
  let local = 0;
  for (const { target, rest } of uses) {
    if (target.startsWith("./")) {
      // A workflow of this repository is read at the commit the run builds, so it is pinned by
      // that commit. ci.yml is the only one.
      assert.equal(target, "./.github/workflows/ci.yml", "release.yml calls a local workflow other than ci.yml");
      local += 1;
      continue;
    }
    const match = /^([\w.-]+\/[\w./-]+)@([0-9a-f]{40})$/.exec(target);
    assert.ok(match !== null, target + " is not pinned by a full commit SHA");
    assert.match(rest, /^\s+# v\d+\.\d+\.\d+$/, target + " has no tag comment after its SHA");
    const [, action, sha] = match;
    if (pinned.has(action!)) {
      assert.equal(sha, pinned.get(action!), action + " is pinned to another SHA in ci.yml");
    }
  }
  assert.equal(local, 1, "release.yml does not call ci.yml once");
  assert.ok(
    job("checks").some((line) => line.trim() === "uses: ./.github/workflows/ci.yml"),
    "the checks job is not the call of ci.yml",
  );
});

test("release.yml grants nothing at the top, and each job only the permissions it names", () => {
  assert.ok(LINES.includes("permissions: {}"), "release.yml does not set `permissions: {}` at the top");
  assert.ok(!/\b(?:write|read)-all\b/.test(RELEASE), "release.yml grants a blanket permission");
  const writes: Record<string, string[]> = { attest: ["attestations", "id-token"], release: ["contents"] };
  const jobs = keysAt(JOBS, 2);
  assert.deepEqual(jobs.sort(), ["attest", "build", "checks", "release", "verify"]);
  for (const name of jobs) {
    const permissions = blockOf(job(name), "permissions", 4);
    assert.ok(permissions !== null && permissions.length > 0, "job " + name + " declares no permissions");
    const granted = permissions.map((line) => {
      const match = /^\s{6}([\w-]+):\s*(read|write|none)$/.exec(line);
      assert.ok(match !== null, "job " + name + " has a permission line that is not `scope: read|write|none`: " + line);
      return { scope: match[1]!, level: match[2]! };
    });
    const written = granted.filter((grant) => grant.level === "write").map((grant) => grant.scope).sort();
    assert.deepEqual(written, writes[name] ?? [], "job " + name + " writes more or less than it needs");
  }
});

test("the job that attests runs only pinned actions and a check of the files against SHA256SUMS", () => {
  const attest = job("attest");
  const uses = attest
    .map((line) => /^\s*(?:-\s+)?uses:\s*([\w.-]+\/[\w./-]+)@/.exec(line)?.[1])
    .filter((action) => action !== undefined);
  assert.deepEqual(
    uses,
    ["actions/download-artifact", "actions/attest", "actions/attest"],
    "the attest job uses an action besides the download and the two attestations",
  );
  const code = attest.join("\n");
  for (const pattern of [/\bnpm\b/, /\bnpx\b/, /\bnode\b/, /\bpip\b/, /\bgit\s/, /\bcurl\b|\bwget\b/]) {
    assert.ok(!pattern.test(code), "the attest job runs " + pattern + " where the attestation token is");
  }
  const sums = code.indexOf("sha256sum --strict -c SHA256SUMS");
  assert.ok(sums !== -1, "the attest job does not check the files against SHA256SUMS");
  assert.ok(sums < code.indexOf("uses: actions/attest@"), "the attest job attests before it checks the files");
  // One action, two attestations, told apart by their inputs: with no sbom-path and no predicate
  // input, actions/attest writes the build provenance; with sbom-path, the SBOM attestation.
  const inputs = attest.flatMap((line, at) => {
    if (!line.includes("uses: actions/attest@")) return [];
    const indent = indentOf(line);
    return [keysAt(blockOf(attest.slice(at), "with", indent) ?? [], indent + 2)];
  });
  assert.deepEqual(inputs, [["subject-path"], ["subject-path", "sbom-path"]], "the attestations are not the provenance and then the SBOM");
  assert.ok(
    attest.some((line) => line.trim() === "needs: [verify, build]"),
    "the attest job does not wait for verify and build",
  );
  assert.ok(
    job("release").some((line) => line.trim() === "needs: [verify, attest]"),
    "the release job does not wait for the attestations",
  );
  const build = job("build").join("\n");
  assert.ok(!/uses:\s*actions\/attest@/.test(build), "the build job attests, with the code it runs");
});

test("the tag is checked through the API: annotated, on the commit built, signature verified", () => {
  const verify = job("verify").join("\n");
  assert.ok(!/git\s+cat-file/.test(verify), "the verify job reads the tag from the clone, which cannot say whether GitHub verified it");
  assert.ok(verify.includes("GH_TOKEN: ${{ github.token }}"), "the tag check has no token to ask the API with");
  // Two reads of the API, each kept in a variable and then read into shell variables: the ref,
  // whose object is an annotated tag, and that tag object, which names the commit and carries
  // GitHub's verification of its signature.
  const reads = [...verify.matchAll(/^\s*if ! (\w+)="\$\(gh api "([^"]+)" --jq '\[([^\]]+)\] \| @tsv'\)"; then$/gm)].map((match) => {
    const prefix = "IFS=$'\\t' read -r ";
    const suffix = ' <<< "$' + match[1]! + '"';
    const into = verify.split("\n").map((line) => line.trim()).find((line) => line.startsWith(prefix) && line.endsWith(suffix));
    assert.ok(into !== undefined, "the answer kept in " + match[1] + " is not read into shell variables at the tabs");
    return { names: into.slice(prefix.length, -suffix.length).split(" "), path: match[2]!, fields: match[3]!.split(", ") };
  });
  assert.deepEqual(
    reads,
    [
      { names: ["ref_type", "tag_sha"], path: "repos/$GITHUB_REPOSITORY/git/ref/tags/$TAG", fields: [".object.type", ".object.sha"] },
      {
        names: ["target_type", "target_sha", "verified", "reason"],
        path: "repos/$GITHUB_REPOSITORY/git/tags/$tag_sha",
        fields: [".object.type", ".object.sha", ".verification.verified", ".verification.reason"],
      },
    ],
    "the tag check does not read the ref and the tag object from the API",
  );
  assert.equal((verify.match(/\bgh api\b/g) ?? []).length, 2, "the tag check asks the API more than the two reads");
  for (const condition of ['"$ref_type" != "tag"', '"$target_type" != "commit"', '"$target_sha" != "$GITHUB_SHA"', '"$verified" != "true"']) {
    assert.ok(verify.includes("[ " + condition + " ]"), "the tag check does not refuse a tag unless " + condition.replace("!=", "=="));
  }
  // The commit is on the default branch: asked of the clone, whose checkout fetches the whole
  // history and every branch, without which every real tag would be refused as off the branch.
  assert.ok(
    verify.includes('if ! git merge-base --is-ancestor "$GITHUB_SHA" "refs/remotes/origin/$DEFAULT_BRANCH"; then'),
    "the tag check does not hold the commit to the default branch",
  );
  assert.ok(verify.includes("DEFAULT_BRANCH: ${{ github.event.repository.default_branch }}"), "the default branch is not the repository's");
  const steps = job("verify");
  const at = steps.findIndex((line) => line.trim().startsWith("- uses: actions/checkout@"));
  assert.ok(at !== -1, "the verify job checks nothing out");
  const next = steps.findIndex((line, i) => i > at && indentOf(line) <= indentOf(steps[at]!));
  assert.deepEqual(
    steps.slice(at + 1, next === -1 ? undefined : next).map((line) => line.trim()),
    ["with:", "fetch-depth: 0", "persist-credentials: false"],
    "the verify checkout does not fetch the whole history, which the default-branch check reads",
  );
});

/**
 * The CHANGELOG section heading the verify job looks for, as a test of one line: the job's
 * `heading=` pattern, with the `${VERSION//./…}` substitution bash makes, read as the extended
 * regular expression `grep -E` reads it. The pattern uses nothing on which ERE and a JavaScript
 * RegExp part ways, which the shape check below holds.
 */
function headingRule(version: string): (line: string) => boolean {
  const verify = job("verify").join("\n");
  const assigned = /^\s*heading="([^"]+)"$/m.exec(verify);
  assert.ok(assigned !== null, "the verify job has no heading= pattern");
  assert.ok(/^\s*if ! grep -Eq "\$heading" CHANGELOG\.md; then$/m.test(verify), "the verify job does not grep CHANGELOG.md with the pattern");
  const substitution = /\$\{VERSION\/\/\.\/([^}]*)\}/;
  const replacement = substitution.exec(assigned[1]!);
  assert.ok(replacement !== null, "the heading pattern does not escape the dots of the version");
  const pattern = assigned[1]!.replace(substitution, version.split(".").join(replacement[1]!));
  assert.match(pattern, /^[\^#\s\\[\]().0-9{}?$-]+$/, "the heading pattern uses a construct the test does not read as grep -E does: " + pattern);
  const regex = new RegExp(pattern);
  return (line) => regex.test(line);
}

test("the CHANGELOG section heading is `## [X.Y.Z]` or `## [X.Y.Z] - YYYY-MM-DD`, and nothing near it", () => {
  const accepts = headingRule("1.20.3");
  for (const line of ["## [1.20.3]", "## [1.20.3] - 2026-10-17"]) {
    assert.ok(accepts(line), "the release workflow refuses the heading " + line);
  }
  for (const line of [
    "## [1.20.3]rc",
    "## [1.20.3] — 2026-10-17",
    "## [1.20.3] - 2026-10-17 (yanked)",
    "## [1.20.3] -2026-10-17",
    // A date in other digits than ASCII ones: Arabic-Indic, then full-width.
    "## [1.20.3] - ٢٠٢٦-١٠-١٧",
    "## [1.20.3] - ２０２６-１０-１７",
    "## [1x20x3]",
    "## [11.20.3]",
    "### [1.20.3]",
    " ## [1.20.3]",
  ]) {
    assert.ok(!accepts(line), "the release workflow accepts the heading " + JSON.stringify(line));
  }
  const version = JSON.parse(read("package.json")).version as string;
  const own = headingRule(version);
  assert.ok(read("CHANGELOG.md").split("\n").some(own), "CHANGELOG.md has no section heading for " + version);
});

test("a bad tag stops before CI, and every later job takes the version verify read", () => {
  assert.ok(job("checks").some((line) => line.trim() === "needs: verify"), "ci.yml runs before the tag is verified");
  assert.ok(
    job("build").some((line) => line.trim() === "needs: [verify, checks]"),
    "the build job does not wait for verify and for CI",
  );
  for (const name of ["build", "attest", "release"]) {
    const body = job(name).join("\n");
    // The build reads the package's name from package.json for the SBOM; never its version.
    const rereads = job(name).filter((line) => /package(?:-lock)?\.json/.test(line) && /version/.test(line));
    assert.deepEqual(rereads, [], "job " + name + " reads the version again");
    const versions = [...body.matchAll(/^\s*VERSION: (.+)$/gm)].map((match) => match[1]!);
    assert.ok(versions.length > 0, "job " + name + " has no VERSION");
    for (const value of versions) {
      assert.equal(value, "${{ needs.verify.outputs.version }}", "job " + name + " takes its version from elsewhere");
    }
  }
});

test("no step of the release publishes to a registry or reads a secret", () => {
  const forbidden = [
    /\bnpm\s+(?:publish|dist-tag|access|token|adduser|login)\b/,
    /\b(?:yarn|pnpm)\s+(?:npm\s+)?publish\b/,
    /\btwine\b/,
    /pypi-publish/,
    /registry-url/,
    /--provenance/,
    /NODE_AUTH_TOKEN|NPM_TOKEN/,
    /\bsecrets\./,
    // The publication guard's approval: it also lifts the guard's private and publishConfig
    // checks, and releasing.md keeps it for a publish job that does not exist.
    /LOQUITUR_VERIFY_NPM_PUBLISH_APPROVED/,
  ];
  // ci.yml runs inside a release too, through the checks job.
  for (const [name, text] of [["release.yml", RELEASE], ["ci.yml", CI]] as const) {
    const code = codeLines(text).join("\n");
    for (const pattern of forbidden) {
      assert.ok(!pattern.test(code), name + " matches " + pattern + ": a release publishes nothing");
    }
  }
});

test("the release is a draft for an existing tag, created on a tag push only", () => {
  const release = job("release");
  assert.ok(
    release.some((line) => line.trim() === "if: github.event_name == 'push'"),
    "the release job also runs on a manual run, which is a dry run",
  );
  const commands = (lines: string[]) => lines.join("\n").replace(/\\\n\s*/g, " ").split("\n");
  const ghRelease = commands(LINES).filter((line) => /\bgh\s+release\b/.test(line));
  assert.equal(ghRelease.length, 1, "release.yml runs gh release more than once: " + JSON.stringify(ghRelease));
  assert.ok(commands(release).includes(ghRelease[0]!), "gh release runs outside the release job");
  const create = ghRelease[0]!;
  assert.match(create, /\bgh\s+release\s+create\b/);
  assert.match(create, /\s--draft(?:\s|$)/, "the release is not created as a draft");
  assert.match(create, /\s--verify-tag(?:\s|$)/, "the release could create its tag");
  assert.ok(!/--draft=false|--latest|--discussion-category/.test(create), "the create step publishes the release");
  assert.ok(create.endsWith(" release-files/*"), "the release does not carry the files the artifact holds");
  const code = release.join("\n");
  const sums = code.indexOf("sha256sum --strict -c SHA256SUMS");
  assert.ok(sums !== -1 && sums < code.indexOf("gh release create"), "the release job does not check the files before it uploads them");
});

test("the maintainer documents name the release workflow and how to check its files", () => {
  const releasing = read("docs/maintainers/releasing.md");
  for (const needle of [".github/workflows/release.yml", "sha256sum -c SHA256SUMS", "gh attestation verify", "git tag -v"]) {
    assert.ok(releasing.includes(needle), "docs/maintainers/releasing.md does not give " + needle);
  }
  const verifies = releasing
    .replace(/\\\n\s*/g, " ")
    .split("\n")
    .filter((line) => line.startsWith("gh attestation verify "));
  assert.equal(verifies.length, 4, "releasing.md gives another number of attestation checks: " + verifies.length);
  for (const command of verifies) {
    assert.ok(
      command.includes("--signer-workflow loquitur-dev/loquitur-verify-ts/.github/workflows/release.yml") &&
        command.includes("--source-ref refs/tags/vX.Y.Z"),
      "an attestation check accepts any workflow or ref of the repository: " + command,
    );
    assert.match(
      command,
      /\s--deny-self-hosted-runners(?:\s|$)/,
      "an attestation check accepts a build on a self-hosted runner: " + command,
    );
  }
  const layout = read("docs/maintainers/REPOSITORY_LAYOUT.md");
  assert.ok(layout.includes("`.github/workflows/release.yml`"), "REPOSITORY_LAYOUT.md has no row for the release workflow");
  assert.ok(read("CONTRIBUTING.md").includes("docs/maintainers/releasing.md"), "CONTRIBUTING.md does not link releasing.md");
  assert.ok(read("SECURITY.md").includes("docs/maintainers/releasing.md"), "SECURITY.md does not point to releasing.md");
});

/** The `scope: level` lines of a permissions block, as a map; `{}` and an absent block are empty. */
function grantsOf(lines: string[] | null, where: string): Map<string, string> {
  const grants = new Map<string, string>();
  for (const line of lines ?? []) {
    const match = /^\s*([\w-]+):\s*(read|write|none)$/.exec(line);
    assert.ok(match !== null, where + " has a permission line that is not `scope: read|write|none`: " + line);
    grants.set(match[1]!, match[2]!);
  }
  return grants;
}

test("ci.yml stays callable by release.yml, and neither workflow can wait on itself", () => {
  const ci = codeLines(CI);
  const on = blockOf(ci, "on", 0);
  assert.ok(on !== null && keysAt(on, 2).includes("workflow_call"), "ci.yml lost `workflow_call`: the release's checks job cannot call it");
  // A called workflow may ask for no more than its caller grants, or the run fails before any job
  // starts, and only on a tag push.
  const level = { none: 0, read: 1, write: 2 } as Record<string, number>;
  const granted = grantsOf(blockOf(job("checks"), "permissions", 4), "the checks job");
  assert.ok(granted.size > 0, "the checks job grants ci.yml nothing");
  const asked: [string, Map<string, string>][] = [["ci.yml", grantsOf(blockOf(ci, "permissions", 0), "ci.yml")]];
  for (const name of keysAt(blockOf(ci, "jobs", 0) ?? [], 2)) {
    asked.push(["ci.yml job " + name, grantsOf(blockOf(blockOf(blockOf(ci, "jobs", 0)!, name, 2)!, "permissions", 4), "ci.yml job " + name)]);
  }
  assert.ok(!/\b(?:write|read)-all\b/.test(CI), "ci.yml asks for a blanket permission");
  for (const [where, grants] of asked) {
    for (const [scope, wanted] of grants) {
      assert.ok(level[wanted]! <= level[granted.get(scope) ?? "none"]!, where + " asks for " + scope + ": " + wanted + ", which release.yml does not grant");
    }
  }
  // Inside a called workflow, github.workflow and github.ref are the caller's: a caller holding
  // `${{ github.workflow }}-${{ github.ref }}` would share its group with the run it calls.
  assert.ok(!LINES.some((line) => /^\s*concurrency:/.test(line)), "release.yml sets a concurrency group, which the ci.yml it calls could wait on");
  assert.deepEqual(
    blockOf(ci, "concurrency", 0)?.map((line) => line.trim()),
    ["group: ci-${{ github.workflow }}-${{ github.ref }}-${{ github.event_name }}", "cancel-in-progress: true"],
    "ci.yml's concurrency group is not the one that keeps it apart from its caller",
  );
});

/**
 * Every `run:` script of a workflow, as written, comments included: GitHub evaluates an expression
 * wherever it stands in the script, a shell comment included.
 */
function runScripts(text: string): string[] {
  const lines = text.split("\n");
  const found: string[] = [];
  lines.forEach((line, index) => {
    const match = /^(\s*(?:-\s+)?)run:\s*(.*)$/.exec(line);
    if (match === null) return;
    const column = match[1]!.length;
    if (!/^[|>][-+]?$/.test(match[2]!)) {
      found.push(match[2]!);
      return;
    }
    const body: string[] = [];
    for (const next of lines.slice(index + 1)) {
      if (next.trim() !== "" && indentOf(next) <= column) break;
      body.push(next);
    }
    found.push(body.join("\n"));
  });
  return found;
}

test("no run script of ci.yml or release.yml pastes an expression into its text", () => {
  // The value of an expression is pasted into the script before the shell reads it, so a branch
  // name or a commit message becomes shell code. Values reach a script through `env:`.
  const planted = runScripts("    steps:\n      - run: |\n          echo ok\n          # ${{ github.ref }}\n      - run: echo done\n");
  assert.deepEqual(planted, ["          echo ok\n          # ${{ github.ref }}", "echo done"], "the reader of run scripts misses a block");
  for (const [name, text] of [["release.yml", RELEASE], ["ci.yml", CI]] as const) {
    const runs = runScripts(text);
    assert.ok(runs.length >= 8, name + " has fewer run scripts than it is written with: " + runs.length);
    const pasted = runs.filter((script) => script.includes("${{"));
    assert.deepEqual(pasted, [], name + " pastes an expression into a run script");
  }
});

/** The `run: |` script of the step named `name`, of release.yml unless `workflow` names another, dedented, comments included. */
function stepScript(name: string, workflow: readonly [string, string] = ["release.yml", RELEASE]): string {
  const lines = workflow[1].split("\n");
  const head = lines.findIndex((line) => line.trim() === "- name: " + name);
  assert.ok(head !== -1, workflow[0] + " has no step named " + JSON.stringify(name));
  const stepIndent = indentOf(lines[head]!);
  for (let index = head + 1; index < lines.length; index++) {
    const line = lines[index]!;
    if (line.trim() !== "" && indentOf(line) <= stepIndent) break;
    const run = /^(\s*)run: \|$/.exec(line);
    if (run === null) continue;
    const body: string[] = [];
    for (const next of lines.slice(index + 1)) {
      if (next.trim() !== "" && indentOf(next) <= run[1]!.length) break;
      body.push(next);
    }
    const margin = Math.min(...body.filter((next) => next.trim() !== "").map(indentOf));
    return body.map((next) => next.slice(margin)).join("\n");
  }
  assert.fail("the step " + JSON.stringify(name) + " has no `run: |` script");
}

/**
 * A bash with awk, grep and cut that passes this process's environment on, or null. On Windows
 * the `bash` on the PATH may be the WSL launcher, which passes none: the probe refuses it.
 */
function findBash(): string | null {
  const candidates = [process.env.LOQUITUR_BASH, process.platform === "win32" ? "C:\\Program Files\\Git\\bin\\bash.exe" : undefined, "bash"];
  for (const candidate of candidates.filter((c): c is string => Boolean(c))) {
    const probe = spawnSync(candidate, ["-c", 'command -v awk grep cut >/dev/null && printf %s "$LQ_PROBE"'], {
      env: { ...process.env, LQ_PROBE: "passed" },
      encoding: "utf8",
    });
    if (!probe.error && probe.status === 0 && probe.stdout === "passed") return candidate;
  }
  return null;
}

const BASH = findBash();
const NO_BASH = BASH === null ? "no bash with awk, grep and cut on this host (LOQUITUR_BASH, bash)" : false;

/** A release.yml step's script, run by bash in `cwd` after `prelude`, which stands in for gh, git or npm. */
function runStep(name: string, cwd: string, env: Record<string, string>, prelude = "") {
  const run = spawnSync(BASH!, ["-c", prelude + "\n" + stepScript(name)], { cwd, env: { ...process.env, ...env }, encoding: "utf8" });
  assert.equal(run.error, undefined);
  return { status: run.status, out: run.stdout + run.stderr };
}

const scratch = () => mkdtempSync(join(tmpdir(), "lq-release-step-"));

test("a manual run on a tag is refused before anything else runs", { skip: NO_BASH }, () => {
  const steps = job("verify");
  const first = (blockOf(steps, "steps", 4) ?? [])[0];
  assert.equal(first?.trim(), "- name: A tag is released by pushing it, not by a manual run", "the refusal is not the verify job's first step");
  const condition = steps[steps.indexOf(first!) + 1]!.trim();
  assert.equal(condition, "if: github.event_name != 'push' && github.ref_type == 'tag'", "the refusal does not run on a manual run on a tag");
  const run = runStep("A tag is released by pushing it, not by a manual run", PACKAGE_DIR, {});
  assert.equal(run.status, 1, run.out);
  assert.match(run.out, /^::error::a dry run runs on a branch; a tag is released by pushing it$/m);
});

test("the verify job refuses a CHANGELOG section with no text", { skip: NO_BASH }, () => {
  const step = "The CHANGELOG has a section for the version, with text in it";
  const cases: [string, string, RegExp | null][] = [
    ["with text", "# Changelog\n\n## [1.2.3] - 2026-10-17\n\n### Added\n- a thing\n\n## [1.2.2]\n\nolder\n", null],
    ["text after blank lines, at the end", "# Changelog\n\n## [1.2.3]\n\n\nThe text.\n", null],
    ["empty before the next section", "# Changelog\n\n## [1.2.3]\n\n## [1.2.2]\n\nolder\n", /section for 1\.2\.3 has no text/],
    ["empty at the end of the file", "# Changelog\n\n## [1.2.2]\n\nolder\n\n## [1.2.3]\n\n", /section for 1\.2\.3 has no text/],
    ["no section", "# Changelog\n\n## [1.2.2]\n\nolder\n", /has no section heading for 1\.2\.3/],
  ];
  for (const [label, changelog, refusal] of cases) {
    const dir = scratch();
    try {
      writeFileSync(join(dir, "CHANGELOG.md"), changelog);
      const run = runStep(step, dir, { VERSION: "1.2.3" });
      if (refusal === null) {
        assert.equal(run.status, 0, label + ": " + run.out);
      } else {
        assert.equal(run.status, 1, label + ": " + run.out);
        assert.match(run.out, new RegExp("::error::.*" + refusal.source), label);
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

test("the tag check ends every refusal with an error line, an API failure included", { skip: NO_BASH }, () => {
  const step = "The tag is vX.Y.Z of that version, annotated, signed and on the default branch";
  // gh answers from MOCK_REF and MOCK_TAG (`fail` fails as gh does on a 404); git answers the
  // default-branch question from MOCK_ON_BRANCH.
  const prelude = [
    "gh() {",
    '  case "$2" in */git/ref/tags/*) answer="$MOCK_REF" ;; *) answer="$MOCK_TAG" ;; esac',
    '  if [ "$answer" = fail ]; then echo "gh: Not Found (HTTP 404)" >&2; return 1; fi',
    "  printf '%b\\n' \"$answer\"",
    "}",
    'git() { [ "$1" = merge-base ] && [ "$MOCK_ON_BRANCH" = yes ]; }',
  ].join("\n");
  const commit = "c".repeat(40);
  const good = { MOCK_REF: "tag\\t" + "a".repeat(40), MOCK_TAG: "commit\\t" + commit + "\\ttrue\\tvalid", MOCK_ON_BRANCH: "yes" };
  const base = { TAG: "v1.2.3", VERSION: "1.2.3", DEFAULT_BRANCH: "main", GITHUB_REPOSITORY: "owner/repo", GITHUB_SHA: commit };
  const cases: [string, Record<string, string>, RegExp | null][] = [
    ["a good tag", {}, null],
    ["the ref cannot be read", { MOCK_REF: "fail" }, /no answer for the ref of tag v1\.2\.3/],
    ["a lightweight tag", { MOCK_REF: "commit\\t" + commit }, /tag v1\.2\.3 is lightweight/],
    ["a ref with no object", { MOCK_REF: "\\t" }, /names no tag object/],
    ["the tag object cannot be read", { MOCK_TAG: "fail" }, /no answer for the tag object/],
    ["a tag on another commit", { MOCK_TAG: "commit\\t" + "d".repeat(40) + "\\ttrue\\tvalid" }, /not the commit this run builds/],
    ["an unverified signature", { MOCK_TAG: "commit\\t" + commit + "\\tfalse\\tunknown signature type" }, /no signature GitHub verifies \(unknown signature type\)/],
    ["a commit off the default branch", { MOCK_ON_BRANCH: "no" }, /not on main/],
    ["a tag that is not the version", { TAG: "v1.2.4" }, /does not match package\.json version/],
  ];
  for (const [label, change, refusal] of cases) {
    const run = runStep(step, PACKAGE_DIR, { ...base, ...good, ...change }, prelude);
    if (refusal === null) {
      assert.equal(run.status, 0, label + ": " + run.out);
      assert.match(run.out, /annotated, signed and verified/, label);
    } else {
      assert.equal(run.status, 1, label + ": " + run.out);
      assert.match(run.out, new RegExp("^::error::.*" + refusal.source, "m"), label + ": " + run.out);
    }
  }
});

test("the SBOM names the package, not the folder npm ran in", { skip: NO_BASH }, () => {
  const manifest = JSON.parse(read("package.json")) as { name: string; version: string };
  // What npm sbom writes in a checkout folder named loquitur-verify-ts: the root component's
  // name is the folder's, its bom-ref and purl the package's.
  const root = {
    "bom-ref": manifest.name + "@" + manifest.version,
    type: "library",
    name: "loquitur-verify-ts",
    version: manifest.version,
    purl: "pkg:npm/" + manifest.name.replace("@", "%40") + "@" + manifest.version,
  };
  const written = { bomFormat: "CycloneDX", specVersion: "1.5", metadata: { component: root }, components: [] };
  const cases: [string, object, boolean][] = [
    ["as npm writes it", written, true],
    ["with another version", { ...written, metadata: { component: { ...root, version: "9.9.9" } } }, false],
    ["with no root component", { ...written, metadata: {} }, false],
  ];
  for (const [label, sbom, named] of cases) {
    const dir = scratch();
    try {
      writeFileSync(join(dir, "package.json"), read("package.json"));
      mkdirSync(join(dir, "release-files"));
      writeFileSync(join(dir, "sbom.json"), JSON.stringify(sbom));
      const run = runStep("Write the CycloneDX SBOM", dir, { VERSION: manifest.version }, "npm() { cat sbom.json; }");
      if (!named) {
        assert.equal(run.status, 1, label + ": " + run.out);
        assert.match(run.out, /^::error::/m, label);
        continue;
      }
      assert.equal(run.status, 0, label + ": " + run.out);
      const result = JSON.parse(readFileSync(join(dir, "release-files", "loquitur-verify-" + manifest.version + ".cdx.json"), "utf8"));
      assert.equal(result.metadata.component.name, manifest.name, "the SBOM's root component is not named after the package");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});

test("the build runs on the newest Node.js 22, as releasing.md says", () => {
  const build = job("build").map((line) => line.trim());
  assert.ok(build.includes('node-version: "22"'), "the build does not set up Node.js 22");
  assert.ok(build.includes("check-latest: true"), "setup-node takes the 22.x cached on the runner, not the newest");
  assert.ok(build.includes("package-manager-cache: false"), "setup-node may restore a dependency cache into the release build");
  assert.ok(read("docs/maintainers/releasing.md").includes("newest Node.js 22"), "releasing.md does not say which Node.js builds a release");
});

test("the build searches the packed tarball for disclosure needles before it sums the files", () => {
  const build = job("build").join("\n");
  const scan = build.indexOf('run: python tools/check_packed_tarball.py "release-files/loquitur-verify-$VERSION.tgz"');
  assert.ok(scan !== -1, "the build does not run tools/check_packed_tarball.py over the tarball it packed");
  const pack = build.indexOf("npm pack --pack-destination release-files");
  assert.ok(pack !== -1 && pack < scan, "the build searches the tarball before it packs it");
  assert.ok(scan < build.indexOf("> SHA256SUMS"), "the build sums the files before it searches the tarball");
  assert.ok(scan < build.indexOf("uses: actions/upload-artifact@"), "the build keeps the files before it searches the tarball");
  assert.ok(
    build.lastIndexOf("uses: actions/setup-python@", scan) !== -1,
    "the build runs the tarball check with no Python set up",
  );
  assert.ok(read("docs/maintainers/releasing.md").includes("tools/check_packed_tarball.py"), "releasing.md does not say the tarball is searched");
});

test("a dry run in a private repository attests nothing, and says so", () => {
  const attest = job("attest");
  const guard = "if: github.event_name == 'push' || !github.event.repository.private";
  const attestations = attest.flatMap((line, at) => (line.includes("uses: actions/attest@") ? [at] : []));
  assert.equal(attestations.length, 2, "the attest job does not run actions/attest twice, for the provenance and the SBOM");
  for (const at of attestations) {
    assert.ok(at > 0 && attest[at - 1]!.trim() === guard, "an attestation runs in a private dry run, where GitHub stores no attestation");
  }
  const notice = attest.findIndex((line) => line.trim() === "- name: Say that this dry run attested nothing");
  assert.ok(notice !== -1, "a dry run that attested nothing does not say so");
  assert.equal(attest[notice + 1]!.trim(), "if: github.event_name != 'push' && github.event.repository.private");
  // The same step, in the same place, as in the three other repositories: the last of the job,
  // after both attestations.
  assert.equal(
    attest[notice + 2]!.trim(),
    'run: echo "::notice::private repository, so this dry run built, summed and described the files and attested none"',
  );
  assert.equal(notice + 3, attest.length, "the notice is not the last step of the attest job");
  assert.ok(attestations.at(-1)! < notice, "the notice comes before an attestation");
});

test("CI installs the packed tarball into a new project and runs the README example against it", () => {
  const packaging = blockOf(blockOf(codeLines(CI), "jobs", 0) ?? [], "packaging", 2);
  assert.ok(packaging !== null, "ci.yml has no packaging job");
  const script = packaging.map((line) => line.trim());
  const order = [
    'npm pack --pack-destination "$packed"',
    'cp examples/verify-test-vectors.mjs "$project/"',
    'cd "$project"',
    'npm install --ignore-scripts --no-audit --no-fund "${tarballs[0]}"',
    'node verify-test-vectors.mjs "$GITHUB_WORKSPACE/test-vectors"',
  ].map((line) => script.indexOf(line));
  assert.ok(!order.includes(-1), "the packaging job does not pack, install and run the example in a new project: " + order);
  assert.deepEqual([...order].sort((a, b) => a - b), order, "the packaging job runs the installed example out of order");
  assert.ok(script.includes('project="$RUNNER_TEMP/installed"'), "the project the tarball is installed into is inside the checkout");
});

// `git` as GitHub answers the sibling probe: STUB_PROBE holds one `status|message` answer per
// attempt, separated by `;`, the last one repeated, and the file `attempts` counts the calls;
// `sleep` returns at once. Bash builtins only.
const PROBE_STUBS = [
  "git() {",
  "  local count=0 answers line",
  "  if [ -f attempts ]; then read -r count < attempts; fi",
  "  echo $((count + 1)) > attempts",
  "  IFS=';' read -ra answers <<< \"$STUB_PROBE\"",
  "  line=\"${answers[count < ${#answers[@]} ? count : ${#answers[@]} - 1]}\"",
  "  echo \"${line#*|}\" >&2",
  "  return \"${line%%|*}\"",
  "}",
  "sleep() { :; }",
].join("\n");
const PROBE = "Find the siblings that are publicly readable";
const PROBE_READABLE = "0|";
const PROBE_NOT_FOUND: Record<string, string> = {
  private: "128|fatal: could not read Username for 'https://github.com': terminal prompts disabled",
  absent: "128|remote: Repository not found.\nfatal: repository 'https://github.com/o/r.git/' not found",
  "no HEAD": "2|",
};
const PROBE_UNREACHABLE: Record<string, string> = {
  "no name resolution": "128|fatal: unable to access 'https://github.com/o/r.git/': Could not resolve host: github.com",
  "a server error": "128|fatal: unable to access 'https://github.com/o/r.git/': The requested URL returned error: 503",
  "a rate limit": "128|fatal: unable to access 'https://github.com/o/r.git/': The requested URL returned error: 403",
};

/** The siblings the probe asks for, in its order. */
function probedSiblings(): string[] {
  const found = /^for repo in ([a-z -]+); do$/m.exec(stepScript(PROBE, ["ci.yml", CI]));
  assert.ok(found !== null, "the probe names no sibling");
  return found[1]!.split(" ");
}

/** The probe step, run as the runner runs a bash step, with git answering `answers`. */
function runProbe(answers: string, refType: string) {
  const dir = scratch();
  try {
    const output = join(dir, "output");
    writeFileSync(output, "");
    const env = { ...process.env, OWNER: "owner", REF_TYPE: refType, STUB_PROBE: answers, GITHUB_OUTPUT: output };
    const script = PROBE_STUBS + "\n" + stepScript(PROBE, ["ci.yml", CI]);
    const run = spawnSync(BASH!, ["--noprofile", "--norc", "-eo", "pipefail", "-c", script], { cwd: dir, env, encoding: "utf8" });
    assert.equal(run.error, undefined);
    let attempts = 0;
    try {
      attempts = Number(readFileSync(join(dir, "attempts"), "utf8"));
    } catch {
      // No attempt was made.
    }
    return { status: run.status, out: run.stdout + run.stderr, stdout: run.stdout, outputs: readFileSync(output, "utf8").split("\n"), attempts };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("ci.yml's probe reads the ref type through env", () => {
  const siblings = blockOf(blockOf(codeLines(CI), "jobs", 0) ?? [], "siblings", 2) ?? [];
  const env = siblings.find((line) => line.trim().startsWith("env: { GIT_TERMINAL_PROMPT"));
  assert.ok(env?.includes('REF_TYPE: "${{ github.ref_type }}"'), "the probe step does not read github.ref_type through env");
});

test("ci.yml's probe checks out every sibling that answers", { skip: NO_BASH }, () => {
  for (const refType of ["branch", "tag"]) {
    const run = runProbe(PROBE_READABLE, refType);
    assert.equal(run.status, 0, run.out);
    assert.ok(run.outputs.includes("published=" + probedSiblings().join(" ")), run.outputs.join("\n"));
    assert.equal(run.attempts, probedSiblings().length);
  }
});

test("ci.yml's probe skips a sibling that is not found at once, on a tag too", { skip: NO_BASH }, () => {
  for (const [label, answer] of Object.entries(PROBE_NOT_FOUND)) {
    for (const refType of ["branch", "tag"]) {
      const run = runProbe(answer, refType);
      assert.equal(run.status, 0, label + ": " + run.out);
      assert.ok(run.outputs.includes("published=") && !run.stdout.includes("::"), label + ": " + run.out);
      assert.equal(run.attempts, probedSiblings().length, label);
    }
  }
});

test("ci.yml's probe fails a run on a tag when a sibling cannot be probed for any other reason", { skip: NO_BASH }, () => {
  for (const [label, answer] of Object.entries(PROBE_UNREACHABLE)) {
    const run = runProbe(answer, "tag");
    assert.equal(run.status, 1, label + ": " + run.out);
    assert.ok(run.stdout.includes("::error::" + probedSiblings()[0] + " could not be probed"), label + ": " + run.out);
    assert.equal(run.attempts, 4, label);
    assert.deepEqual(run.outputs, [""], label);
  }
});

test("ci.yml's probe warns and skips a sibling it cannot probe on a run that is not on a tag", { skip: NO_BASH }, () => {
  for (const [label, answer] of Object.entries(PROBE_UNREACHABLE)) {
    const run = runProbe(answer, "branch");
    assert.equal(run.status, 0, label + ": " + run.out);
    assert.equal(run.stdout.split("::warning::").length - 1, probedSiblings().length, label + ": " + run.out);
    assert.ok(run.outputs.includes("published="), label);
    assert.equal(run.attempts, 4 * probedSiblings().length, label);
  }
});

test("ci.yml's probe asks again after a transient failure", { skip: NO_BASH }, () => {
  const run = runProbe(PROBE_UNREACHABLE["a server error"] + ";" + PROBE_READABLE, "tag");
  assert.equal(run.status, 0, run.out);
  assert.ok(run.outputs.includes("published=" + probedSiblings().join(" ")), run.outputs.join("\n"));
  assert.equal(run.attempts, probedSiblings().length + 1);
});
