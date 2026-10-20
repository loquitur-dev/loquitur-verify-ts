// What the published files of this package say the verifier does, held to what it does.
//
// A published sentence that scopes what the package does can go stale while the code changes beside
// it: a summary that says the verifier authenticates no trust registry against a root, and that an
// authorization run can do no better than a review, would contradict README.md's "Scope and
// limits", which states the opposite. A sweep keyed to the vocabulary of one such sentence cannot
// reach the next one.
//
// So the rule is a comparison, not a word list: a published file states the outcome of an
// authorization run in the words a run of this package produces here, and the citation it hangs
// that on resolves. The runs are made through every entry, because the sentence is about the
// package and not about one of its doors. The keys are made for the run and never written.
//
// This file runs in a single-repository clone: it reads no sibling checkout, so it holds the
// published copy's own README.md, which is the one place the claim has to be true.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { Bundle, ENTRIES, PACKAGE_DIR, ephemeralAuthorizationWith, ephemeralRoot, rootDocument } from "./bundle-kit.ts";
import { trackedFiles } from "./tracked-files.ts";

/** The operator's evaluation time: the fixture windows hold it. */
const EVALUATION_TIME = "2026-05-10T00:00:00Z";

type Doc = Record<string, any>;

/** The published files that state what an authorization run of this package reports. */
const CLAIMING = ["README.md"];

// The phrases of a limit this package does not have. Built from their words rather than written
// out, so this file does not carry the sentences the sweep below refuses: the guard would
// otherwise find itself and never hold anything else.
const ABSENT_LIMIT = [["no", "trust-root", "verification"], ["authorization", "is", "review", "at", "best"]].map((words) => words.join(" "));

const flat = (text: string) => text.replace(/\s+/g, " ");
const read = (name: string) => readFileSync(join(PACKAGE_DIR, name), "utf8");

/**
 * The material of one authorization run: a bundle, an entry signed by an issuer key made for the
 * run, the trust registry authorizing it signed by the root `N`, and a stranger root under the same
 * key id.
 */
function material() {
  const bundle = Bundle.linkValid().seal();
  const { root: N, sign } = ephemeralRoot("root-1");
  const { registryEntry, trustRegistry } = ephemeralAuthorizationWith(bundle, { trust: (t: Doc) => { delete t.signature; } });
  sign(trustRegistry);
  return { bundle, registryEntry, trustRegistry, N, stranger: ephemeralRoot("root-1").root };
}

/**
 * What an authorization run through `verify`, at the operator's evaluation time, reports about a
 * trust registry it can authenticate, one it cannot, and one it is given no root for: the sentence
 * the published files have to carry.
 */
function sentenceFrom(verify: (bundle: Bundle, options?: any) => any): string {
  const { bundle, registryEntry, trustRegistry, N, stranger } = material();
  const run = (roots: Doc[] | null) =>
    verify(bundle, roots === null
      ? { registryEntry, trustRegistry, evaluationTime: EVALUATION_TIME }
      : { registryEntry, trustRegistry, trustRoots: rootDocument(roots), evaluationTime: EVALUATION_TIME });
  const held = run([N]);
  const other = run([stranger]);
  const none = run(null);
  const status = (report: any): string => report.trust_registry?.trust_registry_root_signature_status;
  assert.equal(
    new Set([held.verdict, other.verdict, none.verdict]).size,
    3,
    "the three runs do not part: the sentence below would hold over a verifier that ignores its roots",
  );
  return (
    "an authorization run that holds at the operator's evaluation time is " + held.verdict + " when the registry authenticates (`" + status(held) +
    "`) and " + other.verdict + " otherwise; without roots it is " + none.verdict + " (`" + status(none) + "`)"
  );
}

test("the published files state the root outcome an authorization run of this package reports", () => {
  const sentences = new Map(ENTRIES.map(([name, verify]) => [name, sentenceFrom(verify)]));
  assert.equal(sentences.size, ENTRIES.length);
  assert.equal(
    new Set(sentences.values()).size,
    1,
    "the entries report different root outcomes, so no one sentence is true of this package: " +
      JSON.stringify(Object.fromEntries(sentences)),
  );
  const sentence = [...sentences.values()][0]!;
  for (const name of CLAIMING) {
    assert.ok(
      flat(read(name)).includes(sentence),
      name + " does not state what an authorization run reports. A run of this package says: " + sentence,
    );
  }
});

/** The anchor GitHub gives a heading: lower case, punctuation other than hyphens dropped, spaces as hyphens. */
const anchor = (heading: string) => heading.toLowerCase().replace(/[^a-z0-9 -]/g, "").replace(/ /g, "-");

test("the README status box hangs the limits on sections README.md has", () => {
  const readme = read("README.md").replace(/\r\n/g, "\n");
  const box = /<!-- lq-include: status -->\n([\s\S]*?)<!-- lq-include-end: status -->/.exec(readme);
  assert.ok(box !== null, "README.md has no status box between its include markers");
  // The box is included on other pages, so it links this README by its absolute address
  // (readme-include-markers.test.ts refuses a bare anchor in any included block).
  const cited = [...box[1]!.matchAll(/\]\(https:\/\/github\.com\/loquitur-dev\/loquitur-verify-ts\/blob\/main\/README\.md#([^)]+)\)/g)].map((match) => match[1]!);
  for (const limits of ["what-it-does-not-verify", "scope-and-limits"]) {
    assert.ok(cited.includes(limits), "the status box does not link to #" + limits + ", so nothing below holds the limits");
  }
  const anchors = readme.split("\n").filter((line) => line.startsWith("## ")).map((line) => anchor(line.slice(3).trim()));
  for (const target of cited) {
    assert.ok(anchors.includes(target), "README.md has no section with the anchor #" + target + ": " + JSON.stringify(anchors));
  }
});

test("no tracked file states a trust-root limit this package does not have", () => {
  assert.ok(
    ABSENT_LIMIT.every((phrase) => flat("and " + phrase.replace(" ", "\n") + " of any kind").includes(phrase)),
    "the sweep must see a phrase broken across lines",
  );
  const findings: string[] = [];
  for (const path of trackedFiles()) {
    let text: string;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(readFileSync(path));
    } catch {
      continue; // not UTF-8 text: an archive, an image, a binary fixture
    }
    const name = relative(PACKAGE_DIR, path).split(sep).join("/");
    const flattened = flat(text).toLowerCase();
    findings.push(...ABSENT_LIMIT.filter((phrase) => flattened.includes(phrase)).map((phrase) => name + ': "' + phrase + '"'));
  }
  assert.deepEqual(findings, [], "this package verifies trust roots; these say it does not: " + findings.join(", "));
});
