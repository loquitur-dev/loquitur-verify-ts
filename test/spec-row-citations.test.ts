// Row citations of loquitur-protocol trust-root.md section 5, held to that table.
//
// Comments here cite rows of the section 5 evaluation order by number. A number alone goes stale
// when the table is renumbered and sends a reader to a row that says something else, so every
// citation of a row in the sentence that cites trust-root.md section 5 names the row's status
// beside its number, "row N (STATUS)", and this test reads the table from the sibling checkout and
// requires each pair to be a row of it. A renumbered table fails the test until the citations
// follow. A row cited in another sentence of the same file belongs to another table, such as the
// evaluation order of trust-registry-authorization.md, and is not read as one of these.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { PACKAGE_DIR } from "./bundle-kit.ts";
import { code, readSpecification, specification, table } from "./spec-tables.ts";

const DOCUMENT = "trust-root.md";
const SPEC = specification(DOCUMENT);
const CITING = "trust-root.md section 5";

function sources(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return entry.name === "generated" ? [] : sources(path);
    return /\.(ts|mjs)$/.test(entry.name) ? [path] : [];
  });
}

test("every row of trust-root.md section 5 cited here is cited with its status", SPEC.options, () => {
  const rows = table(readSpecification(SPEC, DOCUMENT), ["#", "condition", "status", "effect"]);
  const status = new Map(rows.filter((row) => row["#"] !== "—").map((row) => [row["#"]!, code(row["status"]!)]));
  const cited: string[] = [];
  const problems: string[] = [];
  for (const file of [...sources(join(PACKAGE_DIR, "src")), ...sources(join(PACKAGE_DIR, "test"))]) {
    const text = readFileSync(file, "utf8").replace(/\n\s*\/\/\s*/g, " ");
    if (!text.includes(CITING) || file.endsWith("spec-row-citations.test.ts")) continue;
    const sentences = [...text.matchAll(/trust-root\.md section 5[^]*?(?:\.\s|$)/g)].map((m) => m[0]);
    for (const match of sentences.join(" ").matchAll(/\brow (\d+)( \(([A-Z_]+)\))?/g)) {
      const [, number, , named] = match;
      if (named === undefined) problems.push(`${file}: row ${number} is cited without its status`);
      else if (status.get(number!) !== named) problems.push(`${file}: row ${number} is ${status.get(number!)}, not ${named}`);
      else cited.push(`${number} ${named}`);
    }
  }
  assert.deepEqual(problems, []);
  // Non-vacuity: the citations this test was written for are among those it checked.
  assert.ok(cited.includes("5 MALFORMED_SIGNATURE") && cited.includes("12 ROOT_SIGNATURE_INVALID"), cited.join(", "));
});
