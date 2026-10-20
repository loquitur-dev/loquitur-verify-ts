// Tables of the protocol's normative documents, read by the tests that hold this verifier to them.
//
// loquitur-protocol states several rules as Markdown tables: the link comparisons
// (registry-link.md) and the authorization order (trust-registry-authorization.md) among them. A
// test that restated a table here would check the verifier against a copy; these helpers read the
// table from the sibling checkout, so a row changed in the specification fails the test until the
// verifier follows it, and a behavior changed in the verifier fails it until the specification
// does. The sibling is absent in a single-repository clone: the tests skip there, and fail when
// LOQUITUR_REQUIRE_SIBLINGS is set.
//
// Not a test file: `npm test` runs test/*.test.ts, and this is imported by them.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { PACKAGE_DIR } from "./bundle-kit.ts";
import { sibling, type Sibling } from "./siblings.ts";

export function specification(document: string): Sibling {
  return sibling(
    "loquitur-protocol",
    [join(PACKAGE_DIR, "../loquitur-protocol/docs/specification"), join(PACKAGE_DIR, "../public/loquitur-protocol/docs/specification")],
    document,
    `sibling loquitur-protocol specification ${document} absent`,
  );
}

// A reference to another specification document is a link to its file, [`x.md`](x.md). The link is
// markup: the tests read the text a reader sees, the document name in a code span.
const DOCUMENT_LINK = /\[`([^`\]]+\.md)`\]\(\1\)/g;

export function readSpecification(spec: Sibling, document: string): string {
  return readFileSync(spec.path(document), "utf8").replace(DOCUMENT_LINK, "`$1`");
}

function cells(line: string): string[] {
  const parts = line.trim().split(/(?<!\\)\|/);
  return parts.slice(1, -1).map((part) => part.trim().replace(/\\\|/g, "|"));
}

/**
 * The body of each `## ` section of a document, by its title. A document that states one kind of
 * rule per section carries several tables with the same header (document-contracts.md gives
 * every document the same member columns), and `table` refuses that on purpose.
 */
export function sections(text: string): Map<string, string> {
  const found = new Map<string, string>();
  let title: string | null = null;
  let body: string[] = [];
  for (const line of text.split(/\r?\n/)) {
    if (line.startsWith("## ")) {
      if (title !== null) found.set(title, body.join("\n"));
      title = line.slice(3).trim();
      body = [];
    } else {
      body.push(line);
    }
  }
  if (title !== null) found.set(title, body.join("\n"));
  return found;
}

/** Every table of `text` headed exactly `header`, as row mappings; a section may carry several. */
export function tablesWithHeader(text: string, header: string[]): Array<Record<string, string>> {
  const lines = text.split(/\r?\n/);
  const out: Array<Record<string, string>> = [];
  for (let i = 0; i + 1 < lines.length; i++) {
    if (!lines[i]!.trimStart().startsWith("|") || !/^\s*\|(\s*:?-{3,}:?\s*\|)+\s*$/.test(lines[i + 1]!)) continue;
    const head = cells(lines[i]!);
    let j = i + 2;
    const rows: Array<Record<string, string>> = [];
    for (; j < lines.length && lines[j]!.trimStart().startsWith("|"); j++) {
      const row = cells(lines[j]!);
      if (row.length !== head.length) throw new Error(`row ${lines[j]} does not have ${head.length} cells`);
      rows.push(Object.fromEntries(head.map((name, k) => [name, row[k]!])));
    }
    if (JSON.stringify(head) === JSON.stringify(header)) out.push(...rows);
    i = j - 1;
  }
  return out;
}

/** The one table of `text` whose header cells are exactly `header`, as row mappings. */
export function table(text: string, header: string[]): Array<Record<string, string>> {
  const lines = text.split(/\r?\n/);
  const found: Array<Array<Record<string, string>>> = [];
  for (let i = 0; i + 1 < lines.length; i++) {
    if (!lines[i]!.trimStart().startsWith("|") || !/^\s*\|(\s*:?-{3,}:?\s*\|)+\s*$/.test(lines[i + 1]!)) continue;
    const head = cells(lines[i]!);
    const rows: Array<Record<string, string>> = [];
    let j = i + 2;
    for (; j < lines.length && lines[j]!.trimStart().startsWith("|"); j++) {
      const row = cells(lines[j]!);
      if (row.length !== head.length) throw new Error(`row ${lines[j]} does not have ${head.length} cells`);
      rows.push(Object.fromEntries(head.map((name, k) => [name, row[k]!])));
    }
    if (JSON.stringify(head) === JSON.stringify(header)) found.push(rows);
    i = j - 1;
  }
  if (found.length !== 1) throw new Error(`expected exactly one table headed ${header.join(" | ")}, found ${found.length}`);
  if (found[0]!.length === 0) throw new Error(`the table headed ${header.join(" | ")} has no rows`);
  return found[0]!;
}

/** The content of a cell that is one code span. */
export function code(cell: string): string {
  const match = /^`([^`]*)`$/.exec(cell);
  if (!match) throw new Error(`expected one code span, got ${cell}`);
  return match[1]!;
}

/** Every code span of a cell, in order. */
export function codes(cell: string): string[] {
  return [...cell.matchAll(/`([^`]*)`/g)].map((m) => m[1]!);
}
