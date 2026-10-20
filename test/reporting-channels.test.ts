// CODE_OF_CONDUCT.md section 5 and SECURITY.md "Reporting a vulnerability" send a reporter to the
// same two channels in the same order: GitHub's private vulnerability reporting first, and the
// mailbox only when that is unavailable. A reporter who reads one file and then the other must not
// be told to start in a different place.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { PACKAGE_DIR } from "./bundle-kit.ts";

const PRIVATE_REPORTING = "**Use GitHub's private vulnerability reporting on this repository**";
const MAILBOX = "**security@loquitur.dev**";

/** The text of `file` from the heading `heading` to the next heading of its level, or null. */
function section(file: string, heading: string): string | null {
  const text = readFileSync(join(PACKAGE_DIR, file), "utf8").replace(/\r\n/g, "\n");
  const start = text.split("\n").findIndex((line) => line === heading);
  if (start === -1) return null;
  const rest = text.split("\n").slice(start + 1);
  const end = rest.findIndex((line) => line.startsWith("## "));
  return (end === -1 ? rest : rest.slice(0, end)).join("\n");
}

test("the code of conduct and the security policy name the two reporting channels in the same order", () => {
  for (const [file, heading] of [
    ["CODE_OF_CONDUCT.md", "## 5. Reporting conduct issues"],
    ["SECURITY.md", "## Reporting a vulnerability"],
  ] as const) {
    const body = section(file, heading);
    assert.ok(body !== null, `${file} has no section ${JSON.stringify(heading)}`);
    const first = body.indexOf(PRIVATE_REPORTING);
    const second = body.indexOf(MAILBOX);
    assert.ok(first !== -1, `${file}, ${heading}: does not send the reporter to GitHub's private reporting`);
    assert.ok(second !== -1, `${file}, ${heading}: does not give the mailbox`);
    assert.ok(first < second, `${file}, ${heading}: gives the mailbox before GitHub's private reporting`);
  }
});
