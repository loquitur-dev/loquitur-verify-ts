// A member's path is the root as it was given, the separator and the member's name: nothing is
// normalized (report-contract.md section 5.3). On a POSIX host a root `lnk/..` names the directory
// above the link's target, which the host resolves; folded lexically, as path.join folds it, it
// would name the directory holding the link, another directory, and the members read would be
// another bundle's. The rule is held for both separators on every host.
import { test } from "node:test";
import assert from "node:assert/strict";
import { memberPath } from "../src/verify.ts";

test("a member's path keeps the root as given, '..' and '.' included, for either separator", () => {
  const rows: [string, string, "/" | "\\", string][] = [
    ["/t/a/lnk/..", "manifest.json", "/", "/t/a/lnk/../manifest.json"],
    ["/t/a/lnk/../b", "files/x.json", "/", "/t/a/lnk/../b/files/x.json"],
    ["lnk/..", "p1.json", "/", "lnk/../p1.json"],
    ["./a/./b", "manifest.json", "/", "./a/./b/manifest.json"],
    ["/t/a/lnk/../", "manifest.json", "/", "/t/a/lnk/../manifest.json"],
    ["/t/a//b", "manifest.json", "/", "/t/a//b/manifest.json"],
    ["C:\\t\\lnk\\..", "files/x.json", "\\", "C:\\t\\lnk\\..\\files\\x.json"],
    ["C:\\t\\b\\", "manifest.json", "\\", "C:\\t\\b\\manifest.json"],
    ["C:\\t\\b/", "manifest.json", "\\", "C:\\t\\b/manifest.json"],
  ];
  for (const [root, rel, sep, expected] of rows) {
    assert.equal(memberPath(root, rel, sep), expected, `${root} + ${rel}`);
  }
});

test("the root itself is the member path of the empty name", () => {
  assert.equal(memberPath("/t/a/lnk/..", "", "/"), "/t/a/lnk/..");
  assert.equal(memberPath("C:\\t\\lnk\\..", "", "\\"), "C:\\t\\lnk\\..");
});

test("without a separator given, the host's is used", () => {
  const sep = process.platform === "win32" ? "\\" : "/";
  assert.equal(memberPath(`r${sep}lnk${sep}..`, "sub/m.json"), `r${sep}lnk${sep}..${sep}sub${sep}m.json`);
});
