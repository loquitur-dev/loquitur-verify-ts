// The files this package publishes, listed once.
//
// Two guards sweep the whole package, the invisible-character rule and the published-claim
// rule, and a sweep is only as wide as its file list. Written twice, one copy drifts from the
// other and a guard stops covering what it names without failing. Not a test file: `npm test` runs
// test/*.test.ts, and this is imported by them.
import { execFileSync } from "node:child_process";
import { readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { PACKAGE_DIR } from "./bundle-kit.ts";

/**
 * Every file git tracks, as an absolute path; outside a checkout, every file of the tree, so a
 * copy taken without git history is swept too. `node_modules` and `.git` are not the package.
 */
export function trackedFiles(): string[] {
  try {
    const listed = execFileSync("git", ["-C", PACKAGE_DIR, "ls-files", "-z"], { encoding: "utf8" });
    return listed.split("\u0000").filter((name) => name !== "").map((name) => join(PACKAGE_DIR, name));
  } catch {
    const walk = (dir: string): string[] =>
      readdirSync(dir).flatMap((name) => {
        if (name === ".git" || name === "node_modules") return [];
        const path = join(dir, name);
        return statSync(path).isDirectory() ? walk(path) : [path];
      });
    return walk(PACKAGE_DIR);
  }
}
