// Sibling repositories a test reads from, and what their absence means.
//
// A single-repository clone does not have the siblings, and a test that needs one skips
// there: the absence is not a defect of this repository. A workspace that assembles every
// repository sets LOQUITUR_REQUIRE_SIBLINGS, and there the same absence is a defect (a
// checkout step that failed, a directory under the wrong name), and a skip would report a
// gate that did not run as a gate that passed. The Python repositories honor the variable
// the same way.
//
// Not a test file: `npm test` runs test/*.test.ts, and this is imported by them.
import { existsSync } from "node:fs";
import { join } from "node:path";

export const REQUIRE_SIBLINGS_ENV = "LOQUITUR_REQUIRE_SIBLINGS";

export function siblingsRequired(): boolean {
  return ["1", "true", "yes", "on"].includes((process.env[REQUIRE_SIBLINGS_ENV] ?? "").trim().toLowerCase());
}

export interface Sibling {
  /** The directory the fixtures were found in, or the first candidate when none holds them. */
  readonly dir: string;
  readonly present: boolean;
  /** node:test options: skip when absent, unless the workspace requires the sibling. */
  readonly options: { skip: string | false };
  /** A path under `dir`; throws, naming the sibling, when it is absent. */
  path(name: string): string;
}

/**
 * @param repository the sibling's repository name, as a reader would look for it
 * @param candidates directories that may hold its fixtures, in order of preference
 * @param marker a file whose presence in a candidate means the fixtures are there
 * @param skipReason what a skipped test says when the sibling is absent and not required
 */
export function sibling(repository: string, candidates: string[], marker: string, skipReason: string): Sibling {
  const found = candidates.find((candidate) => existsSync(join(candidate, marker)));
  const present = found !== undefined;
  const dir = found ?? candidates[0]!;
  const message =
    `${REQUIRE_SIBLINGS_ENV} is set, but the sibling repository ${repository} is not checked out: ` +
    `no ${marker} in ${candidates.join(" or ")}`;
  return {
    dir,
    present,
    options: { skip: present || siblingsRequired() ? false : skipReason },
    path(name: string): string {
      if (!present) throw new Error(message);
      return join(dir, name);
    },
  };
}
