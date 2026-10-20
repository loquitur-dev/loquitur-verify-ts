// Run by stack-fault-is-not-a-verdict.test.ts in a child process. Builds the run it is given and
// climbs it from the end of the stack, one climb after another in the same process: each climb
// finds the deepest depth at which an attempt still starts, and tries the run at every depth from
// there up, one frame at a time. Each depth is written to stdout as a line of JSON as soon as it is
// tried, with a synchronous write, so the lines already written are there to be read even when the
// engine ends the process in the middle of a try.
//
// The argument is a Climbs as JSON. For each climb in turn, the lines are:
//   {"climb", "expected", "boundary"}: the climb's index, the run's outcome with the whole stack,
//     and the deepest depth at which an attempt starts;
//   {"climb", "offset", "outcome"}: one for each depth, its offset above that deepest depth and
//     what the try gave;
//   {"climb", "done": true}, once the climb has ended.
// A try's outcome is "expected" when it is the outcome with the whole stack, "stack fault" when the
// stack ran out inside the run, "not started" when it ran out before the run started, and otherwise
// the outcome itself.
//
// Not a test file: `npm test` runs test/*.test.ts, and this is started by one of them.
import { writeSync } from "node:fs";
import { readDocumentPath, verifyBundle } from "../src/verify.ts";
import { Bundle, ephemeralAuthorizationWith, ephemeralRoot, authorizationOutcome, rootDocument, verifyInMemory } from "./bundle-kit.ts";

/**
 * The run a climb tries: a valid authorization run with trust roots, built here with keys made for
 * it; the documents at the given paths read with readDocumentPath; or verifyBundle on the given
 * input.
 */
export type Run =
  | { kind: "authorization" }
  | { kind: "documents"; documents: Record<string, string> }
  | { kind: "inspection"; input: string };

/**
 * The climbs of one run, or the rest of them: the run, how many climbs there are, and where this
 * process takes them up. That is the climb to start with, the offset above its boundary to start
 * from, how many tries that climb has made so far, and after how many of them the run first
 * completed in it (null if it has not). The climbs after it start from their boundary.
 */
export interface Climbs {
  run: Run;
  climbs: number;
  climb: number;
  from: number;
  tried: number;
  completed: number | null;
}

/** The attempt for `run`, giving its outcome as text. */
function attemptFor(run: Run): () => string {
  switch (run.kind) {
    case "authorization": {
      const bundle = Bundle.linkValid().seal();
      const { root, sign } = ephemeralRoot("root-1");
      const material = ephemeralAuthorizationWith(bundle, { trust: (t) => { delete t.signature; } });
      sign(material.trustRegistry);
      const options = { ...material, trustRoots: rootDocument([root]), evaluationTime: "2026-05-10T00:00:00Z" };
      return () => JSON.stringify(authorizationOutcome(verifyInMemory(bundle, options)));
    }
    case "documents": {
      // The two markers readDocumentPath returns are symbols, which JSON.stringify would drop.
      const shown = (value: unknown) => (typeof value === "symbol" ? String(value) : value);
      const entries = Object.entries(run.documents);
      return () => JSON.stringify(Object.fromEntries(entries.map(([key, path]) => [key, shown(readDocumentPath(path))])));
    }
    case "inspection":
      return () => {
        const report = verifyBundle(run.input);
        return JSON.stringify({ status: report.status, verdict: report.verdict, exit_code: report.exit_code, errors: report.errors.map((e) => e.code) });
      };
  }
}

/** Whether `err` is the engine's report of a stack that ran out. */
function stackFault(err: unknown): boolean {
  return err instanceof RangeError || (err instanceof SyntaxError && /Stack overflow$/.test(err.message));
}

const line = (value: unknown) => writeSync(1, `${JSON.stringify(value)}\n`);

/**
 * Climb `attempt` from the end of the stack, writing each depth as it is tried. The deepest depth
 * at which an attempt still starts is found first, with an attempt that does nothing, so the run
 * itself is first tried at the end of the stack rather than after a search has warmed it up. The
 * climb starts `from` depths above it and goes on until the run has completed, and then for as many
 * tries again as it took; `tried` and `completed` carry a climb that an earlier process began.
 */
function climbOnce(
  climb: number, attempt: () => string, expected: string, from: number, tried: number, completed: number | null,
): void {
  let started = false;
  const descend = (depth: number, bottom: () => string): string => {
    if (depth > 0) return descend(depth - 1, bottom);
    started = true;
    return bottom();
  };
  /** The outcome at `depth`, "stack fault", or undefined when the stack ran out before `bottom` started. */
  const at = (depth: number, bottom: () => string): string | undefined => {
    started = false;
    try {
      return descend(depth, bottom);
    } catch (err) {
      if (!stackFault(err)) throw err;
      return started ? "stack fault" : undefined;
    }
  };
  const nothing = () => "";
  // The deepest depth at which an attempt starts: double until it does not, then bisect.
  let starts = 0;
  let short = 1;
  while (at(short, nothing) !== undefined) {
    starts = short;
    short *= 2;
  }
  while (short - starts > 1) {
    const middle = Math.floor((starts + short) / 2);
    if (at(middle, nothing) === undefined) short = middle;
    else starts = middle;
  }
  // A frame's size can change as the engine tiers the recursion up, so the boundary is checked
  // again just before the climb starts from it.
  while (at(starts + 1, nothing) !== undefined) starts += 1;
  line({ climb, expected, boundary: starts });
  for (let depth = starts - from; depth >= 0 && (completed === null || tried < 2 * completed); depth -= 1) {
    const outcome = at(depth, attempt);
    const offset = starts - depth;
    if (outcome === undefined) {
      line({ climb, offset, outcome: "not started" });
      continue;
    }
    tried += 1;
    line({ climb, offset, outcome: outcome === expected ? "expected" : outcome });
    if (outcome !== "stack fault" && completed === null) completed = tried;
  }
  line({ climb, done: true });
}

const climbs = JSON.parse(process.argv[2]!) as Climbs;
const attempt = attemptFor(climbs.run);
const expected = attempt();
climbOnce(climbs.climb, attempt, expected, climbs.from, climbs.tried, climbs.completed);
for (let climb = climbs.climb + 1; climb < climbs.climbs; climb += 1) climbOnce(climb, attempt, expected, 0, 0, null);
