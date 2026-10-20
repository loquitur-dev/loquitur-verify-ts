// Input strictness over a JSON value already in memory (canonicalization-and-hashing.md, "Input
// strictness", rules 2 to 4 and the nesting bound), shared by every host document a verifier is
// handed: the registry entry, the trust registry and the trust-root document.

/** A document nested deeper than this is invalid. A scalar has depth 0, `[]` depth 1. */
export const MAX_JSON_DEPTH = 64;
const JS_SAFE_INT_MAX = 9007199254740991;

/**
 * True when `s` holds a noncharacter: U+FDD0 to U+FDEF, or a code point ending in FFFE or FFFF.
 * A document whose string or member name holds one is not strict JSON (input strictness rule 9,
 * RFC 7493 section 2.1). A host path holding one finds nothing and is not handed to the host
 * (report-contract.md section 5.3): Node.js on Windows stops the process when a path holding
 * U+10FFFF reaches the file system. No member name holds one, since a member name holds only the
 * portable characters.
 */
export function hasNoncharacter(s: string): boolean {
  for (const ch of s) {
    const c = ch.codePointAt(0)!;
    if ((c >= 0xfdd0 && c <= 0xfdef) || (c & 0xfffe) === 0xfffe) return true;
  }
  return false;
}

export function hasLoneSurrogate(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = i + 1 < s.length ? s.charCodeAt(i + 1) : 0;
      if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      return true;
    }
  }
  return false;
}

/**
 * Whether the bracket nesting of a JSON text exceeds MAX_JSON_DEPTH, by a single forward scan.
 * Runs before the parser, whose duplicate-member walk is recursive, so no stack size decides
 * whether a document is accepted: 64 levels pass and 65 fail on every host.
 */
export function jsonTextTooDeep(text: string): boolean {
  let depth = 0;
  let inString = false;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (inString) {
      if (c === 0x5c) i++;
      else if (c === 0x22) inString = false;
    } else if (c === 0x22) {
      inString = true;
    } else if (c === 0x5b || c === 0x7b) {
      if (++depth > MAX_JSON_DEPTH) return true;
    } else if (c === 0x5d || c === 0x7d) {
      depth--;
    }
  }
  return false;
}

/**
 * Rethrow a stack the host ran out of. Every document and value is held to rule 6's 64 levels by
 * an iterative walk before the verifier recurses on it, so the stack only runs out on a value the
 * protocol admits, in a host that left too little of it: a fault of the host, never a verdict on
 * the evidence (report-contract.md section 4). A catch that turns what it catches into a failed
 * check calls this first, so the fault propagates. See isHostStackFault for what counts as one.
 */
export function rethrowHostStackFault(err: unknown): void {
  if (isHostStackFault(err)) throw err;
}

/**
 * Whether `err` is a stack the host ran out of. V8 raises it as a RangeError, or, while it
 * compiles or runs a regular expression, as a SyntaxError "Invalid regular expression: ...: Stack
 * overflow"; every pattern here is a constant this package wrote, so no content raises either.
 * Node gives every RangeError of its own a code (ERR_FS_FILE_TOO_LARGE for a file too large to
 * read, say), and those are the host refusing an operation, which a reader classifies as a failed
 * read (report-contract.md section 5.3); the engine's RangeError has no code. A catch around host
 * I/O asks this too before it classifies, so a stack that runs out inside a file-system call is not
 * read as a read failure.
 */
export function isHostStackFault(err: unknown): boolean {
  if (err instanceof RangeError) return typeof (err as { code?: unknown }).code !== "string";
  return err instanceof SyntaxError && err.message.startsWith("Invalid regular expression");
}

/**
 * Input strictness over a whole JSON value, projected or not, member names included. Iterative,
 * so a host object of any depth gets an answer rather than a RangeError. Returns true when the
 * value is not an acceptable JSON document: a non-finite number, an integer-valued number beyond
 * 2^53-1 however it was spelled (9007199254740993, 1e16, 9007199254740992.0), a lone surrogate
 * or a noncharacter (rule 9) in a string or a member name, nesting deeper than MAX_JSON_DEPTH, or
 * a value JSON cannot hold.
 */
export function jsonValueViolatesStrictness(root: unknown): boolean {
  return jsonStrictnessViolation(root) !== null;
}

/**
 * The rule of input strictness a JSON value breaks, by the name the Python verifier's
 * strict loader gives it (`json_lone_surrogate`, `json_noncharacter`,
 * `json_integer_outside_safe_range`, `non_finite_json_number`), or `json_nesting_too_deep` and
 * `not_a_json_value` for the two a value in memory can break too; null when it breaks none. The
 * walk of jsonValueViolatesStrictness, which asks this.
 */
export function jsonStrictnessViolation(root: unknown): string | null {
  const stack: Array<[unknown, number]> = [[root, 0]];
  while (stack.length > 0) {
    const [value, depth] = stack.pop()!;
    if (value === null || typeof value === "boolean") continue;
    if (typeof value === "string") {
      if (hasLoneSurrogate(value)) return "json_lone_surrogate";
      if (hasNoncharacter(value)) return "json_noncharacter";
      continue;
    }
    if (typeof value === "number") {
      if (!Number.isFinite(value)) return "non_finite_json_number";
      if (Number.isInteger(value) && Math.abs(value) > JS_SAFE_INT_MAX) return "json_integer_outside_safe_range";
      continue;
    }
    if (typeof value !== "object") return "not_a_json_value";
    if (depth + 1 > MAX_JSON_DEPTH) return "json_nesting_too_deep";
    if (Array.isArray(value)) {
      for (let i = 0; i < value.length; i++) stack.push([value[i], depth + 1]);
      continue;
    }
    for (const key of Object.keys(value)) {
      if (hasLoneSurrogate(key)) return "json_lone_surrogate";
      if (hasNoncharacter(key)) return "json_noncharacter";
      stack.push([(value as Record<string, unknown>)[key], depth + 1]);
    }
  }
  return null;
}

/**
 * Whether a value in memory nests arrays and objects deeper than `limit`, by an iterative walk.
 * The depth is input strictness rule 6's: a scalar has depth 0, `[]` depth 1. The walk stops at
 * `limit + 1`, so a value that contains itself gets an answer too.
 */
export function jsonValueNestingExceeds(root: unknown, limit: number): boolean {
  const stack: Array<[unknown, number]> = [[root, 0]];
  while (stack.length > 0) {
    const [value, depth] = stack.pop()!;
    if (value === null || typeof value !== "object") continue;
    if (depth + 1 > limit) return true;
    const children = Array.isArray(value) ? value : Object.values(value as Record<string, unknown>);
    for (const child of children) stack.push([child, depth + 1]);
  }
  return false;
}

/** A JSON object that is not an array and not null. */
export function isPlainObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}
