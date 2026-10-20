// RFC 8785 (JCS) canonicalization and SHA-256 (canonicalization-and-hashing.md). The bytes
// must equal those every other implementation of the specification computes, `loquitur-verify`
// and `loquitur-schemas` included: a commitment hash over different bytes verifies nothing.
import * as canonicalizeNs from "canonicalize";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex } from "@noble/hashes/utils";
import { MAX_JSON_DEPTH, hasNoncharacter, jsonStrictnessViolation, jsonTextTooDeep, jsonValueNestingExceeds, rethrowHostStackFault } from "./json-strictness.js";
import { defineJsonMember } from "./json-member.js";

// canonicalize ships as CJS (module.exports = fn); normalize the interop shape.
const canonicalize = ((canonicalizeNs as any).default ?? canonicalizeNs) as (
  input: unknown,
) => string | undefined;

export class CanonicalizationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CanonicalizationError";
  }
}

/**
 * Refuse a lone surrogate in a key or a value, as the Python canonicalizer does.
 *
 * A JavaScript string is a sequence of UTF-16 code units and may contain lone surrogates (an
 * unpaired \uD800 to \uDBFF or \uDC00 to \uDFFF). They encode no Unicode scalar value, and they
 * cannot be encoded to UTF-8 without substitution. The Python canonicalizer refuses them, while
 * the `canonicalize` package serializes them as "\ud800" escapes: without this check the same
 * object would canonicalize here and fail in Python. Canonical bytes are signed and hashed, so the
 * two implementations would compute different bytes for one value.
 */
function assertNoLoneSurrogates(s: string, path: string): void {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      // high surrogate: must be followed by a low surrogate
      const next = i + 1 < s.length ? s.charCodeAt(i + 1) : NaN;
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new CanonicalizationError(`${path}: lone high surrogate is not valid Unicode`);
      }
      i++; // consume the pair
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      // low surrogate not preceded by a high surrogate
      throw new CanonicalizationError(`${path}: lone low surrogate is not valid Unicode`);
    }
  }
}

// The acceptance rules of the Python `_prepare_for_jcs`, so a value canonicalizes in both
// implementations or in neither. Non-finite numbers and integers outside the JavaScript safe
// range are refused.
function prepareForJcs(value: unknown, path = "$"): unknown {
  if (value === null) return null;
  const t = typeof value;
  if (t === "boolean") return value;
  if (t === "string") {
    assertNoLoneSurrogates(value as string, path);
    // Input strictness rule 9 (RFC 7493 section 2.1): no string holds a noncharacter. Refused
    // here as the Python verifier's canonicalizer refuses it, so the two exported canonicalizers
    // answer every value alike.
    if (hasNoncharacter(value as string)) {
      throw new CanonicalizationError(`${path}: noncharacter is not admitted (input strictness rule 9)`);
    }
    return value;
  }
  if (t === "number") {
    const n = value as number;
    if (!Number.isFinite(n)) throw new CanonicalizationError(`${path}: non-finite number not allowed`);
    if (Number.isInteger(n) && !Number.isSafeInteger(n)) {
      throw new CanonicalizationError(`${path}: integer outside RFC8785/ECMAScript safe range`);
    }
    return n;
  }
  if (Array.isArray(value)) return value.map((v, i) => prepareForJcs(v, `${path}[${i}]`));
  if (t === "object") {
    // A JSON object, from this realm or another: its prototype is null or a prototype whose own
    // prototype is null. A Date, Map, Set, typed array or boxed primitive is not a JSON value and
    // is refused, as the Python verifier refuses what is not a dict, list, str, int, float, bool
    // or None; serializing it as an object of its enumerable members would sign something else.
    const proto: unknown = Object.getPrototypeOf(value);
    if (proto !== null && Object.getPrototypeOf(proto) !== null) {
      throw new CanonicalizationError(`${path}: not a JSON object`);
    }
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      // Keys are canonicalized (and sorted) too, so an invalid key is refused as well.
      assertNoLoneSurrogates(k, `${path}.<key>`);
      if (hasNoncharacter(k)) {
        throw new CanonicalizationError(`${path}: member name with a noncharacter is not admitted`);
      }
      defineJsonMember(out, k, prepareForJcs(v, `${path}.${k}`));
    }
    return out;
  }
  throw new CanonicalizationError(`${path}: unsupported JSON value type: ${t}`);
}

/**
 * Return RFC 8785 (JCS) canonical UTF-8 JSON bytes for a JSON-compatible value.
 *
 * A value nested deeper than MAX_JSON_DEPTH is refused before any recursive step, as input
 * strictness rule 6 refuses the document: the bound is the protocol's, never the stack's.
 * prepareForJcs recurses per level, so a bound left to the stack would let a host and a
 * Python version decide whether a deep value canonicalizes; both verifiers refuse it with
 * this bound.
 */
export function canonicalJsonBytes(value: unknown): Uint8Array {
  if (jsonValueNestingExceeds(value, MAX_JSON_DEPTH)) {
    throw new CanonicalizationError(`$: nesting deeper than ${MAX_JSON_DEPTH} levels`);
  }
  const canonical = canonicalize(prepareForJcs(value));
  if (canonical === undefined) {
    throw new CanonicalizationError("value is not canonical JSON serializable");
  }
  return new TextEncoder().encode(canonical);
}

/** Return a `sha256:<hex>` digest URI for bytes. */
export function sha256Uri(payload: Uint8Array): string {
  return "sha256:" + bytesToHex(sha256(payload));
}

/** Return the `sha256:` digest of the RFC 8785 canonical bytes of `value`. */
export function canonicalHash(value: unknown): string {
  return sha256Uri(canonicalJsonBytes(value));
}

export class JsonParseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "JsonParseError";
  }
}

/**
 * The decimal value a JSON number token spells, as a sign, a digit string with no leading or
 * trailing zero, and a power of ten; zero is `{ zero: true }` whatever its sign. Read from the
 * token's characters alone, so no binary rounding enters the comparison of the excess-precision
 * rule.
 */
type DecimalValue = { zero: true } | { zero: false; negative: boolean; digits: string; exponent: number };

function decimalValue(spelling: string): DecimalValue {
  let rest = spelling;
  const negative = rest.startsWith("-");
  if (negative) rest = rest.slice(1);
  let exponent = 0;
  const e = rest.search(/[eE]/);
  if (e >= 0) {
    exponent = Number(rest.slice(e + 1));
    rest = rest.slice(0, e);
  }
  const dot = rest.indexOf(".");
  let digits = rest;
  if (dot >= 0) {
    digits = rest.slice(0, dot) + rest.slice(dot + 1);
    exponent -= rest.length - dot - 1;
  }
  let start = 0;
  while (start < digits.length && digits.charCodeAt(start) === 0x30) start++;
  let end = digits.length;
  while (end > start && digits.charCodeAt(end - 1) === 0x30) end--;
  if (start === end) return { zero: true };
  exponent += digits.length - end;
  return { zero: false, negative, digits: digits.slice(start, end), exponent };
}

/**
 * Whether a number token names exactly the binary64 value it is read as (canonicalization-and-
 * hashing.md, "No excess precision"): the decimal value it spells equals the decimal value of the
 * RFC 8785 serialization of its nearest binary64 value, which is ECMAScript's Number-to-String.
 * A token whose value is not finite is left to rule 3.
 */
function numberSpellingExact(spelling: string, value: number): boolean {
  if (!Number.isFinite(value)) return true;
  const spelled = decimalValue(spelling);
  const serialized = decimalValue(String(value));
  if (spelled.zero || serialized.zero) return spelled.zero === serialized.zero;
  return spelled.negative === serialized.negative && spelled.digits === serialized.digits && spelled.exponent === serialized.exponent;
}

const NUMBER_TOKEN = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;
const HEX4 = /^[0-9a-fA-F]{4}$/;
const SIMPLE_ESCAPES: Record<string, string> = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };

/**
 * Decode a strict JSON text into a value with this package's own tokenizer, never with the host's
 * JSON.parse: a value the verifier hashes must be a function of the text alone, and V8's
 * JSON.parse has decoded a member name differently after an earlier document in the same process.
 * The grammar is RFC 8259's; on top of it, duplicate member names (rule 1) and numbers that carry
 * more precision than binary64 holds are refused. Objects are built by definition, so a member
 * named __proto__ is a member. Time is linear in the text's length, and recursion is bounded by
 * the depth scan that runs first.
 */
function decodeJson(text: string): unknown {
  let i = 0;
  const n = text.length;
  const fail = (msg: string): never => {
    throw new JsonParseError(`${msg} at offset ${i}`);
  };
  const ws = (): void => {
    while (i < n) {
      const c = text.charCodeAt(i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) i++;
      else break;
    }
  };
  const stringToken = (): string => {
    i++; // opening quote
    let out = "";
    let run = i;
    while (i < n) {
      const c = text.charCodeAt(i);
      if (c === 0x22) {
        out += text.slice(run, i);
        i++;
        return out;
      }
      if (c < 0x20) fail("unescaped control character in string");
      if (c === 0x5c) {
        out += text.slice(run, i);
        const esc = text[i + 1];
        if (esc === undefined) fail("unterminated string");
        if (esc === "u") {
          const hex = text.slice(i + 2, i + 6);
          if (!HEX4.test(hex)) fail("invalid \\u escape");
          out += String.fromCharCode(parseInt(hex, 16));
          i += 6;
        } else {
          const simple = SIMPLE_ESCAPES[esc!];
          if (simple === undefined) fail("invalid string escape");
          out += simple;
          i += 2;
        }
        run = i;
        continue;
      }
      i++;
    }
    return fail("unterminated string");
  };
  const numberToken = (): number => {
    NUMBER_TOKEN.lastIndex = i;
    const m = NUMBER_TOKEN.exec(text);
    if (m === null || m[0].length === 0) return fail("invalid number");
    const spelling = m[0];
    const value = Number(spelling);
    if (!numberSpellingExact(spelling, value)) fail("number carries more precision than binary64 holds");
    i += spelling.length;
    return value;
  };
  const value = (): unknown => {
    ws();
    const c = text[i];
    if (c === "{") return objectValue();
    if (c === "[") return arrayValue();
    if (c === '"') return stringToken();
    if (c === "-" || (c !== undefined && c >= "0" && c <= "9")) return numberToken();
    if (text.startsWith("true", i)) {
      i += 4;
      return true;
    }
    if (text.startsWith("false", i)) {
      i += 5;
      return false;
    }
    if (text.startsWith("null", i)) {
      i += 4;
      return null;
    }
    return fail("unexpected token");
  };
  const objectValue = (): Record<string, unknown> => {
    i++; // {
    const out: Record<string, unknown> = {};
    ws();
    if (text[i] === "}") {
      i++;
      return out;
    }
    for (;;) {
      ws();
      if (text[i] !== '"') fail("expected object key");
      const key = stringToken();
      if (Object.prototype.hasOwnProperty.call(out, key)) throw new JsonParseError(`duplicate object key: ${JSON.stringify(key)}`);
      ws();
      if (text[i] !== ":") fail("expected ':'");
      i++;
      defineJsonMember(out, key, value());
      ws();
      if (text[i] === ",") {
        i++;
        continue;
      }
      if (text[i] === "}") {
        i++;
        return out;
      }
      fail("expected ',' or '}'");
    }
  };
  const arrayValue = (): unknown[] => {
    i++; // [
    const out: unknown[] = [];
    ws();
    if (text[i] === "]") {
      i++;
      return out;
    }
    for (;;) {
      out.push(value());
      ws();
      if (text[i] === ",") {
        i++;
        continue;
      }
      if (text[i] === "]") {
        i++;
        return out;
      }
      fail("expected ',' or ']'");
    }
  };
  const result = value();
  ws();
  if (i !== n) fail("unexpected trailing characters");
  return result;
}

/**
 * Reject a JSON text that is not strict JSON, as parseJsonStrict does: outside the grammar, nested
 * deeper than MAX_JSON_DEPTH, carrying a duplicate member name (after escape decoding; I-JSON, RFC
 * 7493 section 2.3), a number with excess precision, a number that is not finite or an integer
 * beyond 2^53 - 1, or a lone surrogate or a noncharacter. Kept for callers that only need the
 * answer.
 */
export function assertNoDuplicateJsonKeys(text: string): void {
  parseJsonStrict(text);
}

/**
 * Strict JSON parse with this package's own decoder (decodeJson), refusing what the Python
 * verifier's strict loader refuses (canonicalization-and-hashing.md, "Input strictness",
 * rules 1 to 4, 6 and 9, and "No excess precision"): nesting deeper than MAX_JSON_DEPTH is refused
 * by a linear forward scan before anything recurses, then the grammar, duplicate member names and
 * excess precision, then, over the whole decoded value, member names included, a number that is not
 * finite (1e400), an integer beyond 2^53 - 1 however it is spelled (9007199254740992, 1e16, 1e21),
 * a lone surrogate and a noncharacter, each a JsonParseError that starts with the name the Python
 * loader gives the rule. No stack size and no earlier document decides the outcome.
 */
export function parseJsonStrict(text: string): unknown {
  if (jsonTextTooDeep(text)) throw new JsonParseError(`nesting deeper than ${MAX_JSON_DEPTH} levels`);
  const value = decodeJson(text);
  const violation = jsonStrictnessViolation(value);
  if (violation !== null) throw new JsonParseError(`${violation}: the text is not strict JSON`);
  return value;
}

// ignoreBOM keeps a leading U+FEFF, so the strict parser sees it and refuses the document, as the
// Python verifier's strict loader does; fatal refuses bytes that are not UTF-8.
const strictUtf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

/**
 * A JSON document read from its exact bytes, as the verifier reads a bundle member or a document a
 * host names by path (canonicalization-and-hashing.md, "Input strictness", rule 7 and the rules of
 * parseJsonStrict): the bytes are decoded as UTF-8 with fatal errors and the BOM kept, so invalid
 * UTF-8 and a leading BOM are refused rather than repaired, then parsed by parseJsonStrict. A
 * refusal is a JsonParseError; a stack the host ran out of propagates.
 */
export function parseJsonBytesStrict(bytes: Uint8Array): unknown {
  let text: string;
  try {
    text = strictUtf8.decode(bytes);
  } catch (err) {
    rethrowHostStackFault(err);
    throw new JsonParseError("invalid_utf8: the bytes are not UTF-8");
  }
  return parseJsonStrict(text);
}
