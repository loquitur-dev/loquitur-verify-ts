// A registry entry's verdict is the verdict its reason codes derive (verdict-grounds.md VG-1 to
// VG-4 applied to the entry), as in the Python verifier.
//
//   VG-1: the entry cites at least one code and no code twice;
//   VG-2: every cited code is in the catalog;
//   VG-3: the verdict equals the verdict the highest cited severity maps to
//         (info PASS, warn WARN, review REVIEW, fail FAIL);
//   VG-4: a PASS cites at least one info-severity code.
//
// VG-1 and VG-2 are preconditions and stop the check (verdict-grounds.md section 5); VG-3 and VG-4
// are evaluated together. A verdict outside the closed vocabulary is a VG-3 finding, made after
// VG-1 and VG-2 like the rest of VG-3, and reported beside the contradiction it also is. Severities
// come from the catalog table generated into src/reason-code-severity.generated.ts. I/O-free.
import { REASON_CODE_SEVERITY, type ReasonCodeSeverity } from "./reason-code-severity.generated.js";

const SEVERITY_ORDER: readonly ReasonCodeSeverity[] = ["info", "warn", "review", "fail"];
const VERDICT_FOR_SEVERITY: Readonly<Record<ReasonCodeSeverity, string>> = { info: "PASS", warn: "WARN", review: "REVIEW", fail: "FAIL" };
const VERDICTS = new Set(Object.values(VERDICT_FOR_SEVERITY));

export interface GroundsViolation {
  rule: "VG-1" | "VG-2" | "VG-3" | "VG-4";
  field: "verdict" | "reason_codes";
  code: string;
}

const hasOwn = (o: object, k: string) => Object.prototype.hasOwnProperty.call(o, k);

/** Every way `verdict` is not the verdict `reasonCodes` derive; empty when it is. */
export function verdictGroundsViolations(verdict: unknown, reasonCodes: unknown): GroundsViolation[] {
  const codes: unknown[] = Array.isArray(reasonCodes) ? reasonCodes : [];
  if (codes.length === 0) return [{ rule: "VG-1", field: "reason_codes", code: "reason_codes_absent" }];
  if (new Set(codes).size !== codes.length) return [{ rule: "VG-1", field: "reason_codes", code: "reason_codes_duplicated" }];
  const severities: ReasonCodeSeverity[] = [];
  for (const code of codes) {
    if (typeof code !== "string" || !hasOwn(REASON_CODE_SEVERITY, code)) {
      return [{ rule: "VG-2", field: "reason_codes", code: "reason_code_not_in_catalog" }];
    }
    severities.push(REASON_CODE_SEVERITY[code]!);
  }
  const highest = severities.reduce((a, b) => (SEVERITY_ORDER.indexOf(b) > SEVERITY_ORDER.indexOf(a) ? b : a));
  const violations: GroundsViolation[] = [];
  if (typeof verdict !== "string" || !VERDICTS.has(verdict)) {
    violations.push({ rule: "VG-3", field: "verdict", code: "verdict_outside_vocabulary" });
  }
  if (verdict !== VERDICT_FOR_SEVERITY[highest]) violations.push({ rule: "VG-3", field: "verdict", code: "verdict_contradicts_grounds" });
  if (verdict === "PASS" && !severities.includes("info")) {
    violations.push({ rule: "VG-4", field: "verdict", code: "pass_without_affirmative_ground" });
  }
  return violations;
}

/**
 * The entry-contract errors for an entry's verdict and grounds, as `$.<field>: <code>`. Only a
 * verdict and reason codes the schema accepts are judged here; the schema's own refusals are not
 * repeated.
 */
export function registryEntryGroundsErrors(entry: Record<string, unknown>): string[] {
  const { verdict, reason_codes: codes } = entry;
  if (typeof verdict !== "string" || !VERDICTS.has(verdict) || !Array.isArray(codes) || codes.length === 0) return [];
  if (codes.some((code) => typeof code !== "string" || !hasOwn(REASON_CODE_SEVERITY, code))) return [];
  if (new Set(codes).size !== codes.length) return [];
  return verdictGroundsViolations(verdict, codes).map((v) => `$.${v.field}: ${v.code}`);
}

/** The rules of verdict-grounds.md section 3 a verification summary can violate, in rule order. */
export type SummaryRule = "VG-1" | "VG-2" | "VG-3" | "VG-4" | "VG-5" | "VG-6" | "VG-7";

const STATUS_FOR_SEVERITY: Readonly<Record<ReasonCodeSeverity, string>> = { info: "pass", warn: "warning", review: "review", fail: "fail" };
const STATUSES = new Set(Object.values(STATUS_FOR_SEVERITY));
const ACTIONABLE: ReadonlySet<ReasonCodeSeverity> = new Set(["review", "fail"]);

/** Python's json.dumps of a string with ensure_ascii: everything outside space to tilde, and the quote and the backslash, is escaped by UTF-16 unit. */
function jsonString(text: string): string {
  const short: Record<string, string> = { '"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t" };
  return `"${text.replace(/[\\"]|[^ -~]/g, (c) => short[c] ?? `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`)}"`;
}

/** How Python's repr writes a finite, non-integral binary64: the shortest digits that read back, positional between 1e-4 and 1e16. */
function nonIntegralSpelling(x: number): string {
  const [mantissa, exponent] = Math.abs(x).toExponential().split("e") as [string, string];
  const digits = mantissa.replace(".", "");
  const e = Number(exponent);
  const sign = x < 0 ? "-" : "";
  if (e < -4 || e >= 16) {
    const point = digits.length > 1 ? `${digits[0]}.${digits.slice(1)}` : digits;
    return `${sign}${point}e${e < 0 ? "-" : "+"}${String(Math.abs(e)).padStart(2, "0")}`;
  }
  if (e < 0) return `${sign}0.${"0".repeat(-e - 1)}${digits}`;
  return `${sign}${digits.slice(0, e + 1)}.${digits.slice(e + 1)}`;
}

/** The binary64 value a number is read as, spelled so that no finite number, `null` or other JSON value shares it. */
function numberSpelling(reading: number): string {
  if (Number.isNaN(reading)) return "nan";
  if (reading === Infinity) return "inf";
  if (reading === -Infinity) return "-inf";
  // -0 is written 0, as RFC 8785 writes it; an integral value beyond 2^53 is written out in full, as int() writes it.
  if (Number.isInteger(reading)) return Math.abs(reading) <= Number.MAX_SAFE_INTEGER ? String(reading + 0) : BigInt(reading).toString();
  return nonIntegralSpelling(reading);
}

/** Member names in code point order, as Python sorts them: UTF-16 order differs only where a surrogate meets U+E000 to U+FFFF. */
function byCodePoint(a: string, b: string): number {
  const x = Array.from(a);
  const y = Array.from(b);
  for (let i = 0; i < x.length && i < y.length; i++) {
    const d = x[i]!.codePointAt(0)! - y[i]!.codePointAt(0)!;
    if (d !== 0) return d;
  }
  return x.length - y.length;
}

/**
 * A key under which two entries are equal exactly when they are the same JSON value, as
 * json_value_key of loquitur-schemas does. A string is keyed as itself; anything else is
 * serialized with the members of each object sorted by name and every number written as the
 * binary64 value it is read as, so 1, 1.0 and 1e0 are one value. NaN and the infinities, which
 * JSON.stringify would write as null, are `nan`, `inf` and `-inf`, which no finite number and not
 * null is written as. A value JSON cannot hold (undefined, a function, a symbol, a cycle) has a
 * spelling no JSON value has. The walk is iterative, so a value's depth never reaches the stack,
 * and nothing in the value makes it throw.
 */
export function jsonIdentity(value: unknown): string {
  if (typeof value === "string") return `s:${value}`;
  const VALUE = 0, TEXT = 1, LEAVE = 2;
  const stack: unknown[] = [value];
  const kinds: number[] = [VALUE];
  const open = new Set<object>();
  const parts: string[] = [];
  const push = (kind: number, item: unknown): void => { stack.push(item); kinds.push(kind); };
  while (stack.length > 0) {
    const kind = kinds.pop()!;
    const item = stack.pop();
    if (kind === TEXT) { parts.push(item as string); continue; }
    if (kind === LEAVE) { open.delete(item as object); continue; }
    if (item === null) parts.push("null");
    else if (typeof item === "boolean") parts.push(item ? "true" : "false");
    else if (typeof item === "string") parts.push(jsonString(item));
    else if (typeof item === "number") parts.push(numberSpelling(item));
    else if (typeof item === "bigint") parts.push(numberSpelling(Number(item)));
    else if (typeof item === "object" && open.has(item)) parts.push('?"cycle"');
    else if (Array.isArray(item)) {
      open.add(item);
      push(LEAVE, item);
      push(TEXT, "]");
      for (let i = item.length - 1; i >= 0; i--) {
        push(VALUE, item[i]);
        if (i > 0) push(TEXT, ",");
      }
      push(TEXT, "[");
    } else if (typeof item === "object") {
      open.add(item);
      push(LEAVE, item);
      push(TEXT, "}");
      // An own data property is read by its name even when the name is __proto__.
      const record = item as Record<string, unknown>;
      const names = Object.keys(record).sort(byCodePoint);
      for (let i = names.length - 1; i >= 0; i--) {
        push(VALUE, record[names[i]!]);
        push(TEXT, `${jsonString(names[i]!)}:`);
        if (i > 0) push(TEXT, ",");
      }
      push(TEXT, "{");
    } else parts.push(`?${jsonString(typeof item)}`);
  }
  return `j:${parts.join("")}`;
}

/**
 * Whether `key_checks` reports nothing for VG-5: absent, null, `[]` or `{}`. A value that is not an
 * array, an object or null (a string, a number, true or false) is treated as absent.
 */
function empty(value: unknown): boolean {
  if (Array.isArray(value)) return value.length === 0;
  if (value !== null && typeof value === "object") return Object.keys(value as object).length === 0;
  return true;
}

const isObject = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value);

/**
 * The rules of verdict-grounds.md section 3 that a verification summary violates, in rule order,
 * with the evaluation order of section 5: a violation of VG-1 (no `reason_codes` array, an empty
 * one, or one citing a JSON value twice) or of VG-2 (a cited entry that is not a code of the
 * catalog) is the only rule listed; otherwise VG-3 to VG-7 are judged together. Empty when the
 * summary satisfies every rule. The rules apply to any JSON value, valid against the schema or
 * not (section 1): a document that is not a JSON object cites nothing (VG-1), a `key_checks` that
 * is not an array, an object or null is absent (VG-5), a `reason_context` that is not an array is
 * absent, and an entry of it that is not an object, has no `code` or whose `code` is not a string
 * names no catalog code (VG-7). Entries of `reason_codes` are compared as JSON values, so 1, 1.0
 * and 1e0 are one entry (VG-1), and `reason_code_vocabulary_version` is not read (VG-2). Nothing
 * in the document makes this throw, and nothing is repaired. The catalog is the protocol's,
 * generated into src/reason-code-severity.generated.ts; schema validation is a separate question
 * and is not asked.
 */
export function summaryViolatedRules(summary: unknown): SummaryRule[] {
  if (summary === null || typeof summary !== "object" || Array.isArray(summary)) return ["VG-1"];
  const document = summary as Record<string, unknown>;
  const field = (name: string): unknown => (hasOwn(document, name) ? document[name] : undefined);
  const raw = field("reason_codes");
  const entries: unknown[] = Array.isArray(raw) ? raw : [];
  if (entries.length === 0) return ["VG-1"];
  if (new Set(entries.map(jsonIdentity)).size !== entries.length) return ["VG-1"];
  if (entries.some((code) => typeof code !== "string" || !hasOwn(REASON_CODE_SEVERITY, code))) return ["VG-2"];
  const codes = entries as string[];
  const severities = codes.map((code) => REASON_CODE_SEVERITY[code]!);
  const highest = severities.reduce((a, b) => (SEVERITY_ORDER.indexOf(b) > SEVERITY_ORDER.indexOf(a) ? b : a));
  const status = field("status");
  const violated = new Set<SummaryRule>();
  if (typeof status !== "string" || !STATUSES.has(status) || status !== STATUS_FOR_SEVERITY[highest]) violated.add("VG-3");
  if (status === "pass" && !severities.includes("info")) violated.add("VG-4");
  if (status === "pass" && empty(field("key_checks"))) violated.add("VG-5");
  // A reason_context that is not an array is treated as absent: it has no entries for VG-7, and
  // meets no VG-6 obligation. Each entry names the code of its string `code`, or none.
  const context = field("reason_context");
  const named = (Array.isArray(context) ? context : [])
    .map((entry) => (isObject(entry) && hasOwn(entry, "code") && typeof entry.code === "string" ? entry.code : null));
  const contextCodes = new Set(named.filter((code): code is string => code !== null));
  if (codes.some((code, i) => ACTIONABLE.has(severities[i]!) && !contextCodes.has(code))) violated.add("VG-6");
  if (named.some((code) => code === null || !hasOwn(REASON_CODE_SEVERITY, code))) violated.add("VG-7");
  return (["VG-3", "VG-4", "VG-5", "VG-6", "VG-7"] as const).filter((rule) => violated.has(rule));
}
