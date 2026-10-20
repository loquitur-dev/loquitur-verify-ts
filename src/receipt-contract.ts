// The verification receipt's closed contract, enforced from the rules generated out of the
// protocol schema (src/receipt-contract.generated.ts). I/O-free: no node:* import and no JSON
// import, so the browser entry bundles it unchanged.
import type { ContractRule } from "./contract-rule.js";
import { RECEIPT_CONTRACT } from "./receipt-contract.generated.js";
import { PROTOCOL_INSTANT_SOURCE, isCalendarInstant } from "./instant.js";
import { nonBlankString } from "./whitespace.js";

// The receipt's free strings (registry-link.md section 2; bundle-objects.md, "Free strings"): the
// members the schema types as strings and holds to no pattern, enumeration or constant. Each, when
// it is a string, has a code point outside the whitespace set W; the empty string has none and
// breaks the contract whatever the schema's minLength says. null stays admitted where it is.
const RECEIPT_FREE_STRINGS = ["bundle_id", "policy_id", "verification_mode", "asset_id", "network", "anchor_provider", "anchor_type"];

/** A JSON value in a form where equal values have equal keys (member order does not count). */
function valueKey(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(valueKey).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((k) => `${JSON.stringify(k)}:${valueKey(record[k])}`).join(",")}}`;
  }
  return JSON.stringify(value) ?? "undefined";
}

function hasType(value: unknown, type: string): boolean {
  switch (type) {
    case "null": return value === null;
    case "boolean": return typeof value === "boolean";
    case "string": return typeof value === "string";
    // The canonical numeric model: an integer is a number whose value is integral.
    case "integer": return typeof value === "number" && Number.isInteger(value);
    case "number": return typeof value === "number" && Number.isFinite(value);
    case "array": return Array.isArray(value);
    case "object": return value !== null && typeof value === "object" && !Array.isArray(value);
    default: return false;
  }
}

const patterns = new Map<string, RegExp>();
function patternOf(source: string): RegExp {
  let re = patterns.get(source);
  if (re === undefined) {
    re = new RegExp(source, "u");
    patterns.set(source, re);
  }
  return re;
}

function check(rule: ContractRule, value: unknown, path: string, errors: string[]): void {
  if (rule.types && !rule.types.some((t) => hasType(value, t))) {
    errors.push(`${path}:type`);
    return;
  }
  if ("const" in rule && valueKey(value) !== valueKey(rule.const)) errors.push(`${path}:const`);
  if (rule.enum && !rule.enum.some((option) => valueKey(option) === valueKey(value))) errors.push(`${path}:enum`);
  if (typeof value === "string") {
    // minLength counts code points, not UTF-16 code units.
    if (rule.minLength !== undefined && [...value].length < rule.minLength) errors.push(`${path}:minLength`);
    if (rule.pattern !== undefined && !patternOf(rule.pattern).test(value)) errors.push(`${path}:pattern`);
    // A value in the protocol instant pattern must also be a calendar instant (src/instant.ts), as
    // in the Python verifier's contract: verified_at 2026-02-30T00:00:00Z breaks it.
    else if (rule.pattern === PROTOCOL_INSTANT_SOURCE && !isCalendarInstant(value)) errors.push(`${path}:calendar`);
  }
  if (typeof value === "number" && rule.minimum !== undefined && value < rule.minimum) errors.push(`${path}:minimum`);
  if (Array.isArray(value)) {
    if (rule.minItems !== undefined && value.length < rule.minItems) errors.push(`${path}:minItems`);
    if (rule.uniqueItems && new Set(value.map(valueKey)).size !== value.length) errors.push(`${path}:uniqueItems`);
    if (rule.items) value.forEach((item, i) => check(rule.items!, item, `${path}[${i}]`, errors));
  }
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    const record = value as Record<string, unknown>;
    const own = (k: string) => Object.prototype.hasOwnProperty.call(record, k);
    for (const name of rule.required ?? []) if (!own(name)) errors.push(`${path}.${name}:required`);
    if (rule.additionalProperties === false) {
      for (const name of Object.keys(record)) {
        if (!rule.properties || !Object.prototype.hasOwnProperty.call(rule.properties, name)) errors.push(`${path}.${name}:additionalProperties`);
      }
    }
    for (const [name, sub] of Object.entries(rule.properties ?? {})) {
      if (own(name)) check(sub, record[name], `${path}.${name}`, errors);
    }
  }
}

/**
 * The ways a value breaks verification_receipt.schema.json, as `<path>:<keyword>` strings; empty
 * when it is a conforming receipt. The value is expected to have been loaded strictly (bounded
 * depth, rules 2 to 4), as verify-core loads every bundle member.
 */
export function receiptContractErrors(value: unknown): string[] {
  const errors: string[] = [];
  check(RECEIPT_CONTRACT, value, "$", errors);
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    const record = value as Record<string, unknown>;
    for (const name of RECEIPT_FREE_STRINGS) {
      const member = record[name];
      if (typeof member === "string" && !nonBlankString(member)) errors.push(`$.${name}:blank`);
    }
  }
  return errors;
}
