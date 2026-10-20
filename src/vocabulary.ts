// Registered vocabularies: which asset types, workflows and anchoring methods this verifier knows,
// written from loquitur-protocol docs/specification/verification-vocabularies.md sections 5 to 9.
//
// The schemas hold `asset_type`, `workflow` and `anchor.method` to an identifier and nothing more
// (sections 5 and 7). Whether a well-formed value is one the verifier knows is decided against a
// registered vocabulary document, one per kind: the version built into this package
// (src/registered-vocabularies.generated.ts, generated from loquitur-protocol), or one the operator
// supplies (section 8). No input of a run supplies one. No node:* import, so it runs in every entry
// point.
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex } from "@noble/hashes/utils";
import { CanonicalizationError, canonicalJsonBytes, parseJsonStrict } from "./canonical.js";
import { isPlainObject, jsonValueViolatesStrictness } from "./json-strictness.js";
import { IDENTIFIER } from "./protocol-input.js";
import { REGISTERED_VOCABULARIES, REGISTERED_VOCABULARY_SHA256 } from "./registered-vocabularies.generated.js";
import { nonBlankString } from "./whitespace.js";

/** The kinds of registered vocabulary, closed (verification-vocabularies.md section 5), in its order. */
export const VOCABULARY_KINDS = ["asset_type", "workflow", "anchoring_method"] as const;
/** A kind of registered vocabulary. */
export type VocabularyKind = (typeof VOCABULARY_KINDS)[number];

/** Where the document held for a kind came from: built into this package, or supplied by the operator. */
export type VocabularySource = "embedded" | "operator";

/** Whether a governed member's value is known, unknown or invalid (verification-vocabularies.md section 7). */
export type VocabularyValueStatus = "known" | "unknown" | "invalid";

/**
 * The refusal of a registered vocabulary document an operator supplies
 * (verification-vocabularies.md section 8): it is not a JSON object, not strict JSON, breaks
 * section 6, or registers another kind than the one it is supplied for; or the host says nothing,
 * or nothing that is a regular file, is found at its path, or that it failed to read the file. A
 * library interface raises it before it reads any evidence and returns no report
 * (report-contract.md section 4).
 */
export class VocabularyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "VocabularyError";
  }
}

/** One registered vocabulary document a run holds for its kind. */
export interface HeldVocabulary {
  readonly kind: VocabularyKind;
  /** The document's `version`, `MAJOR.MINOR.PATCH`. */
  readonly version: string;
  /** The registered values, whatever their status: a deprecated value is known. */
  readonly values: ReadonlySet<string>;
  /**
   * SHA-256, lowercase hexadecimal: of the embedded file's bytes for an embedded document, and of
   * the RFC 8785 canonical bytes of the document for one the operator supplies, which this library
   * takes as a parsed document and not as bytes.
   */
  readonly sha256: string;
  readonly source: VocabularySource;
}

/** The informative report member `vocabularies` records, per kind, the document a run held (section 8). */
export interface VocabularyRecord {
  version: string;
  /** `sha256:<64 lowercase hex>`, as HeldVocabulary.sha256 describes. */
  sha256: string;
  source: VocabularySource;
}

/** One document for each kind. */
export type HeldVocabularies = Readonly<Record<VocabularyKind, HeldVocabulary>>;

// Section 6: `version` and every `since`, three decimal integers of at most nine digits, no
// leading zero and no suffix.
const VERSION = /^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$/;
const DOCUMENT_MEMBERS: ReadonlySet<string> = new Set(["object_type", "schema_version", "kind", "version", "values"]);
const VALUE_MEMBERS: ReadonlySet<string> = new Set(["since", "status", "title", "profile", "asset_types"]);
const VALUE_REQUIRED = ["since", "status", "title", "profile"] as const;
const STATUSES: ReadonlySet<string> = new Set(["active", "deprecated"]);

const own = (object: Record<string, unknown>, name: string): boolean => Object.prototype.hasOwnProperty.call(object, name);
const isKind = (value: unknown): value is VocabularyKind => typeof value === "string" && (VOCABULARY_KINDS as readonly string[]).includes(value);
const identifier = (value: unknown): value is string => typeof value === "string" && IDENTIFIER.test(value);

/** A version of section 6 as its three integers, compared component by component. */
function versionTriple(text: string): [number, number, number] {
  const match = VERSION.exec(text)!;
  return [Number(match[1]), Number(match[2]), Number(match[3])];
}

/** Whether version `a` is later than version `b`, compared as integers from MAJOR to PATCH. */
function laterVersion(a: string, b: string): boolean {
  const x = versionTriple(a);
  const y = versionTriple(b);
  for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i]! > y[i]!;
  return false;
}

/** Every way one registered value breaks section 6, the rule on `asset_types` included when `kind` is known. */
function valueProblems(name: string, entry: unknown, kind: unknown, version: unknown): string[] {
  const where = `values.${name}`;
  if (!isPlainObject(entry)) return [`${where}: not an object`];
  const problems: string[] = [];
  for (const member of Object.keys(entry)) if (!VALUE_MEMBERS.has(member)) problems.push(`${where}.${member}: not a member of the format`);
  for (const member of VALUE_REQUIRED) if (!own(entry, member)) problems.push(`${where}.${member}: required`);
  const since = entry.since;
  if (own(entry, "since")) {
    if (typeof since !== "string" || !VERSION.test(since)) problems.push(`${where}.since: not a version`);
    // The first rule the schema cannot state: no value's since is later than the document's
    // version.
    else if (typeof version === "string" && VERSION.test(version) && laterVersion(since, version)) {
      problems.push(`${where}.since: later than the document's version`);
    }
  }
  if (own(entry, "status") && !(typeof entry.status === "string" && STATUSES.has(entry.status))) problems.push(`${where}.status: not active or deprecated`);
  // `title`, and `profile` when it is a string, have a code point outside W.
  if (own(entry, "title") && !nonBlankString(entry.title)) problems.push(`${where}.title: not a string with a code point outside W`);
  if (own(entry, "profile") && entry.profile !== null && !nonBlankString(entry.profile)) {
    problems.push(`${where}.profile: neither null nor a string with a code point outside W`);
  }
  if (own(entry, "asset_types")) {
    const types = entry.asset_types;
    if (!Array.isArray(types) || types.length === 0 || !types.every(identifier) || new Set(types).size !== types.length) {
      problems.push(`${where}.asset_types: not a non-empty array of distinct identifiers`);
    }
  }
  // The second rule the schema cannot state: asset_types is present exactly when kind is workflow.
  if (isKind(kind) && own(entry, "asset_types") !== (kind === "workflow")) {
    problems.push(`${where}.asset_types: present exactly when the kind is workflow`);
  }
  return problems;
}

/**
 * Every way `document` breaks verification-vocabularies.md section 6: the closed members of
 * `registered-vocabularies/schema.json` at both levels, their values, and the two rules that schema
 * cannot state (no `since` later than `version`; `asset_types` present exactly for a workflow).
 * Empty when the document satisfies the section. Input strictness is held first: a document in
 * memory that no strict JSON text could produce is not a vocabulary document.
 */
export function vocabularyDocumentProblems(document: unknown): string[] {
  if (!isPlainObject(document)) return ["$: not a JSON object"];
  if (jsonValueViolatesStrictness(document)) return ["$: not a strict JSON document"];
  const problems: string[] = [];
  for (const member of Object.keys(document)) if (!DOCUMENT_MEMBERS.has(member)) problems.push(`${member}: not a member of the format`);
  for (const member of DOCUMENT_MEMBERS) if (!own(document, member)) problems.push(`${member}: required`);
  if (own(document, "object_type") && document.object_type !== "registered_vocabulary") problems.push("object_type: not registered_vocabulary");
  if (own(document, "schema_version") && document.schema_version !== "v1") problems.push("schema_version: not v1");
  if (own(document, "kind") && !isKind(document.kind)) problems.push("kind: not a kind of registered vocabulary");
  if (own(document, "version") && !(typeof document.version === "string" && VERSION.test(document.version))) problems.push("version: not a version");
  if (own(document, "values")) {
    const values = document.values;
    if (!isPlainObject(values)) problems.push("values: not an object");
    else {
      const names = Object.keys(values);
      if (names.length === 0) problems.push("values: no member");
      for (const name of names) {
        if (!identifier(name)) problems.push(`values.${name}: the name is not an identifier`);
        problems.push(...valueProblems(name, values[name], document.kind, document.version));
      }
    }
  }
  return problems;
}

/** The document held for `kind`, from a document that satisfies section 6, or a VocabularyError. */
function heldVocabulary(kind: VocabularyKind, document: unknown, source: VocabularySource, digest: () => string): HeldVocabulary {
  const problems = vocabularyDocumentProblems(document);
  if (problems.length > 0) throw new VocabularyError(`the ${kind} vocabulary breaks verification-vocabularies.md section 6: ${problems[0]}`);
  const valid = document as { kind: VocabularyKind; version: string; values: Record<string, unknown> };
  if (valid.kind !== kind) throw new VocabularyError(`the document registers the kind ${valid.kind}, not ${kind}`);
  return { kind, version: valid.version, values: new Set(Object.keys(valid.values)), sha256: digest(), source };
}

const embedded = new Map<VocabularyKind, HeldVocabulary>();

/**
 * The version of `kind` built into this package: the protocol's file, read under the same rules as
 * a document the operator supplies, and recorded with the SHA-256 of the file's bytes.
 */
export function embeddedVocabulary(kind: VocabularyKind): HeldVocabulary {
  let held = embedded.get(kind);
  if (held === undefined) {
    const text = REGISTERED_VOCABULARIES[kind];
    held = heldVocabulary(kind, parseJsonStrict(text), "embedded", () => bytesToHex(sha256(new TextEncoder().encode(text))));
    if (held.sha256 !== REGISTERED_VOCABULARY_SHA256[kind]) throw new Error(`the embedded ${kind} vocabulary does not match its recorded digest`);
    embedded.set(kind, held);
  }
  return held;
}

/**
 * The vocabulary of `kind` in a document the operator supplies, already parsed (a host that read
 * bytes that are not strict JSON passes DOCUMENT_NOT_STRICT_JSON, which the caller refuses before
 * this runs). Refused with a VocabularyError under
 * verification-vocabularies.md section 8. The digest recorded is the SHA-256 of the document's
 * RFC 8785 canonical bytes: this library is given a document, not the bytes it was read from.
 */
export function operatorVocabulary(kind: VocabularyKind, document: unknown): HeldVocabulary {
  return heldVocabulary(kind, document, "operator", () => {
    try {
      return bytesToHex(sha256(canonicalJsonBytes(document)));
    } catch (err) {
      if (err instanceof CanonicalizationError) throw new VocabularyError(`the ${kind} vocabulary cannot be canonicalized: ${err.message}`);
      throw err;
    }
  });
}

/**
 * `known` when `value` is an identifier the vocabulary registers, whatever its status; `unknown`
 * when it is an identifier the vocabulary does not register; `invalid` when it is not an identifier
 * (verification-vocabularies.md section 7).
 */
export function vocabularyValueStatus(value: unknown, held: HeldVocabulary): VocabularyValueStatus {
  if (!identifier(value)) return "invalid";
  return held.values.has(value) ? "known" : "unknown";
}

/** The informative report member `vocabularies`: for each kind, the version, digest and source held. */
export function vocabulariesRecord(held: HeldVocabularies): Record<VocabularyKind, VocabularyRecord> {
  const record = {} as Record<VocabularyKind, VocabularyRecord>;
  for (const kind of VOCABULARY_KINDS) {
    const vocabulary = held[kind];
    record[kind] = { version: vocabulary.version, sha256: `sha256:${vocabulary.sha256}`, source: vocabulary.source };
  }
  return record;
}
