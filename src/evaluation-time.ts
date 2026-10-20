// The evaluation time of trust-registry-authorization.md section 2: supplied by the operator, and
// by nobody else. The issuer's own dates (effective_at, issued_at, anchored_at) take part in no
// authorization decision, and no other source of time exists in this version. Without an
// evaluation time the rows that read it are skipped, and authorization is not established.
import { isCalendarInstant } from "./instant.js";

/**
 * The refusal of a supplied evaluation time: empty, not a string, or not a calendar instant of
 * the form YYYY-MM-DDTHH:MM:SSZ. Raised before any evidence is read; no report is returned.
 */
export class EvaluationTimeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EvaluationTimeError";
  }
}

/** The operator's evaluation time. */
export interface EvaluationTime {
  /** YYYY-MM-DDTHH:MM:SSZ, a calendar instant. */
  readonly value: string;
  /** The same instant as UTC milliseconds, for the window comparisons. */
  readonly epoch: number;
}

/**
 * The operator's evaluation time: a calendar instant of the exact form, and nothing else. A
 * verifier refuses any other value before evaluating anything (section 2).
 */
export function operatorEvaluationTime(value: unknown): EvaluationTime {
  if (typeof value !== "string" || value.length === 0) {
    throw new EvaluationTimeError("the evaluation time must be a non-empty string of the form YYYY-MM-DDTHH:MM:SSZ");
  }
  if (!isCalendarInstant(value)) {
    throw new EvaluationTimeError(`the evaluation time is not a calendar instant of the form YYYY-MM-DDTHH:MM:SSZ: ${JSON.stringify(value)}`);
  }
  return { value, epoch: Date.parse(value) };
}
