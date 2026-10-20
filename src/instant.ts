// Protocol instants: the pattern every protocol schema gives an instant, and the calendar.
//
// registry_entry.schema.json, trust_registry.schema.json and verification_receipt.schema.json give
// each instant the pattern below. It admits values that name no instant: February 30, April 31,
// February 29 of a common year, second 60, year 0000. A protocol document carrying one is refused
// wherever the document is loaded, with the document's own outcome, not only where the instant is
// evaluated. JSON Schema cannot say so, so the rule is keyed to the pattern.

/** The instant pattern of the protocol schemas, character for character. */
export const PROTOCOL_INSTANT_SOURCE =
  "^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:([0-5][0-9]|60)Z$";
export const PROTOCOL_INSTANT = new RegExp(PROTOCOL_INSTANT_SOURCE);

const INSTANT_SHAPE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

/**
 * True when `value` is YYYY-MM-DDTHH:MM:SSZ naming a real UTC instant. Date.parse rolls
 * 2026-02-30 over to March 2 and returns NaN for second 60, and the round trip through
 * toISOString refuses both. Year 0000 survives the round trip, and the Python verifier's calendar
 * (MINYEAR 1) refuses it, so it is refused explicitly.
 */
export function isCalendarInstant(value: string): boolean {
  if (!INSTANT_SHAPE.test(value) || value.startsWith("0000")) return false;
  const t = Date.parse(value);
  return !Number.isNaN(t) && new Date(t).toISOString().slice(0, 19) + "Z" === value;
}
