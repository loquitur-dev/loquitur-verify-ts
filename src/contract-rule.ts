// The shape of one generated contract rule, in a module of its own so that the generated
// receipt contract and the validator that reads it import it from here and not from each
// other. Types only.

/** One schema node, reduced to the keywords this validator enforces. */
export interface ContractRule {
  types?: string[];
  const?: unknown;
  enum?: unknown[];
  pattern?: string;
  minLength?: number;
  minimum?: number;
  minItems?: number;
  uniqueItems?: boolean;
  items?: ContractRule;
  required?: string[];
  additionalProperties?: boolean;
  properties?: Record<string, ContractRule>;
}
