# Public and private boundary

`@loquitur/verify` is the TypeScript offline verifier for Loquitur evidence bundles, a preview.

## What this package is

- A TypeScript package that verifies Loquitur evidence locally.
- Offline only: canonicalization, hashing, signature verification, the registry link check and
  the issuer and key authorization check.

## What this package is not

- Not an HTTP client. It ships no generated client, no `fetch` call and no base URL.
- Not a stable public contract.
- Not a production package.
- Not a browser user interface.
- Not a server.
- Not a registry explorer.
- Not a proof of compliance, legal truth, audit, valuation or finality.
- Not an oracle or a price feed.

## HTTP client

This package carries no HTTP client, generated or written by hand, no vendored API description
and no client lock. No API description is a generation input for this package.

## Generated material in this package

`src/generated/loquitur-protocol.ts` is generated from the `loquitur-schemas` declaration
artifact and bound by `SCHEMA_TYPES_LOCK.json`. It is type-only protocol material, not a client.

## Claims this package does not make

- operation of a production registry;
- a stable API or a stable package contract;
- an external audit or SOC 2 coverage;
- regulatory compliance;
- legal truth;
- valuation correctness;
- chain finality;
- oracle behavior.
