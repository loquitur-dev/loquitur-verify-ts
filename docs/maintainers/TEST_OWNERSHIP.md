# Test ownership

This repository owns the tests of its own surface. Which tests it owns does not depend on the
layout of any other repository.

## This repository owns

- the TypeScript typecheck of the sources and the tests;
- the package build and the publication guard;
- the verifier's behavior, including the cross-language vectors in `test-vectors/`.

## This repository does not own

- the normative expectations of the protocol, which belong to the protocol's governance role,
  `loquitur-protocol-governance`, and reach this repository through the pinned conformance
  corpus;
- tests of an HTTP client: this package has none.

## Sibling repositories

Some tests read `loquitur-protocol`, `loquitur-schemas` and `loquitur-verify-py` checked out
beside this one. They compare this verifier with those repositories; they do not move ownership
of anything here. A test brought over from another repository keeps the public and private
boundary, and adds no claim of production use, audit, compliance, legal truth, valuation
correctness or chain finality.

## Local check commands

The commands, and how to run the tests that read sibling repositories, are in
[`testing.md`](testing.md).
