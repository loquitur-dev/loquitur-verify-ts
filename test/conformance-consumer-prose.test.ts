// The corpus this repository says it consumes, held to the corpus it pins.
//
// CONFORMANCE_CONSUMER.json pins the corpus by id, artifact name, byte count and digest.
// README.md names the same corpus in prose, under "Conformance", and that sentence is what a
// reader meets first. Two files that name different corpora give different answers to the same
// question: which corpus this package is measured against.
//
// The pin moves whenever a new corpus is pinned, and prose no test reads does not move
// with it. This binds one to the other.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const readme = readFileSync(new URL("../README.md", import.meta.url), "utf8");
const pin = JSON.parse(readFileSync(new URL("../CONFORMANCE_CONSUMER.json", import.meta.url), "utf8"));

test("README.md names the corpus this repository pins", () => {
  const named = new Set(
    [...readme.matchAll(/`(loquitur-conformance-[A-Za-z0-9._-]+)`/g)].map((match) => match[1]),
  );
  assert.ok(named.size > 0, "README.md does not name the corpus this repository consumes");
  assert.deepEqual(
    [...named].sort(),
    [pin.corpus_id],
    `README.md names ${[...named].sort().join(", ")}; CONFORMANCE_CONSUMER.json pins ${pin.corpus_id}`,
  );
});
