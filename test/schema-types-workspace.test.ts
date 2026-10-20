// SCHEMA_TYPES_LOCK.json pins three digests of artifacts that live in loquitur-schemas:
// the generated declarations, their manifest, and the copy of the declarations shipped here.
// Two of those pins are only compared with the sibling when scripts/check-schema-types.mjs is
// given --schemas-root, which is what the `types:schema:check:workspace` script does.
//
// CI runs `types:schema:check`, the form without the flag, which compares the lock only with
// this repository's own copy, so without this test the lock and the schemas package could
// drift apart and every suite stay green: a schema description corrected in loquitur-schemas
// regenerates the manifest there, and a stale manifest pin here would go unseen.
//
// This test runs the workspace form. Where the sibling is absent it skips, and
// under LOQUITUR_REQUIRE_SIBLINGS it fails rather than reporting an unrun check as a passing one.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { sibling } from "./siblings.js";

const PACKAGE_DIR = join(dirname(fileURLToPath(import.meta.url)), "..");
const WORKSPACE = join(PACKAGE_DIR, "..");
const SCRIPT = join(PACKAGE_DIR, "scripts", "check-schema-types.mjs");

const SCHEMAS = sibling(
  "loquitur-schemas",
  [join(WORKSPACE, "loquitur-schemas")],
  "src/loquitur/schemas/types/loquitur-protocol.manifest.json",
  "loquitur-schemas is not checked out beside this repository",
);

test("the schema types lock is compared with the schemas package, not only with itself", SCHEMAS.options, () => {
  const result = spawnSync(process.execPath, [SCRIPT, "--schemas-root", SCHEMAS.dir], {
    encoding: "utf8",
    cwd: PACKAGE_DIR,
  });
  assert.equal(
    result.status,
    0,
    "the schema types check failed against loquitur-schemas; the lock here and the artifacts " +
      `there have drifted apart:\n${result.stdout}${result.stderr}`,
  );
});

test("the lock names the sibling artifacts the check compares", () => {
  const lock = JSON.parse(readFileSync(join(PACKAGE_DIR, "SCHEMA_TYPES_LOCK.json"), "utf8"));
  for (const field of ["source_repository", "source_path", "source_manifest_path", "source_sha256", "source_manifest_sha256"]) {
    assert.ok(
      typeof lock[field] === "string" && lock[field].length > 0,
      `SCHEMA_TYPES_LOCK.json does not carry ${field}, so the comparison above has no subject`,
    );
  }
  assert.equal(lock.source_repository, "loquitur-schemas");
});
