// Fail-closed npm publication guard.
//
// The package is a preview, not published to npm: publication stays blocked in depth
// (`private: true`, no `publishConfig`, and this guard on `prepack` /
// `prepublishOnly`) while local packaging (`npm pack`, `npm pack --dry-run`)
// must remain usable so a consumer project can install a local tarball.
//
// Contract documented in docs/maintainers/REPOSITORY_LAYOUT.md: the guard stays active until the
// maintainer decides to publish to npm. A release does not set LOQUITUR_VERIFY_NPM_PUBLISH_APPROVED:
// release.yml packs its tarball through this guard without it. docs/maintainers/releasing.md
// keeps the variable for a `publish` job that would be added with that decision.
//
// This script must be invoked directly (`node scripts/publish-guard.mjs`),
// not via a nested `npm run`. npm reports `npm_command=run` to nested scripts,
// which makes `npm pack` and `npm publish` indistinguishable from inside.
import { readFileSync } from "node:fs";

const APPROVAL_ENV = "LOQUITUR_VERIFY_NPM_PUBLISH_APPROVED";
// Commands that only build or inspect a tarball locally. Anything not listed
// here, an unset npm_command included, is treated as a publication attempt.
const LOCAL_COMMANDS = new Set(["pack", "install", "ci", "run", "run-script", "test", "exec"]);

const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
const approved = process.env[APPROVAL_ENV] === "1";
const command = process.env.npm_command ?? "";
const publicationAttempt = !LOCAL_COMMANDS.has(command);
const errors = [];

if (!approved) {
  if (pkg.private !== true) {
    errors.push('package.json must keep "private": true until a release approves npm publication');
  }
  if (pkg.publishConfig !== undefined) {
    errors.push(`package.json must not define "publishConfig" unless ${APPROVAL_ENV}=1 (registry override risk)`);
  }
  if (publicationAttempt) {
    errors.push(
      `npm publication is blocked: this package is a preview ` +
        `(npm_command=${command || "unset"}). It is not published to npm, and a release does not ` +
        `set ${APPROVAL_ENV}; docs/maintainers/releasing.md says how a publication would be added.`,
    );
  }
}

// Invariants enforced in every mode, including an approved release.
if (pkg.license !== "MIT OR Apache-2.0") {
  errors.push('package.json "license" must be MIT OR Apache-2.0');
}
if (!Array.isArray(pkg.files) || pkg.files.length === 0) {
  errors.push('package.json "files" must whitelist the published contents');
} else {
  // src/, generated/, examples and tests are not listed: the tarball ships the build under
  // dist/src. The text of src/ reaches readers on purpose inside dist/src/**/*.js.map
  // (sourcesContent, under the same license), so a stack trace maps to source;
  // scripts/check-pack-maps.mjs, which prepack runs after the build, holds the maps to src/ text
  // only. generated/, examples and tests ship in no form.
  const leaked = pkg.files.filter((entry) => /^\.?\/?(src|generated|examples|test)\b/.test(entry));
  if (leaked.length > 0) {
    errors.push(`package.json "files" must not publish internal material: ${leaked.join(", ")}`);
  }
  // tsconfig compiles test/type-contract.ts so it is type-checked, which emits it into
  // dist/test/. Shipping a bare "dist" therefore publishes compiled test code to
  // consumers. Require the published tree to be narrowed to the runtime output.
  const shipsAllOfDist = pkg.files.some((entry) => /^\.?\/?dist\/?$/.test(entry));
  if (shipsAllOfDist) {
    errors.push(
      'package.json "files" must not ship all of "dist" (it contains compiled test output); ' +
        'publish "dist/src" instead',
    );
  }
  const leakedDistTests = pkg.files.filter((entry) => /^\.?\/?dist\/(test|tests)\b/.test(entry));
  if (leakedDistTests.length > 0) {
    errors.push(`package.json "files" must not publish compiled tests: ${leakedDistTests.join(", ")}`);
  }
}

if (errors.length > 0) {
  console.error("publish guard: BLOCKED");
  for (const error of errors) console.error(`  - ${error}`);
  process.exit(1);
}

console.error(
  approved
    ? `publish guard: publication explicitly approved via ${APPROVAL_ENV}=1`
    : `publish guard: OK (preview; npm_command=${command || "unset"})`,
);
