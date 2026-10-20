// The licenses a consumer of @loquitur/verify receives, and the name they credit.
//
// The package is licensed under either of the Apache License 2.0 and the MIT license, at the
// recipient's option: package.json declares "MIT OR Apache-2.0", and both texts ship in the
// tarball. LICENSE-APACHE is the full text of the Apache License 2.0. The short notice that goes
// at the top of a source file is not the license: section 4(a) requires that a redistributor
// give recipients "a copy of this License", and a tarball that carries only the short notice does
// not contain one. The copyright holder is a legal person, Andrea Venè, as README.md and NOTICE
// credit.
//
// LICENSE-APACHE and LICENSE-MIT are the files the other repositories carry, byte for byte: the
// Apache License 2.0, unmodified, with the appendix's copyright line filled in for Andrea Venè,
// and the MIT license with its copyright line. The digests below are those files'; a change to
// any copy shows up here.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";

const apache = readFileSync(new URL("../LICENSE-APACHE", import.meta.url));
const mit = readFileSync(new URL("../LICENSE-MIT", import.meta.url));
const notice = readFileSync(new URL("../NOTICE", import.meta.url));
const pkg = readFileSync(new URL("../package.json", import.meta.url));

// sha256 of LICENSE-APACHE and LICENSE-MIT as loquitur-schemas, loquitur-verify-py and
// loquitur-protocol carry them.
const WORKSPACE_APACHE_SHA256 = "b67e145e47c0c9b190b0bc542481e05c5f9d001d78fda0dd5c41fb8b12d4c192";
const WORKSPACE_MIT_SHA256 = "cd1a09a7a2e280075e41892deb81c8b552bd8e817597f9d0e357ba9a5546e83a";
const OWNER = "Andrea Venè";

// A digest follows a copy that one change replaced here and in the other repositories together, so
// the content is held too: a LICENSE that is the short notice, or a truncated text, is refused.
test("LICENSE-APACHE is the full Apache License 2.0 the other repositories carry", () => {
  const text = apache.toString("utf8");
  assert.ok(text.includes("TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION"), "no terms: not the license");
  assert.ok(text.includes("END OF TERMS AND CONDITIONS"), "the terms are truncated");
  assert.ok(text.includes(`   Copyright 2026 ${OWNER}\n`), "appendix copyright line does not name the copyright holder");
  assert.equal(createHash("sha256").update(apache).digest("hex"), WORKSPACE_APACHE_SHA256);
});

test("LICENSE-MIT is the MIT license the other repositories carry", () => {
  const text = mit.toString("utf8");
  assert.ok(text.startsWith(`MIT License\n\nCopyright (c) 2026 ${OWNER}\n`), "copyright line does not name the copyright holder");
  assert.ok(text.includes("Permission is hereby granted, free of charge, to any person obtaining a copy"), "no grant");
  assert.ok(text.includes('THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND'), "no disclaimer");
  assert.equal(createHash("sha256").update(mit).digest("hex"), WORKSPACE_MIT_SHA256);
});

test("package.json declares the dual license and ships both texts", () => {
  const manifest = JSON.parse(pkg.toString("utf8"));
  assert.equal(manifest.license, "MIT OR Apache-2.0");
  for (const name of ["LICENSE-APACHE", "LICENSE-MIT", "NOTICE"]) {
    assert.ok((manifest.files as string[]).includes(name), `package.json "files" does not list ${name}`);
  }
  const text = notice.toString("utf8");
  assert.ok(text.includes("LICENSE-APACHE") && text.includes("LICENSE-MIT"), "NOTICE does not name both licenses");
});

// The name is compared as UTF-8 bytes. A name doubly encoded (C3 A8 read as CP1252 and written
// back as C3 83 C2 A8) still reads as a plausible name in most terminals, and npm freezes the
// author field of a published version.
test("package.json, NOTICE and both licenses spell the copyright holder's name in UTF-8", () => {
  const expected = Buffer.from(OWNER, "utf8");
  const doubled = Buffer.from(Buffer.from(OWNER, "utf8").toString("latin1"), "utf8");
  assert.equal(JSON.parse(pkg.toString("utf8")).author, OWNER);
  const files = [["package.json", pkg], ["NOTICE", notice], ["LICENSE-APACHE", apache], ["LICENSE-MIT", mit]] as const;
  for (const [name, bytes] of files) {
    assert.ok(bytes.includes(expected), `${name} does not carry the copyright holder's name as UTF-8`);
    assert.ok(!bytes.includes(doubled), `${name} carries the copyright holder's name doubly encoded`);
  }
});
