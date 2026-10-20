import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const lock = JSON.parse(readFileSync(resolve(root, "SCHEMA_TYPES_LOCK.json"), "utf8"));
const sdkPath = resolve(root, lock.sdk_path);
const sdkBytes = readFileSync(sdkPath);
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const errors = [];
if (digest(sdkBytes) !== lock.sdk_sha256) errors.push("SDK generated type hash mismatch");
if (lock.sdk_sha256 !== lock.source_sha256) errors.push("source/SDK type lock mismatch");
const typesText = readFileSync(resolve(root, "src/types.ts"), "utf8");
if (typesText.includes("export interface VerificationReceipt")) errors.push("canonical interfaces must not be hand-maintained in src/types.ts");
if (typesText.includes("[key: string]: unknown")) errors.push("public validated types must not expose permissive index signatures");
const index = process.argv.indexOf("--schemas-root");
if (index >= 0) {
  const supplied = process.argv[index + 1];
  if (!supplied) errors.push("--schemas-root requires a path");
  else {
    const schemasRoot = resolve(supplied);
    const source = readFileSync(resolve(schemasRoot, lock.source_path));
    const manifest = readFileSync(resolve(schemasRoot, lock.source_manifest_path));
    if (!source.equals(sdkBytes)) errors.push("SDK generated types differ from schemas artifact");
    if (digest(source) !== lock.source_sha256) errors.push("schemas declaration hash differs from lock");
    if (digest(manifest) !== lock.source_manifest_sha256) errors.push("schemas declaration manifest hash differs from lock");
  }
}
if (errors.length) { for (const error of errors) console.error(error); process.exit(1); }
console.log(`schema types OK: ${lock.generator_id} ${lock.sdk_sha256}`);
