import type { VerificationReceipt, VerificationStatus, UntrustedRegistryEntryInput, ValidatedRegistryEntry } from "../src/index.js";
import { parseRegistryEntry } from "../src/index.js";

const status: VerificationStatus = "review";
const receipt = null as unknown as VerificationReceipt;
const untrusted: UntrustedRegistryEntryInput = JSON.parse("{}");
const parsed = parseRegistryEntry(untrusted);
if (parsed.ok) {
  const validated: ValidatedRegistryEntry = parsed.value;
  void validated.registry_entry_id;
}
void status; void receipt;

// The report's status, verdict and requested checks are closed unions, not strings: a caller's
// switch over them is checked by the compiler.
import type { VerifyReport } from "../src/index.js";
type Equal<A, B> = (<T>() => T extends A ? 1 : 2) extends (<T>() => T extends B ? 1 : 2) ? true : false;
const statusUnion: Equal<VerifyReport["status"], "OFFLINE_OK" | "OFFLINE_REVIEW" | "OFFLINE_FAIL" | "UNSUPPORTED_VERSION" | "HOST_FAILURE"> = true;
const verdictUnion: Equal<VerifyReport["verdict"], "PASS" | "REVIEW" | "FAIL" | null> = true;
const checksUnion: Equal<VerifyReport["checks_requested"][number], "structure" | "integrity" | "link" | "authorization"> = true;
void statusUnion; void verdictUnion; void checksUnion;
const reasonsNarrow: Equal<string extends VerifyReport["review_reasons"][number] ? true : false, false> = true;
void reasonsNarrow;

// The closed sets are reachable by name from the entry, as values and as the unions they define.
import type { AuthorizationStatus, CheckName, ReportStatus, ReportVerdict, ReviewReason } from "../src/index.js";
import type { AUTHORIZATION_STATUSES, CHECK_NAMES, REVIEW_REASONS } from "../src/index.js";
const reportStatusUnion: Equal<ReportStatus, VerifyReport["status"]> = true;
const reportVerdictUnion: Equal<ReportVerdict | null, VerifyReport["verdict"]> = true;
const checkNameUnion: Equal<CheckName, (typeof CHECK_NAMES)[number]> = true;
const reviewReasonUnion: Equal<ReviewReason, (typeof REVIEW_REASONS)[number]> = true;
const authorizationUnion: Equal<AuthorizationStatus, (typeof AUTHORIZATION_STATUSES)[number]> = true;
void reportStatusUnion; void reportVerdictUnion; void checkNameUnion; void reviewReasonUnion; void authorizationUnion;
