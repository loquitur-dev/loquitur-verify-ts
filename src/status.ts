// Status of this package: the offline verifier, tested against the cross-language vectors
// shared with the Python verifier. The public API is not frozen.
// The package ships the offline verifier only, and no HTTP client.
export const LOQUITUR_VERIFY_STATUS = {
  role: "offline_verifier",
  packageStatus: "preview",
  crossLanguageGoldenTested: true,
  publicApiStable: false,
  productionReady: false,
  npmPackageName: "@loquitur/verify",
  httpClientIncluded: false,
} as const;

export type LoquiturVerifyStatus = typeof LOQUITUR_VERIFY_STATUS;
