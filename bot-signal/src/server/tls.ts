import type { ConfidenceLevel } from "./types.js";
import { getScriptingUserAgentKind } from "../userAgent.js";
import {
  computeTlsFingerprints,
  isGreaseValue,
  parseJa4,
} from "./tlsClientHello.js";
import type { TlsClientHello } from "./tlsClientHello.js";

export interface TlsFingerprintSource {
  userAgent?: string;
  tlsFingerprint?: string;
  tlsFingerprintType?: "ja3" | "ja4";
  tlsClientHello?: TlsClientHello;
}

export interface TlsFingerprintCandidate {
  fingerprint: string;
  type: "ja3" | "ja4";
}

export interface TlsFingerprintEntry {
  id: string;
  label: string;
  /** Defaults to `ja3` for backward compatibility. */
  fingerprintType?: "ja3" | "ja4";
  hash?: string;
  prefix?: string;
  families: UserAgentFamily[];
  confidence: ConfidenceLevel;
}

export type UserAgentFamily =
  | "chrome"
  | "chrome-headless"
  | "edge"
  | "firefox"
  | "safari"
  | "curl"
  | "python"
  | "go"
  | "java"
  | "scripting"
  | "unknown";

/** Curated automation and scripting TLS fingerprints (JA3 hash or prefix) */
export const KNOWN_SUSPICIOUS_TLS_FINGERPRINTS: TlsFingerprintEntry[] = [];

const JA3_HASH_PATTERN = /^[0-9a-f]{32}$/;

/**
 * Whether a string is a well-formed JA3 hash (32-character lowercase MD5).
 * A hash of any other length can never match a real JA3 and is almost always
 * a typo or a truncated/expanded copy-paste.
 */
export function isValidJa3Hash(value: string): boolean {
  return JA3_HASH_PATTERN.test(value.trim().toLowerCase());
}

const BROWSER_UA_FAMILIES: UserAgentFamily[] = [
  "chrome",
  "chrome-headless",
  "edge",
  "firefox",
  "safari",
];

const UA_FAMILY_COMPATIBILITY: Record<UserAgentFamily, UserAgentFamily[]> = {
  chrome: ["chrome", "chrome-headless", "edge"],
  "chrome-headless": ["chrome", "chrome-headless", "edge"],
  edge: ["chrome", "edge", "chrome-headless"],
  firefox: ["firefox"],
  safari: ["safari"],
  curl: ["curl", "scripting"],
  python: ["python", "scripting"],
  go: ["go", "scripting"],
  java: ["java", "scripting"],
  scripting: ["scripting", "python", "curl", "go", "java"],
  unknown: [],
};

/** Lowercases and trims a JA3/JA4 fingerprint for comparison. */
export function normalizeTlsFingerprint(fingerprint: string): string {
  return fingerprint.trim().toLowerCase();
}

/** Coarse client family from a User-Agent string (`chrome`, `curl`, `python`, …). */
export function getUserAgentFamily(userAgent: string | undefined): UserAgentFamily {
  if (!userAgent) {
    return "unknown";
  }

  const scriptingFamily = getScriptingUserAgentKind(userAgent);
  if (scriptingFamily) {
    return scriptingFamily;
  }

  if (/HeadlessChrome/i.test(userAgent)) {
    return "chrome-headless";
  }

  if (/Edg\//i.test(userAgent)) {
    return "edge";
  }

  if (/Chrome\//i.test(userAgent)) {
    return "chrome";
  }

  if (/Firefox\//i.test(userAgent)) {
    return "firefox";
  }

  if (/Safari\//i.test(userAgent) && !/Chrome/i.test(userAgent)) {
    return "safari";
  }

  return "unknown";
}

/** Whether the User-Agent claims to be a real browser (Chrome/Edge/Firefox/Safari). */
export function isBrowserLikeUserAgent(userAgent: string | undefined): boolean {
  const family = getUserAgentFamily(userAgent);
  return BROWSER_UA_FAMILIES.includes(family);
}

/** Finds the curated (or caller-supplied) entry matching a TLS fingerprint. */
export function findTlsFingerprintEntry(
  fingerprint: string,
  extraFingerprints: string[] = [],
  fingerprintType: "ja3" | "ja4" = "ja3",
  extraEntries: TlsFingerprintEntry[] = [],
): TlsFingerprintEntry | undefined {
  const normalized = normalizeTlsFingerprint(fingerprint);

  for (const entry of [
    ...KNOWN_SUSPICIOUS_TLS_FINGERPRINTS,
    ...extraEntries,
  ]) {
    if ((entry.fingerprintType ?? "ja3") !== fingerprintType) {
      continue;
    }
    const normalizedHash = entry.hash
      ? normalizeTlsFingerprint(entry.hash)
      : undefined;
    if (normalizedHash && normalized === normalizedHash) {
      return entry;
    }

    const normalizedPrefix = entry.prefix
      ? normalizeTlsFingerprint(entry.prefix)
      : undefined;
    if (normalizedPrefix && normalized.startsWith(normalizedPrefix)) {
      return entry;
    }
  }

  for (const extra of extraFingerprints) {
    const normalizedExtra = normalizeTlsFingerprint(extra);
    if (!normalizedExtra) {
      continue;
    }

    if (
      normalized === normalizedExtra ||
      normalized.startsWith(normalizedExtra)
    ) {
      return {
        id: "custom",
        label: "Custom suspicious TLS fingerprint",
        families: ["scripting"],
        confidence: "high",
      };
    }
  }

  return undefined;
}

/** Whether the fingerprint matches a known automation/scripting TLS client. */
export function isKnownSuspiciousTlsFingerprint(
  fingerprint: string | undefined,
  extraFingerprints: string[] = [],
  fingerprintType: "ja3" | "ja4" = "ja3",
  extraEntries: TlsFingerprintEntry[] = [],
): boolean {
  if (!fingerprint) {
    return false;
  }

  return (
    findTlsFingerprintEntry(
      fingerprint,
      extraFingerprints,
      fingerprintType,
      extraEntries,
    ) !==
    undefined
  );
}

/**
 * Whether a recognized TLS fingerprint contradicts the declared User-Agent —
 * e.g. a curl JA3 hash presented alongside a Chrome UA.
 */
export function isTlsUserAgentMismatch(
  fingerprint: string | undefined,
  userAgent: string | undefined,
  extraFingerprints: string[] = [],
  fingerprintType: "ja3" | "ja4" = "ja3",
  extraEntries: TlsFingerprintEntry[] = [],
): boolean {
  if (!fingerprint || !userAgent) {
    return false;
  }

  const entry = findTlsFingerprintEntry(
    fingerprint,
    extraFingerprints,
    fingerprintType,
    extraEntries,
  );
  if (!entry) {
    return false;
  }
  if (
    entry.id === "custom" &&
    ![...KNOWN_SUSPICIOUS_TLS_FINGERPRINTS, ...extraEntries].includes(entry)
  ) {
    return false;
  }

  const uaFamily = getUserAgentFamily(userAgent);
  if (uaFamily === "unknown") {
    return false;
  }

  const compatibleFamilies = UA_FAMILY_COMPATIBILITY[uaFamily];
  return !entry.families.some((family) => compatibleFamilies.includes(family));
}

export function getTlsFingerprintCandidates(
  source: TlsFingerprintSource,
): TlsFingerprintCandidate[] {
  const candidates: TlsFingerprintCandidate[] = [];
  if (source.tlsFingerprint) {
    candidates.push({
      fingerprint: source.tlsFingerprint,
      type: source.tlsFingerprintType ?? "ja3",
    });
  }
  if (source.tlsClientHello) {
    const { ja3Hash, ja4 } = computeTlsFingerprints(source.tlsClientHello);
    candidates.push({ fingerprint: ja4, type: "ja4" }, { fingerprint: ja3Hash, type: "ja3" });
  }
  return candidates;
}

const TLS_PROFILE_FAMILIES: ReadonlySet<UserAgentFamily> = new Set<UserAgentFamily>([
  "chrome",
  "edge",
  "firefox",
  "safari",
]);
const LEGACY_JA4_VERSIONS: ReadonlySet<string> = new Set(["12", "11", "10", "s3", "s2", "00"]);
const BROWSER_ALPN: ReadonlySet<string> = new Set(["h2", "h3"]);
const RAW_JA3_PATTERN = /^\d+,[\d-]*,[\d-]*,[\d-]*,[\d-]*$/;

export function getTlsBrowserProfileMismatches(source: TlsFingerprintSource): string[] {
  const family = getUserAgentFamily(source.userAgent);
  if (!TLS_PROFILE_FAMILIES.has(family)) {
    return [];
  }

  const reasons = new Set<string>();
  const type = source.tlsFingerprintType ?? "ja3";
  const ja4Values = [
    ...(source.tlsClientHello ? [computeTlsFingerprints(source.tlsClientHello).ja4] : []),
    ...(source.tlsFingerprint && type === "ja4" ? [source.tlsFingerprint] : []),
  ];

  for (const value of ja4Values) {
    const parts = parseJa4(value);
    if (!parts) {
      continue;
    }
    if (LEGACY_JA4_VERSIONS.has(parts.version)) {
      reasons.add("offered no TLS 1.3");
    }
    if (parts.alpn === "00") {
      reasons.add("sent no ALPN");
    } else if (!BROWSER_ALPN.has(parts.alpn.toLowerCase())) {
      reasons.add(`offered ALPN ${parts.alpn} instead of HTTP/2`);
    }
  }

  const raw = source.tlsFingerprint?.trim();
  if (raw && type === "ja3" && RAW_JA3_PATTERN.test(raw)) {
    const extensions = raw.split(",")[2].split("-").filter(Boolean).map(Number);
    if (!extensions.includes(43)) {
      reasons.add("offered no TLS 1.3");
    }
    if (!extensions.includes(16)) {
      reasons.add("sent no ALPN");
    }
  }

  const hello = source.tlsClientHello;
  if (
    hello &&
    (family === "chrome" || family === "edge") &&
    !hello.cipherSuites.some(isGreaseValue) &&
    !hello.extensions.some(isGreaseValue)
  ) {
    reasons.add("Chromium User-Agent sent no GREASE values");
  }

  return [...reasons];
}

/** Browser-like UA arriving without a TLS fingerprint (only when `requireTlsFingerprint`). */
export function isMissingTlsFingerprint(
  fingerprint: string | undefined,
  userAgent: string | undefined,
  requireTlsFingerprint: boolean,
): boolean {
  if (!requireTlsFingerprint) {
    return false;
  }

  return isBrowserLikeUserAgent(userAgent) && !fingerprint;
}
