import { createAutomationAssessment } from "../automation.js";
import type { AutomationKind } from "../automation.js";
import { getBotUserAgentKind } from "../userAgent.js";
import { enrichServerContext } from "./enrich.js";
import { buildServerSignals } from "./analysis.js";
import { classifyBotUserAgent } from "./bots.js";
import type {
  ConfidenceLevel,
  ServerClientContext,
  ServerClientResult,
  ServerDetectorOptions,
  ServerSignal,
} from "./types.js";
import type { EnrichedServerContext } from "./enrich.js";
import {
  findTlsFingerprintEntry,
  getTlsFingerprintCandidates,
  getUserAgentFamily,
  isTlsUserAgentMismatch,
  KNOWN_SUSPICIOUS_TLS_FINGERPRINTS,
} from "./tls.js";
import type { TlsFingerprintEntry } from "./tls.js";
import { computeTlsFingerprints } from "./tlsClientHello.js";
import type { TlsClientHello } from "./tlsClientHello.js";

const DECLARED_BOT_AUTOMATION_KINDS: Readonly<Record<string, AutomationKind>> = {
  scrapy: "python",
  beautifulsoup: "python",
  httpx: "python",
  aiohttp: "python",
  "python-requests": "python",
  "python-urllib": "python",
  python: "python",
  colly: "go",
  "go-http-client": "go",
  jsoup: "java",
  okhttp: "java",
  "apache-httpclient": "java",
  java: "java",
  curl: "curl",
  headlesschrome: "browser-automation",
  puppeteer: "puppeteer",
  playwright: "playwright",
  selenium: "selenium",
  phantomjs: "phantomjs",
};

/**
 * Combines triggered signal weights into one score:
 * `1 - Π(1 - weightᵢ)` — independent-probability union, so extra signals
 * always raise the score but never past 1.
 * @internal
 */
export function aggregateServerSuspicionScore(signals: ServerSignal[]): number {
  const triggered = signals.filter((signal) => signal.triggered);

  if (triggered.length === 0) {
    return 0;
  }

  let score = 1;

  for (const signal of triggered) {
    score *= 1 - signal.weight;
  }

  return 1 - score;
}

/**
 * Confidence in the verdict based on high-confidence signal hits and score.
 * @internal
 */
export function resolveServerConfidence(
  signals: ServerSignal[],
  suspicionScore: number,
): ConfidenceLevel {
  const triggeredHigh = signals.filter(
    (signal) => signal.triggered && signal.confidence === "high",
  ).length;

  if (triggeredHigh >= 1 || suspicionScore >= 0.7) {
    return "high";
  }

  if (suspicionScore >= 0.35) {
    return "medium";
  }

  return "low";
}

function buildResultContext(
  context: EnrichedServerContext,
): ServerClientResult["context"] {
  const declaredBot = classifyBotUserAgent(context.userAgent);
  return {
    clientIp: context.clientIp,
    ipTimezone: context.ipTimezone,
    clientTimezone: context.clientTimezone,
    tlsFingerprint: context.tlsFingerprint,
    tlsFingerprintType: context.tlsFingerprintType,
    userAgent: context.userAgent,
    clientUserAgent: context.clientUserAgent,
    acceptLanguage: context.acceptLanguage,
    clientLanguage: context.clientLanguage,
    clientLanguages: context.clientLanguages,
    clientPlatform: context.clientPlatform,
    secChUa: context.secChUa,
    secChUaPlatform: context.secChUaPlatform,
    secChUaMobile: context.secChUaMobile,
    secFetchSite: context.secFetchSite,
    secFetchMode: context.secFetchMode,
    secFetchDest: context.secFetchDest,
    ipCountry: context.ipCountry,
    isDatacenterIp: context.isDatacenterIp,
    isAbuseListedIp: context.isAbuseListedIp,
    isIcloudPrivateRelay: context.isIcloudPrivateRelay,
    crawlerVerificationStatus: context.crawlerVerificationStatus,
    datacenterProvider: context.datacenterProvider,
    icloudRelayCountry: context.icloudRelayCountry,
    ...tlsResultContext(context.tlsClientHello),
    ...(declaredBot.known ? { declaredBot } : {}),
  };
}

function tlsResultContext(
  hello: TlsClientHello | undefined,
): Pick<ServerClientResult["context"], "tlsJa3" | "tlsJa3Hash" | "tlsJa4"> {
  if (!hello) {
    return {};
  }
  const { ja3, ja3Hash, ja4 } = computeTlsFingerprints(hello);
  return { tlsJa3: ja3, tlsJa3Hash: ja3Hash, tlsJa4: ja4 };
}

function classifyServerAutomation(
  context: ServerClientContext,
  suspiciousTlsFingerprints: string[],
  suspiciousTlsFingerprintEntries: TlsFingerprintEntry[],
) {
  const crawlerVerificationEvidence =
    context.crawlerVerificationStatus === "verified"
      ? "Trusted edge verified an automated crawler identity"
      : context.crawlerVerificationStatus === "spoofed"
        ? "Trusted edge conclusively rejected the claimed crawler identity"
        : undefined;
  const uaFamily = getUserAgentFamily(context.userAgent);
  const labelledEntries = [
    ...KNOWN_SUSPICIOUS_TLS_FINGERPRINTS,
    ...suspiciousTlsFingerprintEntries,
  ];
  const tlsSupportsUa = getTlsFingerprintCandidates(context).some((candidate) => {
    const entry = findTlsFingerprintEntry(
      candidate.fingerprint,
      suspiciousTlsFingerprints,
      candidate.type,
      suspiciousTlsFingerprintEntries,
    );
    return Boolean(
      entry &&
        labelledEntries.includes(entry) &&
        context.userAgent &&
        !isTlsUserAgentMismatch(
          candidate.fingerprint,
          context.userAgent,
          suspiciousTlsFingerprints,
          candidate.type,
          suspiciousTlsFingerprintEntries,
        ),
    );
  });
  if (["curl", "python", "go", "java"].includes(uaFamily)) {
    return createAutomationAssessment(
      true,
      uaFamily as "curl" | "python" | "go" | "java",
      crawlerVerificationEvidence ? "high" : "medium",
      [
        `User-Agent claims ${uaFamily}`,
        ...(crawlerVerificationEvidence ? [crawlerVerificationEvidence] : []),
        ...(tlsSupportsUa ? [`TLS fingerprint is compatible with ${uaFamily}`] : []),
      ],
    );
  }

  const botUaKind = getBotUserAgentKind(context.userAgent);
  if (botUaKind) {
    const alternatives = botUaKind === "browser-automation"
      ? ["patchright", "playwright", "puppeteer", "selenium"] as const
      : [];
    return createAutomationAssessment(
      true,
      botUaKind === "crawler" || botUaKind === "http-client"
        ? "unknown"
        : botUaKind,
      "high",
      [
        `User-Agent claims ${botUaKind}`,
        ...(crawlerVerificationEvidence ? [crawlerVerificationEvidence] : []),
        ...(tlsSupportsUa && uaFamily !== "unknown"
          ? [`TLS fingerprint is compatible with ${uaFamily}`]
          : []),
      ],
      [...alternatives],
    );
  }

  const declaredBot = classifyBotUserAgent(context.userAgent);
  if (declaredBot.known) {
    return createAutomationAssessment(
      true,
      DECLARED_BOT_AUTOMATION_KINDS[declaredBot.id as string] ?? "unknown",
      crawlerVerificationEvidence ? "high" : "medium",
      [
        `User-Agent declares ${declaredBot.name} (${declaredBot.category})`,
        ...(crawlerVerificationEvidence ? [crawlerVerificationEvidence] : []),
      ],
    );
  }

  if (crawlerVerificationEvidence) {
    return createAutomationAssessment(
      true,
      "unknown",
      "high",
      [crawlerVerificationEvidence],
    );
  }

  return createAutomationAssessment(false, "unknown", "low", []);
}

/**
 * Scores an already-enriched request context synchronously. Use this when you
 * have your own GeoIP/blocklist pipeline; otherwise prefer
 * {@link detectServerClientAsync}, which fills the context from `clientIp`.
 */
export function detectServerClient(
  context: ServerClientContext,
  options: ServerDetectorOptions = {},
): ServerClientResult {
  const scoreThreshold = options.scoreThreshold ?? 0.5;
  const signals = buildServerSignals(context, options);
  const suspicionScore = aggregateServerSuspicionScore(signals);
  const confidence = resolveServerConfidence(signals, suspicionScore);
  const isLegitClient = suspicionScore < scoreThreshold;

  return {
    suspicionScore,
    confidence,
    signals,
    isLegitClient,
    automation: classifyServerAutomation(
      context,
      options.suspiciousTlsFingerprints ?? [],
      options.suspiciousTlsFingerprintEntries ?? [],
    ),
    context: buildResultContext(context),
  };
}

/**
 * Scores a request in one call. When `clientIp` is set, the context is
 * auto-enriched with GeoIP country/timezone and bundled blocklist matches
 * (datacenter ranges, AbuseIPDB, iCloud Private Relay) before scoring.
 *
 * @example
 * const result = await detectServerClientAsync({
 *   clientIp: req.ip,
 *   clientTimezone: req.headers["x-timezone"],
 *   userAgent: req.headers["user-agent"],
 *   tlsFingerprint: req.headers["x-ja3-hash"],
 * });
 * if (!result.isLegitClient) return res.status(403).end();
 */
export async function detectServerClientAsync(
  context: ServerClientContext,
  options: ServerDetectorOptions = {},
): Promise<ServerClientResult> {
  const enriched = await enrichServerContext(context, options);
  return detectServerClient(enriched, options);
}
