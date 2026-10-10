import { describe, expect, it } from "vitest";
import {
  buildServerSignals,
  computeTlsFingerprints,
  detectServerClient,
  getTlsBrowserProfileMismatches,
  getTlsFingerprintCandidates,
  isDeclaredBotAgent,
  parseTlsClientHello,
} from "../src/server/index.js";
import type { TlsClientHello } from "../src/server/index.js";
import {
  alpnExtension,
  chromeLikeHello,
  clientHelloRecord,
  sniExtension,
  supportedVersionsExtension,
} from "./helpers/tls-hello.js";

const CHROME =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
const FIREFOX = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0";
const CHROME_JA4 = "t13d1516h2_8daaf6152771_e5627efa2ab1";

const chromeHello = parseTlsClientHello(chromeLikeHello()) as TlsClientHello;
const scriptHello = parseTlsClientHello(
  clientHelloRecord({
    ciphers: [0x1301, 0x1302, 0x1303, 0xc02f],
    extensions: [sniExtension("example.com"), alpnExtension(["http/1.1"]), supportedVersionsExtension([0x0304, 0x0303])],
  }),
) as TlsClientHello;

function signal(signals: ReturnType<typeof buildServerSignals>, id: string) {
  return signals.find((candidate) => candidate.id === id);
}

describe("declared-bot-agent", () => {
  it("fires for agents outside the conservative token list", () => {
    expect(isDeclaredBotAgent("Scrapy/2.11.0 (+https://scrapy.org)")).toBe(true);
    const fired = signal(buildServerSignals({ userAgent: "Scrapy/2.11.0 (+https://scrapy.org)" }), "declared-bot-agent");
    expect(fired).toMatchObject({ triggered: true, weight: 0.6, score: 0.6, confidence: "medium" });
    expect(fired?.description).toBe("User-Agent declares Scrapy (generic_scraper)");
  });

  it("stays quiet for browsers and for agents the stricter signals already cover", () => {
    expect(isDeclaredBotAgent(CHROME)).toBe(false);
    expect(isDeclaredBotAgent("python-requests/2.32.3")).toBe(false);
    expect(isDeclaredBotAgent("GPTBot/1.1")).toBe(false);
    expect(isDeclaredBotAgent(undefined)).toBe(false);
    expect(signal(buildServerSignals({ userAgent: CHROME }), "declared-bot-agent")?.description).toBe(
      "User-Agent declares a known automated agent",
    );
  });
});

describe("TLS browser profile", () => {
  it("accepts what real browsers send", () => {
    expect(getTlsBrowserProfileMismatches({ userAgent: CHROME, tlsClientHello: chromeHello })).toEqual([]);
    expect(getTlsBrowserProfileMismatches({ userAgent: CHROME, tlsFingerprint: CHROME_JA4, tlsFingerprintType: "ja4" })).toEqual([]);
    expect(
      getTlsBrowserProfileMismatches({
        userAgent: CHROME,
        tlsFingerprint: "q13d0310h3_55b375c5d22e_cd85d2d88918",
        tlsFingerprintType: "ja4",
      }),
    ).toEqual([]);
  });

  it("flags legacy TLS, missing ALPN and HTTP/1.1-only offers from a browser User-Agent", () => {
    const ja4 = (value: string) =>
      getTlsBrowserProfileMismatches({ userAgent: CHROME, tlsFingerprint: value, tlsFingerprintType: "ja4" });
    expect(ja4("t12d1516h2_8daaf6152771_e5627efa2ab1")).toEqual(["offered no TLS 1.3"]);
    expect(ja4("t13d151600_8daaf6152771_e5627efa2ab1")).toEqual(["sent no ALPN"]);
    expect(ja4("t13d1516h1_8daaf6152771_e5627efa2ab1")).toEqual(["offered ALPN h1 instead of HTTP/2"]);
    expect(ja4("not-a-ja4")).toEqual([]);
  });

  it("reads raw JA3 strings but not JA3 hashes", () => {
    const raw = (value: string) => getTlsBrowserProfileMismatches({ userAgent: FIREFOX, tlsFingerprint: value });
    expect(raw("771,4865-4866,0-23-65281-10-11,29-23,0")).toEqual(["offered no TLS 1.3", "sent no ALPN"]);
    expect(raw("771,4865-4866,0-16-43-51,29-23,0")).toEqual([]);
    expect(raw("771,,,,")).toEqual(["offered no TLS 1.3", "sent no ALPN"]);
    expect(raw("cd08e31494f9531f560d64c695473da9")).toEqual([]);
  });

  it("expects GREASE from Chromium but not from Firefox", () => {
    expect(getTlsBrowserProfileMismatches({ userAgent: CHROME, tlsClientHello: scriptHello })).toEqual([
      "offered ALPN h1 instead of HTTP/2",
      "Chromium User-Agent sent no GREASE values",
    ]);
    expect(getTlsBrowserProfileMismatches({ userAgent: FIREFOX, tlsClientHello: scriptHello })).toEqual([
      "offered ALPN h1 instead of HTTP/2",
    ]);
  });

  it("only judges clients that claim to be a browser", () => {
    expect(getTlsBrowserProfileMismatches({ userAgent: "curl/8.7.1", tlsClientHello: scriptHello })).toEqual([]);
    expect(getTlsBrowserProfileMismatches({ tlsClientHello: scriptHello })).toEqual([]);
  });

  it("raises a sub-threshold signal with the reasons in its description", () => {
    const fired = signal(buildServerSignals({ userAgent: CHROME, tlsClientHello: scriptHello }), "tls-browser-profile-mismatch");
    expect(fired).toMatchObject({ triggered: true, weight: 0.45, confidence: "medium" });
    expect(fired?.description).toContain("Chromium User-Agent sent no GREASE values");
    expect(signal(buildServerSignals({ userAgent: CHROME }), "tls-browser-profile-mismatch")?.triggered).toBe(false);
  });
});

describe("locally computed fingerprints", () => {
  it("offers explicit and ClientHello-derived fingerprints as candidates", () => {
    const { ja3Hash, ja4 } = computeTlsFingerprints(chromeHello);
    expect(getTlsFingerprintCandidates({ tlsFingerprint: "abc", tlsClientHello: chromeHello })).toEqual([
      { fingerprint: "abc", type: "ja3" },
      { fingerprint: ja4, type: "ja4" },
      { fingerprint: ja3Hash, type: "ja3" },
    ]);
    expect(getTlsFingerprintCandidates({ tlsFingerprint: CHROME_JA4, tlsFingerprintType: "ja4" })).toEqual([
      { fingerprint: CHROME_JA4, type: "ja4" },
    ]);
  });

  it("matches suspicious JA3 and JA4 entries against a captured ClientHello", () => {
    const { ja3Hash, ja4 } = computeTlsFingerprints(scriptHello);
    const viaJa4 = detectServerClient(
      { userAgent: CHROME, tlsClientHello: scriptHello },
      {
        suspiciousTlsFingerprintEntries: [
          { id: "py", label: "python ja4", fingerprintType: "ja4", hash: ja4, families: ["python"], confidence: "high" },
        ],
      },
    );
    const ids = viaJa4.signals.filter((item) => item.triggered).map((item) => item.id);
    expect(ids).toEqual(
      expect.arrayContaining(["known-suspicious-tls", "tls-user-agent-mismatch", "tls-browser-profile-mismatch"]),
    );
    expect(viaJa4.isLegitClient).toBe(false);
    expect(viaJa4.context).toMatchObject({ tlsJa4: ja4, tlsJa3Hash: ja3Hash });
    expect(viaJa4.context.tlsJa3?.startsWith("771,")).toBe(true);

    const viaJa3 = detectServerClient(
      { userAgent: "python-requests/2.32.3", tlsClientHello: scriptHello },
      {
        suspiciousTlsFingerprintEntries: [
          { id: "py3", label: "python ja3", hash: ja3Hash, families: ["python"], confidence: "medium" },
        ],
      },
    );
    expect(viaJa3.automation.evidence).toContain("TLS fingerprint is compatible with python");
    expect(viaJa3.signals.find((item) => item.id === "known-suspicious-tls")?.confidence).toBe("medium");
  });

  it("counts a captured ClientHello as a TLS fingerprint", () => {
    const result = detectServerClient(
      { userAgent: CHROME, tlsClientHello: chromeHello },
      { requireTlsFingerprint: true },
    );
    expect(result.signals.find((item) => item.id === "missing-tls-fingerprint")?.triggered).toBe(false);
    expect(result.isLegitClient).toBe(true);
    expect(result.context.declaredBot).toBeUndefined();
  });
});

describe("declared bot attribution", () => {
  it("maps registry agents onto automation kinds where the client library is known", () => {
    const scrapy = detectServerClient({ userAgent: "Scrapy/2.11.0 (+https://scrapy.org)" });
    expect(scrapy.automation).toMatchObject({ isAutomated: true, kind: "python", confidence: "medium" });
    expect(scrapy.automation.evidence).toEqual(["User-Agent declares Scrapy (generic_scraper)"]);
    expect(scrapy.context.declaredBot?.id).toBe("scrapy");

    const feedly = detectServerClient({
      userAgent: "Feedly/1.0 (+http://www.feedly.com/fetcher.html; 3 subscribers)",
      crawlerVerificationStatus: "verified",
    });
    expect(feedly.automation).toMatchObject({ kind: "unknown", confidence: "high" });
    expect(feedly.automation.evidence).toContain("Trusted edge verified an automated crawler identity");
  });
});
