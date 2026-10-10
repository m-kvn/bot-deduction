import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import {
  CRAWLER_RANGES_FILE,
  createCrawlerRangeVerifier,
  loadCrawlerRangeData,
} from "../src/server/crawlerRanges.js";

const scratch = mkdtempSync(join(tmpdir(), "crawler-ranges-"));

afterAll(() => {
  rmSync(scratch, { recursive: true, force: true });
});

describe("published crawler IP ranges", () => {
  it("ships ranges for the crawlers that publish them", () => {
    const data = loadCrawlerRangeData();
    expect(data.updatedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    const verifier = createCrawlerRangeVerifier();
    expect(verifier.updatedAt).toBe(data.updatedAt);
    expect(verifier.botIds).toEqual(
      expect.arrayContaining(["googlebot", "bingbot", "gptbot", "oai-searchbot", "chatgpt-user", "perplexitybot", "applebot", "ccbot"]),
    );
    expect(verifier.verify("googlebot", "66.249.66.1")).toMatchObject({ status: "verified", source: "google-common-crawlers" });
    expect(verifier.verify("Googlebot", "203.0.113.7")).toEqual({ status: "unverified", botId: "Googlebot" });
  });

  it("verifies IPv4 and IPv6 membership, and stays silent for crawlers without ranges", () => {
    const verifier = createCrawlerRangeVerifier({
      data: {
        sources: [
          { id: "alpha", bots: ["AlphaBot"], ranges: ["198.51.100.0/24", "2001:db8:10::/48", "bogus", "10.0.0.0/33", "10.0.0.0/8/1", "10.1.0.0"] },
          { id: "alpha-extra", bots: ["alphabot", "betabot"], ranges: ["192.0.2.128/25"] },
        ],
      },
      outsideRanges: "spoofed",
    });
    expect(verifier.botIds).toEqual(["alphabot", "betabot"]);
    expect(verifier.verify("alphabot", "198.51.100.200")).toEqual({ status: "verified", botId: "alphabot", source: "alpha" });
    expect(verifier.verify("alphabot", "2001:db8:10:ffff::1")).toMatchObject({ status: "verified", source: "alpha" });
    expect(verifier.verify("alphabot", "192.0.2.200")).toMatchObject({ status: "verified", source: "alpha-extra" });
    expect(verifier.verify("betabot", "192.0.2.1")).toEqual({ status: "spoofed", botId: "betabot" });
    expect(verifier.verify("alphabot", "10.0.0.1")).toEqual({ status: "spoofed", botId: "alphabot" });
    expect(verifier.verify("alphabot", "2001:db8:11::1")).toMatchObject({ status: "spoofed" });
    expect(verifier.verify("alphabot", undefined)).toEqual({ status: "unverified", botId: "alphabot" });
    expect(verifier.verify("alphabot", "not-an-ip")).toEqual({ status: "unverified", botId: "alphabot" });
    expect(verifier.verify("gammabot", "198.51.100.1")).toBeUndefined();
    expect(verifier.verify(undefined, "198.51.100.1")).toBeUndefined();
  });

  it("treats a missing data file as no ranges and a malformed one as an error", () => {
    expect(loadCrawlerRangeData(scratch)).toEqual({ sources: [] });
    expect(createCrawlerRangeVerifier({ dataDir: scratch }).botIds).toEqual([]);
    writeFileSync(join(scratch, CRAWLER_RANGES_FILE), JSON.stringify({ updatedAt: "x" }));
    expect(() => loadCrawlerRangeData(scratch)).toThrow(TypeError);
  });
});
