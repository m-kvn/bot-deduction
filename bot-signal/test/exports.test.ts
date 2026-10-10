import { describe, expect, it } from "vitest";
import * as browserApi from "../src/browser.js";
import * as rootApi from "../src/index.js";
import * as serverApi from "../src/server.js";

describe("public entry points", () => {
  it("exports the browser API from the browser entry", () => {
    expect(browserApi).toMatchObject({
      detectInstantClient: expect.any(Function),
      detectInstantClientAsync: expect.any(Function),
      isHuman: expect.any(Function),
      isHumanAsync: expect.any(Function),
      isBotUserAgent: expect.any(Function),
      buildInstantSignals: expect.any(Function),
      aggregateInstantSuspicionScore: expect.any(Function),
      resolveInstantConfidence: expect.any(Function),
      createBehavioralClientDetector: expect.any(Function),
      analyzeBehavioralSamples: expect.any(Function),
      hasCdpInputCoordinateLeak: expect.any(Function),
      isSoftwareRenderer: expect.any(Function),
    });
    expect("detectServerClientAsync" in browserApi).toBe(false);
  });

  it("exports the server API from the server entry", () => {
    expect(serverApi).toMatchObject({
      detectServerClient: expect.any(Function),
      detectServerClientAsync: expect.any(Function),
      createIpListChecker: expect.any(Function),
      parseIp: expect.any(Function),
      preloadIpLists: expect.any(Function),
      isValidJa3Hash: expect.any(Function),
      normalizeTlsFingerprint: expect.any(Function),
      isBotUserAgent: expect.any(Function),
      isClientUserAgentMismatch: expect.any(Function),
      isClientLanguageMismatch: expect.any(Function),
      isClientPlatformMismatch: expect.any(Function),
      isClientHintsMobileMismatch: expect.any(Function),
      createBotProtection: expect.any(Function),
      createRateLimiter: expect.any(Function),
      createTripwire: expect.any(Function),
      createHoneytoken: expect.any(Function),
      createHoneypotField: expect.any(Function),
      createBotPolicy: expect.any(Function),
      classifyBotUserAgent: expect.any(Function),
      findAttackSignature: expect.any(Function),
      resolveClientIp: expect.any(Function),
      trackTlsClientHellos: expect.any(Function),
      computeJa3: expect.any(Function),
      computeJa4: expect.any(Function),
      parseTlsClientHello: expect.any(Function),
      MemoryRateLimitStore: expect.any(Function),
    });
    expect(serverApi.BOT_REGISTRY.length).toBeGreaterThan(100);
    expect("detectInstantClient" in serverApi).toBe(false);
    expect("createBotProtection" in browserApi).toBe(false);
  });

  it("exports both browser and server APIs from the root entry", () => {
    expect(rootApi).toMatchObject({
      detectInstantClient: expect.any(Function),
      isHuman: expect.any(Function),
      createBehavioralClientDetector: expect.any(Function),
      hasCdpInputCoordinateLeak: expect.any(Function),
      detectServerClientAsync: expect.any(Function),
      getIpListChecker: expect.any(Function),
      createBotProtection: expect.any(Function),
      trackTlsClientHellos: expect.any(Function),
    });
  });

  it("exports VERSION from all entry points", () => {
    expect(typeof rootApi.VERSION).toBe("string");
    expect(typeof browserApi.VERSION).toBe("string");
    expect(typeof serverApi.VERSION).toBe("string");
    expect(rootApi.VERSION).toBe(browserApi.VERSION);
  });
});
