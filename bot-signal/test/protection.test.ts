import { afterEach, describe, expect, it, vi } from "vitest";
import http from "node:http";
import type { AddressInfo } from "node:net";
import type { IncomingMessage, ServerResponse } from "node:http";
import {
  createBotProtection,
  matchesPathPattern,
  requestPathForms,
} from "../src/server/index.js";
import type { BotProtectionOptions, ProtectionDecision, RateLimitStore } from "../src/server/index.js";

const CHROME =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
const GOOGLEBOT =
  "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
const BROWSER_HEADERS = {
  "user-agent": CHROME,
  "accept-language": "en-US,en;q=0.9",
  "sec-ch-ua": '"Chromium";v="140", "Google Chrome";v="140", "Not=A?Brand";v="24"',
  "sec-ch-ua-platform": '"Windows"',
  "sec-ch-ua-mobile": "?0",
  "sec-fetch-site": "none",
  "sec-fetch-mode": "navigate",
  "sec-fetch-dest": "document",
};
const QUIET: BotProtectionOptions = { detection: { lookupGeo: false, checkIpLists: false } };

function ruleStates(decision: ProtectionDecision) {
  return Object.fromEntries(decision.results.map((outcome) => [outcome.rule, `${outcome.state}:${outcome.action}`]));
}

describe("path matching", () => {
  it("matches exact paths, segment prefixes and regular expressions", () => {
    expect(matchesPathPattern("/health", ["/health"])).toBe(true);
    expect(matchesPathPattern("/health/live", ["/health"])).toBe(true);
    expect(matchesPathPattern("/healthz", ["/health"])).toBe(false);
    expect(matchesPathPattern("/static/app.js", ["/static/"])).toBe(true);
    expect(matchesPathPattern("/img/a.png", [/\.png$/])).toBe(true);
    expect(matchesPathPattern("/API/Login", ["/api/login"])).toBe(false);
    expect(matchesPathPattern("/API/Login", ["/api/login"], true)).toBe(true);
    expect(matchesPathPattern("/x", [])).toBe(false);
  });

  it("derives every reading of a request path a router might use", () => {
    expect(requestPathForms("/a/..%2f.env")).toEqual(["/a/..%2f.env", "/.env"]);
    expect(requestPathForms("//evil.example/x")).toEqual(["//evil.example/x", "/evil.example/x", "/x"]);
    expect(requestPathForms("//[")).toEqual(["//[", "/["]);
  });
});

describe("createBotProtection().protect", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("allows an ordinary browser request in monitor mode by default", async () => {
    const protection = createBotProtection(QUIET);
    const decision = await protection.protect({ url: "/index.html", headers: BROWSER_HEADERS, peer: "203.0.113.5" });
    expect(decision).toMatchObject({
      mode: "monitor",
      conclusion: "ALLOW",
      allowed: true,
      blocked: false,
      skipped: false,
      status: 200,
      method: "GET",
      path: "/index.html",
      clientIp: "203.0.113.5",
      headers: {},
    });
    expect(ruleStates(decision)).toEqual({
      "test-trigger": "RUN:ALLOW",
      honeytoken: "RUN:ALLOW",
      tripwire: "RUN:ALLOW",
      "attack-signatures": "RUN:ALLOW",
      detection: "RUN:ALLOW",
    });
    expect(decision.id).toMatch(/^[0-9a-f-]{36}$/);
    expect(decision.bot.known).toBe(false);
    expect(decision.server?.isLegitClient).toBe(true);
    expect(protection.mode).toBe("monitor");
    await protection.destroy();
  });

  it("leaves server detection off unless it is asked for", async () => {
    const decision = await createBotProtection().protect({ url: "/", headers: BROWSER_HEADERS });
    expect(decision.results.map((outcome) => outcome.rule)).toEqual([
      "test-trigger",
      "honeytoken",
      "tripwire",
      "attack-signatures",
    ]);
    expect(decision.server).toBeUndefined();
  });

  it("validates its options up front", () => {
    expect(() => createBotProtection({ trustProxy: true as never })).toThrow(TypeError);
    expect(() => createBotProtection({ trustProxy: -1 })).toThrow(TypeError);
    expect(() => createBotProtection({ maxTrackedTraps: 0 })).toThrow(RangeError);
    expect(() => createBotProtection({ maxTrackedTraps: Number.NaN })).toThrow(RangeError);
    expect(() => createBotProtection({ trustProxy: { header: "cf-connecting-ip" }, maxTrackedTraps: 5 })).not.toThrow();
  });

  it("denies scanner bait paths and remembers the address", async () => {
    const protection = createBotProtection({ ...QUIET, mode: "enforce" });
    const decision = await protection.protect({ url: "//x/../.git/config?a=1", peer: "198.51.100.7" });
    expect(decision).toMatchObject({
      conclusion: "DENY",
      blocked: true,
      rule: "tripwire",
      status: 404,
      body: { error: "Not Found" },
      path: "/.git/config",
      trapHit: { path: "/.git/config", honeytoken: false, matchedBy: "prefix", exempt: false },
    });
    expect(decision.reason).toContain("Scanner bait path /.git/config");
    expect(decision.trap).toMatchObject({ ip: "198.51.100.7", hits: 1, honeytoken: false });
    expect(protection.getTrap("::ffff:198.51.100.7")?.path).toBe("/.git/config");
    expect(protection.getTrap("not an ip")).toBeUndefined();
    protection.clearTraps();
    expect(protection.getTrap("198.51.100.7")).toBeUndefined();
  });

  it("sees traps behind absolute-form targets and dot-segment tricks", async () => {
    const protection = createBotProtection({ ...QUIET, mode: "enforce" });
    expect((await protection.protect({ url: "http://forms.example/.env" })).rule).toBe("tripwire");
    expect((await protection.protect({ url: "/a/%2e%2e/.env" })).rule).toBe("tripwire");
  });

  it("traps the honeytoken unless an edge verified the crawler", async () => {
    const protection = createBotProtection({ ...QUIET, honeytoken: { secret: "s" } });
    const trapPath = protection.honeytoken?.current().path as string;

    const scraper = await protection.protect({ url: trapPath.toUpperCase(), headers: { "user-agent": "Scrapy/2.11" }, peer: "192.0.2.1" });
    expect(scraper).toMatchObject({ conclusion: "DENY", rule: "honeytoken", blocked: false });
    expect(scraper.trap).toMatchObject({ honeytoken: true });
    expect(scraper.reason).toContain("Hidden honeytoken link");

    const claimedGooglebot = await protection.protect({ url: trapPath, headers: { "user-agent": GOOGLEBOT }, peer: "192.0.2.2" });
    expect(claimedGooglebot.conclusion).toBe("DENY");
    expect(protection.getTrap("192.0.2.2")?.honeytoken).toBe(true);

    const verified = await protection.protect({
      url: trapPath,
      headers: { "user-agent": GOOGLEBOT },
      peer: "192.0.2.3",
      context: { crawlerVerificationStatus: "verified" },
    });
    expect(verified.conclusion).toBe("ALLOW");
    expect(ruleStates(verified).honeytoken).toBe("DRY_RUN:DENY");
    expect(verified.trapHit).toMatchObject({ exempt: true, exemptReason: "a crawler the edge verified" });
    expect(verified.results.find((outcome) => outcome.rule === "honeytoken")?.reason).toContain("not attributed");
    expect(protection.getTrap("192.0.2.3")).toBeUndefined();
  });

  it("never attributes cross-site, embedded or speculative requests", async () => {
    const protection = createBotProtection({ ...QUIET, tripwire: { lockoutMs: 60_000 } });
    const requests = [
      { "sec-fetch-site": "cross-site", "sec-fetch-dest": "image" },
      { "sec-fetch-site": "same-site", "sec-fetch-dest": "document" },
      { "sec-fetch-site": "same-origin", "sec-fetch-dest": "script" },
      { "sec-fetch-site": "same-origin", "sec-fetch-dest": "document", "sec-purpose": "prefetch;prerender" },
      { purpose: "prefetch" },
      { "x-moz": "prefetch" },
    ];
    for (const headers of requests) {
      const decision = await protection.protect({ url: "/.env", headers, peer: "192.0.2.80" });
      expect(decision.conclusion).toBe("ALLOW");
      expect(decision.trapHit?.exemptReason).toBe("a cross-site, embedded or speculative request");
    }
    expect(protection.getTrap("192.0.2.80")).toBeUndefined();
    const navigation = await protection.protect({
      url: "/.env",
      headers: { "sec-fetch-site": "none", "sec-fetch-dest": "document" },
      peer: "192.0.2.80",
    });
    expect(navigation.conclusion).toBe("DENY");
    const harvester = await protection.protect({
      url: "/.env",
      headers: { "sec-fetch-site": "same-origin", "sec-fetch-dest": "empty" },
      peer: "192.0.2.81",
    });
    expect(harvester.conclusion).toBe("DENY");
  });

  it("supports a 403 tripwire status, dry runs that record nothing, and disabled traps", async () => {
    const forbidden = createBotProtection({ ...QUIET, tripwire: { status: 403 } });
    const denied = await forbidden.protect({ url: "/.env" });
    expect(denied.body).toEqual({ error: "Forbidden", rule: "tripwire", id: denied.id });
    expect(denied.trap).toBeUndefined();

    const watching = createBotProtection({
      ...QUIET,
      tripwire: { dryRun: true, lockoutMs: 60_000 },
      honeytoken: { dryRun: true },
    });
    const watched = await watching.protect({ url: "/wp-config.php", peer: "192.0.2.4" });
    expect(watched.conclusion).toBe("ALLOW");
    expect(ruleStates(watched).tripwire).toBe("DRY_RUN:DENY");
    const watchedToken = await watching.protect({ url: watching.honeytoken?.current().path, peer: "192.0.2.4" });
    expect(ruleStates(watchedToken).honeytoken).toBe("DRY_RUN:DENY");
    expect(watching.getTrap("192.0.2.4")).toBeUndefined();
    const after = await watching.protect({ url: "/", peer: "192.0.2.4" });
    expect(ruleStates(after)["trap-lockout"]).toBe("RUN:ALLOW");

    const off = createBotProtection({ ...QUIET, tripwire: false, honeytoken: false, attackSignatures: false, detection: false });
    const plain = await off.protect({ url: "/.env" });
    expect(plain.results.map((outcome) => outcome.rule)).toEqual(["test-trigger"]);
    expect(off.honeytoken).toBeUndefined();
    expect(off.robotsTxt()).toBe("# Generated by bot-signal.\n\nUser-agent: *\nDisallow:\n");
  });

  it("locks out an address that walked into a trap, for the configured window only", async () => {
    let now = 1_000_000;
    vi.spyOn(Date, "now").mockImplementation(() => now);
    const protection = createBotProtection({ ...QUIET, tripwire: { lockoutMs: 60_000, memoryMs: 120_000 } });
    await protection.protect({ url: "/.env", peer: "192.0.2.10" });
    now += 1_000;
    const locked = await protection.protect({ url: "/index.html", headers: BROWSER_HEADERS, peer: "192.0.2.10" });
    expect(locked).toMatchObject({ conclusion: "DENY", rule: "trap-lockout", status: 403 });
    expect(locked.reason).toContain("requested trap path /.env 1s ago");

    await protection.protect({ url: "/.git/HEAD", peer: "192.0.2.10" });
    expect(protection.getTrap("192.0.2.10")).toMatchObject({ hits: 2, path: "/.git/HEAD" });

    now += 61_000;
    const released = await protection.protect({ url: "/index.html", headers: BROWSER_HEADERS, peer: "192.0.2.10" });
    expect(released.conclusion).toBe("ALLOW");
    expect(released.trap?.hits).toBe(2);

    now += 200_000;
    expect(protection.getTrap("192.0.2.10")).toBeUndefined();

    const observing = createBotProtection({ ...QUIET, honeytoken: { secret: "x" }, tripwire: { lockoutMs: 60_000, dryRun: true } });
    await observing.protect({ url: observing.honeytoken?.current().path, peer: "192.0.2.11" });
    const observed = await observing.protect({ url: "/", peer: "192.0.2.11" });
    expect(ruleStates(observed)["trap-lockout"]).toBe("DRY_RUN:DENY");
  });

  it("treats an IPv6 /64 as one client for traps and limits", async () => {
    const protection = createBotProtection({ ...QUIET, rateLimit: { max: 1, windowMs: 60_000 } });
    await protection.protect({ url: "/.env", peer: "2001:db8:1:2::10" });
    expect(protection.getTrap("2001:db8:1:2::ffff")?.ip).toBe("2001:db8:1:2::/64");
    expect(protection.getTrap("2001:db8:1:3::1")).toBeUndefined();
    const rotated = await protection.protect({ url: "/", peer: "2001:db8:1:2:aaaa::1" });
    expect(rotated.conclusion).toBe("THROTTLE");
  });

  it("bounds how many trapped addresses it remembers", async () => {
    const protection = createBotProtection({ ...QUIET, maxTrackedTraps: 2 });
    for (const ip of ["192.0.2.21", "192.0.2.22", "192.0.2.23"]) {
      await protection.protect({ url: "/.env", peer: ip });
    }
    expect(protection.getTrap("192.0.2.21")).toBeUndefined();
    expect(protection.getTrap("192.0.2.23")).toBeDefined();
  });

  it("observes attack payloads by default and refuses them when enforced", async () => {
    const watching = createBotProtection(QUIET);
    const observed = await watching.protect({ url: "/search?q=1%27%20OR%201=1--", peer: "192.0.2.30" });
    expect(observed.conclusion).toBe("ALLOW");
    expect(ruleStates(observed)["attack-signatures"]).toBe("DRY_RUN:DENY");
    expect(observed.attack).toEqual({ id: "sqli_tautology", label: "SQL tautology", where: "query" });

    const enforcing = createBotProtection({ ...QUIET, attackSignatures: { dryRun: false } });
    const attack = await enforcing.protect({ url: "/search?q=1%27%20OR%201=1--" });
    expect(attack).toMatchObject({ conclusion: "DENY", rule: "attack-signatures", status: 403 });
    const lenient = createBotProtection({ ...QUIET, attackSignatures: { exclude: ["sqli_tautology"], dryRun: false } });
    expect((await lenient.protect({ url: "/search?q=1%27%20OR%201=1--" })).conclusion).toBe("ALLOW");
    expect((await enforcing.protect({ path: "/q", query: "a=1 union select 2,3" })).rule).toBe("attack-signatures");
  });

  it("enforces a published bot policy", async () => {
    const protection = createBotProtection({ ...QUIET, bots: { deny: ["training_crawler"] } });
    const gptbot = await protection.protect({ url: "/", headers: { "user-agent": "GPTBot/1.1" } });
    expect(gptbot).toMatchObject({ conclusion: "DENY", rule: "bots" });
    expect(gptbot.reason).toBe("GPTBot (training_crawler) is denied by the bot policy");
    expect((await protection.protect({ url: "/", headers: BROWSER_HEADERS })).conclusion).toBe("ALLOW");
    expect(protection.botPolicy?.matched.length).toBeGreaterThan(5);
    expect(protection.robotsTxt()).toContain("User-agent: GPTBot");

    const observing = createBotProtection({ ...QUIET, bots: { deny: ["gptbot"], dryRun: true } });
    expect(ruleStates(await observing.protect({ url: "/", headers: { "user-agent": "GPTBot/1.1" } })).bots).toBe("DRY_RUN:DENY");
    expect(createBotProtection({ ...QUIET, bots: false }).botPolicy).toBeUndefined();
  });

  it("throttles over-limit clients with Retry-After and RateLimit headers", async () => {
    const protection = createBotProtection({
      ...QUIET,
      mode: "enforce",
      rateLimit: { max: 2, windowMs: 60_000 },
    });
    const first = await protection.protect({ url: "/api", peer: "192.0.2.40" });
    expect(first.headers).toMatchObject({ "RateLimit-Limit": "2", "RateLimit-Remaining": "1" });
    expect(first.rateLimit?.remaining).toBe(1);
    await protection.protect({ url: "/api", peer: "192.0.2.40" });
    const third = await protection.protect({ url: "/api", peer: "192.0.2.40" });
    expect(third).toMatchObject({ conclusion: "THROTTLE", rule: "rate-limit", status: 429, blocked: true });
    expect(third.headers["Retry-After"]).toBe("60");
    expect(third.body).toEqual({ error: "Too Many Requests", retryAfter: 60 });
    expect(third.reason).toBe("Rate limit exceeded: 2 requests per 60s");
    expect((await protection.protect({ url: "/api", peer: "192.0.2.41" })).conclusion).toBe("ALLOW");
    await protection.destroy();
  });

  it("scopes limits by every reading of the path, by method and by key", async () => {
    const protection = createBotProtection({
      ...QUIET,
      rateLimit: [
        { max: 100, windowMs: 60_000 },
        { name: "submit", max: 1, windowMs: 60_000, paths: ["/api/submit"], methods: ["post"] },
        { max: 5, windowMs: 60_000, key: (request) => request.headers["x-api-key"] as string | undefined },
        { max: 1, windowMs: 60_000, dryRun: true, paths: [/^\/dry/] },
      ],
    });
    const get = await protection.protect({ url: "/api/submit", headers: { "x-api-key": "k1" }, peer: "192.0.2.50" });
    expect(get.results.map((outcome) => outcome.rule)).toEqual(
      expect.arrayContaining(["rate-limit-1", "rate-limit-3"]),
    );
    expect(get.results.some((outcome) => outcome.rule === "submit")).toBe(false);
    expect(get.rateLimit?.limit).toBe(5);

    await protection.protect({ method: "POST", url: "/api/submit", peer: "192.0.2.50" });
    for (const url of ["http://forms.example/api/submit", "/API/submit", "/x/..%2f/api/submit"]) {
      const evasive = await protection.protect({ method: "POST", url, peer: "192.0.2.50" });
      expect(evasive).toMatchObject({ conclusion: "THROTTLE", rule: "submit" });
    }
    const second = await protection.protect({ method: "POST", url: "/api/submit", peer: "192.0.2.50" });
    expect(ruleStates(second)["rate-limit-3"]).toBe("NOT_RUN:ALLOW");

    await protection.protect({ url: "/dry", peer: "192.0.2.51" });
    const dry = await protection.protect({ url: "/dry", peer: "192.0.2.51" });
    expect(dry.conclusion).toBe("ALLOW");
    expect(ruleStates(dry)["rate-limit-4"]).toBe("DRY_RUN:THROTTLE");
    expect(dry.rateLimit?.limit).toBe(100);
    expect(dry.headers["Retry-After"]).toBeUndefined();

    const anonymous = await protection.protect({ url: "/x" });
    expect(anonymous.results.find((outcome) => outcome.rule === "rate-limit-1")).toMatchObject({
      state: "NOT_RUN",
      reason: "No client identity to key the limit on",
    });
  });

  it("reports the tightest of several applicable limits", async () => {
    const protection = createBotProtection({
      tripwire: true,
      honeytoken: true,
      attackSignatures: true,
      detection: false,
      rateLimit: [
        { max: 5, windowMs: 60_000 },
        { max: 100, windowMs: 60_000 },
      ],
    });
    const decision = await protection.protect({ url: "/", peer: "192.0.2.55" });
    expect(decision.rateLimit?.limit).toBe(5);
    expect(decision.results.map((outcome) => outcome.rule)).toEqual([
      "test-trigger",
      "honeytoken",
      "tripwire",
      "attack-signatures",
      "rate-limit-1",
      "rate-limit-2",
    ]);
  });

  it("fails open per rule when a shared rate-limit store errors", async () => {
    const failing: RateLimitStore = {
      consume: async () => {
        throw new Error("redis down");
      },
    };
    const odd: RateLimitStore = {
      consume: () => {
        throw "plain failure";
      },
    };
    const protection = createBotProtection({
      ...QUIET,
      rateLimit: [
        { max: 1, windowMs: 1_000, store: failing },
        { max: 1, windowMs: 1_000, store: odd },
      ],
    });
    const decision = await protection.protect({ url: "/", peer: "192.0.2.60" });
    expect(decision.conclusion).toBe("ALLOW");
    expect(decision.results.find((outcome) => outcome.rule === "rate-limit-1")?.reason).toBe(
      "Rate-limit store failed: redis down",
    );
    expect(decision.results.find((outcome) => outcome.rule === "rate-limit-2")?.reason).toBe(
      "Rate-limit store failed: plain failure",
    );
  });

  it("returns an ERROR decision that still lets the request through when protection itself fails", async () => {
    const protection = createBotProtection({
      ...QUIET,
      rateLimit: {
        max: 1,
        windowMs: 1_000,
        key: () => {
          throw new Error("key exploded");
        },
      },
    });
    const decision = await protection.protect({ url: "/page", peer: "192.0.2.70" });
    expect(decision).toMatchObject({
      conclusion: "ERROR",
      allowed: true,
      blocked: false,
      error: "key exploded",
      path: "/page",
      clientIp: "192.0.2.70",
    });
    const stringly = createBotProtection({
      ...QUIET,
      rateLimit: {
        max: 1,
        windowMs: 1_000,
        key: () => {
          throw "nope";
        },
      },
    });
    expect((await stringly.protect({ url: "/", peer: "192.0.2.71" })).error).toBe("nope");
  });

  it("scores the request with server detection, observing by default", async () => {
    const protection = createBotProtection({
      detection: { lookupGeo: false },
      trustedHeaders: { ja4: "x-ja4", ja3: "x-ja3-hash" },
    });
    const scripted = await protection.protect({
      url: "/",
      headers: { "user-agent": "python-requests/2.32.3", "x-ja4": "t13d1516h1_8daaf6152771_e5627efa2ab1" },
      peer: "3.0.0.1",
    });
    expect(scripted.conclusion).toBe("ALLOW");
    expect(ruleStates(scripted).detection).toBe("DRY_RUN:DENY");
    expect(scripted.server?.context).toMatchObject({
      tlsFingerprint: "t13d1516h1_8daaf6152771_e5627efa2ab1",
      tlsFingerprintType: "ja4",
      clientIp: "3.0.0.1",
    });

    const ja3Only = await protection.protect({ url: "/", headers: { ...BROWSER_HEADERS, "x-ja3-hash": "abc" } });
    expect(ja3Only.server?.context).toMatchObject({ tlsFingerprint: "abc", tlsFingerprintType: "ja3" });

    const enforcing = createBotProtection({ detection: { dryRun: false, lookupGeo: false, checkIpLists: false } });
    const denied = await enforcing.protect({ url: "/", headers: { "user-agent": "python-requests/2.32.3" } });
    expect(denied).toMatchObject({ conclusion: "DENY", rule: "detection" });
    expect(denied.reason).toContain("scripting-user-agent");

    const withContext = await enforcing.protect({
      url: "/",
      headers: BROWSER_HEADERS,
      context: { clientUserAgent: "different" },
    });
    expect(withContext.rule).toBe("detection");
    expect((await createBotProtection({ detection: true }).protect({ url: "/" })).server).toBeDefined();
  });

  it("reads crawler verification only from the configured trusted header", async () => {
    const protection = createBotProtection({
      ...QUIET,
      trustedHeaders: { crawlerVerification: "x-crawler-verification" },
    });
    const verified = { "user-agent": "Scrapy/2.11", "x-crawler-verification": "verified" };
    const bait = await protection.protect({ url: "/.env", headers: verified, peer: "192.0.2.9" });
    expect(bait.conclusion).toBe("ALLOW");
    expect(bait.trapHit?.exempt).toBe(true);
    const bogus = await protection.protect({
      url: "/",
      headers: { "user-agent": "Scrapy/2.11", "x-crawler-verification": "trust-me" },
      peer: "192.0.2.9",
    });
    expect(bogus.server?.context.crawlerVerificationStatus).toBeUndefined();
    const untrusted = await createBotProtection(QUIET).protect({ url: "/.env", headers: verified });
    expect(untrusted.conclusion).toBe("DENY");
  });

  it("skips only when every reading of the path is exempt, and honours the allow list", async () => {
    const protection = createBotProtection({
      ...QUIET,
      skipPaths: ["/health", "/static", /^\/assets\//g],
      allowIps: ["10.20.0.0/16"],
      trustProxy: 1,
    });
    const health = await protection.protect({ url: "/health/live" });
    expect(health).toMatchObject({ skipped: true, results: [], conclusion: "ALLOW" });
    expect((await protection.protect({ url: "/assets/a.js" })).skipped).toBe(true);
    expect((await protection.protect({ url: "/health/../.env" })).rule).toBe("tripwire");
    expect((await protection.protect({ url: "/static/..%2f..%2fapi/users" })).skipped).toBe(false);

    const office = await protection.protect({
      url: "/.env",
      headers: { "x-forwarded-for": "1.2.3.4, 10.20.1.1" },
      peer: "127.0.0.1",
    });
    expect(office.clientIp).toBe("10.20.1.1");
    expect(ruleStates(office)).toEqual({ allowlist: "RUN:ALLOW" });

    const explicit = await protection.protect({ url: "/", ip: "::ffff:198.51.100.200", peer: "127.0.0.1" });
    expect(explicit.clientIp).toBe("198.51.100.200");
  });

  it("answers the reserved installation probe with a deterministic denial", async () => {
    const protection = createBotProtection(QUIET);
    const probe = await protection.protect({ url: "/", headers: { "user-agent": "  BotSignal-Test/1.0" } });
    expect(probe).toMatchObject({ conclusion: "DENY", rule: "test-trigger", status: 403 });
    const custom = createBotProtection({ ...QUIET, testUserAgentPrefix: "Acme-Probe/" });
    expect((await custom.protect({ url: "/", headers: { "user-agent": "acme-probe/2" } })).rule).toBe("test-trigger");
    const disabled = createBotProtection({ ...QUIET, testUserAgentPrefix: false });
    expect((await disabled.protect({ url: "/", headers: { "user-agent": "BotSignal-Test/1.0" } })).conclusion).toBe("ALLOW");
  });

  it("accepts explicit paths and normalises odd targets", async () => {
    const protection = createBotProtection({ ...QUIET, detection: false });
    expect((await protection.protect({ path: "", query: "a=1" })).path).toBe("/");
    expect((await protection.protect({ url: "?only=query" })).path).toBe("/");
    expect((await protection.protect({ url: "/a#frag" })).path).toBe("/a");
    expect((await protection.protect({ url: "" })).path).toBe("/");
    expect((await protection.protect({ url: "https://forms.example" })).path).toBe("/");
    expect((await protection.protect({})).method).toBe("GET");
    expect((await protection.protect({ method: "post", url: "/x", query: "fallback" })).method).toBe("POST");
  });

  it("publishes robots.txt with the honeytoken disallowed", () => {
    const protection = createBotProtection({ honeytoken: { secret: "robots" }, bots: { deny: ["gptbot"] } });
    const robots = protection.robotsTxt({ disallow: ["/admin"], sitemap: "https://example.com/s.xml" });
    expect(robots).toContain(`Disallow: ${protection.honeytoken?.current().path}`);
    expect(robots).toContain("Disallow: /admin");
    expect(robots).toContain("User-agent: GPTBot");
    expect(robots).toContain("Sitemap: https://example.com/s.xml");
  });
});

interface Served {
  url: string;
  close: () => Promise<void>;
}

const running: Served[] = [];

async function serve(handler: (req: IncomingMessage, res: ServerResponse) => unknown): Promise<Served> {
  const server = http.createServer((req, res) => {
    Promise.resolve(handler(req, res)).catch((error: unknown) => {
      res.statusCode = 500;
      res.end(String(error));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const served = {
    url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
  running.push(served);
  return served;
}

describe("handle and middleware", () => {
  afterEach(async () => {
    await Promise.all(running.splice(0).map((served) => served.close()));
  });

  const PAGE = "<!doctype html><html><body><h1>Hello</h1></body></html>";

  it("injects the honeytoken into HTML pages and fixes Content-Length", async () => {
    const protection = createBotProtection({ ...QUIET, honeytoken: { secret: "page" } });
    const middleware = protection.middleware();
    const { url } = await serve((req, res) =>
      middleware(req, res, () => {
        res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Content-Length": String(PAGE.length) });
        res.end(PAGE);
      }),
    );
    const response = await fetch(`${url}/`);
    const body = await response.text();
    const link = protection.honeytoken?.current().linkHtml as string;
    expect(body).toBe(PAGE.replace("</body>", `${link}</body>`));
    expect(response.headers.get("content-length")).toBe(String(Buffer.byteLength(body)));
  });

  it("serves robots.txt and blocks in enforce mode with JSON bodies", async () => {
    const protection = createBotProtection({ ...QUIET, mode: "enforce", rateLimit: { max: 3, windowMs: 60_000 } });
    const seen: unknown[] = [];
    const middleware = protection.middleware({ serveRobotsTxt: true, robotsTxt: { sitemap: "https://e.test/s.xml" } });
    const { url } = await serve((req, res) =>
      middleware(req, res, () => {
        seen.push((req as unknown as { botSignal: ProtectionDecision }).botSignal.conclusion);
        res.end("app");
      }),
    );
    const robots = await fetch(`${url}/robots.txt`);
    expect(robots.headers.get("content-type")).toBe("text/plain; charset=utf-8");
    expect(await robots.text()).toContain("Sitemap: https://e.test/s.xml");
    const head = await fetch(`${url}/robots.txt`, { method: "HEAD" });
    expect(head.status).toBe(200);

    const allowed = await fetch(`${url}/page`);
    expect(await allowed.text()).toBe("app");
    expect(allowed.headers.get("ratelimit-remaining")).toBe("0");
    expect(seen).toEqual(["ALLOW"]);

    const throttled = await fetch(`${url}/page`);
    expect(throttled.status).toBe(429);
    expect(throttled.headers.get("retry-after")).toBe("60");
    expect(throttled.headers.get("cache-control")).toBe("no-store");
    expect(await throttled.json()).toEqual({ error: "Too Many Requests", retryAfter: 60 });
  });

  it("monitor mode lets everything through but records the decision", async () => {
    const protection = createBotProtection(QUIET);
    const decisions: ProtectionDecision[] = [];
    const middleware = protection.middleware({ property: "guard" });
    const { url } = await serve((req, res) =>
      middleware(req, res, () => {
        decisions.push((req as unknown as { guard: ProtectionDecision }).guard);
        res.statusCode = 404;
        res.end("missing");
      }),
    );
    const response = await fetch(`${url}/.env`);
    expect(response.status).toBe(404);
    expect(await response.text()).toBe("missing");
    expect(decisions[0]).toMatchObject({ conclusion: "DENY", blocked: false, responded: false, rule: "tripwire" });
    expect(response.headers.get("ratelimit-limit")).toBeNull();
  });

  it("hands blocked requests to a custom onBlocked handler", async () => {
    const protection = createBotProtection({ ...QUIET, mode: "enforce" });
    const middleware = protection.middleware({
      onBlocked: (decision, _req, res) => {
        res.statusCode = 410;
        res.end(`gone:${decision.rule}`);
      },
    });
    const next = vi.fn();
    const { url } = await serve((req, res) => middleware(req, res, next));
    const response = await fetch(`${url}/.env`);
    expect(response.status).toBe(410);
    expect(await response.text()).toBe("gone:tripwire");
    expect(next).not.toHaveBeenCalled();
  });

  it("fails open when the response handling itself throws", async () => {
    const protection = createBotProtection({ ...QUIET, mode: "enforce" });
    const errors: unknown[] = [];
    const middleware = protection.middleware({
      onBlocked: () => {
        throw new Error("renderer broke");
      },
      onError: (error) => errors.push(error),
    });
    const { url } = await serve((req, res) => middleware(req, res, () => res.end("served anyway")));
    expect(await (await fetch(`${url}/.env`)).text()).toBe("served anyway");
    expect(String(errors[0])).toContain("renderer broke");

    const silent = createBotProtection({ ...QUIET, mode: "enforce" }).middleware({
      onBlocked: () => {
        throw new Error("again");
      },
    });
    const second = await serve(async (req, res) => {
      await silent(req, res);
      res.end("no next given");
    });
    expect(await (await fetch(`${second.url}/.env`)).text()).toBe("no next given");
  });

  it("works without next() and honours Express's originalUrl", async () => {
    const protection = createBotProtection({ ...QUIET, mode: "enforce" });
    const { url } = await serve(async (req, res) => {
      (req as unknown as { originalUrl: string }).originalUrl = "/mounted/.env";
      req.url = "/.env";
      const decision = await protection.handle(req, res, { injectHoneytoken: false });
      if (!decision.responded) {
        res.end(decision.path);
      }
    });
    const response = await fetch(`${url}/anything`);
    expect(await response.text()).toBe("/mounted/.env");
  });

  it("writes nothing more when headers were already sent before blocking", async () => {
    const protection = createBotProtection({ ...QUIET, mode: "enforce" });
    const { url } = await serve(async (req, res) => {
      res.writeHead(200, { "content-type": "text/plain" });
      res.write("early ");
      await protection.handle(req, res);
    });
    const response = await fetch(`${url}/.env`);
    expect(response.status).toBe(200);
    expect(await response.text()).toBe("early ");
  });

  it("does not wrap HEAD requests", async () => {
    const protection = createBotProtection(QUIET);
    const { url } = await serve(async (req, res) => {
      await protection.handle(req, res);
      res.setHeader("content-type", "text/html");
      res.setHeader("content-length", String(PAGE.length));
      res.end(req.method === "HEAD" ? undefined : PAGE);
    });
    const response = await fetch(url, { method: "HEAD" });
    expect(response.headers.get("content-length")).toBe(String(PAGE.length));
  });
});
