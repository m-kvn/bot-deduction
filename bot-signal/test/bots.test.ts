import { beforeEach, describe, expect, it } from "vitest";
import {
  BOT_CATEGORIES,
  BOT_REGISTRY,
  buildRobotsTxt,
  classifyBotUserAgent,
  clearBotUserAgentCache,
  createBotPolicy,
  isAiBotCategory,
  matchBotUserAgent,
} from "../src/server/index.js";

const CHROME =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";

describe("bot registry", () => {
  it("ships the WebDecoy agent table across its categories", () => {
    expect(BOT_REGISTRY.length).toBeGreaterThanOrEqual(180);
    expect(BOT_CATEGORIES).toContain("training_crawler");
    expect(BOT_CATEGORIES).toContain("none");
    for (const agent of BOT_REGISTRY) {
      expect(BOT_CATEGORIES).toContain(agent.category);
      expect(agent.uaPatterns.length).toBeGreaterThan(0);
      for (const pattern of agent.uaPatterns) {
        expect(pattern).toBe(pattern.toLowerCase());
      }
    }
  });
});

describe("classifyBotUserAgent", () => {
  beforeEach(() => clearBotUserAgentCache());

  it("identifies self-declared crawlers, scrapers and AI agents", () => {
    expect(
      classifyBotUserAgent(
        "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.1; +https://openai.com/gptbot",
      ),
    ).toMatchObject({ known: true, id: "gptbot", category: "training_crawler", isAI: true, organization: "OpenAI" });
    expect(classifyBotUserAgent("Scrapy/2.11.0 (+https://scrapy.org)")).toMatchObject({
      known: true,
      id: "scrapy",
      category: "generic_scraper",
      isAI: false,
    });
    expect(
      classifyBotUserAgent(
        "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
      ),
    ).toMatchObject({ id: "googlebot", category: "search_crawler", respectsRobots: true });
    expect(classifyBotUserAgent("Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)").id).toBe("slackbot");
  });

  it("does not read an app name inside an ordinary in-app browser as a crawler", () => {
    const pinterestApp =
      "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 [Pinterest/iOS]";
    const naverApp =
      "Mozilla/5.0 (Linux; Android 14; SM-S918N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36 NAVER(inapp; search; 2000; 12.6.6)";
    expect(classifyBotUserAgent(pinterestApp).known).toBe(false);
    expect(classifyBotUserAgent(naverApp).known).toBe(false);
    expect(classifyBotUserAgent(CHROME)).toEqual({ known: false, category: "none", score: 0, isAI: false });
  });

  it("still sees headless browser tokens inside browser-shaped user agents", () => {
    expect(
      classifyBotUserAgent(
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/140.0.0.0 Safari/537.36",
      ).id,
    ).toBe("headlesschrome");
  });

  it("requires a token boundary before a pattern", () => {
    expect(matchBotUserAgent("cooperator-client/1.0")).toBeUndefined();
    expect(matchBotUserAgent("operator/1.0")?.id).toBe("operator");
    expect(matchBotUserAgent("x-operator x-cooperator")?.id).toBe("operator");
    expect(matchBotUserAgent(undefined)).toBeUndefined();
    expect(matchBotUserAgent("")).toBeUndefined();
  });

  it("caches matches and misses, and stays bounded", () => {
    const first = matchBotUserAgent("Scrapy/2.11.0");
    expect(matchBotUserAgent("Scrapy/2.11.0")).toBe(first);
    expect(matchBotUserAgent(CHROME)).toBeUndefined();
    expect(matchBotUserAgent(CHROME)).toBeUndefined();
    for (let index = 0; index < 1_100; index += 1) {
      matchBotUserAgent(`unique-client-${index}`);
    }
    expect(matchBotUserAgent("Scrapy/2.11.0")?.id).toBe("scrapy");
  });

  it("groups the AI categories", () => {
    expect(isAiBotCategory("ai_agent")).toBe(true);
    expect(isAiBotCategory("search_crawler")).toBe(false);
  });
});

describe("bot policy", () => {
  it("resolves categories, agents and the ai shorthand, with allow winning", () => {
    const policy = createBotPolicy({
      deny: ["training_crawler", "Ahrefsbot", "AI"],
      allow: ["perplexitybot", "ClaudeBot"],
    });
    const ids = policy.matched.map((agent) => agent.id);
    expect(ids).toContain("gptbot");
    expect(ids).toContain("ahrefsbot");
    expect(ids).toContain("chatgpt-user");
    expect(ids).not.toContain("perplexitybot");
    expect(ids).not.toContain("claudebot");
    expect(ids).not.toContain("googlebot");
    expect(policy.unenforceable.every((agent) => !agent.respectsRobots)).toBe(true);
    expect(policy.denies(classifyBotUserAgent("GPTBot/1.1"))).toBe(true);
    expect(policy.denies(classifyBotUserAgent("PerplexityBot/1.0"))).toBe(false);
    expect(policy.denies(classifyBotUserAgent(CHROME))).toBe(false);
    expect(policy.denies({ known: true, category: "none", score: 0, isAI: false })).toBe(false);
  });

  it("publishes the same agent set it enforces as robots.txt", () => {
    const policy = createBotPolicy({ deny: ["gptbot", "facebookexternalhit", "yahoo-slurp", "screaming-frog", "curl"] });
    const robots = policy.robotsTxt({ disallow: ["/private", "/private"], sitemap: "https://example.com/sitemap.xml", crawlDelay: 5 });
    expect(robots).toContain("User-agent: GPTBot\n");
    expect(robots).toContain("User-agent: facebookexternalhit\n");
    expect(robots).toContain("User-agent: slurp\n");
    expect(robots).toContain("User-agent: ScreamingFrog\n");
    expect(robots).toContain("User-agent: cURL\n");
    expect(robots).toContain("Disallow: /\n");
    expect(robots.match(/Disallow: \/private/g)).toHaveLength(1);
    expect(robots).toContain("Crawl-delay: 5");
    expect(robots).toContain("Sitemap: https://example.com/sitemap.xml");
    expect(robots).toContain("#   cURL (Open Source)");
  });

  it("builds a permissive robots.txt with no policy and no annotations", () => {
    expect(buildRobotsTxt({ annotate: false })).toBe("User-agent: *\nDisallow:\n");
    expect(buildRobotsTxt()).toBe("# Generated by bot-signal.\n\nUser-agent: *\nDisallow:\n");
    expect(createBotPolicy().matched).toEqual([]);
  });
});
