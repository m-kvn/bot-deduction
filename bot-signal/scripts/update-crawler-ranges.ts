import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { request } from "undici";
import { CRAWLER_RANGES_FILE } from "../src/server/crawlerRanges.js";
import type { CrawlerRangeSource } from "../src/server/crawlerRanges.js";
import { parseIp } from "../src/server/ipLists.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUTPUT = path.resolve(__dirname, "../data", CRAWLER_RANGES_FILE);
const FORCE = process.argv.includes("--force");
const MIN_RETAIN_RATIO = 0.5;

const SOURCES: ReadonlyArray<Omit<CrawlerRangeSource, "ranges" | "creationTime"> & { url: string }> = [
  {
    id: "google-common-crawlers",
    url: "https://developers.google.com/static/crawling/ipranges/common-crawlers.json",
    bots: ["googlebot", "google-inspectiontool"],
  },
  {
    id: "google-user-triggered-fetchers",
    url: "https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers.json",
    bots: ["feedfetcher-google"],
  },
  {
    id: "google-user-triggered-fetchers-google",
    url: "https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers-google.json",
    bots: ["feedfetcher-google"],
  },
  { id: "bingbot", url: "https://www.bing.com/toolbox/bingbot.json", bots: ["bingbot", "msnbot"] },
  { id: "openai-gptbot", url: "https://openai.com/gptbot.json", bots: ["gptbot"] },
  { id: "openai-searchbot", url: "https://openai.com/searchbot.json", bots: ["oai-searchbot"] },
  { id: "openai-chatgpt-user", url: "https://openai.com/chatgpt-user.json", bots: ["chatgpt-user"] },
  { id: "perplexitybot", url: "https://www.perplexity.ai/perplexitybot.json", bots: ["perplexitybot"] },
  { id: "perplexity-user", url: "https://www.perplexity.ai/perplexity-user.json", bots: ["perplexity-user"] },
  { id: "applebot", url: "https://search.developer.apple.com/applebot.json", bots: ["applebot"] },
  { id: "ccbot", url: "https://index.commoncrawl.org/ccbot.json", bots: ["ccbot"] },
  { id: "duckduckbot", url: "https://duckduckgo.com/duckduckbot.json", bots: ["duckduckbot"] },
  { id: "duckassistbot", url: "https://duckduckgo.com/duckassistbot.json", bots: ["duckassistbot"] },
  { id: "ahrefsbot", url: "https://api.ahrefs.com/v3/public/crawler-ip-ranges", bots: ["ahrefsbot"] },
  { id: "mistralai-user", url: "https://mistral.ai/mistralai-user-ips.json", bots: ["mistralai-user"] },
];

interface PublishedRanges {
  creationTime?: unknown;
  prefixes?: Array<{ ipv4Prefix?: unknown; ipv6Prefix?: unknown }>;
}

function isValidCidr(cidr: string): boolean {
  const [network, prefixText, extra] = cidr.split("/");
  const parsed = parseIp(network ?? "");
  if (!parsed || extra !== undefined || !/^\d+$/.test(prefixText ?? "")) {
    return false;
  }
  return Number(prefixText) <= (parsed.kind === "ipv4" ? 32 : 128);
}

async function fetchJson(url: string, redirects = 3): Promise<PublishedRanges> {
  const { body, statusCode, headers } = await request(url, { headers: { accept: "application/json" } });
  const location = headers.location;
  if (statusCode >= 300 && statusCode < 400 && typeof location === "string" && redirects > 0) {
    await body.dump();
    return fetchJson(new URL(location, url).toString(), redirects - 1);
  }
  if (statusCode >= 400) {
    throw new Error(`Failed to fetch ${url}: HTTP ${statusCode}`);
  }
  return (await body.json()) as PublishedRanges;
}

async function prepare(source: (typeof SOURCES)[number]): Promise<CrawlerRangeSource> {
  const published = await fetchJson(source.url);
  const ranges = (published.prefixes ?? [])
    .map((prefix) => String(prefix.ipv4Prefix ?? prefix.ipv6Prefix ?? "").trim())
    .filter(isValidCidr);
  if (ranges.length === 0) {
    throw new Error(`Refusing ${source.url}: no usable prefixes`);
  }
  return {
    id: source.id,
    url: source.url,
    bots: source.bots,
    ...(typeof published.creationTime === "string" ? { creationTime: published.creationTime } : {}),
    ranges: [...new Set(ranges)],
  };
}

function existingRangeCount(): number {
  if (!fs.existsSync(OUTPUT)) {
    return 0;
  }
  const existing = JSON.parse(fs.readFileSync(OUTPUT, "utf8")) as { sources?: CrawlerRangeSource[] };
  return (existing.sources ?? []).reduce((total, source) => total + source.ranges.length, 0);
}

async function main(): Promise<void> {
  const settled = await Promise.allSettled(SOURCES.map(prepare));
  const sources: CrawlerRangeSource[] = [];
  settled.forEach((result, index) => {
    if (result.status === "fulfilled") {
      sources.push(result.value);
    } else {
      console.warn(`Skipping ${SOURCES[index].id}: ${String(result.reason)}`);
    }
  });
  const total = sources.reduce((sum, source) => sum + source.ranges.length, 0);
  const existing = existingRangeCount();
  if (!FORCE && existing > 0 && total < existing * MIN_RETAIN_RATIO) {
    throw new Error(`Refusing to overwrite: ${total} ranges is a sharp drop from ${existing} (pass --force)`);
  }
  fs.writeFileSync(
    OUTPUT,
    `${JSON.stringify({ updatedAt: new Date().toISOString(), sources }, null, 2)}\n`,
    "utf8",
  );
  console.log(`Wrote ${total} ranges from ${sources.length}/${SOURCES.length} sources to ${OUTPUT}`);
}

main().catch((error: unknown) => {
  console.error("Crawler range update failed:", error);
  process.exit(1);
});
