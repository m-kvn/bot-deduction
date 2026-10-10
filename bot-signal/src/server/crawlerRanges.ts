import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { getDefaultIpDataDir, parseIp } from "./ipLists.js";
import type { CrawlerVerificationStatus } from "./types.js";

export interface CrawlerRangeSource {
  id: string;
  url?: string;
  bots: readonly string[];
  ranges: readonly string[];
  creationTime?: string;
}

export interface CrawlerRangeData {
  updatedAt?: string;
  sources: readonly CrawlerRangeSource[];
}

export interface CrawlerRangeVerifierOptions {
  dataDir?: string;
  data?: CrawlerRangeData;
  outsideRanges?: "unverified" | "spoofed";
}

export interface CrawlerRangeMatch {
  status: CrawlerVerificationStatus;
  botId: string;
  source?: string;
}

export interface CrawlerRangeVerifier {
  readonly botIds: readonly string[];
  readonly updatedAt?: string;
  verify(botId: string | undefined, ip: string | undefined): CrawlerRangeMatch | undefined;
}

interface Network {
  kind: "ipv4" | "ipv6";
  value: bigint;
  shift: bigint;
  source: string;
}

export const CRAWLER_RANGES_FILE = "crawler_ip_ranges.json";

function parseNetwork(cidr: string, source: string): Network | null {
  const [address, prefixText, extra] = cidr.trim().split("/");
  const parsed = parseIp(address);
  const width = parsed?.kind === "ipv4" ? 32 : 128;
  const prefix = Number(prefixText);
  if (!parsed || extra !== undefined || !/^\d+$/.test(prefixText ?? "") || prefix > width) {
    return null;
  }
  const shift = BigInt(width - prefix);
  return { kind: parsed.kind, value: BigInt(parsed.value) >> shift, shift, source };
}

export function loadCrawlerRangeData(dataDir = getDefaultIpDataDir()): CrawlerRangeData {
  const file = join(dataDir, CRAWLER_RANGES_FILE);
  if (!existsSync(file)) {
    return { sources: [] };
  }
  const parsed = JSON.parse(readFileSync(file, "utf8")) as Partial<CrawlerRangeData>;
  if (!Array.isArray(parsed.sources)) {
    throw new TypeError(`${CRAWLER_RANGES_FILE} has no sources list`);
  }
  return { updatedAt: parsed.updatedAt, sources: parsed.sources };
}

export function createCrawlerRangeVerifier(options: CrawlerRangeVerifierOptions = {}): CrawlerRangeVerifier {
  const data = options.data ?? loadCrawlerRangeData(options.dataDir);
  const outside = options.outsideRanges ?? "unverified";
  const byBot = new Map<string, Network[]>();

  for (const source of data.sources) {
    const networks = source.ranges
      .map((range) => parseNetwork(range, source.id))
      .filter((network): network is Network => network !== null);
    for (const bot of source.bots) {
      const id = bot.toLowerCase();
      byBot.set(id, [...(byBot.get(id) ?? []), ...networks]);
    }
  }

  return {
    botIds: [...byBot.keys()],
    updatedAt: data.updatedAt,
    verify(botId, ip) {
      const networks = botId ? byBot.get(botId.toLowerCase()) : undefined;
      if (!networks) {
        return undefined;
      }
      const address = ip ? parseIp(ip) : null;
      if (!address) {
        return { status: "unverified", botId: botId as string };
      }
      const value = BigInt(address.value);
      const match = networks.find(
        (network) => network.kind === address.kind && value >> network.shift === network.value,
      );
      return match
        ? { status: "verified", botId: botId as string, source: match.source }
        : { status: outside, botId: botId as string };
    },
  };
}
