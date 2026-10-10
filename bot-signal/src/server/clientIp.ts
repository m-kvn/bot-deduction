import { parseIp } from "./ipLists.js";

export type TrustProxy = false | number | readonly string[] | { header: string };

export type HeaderBag = Record<string, string | string[] | undefined>;

export interface ResolveClientIpOptions {
  headers?: HeaderBag;
  peer?: string;
  trustProxy?: TrustProxy;
}

export function readHeader(headers: HeaderBag | undefined, name: string): string | undefined {
  const value = headers?.[name.toLowerCase()];
  return Array.isArray(value) ? value.join(",") : value;
}

export function normalizeIp(raw: string | undefined | null): string | undefined {
  if (!raw) {
    return undefined;
  }

  let value = raw.trim();
  if (value.startsWith("[")) {
    const close = value.indexOf("]");
    if (close === -1) {
      return undefined;
    }
    value = value.slice(1, close);
  } else if (value.includes(".") && value.split(":").length === 2) {
    value = value.slice(0, value.indexOf(":"));
  }

  return parseIp(value)?.canonical;
}

export function isIpInCidr(ip: string, cidr: string): boolean {
  const slash = cidr.indexOf("/");
  const address = parseIp(ip);
  const network = parseIp(slash === -1 ? cidr : cidr.slice(0, slash));
  if (!address || !network) {
    return false;
  }

  const width = address.kind === "ipv4" ? 32 : 128;
  const prefixText = slash === -1 ? String(width) : cidr.slice(slash + 1).trim();
  const prefix = Number(prefixText);
  if (prefixText === "" || !Number.isInteger(prefix) || prefix < 0 || prefix > width) {
    return false;
  }

  if (address.kind === "ipv4" && network.kind === "ipv4") {
    const size = 2 ** (32 - prefix);
    return Math.floor(address.value / size) === Math.floor(network.value / size);
  }
  if (address.kind === "ipv6" && network.kind === "ipv6") {
    const shift = BigInt(128 - prefix);
    return address.value >> shift === network.value >> shift;
  }
  return false;
}

export function isPublicIp(ip: string | undefined): boolean {
  const parsed = ip ? parseIp(ip) : null;
  if (!parsed) {
    return false;
  }

  const privateRanges =
    parsed.kind === "ipv4"
      ? [
          "0.0.0.0/8",
          "10.0.0.0/8",
          "100.64.0.0/10",
          "127.0.0.0/8",
          "169.254.0.0/16",
          "172.16.0.0/12",
          "192.168.0.0/16",
        ]
      : ["::/127", "fc00::/7", "fe80::/10"];
  return !privateRanges.some((range) => isIpInCidr(parsed.canonical, range));
}

export function isValidTrustProxy(value: unknown): value is TrustProxy {
  if (value === false) {
    return true;
  }
  if (typeof value === "number") {
    return Number.isInteger(value) && value >= 0;
  }
  if (Array.isArray(value)) {
    return value.every((entry) => typeof entry === "string");
  }
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as { header?: unknown }).header === "string"
  );
}

export function clientNetworkKey(ip: string): string {
  const parsed = parseIp(ip);
  if (!parsed) {
    return ip;
  }
  return parsed.kind === "ipv4"
    ? parsed.canonical
    : `${parsed.canonical.split(":").slice(0, 4).join(":")}::/64`;
}

function forwardedChain(headers: HeaderBag | undefined): Array<string | undefined> {
  return (readHeader(headers, "x-forwarded-for") ?? "")
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry !== "")
    .map((entry) => normalizeIp(entry));
}

export function resolveClientIp(options: ResolveClientIpOptions): string | undefined {
  const { headers, trustProxy = false } = options;
  const peer = normalizeIp(options.peer);

  if (!isValidTrustProxy(trustProxy) || trustProxy === false || trustProxy === 0) {
    return peer;
  }

  if (typeof trustProxy === "number") {
    const chain = forwardedChain(headers);
    const index = chain.length - trustProxy;
    return index < 0 ? peer : (chain[index] ?? peer);
  }

  if (!Array.isArray(trustProxy)) {
    const value = readHeader(headers, (trustProxy as { header: string }).header);
    return normalizeIp(value?.split(",").pop()) ?? peer;
  }

  const ranges = trustProxy as readonly string[];
  const chain = forwardedChain(headers);
  const hops = peer ? [...chain, peer] : chain;
  for (let index = hops.length - 1; index >= 0; index -= 1) {
    const candidate = hops[index];
    if (candidate === undefined) {
      return peer;
    }
    if (!ranges.some((range) => isIpInCidr(candidate, range))) {
      return candidate;
    }
  }
  return hops[0] ?? peer;
}
