import { constants, createHash, createPublicKey, verify as verifySignature } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { readHeader } from "./clientIp.js";
import type { HeaderBag } from "./clientIp.js";
import { parseDictionary } from "./structuredFields.js";
import type { BareItem, DictionaryMember } from "./structuredFields.js";

export type AgentStatus = "none" | "verified" | "impersonation" | "claimed";

export interface AgentVerdict {
  status: AgentStatus;
  agentName?: string;
  category?: string;
  keyId?: string;
  algorithm?: string;
  reason?: string;
}

export interface AgentJsonWebKey {
  kty?: unknown;
  crv?: unknown;
  x?: unknown;
  n?: unknown;
  e?: unknown;
  kid?: unknown;
  nbf?: unknown;
  exp?: unknown;
}

export interface SignedAgentKey {
  name: string;
  category: string;
  jwk: AgentJsonWebKey;
}

export interface SignedAgentDirectory {
  name: string;
  category: string;
  directory: string;
}

export interface AgentVerifierOptions {
  keys?: readonly SignedAgentKey[];
  directories?: readonly SignedAgentDirectory[];
  refreshIntervalMs?: number;
  retryAfterFailureMs?: number;
  fetchTimeoutMs?: number;
  toleranceSec?: number;
  maxTrackedNonces?: number;
  fetch?: typeof fetch;
  now?: () => number;
}

export interface AgentVerificationRequest {
  method?: string;
  url: string | URL;
  headers: HeaderBag;
  alternateUrls?: ReadonlyArray<string | URL>;
}

export interface AgentVerifier {
  readonly keyCount: number;
  readonly refreshedAt: number | undefined;
  verify(request: AgentVerificationRequest): AgentVerdict;
  refresh(): Promise<number>;
}

interface ResolvedKey {
  keyObject: KeyObject;
  algorithm: "ed25519" | "rsa-pss-sha512";
  name: string;
  category: string;
  nbf?: number;
  exp?: number;
}

interface SignatureMember {
  label: string;
  components: Array<{ name: string; key?: string }>;
  params: Map<string, BareItem>;
  raw: string;
}

export const DEFAULT_SIGNED_AGENT_DIRECTORIES: readonly SignedAgentDirectory[] = [
  { name: "OpenAI ChatGPT", category: "ai_agent", directory: "https://chatgpt.com" },
  { name: "Google Agent", category: "ai_agent", directory: "https://agent.bot.goog" },
];

const TAG = "web-bot-auth";
const WELL_KNOWN_DIRECTORY = "/.well-known/http-message-signatures-directory";
const DIRECTORY_ACCEPT =
  "application/http-message-signatures-directory+json, application/jwk-set+json, application/json";
const DEFAULT_REFRESH_MS = 6 * 60 * 60_000;
const DEFAULT_RETRY_MS = 60_000;
const DEFAULT_FETCH_TIMEOUT_MS = 5_000;
const DEFAULT_TOLERANCE_SEC = 300;
const DEFAULT_MAX_NONCES = 10_000;
const PRECEDENCE: Record<AgentStatus, number> = { none: 0, claimed: 1, impersonation: 2, verified: 3 };

function normalizeEpoch(value: unknown): number | undefined {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
    return undefined;
  }
  return value > 1e12 ? Math.floor(value / 1000) : value;
}

export function jwkThumbprint(jwk: AgentJsonWebKey): string | undefined {
  if (jwk.kty === "OKP" && typeof jwk.crv === "string" && typeof jwk.x === "string") {
    return createHash("sha256")
      .update(`{"crv":${JSON.stringify(jwk.crv)},"kty":"OKP","x":${JSON.stringify(jwk.x)}}`)
      .digest("base64url");
  }
  if (jwk.kty === "RSA" && typeof jwk.n === "string" && typeof jwk.e === "string") {
    return createHash("sha256")
      .update(`{"e":${JSON.stringify(jwk.e)},"kty":"RSA","n":${JSON.stringify(jwk.n)}}`)
      .digest("base64url");
  }
  return undefined;
}

function importKey(jwk: unknown, owner: { name: string; category: string }): { ids: string[]; key: ResolvedKey } | null {
  if (typeof jwk !== "object" || jwk === null) {
    return null;
  }
  const candidate = jwk as AgentJsonWebKey;
  const thumbprint = jwkThumbprint(candidate);
  if (!thumbprint || (candidate.kty === "OKP" && candidate.crv !== "Ed25519")) {
    return null;
  }
  try {
    const keyObject = createPublicKey({
      key:
        candidate.kty === "OKP"
          ? { kty: "OKP", crv: "Ed25519", x: candidate.x as string }
          : { kty: "RSA", n: candidate.n as string, e: candidate.e as string },
      format: "jwk",
    });
    const ids = [thumbprint];
    if (typeof candidate.kid === "string" && candidate.kid !== thumbprint) {
      ids.push(candidate.kid);
    }
    return {
      ids,
      key: {
        keyObject,
        algorithm: candidate.kty === "OKP" ? "ed25519" : "rsa-pss-sha512",
        name: owner.name,
        category: owner.category,
        nbf: normalizeEpoch(candidate.nbf),
        exp: normalizeEpoch(candidate.exp),
      },
    };
  } catch {
    return null;
  }
}

function directoryUrl(directory: string): string {
  const url = new URL(directory);
  if (url.pathname === "/") {
    url.pathname = WELL_KNOWN_DIRECTORY;
  }
  return url.toString();
}

function canonicalAuthority(url: URL): string {
  const host = url.hostname.toLowerCase();
  const defaultPort = (url.protocol === "https:" && url.port === "443") || (url.protocol === "http:" && url.port === "80");
  return url.port && !defaultPort ? `${host}:${url.port}` : host;
}

function fieldValue(headers: HeaderBag, name: string): string {
  const value = readHeader(headers, name);
  if (value === undefined) {
    throw new Error(`Covered field ${name} is absent`);
  }
  return value.trim().replace(/\s+/g, " ");
}

function componentValue(method: string, url: URL, headers: HeaderBag, component: { name: string; key?: string }): string {
  switch (component.name) {
    case "@method":
      return method.toUpperCase();
    case "@authority":
      return canonicalAuthority(url);
    case "@scheme":
      return url.protocol.slice(0, -1).toLowerCase();
    case "@target-uri":
      return `${url.protocol}//${canonicalAuthority(url)}${url.pathname}${url.search}`;
    case "@path":
      return url.pathname;
    case "@query":
      return url.search === "" ? "?" : url.search;
    default:
      break;
  }
  if (component.name.startsWith("@")) {
    throw new Error(`Unsupported derived component ${component.name}`);
  }
  const value = fieldValue(headers, component.name);
  if (component.key === undefined) {
    return value;
  }
  const member = parseDictionary(value).find((entry) => entry.key === component.key);
  if (!member) {
    throw new Error(`Field ${component.name} has no member ${component.key}`);
  }
  return member.raw;
}

function signatureBase(method: string, url: URL, headers: HeaderBag, member: SignatureMember): string {
  const lines = member.components.map((component) => {
    const id = component.key === undefined ? `"${component.name}"` : `"${component.name}";key="${component.key}"`;
    return `${id}: ${componentValue(method, url, headers, component)}`;
  });
  lines.push(`"@signature-params": ${member.raw}`);
  return lines.join("\n");
}

function toSignatureMember(entry: DictionaryMember): SignatureMember {
  if (!entry.isList) {
    throw new SyntaxError(`Signature-Input member ${entry.key} is not an inner list`);
  }
  return {
    label: entry.key,
    components: entry.items.map((item) => {
      if (typeof item.value !== "string") {
        throw new SyntaxError("Component identifier is not a string");
      }
      const key = item.params.get("key");
      return { name: item.value.toLowerCase(), ...(typeof key === "string" ? { key } : {}) };
    }),
    params: entry.params,
    raw: entry.raw,
  };
}

function signatureBytes(header: string): Map<string, Buffer> {
  const output = new Map<string, Buffer>();
  for (const entry of parseDictionary(header)) {
    const bytes = entry.items[0].bytes;
    if (entry.isList || !bytes) {
      throw new SyntaxError(`Signature member ${entry.key} is not a byte sequence`);
    }
    output.set(entry.key, bytes);
  }
  return output;
}

function verifyBytes(key: ResolvedKey, base: string, signature: Buffer): boolean {
  return key.algorithm === "ed25519"
    ? verifySignature(null, Buffer.from(base), key.keyObject, signature)
    : verifySignature(
        "sha512",
        Buffer.from(base),
        { key: key.keyObject, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 64 },
        signature,
      );
}

function higher(current: AgentVerdict, next: AgentVerdict): AgentVerdict {
  return PRECEDENCE[next.status] >= PRECEDENCE[current.status] ? next : current;
}

function keyVerdict(status: "verified" | "impersonation", keyId: string, key: ResolvedKey, reason?: string): AgentVerdict {
  return {
    status,
    keyId,
    agentName: key.name,
    category: key.category,
    algorithm: key.algorithm,
    ...(reason ? { reason } : {}),
  };
}

function parseUrls(request: AgentVerificationRequest): URL[] {
  return [request.url, ...(request.alternateUrls ?? [])].map((candidate) => new URL(String(candidate)));
}

export function createAgentVerifier(options: AgentVerifierOptions = {}): AgentVerifier {
  const directories = [...(options.directories ?? [])];
  const refreshIntervalMs = options.refreshIntervalMs ?? DEFAULT_REFRESH_MS;
  const retryAfterFailureMs = options.retryAfterFailureMs ?? DEFAULT_RETRY_MS;
  const fetchTimeoutMs = options.fetchTimeoutMs ?? DEFAULT_FETCH_TIMEOUT_MS;
  const toleranceSec = options.toleranceSec ?? DEFAULT_TOLERANCE_SEC;
  const maxTrackedNonces = options.maxTrackedNonces ?? DEFAULT_MAX_NONCES;
  const fetchImpl = options.fetch ?? ((input: string | URL | Request, init?: RequestInit) => fetch(input, init));
  const now = options.now ?? Date.now;

  const pinned = new Map<string, ResolvedKey>();
  for (const entry of options.keys ?? []) {
    const resolved = importKey(entry.jwk, entry);
    if (!resolved) {
      throw new TypeError(`Unsupported Web Bot Auth key for ${entry.name}`);
    }
    for (const id of resolved.ids) {
      pinned.set(id, resolved.key);
    }
  }

  const fetched = new Map<number, Map<string, ResolvedKey>>();
  let index = new Map(pinned);
  const nonces = new Map<string, number>();
  let refreshedAt: number | undefined;
  let nextRefreshAt = 0;
  let inflight: Promise<number> | null = null;

  function rebuildIndex(): void {
    const next = new Map<string, ResolvedKey>();
    for (const keys of fetched.values()) {
      for (const [id, key] of keys) {
        if (!next.has(id)) {
          next.set(id, key);
        }
      }
    }
    for (const [id, key] of pinned) {
      next.set(id, key);
    }
    index = next;
  }

  async function loadDirectory(source: SignedAgentDirectory, signal: AbortSignal): Promise<Map<string, ResolvedKey> | null> {
    const response = await fetchImpl(directoryUrl(source.directory), {
      signal,
      headers: { accept: DIRECTORY_ACCEPT },
    });
    if (!response.ok) {
      return null;
    }
    const body = (await response.json()) as { keys?: unknown } | null;
    if (!body || !Array.isArray(body.keys)) {
      return null;
    }
    const keys = new Map<string, ResolvedKey>();
    for (const jwk of body.keys) {
      const resolved = importKey(jwk, source);
      for (const id of resolved?.ids ?? []) {
        keys.set(id, (resolved as { key: ResolvedKey }).key);
      }
    }
    return keys;
  }

  async function fetchDirectory(source: SignedAgentDirectory): Promise<Map<string, ResolvedKey> | null> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), fetchTimeoutMs);
    timer.unref?.();
    const keys = await loadDirectory(source, controller.signal).catch(() => null);
    clearTimeout(timer);
    return keys;
  }

  function refresh(): Promise<number> {
    if (inflight) {
      return inflight;
    }
    inflight = (async () => {
      const results = await Promise.all(directories.map((source) => fetchDirectory(source)));
      let succeeded = false;
      results.forEach((keys, position) => {
        if (keys) {
          succeeded = true;
          fetched.set(position, keys);
        }
      });
      const finishedAt = now();
      if (succeeded) {
        refreshedAt = finishedAt;
        rebuildIndex();
      }
      nextRefreshAt = finishedAt + (succeeded ? refreshIntervalMs : retryAfterFailureMs);
      inflight = null;
      return index.size;
    })();
    return inflight;
  }

  function maybeRefresh(): void {
    if (directories.length > 0 && !inflight && now() >= nextRefreshAt) {
      void refresh();
    }
  }

  function isReplay(keyId: string, params: Map<string, BareItem>, nowSec: number, expires: number | undefined): boolean {
    const nonce = params.get("nonce");
    if (typeof nonce !== "string" || maxTrackedNonces <= 0) {
      return false;
    }
    const id = `${keyId}\n${nonce}`;
    const seenUntil = nonces.get(id);
    if (seenUntil !== undefined && seenUntil >= nowSec) {
      return true;
    }
    nonces.delete(id);
    while (nonces.size >= maxTrackedNonces) {
      nonces.delete(nonces.keys().next().value as string);
    }
    nonces.set(id, (expires ?? nowSec) + toleranceSec);
    return false;
  }

  function evaluateMember(
    member: SignatureMember,
    signature: Buffer | undefined,
    method: string,
    urls: URL[],
    headers: HeaderBag,
    nowSec: number,
  ): AgentVerdict {
    const keyId = member.params.get("keyid");
    if (!signature || typeof keyId !== "string") {
      return { status: "claimed", reason: "unverifiable" };
    }
    if (!member.components.some((component) => component.name === "@authority" || component.name === "@target-uri")) {
      return { status: "claimed", keyId, reason: "authority-not-covered" };
    }
    const key = index.get(keyId);
    if (!key) {
      return { status: "claimed", keyId, reason: "unknown-key" };
    }
    const created = member.params.get("created");
    const expires = member.params.get("expires");
    const alg = member.params.get("alg");
    if (typeof expires === "number" && nowSec > expires + toleranceSec) {
      return keyVerdict("impersonation", keyId, key, "expired");
    }
    if (typeof created === "number" && nowSec + toleranceSec < created) {
      return keyVerdict("impersonation", keyId, key, "not-yet-valid");
    }
    if ((key.exp !== undefined && nowSec > key.exp + toleranceSec) || (key.nbf !== undefined && nowSec + toleranceSec < key.nbf)) {
      return keyVerdict("impersonation", keyId, key, "key-outside-validity");
    }
    if (alg !== undefined && alg !== key.algorithm) {
      return keyVerdict("impersonation", keyId, key, "algorithm-mismatch");
    }
    let uncoverable = false;
    for (const url of urls) {
      let base: string;
      try {
        base = signatureBase(method, url, headers, member);
      } catch {
        uncoverable = true;
        continue;
      }
      if (verifyBytes(key, base, signature)) {
        return isReplay(keyId, member.params, nowSec, typeof expires === "number" ? expires : undefined)
          ? { status: "claimed", keyId, reason: "replayed-nonce" }
          : keyVerdict("verified", keyId, key);
      }
    }
    return uncoverable
      ? { status: "claimed", keyId, reason: "uncoverable-component" }
      : keyVerdict("impersonation", keyId, key, "bad-signature");
  }

  function verify(request: AgentVerificationRequest): AgentVerdict {
    const signatureInput = readHeader(request.headers, "signature-input");
    const signatureHeader = readHeader(request.headers, "signature");
    if (signatureInput === undefined && signatureHeader === undefined) {
      return { status: "none" };
    }
    maybeRefresh();
    if (signatureInput === undefined || signatureHeader === undefined) {
      return { status: "claimed", reason: "incomplete-signature" };
    }
    let members: SignatureMember[];
    let signatures: Map<string, Buffer>;
    let urls: URL[];
    try {
      members = parseDictionary(signatureInput).map(toSignatureMember);
      signatures = signatureBytes(signatureHeader);
      urls = parseUrls(request);
    } catch {
      return { status: "claimed", reason: "malformed-signature" };
    }
    const method = request.method ?? "GET";
    const nowSec = now() / 1000;
    let best: AgentVerdict = { status: "none" };
    for (const member of members.filter((candidate) => candidate.params.get("tag") === TAG)) {
      best = higher(best, evaluateMember(member, signatures.get(member.label), method, urls, request.headers, nowSec));
      if (best.status === "verified") {
        return best;
      }
    }
    return best;
  }

  return {
    get keyCount() {
      return index.size;
    },
    get refreshedAt() {
      return refreshedAt;
    },
    verify,
    refresh,
  };
}
