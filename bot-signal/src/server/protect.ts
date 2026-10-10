import { randomUUID } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { findAttackSignature } from "./attackSignatures.js";
import type { AttackSignatureMatch, AttackSignatureOptions } from "./attackSignatures.js";
import { buildRobotsTxt, classifyBotUserAgent, createBotPolicy } from "./bots.js";
import type { BotPolicy, BotPolicyOptions, BotVerdict } from "./bots.js";
import {
  clientNetworkKey,
  isIpInCidr,
  isPublicIp,
  isValidTrustProxy,
  normalizeIp,
  readHeader,
  resolveClientIp,
} from "./clientIp.js";
import type { HeaderBag, TrustProxy } from "./clientIp.js";
import { createHoneytoken } from "./honeytoken.js";
import type { Honeytoken, HoneytokenOptions } from "./honeytoken.js";
import { injectHoneytokenIntoResponse } from "./htmlInjection.js";
import { createRateLimiter, rateLimitHeaders } from "./rateLimit.js";
import type { RateLimitAlgorithm, RateLimitResult, RateLimitStore, RateLimiter } from "./rateLimit.js";
import { detectServerClientAsync } from "./scoring.js";
import { getTlsClientHello } from "./tlsClientHello.js";
import type { TlsClientHello } from "./tlsClientHello.js";
import { canonicalizeRequestPath, createTripwire } from "./tripwire.js";
import type { Tripwire, TripwireMatchKind, TripwireOptions } from "./tripwire.js";
import type {
  CrawlerVerificationStatus,
  ServerClientContext,
  ServerClientResult,
  ServerDetectorOptions,
} from "./types.js";

export type ProtectionMode = "monitor" | "enforce";
export type ProtectionConclusion = "ALLOW" | "DENY" | "THROTTLE" | "ERROR";
export type ProtectionRuleState = "RUN" | "DRY_RUN" | "NOT_RUN";
export type ProtectionRuleAction = "ALLOW" | "DENY" | "THROTTLE";
export type PathPattern = string | RegExp;

export interface ProtectionRuleOutcome {
  rule: string;
  state: ProtectionRuleState;
  action: ProtectionRuleAction;
  reason?: string;
  metadata?: Record<string, unknown>;
}

export interface TripwireProtectionOptions extends TripwireOptions {
  dryRun?: boolean;
  status?: number;
  lockoutMs?: number;
  memoryMs?: number;
}

export interface HoneytokenProtectionOptions extends HoneytokenOptions {
  dryRun?: boolean;
}

export interface AttackSignatureProtectionOptions extends AttackSignatureOptions {
  dryRun?: boolean;
}

export interface BotPolicyProtectionOptions extends BotPolicyOptions {
  dryRun?: boolean;
}

export interface NormalizedProtectionRequest {
  method: string;
  path: string;
  rawPath: string;
  paths: readonly string[];
  query?: string;
  headers: HeaderBag;
  ip?: string;
  userAgent?: string;
  body?: string;
}

export interface RateLimitRuleOptions {
  name?: string;
  max: number;
  windowMs: number;
  algorithm?: RateLimitAlgorithm;
  store?: RateLimitStore;
  paths?: readonly PathPattern[];
  methods?: readonly string[];
  key?: (request: NormalizedProtectionRequest) => string | undefined;
  dryRun?: boolean;
}

export interface DetectionProtectionOptions extends ServerDetectorOptions {
  dryRun?: boolean;
}

export interface TrustedHeaderOptions {
  ja4?: string;
  ja3?: string;
  crawlerVerification?: string;
}

export interface BotProtectionOptions {
  mode?: ProtectionMode;
  trustProxy?: TrustProxy;
  trustedHeaders?: TrustedHeaderOptions;
  skipPaths?: readonly PathPattern[];
  allowIps?: readonly string[];
  tripwire?: boolean | TripwireProtectionOptions;
  honeytoken?: boolean | HoneytokenProtectionOptions;
  attackSignatures?: boolean | AttackSignatureProtectionOptions;
  bots?: false | BotPolicyProtectionOptions;
  rateLimit?: false | RateLimitRuleOptions | readonly RateLimitRuleOptions[];
  detection?: boolean | DetectionProtectionOptions;
  testUserAgentPrefix?: string | false;
  maxTrackedTraps?: number;
}

export interface ProtectionRequest {
  method?: string;
  url?: string;
  path?: string;
  query?: string;
  headers?: HeaderBag;
  ip?: string;
  peer?: string;
  body?: string;
  tlsClientHello?: TlsClientHello;
  context?: Partial<ServerClientContext>;
}

export interface TrapRecord {
  ip: string;
  path: string;
  honeytoken: boolean;
  firstAt: number;
  lastAt: number;
  hits: number;
}

export interface ProtectionTrapHit {
  path: string;
  honeytoken: boolean;
  matchedBy: TripwireMatchKind | "honeytoken";
  exempt: boolean;
  exemptReason?: string;
}

export interface ProtectionDecision {
  id: string;
  mode: ProtectionMode;
  conclusion: ProtectionConclusion;
  allowed: boolean;
  blocked: boolean;
  skipped: boolean;
  rule?: string;
  reason?: string;
  status: number;
  headers: Record<string, string>;
  body?: Record<string, unknown>;
  results: ProtectionRuleOutcome[];
  method: string;
  path: string;
  clientIp?: string;
  bot: BotVerdict;
  trapHit?: ProtectionTrapHit;
  trap?: TrapRecord;
  attack?: AttackSignatureMatch;
  rateLimit?: RateLimitResult;
  server?: ServerClientResult;
  error?: string;
}

export interface HandledProtectionDecision extends ProtectionDecision {
  responded: boolean;
}

export interface ProtectionHandleOptions {
  injectHoneytoken?: boolean;
  serveRobotsTxt?: boolean;
  robotsTxt?: RobotsTxtProtectionOptions;
  onBlocked?: (decision: ProtectionDecision, req: IncomingMessage, res: ServerResponse) => void;
}

export interface ProtectionMiddlewareOptions extends ProtectionHandleOptions {
  property?: string;
  onError?: (error: unknown, req: IncomingMessage) => void;
}

export interface RobotsTxtProtectionOptions {
  disallow?: readonly string[];
  sitemap?: string;
  crawlDelay?: number;
  annotate?: boolean;
}

export type ProtectionMiddleware = (
  req: IncomingMessage,
  res: ServerResponse,
  next?: (error?: unknown) => void,
) => Promise<void>;

export interface BotProtection {
  readonly mode: ProtectionMode;
  readonly honeytoken?: Honeytoken;
  readonly botPolicy?: BotPolicy;
  protect(request: ProtectionRequest): Promise<ProtectionDecision>;
  handle(
    req: IncomingMessage,
    res: ServerResponse,
    options?: ProtectionHandleOptions,
  ): Promise<HandledProtectionDecision>;
  middleware(options?: ProtectionMiddlewareOptions): ProtectionMiddleware;
  robotsTxt(options?: RobotsTxtProtectionOptions): string;
  getTrap(ip: string): TrapRecord | undefined;
  clearTraps(): void;
  destroy(): Promise<void>;
}

interface RuleEvaluation {
  outcome: ProtectionRuleOutcome;
  status?: number;
  headers?: Record<string, string>;
  body?: Record<string, unknown>;
}

interface PreparedRateLimit {
  name: string;
  limiter: RateLimiter;
  options: RateLimitRuleOptions;
}

const DEFAULT_TEST_PREFIX = "BotSignal-Test/";
const DEFAULT_TRAP_MEMORY_MS = 60 * 60_000;
const DEFAULT_MAX_TRAPS = 10_000;
const CRAWLER_STATUSES: ReadonlySet<string> = new Set(["verified", "spoofed", "unverified"]);
const ATTRIBUTABLE_FETCH_SITES: ReadonlySet<string> = new Set(["same-origin", "none"]);
const ATTRIBUTABLE_FETCH_DESTS: ReadonlySet<string> = new Set(["document", "empty"]);
const ABSOLUTE_FORM_TARGET = /^[a-z][a-z0-9+.-]*:\/\/[^/?#]*/i;

function optionObject<T extends object>(value: boolean | T | undefined): T | null {
  if (value === false) {
    return null;
  }
  return value === undefined || value === true ? ({} as T) : value;
}

function compilePatterns(patterns: readonly PathPattern[] | undefined): PathPattern[] {
  return (patterns ?? []).map((pattern) =>
    typeof pattern === "string"
      ? pattern
      : new RegExp(pattern.source, pattern.flags.replace(/[gy]/g, "")),
  );
}

export function matchesPathPattern(
  path: string,
  patterns: readonly PathPattern[],
  ignoreCase = false,
): boolean {
  const subject = ignoreCase ? path.toLowerCase() : path;
  return patterns.some((pattern) => {
    if (typeof pattern !== "string") {
      return pattern.test(path);
    }
    const expected = ignoreCase ? pattern.toLowerCase() : pattern;
    return (
      subject === expected ||
      subject.startsWith(expected.endsWith("/") ? expected : `${expected}/`)
    );
  });
}

function lowercaseHeaders(headers: HeaderBag | undefined): HeaderBag {
  const output: HeaderBag = {};
  for (const [name, value] of Object.entries(headers ?? {})) {
    output[name.toLowerCase()] = value;
  }
  return output;
}

function splitTarget(request: ProtectionRequest): { rawPath: string; query?: string } {
  if (request.path !== undefined) {
    return { rawPath: request.path || "/", query: request.query };
  }
  const target = (request.url ?? "/").split("#", 1)[0].replace(ABSOLUTE_FORM_TARGET, "");
  const questionMark = target.indexOf("?");
  if (questionMark === -1) {
    return { rawPath: target || "/", query: request.query };
  }
  return {
    rawPath: target.slice(0, questionMark) || "/",
    query: target.slice(questionMark + 1),
  };
}

export function requestPathForms(rawPath: string): string[] {
  const forms = new Set([rawPath, canonicalizeRequestPath(rawPath)]);
  try {
    forms.add(new URL(rawPath, "http://localhost").pathname);
  } catch {
    return [...forms];
  }
  return [...forms];
}

function isAttributableTrapRequest(headers: HeaderBag): boolean {
  const site = readHeader(headers, "sec-fetch-site")?.trim().toLowerCase();
  const dest = readHeader(headers, "sec-fetch-dest")?.trim().toLowerCase();
  const purpose = ["sec-purpose", "purpose", "x-moz"]
    .map((name) => readHeader(headers, name) ?? "")
    .join(" ")
    .toLowerCase();
  return (
    (site === undefined || ATTRIBUTABLE_FETCH_SITES.has(site)) &&
    (dest === undefined || ATTRIBUTABLE_FETCH_DESTS.has(dest)) &&
    !/prefetch|prerender/.test(purpose)
  );
}

function allow(rule: string, extras: Partial<ProtectionRuleOutcome> = {}): RuleEvaluation {
  return { outcome: { rule, state: "RUN", action: "ALLOW", ...extras } };
}

function forbiddenBody(rule: string, id: string): Record<string, unknown> {
  return { error: "Forbidden", rule, id };
}

function bodyForStatus(status: number, rule: string, id: string): Record<string, unknown> {
  return status === 404 ? { error: "Not Found" } : forbiddenBody(rule, id);
}

class TrapStore {
  private readonly records = new Map<string, TrapRecord>();

  constructor(private readonly memoryMs: number, private readonly maxEntries: number) {}

  get(key: string, now: number): TrapRecord | undefined {
    const record = this.records.get(key);
    if (record && now - record.lastAt > this.memoryMs) {
      this.records.delete(key);
      return undefined;
    }
    return record;
  }

  record(key: string, path: string, honeytoken: boolean, now: number): TrapRecord {
    const existing = this.get(key, now);
    if (existing) {
      this.records.delete(key);
      const updated = {
        ...existing,
        path,
        honeytoken: existing.honeytoken || honeytoken,
        lastAt: now,
        hits: existing.hits + 1,
      };
      this.records.set(key, updated);
      return updated;
    }
    while (this.records.size >= this.maxEntries) {
      this.records.delete(this.records.keys().next().value as string);
    }
    const created = { ip: key, path, honeytoken, firstAt: now, lastAt: now, hits: 1 };
    this.records.set(key, created);
    return created;
  }

  clear(): void {
    this.records.clear();
  }
}

function writeJson(res: ServerResponse, status: number, headers: Record<string, string>, body: unknown): void {
  if (res.headersSent) {
    res.end();
    return;
  }
  res.statusCode = status;
  for (const [name, value] of Object.entries(headers)) {
    res.setHeader(name, value);
  }
  res.setHeader("content-type", "application/json; charset=utf-8");
  res.setHeader("cache-control", "no-store");
  res.end(JSON.stringify(body));
}

function validateOptions(options: BotProtectionOptions): void {
  if (options.trustProxy !== undefined && !isValidTrustProxy(options.trustProxy)) {
    throw new TypeError(
      "trustProxy must be false, the number of proxies in front of the app, a list of proxy CIDRs, or { header }",
    );
  }
  const maxTraps = options.maxTrackedTraps;
  if (maxTraps !== undefined && (!Number.isInteger(maxTraps) || maxTraps < 1)) {
    throw new RangeError("maxTrackedTraps must be a positive integer");
  }
}

export function createBotProtection(options: BotProtectionOptions = {}): BotProtection {
  validateOptions(options);
  const mode = options.mode ?? "monitor";
  const trustProxy = options.trustProxy ?? false;
  const trustedHeaders = options.trustedHeaders ?? {};
  const skipPaths = compilePatterns(options.skipPaths);
  const allowIps = [...(options.allowIps ?? [])];
  const testPrefix =
    options.testUserAgentPrefix === false
      ? null
      : (options.testUserAgentPrefix ?? DEFAULT_TEST_PREFIX).toLowerCase();

  const tripwireOptions = optionObject(options.tripwire);
  const tripwire: Tripwire | null = tripwireOptions ? createTripwire(tripwireOptions) : null;
  const tripwireStatus = tripwireOptions?.status ?? 404;
  const lockoutMs = tripwireOptions?.lockoutMs ?? 0;
  const traps = new TrapStore(
    tripwireOptions?.memoryMs ?? Math.max(lockoutMs, DEFAULT_TRAP_MEMORY_MS),
    options.maxTrackedTraps ?? DEFAULT_MAX_TRAPS,
  );

  const honeytokenOptions = optionObject(options.honeytoken);
  const honeytoken = honeytokenOptions ? createHoneytoken(honeytokenOptions) : undefined;

  const attackOptions = optionObject(options.attackSignatures);
  const attackDryRun = attackOptions?.dryRun ?? true;
  const botOptions = options.bots ? options.bots : null;
  const botPolicy = botOptions ? createBotPolicy(botOptions) : undefined;

  const detectionOptions = options.detection === undefined ? null : optionObject(options.detection);
  const detectionDryRun = detectionOptions?.dryRun ?? true;

  const rateLimitList = options.rateLimit
    ? Array.isArray(options.rateLimit)
      ? (options.rateLimit as readonly RateLimitRuleOptions[])
      : [options.rateLimit as RateLimitRuleOptions]
    : [];
  const rateLimits: PreparedRateLimit[] = rateLimitList.map((limit, index) => ({
    name: limit.name ?? (rateLimitList.length === 1 ? "rate-limit" : `rate-limit-${index + 1}`),
    limiter: createRateLimiter({
      max: limit.max,
      windowMs: limit.windowMs,
      algorithm: limit.algorithm,
      store: limit.store,
    }),
    options: { ...limit, paths: compilePatterns(limit.paths) },
  }));

  function crawlerStatus(request: ProtectionRequest, headers: HeaderBag): CrawlerVerificationStatus | undefined {
    const fromContext = request.context?.crawlerVerificationStatus;
    if (fromContext) {
      return fromContext;
    }
    const header = trustedHeaders.crawlerVerification
      ? readHeader(headers, trustedHeaders.crawlerVerification)?.trim()
      : undefined;
    return header && CRAWLER_STATUSES.has(header) ? (header as CrawlerVerificationStatus) : undefined;
  }

  function trapHit(
    path: string,
    honeytokenHit: boolean,
    matchedBy: ProtectionTrapHit["matchedBy"],
    verification: CrawlerVerificationStatus | undefined,
    headers: HeaderBag,
  ): ProtectionTrapHit {
    const exemptReason =
      verification === "verified"
        ? "a crawler the edge verified"
        : isAttributableTrapRequest(headers)
          ? undefined
          : "a cross-site, embedded or speculative request";
    return {
      path,
      honeytoken: honeytokenHit,
      matchedBy,
      exempt: exemptReason !== undefined,
      ...(exemptReason ? { exemptReason } : {}),
    };
  }

  function evaluateTrap(
    rule: "honeytoken" | "tripwire",
    hit: ProtectionTrapHit,
    dryRun: boolean,
    id: string,
    ip: string | undefined,
    now: number,
    state: { trap?: TrapRecord },
  ): RuleEvaluation {
    if (!hit.exempt && !dryRun && ip) {
      state.trap = traps.record(clientNetworkKey(ip), hit.path, hit.honeytoken, now);
    }
    const subject = rule === "honeytoken" ? "Hidden honeytoken link" : "Scanner bait path";
    const reason = hit.exempt
      ? `${subject} ${hit.path} requested by ${hit.exemptReason}; not attributed`
      : rule === "honeytoken"
        ? `${subject} ${hit.path} was followed — only link-harvesting automation finds it`
        : `${subject} ${hit.path} was requested — no page links to it`;
    return {
      outcome: {
        rule,
        state: hit.exempt || dryRun ? "DRY_RUN" : "RUN",
        action: "DENY",
        reason,
        metadata: { path: hit.path, matchedBy: hit.matchedBy, exempt: hit.exempt },
      },
      status: tripwireStatus,
      body: bodyForStatus(tripwireStatus, rule, id),
    };
  }

  async function evaluateRateLimit(
    limit: PreparedRateLimit,
    request: NormalizedProtectionRequest,
  ): Promise<{ evaluation: RuleEvaluation; result?: RateLimitResult } | null> {
    const { options: limitOptions, name } = limit;
    if (
      limitOptions.paths &&
      limitOptions.paths.length > 0 &&
      !request.paths.some((form) => matchesPathPattern(form, limitOptions.paths as PathPattern[], true))
    ) {
      return null;
    }
    if (limitOptions.methods && !limitOptions.methods.some((method) => method.toUpperCase() === request.method)) {
      return null;
    }
    const key = limitOptions.key
      ? limitOptions.key(request)
      : request.ip
        ? clientNetworkKey(request.ip)
        : undefined;
    if (!key) {
      return {
        evaluation: {
          outcome: { rule: name, state: "NOT_RUN", action: "ALLOW", reason: "No client identity to key the limit on" },
        },
      };
    }
    let result: RateLimitResult;
    try {
      result = await limit.limiter.consume(`${name}:${key}`);
    } catch (error) {
      return {
        evaluation: {
          outcome: {
            rule: name,
            state: "NOT_RUN",
            action: "ALLOW",
            reason: `Rate-limit store failed: ${error instanceof Error ? error.message : String(error)}`,
          },
        },
      };
    }
    const metadata = { limit: result.limit, remaining: result.remaining, count: result.count, resetAt: result.resetAt };
    if (result.allowed) {
      return { evaluation: allow(name, { metadata }), result };
    }
    return {
      result,
      evaluation: {
        outcome: {
          rule: name,
          state: limitOptions.dryRun ? "DRY_RUN" : "RUN",
          action: "THROTTLE",
          reason: `Rate limit exceeded: ${result.limit} requests per ${Math.round(limit.limiter.windowMs / 1000)}s`,
          metadata: { ...metadata, retryAfterSeconds: result.retryAfterSeconds },
        },
        status: 429,
        headers: rateLimitHeaders(result),
        body: { error: "Too Many Requests", retryAfter: result.retryAfterSeconds },
      },
    };
  }

  async function protect(request: ProtectionRequest): Promise<ProtectionDecision> {
    const id = randomUUID();
    const method = (request.method ?? "GET").toUpperCase();
    const { rawPath, query } = splitTarget(request);
    let path = rawPath;
    let bot: BotVerdict = classifyBotUserAgent(undefined);
    let clientIp: string | undefined;

    try {
      path = canonicalizeRequestPath(rawPath);
      const paths = requestPathForms(rawPath);
      const headers = lowercaseHeaders(request.headers);
      const userAgent = readHeader(headers, "user-agent");
      bot = classifyBotUserAgent(userAgent);
      clientIp =
        normalizeIp(request.ip) ??
        resolveClientIp({ headers, peer: request.peer, trustProxy });
      const ip = clientIp;
      const now = Date.now();
      const base = { id, mode, method, path, clientIp: ip, bot };

      if (skipPaths.length > 0 && paths.every((form) => matchesPathPattern(form, skipPaths))) {
        return finalize(base, [], { skipped: true });
      }
      if (ip && allowIps.some((range) => isIpInCidr(ip, range))) {
        return finalize(base, [allow("allowlist", { reason: `${ip} is on the allow list` })], {});
      }

      const normalized: NormalizedProtectionRequest = {
        method,
        path,
        rawPath,
        paths,
        query,
        headers,
        ip,
        userAgent,
        body: request.body,
      };
      const verification = crawlerStatus(request, headers);
      const state: { trap?: TrapRecord } = { trap: ip ? traps.get(clientNetworkKey(ip), now) : undefined };
      const priorTrap = state.trap;
      const evaluations: RuleEvaluation[] = [];
      const extras: Partial<ProtectionDecision> = {};

      if (testPrefix) {
        evaluations.push(
          userAgent?.trimStart().toLowerCase().startsWith(testPrefix)
            ? {
                outcome: {
                  rule: "test-trigger",
                  state: "RUN",
                  action: "DENY",
                  reason: "Installation probe User-Agent",
                },
                status: 403,
                body: forbiddenBody("test-trigger", id),
              }
            : allow("test-trigger"),
        );
      }

      if (honeytoken) {
        const activePaths = honeytoken.current().activePaths.map((candidate) => candidate.toLowerCase());
        const matched = paths
          .map((form) => canonicalizeRequestPath(form))
          .find((form) => activePaths.includes(form.toLowerCase()));
        if (matched) {
          const hit = trapHit(matched, true, "honeytoken", verification, headers);
          extras.trapHit = hit;
          evaluations.push(
            evaluateTrap("honeytoken", hit, honeytokenOptions?.dryRun ?? false, id, ip, now, state),
          );
        } else {
          evaluations.push(allow("honeytoken"));
        }
      }

      if (tripwire) {
        const match = paths.map((form) => tripwire.match(form)).find((candidate) => candidate !== null);
        if (match) {
          const hit = trapHit(match.path, false, match.matchedBy, verification, headers);
          extras.trapHit = extras.trapHit ?? hit;
          evaluations.push(
            evaluateTrap("tripwire", hit, tripwireOptions?.dryRun ?? false, id, ip, now, state),
          );
        } else {
          evaluations.push(allow("tripwire"));
        }

        if (lockoutMs > 0) {
          evaluations.push(
            priorTrap && now - priorTrap.lastAt <= lockoutMs
              ? {
                  outcome: {
                    rule: "trap-lockout",
                    state: tripwireOptions?.dryRun ? "DRY_RUN" : "RUN",
                    action: "DENY",
                    reason: `${priorTrap.ip} requested trap path ${priorTrap.path} ${Math.round((now - priorTrap.lastAt) / 1000)}s ago`,
                    metadata: { trapPath: priorTrap.path, hits: priorTrap.hits },
                  },
                  status: 403,
                  body: forbiddenBody("trap-lockout", id),
                }
              : allow("trap-lockout"),
          );
        }
      }

      if (attackOptions) {
        const match = findAttackSignature(
          { path: rawPath, query, body: request.body, headers },
          attackOptions,
        );
        extras.attack = match ?? undefined;
        evaluations.push(
          match
            ? {
                outcome: {
                  rule: "attack-signatures",
                  state: attackDryRun ? "DRY_RUN" : "RUN",
                  action: "DENY",
                  reason: `${match.label} in request ${match.where}`,
                  metadata: { signature: match.id, where: match.where },
                },
                status: 403,
                body: forbiddenBody("attack-signatures", id),
              }
            : allow("attack-signatures"),
        );
      }

      if (botPolicy) {
        evaluations.push(
          botPolicy.denies(bot)
            ? {
                outcome: {
                  rule: "bots",
                  state: botOptions?.dryRun ? "DRY_RUN" : "RUN",
                  action: "DENY",
                  reason: `${bot.name} (${bot.category}) is denied by the bot policy`,
                  metadata: { bot: bot.id, category: bot.category },
                },
                status: 403,
                body: forbiddenBody("bots", id),
              }
            : allow("bots"),
        );
      }

      for (const limit of rateLimits) {
        const evaluated = await evaluateRateLimit(limit, normalized);
        if (!evaluated) {
          continue;
        }
        evaluations.push(evaluated.evaluation);
        if (
          evaluated.result &&
          !limit.options.dryRun &&
          (!extras.rateLimit || evaluated.result.remaining < extras.rateLimit.remaining || !evaluated.result.allowed)
        ) {
          extras.rateLimit = evaluated.result;
        }
      }

      if (detectionOptions) {
        const ja4 = trustedHeaders.ja4 ? readHeader(headers, trustedHeaders.ja4)?.trim() : undefined;
        const ja3 = trustedHeaders.ja3 ? readHeader(headers, trustedHeaders.ja3)?.trim() : undefined;
        const server = await detectServerClientAsync(
          {
            clientIp: isPublicIp(ip) ? ip : undefined,
            userAgent,
            acceptLanguage: readHeader(headers, "accept-language"),
            secChUa: readHeader(headers, "sec-ch-ua"),
            secChUaPlatform: readHeader(headers, "sec-ch-ua-platform"),
            secChUaMobile: readHeader(headers, "sec-ch-ua-mobile"),
            secFetchSite: readHeader(headers, "sec-fetch-site"),
            secFetchMode: readHeader(headers, "sec-fetch-mode"),
            secFetchDest: readHeader(headers, "sec-fetch-dest"),
            ...(ja4 || ja3 ? { tlsFingerprint: ja4 || ja3, tlsFingerprintType: ja4 ? "ja4" : "ja3" } : {}),
            tlsClientHello: request.tlsClientHello,
            crawlerVerificationStatus: verification,
            ...request.context,
          },
          detectionOptions,
        );
        extras.server = server;
        const triggered = server.signals.filter((signal) => signal.triggered).map((signal) => signal.id);
        evaluations.push(
          server.isLegitClient
            ? allow("detection", { metadata: { score: server.suspicionScore, signals: triggered } })
            : {
                outcome: {
                  rule: "detection",
                  state: detectionDryRun ? "DRY_RUN" : "RUN",
                  action: "DENY",
                  reason: `Server signals scored ${server.suspicionScore.toFixed(2)}: ${triggered.join(", ")}`,
                  metadata: { score: server.suspicionScore, signals: triggered },
                },
                status: 403,
                body: forbiddenBody("detection", id),
              },
        );
      }

      extras.trap = state.trap;
      return finalize(base, evaluations, extras);
    } catch (error) {
      return {
        id,
        mode,
        conclusion: "ERROR",
        allowed: true,
        blocked: false,
        skipped: false,
        status: 200,
        headers: {},
        results: [],
        method,
        path,
        clientIp,
        bot,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }

  function finalize(
    base: Pick<ProtectionDecision, "id" | "mode" | "method" | "path" | "clientIp" | "bot">,
    evaluations: RuleEvaluation[],
    extras: Partial<ProtectionDecision>,
  ): ProtectionDecision {
    const deciding = evaluations.find(
      (evaluation) => evaluation.outcome.state === "RUN" && evaluation.outcome.action !== "ALLOW",
    );
    const conclusion: ProtectionConclusion = deciding
      ? (deciding.outcome.action as "DENY" | "THROTTLE")
      : "ALLOW";
    const allowed = conclusion === "ALLOW";
    const headers = deciding?.headers ?? (extras.rateLimit ? rateLimitHeaders(extras.rateLimit) : {});

    return {
      ...base,
      ...extras,
      conclusion,
      allowed,
      blocked: mode === "enforce" && !allowed,
      skipped: extras.skipped ?? false,
      rule: deciding?.outcome.rule,
      reason: deciding?.outcome.reason,
      status: deciding?.status ?? 200,
      headers,
      body: deciding?.body,
      results: evaluations.map((evaluation) => evaluation.outcome),
    };
  }

  function robotsTxt(robotsOptions: RobotsTxtProtectionOptions = {}): string {
    return buildRobotsTxt({
      ...robotsOptions,
      policy: botPolicy,
      disallow: [...(honeytoken?.current().activePaths ?? []), ...(robotsOptions.disallow ?? [])],
    });
  }

  async function handle(
    req: IncomingMessage,
    res: ServerResponse,
    handleOptions: ProtectionHandleOptions = {},
  ): Promise<HandledProtectionDecision> {
    const decision = await protect({
      method: req.method,
      url: (req as { originalUrl?: string }).originalUrl ?? req.url,
      headers: req.headers,
      peer: req.socket?.remoteAddress,
      tlsClientHello: getTlsClientHello(req.socket),
    });

    if (decision.blocked) {
      if (handleOptions.onBlocked) {
        handleOptions.onBlocked(decision, req, res);
      } else {
        writeJson(res, decision.status, decision.headers, decision.body);
      }
      return { ...decision, responded: true };
    }

    if (
      handleOptions.serveRobotsTxt &&
      decision.path === "/robots.txt" &&
      (decision.method === "GET" || decision.method === "HEAD")
    ) {
      res.statusCode = 200;
      res.setHeader("content-type", "text/plain; charset=utf-8");
      res.end(decision.method === "HEAD" ? undefined : robotsTxt(handleOptions.robotsTxt));
      return { ...decision, responded: true };
    }

    if (mode === "enforce" && !res.headersSent) {
      for (const [name, value] of Object.entries(decision.headers)) {
        res.setHeader(name, value);
      }
    }
    if (honeytoken && handleOptions.injectHoneytoken !== false && decision.method === "GET") {
      injectHoneytokenIntoResponse(res, honeytoken.current().linkHtml);
    }
    return { ...decision, responded: false };
  }

  function middleware(middlewareOptions: ProtectionMiddlewareOptions = {}): ProtectionMiddleware {
    const property = middlewareOptions.property ?? "botSignal";
    return async (req, res, next) => {
      let decision: HandledProtectionDecision;
      try {
        decision = await handle(req, res, middlewareOptions);
      } catch (error) {
        middlewareOptions.onError?.(error, req);
        next?.();
        return;
      }
      (req as unknown as Record<string, unknown>)[property] = decision;
      if (!decision.responded) {
        next?.();
      }
    };
  }

  return {
    mode,
    honeytoken,
    botPolicy,
    protect,
    handle,
    middleware,
    robotsTxt,
    getTrap: (ip) => {
      const normalized = normalizeIp(ip);
      return normalized ? traps.get(clientNetworkKey(normalized), Date.now()) : undefined;
    },
    clearTraps: () => traps.clear(),
    destroy: async () => {
      traps.clear();
      await Promise.all(rateLimits.map((limit) => limit.limiter.destroy()));
    },
  };
}
