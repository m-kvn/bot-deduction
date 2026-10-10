import { fixedWindowResult, slidingWindowResult, tokenBucketResult } from "./rateLimit.js";
import type { RateLimitConsumeRequest, RateLimitResult, RateLimitStore } from "./rateLimit.js";

export type RedisScriptRunner = (script: string, keys: string[], args: string[]) => Promise<unknown>;

export interface RedisRateLimitStoreOptions {
  evaluate: RedisScriptRunner;
  prefix?: string;
}

export interface UpstashRateLimitStoreOptions {
  url: string;
  token: string;
  prefix?: string;
  timeoutMs?: number;
  fetch?: typeof fetch;
}

const DEFAULT_PREFIX = "bot-signal:rl:";
const DEFAULT_UPSTASH_TIMEOUT_MS = 1_000;

export const FIXED_WINDOW_SCRIPT = `
local count = tonumber(redis.call('GET', KEYS[1]) or '0')
local ttl = redis.call('PTTL', KEYS[1])
if count < tonumber(ARGV[1]) then
  count = redis.call('INCR', KEYS[1])
  if ttl < 0 then
    redis.call('PEXPIRE', KEYS[1], ARGV[2])
    ttl = tonumber(ARGV[2])
  end
  return {1, count, ttl}
end
if ttl < 0 then
  redis.call('PEXPIRE', KEYS[1], ARGV[2])
  ttl = tonumber(ARGV[2])
end
return {0, count, ttl}
`;

export const SLIDING_WINDOW_SCRIPT = `
local current = tonumber(redis.call('GET', KEYS[1]) or '0')
local previous = tonumber(redis.call('GET', KEYS[2]) or '0')
if previous * tonumber(ARGV[3]) + current + 1 <= tonumber(ARGV[1]) then
  current = redis.call('INCR', KEYS[1])
  redis.call('PEXPIRE', KEYS[1], tonumber(ARGV[2]) * 2)
  return {1, current, previous}
end
return {0, current, previous}
`;

export const TOKEN_BUCKET_SCRIPT = `
local max = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local state = redis.call('HMGET', KEYS[1], 'tokens', 'at')
local tokens = tonumber(state[1]) or max
local at = tonumber(state[2]) or now
tokens = math.min(max, tokens + math.max(0, now - at) * max / window)
local allowed = 0
if tokens >= 1 then
  tokens = tokens - 1
  allowed = 1
end
local exact = string.format('%.17g', tokens)
redis.call('HSET', KEYS[1], 'tokens', exact, 'at', ARGV[3])
redis.call('PEXPIRE', KEYS[1], math.ceil(window * 2))
return {allowed, exact}
`;

function replyArray(reply: unknown): unknown[] {
  if (!Array.isArray(reply) || reply.length < 2) {
    throw new Error("Rate-limit script returned an unexpected reply");
  }
  return reply;
}

function replyNumber(value: unknown): number {
  const number = typeof value === "string" ? Number(value) : value;
  if (typeof number !== "number" || !Number.isFinite(number)) {
    throw new Error("Rate-limit script returned a non-numeric value");
  }
  return number;
}

export function createRedisRateLimitStore(options: RedisRateLimitStoreOptions): RateLimitStore {
  if (typeof options.evaluate !== "function") {
    throw new TypeError("createRedisRateLimitStore needs an evaluate(script, keys, args) function");
  }
  const prefix = options.prefix ?? DEFAULT_PREFIX;
  const evaluate = options.evaluate;

  async function consumeFixed({ key, max, windowMs, now }: RateLimitConsumeRequest): Promise<RateLimitResult> {
    const reply = replyArray(await evaluate(FIXED_WINDOW_SCRIPT, [`${prefix}f:{${key}}`], [String(max), String(Math.ceil(windowMs))]));
    const allowed = replyNumber(reply[0]) === 1;
    return fixedWindowResult(replyNumber(reply[1]), allowed, now + replyNumber(reply[2]), max, now);
  }

  async function consumeSliding({ key, max, windowMs, now }: RateLimitConsumeRequest): Promise<RateLimitResult> {
    const window = Math.floor(now / windowMs);
    const weight = 1 - (now - window * windowMs) / windowMs;
    const reply = replyArray(
      await evaluate(
        SLIDING_WINDOW_SCRIPT,
        [`${prefix}s:{${key}}:${window}`, `${prefix}s:{${key}}:${window - 1}`],
        [String(max), String(Math.ceil(windowMs)), String(weight)],
      ),
    );
    const allowed = replyNumber(reply[0]) === 1;
    return slidingWindowResult(replyNumber(reply[2]), replyNumber(reply[1]), allowed, max, windowMs, now);
  }

  async function consumeBucket({ key, max, windowMs, now }: RateLimitConsumeRequest): Promise<RateLimitResult> {
    const reply = replyArray(
      await evaluate(TOKEN_BUCKET_SCRIPT, [`${prefix}b:{${key}}`], [String(max), String(windowMs), String(now)]),
    );
    const allowed = replyNumber(reply[0]) === 1;
    return tokenBucketResult(replyNumber(reply[1]), allowed, max, windowMs, now);
  }

  return {
    consume(request) {
      if (request.algorithm === "token-bucket") {
        return consumeBucket(request);
      }
      return request.algorithm === "sliding" ? consumeSliding(request) : consumeFixed(request);
    },
  };
}

export function createUpstashRateLimitStore(options: UpstashRateLimitStoreOptions): RateLimitStore {
  if (!options.url || !options.token) {
    throw new TypeError("createUpstashRateLimitStore needs the REST url and token");
  }
  const endpoint = options.url.replace(/\/+$/, "");
  const timeoutMs = options.timeoutMs ?? DEFAULT_UPSTASH_TIMEOUT_MS;
  const fetchImpl = options.fetch ?? ((input: string | URL | Request, init?: RequestInit) => fetch(input, init));

  async function call(command: string[], signal: AbortSignal): Promise<unknown> {
    const response = await fetchImpl(endpoint, {
      method: "POST",
      headers: { authorization: `Bearer ${options.token}`, "content-type": "application/json" },
      body: JSON.stringify(command),
      signal,
    });
    const body = (await response.json().catch(() => null)) as { result?: unknown; error?: unknown } | null;
    if (!response.ok || !body || body.error !== undefined) {
      throw new Error(`Upstash rejected the rate-limit script: ${String(body?.error ?? response.status)}`);
    }
    return body.result;
  }

  return createRedisRateLimitStore({
    prefix: options.prefix,
    evaluate(script, keys, args) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      timer.unref?.();
      return call(["EVAL", script, String(keys.length), ...keys, ...args], controller.signal).finally(() =>
        clearTimeout(timer),
      );
    },
  });
}
