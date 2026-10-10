import RedisMock from "ioredis-mock";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  createRateLimiter,
  fixedWindowResult,
  MemoryRateLimitStore,
  slidingWindowResult,
  tokenBucketResult,
} from "../src/server/rateLimit.js";
import type { RateLimitAlgorithm, RateLimitStore } from "../src/server/rateLimit.js";
import {
  createRedisRateLimitStore,
  createUpstashRateLimitStore,
  FIXED_WINDOW_SCRIPT,
} from "../src/server/rateLimitStores.js";

function clock(start = 1_700_000_000_000) {
  let now = start;
  return {
    now: () => now,
    advance: (ms: number) => {
      now += ms;
    },
  };
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

const redis = new RedisMock();

function redisStore(prefix = "test:"): RateLimitStore {
  return createRedisRateLimitStore({
    prefix,
    evaluate: (script, keys, args) => redis.eval(script, keys.length, ...keys, ...args),
  });
}

beforeEach(async () => {
  await redis.flushall();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("token bucket rate limiting", () => {
  it("allows a burst of max, then refills at max per window", async () => {
    const time = clock();
    const limiter = createRateLimiter({ max: 4, windowMs: 1_000, algorithm: "token-bucket", now: time.now });
    for (let index = 0; index < 4; index += 1) {
      expect((await limiter.consume("k")).allowed).toBe(true);
    }
    const refused = await limiter.consume("k");
    expect(refused).toMatchObject({ allowed: false, remaining: 0, count: 4, retryAfterSeconds: 1 });
    expect(refused.resetAt).toBe(time.now() + 250);

    time.advance(250);
    expect(await limiter.consume("k")).toMatchObject({ allowed: true, remaining: 0, count: 4 });
    time.advance(600);
    const partial = await limiter.consume("k");
    expect(partial).toMatchObject({ allowed: true, remaining: 1 });
    expect(partial.resetAt).toBe(time.now() + Math.ceil(((4 - 1.4) * 1_000) / 4));
  });

  it("caps the bucket at max and ignores a clock that runs backwards", async () => {
    const time = clock();
    const store = new MemoryRateLimitStore();
    const limiter = createRateLimiter({ max: 2, windowMs: 1_000, algorithm: "token-bucket", now: time.now, store });
    await limiter.consume("k");
    time.advance(60_000);
    expect(await limiter.consume("k")).toMatchObject({ allowed: true, remaining: 1 });
    time.advance(-30_000);
    expect(await limiter.consume("k")).toMatchObject({ allowed: true, remaining: 0 });
    expect((await limiter.consume("k")).allowed).toBe(false);
    expect(store.size).toBe(1);
  });
});

describe("shared result helpers", () => {
  it("describe a window the same way for every store", () => {
    expect(fixedWindowResult(3, false, 2_000, 3, 1_500)).toEqual({
      allowed: false,
      limit: 3,
      remaining: 0,
      count: 3,
      resetAt: 2_000,
      retryAfterSeconds: 1,
    });
    expect(slidingWindowResult(0, 1, true, 5, 1_000, 10_500)).toMatchObject({ remaining: 4, count: 1, resetAt: 11_000 });
    expect(tokenBucketResult(0.5, false, 2, 1_000, 0)).toMatchObject({ remaining: 0, count: 2, resetAt: 250 });
  });
});

describe("Redis rate-limit store", () => {
  async function run(algorithm: RateLimitAlgorithm, store: RateLimitStore, steps: number[]) {
    const time = clock(1_700_000_000_000);
    const limiter = createRateLimiter({ max: 3, windowMs: 10_000, algorithm, store, now: time.now });
    const outcomes = [];
    for (const step of steps) {
      time.advance(step);
      outcomes.push(await limiter.consume("client"));
    }
    return outcomes;
  }

  it("matches the in-memory store for sliding windows and token buckets", async () => {
    const steps = [0, 100, 100, 100, 100, 5_000, 4_000, 2_000, 9_000, 100, 30_000];
    for (const algorithm of ["sliding", "token-bucket"] as const) {
      await redis.flushall();
      expect(await run(algorithm, redisStore(), steps), algorithm).toEqual(
        await run(algorithm, new MemoryRateLimitStore(), steps),
      );
    }
  });

  it("anchors a fixed window at the first request and expires it with the key", async () => {
    const limiter = createRateLimiter({ max: 2, windowMs: 80, store: redisStore("fixed:") });
    expect(await limiter.consume("ip")).toMatchObject({ allowed: true, remaining: 1, count: 1 });
    expect(await limiter.consume("ip")).toMatchObject({ allowed: true, remaining: 0, count: 2 });
    const refused = await limiter.consume("ip");
    expect(refused).toMatchObject({ allowed: false, count: 2, retryAfterSeconds: 1 });
    expect(refused.resetAt - Date.now()).toBeLessThanOrEqual(80);
    expect(await redis.keys("fixed:*")).toEqual(["fixed:f:{ip}"]);
    await sleep(120);
    expect(await limiter.consume("ip")).toMatchObject({ allowed: true, count: 1 });
  });

  it("re-arms a fixed window key that lost its expiry", async () => {
    await redis.set("fixed:f:{stuck}", "5");
    const limiter = createRateLimiter({ max: 2, windowMs: 60_000, store: redisStore("fixed:") });
    expect((await limiter.consume("stuck")).allowed).toBe(false);
    expect(await redis.pttl("fixed:f:{stuck}")).toBeGreaterThan(0);
  });

  it("uses the default prefix and hash-tags every key for Redis Cluster", async () => {
    const store = createRedisRateLimitStore({
      evaluate: (script, keys, args) => redis.eval(script, keys.length, ...keys, ...args),
    });
    await createRateLimiter({ max: 1, windowMs: 1_000, algorithm: "sliding", store }).consume("a:b");
    expect((await redis.keys("bot-signal:rl:*"))[0]).toMatch(/^bot-signal:rl:s:\{a:b\}:\d+$/);
  });

  it("refuses replies it does not understand", async () => {
    const reply = vi.fn();
    const store = createRedisRateLimitStore({ evaluate: reply });
    const limiter = createRateLimiter({ max: 1, windowMs: 1_000, store });
    reply.mockResolvedValueOnce("OK");
    await expect(limiter.consume("k")).rejects.toThrow("unexpected reply");
    reply.mockResolvedValueOnce([1]);
    await expect(limiter.consume("k")).rejects.toThrow("unexpected reply");
    reply.mockResolvedValueOnce([1, "many", 10]);
    await expect(limiter.consume("k")).rejects.toThrow("non-numeric");
    reply.mockResolvedValueOnce([1, null, 10]);
    await expect(limiter.consume("k")).rejects.toThrow("non-numeric");
    reply.mockResolvedValueOnce(["1", "1", "900"]);
    expect(await limiter.consume("k")).toMatchObject({ allowed: true, count: 1 });
    expect(() => createRedisRateLimitStore({} as never)).toThrow(TypeError);
  });
});

describe("Upstash rate-limit store", () => {
  function upstash(handler: (body: unknown[], init: RequestInit) => Response | Promise<Response>) {
    const fetch = vi.fn(async (input: string | URL | Request, init?: RequestInit) =>
      handler(JSON.parse(String(init?.body)) as unknown[], init as RequestInit),
    );
    return { fetch, store: createUpstashRateLimitStore({ url: "https://eu1.upstash.example/", token: "t0k", fetch }) };
  }

  it("sends the script as an authenticated EVAL and reads the result", async () => {
    const { fetch, store } = upstash(() => new Response(JSON.stringify({ result: [1, 1, 60_000] })));
    const result = await createRateLimiter({ max: 5, windowMs: 60_000, store }).consume("1.2.3.4");
    expect(result).toMatchObject({ allowed: true, remaining: 4, count: 1 });
    const [url, init] = fetch.mock.calls[0];
    expect(url).toBe("https://eu1.upstash.example");
    expect(init?.method).toBe("POST");
    expect(init?.headers).toEqual({ authorization: "Bearer t0k", "content-type": "application/json" });
    expect(JSON.parse(String(init?.body))).toEqual(["EVAL", FIXED_WINDOW_SCRIPT, "1", "bot-signal:rl:f:{1.2.3.4}", "5", "60000"]);
  });

  it("turns Upstash errors, bad statuses and unreadable bodies into store failures", async () => {
    const replies = [
      new Response(JSON.stringify({ error: "NOSCRIPT" })),
      new Response("upstream down", { status: 502 }),
      new Response("null"),
    ];
    const { store } = upstash(() => replies.shift() as Response);
    const limiter = createRateLimiter({ max: 5, windowMs: 1_000, store });
    await expect(limiter.consume("k")).rejects.toThrow("NOSCRIPT");
    await expect(limiter.consume("k")).rejects.toThrow("502");
    await expect(limiter.consume("k")).rejects.toThrow("Upstash rejected");
  });

  it("aborts a request that outlives its timeout and validates its options", async () => {
    const fetch = vi.fn(
      (_input: string | URL | Request, init?: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => reject(new Error("aborted")));
        }),
    );
    const store = createUpstashRateLimitStore({ url: "https://x.example", token: "t", timeoutMs: 10, fetch });
    await expect(createRateLimiter({ max: 1, windowMs: 1_000, store }).consume("k")).rejects.toThrow("aborted");
    expect(() => createUpstashRateLimitStore({ url: "", token: "t" })).toThrow(TypeError);
    expect(() => createUpstashRateLimitStore({ url: "https://x.example", token: "" })).toThrow(TypeError);
  });

  it("falls back to the global fetch", async () => {
    const fetch = vi.fn(async () => new Response(JSON.stringify({ result: [1, "2.5"] })));
    vi.stubGlobal("fetch", fetch);
    const store = createUpstashRateLimitStore({ url: "https://x.example", token: "t", prefix: "p:" });
    const result = await createRateLimiter({ max: 4, windowMs: 1_000, algorithm: "token-bucket", store }).consume("k");
    expect(result).toMatchObject({ allowed: true, remaining: 2 });
    const [, init] = fetch.mock.calls[0] as unknown as [string, RequestInit];
    expect(JSON.parse(String(init.body))[3]).toBe("p:b:{k}");
  });
});
