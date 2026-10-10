import { describe, expect, it, vi } from "vitest";
import {
  createRateLimiter,
  MemoryRateLimitStore,
  rateLimitHeaders,
} from "../src/server/index.js";
import type { RateLimitStore } from "../src/server/index.js";

function clock(start = 1_000_000) {
  let now = start;
  return {
    now: () => now,
    advance: (ms: number) => {
      now += ms;
    },
  };
}

describe("fixed window rate limiting", () => {
  it("allows max requests per window and resets after it", async () => {
    const time = clock();
    const limiter = createRateLimiter({ max: 2, windowMs: 1_000, now: time.now });
    expect(limiter.algorithm).toBe("fixed");

    const first = await limiter.consume("a");
    expect(first).toMatchObject({ allowed: true, limit: 2, remaining: 1, count: 1, retryAfterSeconds: 0 });
    expect(first.resetAt).toBe(1_001_000);
    expect((await limiter.consume("a")).remaining).toBe(0);

    time.advance(400);
    const refused = await limiter.consume("a");
    expect(refused).toMatchObject({ allowed: false, remaining: 0, count: 2, retryAfterSeconds: 1 });
    expect((await limiter.consume("b")).allowed).toBe(true);

    time.advance(600);
    expect((await limiter.consume("a")).allowed).toBe(true);
  });

  it("does not count refused requests against the next window", async () => {
    const time = clock();
    const limiter = createRateLimiter({ max: 1, windowMs: 10_000, now: time.now });
    await limiter.consume("k");
    for (let index = 0; index < 5; index += 1) {
      expect((await limiter.consume("k")).allowed).toBe(false);
    }
    time.advance(10_000);
    expect((await limiter.consume("k")).allowed).toBe(true);
  });

  it("validates its configuration", () => {
    expect(() => createRateLimiter({ max: 0, windowMs: 1_000 })).toThrow(RangeError);
    expect(() => createRateLimiter({ max: 1.5, windowMs: 1_000 })).toThrow(RangeError);
    expect(() => createRateLimiter({ max: 1, windowMs: 0 })).toThrow(RangeError);
    expect(() => createRateLimiter({ max: 1, windowMs: Number.NaN })).toThrow(RangeError);
  });
});

describe("sliding window rate limiting", () => {
  it("weights the previous window by how much of it still overlaps", async () => {
    const time = clock(0);
    const limiter = createRateLimiter({ max: 10, windowMs: 1_000, algorithm: "sliding", now: time.now });
    for (let index = 0; index < 10; index += 1) {
      expect((await limiter.consume("k")).allowed).toBe(true);
    }
    const full = await limiter.consume("k");
    expect(full).toMatchObject({ allowed: false, remaining: 0, count: 10 });
    expect(full.resetAt).toBe(1_100);

    time.advance(1_500);
    const halfway = await limiter.consume("k");
    expect(halfway).toMatchObject({ allowed: true, count: 6, remaining: 4 });
    for (let index = 0; index < 4; index += 1) {
      await limiter.consume("k");
    }
    const carried = await limiter.consume("k");
    expect(carried.allowed).toBe(false);
    expect(carried.resetAt).toBeGreaterThan(1_500);
    expect(carried.resetAt).toBeLessThanOrEqual(2_000);
    expect(carried.retryAfterSeconds).toBeGreaterThanOrEqual(1);
  });

  it("forgets a window that is more than one window old", async () => {
    const time = clock(0);
    const limiter = createRateLimiter({ max: 1, windowMs: 1_000, algorithm: "sliding", now: time.now });
    await limiter.consume("k");
    time.advance(5_000);
    expect(await limiter.consume("k")).toMatchObject({ allowed: true, count: 1 });
  });

  it("waits into the next window when the current one is already full", async () => {
    const time = clock(0);
    const limiter = createRateLimiter({ max: 1, windowMs: 1_000, algorithm: "sliding", now: time.now });
    await limiter.consume("k");
    const refused = await limiter.consume("k");
    expect(refused.resetAt).toBe(2_000);
    time.advance(1_999);
    expect((await limiter.consume("k")).allowed).toBe(false);
    time.advance(1);
    expect((await limiter.consume("k")).allowed).toBe(true);
  });
});

describe("memory store", () => {
  it("evicts the least recently used key past its bound", () => {
    const store = new MemoryRateLimitStore({ maxKeys: 2 });
    const request = (key: string) => ({ key, max: 1, windowMs: 60_000, algorithm: "fixed" as const, now: 0 });
    store.consume(request("a"));
    store.consume(request("b"));
    expect(store.consume(request("a")).allowed).toBe(false);
    store.consume(request("c"));
    expect(store.size).toBe(2);
    expect(store.consume(request("b")).allowed).toBe(true);
    expect(store.consume(request("a")).allowed).toBe(true);
    store.reset("a");
    expect(store.consume(request("a")).allowed).toBe(true);
    store.destroy();
    expect(store.size).toBe(0);
    expect(() => new MemoryRateLimitStore({ maxKeys: 0 })).toThrow(RangeError);
    expect(() => new MemoryRateLimitStore({ maxKeys: Number.NaN })).toThrow(RangeError);
  });

  it("is used by default and can be swapped for a shared async store", async () => {
    const consume = vi.fn(async () => ({
      allowed: true,
      limit: 5,
      remaining: 4,
      count: 1,
      resetAt: 10,
      retryAfterSeconds: 0,
    }));
    const destroy = vi.fn();
    const reset = vi.fn();
    const store: RateLimitStore = { consume, destroy, reset };
    const limiter = createRateLimiter({ max: 5, windowMs: 1_000, store, now: () => 7 });
    await limiter.consume("ip");
    expect(consume).toHaveBeenCalledWith({ key: "ip", max: 5, windowMs: 1_000, algorithm: "fixed", now: 7 });
    await limiter.reset("ip");
    await limiter.destroy();
    expect(reset).toHaveBeenCalledWith("ip");
    expect(destroy).toHaveBeenCalled();

    const minimal = createRateLimiter({ max: 1, windowMs: 1_000, store: { consume } });
    await expect(minimal.reset("ip")).resolves.toBeUndefined();
    await expect(minimal.destroy()).resolves.toBeUndefined();

    const fallback = createRateLimiter({ max: 1, windowMs: 1_000 });
    await fallback.consume("x");
    await fallback.reset("x");
    expect((await fallback.consume("x")).allowed).toBe(true);
    await fallback.destroy();
  });
});

describe("rate limit headers", () => {
  it("advertises the budget and adds Retry-After only when refused", () => {
    const allowed = { allowed: true, limit: 10, remaining: 3, count: 7, resetAt: 31_000, retryAfterSeconds: 0 };
    expect(rateLimitHeaders(allowed, 1_000)).toEqual({
      "RateLimit-Limit": "10",
      "RateLimit-Remaining": "3",
      "RateLimit-Reset": "30",
    });
    expect(rateLimitHeaders({ ...allowed, allowed: false, remaining: 0, retryAfterSeconds: 30 }, 40_000)).toEqual({
      "RateLimit-Limit": "10",
      "RateLimit-Remaining": "0",
      "RateLimit-Reset": "0",
      "Retry-After": "30",
    });
    expect(rateLimitHeaders(allowed)["RateLimit-Limit"]).toBe("10");
  });
});
