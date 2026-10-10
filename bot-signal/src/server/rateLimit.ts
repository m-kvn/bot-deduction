export type RateLimitAlgorithm = "fixed" | "sliding";

export interface RateLimitConsumeRequest {
  key: string;
  max: number;
  windowMs: number;
  algorithm: RateLimitAlgorithm;
  now: number;
}

export interface RateLimitResult {
  allowed: boolean;
  limit: number;
  remaining: number;
  count: number;
  resetAt: number;
  retryAfterSeconds: number;
}

export interface RateLimitStore {
  consume(request: RateLimitConsumeRequest): RateLimitResult | Promise<RateLimitResult>;
  reset?(key: string): void | Promise<void>;
  destroy?(): void | Promise<void>;
}

export interface MemoryRateLimitStoreOptions {
  maxKeys?: number;
}

export interface RateLimiterOptions {
  max: number;
  windowMs: number;
  algorithm?: RateLimitAlgorithm;
  store?: RateLimitStore;
  now?: () => number;
}

export interface RateLimiter {
  readonly max: number;
  readonly windowMs: number;
  readonly algorithm: RateLimitAlgorithm;
  consume(key: string): Promise<RateLimitResult>;
  reset(key: string): Promise<void>;
  destroy(): Promise<void>;
}

interface WindowEntry {
  window: number;
  count: number;
  previous: number;
}

const DEFAULT_MAX_KEYS = 10_000;

function secondsUntil(at: number, now: number): number {
  return Math.max(1, Math.ceil((at - now) / 1000));
}

export class MemoryRateLimitStore implements RateLimitStore {
  private readonly entries = new Map<string, WindowEntry>();
  private readonly maxKeys: number;

  constructor(options: MemoryRateLimitStoreOptions = {}) {
    const maxKeys = options.maxKeys ?? DEFAULT_MAX_KEYS;
    if (!Number.isInteger(maxKeys) || maxKeys < 1) {
      throw new RangeError("maxKeys must be a positive integer");
    }
    this.maxKeys = maxKeys;
  }

  get size(): number {
    return this.entries.size;
  }

  consume(request: RateLimitConsumeRequest): RateLimitResult {
    const entry = this.touch(request);
    return request.algorithm === "sliding"
      ? this.consumeSliding(entry, request)
      : this.consumeFixed(entry, request);
  }

  reset(key: string): void {
    this.entries.delete(key);
  }

  destroy(): void {
    this.entries.clear();
  }

  private touch({ key, windowMs, algorithm, now }: RateLimitConsumeRequest): WindowEntry {
    const existing = this.entries.get(key);
    if (existing) {
      this.entries.delete(key);
      this.entries.set(key, existing);
      return existing;
    }

    while (this.entries.size >= this.maxKeys) {
      this.entries.delete(this.entries.keys().next().value as string);
    }
    const created: WindowEntry = {
      window: algorithm === "sliding" ? Math.floor(now / windowMs) : now,
      count: 0,
      previous: 0,
    };
    this.entries.set(key, created);
    return created;
  }

  private consumeFixed(entry: WindowEntry, request: RateLimitConsumeRequest): RateLimitResult {
    const { max, windowMs, now } = request;
    if (now - entry.window >= windowMs) {
      entry.window = now;
      entry.count = 0;
    }

    const resetAt = entry.window + windowMs;
    const allowed = entry.count < max;
    if (allowed) {
      entry.count += 1;
    }

    return {
      allowed,
      limit: max,
      remaining: Math.max(0, max - entry.count),
      count: entry.count,
      resetAt,
      retryAfterSeconds: allowed ? 0 : secondsUntil(resetAt, now),
    };
  }

  private consumeSliding(entry: WindowEntry, request: RateLimitConsumeRequest): RateLimitResult {
    const { max, windowMs, now } = request;
    const window = Math.floor(now / windowMs);
    if (entry.window !== window) {
      entry.previous = entry.window === window - 1 ? entry.count : 0;
      entry.count = 0;
      entry.window = window;
    }

    const windowStart = window * windowMs;
    const carried = entry.previous * (1 - (now - windowStart) / windowMs);
    const allowed = carried + entry.count + 1 <= max;
    if (allowed) {
      entry.count += 1;
    }

    const used = carried + entry.count;
    const resetAt = allowed
      ? windowStart + windowMs
      : this.slidingRetryAt(entry, max, windowStart, windowMs);

    return {
      allowed,
      limit: max,
      remaining: Math.max(0, Math.floor(max - used)),
      count: Math.ceil(used),
      resetAt,
      retryAfterSeconds: allowed ? 0 : secondsUntil(resetAt, now),
    };
  }

  private slidingRetryAt(
    entry: WindowEntry,
    max: number,
    windowStart: number,
    windowMs: number,
  ): number {
    if (entry.count + 1 <= max) {
      const fraction = 1 - (max - entry.count - 1) / entry.previous;
      return windowStart + Math.ceil(windowMs * fraction);
    }
    const nextStart = windowStart + windowMs;
    const fraction = Math.max(0, 1 - (max - 1) / entry.count);
    return nextStart + Math.ceil(windowMs * fraction);
  }
}

export function createRateLimiter(options: RateLimiterOptions): RateLimiter {
  if (!Number.isInteger(options.max) || options.max < 1) {
    throw new RangeError("max must be a positive integer");
  }
  if (!Number.isFinite(options.windowMs) || options.windowMs <= 0) {
    throw new RangeError("windowMs must be a positive number");
  }
  const algorithm = options.algorithm ?? "fixed";
  const store = options.store ?? new MemoryRateLimitStore();
  const now = options.now ?? Date.now;

  return {
    max: options.max,
    windowMs: options.windowMs,
    algorithm,
    consume: async (key) =>
      store.consume({
        key,
        max: options.max,
        windowMs: options.windowMs,
        algorithm,
        now: now(),
      }),
    reset: async (key) => {
      await store.reset?.(key);
    },
    destroy: async () => {
      await store.destroy?.();
    },
  };
}

export function rateLimitHeaders(result: RateLimitResult, now = Date.now()): Record<string, string> {
  const headers: Record<string, string> = {
    "RateLimit-Limit": String(result.limit),
    "RateLimit-Remaining": String(result.remaining),
    "RateLimit-Reset": String(Math.max(0, Math.ceil((result.resetAt - now) / 1000))),
  };
  if (!result.allowed) {
    headers["Retry-After"] = String(result.retryAfterSeconds);
  }
  return headers;
}
