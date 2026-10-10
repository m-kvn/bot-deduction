import { afterEach, describe, expect, it, vi } from "vitest";
import { ed25519Key, rsaKey, signRequest } from "./helpers/webBotAuth.js";
import type { SignOptions } from "./helpers/webBotAuth.js";
import { parseDictionary } from "../src/server/structuredFields.js";
import {
  createAgentVerifier,
  DEFAULT_SIGNED_AGENT_DIRECTORIES,
  jwkThumbprint,
} from "../src/server/webBotAuth.js";

function directoryResponse(keys: unknown[], ok = true): Response {
  return new Response(JSON.stringify({ keys }), { status: ok ? 200 : 503 });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("structured field dictionaries", () => {
  it("parses inner lists, parameters, byte sequences and every bare item type", () => {
    const [list, bytes, flag, number, token, text, valueless, tail] = parseDictionary(
      'sig1=("@authority" "signature-agent";key="a1");created=1700000000;keyid="k";tag=web-bot-auth, ' +
        'raw=:aGVsbG8=:, on=?1;off=?0, n=-12.5, t=foo/bar*, s="say \\"hi\\" \\\\ there", flagged;level=3,\tlast',
    );
    expect(list).toMatchObject({ key: "sig1", isList: true });
    expect(list.raw).toBe('("@authority" "signature-agent";key="a1");created=1700000000;keyid="k";tag=web-bot-auth');
    expect(list.items.map((item) => item.value)).toEqual(["@authority", "signature-agent"]);
    expect(list.items[1].params.get("key")).toBe("a1");
    expect(list.params.get("created")).toBe(1700000000);
    expect(list.params.get("tag")).toBe("web-bot-auth");
    expect(bytes.items[0].bytes?.toString()).toBe("hello");
    expect(flag.items[0].value).toBe(true);
    expect(flag.params.get("off")).toBe(false);
    expect(number.items[0].value).toBe(-12.5);
    expect(token.items[0].value).toBe("foo/bar*");
    expect(text.items[0].value).toBe('say "hi" \\ there');
    expect(valueless).toMatchObject({ key: "flagged", raw: "?1", isList: false });
    expect(valueless.params.get("level")).toBe(3);
    expect(tail.key).toBe("last");
    expect(parseDictionary("  ")).toEqual([]);
    expect(parseDictionary("empty=( )")[0].items).toEqual([]);
  });

  it("rejects malformed input instead of guessing", () => {
    for (const input of [
      "Bad=1",
      'a="unterminated',
      'a="bad \\x escape"',
      'a="tab\there"',
      "a=:aGVsbG8=",
      "a=:not*base64:",
      "a=?2",
      "a=@",
      'a=("x"',
      'a=("x""y")',
      'a=("x" ',
      "a=1 b=2",
      "a=1,",
      "a=1;",
    ]) {
      expect(() => parseDictionary(input), input).toThrow(SyntaxError);
    }
  });
});

describe("JWK thumbprints", () => {
  it("matches the RFC 8037 Ed25519 vector and covers RSA keys", () => {
    expect(
      jwkThumbprint({ kty: "OKP", crv: "Ed25519", x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo" }),
    ).toBe("kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k");
    expect(jwkThumbprint({ kty: "RSA", n: "AQAB", e: "AQAB" })).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(jwkThumbprint({ kty: "EC", crv: "P-256" })).toBeUndefined();
    expect(jwkThumbprint({ kty: "OKP", crv: "Ed25519" })).toBeUndefined();
    expect(jwkThumbprint({ kty: "RSA", n: "AQAB" })).toBeUndefined();
  });
});

describe("createAgentVerifier", () => {
  const url = "https://shop.example/products?page=2";

  it("treats requests without a signature as ordinary traffic and never fetches for them", () => {
    const fetch = vi.fn();
    const verifier = createAgentVerifier({ directories: DEFAULT_SIGNED_AGENT_DIRECTORIES, fetch });
    expect(verifier.verify({ url, headers: { "user-agent": "Mozilla/5.0" } })).toEqual({ status: "none" });
    expect(fetch).not.toHaveBeenCalled();
    expect(DEFAULT_SIGNED_AGENT_DIRECTORIES.map((entry) => entry.directory)).toEqual([
      "https://chatgpt.com",
      "https://agent.bot.goog",
    ]);
  });

  it("verifies Ed25519 and RSA-PSS signatures against pinned keys", () => {
    const ed = ed25519Key();
    const rsa = rsaKey();
    const verifier = createAgentVerifier({
      keys: [
        { name: "Test Agent", category: "ai_agent", jwk: ed.jwk },
        { name: "RSA Agent", category: "monitoring", jwk: rsa.jwk },
      ],
    });
    expect(verifier.keyCount).toBe(2);
    expect(verifier.refreshedAt).toBeUndefined();
    expect(verifier.verify({ url, headers: signRequest({ key: ed, url }) })).toEqual({
      status: "verified",
      keyId: ed.keyId,
      agentName: "Test Agent",
      category: "ai_agent",
      algorithm: "ed25519",
    });
    expect(verifier.verify({ url, headers: signRequest({ key: rsa, url, rsa: true, alg: "rsa-pss-sha512" }) })).toMatchObject({
      status: "verified",
      agentName: "RSA Agent",
      algorithm: "rsa-pss-sha512",
    });
  });

  it("rebuilds every supported component, including dictionary members of Signature-Agent", () => {
    const ed = ed25519Key();
    const verifier = createAgentVerifier({ keys: [{ name: "Agent", category: "ai_agent", jwk: ed.jwk }] });
    const target = "http://Shop.Example:8080/a%20b?q=1";
    const headers = signRequest({
      key: ed,
      url: target,
      method: "POST",
      components: ["@method", "@authority", "@scheme", "@path", "@query", "@target-uri", "signature-agent", 'signature-agent;key="a1"', "x-extra"],
      headers: { "signature-agent": 'a1="https://agent.example", a2="https://other.example"', "x-extra": "value" },
    });
    expect(verifier.verify({ method: "post", url: target, headers }).status).toBe("verified");
    const noQuery = "https://shop.example:443/";
    expect(
      verifier.verify({ url: noQuery, headers: signRequest({ key: ed, url: noQuery, components: ["@target-uri", "@query"] }) }).status,
    ).toBe("verified");
  });

  it("accepts a signature made for the other scheme when a proxy terminated TLS", () => {
    const ed = ed25519Key();
    const verifier = createAgentVerifier({ keys: [{ name: "Agent", category: "ai_agent", jwk: ed.jwk }] });
    const headers = signRequest({ key: ed, url, components: ["@target-uri"] });
    expect(verifier.verify({ url: url.replace("https:", "http:"), headers }).status).toBe("impersonation");
    expect(
      verifier.verify({ url: url.replace("https:", "http:"), alternateUrls: [url], headers }).status,
    ).toBe("verified");
  });

  it("calls a failed signature from a known key an impersonation", () => {
    const ed = ed25519Key();
    const now = Math.floor(Date.now() / 1000);
    const verifier = createAgentVerifier({ keys: [{ name: "Agent", category: "ai_agent", jwk: ed.jwk }] });
    const verdict = (options: Partial<SignOptions>) =>
      verifier.verify({ url, headers: signRequest({ key: ed, url, ...options }) });
    expect(verdict({ tamper: true })).toMatchObject({ status: "impersonation", reason: "bad-signature", agentName: "Agent" });
    expect(verdict({ created: now - 7200, expires: now - 3600 })).toMatchObject({ reason: "expired" });
    expect(verdict({ created: now + 3600 })).toMatchObject({ reason: "not-yet-valid" });
    expect(verdict({ alg: "rsa-pss-sha512" })).toMatchObject({ reason: "algorithm-mismatch" });
    expect(verdict({ expires: null }).status).toBe("verified");
  });

  it("holds keys to their published validity window", () => {
    const now = Math.floor(Date.now() / 1000);
    const expired = ed25519Key();
    const future = ed25519Key();
    const verifier = createAgentVerifier({
      keys: [
        { name: "Old", category: "ai_agent", jwk: { ...expired.jwk, exp: now - 3600 } },
        { name: "New", category: "ai_agent", jwk: { ...future.jwk, nbf: (now + 3600) * 1000 } },
      ],
    });
    expect(verifier.verify({ url, headers: signRequest({ key: expired, url }) })).toMatchObject({
      status: "impersonation",
      reason: "key-outside-validity",
    });
    expect(verifier.verify({ url, headers: signRequest({ key: future, url }) })).toMatchObject({
      status: "impersonation",
      reason: "key-outside-validity",
    });
  });

  it("reports unverifiable claims without calling them forgeries", () => {
    const ed = ed25519Key();
    const stranger = ed25519Key();
    const verifier = createAgentVerifier({ keys: [{ name: "Agent", category: "ai_agent", jwk: ed.jwk }] });
    const signed = signRequest({ key: ed, url });
    expect(verifier.verify({ url, headers: { "signature-input": signed["signature-input"] } })).toEqual({
      status: "claimed",
      reason: "incomplete-signature",
    });
    expect(verifier.verify({ url, headers: { ...signed, signature: "sig1=?1" } })).toEqual({
      status: "claimed",
      reason: "malformed-signature",
    });
    expect(verifier.verify({ url, headers: { ...signed, "signature-input": 'sig1="not-a-list"' } })).toEqual({
      status: "claimed",
      reason: "malformed-signature",
    });
    expect(verifier.verify({ url, headers: { ...signed, "signature-input": "sig1=(1 2);tag=\"web-bot-auth\"" } }).reason).toBe(
      "malformed-signature",
    );
    expect(verifier.verify({ url: "http://bad host/", headers: signed }).reason).toBe("malformed-signature");
    expect(verifier.verify({ url, headers: signRequest({ key: stranger, url }) })).toMatchObject({
      status: "claimed",
      reason: "unknown-key",
      keyId: stranger.keyId,
    });
    expect(verifier.verify({ url, headers: signRequest({ key: ed, url, components: ["@path"] }) })).toMatchObject({
      reason: "authority-not-covered",
    });
    expect(verifier.verify({ url, headers: signRequest({ key: ed, url, keyId: null }) })).toEqual({
      status: "claimed",
      reason: "unverifiable",
    });
    expect(
      verifier.verify({ url, headers: { ...signRequest({ key: ed, url }), signature: "other=:aGVsbG8=:" } }),
    ).toEqual({ status: "claimed", reason: "unverifiable" });
    const missingField = signRequest({ key: ed, url, components: ["@authority", "x-gone"], headers: { "x-gone": "1" } });
    delete missingField["x-gone"];
    expect(verifier.verify({ url, headers: missingField })).toMatchObject({ reason: "uncoverable-component" });
    const derived = signRequest({ key: ed, url, components: ["@authority"] });
    derived["signature-input"] = derived["signature-input"].replace('("@authority")', '("@authority" "@request-target")');
    expect(verifier.verify({ url, headers: derived })).toMatchObject({ reason: "uncoverable-component" });
    const member = signRequest({
      key: ed,
      url,
      components: ["@authority", 'signature-agent;key="a1"'],
      headers: { "signature-agent": 'a1="https://agent.example"' },
    });
    member["signature-agent"] = 'a2="https://agent.example"';
    expect(verifier.verify({ url, headers: member })).toMatchObject({ reason: "uncoverable-component" });
  });

  it("ignores other signature profiles and keeps the strongest outcome across members", () => {
    const ed = ed25519Key();
    const stranger = ed25519Key();
    const verifier = createAgentVerifier({ keys: [{ name: "Agent", category: "ai_agent", jwk: ed.jwk }] });
    expect(verifier.verify({ url, headers: signRequest({ key: ed, url, tag: "other-profile" }) })).toEqual({ status: "none" });

    const forged = signRequest({ key: ed, url, label: "sig1", tamper: true });
    const unknown = signRequest({ key: stranger, url, label: "sig2" });
    const good = signRequest({ key: ed, url, label: "sig3" });
    const combine = (...parts: Array<Record<string, string>>) => ({
      "signature-input": parts.map((part) => part["signature-input"]).join(", "),
      signature: parts.map((part) => part.signature).join(", "),
    });
    expect(verifier.verify({ url, headers: combine(forged, unknown) })).toMatchObject({
      status: "impersonation",
      reason: "bad-signature",
    });
    expect(verifier.verify({ url, headers: combine(unknown, forged, good) })).toMatchObject({ status: "verified" });
  });

  it("refuses to treat a replayed nonce as a fresh verification", () => {
    const ed = ed25519Key();
    let now = Date.now();
    const verifier = createAgentVerifier({
      keys: [{ name: "Agent", category: "ai_agent", jwk: ed.jwk }],
      maxTrackedNonces: 1,
      toleranceSec: 0,
      now: () => now,
    });
    const created = Math.floor(now / 1000);
    const first = signRequest({ key: ed, url, nonce: "n-1", created, expires: created + 1 });
    expect(verifier.verify({ url, headers: first }).status).toBe("verified");
    expect(verifier.verify({ url, headers: first })).toEqual({ status: "claimed", keyId: ed.keyId, reason: "replayed-nonce" });
    expect(verifier.verify({ url, headers: signRequest({ key: ed, url, nonce: "n-2", created, expires: created + 1 }) }).status).toBe(
      "verified",
    );
    expect(verifier.verify({ url, headers: first }).status).toBe("verified");
    const lingering = signRequest({ key: ed, url, nonce: "n-4", created, expires: null });
    expect(verifier.verify({ url, headers: lingering }).status).toBe("verified");
    expect(verifier.verify({ url, headers: lingering }).reason).toBe("replayed-nonce");
    now += 1500;
    expect(verifier.verify({ url, headers: lingering }).status).toBe("verified");

    const untracked = createAgentVerifier({ keys: [{ name: "Agent", category: "ai_agent", jwk: ed.jwk }], maxTrackedNonces: 0 });
    expect(untracked.verify({ url, headers: first }).status).toBe("verified");
    expect(untracked.verify({ url, headers: first }).status).toBe("verified");
    const noExpiry = signRequest({ key: ed, url, nonce: "n-3", expires: null });
    expect(untracked.verify({ url, headers: noExpiry }).status).toBe("verified");
    const remembers = createAgentVerifier({ keys: [{ name: "Agent", category: "ai_agent", jwk: ed.jwk }] });
    expect(remembers.verify({ url, headers: noExpiry }).status).toBe("verified");
    expect(remembers.verify({ url, headers: noExpiry }).reason).toBe("replayed-nonce");
  });

  it("rejects pinned keys it cannot use", () => {
    expect(() => createAgentVerifier({ keys: [{ name: "Bad", category: "x", jwk: { kty: "EC" } }] })).toThrow(TypeError);
    expect(() =>
      createAgentVerifier({ keys: [{ name: "Bad", category: "x", jwk: { kty: "OKP", crv: "X25519", x: "AAAA" } }] }),
    ).toThrow(TypeError);
    expect(() =>
      createAgentVerifier({ keys: [{ name: "Bad", category: "x", jwk: { kty: "OKP", crv: "Ed25519", x: "AAAA" } }] }),
    ).toThrow(TypeError);
  });

  it("loads curated directories in the background, keeping each directory's last good keys", async () => {
    const first = ed25519Key();
    const second = ed25519Key();
    const third = ed25519Key();
    let now = Date.now();
    let healthy = true;
    const fetch = vi.fn(async (input: string | URL | Request) => {
      const target = String(input);
      if (target === "https://a.example/.well-known/http-message-signatures-directory") {
        return healthy
          ? directoryResponse([
              { ...first.jwk, kid: "short-a" },
              { ...third.jwk, kid: jwkThumbprint(third.jwk) },
              "junk",
              null,
              { kty: "OKP", crv: "X25519", x: "AAAA" },
            ])
          : directoryResponse([], false);
      }
      if (target === "https://b.example/keys.json") {
        return directoryResponse([{ ...second.jwk, kid: "short-a" }]);
      }
      if (target === "https://c.example/.well-known/http-message-signatures-directory") {
        return new Response("null");
      }
      if (target === "https://d.example/.well-known/http-message-signatures-directory") {
        return new Response(JSON.stringify({ keys: "nope" }));
      }
      throw new Error("offline");
    });
    const pinned = ed25519Key();
    const verifier = createAgentVerifier({
      keys: [{ name: "Pinned", category: "monitoring", jwk: { ...pinned.jwk, kid: "short-a" } }],
      directories: [
        { name: "A", category: "ai_agent", directory: "https://a.example" },
        { name: "B", category: "monitoring", directory: "https://b.example/keys.json" },
        { name: "C", category: "x", directory: "https://c.example/" },
        { name: "D", category: "x", directory: "https://d.example" },
        { name: "E", category: "x", directory: "https://e.example" },
      ],
      refreshIntervalMs: 10_000,
      retryAfterFailureMs: 500,
      fetch,
      now: () => now,
    });
    const url = "https://shop.example/";
    expect(verifier.verify({ url, headers: signRequest({ key: first, url }) })).toMatchObject({ reason: "unknown-key" });
    const pending = verifier.refresh();
    expect(verifier.refresh()).toBe(pending);
    expect(await pending).toBe(5);
    expect(verifier.refreshedAt).toBe(now);
    expect(verifier.verify({ url, headers: signRequest({ key: first, url }) })).toMatchObject({ status: "verified", agentName: "A" });
    expect(verifier.verify({ url, headers: signRequest({ key: second, url }) })).toMatchObject({ status: "verified", agentName: "B" });
    expect(verifier.verify({ url, headers: signRequest({ key: pinned, url, keyId: "short-a" }) })).toMatchObject({
      status: "verified",
      agentName: "Pinned",
    });

    healthy = false;
    now += 20_000;
    const calls = fetch.mock.calls.length;
    verifier.verify({ url, headers: signRequest({ key: first, url }) });
    expect(fetch.mock.calls.length).toBe(calls + 5);
    verifier.verify({ url, headers: signRequest({ key: first, url }) });
    expect(fetch.mock.calls.length).toBe(calls + 5);
    await verifier.refresh();
    expect(verifier.verify({ url, headers: signRequest({ key: first, url }) }).status).toBe("verified");
  });

  it("backs off after every directory fails and uses the global fetch by default", async () => {
    let now = Date.now();
    const fetch = vi.fn(async () => {
      throw new Error("offline");
    });
    vi.stubGlobal("fetch", fetch);
    const ed = ed25519Key();
    const verifier = createAgentVerifier({
      directories: [{ name: "A", category: "ai_agent", directory: "https://a.example" }],
      retryAfterFailureMs: 1_000,
      fetchTimeoutMs: 50,
      now: () => now,
    });
    expect(await verifier.refresh()).toBe(0);
    expect(verifier.refreshedAt).toBeUndefined();
    expect(fetch).toHaveBeenCalledTimes(1);
    verifier.verify({ url: "https://shop.example/", headers: signRequest({ key: ed, url: "https://shop.example/" }) });
    expect(fetch).toHaveBeenCalledTimes(1);
    now += 1_000;
    verifier.verify({ url: "https://shop.example/", headers: signRequest({ key: ed, url: "https://shop.example/" }) });
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it("aborts a directory fetch that outlives its timeout", async () => {
    const fetch = vi.fn(
      (_input: string | URL | Request, init?: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => reject(new Error("aborted")));
        }),
    );
    const verifier = createAgentVerifier({
      directories: [{ name: "Slow", category: "ai_agent", directory: "https://slow.example" }],
      fetchTimeoutMs: 10,
      fetch,
    });
    expect(await verifier.refresh()).toBe(0);
    expect(fetch.mock.calls[0][1]?.headers).toEqual({
      accept: "application/http-message-signatures-directory+json, application/jwk-set+json, application/json",
    });
  });
});
