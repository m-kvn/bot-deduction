import { describe, expect, it } from "vitest";
import { createDecoy } from "../src/server/decoy.js";

describe("createDecoy", () => {
  it("derives a stable endpoint and canary key from the secret", () => {
    const first = createDecoy({ secret: "s3cret" });
    const second = createDecoy({ secret: "s3cret" });
    expect(first.path).toBe(second.path);
    expect(first.credential).toBe(second.credential);
    expect(first.stable).toBe(true);
    expect(first.path).toMatch(/^\/api\/(?:internal|admin|private|export|debug|backup|legacy|v0)\/[0-9a-f]{12}$/);
    expect(first.credential).toMatch(/^key_live_[0-9a-f]{32}$/);
    expect(first.config).toEqual({ apiBase: first.path, apiKey: first.credential });
    expect(Object.isFrozen(first.config)).toBe(true);
    expect(createDecoy({ secret: "other" }).path).not.toBe(first.path);
  });

  it("uses a random secret, custom base path, key prefix and config id when asked", () => {
    const random = createDecoy();
    expect(random.stable).toBe(false);
    const custom = createDecoy({ secret: "x", basePath: "/v2/ops/", credentialPrefix: "ops_", configId: 'cfg"<x>' });
    expect(custom.path).toMatch(/^\/v2\/ops\/[0-9a-f]{12}$/);
    expect(custom.credential).toMatch(/^ops_[0-9a-f]{32}$/);
    expect(custom.configHtml).toBe(
      `<script type="application/json" id="cfg&quot;&lt;x&gt;">{"apiBase":"${custom.path}","apiKey":"${custom.credential}"}</script>`,
    );
  });

  it("keeps the inline config from closing its own script element", () => {
    const decoy = createDecoy({ secret: "x", basePath: "/api/</script><b>" });
    expect(decoy.configHtml).not.toContain("</script><b>");
    expect(decoy.configHtml).toContain("\\u003c/script>\\u003cb>");
    expect(JSON.parse(decoy.configHtml.replace(/^<script[^>]*>|<\/script>$/g, "")).apiBase).toBe(decoy.path);
  });

  it("matches the endpoint and anything beneath it, case-insensitively", () => {
    const decoy = createDecoy({ secret: "s3cret" });
    expect(decoy.matchesPath(decoy.path)).toBe(true);
    expect(decoy.matchesPath(decoy.path.toUpperCase())).toBe(true);
    expect(decoy.matchesPath(`${decoy.path}/export.csv`)).toBe(true);
    expect(decoy.matchesPath(`${decoy.path}x`)).toBe(false);
    expect(decoy.matchesPath("/api/submit")).toBe(false);
  });

  it("finds the canary key in headers, the query string or the body", () => {
    const decoy = createDecoy({ secret: "s3cret" });
    const key = decoy.credential;
    expect(decoy.findCredential({ headers: { authorization: `Bearer ${key}` } })).toBe("header");
    expect(decoy.findCredential({ headers: { "x-api-key": ["a", key] } })).toBe("header");
    expect(decoy.findCredential({ headers: { "x-other": undefined }, query: `api_key=${key}` })).toBe("query");
    expect(decoy.findCredential({ query: `api_key=${key.replace("_", "%5F")}` })).toBe("query");
    expect(decoy.findCredential({ body: JSON.stringify({ token: key }) })).toBe("body");
    expect(decoy.findCredential({ body: `k=${key.replace(/_/g, "%5f")}&broken=%E0%A4%A` })).toBeUndefined();
    expect(decoy.findCredential({ body: `k=${key}&broken=%E0%A4%A` })).toBe("body");
    expect(decoy.findCredential({ headers: { authorization: "Bearer key_live_nope" }, query: "a=1", body: "b=2" })).toBeUndefined();
    expect(
      decoy.findCredential({
        headers: { Referer: `https://site.example/?k=${key}`, origin: key, cookie: `k=${key}` },
      }),
    ).toBeUndefined();
    expect(decoy.findCredential({})).toBeUndefined();
  });
});
