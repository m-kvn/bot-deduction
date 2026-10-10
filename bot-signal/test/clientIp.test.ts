import { describe, expect, it } from "vitest";
import {
  clientNetworkKey,
  isIpInCidr,
  isPublicIp,
  isValidTrustProxy,
  normalizeIp,
  resolveClientIp,
} from "../src/server/index.js";

describe("normalizeIp", () => {
  it("strips ports, brackets, zones and IPv4 mapping", () => {
    expect(normalizeIp("203.0.113.9:44321")).toBe("203.0.113.9");
    expect(normalizeIp("[2001:db8::1]:8080")).toBe("2001:db8:0:0:0:0:0:1");
    expect(normalizeIp("[2001:db8::1]")).toBe("2001:db8:0:0:0:0:0:1");
    expect(normalizeIp("fe80::1%eth0")).toBe("fe80:0:0:0:0:0:0:1");
    expect(normalizeIp("::ffff:203.0.113.9")).toBe("203.0.113.9");
    expect(normalizeIp(" 198.51.100.4 ")).toBe("198.51.100.4");
  });

  it("rejects anything that is not an address", () => {
    expect(normalizeIp(undefined)).toBeUndefined();
    expect(normalizeIp(null)).toBeUndefined();
    expect(normalizeIp("")).toBeUndefined();
    expect(normalizeIp("[::1")).toBeUndefined();
    expect(normalizeIp("unknown")).toBeUndefined();
    expect(normalizeIp("010.0.0.1")).toBeUndefined();
  });
});

describe("isIpInCidr", () => {
  it("matches IPv4 and IPv6 ranges and bare hosts", () => {
    expect(isIpInCidr("10.1.2.3", "10.0.0.0/8")).toBe(true);
    expect(isIpInCidr("11.1.2.3", "10.0.0.0/8")).toBe(false);
    expect(isIpInCidr("10.1.2.3", "10.1.2.3")).toBe(true);
    expect(isIpInCidr("10.1.2.3", "0.0.0.0/0")).toBe(true);
    expect(isIpInCidr("2001:db8::5", "2001:db8::/32")).toBe(true);
    expect(isIpInCidr("2001:db9::5", "2001:db8::/32")).toBe(false);
    expect(isIpInCidr("::ffff:10.0.0.1", "10.0.0.0/8")).toBe(true);
  });

  it("never matches across families or on malformed input", () => {
    expect(isIpInCidr("10.0.0.1", "::/0")).toBe(false);
    expect(isIpInCidr("2001:db8::1", "0.0.0.0/0")).toBe(false);
    expect(isIpInCidr("10.0.0.1", "10.0.0.0/")).toBe(false);
    expect(isIpInCidr("10.0.0.1", "10.0.0.0/33")).toBe(false);
    expect(isIpInCidr("10.0.0.1", "10.0.0.0/-1")).toBe(false);
    expect(isIpInCidr("10.0.0.1", "10.0.0.0/8.5")).toBe(false);
    expect(isIpInCidr("nope", "10.0.0.0/8")).toBe(false);
    expect(isIpInCidr("10.0.0.1", "nope/8")).toBe(false);
  });
});

describe("isPublicIp", () => {
  it("excludes loopback, private, CGNAT, link-local and unique-local space", () => {
    for (const ip of ["127.0.0.1", "10.0.0.1", "172.20.0.1", "192.168.1.1", "100.64.0.1", "169.254.1.1", "0.0.0.0", "::1", "::", "fd00::1", "fe80::1"]) {
      expect(isPublicIp(ip)).toBe(false);
    }
    expect(isPublicIp("8.8.8.8")).toBe(true);
    expect(isPublicIp("2606:4700:4700::1111")).toBe(true);
    expect(isPublicIp(undefined)).toBe(false);
    expect(isPublicIp("not-an-ip")).toBe(false);
  });
});

describe("resolveClientIp", () => {
  const headers = { "x-forwarded-for": "1.1.1.1, 2.2.2.2, 3.3.3.3", "x-real-ip": "4.4.4.4" };

  it("uses the peer address unless told to trust a proxy", () => {
    expect(resolveClientIp({ headers, peer: "::ffff:9.9.9.9" })).toBe("9.9.9.9");
    expect(resolveClientIp({ headers, peer: "9.9.9.9", trustProxy: 0 })).toBe("9.9.9.9");
    expect(resolveClientIp({ headers })).toBeUndefined();
  });

  it("counts trusted hops from the right of X-Forwarded-For", () => {
    expect(resolveClientIp({ headers, peer: "9.9.9.9", trustProxy: 1 })).toBe("3.3.3.3");
    expect(resolveClientIp({ headers, peer: "9.9.9.9", trustProxy: 2 })).toBe("2.2.2.2");
    expect(resolveClientIp({ headers, peer: "9.9.9.9", trustProxy: 4 })).toBe("9.9.9.9");
    expect(resolveClientIp({ headers, peer: "9.9.9.9", trustProxy: -1 })).toBe("9.9.9.9");
    expect(resolveClientIp({ headers, peer: "9.9.9.9", trustProxy: 1.5 })).toBe("9.9.9.9");
    expect(
      resolveClientIp({ headers: { "x-forwarded-for": "1.1.1.1, junk" }, peer: "9.9.9.9", trustProxy: 1 }),
    ).toBe("9.9.9.9");
    expect(
      resolveClientIp({ headers: { "x-forwarded-for": ["5.5.5.5", "6.6.6.6"] }, peer: "9.9.9.9", trustProxy: 1 }),
    ).toBe("6.6.6.6");
    expect(resolveClientIp({ peer: "9.9.9.9", trustProxy: 1 })).toBe("9.9.9.9");
  });

  it("reads a single client header such as X-Real-IP or CF-Connecting-IP", () => {
    expect(resolveClientIp({ headers, peer: "9.9.9.9", trustProxy: { header: "X-Real-IP" } })).toBe("4.4.4.4");
    expect(resolveClientIp({ headers, peer: "9.9.9.9", trustProxy: { header: "cf-connecting-ip" } })).toBe("9.9.9.9");
  });

  it("walks past trusted proxy ranges from the right", () => {
    const chain = { "x-forwarded-for": "1.1.1.1, 10.0.0.2, 10.0.0.3" };
    expect(resolveClientIp({ headers: chain, peer: "10.0.0.4", trustProxy: ["10.0.0.0/8"] })).toBe("1.1.1.1");
    expect(resolveClientIp({ headers: chain, peer: "8.8.4.4", trustProxy: ["10.0.0.0/8"] })).toBe("8.8.4.4");
    expect(
      resolveClientIp({ headers: { "x-forwarded-for": "10.0.0.9" }, peer: "10.0.0.4", trustProxy: ["10.0.0.0/8"] }),
    ).toBe("10.0.0.9");
    expect(
      resolveClientIp({ headers: { "x-forwarded-for": "1.1.1.1, bogus" }, peer: "10.0.0.4", trustProxy: ["10.0.0.0/8"] }),
    ).toBe("10.0.0.4");
    expect(resolveClientIp({ headers: {}, trustProxy: ["10.0.0.0/8"] })).toBeUndefined();
  });
});

describe("proxy trust configuration", () => {
  it("accepts only the shapes it can apply safely", () => {
    expect(isValidTrustProxy(false)).toBe(true);
    expect(isValidTrustProxy(2)).toBe(true);
    expect(isValidTrustProxy(["10.0.0.0/8"])).toBe(true);
    expect(isValidTrustProxy({ header: "x-real-ip" })).toBe(true);
    expect(isValidTrustProxy(true)).toBe(false);
    expect(isValidTrustProxy(1.5)).toBe(false);
    expect(isValidTrustProxy(-1)).toBe(false);
    expect(isValidTrustProxy([1])).toBe(false);
    expect(isValidTrustProxy({ header: 1 })).toBe(false);
    expect(isValidTrustProxy(null)).toBe(false);
    expect(isValidTrustProxy("cloudflare")).toBe(false);
  });

  it("falls back to the peer for a configuration it cannot apply", () => {
    expect(
      resolveClientIp({ headers: { "x-forwarded-for": "1.1.1.1" }, peer: "9.9.9.9", trustProxy: true as never }),
    ).toBe("9.9.9.9");
  });
});

describe("clientNetworkKey", () => {
  it("keys IPv4 by address and IPv6 by its /64", () => {
    expect(clientNetworkKey("203.0.113.9")).toBe("203.0.113.9");
    expect(clientNetworkKey("::ffff:203.0.113.9")).toBe("203.0.113.9");
    expect(clientNetworkKey("2001:db8:1:2::9")).toBe("2001:db8:1:2::/64");
    expect(clientNetworkKey("2001:db8:1:2:ffff:ffff:ffff:ffff")).toBe("2001:db8:1:2::/64");
    expect(clientNetworkKey("not-an-ip")).toBe("not-an-ip");
  });
});
