import { describe, expect, it, vi } from "vitest";
import { lookup } from "doc999tor-fast-geoip";
import { lookupClientIpGeo } from "../src/server/geoip.js";

vi.mock("doc999tor-fast-geoip", () => ({
  lookup: vi.fn(),
}));

describe("lookupClientIpGeo", () => {
  it("maps geo lookup fields", async () => {
    vi.mocked(lookup).mockResolvedValueOnce({
      country: "US",
      timezone: "America/New_York",
      city: "New York",
      region: "NY",
    });

    await expect(lookupClientIpGeo("8.8.8.8")).resolves.toEqual({
      ipCountry: "US",
      ipTimezone: "America/New_York",
      city: "New York",
      region: "NY",
    });
  });

  it("returns null when lookup misses or throws", async () => {
    vi.mocked(lookup).mockResolvedValueOnce(null);
    vi.mocked(lookup).mockRejectedValueOnce(new Error("bad ip"));

    await expect(lookupClientIpGeo("203.0.113.1")).resolves.toBeNull();
    // Both addresses must be IPv4: anything else is now refused before the
    // lookup runs, which would leave the queued rejection for the next test.
    await expect(lookupClientIpGeo("198.51.100.7")).resolves.toBeNull();
  });

  it("omits empty geo fields", async () => {
    vi.mocked(lookup).mockResolvedValueOnce({
      country: "",
      timezone: "",
      city: "",
      region: "",
    });

    await expect(lookupClientIpGeo("192.0.2.1")).resolves.toEqual({
      ipCountry: undefined,
      ipTimezone: undefined,
      city: undefined,
      region: undefined,
    });
  });
});

describe("IPv6 addresses the bundled database cannot answer", () => {
  // The bundled parser splits on dots, so an IPv6 address never fails loudly:
  // parseInt stops at the first colon and the leading hextet becomes an
  // address. Every one of these used to return a confident, wrong answer.
  it.each([
    ["2600:1700:630:9490:ffa0:a901:f306:d62d", "AT&T; parsed as 43,620,761,600"],
    ["2001:4860:4860::8888", "Google; past the end of the table"],
    ["2606:4700:4700::1111", "Cloudflare; past the end of the table"],
    ["2a00:1450:4001:80f::200e", "parses as 2 — a real but unrelated address"],
    ["::1", "parses as NaN"],
    ["fe80::1", "parses as NaN"],
  ])("refuses %s (%s) without consulting the IPv4 table", async (ip) => {
    vi.mocked(lookup).mockClear();
    await expect(lookupClientIpGeo(ip)).resolves.toBeNull();
    expect(lookup).not.toHaveBeenCalled();
  });

  it("still answers for IPv4", async () => {
    vi.mocked(lookup).mockClear();
    vi.mocked(lookup).mockResolvedValueOnce({
      country: "US",
      timezone: "America/Chicago",
      city: "",
      region: "",
    });

    await expect(lookupClientIpGeo("8.8.8.8")).resolves.toMatchObject({
      ipCountry: "US",
      ipTimezone: "America/Chicago",
    });
    expect(lookup).toHaveBeenCalledWith("8.8.8.8");
  });

  it("refuses anything that is not an address", async () => {
    vi.mocked(lookup).mockClear();
    await expect(lookupClientIpGeo("not-an-ip")).resolves.toBeNull();
    await expect(lookupClientIpGeo("")).resolves.toBeNull();
    expect(lookup).not.toHaveBeenCalled();
  });
});
