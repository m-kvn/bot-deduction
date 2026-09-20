import { isIP } from "node:net";

import { lookup } from "doc999tor-fast-geoip";

export interface IpGeoResult {
  ipCountry?: string;
  ipTimezone?: string;
  city?: string;
  region?: string;
}

/**
 * Looks up country, timezone, city, and region for an IP using the bundled
 * offline GeoIP database (`doc999tor-fast-geoip`). Returns `null` when the IP
 * is unknown or invalid — never throws.
 *
 * The bundled database is IPv4-only, and its parser splits on dots, so an IPv6
 * address does not fail loudly: `parseInt` stops at the first colon and the
 * leading hextet becomes an address. `2600:1700:...` turns into 43,620,761,600,
 * ten times past the end of the table, and the binary search returns the last
 * row — an Australian range — for every address in 2000::/3. Worse,
 * `2a00:1450:...` parses as `2`, a valid address that resolves somewhere real.
 * Neither answer is right, and no exception marks them as guesses, so every
 * IPv6 visitor picked up a spurious timezone and country mismatch. Refuse what
 * the data cannot answer instead.
 */
export async function lookupClientIpGeo(ip: string): Promise<IpGeoResult | null> {
  if (isIP(ip) !== 4) {
    return null;
  }

  try {
    const geo = await lookup(ip);

    if (!geo) {
      return null;
    }

    return {
      ipCountry: geo.country || undefined,
      ipTimezone: geo.timezone || undefined,
      city: geo.city || undefined,
      region: geo.region || undefined,
    };
  } catch {
    return null;
  }
}
