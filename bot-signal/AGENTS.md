# AGENTS.md

Guidance for AI agents and contributors working on the **bot-signal** package (npm name: `bot-signal`, GitHub: okasi/bot-signal). It exports `isHuman()` etc. as the simple entry points plus full detection APIs.

## Project overview

TypeScript npm library with three detection layers:

| Layer | Entry point | Location |
|-------|-------------|----------|
| Instant (browser) | `detectInstantClient` | `src/detectInstantClient.ts`, `src/checks.ts`, `src/asyncChecks.ts`, `src/webgpu.ts` |
| Behavioral (browser) | `createBehavioralClientDetector` | `src/behavioral/` |
| Server (Node) | `detectServerClientAsync` | `src/server/` |
| Request protection (Node) | `createBotProtection` | `src/server/protect.ts` and the modules it composes |

`src/automation.ts` contains the shared best-effort attribution result types.
Instant and server results expose `automation` (`kind`, confidence, evidence,
and alternatives); stealth framework names are probabilistic, not definitive.
`src/userAgent.ts` contains shared scripting-client and conservative
bot/HTTP-client/automation User-Agent token parsing.

Entry points: `src/index.ts` (full API), `src/browser.ts` (browser-only),
`src/server.ts` (server-only). The package.json `exports` map routes the root
import to the browser build under the `browser` condition so browser bundlers
never see `node:fs`. `src/version.ts` provides `VERSION`. Build output: `dist/` (tsup — ESM + CJS + IIFE
`browser.global.js` for CDNs).

## Repository layout

```
src/
  index.ts                    # root entry (full API)
  browser.ts                  # browser entry (instant + behavioral)
  server.ts                   # server entry (server detection only)
  automation.ts               # shared automation attribution types/helper
  userAgent.ts                # shared scripting/bot/HTTP-client/automation UA parser
  detectInstantClient.ts      # instant detection entry
  checks.ts                   # high-value browser checks
  asyncChecks.ts              # CDP, permissions, UA-CH, media devices, worker WebDriver/OS/WebGL checks
  webgpu.ts                   # shader-f16 + isChromiumBrowser
  behavioral/
    analysis.ts               # mouse/touch/CDP-input/scroll/typing heuristics
    scoring.ts                # weighted score aggregation
    index.ts                  # detector (DOM event listener lifecycle)
    types.ts
  server/
    geoip.ts                  # doc999tor-fast-geoip wrapper
    ipLists.ts                # parseIp + interval matching (IPv4/IPv6, binary search)
    enrich.ts                 # auto-fill context from clientIp
    analysis.ts               # request contradictions + trusted crawler-verification verdict
    scoring.ts                # detectServerClient(Async)
    tls.ts                    # JA3/JA4 lists, UA mismatch, TLS browser-profile checks
    tlsClientHello.ts         # ClientHello parser, local JA3/JA4, trackTlsClientHellos
    timezone.ts               # TZ offset + accept-language checks
    protect.ts                # createBotProtection: ordered rules, decision, middleware, fetch adapter
    htmlInjection.ts          # streaming trap-markup injection into node:http and fetch Responses
    tripwire.ts               # scanner bait paths + path canonicalisation
    honeytoken.ts             # HMAC honeytoken link, HTML injection, form honeypot field
    decoy.ts                  # HMAC decoy API endpoint + canary API key, inert JSON config
    webBotAuth.ts             # Web Bot Auth (RFC 9421) verifier, directory cache, nonce replay
    structuredFields.ts       # RFC 8941 dictionary parser for Signature-Input / Signature
    crawlerRanges.ts          # published crawler IP-range verification (data/crawler_ip_ranges.json)
    bots.ts                   # registry classification, bot policy, robots.txt
    botRegistry.ts            # 186-agent table ported from WebDecoy (order is significant)
    attackSignatures.ts       # narrow SQLi/XSS/traversal/shell/JNDI signatures
    rateLimit.ts              # fixed/sliding/token-bucket, bounded memory store, store interface
    rateLimitStores.ts        # Redis (Lua, any client) and Upstash REST stores
    clientIp.ts               # right-to-left proxy trust, CIDR matching, public-IP test
    types.ts
data/                         # bundled blocklists (shipped in npm package)
docs/                         # GitHub Pages demo source (index.html + app.js)
scripts/build-site.ts         # builds .pages/ with dist/browser.js + stamped asset URLs
scripts/update-ip-data.ts     # fetches and writes data/*.csv
scripts/update-crawler-ranges.ts # fetches published crawler ranges into data/crawler_ip_ranges.json
test/                         # vitest unit + patchright browser tests
  fixtures/harness.html         # DOM fixtures for browser tests
  helpers/                      # test server + patchright harness
  patchright/                   # real Chromium tests via patchright
  playwright/                   # stock Playwright detection on Windows
.github/workflows/
  ci.yml                      # typecheck + unit + patchright + build (Node 22+)
  pages.yml                   # build .pages/ and deploy via GitHub Pages Actions
  publish.yml                 # publish to npm on v* tags
  update-ip-data.yml          # weekly blocklist refresh
```

## Commands

```bash
npm install
npm run typecheck
npm test                    # unit tests (vitest, mocked window)
npm run test:coverage       # unit tests + 100% coverage gate
npm run test:patchright     # browser tests (patchright + real Chromium)
npm run test:playwright     # stock Playwright detection suite
npm run test:all            # unit + patchright + playwright
npm run build
npm run lint:package        # publint + Are The Types Wrong
npm run check               # typecheck + coverage + patchright + playwright + build + package lint
npm run build:site        # GitHub Pages artifact in .pages/
npm run update:ip-data    # refresh data/*.csv from upstream sources
npm run update:crawler-ranges # refresh data/crawler_ip_ranges.json from the operators' published lists
```

Always run `npm run check` before committing.

Patchright browser tests require `npx patchright install chromium` once after install, and the
Playwright suite `npx playwright install chromium`. The Redis rate-limit scripts are exercised
through `ioredis-mock`, which runs the Lua for real, so no Redis server is needed for the tests.
The browser bundle (`dist/browser.js`, entry `src/browser.ts`) is injected into Patchright's
isolated execution context via blob URL import — page scripts in the main world are not visible
to `page.evaluate`.

## Conventions

- **Imports at top of file** — no inline imports
- **Exhaustive switch** — use `never` in default case for discriminated unions
- **Minimal scope** — focused diffs, match existing style
- **Tests required** for new signals and non-trivial logic
- **Documentation** — update `README.md` (user-facing) and `AGENTS.md` (architecture) only. Do not add other doc files.

## Adding a detection signal

### Instant (browser)

1. Add check in `src/checks.ts` or `detectInstantClient.ts`
2. Add boolean field to `InstantClientResult` in `src/types.ts`
3. Add a spec (weight + confidence) to `INSTANT_SIGNAL_SPECS` in
   `detectInstantClient.ts` — use `triggerWhenFalse` for positive-health flags.
   Definitive markers weigh 1.0; false-positive-prone checks weigh 0.25–0.45 so
   they only block in combination (score `≥ scoreThreshold`, default 0.5).
4. Add test in `test/detectInstantClient.test.ts`
5. Document flag + weight in `README.md` signals table

### Behavioral

1. Add heuristic in `src/behavioral/analysis.ts`
2. Register in `buildBehavioralSignals` with `weight` and `confidence`
3. Add test in `test/behavioral.test.ts`
4. Document in `README.md`

### Server

1. Add check in `src/server/analysis.ts` or dedicated module
2. Extend `ServerClientContext` if new input is needed
3. Register signal in `buildServerSignals`
4. Add test in `test/server.test.ts` (use temp `dataDir` fixtures)
5. Document in `README.md`

Prefer low false-positive signals. Use weighted scoring for ambiguous checks.

### Verifying a new signal

Unit tests prove the logic; they cannot prove the premise. Before adding a
check that asserts "real browsers always do X", measure X in a real browser —
repeatedly, and on more than one origin. Two premises have already failed that
test in this repo:

- `screen.colorDepth` does not track the CSS `color` query (Opera reports 24 on
  a 10-bit panel), which is why `isMediaQueryInconsistent` compares resolution
  only.
- `canvas.toDataURL()` is not byte-stable. Identical pixels produced different
  PNG encodings on the same Chromium build depending on the page's origin, so
  `isCanvasNoiseInjected` compares `getImageData` pixels instead.

Anything a browser's fingerprint protection is free to rewrite — locale,
`hardwareConcurrency`, UA strings, colour depth — is too soft to judge a client
on. Build cross-realm and consistency checks on values protection does not
touch.

## Request protection

`createBotProtection` evaluates rules in a fixed order — `test-trigger`,
`web-bot-auth`, `honeytoken`, `decoy`, `tripwire`, `trap-lockout`,
`attack-signatures`, `bots`, rate limits, `detection` — and records an outcome for
every rule (`RUN`, `DRY_RUN`, `NOT_RUN`).
The first `RUN` outcome whose action is not `ALLOW` decides. Keep these invariants
when changing it:

- `mode: "monitor"` is the default and never refuses; `blocked` is only true in
  enforce mode. A rule that cannot run reports `NOT_RUN`, and a failure inside
  `protect()` returns conclusion `ERROR` with `allowed: true` (fail open).
- Rules see every reading of the target (`requestPathForms`: raw, canonical,
  WHATWG pathname; absolute-form origins stripped). Protective matches (traps,
  rate-limit paths) succeed on any reading, case-insensitively; skip paths only
  when every reading matches.
- The honeytoken must be armed before it is advertised: injection and matching
  both read `honeytoken.current()`; `robotsTxt()` disallows it. The decoy
  endpoint and canary key follow the same rules and are recorded with
  `honeytoken: true`. Only a verified crawler is exempt — verified by the
  request context, the trusted edge header, a Web Bot Auth signature, or the
  operator's published IP ranges, in that order of precedence
  (`decision.crawlerVerificationSource`). Cross-site, same-site, subresource and
  prefetch requests are never recorded as trap hits (no lockout poisoning), and
  dry-run hits are never recorded.
- Web Bot Auth verification is synchronous and never awaits the network:
  directories are fetched by `refresh()` (at construction and in the background
  when stale), each directory keeps its last good keys, and only curated
  directory URLs are fetched — never one taken from the request. Impersonation
  maps to `crawlerVerificationStatus: "spoofed"`; unknown keys, malformed headers
  and replayed nonces are `claimed`, never `impersonation`.
- Published-range verification yields `verified` or `unverified` by default;
  `spoofed` only with `crawlerRanges.outsideRanges: "spoofed"`, because a bundled
  list can lag a new range and `crawler-identity-spoofed` weighs 0.95.
- Redis rate-limit scripts must keep producing exactly what `MemoryRateLimitStore`
  does for the same request sequence (the parity test in
  `test/rateLimitStores.test.ts` runs both); refused requests are never counted.
- Clients are keyed by `clientNetworkKey`: the IPv4 address, or the IPv6 /64.
- Never read the leftmost `X-Forwarded-For` entry. `resolveClientIp` counts
  trusted hops from the right.
- `htmlInjection.ts` only rewrites uncompressed, ASCII-compatible `text/html`
  200 responses to GET requests. It splices bytes before the last `</body>`
  found outside scripts, styles and comments; streams with an 8-byte holdback
  when no `Content-Length` is declared; buffers (up to 2 MB) and adjusts the
  length when one is. It never restores the original `writeHead`/`write`/`end`,
  because later middleware (sessions, compression) may have wrapped them.
  `injectMarkupIntoFetchResponse` applies the same scan to a WHATWG `Response`
  body through a `TransformStream` and drops `Content-Length`.
- `botRegistry.ts` is generated from WebDecoy's registry; do not sort it (first
  match wins). `matchBotUserAgent` ignores app names inside browser-shaped UAs
  with no crawler declaration, so in-app browsers are not read as crawlers.
- `tls-browser-profile-mismatch` asserts browser behaviour; re-run
  `Test_Report/probe/tls_profile_probe.mjs` against real browsers before
  changing what it checks.

## IP blocklists

**Do not hand-edit** `data/*.csv` or `data/crawler_ip_ranges.json`. Update
`scripts/update-ip-data.ts` or `scripts/update-crawler-ranges.ts` instead.

| File | Source |
|------|--------|
| `abuse_ip_db_30d_ips.csv` | `borestad/blocklist-abuseipdb` (all countries) |
| `icloud_private_relay_ip_ranges.csv` | `mask-api.icloud.com` (all countries, `cidr,country`) |
| `datacenter_ip_ranges.csv` | `client9/ipcat` datacenters.csv |

Weekly refresh: `.github/workflows/update-ip-data.yml`
Matching: `src/server/ipLists.ts` parses lists once into sorted numeric
intervals (IPv4 as numbers, IPv6 as bigints) and binary-searches per lookup.
IPv4-mapped IPv6 input normalizes to IPv4. Abuse entries may carry trailing
`# country AS provider` annotations — only the first token is the IP.
GeoIP: `doc999tor-fast-geoip` via `lookupClientIpGeo` when `clientIp` is set
(IPv4-only, like the ipcat datacenter list). Call `preloadIpLists()` at boot to
pay the one-off parse cost up front. `scripts/update-ip-data.ts` validates row
shapes with `parseIp`, rejects HTML error pages, and refuses to overwrite a list
whose row count collapses (`--force` to override).

## Scoring formula

All three modes:

```
suspicionScore = 1 - Π(1 - weightᵢ)   for each triggered signal
isLegitClient = suspicionScore < scoreThreshold
```

Instant now uses this too (previously a hard boolean AND) — see
`INSTANT_SIGNAL_SPECS`. Default thresholds: instant 0.5, behavioral 0.55,
server 0.5.

## Testing notes

- **Coverage gate is 100%** (statements/branches/functions/lines) on `src/**`
  except `types.ts`; patchright tests are excluded from coverage, so every
  branch needs a unit test. Run `npm run test:coverage`.
- Server tests use `createFixtureDataDir()` with temp CSVs and `resetIpListCheckerCache()`
- Browser instant unit tests mock `window` / `navigator` with prototype-based `webdriver`
- Patchright tests (`test/patchright/`) run detection in real Chromium via `test/helpers/patchright-harness.ts`; `runInstantDetection(page, { scoreThreshold })` passes options through
- GeoIP tests call real `lookup("8.8.8.8")` — requires `doc999tor-fast-geoip` data in node_modules
- TLS tests start real `https` servers with `test/fixtures/tls-localhost-*.pem` (self-signed, test-only) and build ClientHello bytes with `test/helpers/tls-hello.ts`; the JA3/JA4 reference vectors are asserted exactly
- Protection tests drive `handle()`/`middleware()` through real `node:http` servers and `fetch`, including the response-injection paths

## Package publishing

`package.json` `files`: `["dist", "data"]`  
Exports: `.` (browser condition → `dist/browser.*`), `./browser`, `./server`,
each with ESM + CJS + split `.d.ts`/`.d.cts`. CDN: `unpkg`/`jsdelivr` point at
`dist/browser.global.js` (IIFE, global `BotSignal`). Keep `publint` and
`@arethetypeswrong/cli` green when touching the exports map.

GitHub Actions (`.github/workflows/publish.yml`) publishes via **npm Trusted Publishing** (OIDC). Every push to `main` automatically creates a patch release: the workflow increments `package.json`, `package-lock.json`, and `src/version.ts`, commits the release version, creates the matching `v*` tag, and publishes it to npm. The workflow uses a concurrency group so main pushes release serially, and GitHub's built-in token prevents the generated release commit/tag from recursively starting another workflow.

**First release:** publish as `bot-signal`. One-time local `npm publish --access public`, then Trusted publishing: `okasi` / `bot-signal` / `publish.yml`.

Every user-facing release must also be published to npm. The normal release process is:

1. Run `npm run check`, commit the user-facing change, and push it to `main`.
2. Let `.github/workflows/publish.yml` create the patch version commit and matching `v*` tag and publish through OIDC. Do not manually bump the version for an ordinary main-branch release.
3. Verify `npm view bot-signal version` reports the new version; do not consider the release complete until it is available on npmjs.com.

## Pull request checklist

- [ ] `npm run check` passes
- [ ] `README.md` updated for user-facing changes
- [ ] `AGENTS.md` updated if architecture or layout changed
- [ ] User-facing releases are versioned, tagged, published, and verified on npmjs.com
- [ ] No new documentation files beyond README.md and AGENTS.md
