# Form demo — who filled this form, a human or an agent?

A 4-field contact form wired to all three bot-signal layers, plus a dashboard that lists every
submission with its verdict.

| Layer | Runs | What it catches |
|-------|------|-----------------|
| Instant | Browser, on page load | Headless Chrome, Playwright/Puppeteer/Selenium artifacts, spoofed fingerprints |
| Behavioral | Browser, while the form is filled | Synthetic events, linear mouse/typing, no mouse activity, teleporting cursor |
| Server | Node, on POST | Scripting/bot User-Agent, datacenter + abuse-listed IP, TLS (JA3) mismatch, timezone/header mismatch |

The three scores combine into one verdict (`1 - Π(1 - scoreᵢ)`); a submission is an **agent** if any
layer rejects it, or if the form was posted without running the page JavaScript.

The demo also requires both browser layers, a one-time server challenge, same-origin `Origin` and
`Referer` request provenance, a cookie-bound page-load session whose document and every subresource
(`styles.css`, `bot-signal.global.js`, `app.js`) were actually fetched with the matching Fetch
Metadata, and credible trusted form input plus submit intent. A direct HTTP client that copies
browser headers still leaves no page-load trail, so `client:invalid-page-session` fires. Text pushed
in at the OS level with `SendInput`/`KEYEVENTF_UNICODE` arrives as a trusted keydown with no physical
key behind it (empty `code`, `keyCode` 231), which the browser layer reports as
`injected-key-input` and the server re-checks on the submitted interaction record. These checks
raise the cost of posting fabricated client results, but the
browser remains an attacker-controlled environment: use the verdict as a risk signal, not proof of
human identity.

## Run

```bash
npm run build          # from the repo root, produces dist/
node examples/form-demo/server.mjs
```

- Form: http://localhost:8787/
- Dashboard: http://localhost:8787/dashboard.html

## Try it

1. Fill the form yourself → **HUMAN**.
2. Script/scraper posting straight to the API:
   ```bash
   node examples/form-demo/bots/script-bot.mjs
   ```
   → **AGENT (python)** — no client signals + scripting User-Agent.
3. Automated browser filling the form:
   ```bash
   npx patchright install chromium   # once
   node examples/form-demo/bots/browser-bot.mjs
   ```
   → **AGENT** — instant automation artifacts + robotic input.

## Visitors abroad, travellers and VPNs

Where the app is hosted makes no difference: every check compares a visitor against *their own* IP,
headers and browser, never against the server's location. Hosting in India while visitors sit in the
US or Australia is fine — but the app must see the real visitor IP, so behind a proxy or CDN forward
it and point `CLIENT_IP_HEADER` at the header your edge writes (`x-forwarded-for` by default, or
`cf-connecting-ip`, `x-real-ip`, `true-client-ip`). Without it every visitor inherits the proxy's
datacenter address; the server logs a warning the first time that looks to be happening.

Two rules keep real people out of the agent bucket:

1. **Location and locale signals are advisory** — `timezone-mismatch`,
   `accept-language-geo-mismatch`, `client-language-mismatch` and `icloud-private-relay` appear as
   notes on the dashboard and add to the score, but never flip a verdict on their own. Timezone
   tolerance defaults to 180 minutes (`TZ_TOLERANCE_MINUTES`) so a US visitor geolocated to another
   US zone does not register at all.
2. **Weak signals need corroboration** — a signal under 0.5 (`datacenter-browser-mismatch`,
   `missing-browser-headers`, `missing-tls-fingerprint`) describes plenty of people on corporate
   VPNs, so one alone stays *human*; two together, or any single signal weighing 0.5+, flips the
   verdict.

So an Australian employee behind a US cloud VPN lands as **human** with advisory notes, while a
datacenter IP that also omits Fetch Metadata headers is flagged.

## Crosscheck the wiring

```bash
node examples/form-demo/crosscheck.mjs
```

Spawns throwaway servers (in-memory DB) and exercises the detection paths: scripting and
bot User-Agents, header-vs-JS UA, Client Hints version/platform/mobile, Fetch Metadata, Accept-Language
vs `navigator.languages`, timezone and country vs GeoIP, datacenter / AbuseIPDB / iCloud-relay IPs,
spoofed crawler identity, suspicious JA3 and JA4, missing TLS fingerprint, client-layer validation,
one-time challenges, trusted interaction history, and the instant + behavioral results forwarded from
the page. Prints PASS/FAIL per case.

TLS options are off by default because plain Node sees no TLS fingerprint. Enable them with
`SUSPICIOUS_TLS` (comma-separated hashes), `SUSPICIOUS_TLS_ENTRIES` (JSON `TlsFingerprintEntry[]` —
required for `tls-user-agent-mismatch`, which never fires for unlabelled hashes) and `REQUIRE_TLS=1`.
`X-Crawler-Verification: verified|spoofed|unverified` feeds the trusted-edge crawler check.
Set `TRUST_EDGE_HEADERS=1` only behind an edge that strips client-supplied forwarding, JA3/JA4, and
crawler-verification headers before writing its own trusted values. The safe default ignores them.

## Wiring it into a real site

- Page: `<script src="https://unpkg.com/bot-signal"></script>`, then `BotSignal.detectInstantClientAsync(window)`
  and `BotSignal.createBehavioralClientDetector({ context: window }).start()` — see `public/app.js`.
- Submit handler: POST the two client results plus `timezone`/`language`/`platform` alongside the form
  fields.
- Backend: `import { detectServerClientAsync } from "bot-signal/server"` and pass the request headers —
  see `handleSubmit` in `server.mjs`.
- Behind a proxy, forward the real client IP (`X-Forwarded-For`) and the JA3 hash (`X-JA3-Hash`) from
  your TLS terminator — without a JA3 hash the TLS checks stay inert.

## Storage

Every submission is written to a local SQLite database (`submissions.db`, created on first run) via
the built-in `node:sqlite` module — no dependency, and rows survive a restart. Set `DB_FILE` to move
it. Columns hold the verdict, the three layer scores, the form fields and request metadata, plus the
full JSON record; see `db.mjs`.

```bash
sqlite3 examples/form-demo/submissions.db "SELECT received_at, verdict, score, automation_kind, email FROM submissions ORDER BY received_at DESC LIMIT 10;"
```
