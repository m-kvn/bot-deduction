# Bot_Deduction — human vs. agent detection demo

A self-hosted contact form that decides, per submission, whether it was filled in by a **human** or
by an **agent / bot** — with no auth, no CAPTCHA, no third-party API and no outbound network calls at
request time. Every signal is computed locally from the browser and from the HTTP request itself.

Latest verified run: **86/86 harness tests, 400 unit tests, 30 crosscheck cases**, and **66/66
agent-driven submissions in the harness matrix are classified as AGENT** — including a real PowerShell `SendInput` session driving a live
Chrome window. That is a rate over the attacks in the matrix, not a claim of completeness: an
independent red team passed four methods it does not contain (see **Known-open vectors** below).
Reports live in `Test_Report/`.

---

## Repo layout

```
.
├─ .env.example                     # every runtime variable, documented
├─ bot-signal/                      # the detection library + the demo app
│  ├─ src/                          # instant, behavioral and server detectors (TypeScript)
│  ├─ data/                         # offline IP lists (datacenter, AbuseIPDB, iCloud Relay)
│  ├─ test/                         # 400 unit tests (vitest)
│  └─ examples/form-demo/
│     ├─ server.mjs                 # the app: static pages + /api/challenge + /api/submit
│     ├─ db.mjs                     # SQLite persistence (node:sqlite, no native deps)
│     ├─ crosscheck.mjs             # 30 server-side detection cases
│     ├─ bots/                      # scripted + browser bot simulators
│     └─ public/                    # index.html (form), dashboard.html, app.js, styles.css
└─ Test_Report/
   ├─ run_tests.mjs                 # 86-case end-to-end harness (Patchright + direct HTTP)
   ├─ probe/                        # OS input-injection measurement + replay tooling
   ├─ generate_agent_detection_report.mjs
   ├─ results.json                  # raw results of the last run
   ├─ agent_detection_test_report.html / .pdf
   └─ *.png                         # evidence screenshots
```

---

## Requirements

| | |
|---|---|
| Node.js | **22 or newer** — the app uses the built-in `node:sqlite` module. Tested on 24.19.0. |
| Disk | ~350 MB with dev dependencies installed, ~40 MB for a production install |
| Network at runtime | none — the IP lists in `bot-signal/data/` are read from disk |
| Chrome / Chromium | only for the test harness, not for serving the app |

---

## Run it locally

```bash
git clone <this-repo-url> Bot_Deduction
cd Bot_Deduction/bot-signal

npm ci                 # install dependencies
npm run build          # produces dist/ — the demo server imports ../../dist/server.js

cd examples/form-demo
node server.mjs
```

Then open:

- Form — <http://localhost:8787/index.html>
- Dashboard — <http://localhost:8787/dashboard.html>

`npm run build` is **not optional**: `dist/` is generated output and is not committed, and both the
server detector and the browser bundle (`/vendor/bot-signal.global.js`) are served from it. Re-run it
after any change under `bot-signal/src/`.

---

## Configuration

Copy `.env.example` to `.env` and edit it, or export the variables directly. Every variable is
optional — the defaults below are what the app uses when nothing is set.

| Variable | Default | What it does |
|---|---|---|
| `PORT` | `8787` | Port the form and dashboard listen on |
| `HOST` | `127.0.0.1` | Interface to bind. Loopback by default, so only a proxy on the same host can reach it. Set `0.0.0.0` for Docker |
| `DB_FILE` | `examples/form-demo/submissions.db` | SQLite file; `:memory:` for an ephemeral store |
| `TRUST_EDGE_HEADERS` | unset | **Set to `1` only behind a proxy you control.** Enables trust in `x-forwarded-proto`, the client-IP header, and the TLS/crawler headers below |
| `CLIENT_IP_HEADER` | `x-forwarded-for` | Header your edge writes the real visitor IP into (`cf-connecting-ip`, `x-real-ip`, `true-client-ip`) — read only when `TRUST_EDGE_HEADERS=1` |
| `REQUIRE_TLS` | unset | Require a JA3/JA4 fingerprint (`x-ja4` / `x-ja3-hash`) on every submission |
| `SUSPICIOUS_TLS` | empty | Comma-separated JA3/JA4 hashes to treat as known-bad |
| `SUSPICIOUS_TLS_ENTRIES` | empty | Same, as JSON, so each entry can carry a label and score |
| `TZ_TOLERANCE_MINUTES` | `180` | Allowed drift between the browser clock and the GeoIP timezone before it is noted |
| `DEMO_URL` / `HEADFUL` / `BOT_UA` | — | Only used by the bot simulators in `examples/form-demo/bots/` |

Node does not read `.env` files on its own. Either load it explicitly
(`node --env-file=../../../.env server.mjs` on Node 22+) or let your process manager inject the
variables — both options are shown below.

> **Security note on `TRUST_EDGE_HEADERS`:** leave it unset when the app is exposed directly to the
> internet. With it on, any caller can forge their own IP and TLS fingerprint simply by sending the
> headers themselves, which silently weakens the server layer.

---

## Deploy

### 1. Behind nginx with systemd (recommended)

Build on the server, then run the demo under systemd.

```bash
# as a deploy user, e.g. /srv/bot-deduction
git clone <this-repo-url> /srv/bot-deduction
cd /srv/bot-deduction/bot-signal
npm ci
npm run build
cp ../.env.example ../.env     # then edit ../.env
```

`/etc/systemd/system/bot-deduction.service`:

```ini
[Unit]
Description=Bot_Deduction form demo
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/srv/bot-deduction/bot-signal/examples/form-demo
EnvironmentFile=/srv/bot-deduction/.env
Environment=NODE_ENV=production
ExecStart=/usr/bin/node server.mjs
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now bot-deduction
sudo systemctl status bot-deduction
```

nginx site, terminating TLS and forwarding the real client IP:

```nginx
server {
  listen 443 ssl http2;
  server_name forms.example.com;

  ssl_certificate     /etc/letsencrypt/live/forms.example.com/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/forms.example.com/privkey.pem;

  location / {
    proxy_pass         http://127.0.0.1:8787;
    proxy_http_version 1.1;

    # Required for the server detection layer to see the real visitor.
    proxy_set_header Host              $host;
    proxy_set_header X-Real-IP         $remote_addr;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;

    # Never let a client inject these — the edge owns them.
    proxy_set_header X-JA4                  "";
    proxy_set_header X-JA3-Hash             "";
    proxy_set_header X-Crawler-Verification "";
  }
}
```

With this in place set `TRUST_EDGE_HEADERS=1` and `CLIENT_IP_HEADER=x-real-ip` in `.env`.

### 2. Docker

Create `Dockerfile` at the repo root:

```dockerfile
FROM node:22-slim AS build
WORKDIR /app
COPY bot-signal/package*.json ./bot-signal/
RUN cd bot-signal && npm ci
COPY bot-signal ./bot-signal
RUN cd bot-signal && npm run build

FROM node:22-slim
WORKDIR /app
ENV NODE_ENV=production PORT=8787 HOST=0.0.0.0 DB_FILE=/data/submissions.db
COPY --from=build /app/bot-signal/dist          ./bot-signal/dist
COPY --from=build /app/bot-signal/data          ./bot-signal/data
COPY --from=build /app/bot-signal/node_modules  ./bot-signal/node_modules
COPY --from=build /app/bot-signal/package.json  ./bot-signal/package.json
COPY bot-signal/examples/form-demo ./bot-signal/examples/form-demo
VOLUME /data
EXPOSE 8787
WORKDIR /app/bot-signal/examples/form-demo
CMD ["node", "server.mjs"]
```

```bash
docker build -t bot-deduction .
docker run -d --name bot-deduction -p 8787:8787 -v bot-deduction-data:/data \
  -e TRUST_EDGE_HEADERS=1 -e CLIENT_IP_HEADER=x-real-ip bot-deduction
```

### 3. A PaaS (Render, Railway, Fly.io, Azure App Service)

- Build command: `cd bot-signal && npm ci && npm run build`
- Start command: `cd bot-signal/examples/form-demo && node server.mjs`
- Set `PORT` to whatever the platform injects, `HOST` to `0.0.0.0` so the platform's router can reach it, `DB_FILE` to a path on a persistent volume, and
  `TRUST_EDGE_HEADERS=1` with `CLIENT_IP_HEADER` matching the platform's real-IP header.
- Without a persistent volume the SQLite file is lost on every redeploy. Use `DB_FILE=:memory:` if
  you only need the live verdict and not the submission history.

### Post-deploy check

```bash
curl -sI https://forms.example.com/index.html          # expect 200

# A direct forged POST must be rejected: expect 403.
curl -s -o /dev/null -w '%{http_code}\n' -X POST \
  -H 'content-type: application/json' \
  -d '{"form":{"name":"probe","email":"probe@example.test"}}' \
  https://forms.example.com/api/submit
```

---

## How a submission is judged

Three independent layers produce a score; they combine as `1 - Π(1 - scoreᵢ)`. A submission is an
**agent** if any layer rejects it **or if the combined score reaches 0.6 with more than one layer
contributing**.

That second clause exists because per-layer thresholds alone are gameable by spreading evidence. A
session scoring 0.30 instant, 0.30 behavioral and 0.35 server is three independent tells and a
combined 0.68, yet every layer individually says "fine" — the old rule computed that 0.68, recorded
it, displayed it, and never read it. Corroboration across layers is the thing worth acting on, so the
rule requires at least two layers to have contributed rather than letting one noisy environment
signal carry a verdict (`AGGREGATE_SCORE_THRESHOLD`, `MIN_CORROBORATING_LAYERS`).

Not every 0.30 carries the same weight. "This desktop has no webcam" and "this address is a
datacenter" describe an environment millions of real people are sitting in; "every click released on
the pixel it pressed" describes how the input was produced. So the bar depends on the kind of
evidence: **0.5 when at least one behavioral or client signal contributed, 0.6 when the evidence is
environmental only** (`AGGREGATE_BEHAVIORAL_THRESHOLD`, `AGGREGATE_SCORE_THRESHOLD`).

The cost is stated plainly, because it is not small. Two combinations that are real people get
flagged:

| Session | score | verdict |
|---|---|---|
| VPN + no webcam + straight trackpad paths | 0.659 | 🔴 agent |
| Trackpad tap-to-click user on a desktop with no webcam | 0.510 | 🔴 agent |

The second is the sharp one: tap-to-click produces short-dwell, zero-movement presses, which is
exactly what `zero-jitter-clicks` looks for, and a desktop without a webcam is ordinary. That session
is **numerically identical** to a reported bypass run — 0.30 instant, 0.30 behavioral, 0.51 combined.
No threshold separates them, because the difference is not in the score.

The decision is isolated in `verdict.mjs`; `verdict_check.mjs` prints the full table for any
threshold you set, so the trade can be moved with its consequences visible rather than guessed at.

1. **Instant (browser)** — headless markers, `navigator.webdriver`, automation globals (Playwright,
   Puppeteer, Selenium, CDP), implausible screen geometry, tampered navigator getters.
2. **Behavioral (browser)** — mouse / scroll / key / touch cadence, synthetic-event counts, linear or
   teleporting pointer paths, uniform and repeated-cadence typing, and **OS-level input injection**
   (see below).
3. **Server (request)** — datacenter / AbuseIPDB / iCloud-Relay IP ranges, UA vs. `sec-ch-ua`
   consistency, Fetch Metadata, `Accept-Language` vs. GeoIP, optional JA3/JA4.

The page's own verdict is treated as advisory. It submits the **raw sample streams** its score was
derived from, and the server recomputes the behavioral result itself — a fabricated
`{score: 0, signals: []}` buys nothing, because nothing downstream reads it.

On top of those, the demo server refuses anything that did not come from a real page load:

- both browser layers must be present and internally consistent;
- a **one-time challenge** from `/api/challenge`, bound to IP, User-Agent and page session;
- **same-origin `Origin` and `Referer`**;
- a **cookie-bound page-load session** whose document *and* every subresource
  (`styles.css`, `bot-signal.global.js`, `app.js`) were actually fetched with matching Fetch
  Metadata — a direct HTTP client that copies browser headers still leaves no page-load trail;
- **trusted** form input and submit intent (`event.isTrusted`), with no untrusted form events;
- **text that a keyboard could have produced**: a keyboard delivers one character per `insertText`,
  while `fill()`, CDP `Input.insertText` and `element.value = …` deliver a whole field in one event.
  Paste, autofill, drag and IME commits carry their own `inputType` and are never counted;
- a **behavioral score the server derived**, not one the client reported — mismatches between the two
  fire `forged-client-verdict`, and a missing sample set fires `missing-behavioral-samples`;
- an **observation window that fits inside the page session**. Both sides are durations, never
  absolute timestamps, so a visitor whose clock is wrong is unaffected, but nobody can watch a page
  for longer than the page has existed.

### OS-level input injection

A harness that drives a real, signed-in browser through the Windows input stack (`SendInput`,
`keybd_event`, `mouse_event`, `SetCursorPos` — the PowerShell and AutoHotkey approach) produces
events that are genuinely `isTrusted`. The window is real, the page load is real, and every
provenance check above passes, so this used to come back HUMAN with score 0.00.

The tell is how the text is pushed in. `SendInput` with `KEYEVENTF_UNICODE` sets `wVk = 0` and carries
the character in the scan-code field, so Windows reports `VK_PACKET` and Chromium has no physical key
to name. Measured against Chrome 140 on Windows 11:

| Input method | `key` | `code` | `keyCode` | `isTrusted` |
|---|---|---|---|---|
| `SendInput` + `KEYEVENTF_UNICODE` | `K` | *(empty)* | `231` (`VK_PACKET`) | `true` |
| Scan-code key press (hardware path) | `b` | `KeyB` | `66` | `true` |

`injected-key-input` fires when at least 5 printable keystrokes — and at least 60% of them — arrive
with no physical key behind them. It is a ratio so that an emoji picker or a dictated word inside an
otherwise hand-typed form is not flagged, and the server enforces the same rule on the submitted
interaction record so a tampered page bundle cannot drop the evidence.
`zero-jitter-clicks` supports it: `mouse_event` releases on the exact pixel it pressed, while a hand
resting on a mouse drifts. It is weighted as supporting evidence only and never decides a verdict
alone.

`Test_Report/probe/` holds the tooling: `probe.mjs` measures what Chromium reports for injected vs.
hardware keystrokes, and `verify_real_injection.mjs` replays a full PowerShell injection run against a
live server. Both take over the mouse and keyboard while they run.

### Known-open vectors

Ten bypass methods were run against the current build, every verdict read back from
`GET /api/submissions`. **Six are caught, four still classify as human** — the full measured matrix
is in [`Test_Report/BYPASS_MATRIX.md`](Test_Report/BYPASS_MATRIX.md). These two classes remain open,
and are stated here rather than buried:

| Vector | Why it is open |
|---|---|
| OS-level injection with real **scan codes** (`SendInput` + `KEYEVENTF_SCANCODE`, patched pyautogui) | The key event is identical to hardware. `injected-key-input` is, in effect, a scan-code check: it catches `KEYEVENTF_UNICODE` and stock pyautogui, which send scan code 0, and nothing else. |
| Raw **CDP `Input`** client driving a normal Chrome build | No `navigator.webdriver`, no automation launcher, genuinely trusted events. The library's console-based CDP probe does not fire for an attached `Input`-domain session, with or without `Runtime.enable`. |

Three detection hypotheses were measured and **all three rejected**. Recorded so they do not get
proposed again:

| Hypothesis | Measurement | Result |
|---|---|---|
| CDP input skips Chromium's rAF-aligned input pipeline | median inter-event gap 16.9 ms (CDP) vs 16.8 ms (real OS input), zero sub-frame gaps in either | rejected — same pipeline |
| Injected input produces fewer coalesced raw events than a polled mouse | 1.01 coalesced/`pointermove` for both `SetCursorPos` and CDP; and any cadence rule is trivially matched once known | rejected — no baseline, self-defeating |
| CDP can drive an unfocused window, a human cannot | `document.hasFocus()` stayed `true` under CDP input with the OS window inactive | rejected — not observable |

Probes: `Test_Report/probe/cdp_timing_probe.mjs`, `coalesced_probe.mjs`, `focus_probe.mjs`.

A fourth idea — `generated-pointer-path` — is implemented and unit-tested but **does not catch these
scripts in practice**. All four move the pointer with a quadratic Bézier whose jitter is applied to
the curve parameter, leaving every sample on one convex arc (0.22–0.25 px deviation on long sweeps,
against 0 crossings). On a real form fill the reaches are short enough that `SetCursorPos` rounding
through 1.25× display scaling contributes ~0.45 px by itself, which is the same order as the signal.
Widening the threshold far enough to catch C4 needs a measured human baseline that does not exist
yet; `Test_Report/BYPASS_MATRIX.md` has the numbers and the calibration command. It is shipped
inert, not counted as a fix.

**Honest limitation:** this raises the cost of forgery; it does not make it impossible. Both open
vectors produce genuinely trusted events, a real page load and human-grade input, so the samples the
server recomputes are honest samples of real input. Detection has no client-side signal left to add.

### Proof of work

Every challenge carries a hash puzzle: find a nonce where `sha256(prefix:nonce)` has N leading zero
bits. At the base 16 bits that is ~0.12s on a synchronous SHA-256 (`crypto.subtle` is unusable here —
one promise per digest makes 65k hashes take longer than ten seconds). A person pays it once.

Difficulty escalates only *past* the point the volume controls already consider abusive, so a busy
shared office address is not progressively punished:

| Variable | Default | Meaning |
|---|---|---|
| `POW_BASE_DIFFICULTY` | 16 | ~0.12 s — what everyone pays |
| `POW_ESCALATION_BITS` | 2 | added per submission beyond `MAX_SUBMISSIONS_PER_IP` |
| `POW_MAX_DIFFICULTY` | 22 | ~7.5 s ceiling |

### Telemetry beacons — forced real-time execution

The page posts a beacon to `/api/telemetry` every two seconds. Each reply carries the nonce the next
beacon must quote, so the stream is a chain rather than a set of independent posts, and **the server
timestamps every link on its own clock**.

At submit, a claimed observation window must be matched by the session having demonstrably reported
across it (`observed ≥ claimed × 0.5 − slack`). There is no fixed minimum beacon count: a page that
submits in three seconds owes almost nothing, while one claiming half a minute of watching has to
have been alive and reporting for most of it. That turns "author a history offline, sleep, POST it"
into "keep a live session emitting a consistent chain" — most of the way to just running a browser.

Tunable via `TELEMETRY_INTERVAL_MS`, `TELEMETRY_COVERAGE`, `TELEMETRY_STALE_MS`.

### Volume and repetition controls

What those vectors cannot hide is repetition: a hand fills this form once, a loop fills it all
afternoon. The server therefore tracks a second axis, kept deliberately separate from the verdict —
`verdict` stays a statement about one submission, `outcome` is what to do about it.

| Response field | Values |
|---|---|
| `verdict` | `human` / `agent` — detection only, unchanged by anything below |
| `outcome` | `accepted` (HTTP 200) · `review` (HTTP 202) · `rejected` (HTTP 403, verdict `agent`) |
| `risk` | the reasons a clean-looking submission was sent to review |

| Limit | Env var | Default |
|---|---|---|
| Submissions per page load | `MAX_SUBMISSIONS_PER_SESSION` | 3 |
| Submissions per IP per window | `MAX_SUBMISSIONS_PER_IP` | 10 |
| Page loads per IP per window | `MAX_SESSIONS_PER_IP` | 12 |
| Challenges per page load | `MAX_CHALLENGES_PER_SESSION` | 24 |
| Identical form content per IP | `MAX_IDENTICAL_SUBMISSIONS` | 1 |
| Rolling window | `RISK_WINDOW_MS` | 600000 |

Verified against the scan-code injection that defeats detection: first run `human` / `accepted`,
second run with the same content `human` / **`review`**. The verdict stays honest; the submission
stops being silently accepted.

---

## Tests and reports

```bash
cd bot-signal
npm test                                   # 400 unit tests
node examples/form-demo/crosscheck.mjs     # 30 server-detection cases

npx patchright install chromium            # once, for the browser harness
cd ../Test_Report
node run_tests.mjs                         # 86 end-to-end cases -> results.json
node generate_agent_detection_report.mjs   # -> HTML + PDF report
```

`run_tests.mjs` and `generate_agent_detection_report.mjs` point at a Windows Chrome install
(`C:\Program Files\Google\Chrome\Application\chrome.exe`). Change the `chromePath` constant at the
top of both files to run them on Linux or macOS.

Every case in the harness is agent-driven, so every expected verdict is `AGENT`. **No genuine human
session has been measured**, which means the false-positive rate against real users is currently
unknown — worth measuring before this gates anything that matters.

---

## Upstream

`bot-signal/` started from [okasi/bot-signal](https://github.com/okasi/bot-signal) (MIT) and has been
modified here: a repeated-typing-cadence behavioral signal, request-provenance checks, and the
cookie-bound page-load session layer in `examples/form-demo/server.mjs`.
