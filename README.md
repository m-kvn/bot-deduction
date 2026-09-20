# Bot_Deduction — human vs. agent detection demo

A self-hosted contact form that decides, per submission, whether it was filled in by a **human** or
by an **agent / bot** — with no auth, no CAPTCHA, no third-party API and no outbound network calls at
request time. Every signal is computed locally from the browser and from the HTTP request itself.

Latest verified run: **76/76 harness tests pass**, and **62/62 agent-driven submissions are
classified as AGENT (100%, 0 missed)**. Reports live in `Test_Report/`.

---

## Repo layout

```
.
├─ .env.example                     # every runtime variable, documented
├─ bot-signal/                      # the detection library + the demo app
│  ├─ src/                          # instant, behavioral and server detectors (TypeScript)
│  ├─ data/                         # offline IP lists (datacenter, AbuseIPDB, iCloud Relay)
│  ├─ test/                         # 381 unit tests (vitest)
│  └─ examples/form-demo/
│     ├─ server.mjs                 # the app: static pages + /api/challenge + /api/submit
│     ├─ db.mjs                     # SQLite persistence (node:sqlite, no native deps)
│     ├─ crosscheck.mjs             # 30 server-side detection cases
│     ├─ bots/                      # scripted + browser bot simulators
│     └─ public/                    # index.html (form), dashboard.html, app.js, styles.css
└─ Test_Report/
   ├─ run_tests.mjs                 # 76-case end-to-end harness (Patchright + direct HTTP)
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
ENV NODE_ENV=production PORT=8787 DB_FILE=/data/submissions.db
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
- Set `PORT` to whatever the platform injects, `DB_FILE` to a path on a persistent volume, and
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

Three independent layers produce a score; they combine as `1 - Π(1 - scoreᵢ)`, and a submission is
an **agent** if any layer rejects it.

1. **Instant (browser)** — headless markers, `navigator.webdriver`, automation globals (Playwright,
   Puppeteer, Selenium, CDP), implausible screen geometry, tampered navigator getters.
2. **Behavioral (browser)** — mouse / scroll / key / touch cadence, synthetic-event counts, linear or
   teleporting pointer paths, uniform and repeated-cadence typing.
3. **Server (request)** — datacenter / AbuseIPDB / iCloud-Relay IP ranges, UA vs. `sec-ch-ua`
   consistency, Fetch Metadata, `Accept-Language` vs. GeoIP, optional JA3/JA4.

On top of those, the demo server refuses anything that did not come from a real page load:

- both browser layers must be present and internally consistent;
- a **one-time challenge** from `/api/challenge`, bound to IP, User-Agent and page session;
- **same-origin `Origin` and `Referer`**;
- a **cookie-bound page-load session** whose document *and* every subresource
  (`styles.css`, `bot-signal.global.js`, `app.js`) were actually fetched with matching Fetch
  Metadata — a direct HTTP client that copies browser headers still leaves no page-load trail;
- **trusted** form input and submit intent (`event.isTrusted`), with no untrusted form events.

**Honest limitation:** this raises the cost of forgery, it does not make it impossible. A script that
fully replays a page load — cookie jar, every subresource, correct Fetch Metadata, realistic timing —
can still get through. That is inherent to client-side signals without auth or a third-party service.
Treat the verdict as a risk signal, not as proof of human identity.

---

## Tests and reports

```bash
cd bot-signal
npm test                                   # 381 unit tests
node examples/form-demo/crosscheck.mjs     # 30 server-detection cases

npx patchright install chromium            # once, for the browser harness
cd ../Test_Report
node run_tests.mjs                         # 76 end-to-end cases -> results.json
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
