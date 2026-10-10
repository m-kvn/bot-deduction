# Measurement probes

The two OS input-injection scripts take over the mouse and keyboard while they run; the TLS and
pointer probes at the end do not.

## `probe.mjs` — what does Chromium report for injected keystrokes?

Opens `probe.html` in a real Chrome window, injects three characters with
`SendInput` + `KEYEVENTF_UNICODE`, then presses one key through the scan-code path as a control,
and prints the `KeyboardEvent` fields the page saw.

```bash
node probe.mjs
```

Result on Chrome 140 / Windows 11:

| Input method | `key` | `code` | `keyCode` | `isTrusted` |
|---|---|---|---|---|
| `SendInput` + `KEYEVENTF_UNICODE` | `K` | *(empty)* | `231` (`VK_PACKET`) | `true` |
| Scan-code key press | `b` | `KeyB` | `66` | `true` |

This measurement is what the `injected-key-input` signal is built on.

## `verify_real_injection.mjs` — does the app catch a real injection run?

Opens the live form, calibrates physical cursor coordinates against page coordinates by moving to
two known screen points and reading back what the page saw, then hands the field positions to
`real_injection.ps1` — curved `SetCursorPos` pointer paths, randomised per-character delays,
`mouse_event` clicks, `KEYEVENTF_UNICODE` typing. Prints the verdict the server returned.

```bash
TARGET=http://127.0.0.1:8799 node verify_real_injection.mjs
```

Expected: `HTTP 403`, `verdict: agent`, on `behavioral:injected-key-input` and
`client:untrusted-form-interaction`.

> Point `TARGET` at a port you started yourself. A forwarder bound to `127.0.0.1` (Cursor and VS Code
> both do this) takes precedence over a server bound to `0.0.0.0` on the same port, so `localhost`
> can quietly reach a different, older process than the one you just restarted.

## `tls_profile_probe.mjs` — what do real browsers put in a ClientHello?

Does **not** take over input: browsers run headless with throwaway profiles. A raw TCP listener
reads each ClientHello, parses it with the library, and closes the connection, so no certificate is
needed. Each installed browser connects to a domain origin (`localhost`, SNI sent) and an IP origin
(`127.0.0.1`, no SNI), three times each; common scripted clients connect once. Results are written
to `tls_profile_results.json`.

```bash
cd ../../bot-signal && npm run build && cd ../Test_Report/probe
node tls_profile_probe.mjs           # TLS_PROBE_REPETITIONS=3 by default
```

Result on Windows 11 (Chrome, Edge and Firefox current stable):

| Client | JA4 (domain / IP origin) | ALPN | GREASE |
|---|---|---|---|
| Google Chrome | `t13d1517h2` / `t13i1516h2` | h2, http/1.1 | yes |
| Microsoft Edge | `t13d1516h2` / `t13i1515h2` | h2, http/1.1 | yes |
| Mozilla Firefox | `t13d1517h2` / `t13i1516h2` | h2, http/1.1 | no |
| Node `https.get` | `t13d521100` | none | no |
| Node `fetch` (undici) | `t13d5212h1` | http/1.1 | no |
| Node `http2.connect` | `t13d5212h2` | h2 | no |
| `curl.exe` (Schannel) | `t13d2012h1` | http/1.1 | no |
| PowerShell `Invoke-WebRequest` | `t13d201100` | none | no |
| Python `urllib` | `t13d181100` | none | no |

All 18 browser handshakes pass `tls-browser-profile-mismatch` against their own User-Agent; all 6
scripted clients fail it when they claim Chrome. Node `http2.connect` offers TLS 1.3 and `h2` like
a browser and is caught only by the missing GREASE — which is also why a real Firefox spoofing a
Chrome User-Agent is flagged, and why the signal stays at 0.45.

## `pointer_probe.mjs` — what pressure does a synthesised mouse press carry?

Does **not** take over input. Opens a test page in Patchright's Chromium, presses a button through
each automation path, and records the `PointerEvent`/`MouseEvent` fields the page saw. Results are
written to `pointer_probe_results.json`.

```bash
node pointer_probe.mjs                # HEADFUL=1 for a visible window, CHROME_PATH for another build
```

Result on Chromium 149:

| Input path | `pointerdown.pressure` | `pointerType` |
|---|---|---|
| Patchright `page.mouse.click` / `locator.click` | 0.5 | mouse |
| Raw CDP `Input.dispatchMouseEvent`, no `force` | **0** | mouse |
| Raw CDP `Input.dispatchMouseEvent`, `force: 0.5` | 0.5 | mouse |
| CDP `Input.dispatchTouchEvent` | 1 | touch |
| `element.click()`, keyboard Enter | *(no pointerdown)* | — |

The same zero was measured end to end through the demo form for Puppeteer 25 and Selenium 4.51
(ChromeDriver), which dispatch mouse input without `force`. The Pointer Events spec assigns 0.5 to a
pressed button on hardware that cannot sense pressure, which is what Playwright and Patchright send.
`synthetic-pointer-pressure` fires when at least half of the trusted mouse presses are weightless.
No real-hardware baseline has been captured yet, so it is weighted as supporting evidence (0.45)
and never decides a verdict alone; Apple platforms, where trackpad force reporting differs, are not
recorded at all.
