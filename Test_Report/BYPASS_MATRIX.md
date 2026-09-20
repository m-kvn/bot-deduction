# Bypass matrix — measured, not inherited

Every case below was executed against the current build on `http://localhost:8799`, and every verdict
was read back from `GET /api/submissions`, not from the screen. Scripts are the red team's own, run
unmodified, from `C:\Users\kavin.kum016\bot-signal-bypass\`.

| # | Method | Verdict | Score | Outcome | Decisive signals |
|---|---|:---:|:---:|:---:|---|
| C1 | HTTP forge, no page session | 🔴 agent | 1.00 | rejected | invalid-challenge, invalid-request-provenance, invalid-page-session, missing-behavioral-samples, missing-browser-headers |
| C2 | HTTP full session replay + forged payload | 🔴 agent | 0.99 | rejected | missing-behavioral-samples, impossible-observation-window |
| C3 | Win32 `KEYEVENTF_UNICODE` (PowerShell → Comet) | 🔴 agent | 0.94 | rejected | injected-key-input, untrusted-form-interaction |
| C4 | Win32 `KEYEVENTF_SCANCODE` (PowerShell → Comet) | 🟢 **human** | 0.00 | review | — |
| C5 | pyautogui, stock | 🔴 agent | 0.94 | rejected | injected-key-input, untrusted-form-interaction |
| C6 | pyautogui, scan-code patched | 🟢 **human** | 0.00 | review | — |
| C7 | Raw CDP, `Input`+`DOM` only | 🟢 **human** | 0.30 | accepted | isSuspiciousWindowDimensions (below threshold) |
| C8 | Raw CDP + `Runtime.enable` | 🟢 **human** | 0.00 | accepted | — |
| C9 | CDP page-context forge | 🔴 agent | 0.99 | rejected | missing-behavioral-samples, impossible-observation-window |
| C10 | Chrome `--enable-automation` | 🔴 agent | 1.00 | rejected | isWebDriver, isHeadless, teleport-mouse |

**6 caught, 4 still classified human.** C4 and C6 reached `outcome: review` on the repetition
controls, so they are no longer silently accepted; C7 and C8 were first-time content in their window
and were accepted.

Suites alongside this run: 400 unit tests, 30 crosscheck cases, 82 harness cases — all passing.

## The four that are still human

C4, C6, C7 and C8 all drive a real browser with genuinely trusted events, a real page load, and input
a page cannot distinguish from a hand's. Three detection hypotheses were measured and rejected
(rAF alignment, coalesced-event cadence, `document.hasFocus()` under CDP — see `probe/CDP_TIMING.md`
and the README).

A fourth was built and **does not work in practice**: `generated-pointer-path`. Every one of these
scripts moves the pointer the same way — a quadratic Bézier with one random perpendicular bow,
smoothstep easing, and jitter applied to the curve *parameter*, which slides each point along the
curve instead of off it. That leaves every sample on a single convex arc, which is measurable:

| Source | arc residual | arc crossings |
|---|---|---|
| Bot, long clean sweeps (`probe/path_probe.mjs`) | 0.22–0.25 px | 0 |
| Bot, real C4 form-fill run | median 0.45 px, max 1.66 px | 0–2 |

The geometry holds, but a real form fill produces short reaches where `SetCursorPos` integer
rounding through 1.25× display scaling contributes ~0.45 px of noise on its own — the same order as
the signal. Catching C4 would mean loosening the threshold to ~2 px and allowing 2 crossings, and
**whether that is safe depends on where a human hand actually sits, which has not been measured**.
The signal ships with thresholds that only hold for long reaches, so it fires on none of the cases
above. It is not a fix and is not counted as one.

To calibrate it, capture a baseline and compare:

```bash
cd Test_Report/probe
HUMAN=1 node path_probe.mjs    # 20 s of real mouse movement, writes human_path.json
```

If the human median lands clearly above ~2 px the thresholds in
`bot-signal/src/behavioral/analysis.ts` (`MAX_GENERATED_ARC_RESIDUAL`, `MIN_ARC_EXCURSION_PX`) can be
opened up to match. If it does not, the metric does not separate hand from Bézier on this hardware
and should be removed.

---

## Round 2 — reverse-API forge, and the scraping toolkit

A second round added a forger that reads the detector bundle and **authors a clean synthetic sample
stream** rather than a summary, defeating the server-side recomputation by giving it honest-looking
data to re-score. Measured against the current build:

| Case | Method | Before | Now |
|---|---|:---:|:---:|
| `reverse_samples.py` | replay + forged sample stream | 🟢 human 0.00 | 🔴 **agent 0.999** |
| `reverse_samples_httpx.py` | same, async httpx transport | 🟢 human 0.00 | 🔴 **agent 0.999** |
| `pw_test.py` | Playwright headless | 🔴 agent 1.00 | 🔴 agent 1.00 |
| `cdp_probe.py` (#15) | `navigator.platform` spoof | 🔴 agent 0.93 | 🔴 agent 0.93 |
| `cdp_probe.py` (#8) | XHR interception | recon only | recon only |

Closed by three additions, all local:

1. **Proof of work** — every challenge carries a hash puzzle (16 bits ≈ 0.12 s, escalating past the
   abuse threshold to a 22-bit ceiling). The forger sends no nonce.
2. **Nonce-chained telemetry beacons** — the page reports every 2 s and the server timestamps each
   arrival on its own clock, so a claimed observation window must be matched by the session having
   actually reported across it. The forger sleeps in front of an offline-authored history and
   produces `0ms across 0 beacons`.
3. **Wall-clock sample timestamps** — the collector stamps `Date.now()`; an authored stream starts
   near zero.

On the 15-technique scraping toolkit the conclusion is unchanged and worth stating plainly: transport,
DOM parsing, boilerplate removal, structured data, caching and markdown conversion **do not move the
verdict at all** on a form-submission target. Fingerprint automation (#2) and spoofing (#15) actively
hurt the attacker; UA/IP rotation (#14) breaks the IP+UA-pinned session. The verdict is decided by the
sample stream and the session gates, not by how the page is fetched or parsed.

**Note on #8.** Wire interception now also reveals `POST /api/telemetry`. The beacon protocol is not
secret and can be replicated — doing so costs the attacker a live, stateful session emitting a valid
nonce chain across real wall-clock time, which is the intended price, not an accident.

## Still open, unchanged

C4, C6, C7 and C8 drive the real page, so the page solves the proof of work and beacons on their
behalf. Nothing in round 2 touches them, and nothing is expected to: they submit genuine samples of
input a browser cannot distinguish from a hand's.
