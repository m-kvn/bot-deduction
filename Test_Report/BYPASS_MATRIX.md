# Bypass matrix — measured, not inherited

Every case below was executed against the current build on `http://localhost:8799`, and every verdict
was read back from `GET /api/submissions`, not from the screen. Scripts are the red team's own, run
unmodified, from `a local bot-signal-bypass folder kept outside this repo`.

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
