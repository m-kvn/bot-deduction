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

---

## Round 3 — stealth frameworks, and the absence pattern

A third round tested the 2025–26 stealth automation frameworks. **patchright** — isolated-world
Playwright — passed out of the box at `human 0.20`, which is the off-the-shelf version of the raw-CDP
case: `pip install patchright`, no fingerprint work required.

The cause was not the fingerprint. It was that `pg.fill()` puts a whole field into the form in one
call, so the behavioral layer had almost no evidence to score — and scoring near-empty evidence as
`0.00` treats absence of evidence as evidence of humanity.

Measured against Chrome 153, the distinction is exact:

| Method | `beforeinput` events | printable keydowns |
|---|---|---|
| `pg.fill("input", "Kavin Kumar")` | **one** `insertText`, `data.length = 11` | **0** |
| real typing | one `insertText` per character, `data.length = 1` | one per character |

A keyboard delivers one character per event. Paste arrives as `insertFromPaste`, autofill as
`insertReplacementText`, drag as `insertFromDrop`, IME commits under their own types — none are
counted. The check fires when at least 12 characters, and at least 60% of the form's text, arrive in
bulk inserts with no keystroke behind them, so a mobile word-suggestion alongside real typing does not
trip it.

| Case | Before | Now |
|---|:---:|:---:|
| `patchright_test.py` | 🟢 human 0.20 | 🔴 **agent 0.84** — `146 of 146 characters arrived without a keystroke` |
| `nodriver_test.py` | 🔴 agent 0.90 | 🔴 agent 0.90 (unchanged — `synthetic-events`) |
| `pw_test.py` | 🔴 agent 1.00 | 🔴 agent 1.00 |

This is the highest-value catch in the whole exercise, because setting a field's value in one call is
how nearly every real-world form bot works — Playwright and Puppeteer `fill()`, Selenium
`send_keys` on some drivers, CDP `Input.insertText`, and plain `element.value = …`.

**TLS.** The HTTP forges present a Python/HTTP-1.1 JA4 against a Chrome UA, which is invisible on a
plain-HTTP localhost target and only becomes a signal behind an edge with `TRUST_EDGE_HEADERS=1`
populating `x-ja4`. `curl_cffi(impersonate="chrome")` closes that gap for an attacker. Browser-driven
methods are inherently immune, being Chrome. Worth enabling in any real deployment; it changes nothing
here.

**Still open:** C4, C6, C7, C8 — genuine trusted input, driven through the real page, typed character
by character. They do not use bulk insertion, so this check does not touch them.

---

## Round 4 — spreading evidence across layers

A run was reported that scored **human at 0.681**: trusted CDP input through patchright with
`--disable-blink-features=AutomationControlled`, bezier pointer paths with overshoot-and-correct,
human typing cadence with deliberate typos corrected by Backspace, Shift-as-three-events capitals,
off-centre clicks, and fingerprint patches confined to surfaces the detector does not scan for
native-function tampering. It had read the detector and patched only the blind spots.

Its three surviving tells were 0.30 instant, 0.30 behavioral and 0.35 server — **one per layer, every
one under the 0.5 bar**. The combined `1 − Π(1 − sᵢ) = 0.681` was computed, recorded and displayed,
and `server.mjs` never read it. Three independent pieces of evidence produced a confident "human".

The verdict now acts on the combined score when more than one layer contributed, with the bar set by
the kind of evidence: **0.5 when a behavioral or client signal is among it, 0.6 when it is purely
environmental**. "This desktop has no webcam" describes a machine millions of people use; "every
click released on the pixel it pressed" describes how the input was produced.

Reproduced end to end in `probe/spread_evidence.mjs` rather than only testing the numbers:

| Run | Result |
|---|---|
| A — the technique as described | 🔴 **agent 0.545, rejected** — `isWorkerWebGLInconsistent` 0.35 + `zero-jitter-clicks` 0.30, neither layer over its own threshold |
| B — same, with the two "cheap to close" tells fixed | 🟢 **human 0.00, no signals**, `review` on repetition only |

Run B is the honest result. Drifting the pointer 1–2px between `mouse.down()` and `mouse.up()`, and
dropping the fingerprint patch altogether, produces a session with **no evidence to aggregate** — 125
mouse moves, 141 keystrokes, 5 clicks, zero synthetic events, 37 seconds of observation, all genuinely
trusted. There is no threshold that catches an absence of evidence.

So the aggregate rule closes the spread-evidence gap; it does not close the technique. That is the
same wall as C4/C6/C7/C8 approached from a different direction, and what stopped Run B was the
repetition controls, not detection.

**Cost of the rule, measured.** A trackpad tap-to-click user on a desktop without a webcam scores
0.30 instant + 0.30 behavioral = 0.510 — numerically identical to a reported bypass run. Tap-to-click
produces the short-dwell, zero-movement presses `zero-jitter-clicks` looks for. `verdict_check.mjs`
prints the table for any threshold; the decision lives in `verdict.mjs`.

---

## Round 5 — key hold time closes C7

`498c48c` added two signals from an axis nothing here had looked at: the collector only ever listened
for `keydown`, so how long a key was *held* was invisible.

| Signal | Weight | Fires on |
|---|---|---|
| `synthetic-key-dwell` | 0.6 | median hold under 25 ms over 12+ pairs — `keyboard.type()` emits one atomic press, measured at 2.2 ms mean |
| `absent-key-rollover` | 0.3 | fast typing where no two keys were ever down together, gated on median flight ≤ 220 ms so hunt-and-peck is exempt |

Measured against the standing matrix:

| Case | Before | Now | Why |
|---|:---:|:---:|---|
| C7 raw CDP `Input`+`DOM` | 🟢 human 0.00 | 🔴 **agent 0.58** | `absent-key-rollover` + `teleport-mouse` |
| spread-evidence reproduction | 🔴 agent 0.545 | 🔴 **agent 0.818** | `synthetic-key-dwell` 0.6 — behavioral alone now rejects |
| C4 Win32 scan-code | 🟢 human 0.00 | 🟢 human 0.00 | unchanged, and correctly so |

C4 surviving is the informative result. It holds keys 18–47 ms, clearing the 25 ms dwell bar, and it
sends genuine Shift down/up around capitals — so keys really do overlap and `absent-key-rollover` has
nothing to report. `cdp_human.py` sets a modifier *bit* instead of dispatching a Shift key, so it
never overlaps, and that is what gives it away. The difference is a real property of how the input was
produced, not a threshold that happened to land well.

`synthetic-key-dwell` is classified as hard evidence in `verdict.mjs`: a median hold under 25 ms is a
claim about physiology, and the check already stands down for soft keyboards, IME composition and
auto-repeat. `absent-key-rollover` stays circumstantial — hunt-and-peck is real.

The same commit also fixed two false positives worth recording: an Android phone using "Request
desktop site" scored **agent 0.96**, because `isEmptyPlugins` asked the User-Agent — the one field
being spoofed — and `isTouchPrimaryDevice()` now asks the input hardware instead; and the bundled
GeoIP database is IPv4-only with a dot-splitting parser, so every IPv6 visitor collected a spurious
timezone and country mismatch (`2600:1700:…` parsed as 43,620,761,600 and the binary search returned
an Australian range for all of `2000::/3`).

Verified on this machine after pulling: 426 unit tests, 30 crosscheck, 86/86 harness, 69/69
classification cases still AGENT, zero false-positive guards failing.

**Still open: C4, C6, C8.** C8 shares `cdp_human.py`'s input path with C7 and is expected to fall the
same way, but was not re-measured in this round and is not claimed.
