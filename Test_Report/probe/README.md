# OS input-injection probe

Two scripts, both of which take over the mouse and keyboard while they run.

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
