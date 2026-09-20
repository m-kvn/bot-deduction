# Rejected hypothesis: CDP input is not rAF-aligned

A red-team pass showed a raw CDP `Input`-domain client driving a normal Chrome build scores human,
and that the library's console-based CDP probe never fires for it — with or without `Runtime.enable`.

The proposed fix was a timing discriminator. Chromium dispatches real pointer input aligned to the
display refresh (coalesced to roughly one `mousemove` per frame), so if `Input.dispatchMouseEvent`
skipped that pipeline, a script dispatching every 10 ms would produce sub-frame gaps that real input
cannot.

`cdp_timing_probe.mjs` measures both paths in the same window, dispatching at the same 10 ms rate:

| Source | events | median gap | min | gaps < 8 ms |
|---|---|---|---|---|
| Real OS input (`SetCursorPos`) | 50 | 16.80 ms | 12.30 ms | 0 (0%) |
| CDP `Input.dispatchMouseEvent` | 110 | 16.90 ms | 12.30 ms | 0 (0%) |

CDP input goes through the same rAF-aligned pipeline. **The hypothesis is wrong and nothing was
shipped for it.** Recorded here so it does not get proposed again.

```bash
node cdp_timing_probe.mjs   # takes over the mouse briefly
```
