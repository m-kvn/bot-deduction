// Does Chromium dispatch CDP-injected pointer input the same way it dispatches
// real OS input? Real mousemove is rAF-aligned (coalesced to one per frame), so
// if CDP dispatch is not, the inter-event gaps give it away.
import { chromium } from "../../bot-signal/node_modules/patchright/index.mjs";
import { spawn } from "node:child_process";

const chromePath = "C:/Program Files/Google/Chrome/Application/chrome.exe";

const PAGE = new URL("timing.html", import.meta.url).href;

function runPs(script) {
  return new Promise((resolve) => {
    const child = spawn("powershell", ["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script]);
    let out = "";
    child.stdout.on("data", (c) => (out += c));
    child.stderr.on("data", (c) => (out += c));
    child.on("exit", () => resolve(out.trim()));
  });
}

const DECL = `
Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices;
public class T {
  [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int X, int Y);
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] public static extern int GetWindowText(IntPtr h, System.Text.StringBuilder s, int n);
}
"@
[void][T]::SetProcessDPIAware()
`;

function stats(label, times) {
  const gaps = [];
  for (let i = 1; i < times.length; i += 1) gaps.push(times[i] - times[i - 1]);
  if (gaps.length === 0) return `${label}: no events`;
  const sorted = [...gaps].sort((a, b) => a - b);
  const median = sorted[Math.floor(sorted.length / 2)];
  const subFrame = gaps.filter((g) => g > 0 && g < 8).length;
  const nearFrame = gaps.filter((g) => g >= 8 && g <= 25).length;
  return [
    `${label}:`,
    `  events=${times.length} gaps=${gaps.length}`,
    `  median gap=${median.toFixed(2)}ms  min=${sorted[0].toFixed(2)}  max=${sorted[sorted.length - 1].toFixed(2)}`,
    `  gaps <8ms: ${subFrame} (${((subFrame / gaps.length) * 100).toFixed(0)}%)`,
    `  gaps 8-25ms: ${nearFrame} (${((nearFrame / gaps.length) * 100).toFixed(0)}%)`,
  ].join("\n");
}

const browser = await chromium.launch({
  headless: false,
  executablePath: chromePath,
  args: ["--window-position=0,0", "--window-size=1100,800"],
});
const context = await browser.newContext({ viewport: null });
const page = await context.newPage();
await page.goto(PAGE, { waitUntil: "load" });
await page.bringToFront();
await page.waitForTimeout(1000);

const readTimes = async () => {
  const raw = await page.evaluate(() => document.documentElement.dataset.t ?? "");
  return raw ? raw.split(",").map(Number) : [];
};
const clear = () => page.evaluate(() => {
  window.__t = [];
  delete document.documentElement.dataset.t;
  delete document.documentElement.dataset.n;
});

// --- A: real OS input, ~10ms apart -----------------------------------------
await clear();
const moves = [];
for (let i = 0; i < 60; i += 1) moves.push(`[void][T]::SetCursorPos(${300 + i * 6}, ${400 + (i % 7)}); Start-Sleep -Milliseconds 10`);
const title = await runPs(`${DECL}
$sb = New-Object System.Text.StringBuilder 512
[void][T]::GetWindowText([T]::GetForegroundWindow(), $sb, 512)
if ($sb.ToString() -notlike "*BSTIMING*") { Write-Output ("WRONG_WINDOW::" + $sb.ToString()); exit 1 }
${moves.join("\n")}
Write-Output "OK"`);
await page.waitForTimeout(500);
const osTimes = await readTimes();

// --- B: CDP-injected input, ~10ms apart ------------------------------------
await clear();
const cdp = await context.newCDPSession(page);
for (let i = 0; i < 60; i += 1) {
  await cdp.send("Input.dispatchMouseEvent", {
    type: "mouseMoved",
    x: 300 + i * 6,
    y: 400 + (i % 7),
    button: "none",
    buttons: 0,
  });
  await new Promise((r) => setTimeout(r, 10));
}
await page.waitForTimeout(500);
const cdpTimes = await readTimes();

console.log("powershell:", title.replaceAll("\n", " "));
console.log(stats("A. real OS input (SetCursorPos, 10ms apart)", osTimes));
console.log(stats("B. CDP Input.dispatchMouseEvent (10ms apart)", cdpTimes));

await browser.close();
