// Real mouse hardware polls at a fixed rate, so its raw (pre-coalescing) events
// are machine-regular. Injected input — SetCursorPos or CDP — is spaced by
// whatever the script slept for. This measures both, and can also capture a
// genuine hand-moved baseline with HUMAN=1.
import { chromium } from "../../bot-signal/node_modules/patchright/index.mjs";
import { spawn } from "node:child_process";

const chromePath = "C:/Program Files/Google/Chrome/Application/chrome.exe";
const PAGE = new URL("coalesced.html", import.meta.url).href;
const HUMAN = process.env.HUMAN === "1";

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

function report(label, counts, raw) {
  if (counts.length === 0) return `${label}: no events`;
  const gaps = [];
  for (let i = 1; i < raw.length; i += 1) {
    const gap = raw[i] - raw[i - 1];
    if (gap > 0) gaps.push(gap);
  }
  const sorted = [...gaps].sort((a, b) => a - b);
  const median = sorted.length ? sorted[Math.floor(sorted.length / 2)] : 0;
  const mean = gaps.reduce((a, b) => a + b, 0) / (gaps.length || 1);
  const sd = Math.sqrt(gaps.reduce((a, b) => a + (b - mean) ** 2, 0) / (gaps.length || 1));
  const multi = counts.filter((c) => c > 1).length;
  const avgCount = counts.reduce((a, b) => a + b, 0) / counts.length;
  return [
    `${label}:`,
    `  pointermove=${counts.length}  raw=${raw.length}  avg coalesced/move=${avgCount.toFixed(2)}`,
    `  moves with >1 coalesced: ${multi} (${((multi / counts.length) * 100).toFixed(0)}%)`,
    `  raw gap median=${median.toFixed(2)}ms mean=${mean.toFixed(2)}ms sd=${sd.toFixed(2)}ms cv=${(sd / (mean || 1)).toFixed(3)}`,
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
await page.waitForTimeout(900);

const read = async () => ({
  counts: (await page.evaluate(() => document.documentElement.dataset.c ?? ""))
    .split(",").filter(Boolean).map(Number),
  raw: (await page.evaluate(() => document.documentElement.dataset.raw ?? ""))
    .split(",").filter(Boolean).map(Number),
});
const clear = () => page.evaluate(() => {
  window.__c = []; window.__raw = [];
  delete document.documentElement.dataset.c;
  delete document.documentElement.dataset.raw;
});

if (HUMAN) {
  console.log("\n>>> Move your mouse around this window continuously for 8 seconds. Starting now...\n");
  await page.waitForTimeout(8000);
  const { counts, raw } = await read();
  console.log(report("HUMAN hand-moved mouse", counts, raw));
  await browser.close();
  process.exit(0);
}

// --- SetCursorPos (C4 / C6 style) ------------------------------------------
await clear();
const moves = [];
for (let i = 0; i < 80; i += 1) {
  const sleep = 6 + Math.floor(Math.random() * 21);
  moves.push(`[void][T]::SetCursorPos(${250 + i * 8}, ${350 + (i % 11) * 3}); Start-Sleep -Milliseconds ${sleep}`);
}
const psOut = await runPs(`${DECL}
$sb = New-Object System.Text.StringBuilder 512
[void][T]::GetWindowText([T]::GetForegroundWindow(), $sb, 512)
if ($sb.ToString() -notlike "*BSCOALESCE*") { Write-Output ("WRONG_WINDOW::" + $sb.ToString()); exit 1 }
${moves.join("\n")}
Write-Output "OK"`);
await page.waitForTimeout(600);
const os = await read();

// --- CDP Input.dispatchMouseEvent (C7 / C8 style) --------------------------
await clear();
const cdp = await context.newCDPSession(page);
for (let i = 0; i < 80; i += 1) {
  await cdp.send("Input.dispatchMouseEvent", {
    type: "mouseMoved",
    x: 250 + i * 8,
    y: 350 + (i % 11) * 3,
    button: "none",
    buttons: 0,
  });
  await new Promise((r) => setTimeout(r, 6 + Math.floor(Math.random() * 21)));
}
await page.waitForTimeout(600);
const cdpResult = await read();

console.log("powershell:", psOut.replaceAll("\n", " "));
console.log(report("A. SetCursorPos injection (C4/C6)", os.counts, os.raw));
console.log(report("B. CDP Input.dispatchMouseEvent (C7/C8)", cdpResult.counts, cdpResult.raw));

await browser.close();
