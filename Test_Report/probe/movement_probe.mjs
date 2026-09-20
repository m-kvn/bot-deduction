import { chromium } from "../../bot-signal/node_modules/patchright/index.mjs";
import { spawn } from "node:child_process";

const chromePath = "C:/Program Files/Google/Chrome/Application/chrome.exe";
const PAGE = new URL("movement.html", import.meta.url).href;

function runPs(s) {
  return new Promise((r) => {
    const c = spawn("powershell", ["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", s]);
    let o = ""; c.stdout.on("data", (d) => (o += d)); c.stderr.on("data", (d) => (o += d));
    c.on("exit", () => r(o.trim()));
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
[void][T]::SetProcessDPIAware()`;

const browser = await chromium.launch({ headless: false, executablePath: chromePath, args: ["--window-position=0,0", "--window-size=1100,800"] });
const context = await browser.newContext({ viewport: null });
const page = await context.newPage();
await page.goto(PAGE, { waitUntil: "load" });
await page.bringToFront();
await page.waitForTimeout(800);

const read = async () => JSON.parse(await page.evaluate(() => document.documentElement.dataset.m ?? "[]"));
const clear = () => page.evaluate(() => { window.__m = []; delete document.documentElement.dataset.m; });

function report(label, rows) {
  const moves = rows.filter((r) => r[0] !== "DOWN");
  if (moves.length === 0) return `${label}: no moves`;
  const zeroMovement = moves.filter((r) => r[0] === 0 && r[1] === 0).length;
  const pressures = [...new Set(moves.map((r) => r[2]))];
  const coalesced = moves.map((r) => r[3]);
  const down = rows.find((r) => r[0] === "DOWN");
  return [
    `${label}:`,
    `  moves=${moves.length}  movementX/Y both zero: ${zeroMovement} (${((zeroMovement / moves.length) * 100).toFixed(0)}%)`,
    `  sample movementX values: ${moves.slice(2, 8).map((r) => r[0]).join(", ")}`,
    `  pressure values seen: ${pressures.join(", ")}`,
    `  coalesced/move avg=${(coalesced.reduce((a, b) => a + b, 0) / coalesced.length).toFixed(2)}`,
    down ? `  pointerdown pressure=${down[3]} movement=${down[1]},${down[2]}` : "  no pointerdown",
  ].join(String.fromCharCode(10));
}

await clear();
const cdp = await context.newCDPSession(page);
for (let i = 0; i < 40; i += 1) {
  await cdp.send("Input.dispatchMouseEvent", { type: "mouseMoved", x: 200 + i * 12, y: 300 + (i % 9) * 5, button: "none", buttons: 0 });
  await new Promise((r) => setTimeout(r, 12));
}
await cdp.send("Input.dispatchMouseEvent", { type: "mousePressed", x: 680, y: 340, button: "left", clickCount: 1 });
await cdp.send("Input.dispatchMouseEvent", { type: "mouseReleased", x: 680, y: 340, button: "left", clickCount: 1 });
await page.waitForTimeout(500);
const cdpRows = await read();

await clear();
const moves = [];
for (let i = 0; i < 40; i += 1) moves.push(`[void][T]::SetCursorPos(${250 + i * 12}, ${420 + (i % 9) * 5}); Start-Sleep -Milliseconds 12`);
const ps = await runPs(`${DECL}
$sb = New-Object System.Text.StringBuilder 512
[void][T]::GetWindowText([T]::GetForegroundWindow(), $sb, 512)
if ($sb.ToString() -notlike "*BSMOVE*") { Write-Output ("WRONG::" + $sb.ToString()); exit 1 }
${moves.join(String.fromCharCode(10))}
Write-Output "OK"`);
await page.waitForTimeout(500);
const osRows = await read();

console.log("powershell:", ps.replaceAll(String.fromCharCode(10), " "));
console.log(report("A. CDP Input.dispatchMouseEvent (C7/C8)", cdpRows));
console.log(report("B. SetCursorPos real OS input (C4/C6)", osRows));
await browser.close();
