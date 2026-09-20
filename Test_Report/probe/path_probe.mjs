// Captures pointer paths three ways and compares their motor-control signature.
//
//   node path_probe.mjs          -> synthetic only (SetCursorPos bezier, CDP bezier)
//   HUMAN=1 node path_probe.mjs  -> asks you to move the mouse, records a baseline
//
// Both synthetic modes reproduce the exact recipe used by every bypass script:
// quadratic bezier, one random perpendicular bow, smoothstep easing, jitter on the
// curve parameter.
import { chromium } from "../../bot-signal/node_modules/patchright/index.mjs";
import { spawn } from "node:child_process";
import { writeFile } from "node:fs/promises";
import { summarise } from "./path_metrics.mjs";

const chromePath = "C:/Program Files/Google/Chrome/Application/chrome.exe";
const PAGE = new URL("path.html", import.meta.url).href;
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
  [DllImport("user32.dll")] public static extern bool GetCursorPos(out POINT p);
  [StructLayout(LayoutKind.Sequential)] public struct POINT { public int X; public int Y; }
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] public static extern int GetWindowText(IntPtr h, System.Text.StringBuilder s, int n);
}
"@
[void][T]::SetProcessDPIAware()

function MoveHuman([int]$x2,[int]$y2){
  $p = New-Object T+POINT
  [void][T]::GetCursorPos([ref]$p)
  $x1=$p.X; $y1=$p.Y
  $dx=$x2-$x1; $dy=$y2-$y1
  $dist=[Math]::Sqrt($dx*$dx+$dy*$dy)
  if($dist -lt 3){ return }
  $steps=[int][Math]::Max(16,[Math]::Min(48,$dist/8))
  $mx=($x1+$x2)/2.0; $my=($y1+$y2)/2.0
  $px=-$dy/$dist; $py=$dx/$dist
  $sign = @(-1,1) | Get-Random
  $bow=(Get-Random -Minimum 25 -Maximum 85) * $sign
  $cx=$mx+$px*$bow; $cy=$my+$py*$bow
  for($i=1;$i -le $steps;$i++){
    $t=$i/[double]$steps
    $te=$t*$t*(3-2*$t) + (Get-Random -Minimum -25 -Maximum 25)/1000.0
    if($te -lt 0){$te=0}; if($te -gt 1){$te=1}
    $u=1-$te
    $bx=$u*$u*$x1 + 2*$u*$te*$cx + $te*$te*$x2
    $by=$u*$u*$y1 + 2*$u*$te*$cy + $te*$te*$y2
    [void][T]::SetCursorPos([int][Math]::Round($bx),[int][Math]::Round($by))
    Start-Sleep -Milliseconds (Get-Random -Minimum 6 -Maximum 27)
  }
  [void][T]::SetCursorPos($x2,$y2)
  Start-Sleep -Milliseconds (Get-Random -Minimum 300 -Maximum 500)
}
`;

const browser = await chromium.launch({
  headless: false,
  executablePath: chromePath,
  args: ["--window-position=0,0", "--window-size=1200,900"],
});
const context = await browser.newContext({ viewport: null });
const page = await context.newPage();
await page.goto(PAGE, { waitUntil: "load" });
await page.bringToFront();
await page.waitForTimeout(900);

const read = async () => {
  const raw = await page.evaluate(() => document.documentElement.dataset.path ?? "");
  return raw
    ? raw.split(";").filter(Boolean).map((entry) => {
        const [x, y, t] = entry.split(",").map(Number);
        return { x, y, t };
      })
    : [];
};
const clear = () => page.evaluate(() => {
  window.__p = [];
  delete document.documentElement.dataset.path;
});
const setMode = (text) => page.evaluate((value) => {
  document.getElementById("mode").textContent = value;
}, text);

if (HUMAN) {
  await setMode("MOVE YOUR MOUSE between the corners of this window, back and forth, for 20 seconds.");
  console.log("\n>>> Move your mouse around this window — long sweeps corner to corner, pausing briefly");
  console.log(">>> at each end, for 20 seconds. Starting now...\n");
  await clear();
  await page.waitForTimeout(20_000);
  const human = await read();
  await writeFile(new URL("human_path.json", import.meta.url), JSON.stringify(human), "utf8");
  console.log(summarise("HUMAN hand-moved mouse", human));
  await browser.close();
  process.exit(0);
}

// --- SetCursorPos bezier (C4 / C6 recipe) ----------------------------------
await setMode("capturing SetCursorPos bezier…");
await clear();
const targets = [[300, 250], [950, 700], [350, 780], [1000, 260], [400, 500], [900, 800]];
const psOut = await runPs(`${DECL}
$sb = New-Object System.Text.StringBuilder 512
[void][T]::GetWindowText([T]::GetForegroundWindow(), $sb, 512)
if ($sb.ToString() -notlike "*BSPATH*") { Write-Output ("WRONG_WINDOW::" + $sb.ToString()); exit 1 }
${targets.map(([x, y]) => `MoveHuman ${x} ${y}`).join("\n")}
Write-Output "OK"`);
await page.waitForTimeout(600);
const osPath = await read();

// --- CDP bezier (C7 / C8 recipe) -------------------------------------------
await setMode("capturing CDP bezier…");
await clear();
const cdp = await context.newCDPSession(page);
let pos = { x: 200, y: 200 };
for (const [x2, y2] of targets) {
  const { x: x1, y: y1 } = pos;
  const dist = Math.hypot(x2 - x1, y2 - y1);
  const steps = Math.max(16, Math.min(48, Math.round(dist / 8)));
  const mx = (x1 + x2) / 2;
  const my = (y1 + y2) / 2;
  const px = -(y2 - y1) / dist;
  const py = (x2 - x1) / dist;
  const bow = (25 + Math.random() * 60) * (Math.random() < 0.5 ? -1 : 1);
  const cx = mx + px * bow;
  const cy = my + py * bow;
  for (let i = 1; i <= steps; i += 1) {
    const t = i / steps;
    const te = Math.min(1, Math.max(0, t * t * (3 - 2 * t) + (Math.random() - 0.5) * 0.05));
    const u = 1 - te;
    await cdp.send("Input.dispatchMouseEvent", {
      type: "mouseMoved",
      x: u * u * x1 + 2 * u * te * cx + te * te * x2,
      y: u * u * y1 + 2 * u * te * cy + te * te * y2,
      button: "none",
      buttons: 0,
    });
    await new Promise((r) => setTimeout(r, 6 + Math.random() * 21));
  }
  await cdp.send("Input.dispatchMouseEvent", { type: "mouseMoved", x: x2, y: y2, button: "none", buttons: 0 });
  pos = { x: x2, y: y2 };
  await new Promise((r) => setTimeout(r, 350));
}
await page.waitForTimeout(600);
const cdpPath = await read();

console.log("powershell:", psOut.replaceAll("\n", " "));
console.log(summarise("A. SetCursorPos bezier (C4/C6)", osPath));
console.log(summarise("B. CDP bezier (C7/C8)", cdpPath));
await writeFile(new URL("synthetic_paths.json", import.meta.url), JSON.stringify({ osPath, cdpPath }), "utf8");

await browser.close();
