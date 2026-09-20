import { chromium } from "../../bot-signal/node_modules/patchright/index.mjs";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { writeFile } from "node:fs/promises";

const chromePath = "C:/Program Files/Google/Chrome/Application/chrome.exe";
const pageUrl = new URL("probe.html", import.meta.url).href;

const browser = await chromium.launch({ headless: false, executablePath: chromePath });
const context = await browser.newContext({ viewport: { width: 900, height: 500 } });
const page = await context.newPage();
await page.goto(pageUrl, { waitUntil: "load" });
await page.locator("#f").click();
await page.waitForTimeout(700);

const ps = `
$ErrorActionPreference='Stop'
Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices;
public class P {
  [StructLayout(LayoutKind.Sequential)] public struct KEYBDINPUT { public ushort wVk; public ushort wScan; public uint dwFlags; public uint time; public IntPtr dwExtraInfo; }
  [StructLayout(LayoutKind.Sequential)] public struct MOUSEINPUT { public int dx; public int dy; public uint mouseData; public uint dwFlags; public uint time; public IntPtr dwExtraInfo; }
  [StructLayout(LayoutKind.Explicit)] public struct INPUT { [FieldOffset(0)] public uint type; [FieldOffset(8)] public MOUSEINPUT mi; [FieldOffset(8)] public KEYBDINPUT ki; }
  [DllImport("user32.dll")] public static extern uint SendInput(uint n, INPUT[] p, int cb);
  [DllImport("user32.dll")] public static extern void keybd_event(byte vk, byte scan, uint f, IntPtr e);
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] public static extern int GetWindowText(IntPtr h, System.Text.StringBuilder s, int n);
  public static void Uni(char c, bool up) {
    INPUT[] i = new INPUT[1];
    i[0].type = 1; i[0].ki.wVk = 0; i[0].ki.wScan = (ushort)c;
    i[0].ki.dwFlags = up ? (uint)(0x0004|0x0002) : (uint)0x0004;
    SendInput(1, i, Marshal.SizeOf(typeof(INPUT)));
  }
}
"@
$sb = New-Object System.Text.StringBuilder 512
[void][P]::GetWindowText([P]::GetForegroundWindow(), $sb, 512)
$title = $sb.ToString()
if ($title -notlike "*BSPROBE-WINDOW*") { Write-Output "WRONG_WINDOW::$title"; exit 1 }
foreach ($c in "Kav".ToCharArray()) {
  [P]::Uni($c,$false); Start-Sleep -Milliseconds 40; [P]::Uni($c,$true); Start-Sleep -Milliseconds 90
}
Start-Sleep -Milliseconds 150
# control sample: a real virtual-key press (VK_B = 0x42) via scancode path
[P]::keybd_event(0x42,0x30,0,[IntPtr]::Zero); Start-Sleep -Milliseconds 40
[P]::keybd_event(0x42,0x30,2,[IntPtr]::Zero)
Write-Output "OK::$title"
`;
await writeFile(new URL("inject.ps1", import.meta.url), ps, "utf8");

const psOut = await new Promise((resolve) => {
  const child = spawn("powershell", ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
    fileURLToPath(new URL("inject.ps1", import.meta.url))]);
  let out = "";
  child.stdout.on("data", (c) => (out += c));
  child.stderr.on("data", (c) => (out += c));
  child.on("exit", () => resolve(out.trim()));
});

await page.waitForTimeout(600);
const log = await page.locator("#out").textContent();
const typed = await page.locator("#f").inputValue();
console.log("typed value:", JSON.stringify(typed));
console.log("powershell:", psOut);
console.log(log);
await browser.close();
