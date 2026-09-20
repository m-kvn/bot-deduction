// A human cannot type into a window that does not have focus. A CDP Input client
// can — Input.dispatchKeyEvent/dispatchMouseEvent are delivered regardless of
// whether the OS considers the window active. This measures whether the page can
// see that difference.
import { chromium } from "../../bot-signal/node_modules/patchright/index.mjs";
import { spawn } from "node:child_process";

const chromePath = "C:/Program Files/Google/Chrome/Application/chrome.exe";
const PAGE = new URL("focus.html", import.meta.url).href;

const browser = await chromium.launch({
  headless: false,
  executablePath: chromePath,
  args: ["--window-position=0,0", "--window-size=900,600"],
});
const context = await browser.newContext({ viewport: null });
const page = await context.newPage();
await page.goto(PAGE, { waitUntil: "load" });
await page.bringToFront();
await page.waitForTimeout(600);

const cdp = await context.newCDPSession(page);
const read = async () => JSON.parse(await page.evaluate(() => document.documentElement.dataset.log ?? "[]"));
const clear = () => page.evaluate(() => {
  window.__log = [];
  delete document.documentElement.dataset.log;
});

async function drive(label) {
  await clear();
  await cdp.send("Input.dispatchMouseEvent", { type: "mouseMoved", x: 400, y: 300, button: "none", buttons: 0 });
  for (const type of ["keyDown", "keyUp"]) {
    await cdp.send("Input.dispatchKeyEvent", {
      type,
      key: "a",
      code: "KeyA",
      windowsVirtualKeyCode: 65,
      nativeVirtualKeyCode: 65,
      ...(type === "keyDown" ? { text: "a" } : {}),
    });
  }
  await page.waitForTimeout(400);
  const log = await read();
  const focused = log.filter((e) => e.hasFocus).length;
  console.log(
    `${label}: events=${log.length} withFocus=${focused} withoutFocus=${log.length - focused} ` +
      `visibility=${[...new Set(log.map((e) => e.visibility))].join("/") || "-"}`,
  );
}

await drive("A. window focused    ");

// Take focus away at the OS level, leaving the Chrome window visible but inactive.
await new Promise((resolve) => {
  const child = spawn("powershell", ["-NoProfile", "-Command",
    "Add-Type -AssemblyName System.Windows.Forms; " +
    "$f = New-Object System.Windows.Forms.Form; $f.Text='BSFOCUS-STEALER'; $f.TopMost=$true; " +
    "$f.Add_Shown({ $f.Activate() }); $t = New-Object System.Windows.Forms.Timer; " +
    "$t.Interval=9000; $t.Add_Tick({ $f.Close() }); $t.Start(); [void]$f.ShowDialog()"]);
  child.unref();
  setTimeout(resolve, 2500);
});

await drive("B. window NOT focused");

await browser.close();
