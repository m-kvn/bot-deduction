import { spawn } from "node:child_process";
import { createServer } from "node:net";
import https from "node:https";
import http2 from "node:http2";
import { mkdtempSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  computeTlsFingerprints,
  getTlsBrowserProfileMismatches,
  isGreaseValue,
  parseTlsClientHello,
  readClientHelloRecords,
} from "../../bot-signal/dist/server.js";

const REPETITIONS = Number(process.env.TLS_PROBE_REPETITIONS ?? 3);
const outFile = fileURLToPath(new URL("./tls_profile_results.json", import.meta.url));

const UA = {
  chrome:
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
  edge:
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0",
  firefox: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:143.0) Gecko/20100101 Firefox/143.0",
};

const BROWSERS = [
  {
    name: "Google Chrome",
    family: "chrome",
    path: process.env.CHROME_PATH ?? "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    args: (url, profile) => [
      "--headless=new",
      `--user-data-dir=${profile}`,
      "--no-first-run",
      "--no-default-browser-check",
      "--disable-extensions",
      url,
    ],
  },
  {
    name: "Microsoft Edge",
    family: "edge",
    path: process.env.EDGE_PATH ?? "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
    args: (url, profile) => [
      "--headless=new",
      `--user-data-dir=${profile}`,
      "--no-first-run",
      "--no-default-browser-check",
      "--disable-extensions",
      url,
    ],
  },
  {
    name: "Mozilla Firefox",
    family: "firefox",
    path: process.env.FIREFOX_PATH ?? "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
    args: (url, profile) => ["--headless", "--no-remote", "--profile", profile, url],
  },
];

function startCapture() {
  const hellos = [];
  const waiters = [];
  const server = createServer((socket) => {
    const chunks = [];
    socket.on("error", () => {});
    socket.on("data", (chunk) => {
      chunks.push(chunk);
      const buffered = Buffer.concat(chunks);
      const state = readClientHelloRecords(buffered).state;
      if (state === "incomplete") return;
      const hello = state === "complete" ? parseTlsClientHello(buffered) : null;
      socket.destroy();
      if (hello) {
        hellos.push(hello);
        waiters.splice(0).forEach((resolve) => resolve());
      }
    });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      resolve({
        port: server.address().port,
        hellos,
        nextHello: (timeoutMs) =>
          new Promise((done) => {
            const timer = setTimeout(done, timeoutMs);
            waiters.push(() => {
              clearTimeout(timer);
              done();
            });
          }),
        close: () => new Promise((done) => server.close(done)),
      });
    });
  });
}

function describe(hello, family) {
  const { ja4, ja3Hash } = computeTlsFingerprints(hello);
  return {
    ja4,
    ja3Hash,
    serverName: hello.serverName ?? null,
    alpn: hello.alpn,
    supportedVersions: hello.supportedVersions.filter((value) => !isGreaseValue(value)).map((value) => value.toString(16)),
    greaseInCiphers: hello.cipherSuites.some(isGreaseValue),
    greaseInExtensions: hello.extensions.some(isGreaseValue),
    mismatchesAsChrome: getTlsBrowserProfileMismatches({ userAgent: UA.chrome, tlsClientHello: hello }),
    mismatchesAsOwnFamily: family
      ? getTlsBrowserProfileMismatches({ userAgent: UA[family], tlsClientHello: hello })
      : null,
  };
}

async function captureBrowser(browser, capture, origin) {
  const profile = mkdtempSync(join(tmpdir(), "tls-probe-"));
  const before = capture.hellos.length;
  const child = spawn(browser.path, browser.args(`https://${origin}:${capture.port}/`, profile), {
    stdio: "ignore",
    windowsHide: true,
  });
  const deadline = Date.now() + 20_000;
  while (capture.hellos.length === before && Date.now() < deadline) {
    await capture.nextHello(500);
  }
  child.kill();
  await new Promise((resolve) => setTimeout(resolve, 800));
  try {
    rmSync(profile, { recursive: true, force: true });
  } catch {
    /* profile still locked by an exiting browser */
  }
  return capture.hellos[before] ?? null;
}

async function captureScript(name, run, capture) {
  const before = capture.hellos.length;
  await run(capture.port).catch(() => {});
  const deadline = Date.now() + 10_000;
  while (capture.hellos.length === before && Date.now() < deadline) {
    await capture.nextHello(250);
  }
  return capture.hellos[before] ?? null;
}

function runProcess(command, args) {
  return new Promise((resolve) => {
    const child = spawn(command, args, { stdio: "ignore", windowsHide: true });
    child.on("error", resolve);
    child.on("exit", resolve);
    setTimeout(() => {
      child.kill();
      resolve();
    }, 8_000);
  });
}

const SCRIPTS = [
  {
    name: "Node https.get",
    run: (port) =>
      new Promise((resolve) => {
        https.get({ host: "localhost", port, rejectUnauthorized: false }, resolve).on("error", resolve);
      }),
  },
  { name: "Node fetch (undici)", run: (port) => fetch(`https://localhost:${port}/`) },
  {
    name: "Node http2.connect",
    run: (port) =>
      new Promise((resolve) => {
        const session = http2.connect(`https://localhost:${port}`, { rejectUnauthorized: false });
        session.on("error", () => resolve());
        session.on("close", () => resolve());
      }),
  },
  { name: "curl.exe (Windows, Schannel)", run: (port) => runProcess("C:\\Windows\\System32\\curl.exe", ["-sk", `https://localhost:${port}/`]) },
  { name: "PowerShell Invoke-WebRequest", run: (port) => runProcess("powershell.exe", ["-NoProfile", "-Command", `try { Invoke-WebRequest -UseBasicParsing https://localhost:${port}/ } catch {}`]) },
  { name: "Python urllib", run: (port) => runProcess("python", ["-c", `import ssl,urllib.request as u\ntry: u.urlopen('https://localhost:${port}/', context=ssl._create_unverified_context(), timeout=5)\nexcept Exception: pass`]) },
];

const capture = await startCapture();
const results = { measuredAt: new Date().toISOString(), repetitions: REPETITIONS, browsers: [], scripts: [] };

for (const browser of BROWSERS) {
  if (!existsSync(browser.path)) {
    results.browsers.push({ name: browser.name, skipped: "not installed" });
    continue;
  }
  for (const origin of ["localhost", "127.0.0.1"]) {
    for (let attempt = 0; attempt < REPETITIONS; attempt += 1) {
      const hello = await captureBrowser(browser, capture, origin);
      results.browsers.push({
        name: browser.name,
        origin,
        attempt: attempt + 1,
        ...(hello ? describe(hello, browser.family) : { error: "no ClientHello captured" }),
      });
      console.log(`${browser.name.padEnd(16)} ${origin.padEnd(10)} #${attempt + 1} ${hello ? computeTlsFingerprints(hello).ja4 : "none"}`);
    }
  }
}

for (const script of SCRIPTS) {
  const hello = await captureScript(script.name, script.run, capture);
  results.scripts.push({ name: script.name, ...(hello ? describe(hello, null) : { error: "no ClientHello captured" }) });
  console.log(`${script.name.padEnd(30)} ${hello ? computeTlsFingerprints(hello).ja4 : "none"}`);
}

await capture.close();
writeFileSync(outFile, `${JSON.stringify(results, null, 2)}\n`);

const browserFalsePositives = results.browsers.filter((entry) => entry.mismatchesAsOwnFamily?.length > 0);
const scriptsCaught = results.scripts.filter((entry) => entry.mismatchesAsChrome?.length > 0);
console.log("");
console.log(`browser handshakes measured: ${results.browsers.filter((entry) => entry.ja4).length}`);
console.log(`browser handshakes flagged against their own User-Agent: ${browserFalsePositives.length}`);
console.log(`scripted handshakes flagged when claiming Chrome: ${scriptsCaught.length}/${results.scripts.filter((entry) => entry.ja4).length}`);
console.log(`written to ${outFile}`);
process.exit(browserFalsePositives.length === 0 ? 0 : 1);
