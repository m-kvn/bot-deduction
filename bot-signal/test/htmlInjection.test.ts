import { afterEach, describe, expect, it } from "vitest";
import http from "node:http";
import zlib from "node:zlib";
import type { AddressInfo } from "node:net";
import type { IncomingMessage, ServerResponse } from "node:http";
import { findBodyCloseIndex, injectHoneytokenIntoResponse, injectMarkupIntoFetchResponse } from "../src/server/index.js";

const LINK = '<a hidden href="/trap">.</a>';

interface Served {
  url: string;
  close: () => Promise<void>;
}

const running: Served[] = [];

async function serve(handler: (req: IncomingMessage, res: ServerResponse) => unknown): Promise<Served> {
  const server = http.createServer((req, res) => {
    Promise.resolve(handler(req, res)).catch((error: unknown) => {
      res.statusCode = 500;
      res.end(String(error));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const served = {
    url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
  running.push(served);
  return served;
}

async function fetchWith(handler: (res: ServerResponse) => unknown, init?: RequestInit) {
  const { url } = await serve((_req, res) => {
    injectHoneytokenIntoResponse(res, LINK);
    return handler(res);
  });
  const response = await fetch(url, init);
  return { response, body: await response.text() };
}

describe("findBodyCloseIndex", () => {
  it("finds the closing body tag outside scripts, styles and comments", () => {
    const html =
      "<html><head><style>a::after{content:'</body>'}</style></head><body>" +
      "<script>document.write('</body>')</script><!-- </body> --><p>x</p></BODY></html>";
    const lower = html.toLowerCase();
    expect(findBodyCloseIndex(lower)).toBe(lower.lastIndexOf("</body>"));
  });

  it("reports how far it has scanned so a stream can resume", () => {
    const state = { closer: null, position: 0 };
    expect(findBodyCloseIndex("<body><script>var a = 1;", state)).toBe(-1);
    expect(state.closer).toBe("</script");
    expect(state.position).toBe("<body><script>var a = 1;".length - "</script".length + 1);
    const plain = { closer: null, position: 0 };
    expect(findBodyCloseIndex("<p>no close tag here at all</p>", plain)).toBe(-1);
    expect(plain.position).toBe("<p>no close tag here at all</p>".length - 8);
  });
});

describe("injectHoneytokenIntoResponse", () => {
  afterEach(async () => {
    await Promise.all(running.splice(0).map((served) => served.close()));
  });

  it("injects into a single-shot page and corrects the declared Content-Length", async () => {
    const page = "<!doctype html><html><body><h1>Hi</h1></body></html>";
    const { response, body } = await fetchWith((res) => {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Content-Length": String(page.length) });
      res.end(page);
    });
    expect(body).toBe(page.replace("</body>", `${LINK}</body>`));
    expect(response.headers.get("content-length")).toBe(String(Buffer.byteLength(body)));
  });

  it("streams a page without Content-Length instead of holding it back", async () => {
    let release: () => void = () => undefined;
    const gate = new Promise<void>((resolve) => (release = resolve));
    const { url } = await serve(async (_req, res) => {
      injectHoneytokenIntoResponse(res, LINK);
      res.setHeader("content-type", "text/html");
      res.write("<html><head><title>streamed</title></head><body><p>first</p>");
      await gate;
      res.write("<p>second</p></bo");
      res.end("dy></html>");
    });
    const response = await fetch(url);
    const reader = (response.body as ReadableStream<Uint8Array>).getReader();
    const first = new TextDecoder().decode((await reader.read()).value);
    expect(first.startsWith("<html><head><title>streamed</title>")).toBe(true);
    release();
    let rest = "";
    for (let chunk = await reader.read(); !chunk.done; chunk = await reader.read()) {
      rest += new TextDecoder().decode(chunk.value);
    }
    expect(first + rest).toBe(
      `<html><head><title>streamed</title></head><body><p>first</p><p>second</p>${LINK}</body></html>`,
    );
  });

  it("splices bytes, so a non-UTF-8 page is not re-encoded", async () => {
    const page = Buffer.concat([Buffer.from("<body>caf"), Buffer.from([0xe9]), Buffer.from("</body>")]);
    const { url } = await serve((_req, res) => {
      injectHoneytokenIntoResponse(res, LINK);
      res.writeHead(200, { "content-type": "text/html; charset=windows-1252" });
      res.end(page);
    });
    const bytes = Buffer.from(await (await fetch(url)).arrayBuffer());
    expect(bytes.equals(Buffer.concat([Buffer.from("<body>caf"), Buffer.from([0xe9]), Buffer.from(LINK), Buffer.from("</body>")]))).toBe(true);
  });

  it("keeps duplicate array headers and honours a status message", async () => {
    const page = "<body></body>";
    const { response, body } = await fetchWith((res) => {
      res.writeHead(200, "Fine", [
        "Content-Type",
        "text/html",
        "Set-Cookie",
        "a=1",
        "Set-Cookie",
        "b=2",
        "Content-Length",
        String(page.length),
      ]);
      res.end(page, "latin1");
    });
    expect(body).toBe(`<body>${LINK}</body>`);
    expect(response.statusText).toBe("Fine");
    expect(response.headers.getSetCookie()).toEqual(["a=1", "b=2"]);
    expect(response.headers.get("content-length")).toBe(String(body.length));

    const objectHead = await fetchWith((res) => {
      res.setHeader("content-type", "text/html");
      res.writeHead(200, { "X-Test": "1", "Content-Length": String(page.length) });
      res.end(page);
    });
    expect(objectHead.body).toBe(`<body>${LINK}</body>`);
    expect(objectHead.response.headers.get("x-test")).toBe("1");
    expect(objectHead.response.headers.get("content-length")).toBe(String(objectHead.body.length));

    const setHeaderLength = await fetchWith((res) => {
      res.setHeader("content-type", "text/html");
      res.setHeader("content-length", String(page.length));
      res.write("<bo");
      res.write("dy>");
      res.end("</body>");
    });
    expect(setHeaderLength.body).toBe(`<body>${LINK}</body>`);
    expect(setHeaderLength.response.headers.get("content-length")).toBe(String(setHeaderLength.body.length));

    const flat = await fetchWith((res) => {
      res.writeHead(200, ["Content-Type", "text/html"]);
      res.end("<body></body>");
    });
    expect(flat.body).toBe(`<body>${LINK}</body>`);
  });

  it("runs writeHead hooks and write wrappers that later middleware installs", async () => {
    const { url } = await serve((req, res) => {
      injectHoneytokenIntoResponse(res, LINK);
      const writeHead = res.writeHead;
      res.writeHead = function hooked(this: ServerResponse, ...args: unknown[]) {
        res.setHeader("set-cookie", "session=1");
        return (writeHead as (...rest: unknown[]) => ServerResponse).apply(res, args);
      } as ServerResponse["writeHead"];
      const end = res.end;
      res.end = function wrapped(this: ServerResponse, chunk?: unknown, ...rest: unknown[]) {
        return (end as (...args: unknown[]) => ServerResponse).call(res, `${String(chunk)}<!--tail-->`, ...rest);
      } as ServerResponse["end"];
      if (req.url === "/json") {
        res.setHeader("content-type", "application/json");
        res.end('{"ok":true}');
        return;
      }
      res.setHeader("content-type", "text/html");
      res.end("<body></body>");
    });
    const page = await fetch(url);
    expect(page.headers.get("set-cookie")).toBe("session=1");
    expect(await page.text()).toBe(`<body>${LINK}</body><!--tail-->`);
    const json = await fetch(`${url}/json`);
    expect(json.headers.get("set-cookie")).toBe("session=1");
    expect(await json.text()).toBe('{"ok":true}<!--tail-->');
  });

  it("delivers write and end callbacks", async () => {
    const callbacks: string[] = [];
    const { body } = await fetchWith((res) => {
      res.setHeader("content-type", "text/html");
      res.write("<html><body>", () => callbacks.push("a"));
      res.write(Buffer.from("<p>x</p>"), "utf8", () => callbacks.push("b"));
      res.write(new Uint8Array([0x3c, 0x2f, 0x62, 0x6f, 0x64, 0x79, 0x3e]));
      res.end(() => callbacks.push("end"));
    });
    expect(body).toBe(`<html><body><p>x</p>${LINK}</body>`);
    expect(callbacks).toEqual(["a", "b", "end"]);
  });

  it("leaves non-HTML, compressed, UTF-16 and non-200 responses untouched", async () => {
    const json = await fetchWith((res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end('{"html":"</body>"}');
    });
    expect(json.body).toBe('{"html":"</body>"}');

    const gzip = await fetchWith((res) => {
      res.writeHead(200, { "content-type": "text/html", "content-encoding": "gzip" });
      res.end(zlib.gzipSync("<body></body>"));
    });
    expect(gzip.body).toBe("<body></body>");

    const identity = await fetchWith((res) => {
      res.setHeader("content-type", "text/html");
      res.setHeader("content-encoding", "identity");
      res.write("<body>");
      res.end("</body>");
    });
    expect(identity.body).toBe(`<body>${LINK}</body>`);

    const missing = await fetchWith((res) => {
      res.statusCode = 404;
      res.setHeader("content-type", "text/html");
      res.write("<body>");
      res.end("</body>");
    });
    expect(missing.body).toBe("<body></body>");

    const wide = await fetchWith((res) => {
      res.writeHead(200, { "content-type": "text/html; charset=utf-16" });
      res.end("<body></body>");
    });
    expect(wide.body).toBe("<body></body>");
  });

  it("does not inject into fragments or empty bodies", async () => {
    const fragment = await fetchWith((res) => {
      res.setHeader("content-type", "text/html");
      res.end("<p>just a fragment</p>");
    });
    expect(fragment.body).toBe("<p>just a fragment</p>");

    const empty = await fetchWith((res) => {
      res.setHeader("content-type", "text/html");
      res.writeHead(200);
      res.end();
    });
    expect(empty.body).toBe("");
  });

  it("streams large pages through and still injects at the end", async () => {
    const chunk = "a".repeat(1024 * 1024);
    const { body } = await fetchWith((res) => {
      res.writeHead(200, { "content-type": "text/html" });
      res.write("<body>");
      res.write(chunk);
      res.write(chunk);
      res.write(chunk);
      res.end("</body>");
    });
    expect(body.length).toBe(3 * 1024 * 1024 + "<body></body>".length + LINK.length);
    expect(body.endsWith(`${LINK}</body>`)).toBe(true);
  });

  it("stops buffering a declared-length page that never closes its body", async () => {
    const chunk = "b".repeat(1024 * 1024);
    const { body, response } = await fetchWith((res) => {
      res.writeHead(200, { "content-type": "text/html", "content-length": String(3 * chunk.length) });
      res.write(chunk);
      res.write(chunk);
      res.write(chunk);
      res.end();
    });
    expect(body.length).toBe(3 * 1024 * 1024);
    expect(response.headers.get("content-length")).toBe(String(3 * chunk.length));
  });

  it("passes writeHead through once the head is committed", async () => {
    const { body } = await fetchWith((res) => {
      res.setHeader("content-type", "text/html");
      res.write("<html><head></head><body><main>");
      try {
        res.writeHead(201);
      } catch {
        res.end("</main></body></html>");
        return;
      }
      res.end("</main></body></html>");
    });
    expect(body).toBe(`<html><head></head><body><main></main>${LINK}</body></html>`);
  });
});

describe("injectMarkupIntoFetchResponse", () => {
  function streamed(chunks: string[], init: ResponseInit = {}): Response {
    const encoder = new TextEncoder();
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        for (const chunk of chunks) {
          controller.enqueue(encoder.encode(chunk));
        }
        controller.close();
      },
    });
    return new Response(body, { status: 200, headers: { "content-type": "text/html; charset=utf-8", "content-length": "999" }, ...init });
  }

  it("injects before the real </body> across chunk boundaries and drops Content-Length", async () => {
    const response = injectMarkupIntoFetchResponse(
      streamed([
        "<html><body><p>héllo</p><script>const s = '</bo",
        "dy>';</script><!-- </body> -->",
        "<p>end</p></b",
        "ody></html>",
      ]),
      LINK,
    );
    expect(response.headers.get("content-length")).toBeNull();
    expect(response.headers.get("content-type")).toBe("text/html; charset=utf-8");
    expect(await response.text()).toBe(
      `<html><body><p>héllo</p><script>const s = '</body>';</script><!-- </body> --><p>end</p>${LINK}</body></html>`,
    );
  });

  it("streams long documents through without holding them and passes the tail after injecting", async () => {
    const filler = "x".repeat(5000);
    const response = injectMarkupIntoFetchResponse(streamed([`<body>${filler}`, `${filler}</body>`, "<!-- after -->"]), LINK);
    expect(await response.text()).toBe(`<body>${filler}${filler}${LINK}</body><!-- after -->`);
    const bodiless = injectMarkupIntoFetchResponse(streamed(["<p>fragment</p>"]), LINK);
    expect(await bodiless.text()).toBe("<p>fragment</p>");
  });

  it("leaves non-HTML, non-200, compressed and empty responses untouched", () => {
    const json = new Response("{}", { headers: { "content-type": "application/json" } });
    expect(injectMarkupIntoFetchResponse(json, LINK)).toBe(json);
    const missing = new Response("<body></body>", { status: 404, headers: { "content-type": "text/html" } });
    expect(injectMarkupIntoFetchResponse(missing, LINK)).toBe(missing);
    const gzipped = new Response("x", { headers: { "content-type": "text/html", "content-encoding": "gzip" } });
    expect(injectMarkupIntoFetchResponse(gzipped, LINK)).toBe(gzipped);
    const empty = new Response(null, { headers: { "content-type": "text/html" } });
    expect(injectMarkupIntoFetchResponse(empty, LINK)).toBe(empty);
  });

  it("treats an identity encoding as uncompressed", async () => {
    const response = injectMarkupIntoFetchResponse(
      streamed(["<body></body>"], { headers: { "content-type": "text/html", "content-encoding": "Identity" } }),
      LINK,
    );
    expect(await response.text()).toBe(`<body>${LINK}</body>`);
  });
});
