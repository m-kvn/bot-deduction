import { afterEach, describe, expect, it, vi } from "vitest";
import fs from "node:fs";
import https from "node:https";
import net from "node:net";
import path from "node:path";
import tls from "node:tls";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import type { AddressInfo } from "node:net";
import {
  computeJa3,
  computeJa4,
  computeTlsFingerprints,
  getTlsClientHello,
  isGreaseValue,
  isValidJa4,
  parseJa4,
  parseTlsClientHello,
  readClientHelloRecords,
  trackTlsClientHellos,
} from "../src/server/index.js";
import type { TlsClientHello } from "../src/server/index.js";
import {
  alpnExtension,
  chromeLikeHello,
  clientHelloHandshake,
  clientHelloRecord,
  extension,
  pointFormatsExtension,
  record,
  sniExtension,
  supportedVersionsExtension,
  u16,
  u16ListExtension,
} from "./helpers/tls-hello.js";

const FIXTURES = path.join(path.dirname(fileURLToPath(import.meta.url)), "fixtures");
const CERT = fs.readFileSync(path.join(FIXTURES, "tls-localhost-cert.pem"));
const KEY = fs.readFileSync(path.join(FIXTURES, "tls-localhost-key.pem"));

function hello(overrides: Partial<TlsClientHello> = {}): TlsClientHello {
  return {
    protocol: "t",
    version: 0x0303,
    cipherSuites: [],
    extensions: [],
    supportedGroups: [],
    ecPointFormats: [],
    signatureAlgorithms: [],
    supportedVersions: [],
    alpn: [],
    ...overrides,
  };
}

describe("GREASE values", () => {
  it("recognises the reserved GREASE pattern only", () => {
    expect(isGreaseValue(0x0a0a)).toBe(true);
    expect(isGreaseValue(0xfafa)).toBe(true);
    expect(isGreaseValue(0x0a1a)).toBe(false);
    expect(isGreaseValue(0x1301)).toBe(false);
  });
});

describe("ClientHello record reader", () => {
  it("reports complete, incomplete and invalid buffers", () => {
    const full = chromeLikeHello();
    expect(readClientHelloRecords(full).state).toBe("complete");
    expect(readClientHelloRecords(full.subarray(0, 3)).state).toBe("incomplete");
    expect(readClientHelloRecords(full.subarray(0, 40)).state).toBe("incomplete");
    expect(readClientHelloRecords(new Uint8Array()).state).toBe("incomplete");
    expect(readClientHelloRecords(Buffer.from("GET / HTTP/1.1\r\n")).state).toBe("invalid");
    expect(readClientHelloRecords(Uint8Array.from([0x47, 0x45])).state).toBe("invalid");
    expect(readClientHelloRecords(Uint8Array.from([0x16, 0x02, 0x01, 0x00, 0x05])).state).toBe("invalid");
    expect(readClientHelloRecords(Uint8Array.from([0x16, 0x03, 0x01, 0x00, 0x00])).state).toBe("invalid");
    expect(readClientHelloRecords(Uint8Array.from([0x16, 0x03, 0x01, 0xff, 0xff])).state).toBe("invalid");
  });

  it("says how many bytes it needs before the next useful look", () => {
    const full = chromeLikeHello();
    expect(readClientHelloRecords(full.subarray(0, 3))).toEqual({ state: "incomplete", needed: 5 });
    expect(readClientHelloRecords(full.subarray(0, 40))).toEqual({ state: "incomplete", needed: full.length });
    const handshake = clientHelloHandshake({ ciphers: [0x1301], extensions: [sniExtension("a.test")] });
    const firstRecord = record(handshake.slice(0, 10));
    expect(readClientHelloRecords(Uint8Array.from(firstRecord))).toEqual({
      state: "incomplete",
      needed: firstRecord.length + 5,
    });
  });

  it("refuses a hello fragmented into more records than any real client sends", () => {
    const handshake = clientHelloHandshake({ ciphers: [0x1301], extensions: [sniExtension("fragmented.test")] });
    const pieces: number[] = [];
    for (let index = 0; index < handshake.length; index += 4) {
      pieces.push(...record(handshake.slice(index, index + 4)));
    }
    expect(readClientHelloRecords(Uint8Array.from(pieces)).state).toBe("invalid");
  });

  it("rejects handshakes that are not ClientHello or are implausibly large", () => {
    expect(readClientHelloRecords(Uint8Array.from(record([2, 0, 0, 1, 0]))).state).toBe("invalid");
    expect(readClientHelloRecords(Uint8Array.from(record([1, 0x02, 0x00, 0x00, 0]))).state).toBe("invalid");
  });

  it("reassembles a ClientHello fragmented across records", () => {
    const handshake = clientHelloHandshake({ ciphers: [0x1301], extensions: [sniExtension("a.test")] });
    const split = Uint8Array.from([
      ...record(handshake.slice(0, 2)),
      ...record(handshake.slice(2, 10)),
      ...record(handshake.slice(10)),
    ]);
    const read = readClientHelloRecords(split);
    expect(read.state).toBe("complete");
    expect(parseTlsClientHello(split)?.serverName).toBe("a.test");
    expect(readClientHelloRecords(split.subarray(0, 8)).state).toBe("incomplete");
  });
});

describe("ClientHello parser", () => {
  it("extracts every field JA3 and JA4 need", () => {
    const parsed = parseTlsClientHello(chromeLikeHello());
    expect(parsed).toMatchObject({
      protocol: "t",
      version: 0x0303,
      serverName: "example.com",
      alpn: ["h2", "http/1.1"],
      supportedVersions: [0x3a3a, 0x0304, 0x0303],
      supportedGroups: [0x2a2a, 0x001d, 0x0017, 0x0018],
      ecPointFormats: [0],
    });
    expect(parsed?.cipherSuites[0]).toBe(0x0a0a);
    expect(parsed?.extensions).toHaveLength(18);
    expect(parsed?.signatureAlgorithms).toHaveLength(8);
  });

  it("returns null for incomplete or truncated hellos and tolerates bad extension bodies", () => {
    expect(parseTlsClientHello(chromeLikeHello().subarray(0, 30))).toBeNull();
    const truncatedBody = [1, 0, 0, 6, 3, 3, 1, 2, 3, 4];
    expect(parseTlsClientHello(Uint8Array.from(record(truncatedBody)))).toBeNull();

    const lenient = parseTlsClientHello(
      clientHelloRecord({
        ciphers: [0x1301],
        sessionId: [9, 9, 9],
        extensions: [
          extension(0x0000, [0, 9, 0]),
          extension(0x0010, [0, 4, 9]),
          extension(0x000a, [0]),
          extension(0x000d, [0, 2]),
          extension(0x002b, []),
          extension(0x000b, [5]),
          sniExtension("ok.test"),
        ],
      }),
    );
    expect(lenient).toMatchObject({
      extensions: [0x0000, 0x0010, 0x000a, 0x000d, 0x002b, 0x000b, 0x0000],
      serverName: "ok.test",
      alpn: [],
      supportedGroups: [],
      signatureAlgorithms: [],
      supportedVersions: [],
      ecPointFormats: [],
    });
  });

  it("skips non host-name SNI entries and handles hellos with no extension block", () => {
    const nameEntries = [1, ...u16(2), 0x61, 0x62, 0, ...u16(3), 0x78, 0x79, 0x7a];
    const parsed = parseTlsClientHello(
      clientHelloRecord({
        ciphers: [0x002f],
        extensions: [extension(0x0000, [...u16(nameEntries.length), ...nameEntries])],
      }),
    );
    expect(parsed?.serverName).toBe("xyz");

    const bare = parseTlsClientHello(clientHelloRecord({ version: 0x0301, ciphers: [0x002f], omitExtensions: true }));
    expect(bare).toMatchObject({ version: 0x0301, extensions: [], alpn: [] });
    expect(parseTlsClientHello(clientHelloRecord({ ciphers: [] }), "q")?.protocol).toBe("q");
  });

  it("fails cleanly when an extension overruns its block", () => {
    const handshake = clientHelloHandshake({ ciphers: [0x1301], extensions: [[0x00, 0x10, 0x00, 0x09, 0x01]] });
    expect(parseTlsClientHello(Uint8Array.from(record(handshake)))).toBeNull();
  });
});

describe("JA3", () => {
  it("matches the published reference vector", () => {
    const { ja3, ja3Hash } = computeJa3(
      hello({
        version: 769,
        cipherSuites: [47, 53, 5, 10, 49161, 49162, 49171, 49172, 50, 56, 19, 4],
        extensions: [0, 10, 11],
        supportedGroups: [23, 24, 25],
        ecPointFormats: [0],
      }),
    );
    expect(ja3).toBe("769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0");
    expect(ja3Hash).toBe("ada70206e40642a3e4461f35503241d5");
  });

  it("drops GREASE and keeps wire order", () => {
    const parsed = parseTlsClientHello(chromeLikeHello()) as TlsClientHello;
    const { ja3, ja3Hash } = computeJa3(parsed);
    expect(ja3.startsWith("771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0")).toBe(true);
    expect(ja3Hash).toBe(createHash("md5").update(ja3).digest("hex"));
  });
});

describe("JA4", () => {
  it("reproduces the canonical example fingerprint", () => {
    const parsed = parseTlsClientHello(chromeLikeHello()) as TlsClientHello;
    expect(computeJa4(parsed)).toBe("t13d1516h2_8daaf6152771_e5627efa2ab1");
  });

  it("derives the version from the hello when supported_versions is absent", () => {
    expect(computeJa4(hello({ version: 0x0303 })).slice(0, 4)).toBe("t12i");
    expect(computeJa4(hello({ version: 0x0301 })).slice(0, 3)).toBe("t10");
    expect(computeJa4(hello({ version: 0x9999 })).slice(0, 3)).toBe("t00");
    expect(computeJa4(hello({ supportedVersions: [0x0a0a] , version: 0x0300 })).slice(0, 3)).toBe("ts3");
    expect(
      computeJa4(hello({ protocol: "d", version: 0xfefd, supportedVersions: [0xfefd, 0xfefc] })).slice(0, 3),
    ).toBe("dd3");
  });

  it("encodes ALPN per the specification, including hex fallbacks", () => {
    const alpn = (value: string) => computeJa4(hello({ alpn: [value] })).slice(8, 10);
    expect(alpn("h2")).toBe("h2");
    expect(alpn("http/1.1")).toBe("h1");
    expect(alpn("h")).toBe("hh");
    expect(alpn("\xab")).toBe("ab");
    expect(alpn("\xab\xcd")).toBe("ad");
    expect(alpn("0\xab")).toBe("3b");
    expect(alpn("01\xab\xcd")).toBe("3d");
    expect(alpn("0\xab\xcd1")).toBe("01");
    expect(computeJa4(hello({ alpn: [] })).slice(8, 10)).toBe("00");
  });

  it("caps counts at 99 and zero-fills empty sections", () => {
    const many = Array.from({ length: 120 }, (_, index) => index + 1);
    const ja4 = computeJa4(hello({ cipherSuites: many, extensions: many }));
    expect(ja4.slice(4, 8)).toBe("9999");
    expect(computeJa4(hello())).toBe("t12i000000_000000000000_000000000000");
    expect(computeJa4(hello({ extensions: [0x0000, 0x0010] })).endsWith("_000000000000")).toBe(true);
  });

  it("hashes extensions without signature algorithms when none were offered", () => {
    const ja4 = computeJa4(hello({ extensions: [0x000a, 0x0017] }));
    const expected = createHash("sha256").update("000a,0017").digest("hex").slice(0, 12);
    expect(ja4.endsWith(`_${expected}`)).toBe(true);
  });

  it("memoises fingerprints per hello object", () => {
    const parsed = parseTlsClientHello(chromeLikeHello()) as TlsClientHello;
    const first = computeTlsFingerprints(parsed);
    expect(computeTlsFingerprints(parsed)).toBe(first);
    expect(first.ja4).toBe("t13d1516h2_8daaf6152771_e5627efa2ab1");
  });

  it("parses and validates JA4 strings", () => {
    expect(parseJa4(" t13d1516h2_8DAAF6152771_e5627efa2ab1 ")).toEqual({
      protocol: "t",
      version: "13",
      sni: "d",
      cipherCount: 15,
      extensionCount: 16,
      alpn: "h2",
      cipherHash: "8daaf6152771",
      extensionHash: "e5627efa2ab1",
    });
    expect(parseJa4("Q13I0310H3_55b375c5d22e_cd85d2d88918")?.protocol).toBe("q");
    expect(parseJa4(undefined)).toBeNull();
    expect(isValidJa4("cd08e31494f9531f560d64c695473da9")).toBe(false);
    expect(isValidJa4("t13d1516h2_8daaf6152771_e5627efa2ab1")).toBe(true);
  });
});

function startTrackedServer(trackOptions?: Parameters<typeof trackTlsClientHellos>[1]) {
  const seen: Array<TlsClientHello | undefined> = [];
  const server = https.createServer({ cert: CERT, key: KEY }, (req, res) => {
    const captured = getTlsClientHello(req.socket);
    seen.push(captured);
    res.end(captured ? computeJa4(captured) : "none");
  });
  trackTlsClientHellos(server, trackOptions);
  return new Promise<{ server: https.Server; port: number; seen: typeof seen }>((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      resolve({ server, port: (server.address() as AddressInfo).port, seen });
    });
  });
}

function get(port: number, options: https.RequestOptions = {}): Promise<string> {
  return new Promise((resolve, reject) => {
    https
      .get({ host: "127.0.0.1", port, path: "/", agent: false, rejectUnauthorized: false, ...options }, (res) => {
        let body = "";
        res.on("data", (chunk) => (body += chunk));
        res.on("end", () => resolve(body));
      })
      .on("error", reject);
  });
}

describe("trackTlsClientHellos", () => {
  const servers: https.Server[] = [];
  afterEach(async () => {
    vi.useRealTimers();
    await Promise.all(servers.splice(0).map((server) => new Promise((resolve) => server.close(resolve))));
  });

  it("captures the real ClientHello of each connection and still completes the handshake", async () => {
    const { server, port, seen } = await startTrackedServer();
    servers.push(server);

    const plain = await get(port);
    const h2 = await get(port, { ALPNProtocols: ["h2", "http/1.1"], servername: "localhost" } as https.RequestOptions);

    expect(parseJa4(plain)?.alpn).toBe("00");
    expect(parseJa4(plain)?.version).toBe("13");
    expect(parseJa4(h2)).toMatchObject({ alpn: "h2", sni: "d" });
    expect(seen).toHaveLength(2);
    expect(seen[1]?.serverName).toBe("localhost");
    expect(getTlsClientHello(undefined)).toBeUndefined();
    expect(getTlsClientHello({ remoteAddress: "127.0.0.1" })).toBeUndefined();
  });

  it("reads a ClientHello that arrives a few bytes at a time", async () => {
    const recorder = net.createServer();
    const realHello = await new Promise<Buffer>((resolve) => {
      recorder.on("connection", (socket) => {
        socket.once("data", (chunk: Buffer) => {
          resolve(chunk);
          socket.destroy();
        });
      });
      recorder.listen(0, "127.0.0.1", () => {
        const client = tls.connect({ host: "127.0.0.1", port: (recorder.address() as AddressInfo).port, rejectUnauthorized: false });
        client.on("error", () => undefined);
      });
    });
    recorder.close();

    const { server, port } = await startTrackedServer();
    servers.push(server);
    const raw = net.connect(port, "127.0.0.1");
    raw.setNoDelay(true);
    await new Promise((resolve) => raw.once("connect", resolve));
    const reply = new Promise<number>((resolve) => raw.once("data", (chunk: Buffer) => resolve(chunk[0])));
    for (let offset = 0; offset < realHello.length; offset += 97) {
      raw.write(realHello.subarray(offset, offset + 97));
      await new Promise((resolve) => setTimeout(resolve, 2));
    }
    expect(await reply).toBe(0x16);
    raw.destroy();
  });

  it("gives up early on a first byte that cannot start a TLS record", async () => {
    const { server, port } = await startTrackedServer();
    servers.push(server);
    const closed = await new Promise<boolean>((resolve) => {
      const socket = net.connect(port, "127.0.0.1", () => {
        socket.write("G");
        setTimeout(() => socket.write("ET / HTTP/1.1\r\nHost: x\r\n\r\n"), 50);
      });
      socket.on("error", () => resolve(true));
      socket.on("close", () => resolve(true));
    });
    expect(closed).toBe(true);
  });

  it("stops reading at the byte budget even before a record header is complete", async () => {
    const { server, port } = await startTrackedServer({ maxBytes: 3 });
    servers.push(server);
    const closed = await new Promise<boolean>((resolve) => {
      const socket = net.connect(port, "127.0.0.1", () => socket.write(Buffer.from([0x16, 0x03, 0x01, 0x00])));
      socket.setTimeout(3_000, () => {
        socket.destroy();
        resolve(false);
      });
      socket.on("error", () => resolve(true));
      socket.on("close", () => resolve(true));
      setTimeout(() => socket.end(), 200);
    });
    expect(closed).toBe(true);
  });

  it("hands non-TLS bytes straight to the TLS layer without a fingerprint", async () => {
    const { server, port } = await startTrackedServer();
    servers.push(server);
    const closed = await new Promise<boolean>((resolve) => {
      const socket = net.connect(port, "127.0.0.1", () => socket.write("GET / HTTP/1.1\r\n\r\n"));
      socket.on("error", () => resolve(true));
      socket.on("close", () => resolve(true));
    });
    expect(closed).toBe(true);
  });

  it("hands the connection over unfingerprinted once the byte budget is spent", async () => {
    const recorder = net.createServer();
    const realHello = await new Promise<Buffer>((resolve) => {
      recorder.on("connection", (socket) => {
        socket.once("data", (chunk: Buffer) => {
          resolve(chunk);
          socket.destroy();
        });
      });
      recorder.listen(0, "127.0.0.1", () => {
        const client = tls.connect({
          host: "127.0.0.1",
          port: (recorder.address() as AddressInfo).port,
          rejectUnauthorized: false,
        });
        client.on("error", () => undefined);
      });
    });
    recorder.close();

    const { server, port } = await startTrackedServer({ maxBytes: 8 });
    servers.push(server);
    const raw = net.connect(port, "127.0.0.1");
    await new Promise((resolve) => raw.once("connect", resolve));
    const reply = new Promise<number>((resolve) => raw.once("data", (chunk: Buffer) => resolve(chunk[0])));
    raw.write(realHello.subarray(0, 20));
    await new Promise((resolve) => setTimeout(resolve, 30));
    raw.write(realHello.subarray(20));
    expect(await reply).toBe(0x16);
    raw.destroy();
  });

  it("hands the connection over unfingerprinted when no hello arrives in time", async () => {
    const { server, port } = await startTrackedServer({ timeoutMs: 40 });
    servers.push(server);
    const raw = net.connect(port, "127.0.0.1");
    await new Promise((resolve) => raw.once("connect", resolve));
    await new Promise((resolve) => setTimeout(resolve, 120));
    const secure = tls.connect({ socket: raw, rejectUnauthorized: false, servername: "localhost" });
    await new Promise((resolve) => secure.once("secureConnect", resolve));
    secure.write("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    const response = await new Promise<string>((resolve) => {
      let text = "";
      secure.on("data", (chunk) => (text += chunk));
      secure.on("end", () => resolve(text));
    });
    expect(response.endsWith("none")).toBe(true);
  });

  it("destroys sockets that fail while the hello is still being read", async () => {
    const { server, port } = await startTrackedServer({ timeoutMs: 5_000 });
    servers.push(server);
    await new Promise<void>((resolve) => {
      const socket = net.connect(port, "127.0.0.1", () => {
        socket.write(chromeLikeHello().subarray(0, 10));
        setTimeout(() => {
          socket.destroy();
          setTimeout(resolve, 50);
        }, 20);
      });
    });
    const tlsSocket = await new Promise<string>((resolve, reject) => {
      const client = tls.connect({ host: "127.0.0.1", port, rejectUnauthorized: false }, () => {
        resolve(client.getProtocol() ?? "");
        client.end();
      });
      client.on("error", reject);
    });
    expect(tlsSocket).toMatch(/TLS/);
  });

  it("preserves listeners that were registered before tracking", async () => {
    const server = https.createServer({ cert: CERT, key: KEY }, (_req, res) => res.end("ok"));
    const extra = vi.fn();
    server.on("connection", extra);
    trackTlsClientHellos(server);
    servers.push(server);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const body = await get((server.address() as AddressInfo).port);
    expect(body).toBe("ok");
    expect(extra).toHaveBeenCalledTimes(1);
  });

  it("builds JA4 for ALPN and supported_versions captured from synthetic extensions", () => {
    const parsed = parseTlsClientHello(
      clientHelloRecord({
        ciphers: [0x1301, 0x1302],
        extensions: [
          alpnExtension(["http/1.1"]),
          supportedVersionsExtension([0x0304]),
          u16ListExtension(0x000d, [0x0403]),
          pointFormatsExtension([0, 1]),
        ],
      }),
    ) as TlsClientHello;
    expect(computeJa4(parsed).slice(0, 10)).toBe("t13i0204h1");
  });
});
