import { createHash } from "node:crypto";
import type { Server as NetServer, Socket } from "node:net";

export type TlsTransport = "t" | "q" | "d";

export interface TlsClientHello {
  protocol: TlsTransport;
  version: number;
  cipherSuites: readonly number[];
  extensions: readonly number[];
  supportedGroups: readonly number[];
  ecPointFormats: readonly number[];
  signatureAlgorithms: readonly number[];
  supportedVersions: readonly number[];
  serverName?: string;
  alpn: readonly string[];
}

export interface TlsFingerprints {
  ja3: string;
  ja3Hash: string;
  ja4: string;
}

export interface Ja4Parts {
  protocol: TlsTransport;
  version: string;
  sni: "d" | "i";
  cipherCount: number;
  extensionCount: number;
  alpn: string;
  cipherHash: string;
  extensionHash: string;
}

export type ClientHelloReadState =
  | { state: "complete"; handshake: Uint8Array }
  | { state: "incomplete"; needed: number }
  | { state: "invalid" };

export interface TrackTlsClientHellosOptions {
  timeoutMs?: number;
  maxBytes?: number;
}

const HANDSHAKE_RECORD = 0x16;
const CLIENT_HELLO = 0x01;
const MAX_HANDSHAKE_LENGTH = 0x10000;
const MAX_RECORD_LENGTH = 16_384 + 2_048;
const MAX_HELLO_RECORDS = 8;
const EMPTY_HASH = "000000000000";

const EXTENSION_SERVER_NAME = 0x0000;
const EXTENSION_SUPPORTED_GROUPS = 0x000a;
const EXTENSION_EC_POINT_FORMATS = 0x000b;
const EXTENSION_SIGNATURE_ALGORITHMS = 0x000d;
const EXTENSION_ALPN = 0x0010;
const EXTENSION_SUPPORTED_VERSIONS = 0x002b;

const JA4_VERSIONS: Readonly<Record<number, string>> = {
  0x0304: "13",
  0x0303: "12",
  0x0302: "11",
  0x0301: "10",
  0x0300: "s3",
  0x0002: "s2",
  0xfeff: "d1",
  0xfefd: "d2",
  0xfefc: "d3",
};

const JA4_PATTERN =
  /^([tqd])(13|12|11|10|s3|s2|d1|d2|d3|00)([di])(\d{2})(\d{2})([0-9a-z]{2})_([0-9a-f]{12})_([0-9a-f]{12})$/i;

export function isGreaseValue(value: number): boolean {
  return (value & 0x0f0f) === 0x0a0a && value >> 8 === (value & 0xff);
}

export function readClientHelloRecords(data: Uint8Array): ClientHelloReadState {
  const fragments: Uint8Array[] = [];
  let collected = 0;
  let expected: number | undefined;
  let offset = 0;
  let needed = 5;

  while (offset + 5 <= data.length) {
    const type = data[offset];
    const major = data[offset + 1];
    const length = (data[offset + 3] << 8) | data[offset + 4];
    if (
      type !== HANDSHAKE_RECORD ||
      major !== 3 ||
      length === 0 ||
      length > MAX_RECORD_LENGTH ||
      fragments.length >= MAX_HELLO_RECORDS
    ) {
      return { state: "invalid" };
    }
    if (offset + 5 + length > data.length) {
      needed = offset + 5 + length;
      break;
    }
    needed = offset + 5 + length + 5;
    fragments.push(data.subarray(offset + 5, offset + 5 + length));
    collected += length;
    offset += 5 + length;

    if (expected === undefined && collected >= 4) {
      const head = concat(fragments, 4);
      if (head[0] !== CLIENT_HELLO) {
        return { state: "invalid" };
      }
      expected = 4 + ((head[1] << 16) | (head[2] << 8) | head[3]);
      if (expected > MAX_HANDSHAKE_LENGTH) {
        return { state: "invalid" };
      }
    }
    if (expected !== undefined && collected >= expected) {
      return { state: "complete", handshake: concat(fragments, expected) };
    }
  }

  if (data.length > 0 && data[0] !== HANDSHAKE_RECORD) {
    return { state: "invalid" };
  }
  return { state: "incomplete", needed };
}

function concat(fragments: readonly Uint8Array[], length: number): Uint8Array {
  const output = new Uint8Array(length);
  let offset = 0;
  for (const fragment of fragments) {
    const take = Math.min(fragment.length, length - offset);
    output.set(fragment.subarray(0, take), offset);
    offset += take;
    if (offset === length) {
      break;
    }
  }
  return output;
}

class Reader {
  offset = 0;

  constructor(private readonly bytes: Uint8Array, private readonly end = bytes.length) {}

  get remaining(): number {
    return this.end - this.offset;
  }

  u8(): number {
    this.require(1);
    return this.bytes[this.offset++];
  }

  u16(): number {
    this.require(2);
    const value = (this.bytes[this.offset] << 8) | this.bytes[this.offset + 1];
    this.offset += 2;
    return value;
  }

  take(length: number): Uint8Array {
    this.require(length);
    const slice = this.bytes.subarray(this.offset, this.offset + length);
    this.offset += length;
    return slice;
  }

  sub(length: number): Reader {
    return new Reader(this.take(length));
  }

  private require(length: number): void {
    if (this.offset + length > this.end) {
      throw new RangeError("truncated");
    }
  }
}

function u16List(reader: Reader): number[] {
  const values: number[] = [];
  while (reader.remaining >= 2) {
    values.push(reader.u16());
  }
  return values;
}

function latin1(bytes: Uint8Array): string {
  return String.fromCharCode(...bytes);
}

interface ExtensionDetails {
  supportedGroups: number[];
  ecPointFormats: number[];
  signatureAlgorithms: number[];
  supportedVersions: number[];
  serverName?: string;
  alpn: string[];
}

function readExtension(type: number, data: Uint8Array, details: ExtensionDetails): void {
  const reader = new Reader(data);
  try {
    switch (type) {
      case EXTENSION_SERVER_NAME: {
        const list = reader.sub(reader.u16());
        while (list.remaining > 0 && details.serverName === undefined) {
          const nameType = list.u8();
          const name = list.take(list.u16());
          if (nameType === 0) {
            details.serverName = latin1(name);
          }
        }
        break;
      }
      case EXTENSION_SUPPORTED_GROUPS:
        details.supportedGroups = u16List(reader.sub(reader.u16()));
        break;
      case EXTENSION_EC_POINT_FORMATS:
        details.ecPointFormats = [...reader.take(reader.u8())];
        break;
      case EXTENSION_SIGNATURE_ALGORITHMS:
        details.signatureAlgorithms = u16List(reader.sub(reader.u16()));
        break;
      case EXTENSION_ALPN: {
        const list = reader.sub(reader.u16());
        const protocols: string[] = [];
        while (list.remaining > 0) {
          protocols.push(latin1(list.take(list.u8())));
        }
        details.alpn = protocols;
        break;
      }
      case EXTENSION_SUPPORTED_VERSIONS:
        details.supportedVersions = u16List(reader.sub(reader.u8()));
        break;
      default:
        break;
    }
  } catch {
    return;
  }
}

export function parseTlsClientHello(
  data: Uint8Array,
  protocol: TlsTransport = "t",
): TlsClientHello | null {
  const read = readClientHelloRecords(data);
  if (read.state !== "complete") {
    return null;
  }

  try {
    const reader = new Reader(read.handshake);
    reader.take(4);
    const version = reader.u16();
    reader.take(32);
    reader.take(reader.u8());
    const cipherSuites = u16List(reader.sub(reader.u16()));
    reader.take(reader.u8());

    const extensions: number[] = [];
    const details: ExtensionDetails = {
      supportedGroups: [],
      ecPointFormats: [],
      signatureAlgorithms: [],
      supportedVersions: [],
      alpn: [],
    };
    if (reader.remaining >= 2) {
      const block = reader.sub(reader.u16());
      while (block.remaining >= 4) {
        const type = block.u16();
        const body = block.take(block.u16());
        extensions.push(type);
        readExtension(type, body, details);
      }
    }

    return {
      protocol,
      version,
      cipherSuites,
      extensions,
      supportedGroups: details.supportedGroups,
      ecPointFormats: details.ecPointFormats,
      signatureAlgorithms: details.signatureAlgorithms,
      supportedVersions: details.supportedVersions,
      serverName: details.serverName,
      alpn: details.alpn,
    };
  } catch {
    return null;
  }
}

function withoutGrease(values: readonly number[]): number[] {
  return values.filter((value) => !isGreaseValue(value));
}

function hex4(value: number): string {
  return value.toString(16).padStart(4, "0");
}

function truncatedSha256(input: string): string {
  return createHash("sha256").update(input).digest("hex").slice(0, 12);
}

function twoDigits(count: number): string {
  return String(Math.min(count, 99)).padStart(2, "0");
}

function isAlphanumericCode(code: number): boolean {
  return (
    (code >= 0x30 && code <= 0x39) ||
    (code >= 0x41 && code <= 0x5a) ||
    (code >= 0x61 && code <= 0x7a)
  );
}

function ja4Alpn(value: string | undefined): string {
  if (!value) {
    return "00";
  }
  const first = value.charCodeAt(0);
  const last = value.charCodeAt(value.length - 1);
  if (isAlphanumericCode(first) && isAlphanumericCode(last)) {
    return `${value[0]}${value[value.length - 1]}`;
  }
  const hex = Buffer.from(value, "latin1").toString("hex");
  return `${hex[0]}${hex[hex.length - 1]}`;
}

export function computeJa3(hello: TlsClientHello): { ja3: string; ja3Hash: string } {
  const ja3 = [
    String(hello.version),
    withoutGrease(hello.cipherSuites).join("-"),
    withoutGrease(hello.extensions).join("-"),
    withoutGrease(hello.supportedGroups).join("-"),
    hello.ecPointFormats.join("-"),
  ].join(",");
  return { ja3, ja3Hash: createHash("md5").update(ja3).digest("hex") };
}

export function computeJa4(hello: TlsClientHello): string {
  const versions = withoutGrease(hello.supportedVersions);
  const version =
    versions.length === 0
      ? hello.version
      : hello.protocol === "d"
        ? Math.min(...versions)
        : Math.max(...versions);
  const ciphers = withoutGrease(hello.cipherSuites);
  const extensions = withoutGrease(hello.extensions);
  const sni = extensions.includes(EXTENSION_SERVER_NAME) ? "d" : "i";
  const head =
    `${hello.protocol}${JA4_VERSIONS[version] ?? "00"}${sni}` +
    `${twoDigits(ciphers.length)}${twoDigits(extensions.length)}${ja4Alpn(hello.alpn[0])}`;

  const cipherHash =
    ciphers.length === 0
      ? EMPTY_HASH
      : truncatedSha256([...ciphers].sort((left, right) => left - right).map(hex4).join(","));

  const hashedExtensions = extensions
    .filter((value) => value !== EXTENSION_SERVER_NAME && value !== EXTENSION_ALPN)
    .sort((left, right) => left - right)
    .map(hex4)
    .join(",");
  const signatures = withoutGrease(hello.signatureAlgorithms).map(hex4).join(",");
  const extensionHash =
    hashedExtensions === ""
      ? EMPTY_HASH
      : truncatedSha256(signatures ? `${hashedExtensions}_${signatures}` : hashedExtensions);

  return `${head}_${cipherHash}_${extensionHash}`;
}

const fingerprintCache = new WeakMap<TlsClientHello, TlsFingerprints>();

export function computeTlsFingerprints(hello: TlsClientHello): TlsFingerprints {
  const cached = fingerprintCache.get(hello);
  if (cached) {
    return cached;
  }
  const fingerprints = { ...computeJa3(hello), ja4: computeJa4(hello) };
  fingerprintCache.set(hello, fingerprints);
  return fingerprints;
}

export function parseJa4(value: string | undefined): Ja4Parts | null {
  const match = value?.trim().match(JA4_PATTERN);
  if (!match) {
    return null;
  }
  return {
    protocol: match[1].toLowerCase() as TlsTransport,
    version: match[2].toLowerCase(),
    sni: match[3].toLowerCase() as "d" | "i",
    cipherCount: Number(match[4]),
    extensionCount: Number(match[5]),
    alpn: match[6],
    cipherHash: match[7].toLowerCase(),
    extensionHash: match[8].toLowerCase(),
  };
}

export function isValidJa4(value: string | undefined): boolean {
  return parseJa4(value) !== null;
}

const hellosBySocket = new Map<string, TlsClientHello>();

function socketKey(socket: { remoteAddress?: string; remotePort?: number }): string | undefined {
  return socket.remoteAddress && socket.remotePort
    ? `${socket.remoteAddress}|${socket.remotePort}`
    : undefined;
}

export function getTlsClientHello(
  socket: { remoteAddress?: string; remotePort?: number } | null | undefined,
): TlsClientHello | undefined {
  const key = socket ? socketKey(socket) : undefined;
  return key ? hellosBySocket.get(key) : undefined;
}

function captureClientHello(
  socket: Socket,
  options: Required<TrackTlsClientHellosOptions>,
  handOver: () => void,
): void {
  const chunks: Buffer[] = [];
  let size = 0;
  let needed = 5;

  const cleanup = () => {
    clearTimeout(timer);
    socket.removeListener("data", onData);
    socket.removeListener("error", onAbort);
    socket.removeListener("close", onAbort);
  };

  const finish = (hello: TlsClientHello | null) => {
    cleanup();
    socket.pause();
    const key = socketKey(socket);
    if (hello && key) {
      hellosBySocket.set(key, hello);
      socket.once("close", () => hellosBySocket.delete(key));
    }
    if (chunks.length > 0) {
      socket.unshift(Buffer.concat(chunks));
    }
    handOver();
  };

  const onAbort = () => {
    cleanup();
    socket.destroy();
  };

  const onData = (chunk: Buffer) => {
    chunks.push(chunk);
    size += chunk.length;
    if (size < needed && size < options.maxBytes && chunks[0][0] === HANDSHAKE_RECORD) {
      return;
    }
    const buffered = Buffer.concat(chunks);
    chunks.splice(0, chunks.length, buffered);
    const read = readClientHelloRecords(buffered);
    if (read.state === "complete") {
      finish(parseTlsClientHello(buffered));
    } else if (read.state === "invalid" || size >= options.maxBytes) {
      finish(null);
    } else {
      needed = read.needed;
    }
  };

  const timer = setTimeout(() => finish(null), options.timeoutMs);
  timer.unref?.();
  socket.on("error", onAbort);
  socket.on("close", onAbort);
  socket.on("data", onData);
}

export function trackTlsClientHellos(
  server: NetServer,
  options: TrackTlsClientHellosOptions = {},
): void {
  const resolved = {
    timeoutMs: options.timeoutMs ?? 10_000,
    maxBytes: options.maxBytes ?? 32 * 1024,
  };
  const listeners = server.listeners("connection") as Array<(socket: Socket) => void>;
  server.removeAllListeners("connection");
  server.on("connection", (socket: Socket) => {
    captureClientHello(socket, resolved, () => {
      for (const listener of listeners) {
        listener.call(server, socket);
      }
    });
  });
}
