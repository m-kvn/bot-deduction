export function u16(value: number): number[] {
  return [(value >> 8) & 0xff, value & 0xff];
}

function u24(value: number): number[] {
  return [(value >> 16) & 0xff, (value >> 8) & 0xff, value & 0xff];
}

export function extension(type: number, body: number[] = []): number[] {
  return [...u16(type), ...u16(body.length), ...body];
}

export function sniExtension(host: string): number[] {
  const name = [...Buffer.from(host, "latin1")];
  const entry = [0, ...u16(name.length), ...name];
  return extension(0x0000, [...u16(entry.length), ...entry]);
}

export function alpnExtension(protocols: string[]): number[] {
  const list = protocols.flatMap((protocol) => [
    protocol.length,
    ...Buffer.from(protocol, "latin1"),
  ]);
  return extension(0x0010, [...u16(list.length), ...list]);
}

export function u16ListExtension(type: number, values: number[]): number[] {
  const body = values.flatMap(u16);
  return extension(type, [...u16(body.length), ...body]);
}

export function supportedVersionsExtension(values: number[]): number[] {
  const body = values.flatMap(u16);
  return extension(0x002b, [body.length, ...body]);
}

export function pointFormatsExtension(values: number[]): number[] {
  return extension(0x000b, [values.length, ...values]);
}

export interface ClientHelloSpec {
  version?: number;
  ciphers: number[];
  extensions?: number[][];
  omitExtensions?: boolean;
  sessionId?: number[];
}

export function clientHelloHandshake(spec: ClientHelloSpec): number[] {
  const cipherBytes = spec.ciphers.flatMap(u16);
  const extensionBytes = (spec.extensions ?? []).flat();
  const sessionId = spec.sessionId ?? [];
  const body = [
    ...u16(spec.version ?? 0x0303),
    ...new Array<number>(32).fill(7),
    sessionId.length,
    ...sessionId,
    ...u16(cipherBytes.length),
    ...cipherBytes,
    1,
    0,
    ...(spec.omitExtensions ? [] : [...u16(extensionBytes.length), ...extensionBytes]),
  ];
  return [1, ...u24(body.length), ...body];
}

export function record(handshake: number[], recordVersion = 0x0301): number[] {
  return [0x16, ...u16(recordVersion), ...u16(handshake.length), ...handshake];
}

export function clientHelloRecord(spec: ClientHelloSpec): Uint8Array {
  return Uint8Array.from(record(clientHelloHandshake(spec)));
}

export const CHROME_LIKE_CIPHERS = [
  0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
  0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
];

export const CHROME_LIKE_SIGNATURES = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601];

export function chromeLikeExtensions(alpn: string[] = ["h2", "http/1.1"]): number[][] {
  return [
    extension(0x1a1a),
    sniExtension("example.com"),
    extension(0x0017),
    extension(0xff01, [0]),
    u16ListExtension(0x000a, [0x2a2a, 0x001d, 0x0017, 0x0018]),
    pointFormatsExtension([0]),
    extension(0x0023),
    alpnExtension(alpn),
    extension(0x0005, [1, 0, 0, 0, 0]),
    u16ListExtension(0x000d, CHROME_LIKE_SIGNATURES),
    extension(0x0012),
    extension(0x0033, [0, 0]),
    extension(0x002d, [1, 1]),
    supportedVersionsExtension([0x3a3a, 0x0304, 0x0303]),
    extension(0x001b, [2, 0, 2]),
    extension(0x4469, [0, 3, 2, 0x68, 0x32]),
    extension(0x0015, [0, 0, 0]),
    extension(0x5a5a, [0]),
  ];
}

export function chromeLikeHello(alpn?: string[]): Uint8Array {
  return clientHelloRecord({ ciphers: CHROME_LIKE_CIPHERS, extensions: chromeLikeExtensions(alpn) });
}
