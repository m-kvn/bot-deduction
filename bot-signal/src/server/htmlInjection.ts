import type { ServerResponse } from "node:http";
import { isInjectableHtml } from "./honeytoken.js";

type WriteHeadArgs = Parameters<ServerResponse["writeHead"]>;

interface ScanState {
  closer: string | null;
  position: number;
}

const SCAN_PATTERN = /<!--|<script\b|<style\b|<\/body\b/g;
const HOLDBACK_BYTES = 8;
const MAX_BUFFERED_BYTES = 2 * 1024 * 1024;

export function findBodyCloseIndex(lowerHtml: string, state: ScanState = { closer: null, position: 0 }): number {
  for (;;) {
    if (state.closer) {
      const end = lowerHtml.indexOf(state.closer, state.position);
      if (end === -1) {
        state.position = Math.max(state.position, lowerHtml.length - state.closer.length + 1);
        return -1;
      }
      state.position = end + state.closer.length;
      state.closer = null;
    }
    SCAN_PATTERN.lastIndex = state.position;
    const match = SCAN_PATTERN.exec(lowerHtml);
    if (!match) {
      state.position = Math.max(state.position, lowerHtml.length - HOLDBACK_BYTES);
      return -1;
    }
    if (match[0] === "</body") {
      return match.index;
    }
    state.closer = match[0] === "<!--" ? "-->" : match[0] === "<script" ? "</script" : "</style";
    state.position = SCAN_PATTERN.lastIndex;
  }
}

function headerArgument(args: readonly unknown[]): unknown {
  const last = args[args.length - 1];
  return typeof last === "object" && last !== null ? last : undefined;
}

function headerEntries(headers: unknown): Array<[string, unknown]> {
  if (Array.isArray(headers)) {
    const pairs: Array<[string, unknown]> = [];
    for (let index = 0; index + 1 < headers.length; index += 2) {
      pairs.push([String(headers[index]), headers[index + 1]]);
    }
    return pairs;
  }
  return Object.entries(headers as Record<string, unknown>);
}

function headerFrom(res: ServerResponse, headArgs: readonly unknown[], name: string): unknown {
  const headers = headerArgument(headArgs);
  const pair = headers === undefined
    ? undefined
    : headerEntries(headers).find(([key]) => key.toLowerCase() === name);
  return pair ? pair[1] : res.getHeader(name);
}

function withContentLengthDelta(res: ServerResponse, args: unknown[], delta: number): unknown[] {
  const headers = headerArgument(args);
  if (headers !== undefined) {
    if (Array.isArray(headers)) {
      const copy = headers.map((value, index) =>
        index % 2 === 1 && String(headers[index - 1]).toLowerCase() === "content-length"
          ? String(Number(value) + delta)
          : value,
      );
      return [...args.slice(0, -1), copy];
    }
    const entry = Object.keys(headers as object).find((key) => key.toLowerCase() === "content-length");
    if (entry !== undefined) {
      const record = headers as Record<string, unknown>;
      return [...args.slice(0, -1), { ...record, [entry]: String(Number(record[entry]) + delta) }];
    }
  }
  if (res.hasHeader("content-length")) {
    res.setHeader("content-length", String(Number(res.getHeader("content-length")) + delta));
  }
  return args;
}

function toBuffer(chunk: unknown, encoding: unknown): Buffer {
  if (Buffer.isBuffer(chunk)) {
    return chunk;
  }
  if (chunk instanceof Uint8Array) {
    return Buffer.from(chunk);
  }
  return Buffer.from(String(chunk), typeof encoding === "string" ? (encoding as BufferEncoding) : "utf8");
}

export function injectHoneytokenIntoResponse(res: ServerResponse, linkHtml: string): void {
  const originalWriteHead = res.writeHead;
  const originalWrite = res.write as (...args: unknown[]) => boolean;
  const originalEnd = res.end as (...args: unknown[]) => ServerResponse;
  const link = Buffer.from(linkHtml, "utf8");
  const state: ScanState = { closer: null, position: 0 };
  let mode: "undecided" | "scan" | "pass" = "undecided";
  let pendingHead: unknown[] | null = null;
  let headCommitted = false;
  let lengthDeclared: boolean | null = null;
  let held: Buffer[] = [];
  let heldBytes = 0;
  let lower = "";
  let lowerOffset = 0;

  const decide = (statusCode: number, headArgs: readonly unknown[]) => {
    if (mode !== "undecided") {
      return;
    }
    const encoding = headerFrom(res, headArgs, "content-encoding");
    mode =
      statusCode === 200 &&
      isInjectableHtml(headerFrom(res, headArgs, "content-type") as string | undefined) &&
      (encoding === undefined || String(encoding).toLowerCase() === "identity")
        ? "scan"
        : "pass";
  };

  const commitHead = (delta: number) => {
    if (headCommitted) {
      return;
    }
    headCommitted = true;
    const args = pendingHead;
    pendingHead = null;
    if (args) {
      originalWriteHead.apply(res, withContentLengthDelta(res, args, delta) as WriteHeadArgs);
    } else if (delta !== 0) {
      withContentLengthDelta(res, [], delta);
    }
  };

  const takeHeld = (): Buffer => {
    const all = held.length === 1 ? held[0] : Buffer.concat(held);
    held = [];
    heldBytes = 0;
    return all;
  };

  const emit = (chunk: Buffer) => {
    if (chunk.length > 0) {
      originalWrite.call(res, chunk);
    }
  };

  const absorb = (incoming: Buffer): number => {
    if (lengthDeclared === null) {
      lengthDeclared = headerFrom(res, pendingHead ? pendingHead.slice(1) : [], "content-length") !== undefined;
    }
    held.push(incoming);
    heldBytes += incoming.length;
    lower += incoming.toString("latin1").toLowerCase();
    const index = findBodyCloseIndex(lower, state);
    if (index !== -1) {
      return lowerOffset + index;
    }
    lower = lower.slice(state.position);
    lowerOffset += state.position;
    state.position = 0;
    return -1;
  };

  const injectAt = (index: number): Buffer[] => {
    const all = takeHeld();
    mode = "pass";
    commitHead(link.length);
    return [all.subarray(0, index), link, all.subarray(index)];
  };

  const streamOrBuffer = () => {
    if (lengthDeclared) {
      if (heldBytes > MAX_BUFFERED_BYTES) {
        mode = "pass";
        commitHead(0);
        emit(takeHeld());
      }
      return;
    }
    const flushed = heldBytes - HOLDBACK_BYTES;
    if (flushed <= 0) {
      return;
    }
    commitHead(0);
    const all = takeHeld();
    emit(all.subarray(0, flushed));
    const tail = all.subarray(flushed);
    held = [tail];
    heldBytes = tail.length;
    lowerOffset -= flushed;
  };

  res.writeHead = function writeHead(this: ServerResponse, ...args: unknown[]) {
    decide(args[0] as number, args.slice(1));
    if (mode === "pass" || headCommitted) {
      return originalWriteHead.apply(res, args as WriteHeadArgs);
    }
    pendingHead = args;
    return res;
  } as ServerResponse["writeHead"];

  res.write = function write(this: ServerResponse, ...args: unknown[]) {
    decide(res.statusCode, []);
    if (mode === "pass") {
      return originalWrite.apply(res, args);
    }
    const [chunk, encoding, callback] = args;
    const done = typeof encoding === "function" ? encoding : callback;
    const index = absorb(toBuffer(chunk, encoding));
    if (index !== -1) {
      injectAt(index).forEach(emit);
    } else {
      streamOrBuffer();
    }
    if (typeof done === "function") {
      process.nextTick(done as () => void);
    }
    return true;
  } as ServerResponse["write"];

  res.end = function end(this: ServerResponse, ...args: unknown[]) {
    decide(res.statusCode, []);
    if (mode === "pass") {
      return originalEnd.apply(res, args);
    }
    const callback = args.find((arg) => typeof arg === "function");
    const [chunk, encoding] = args;
    const index = absorb(
      chunk === undefined || chunk === null || typeof chunk === "function"
        ? Buffer.alloc(0)
        : toBuffer(chunk, encoding),
    );
    if (index !== -1) {
      return originalEnd.call(res, Buffer.concat(injectAt(index)), callback);
    }
    mode = "pass";
    commitHead(0);
    return originalEnd.call(res, takeHeld(), callback);
  } as ServerResponse["end"];
}
