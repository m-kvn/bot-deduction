export type BareItem = string | number | boolean;

export interface StructuredItem {
  value: BareItem;
  params: Map<string, BareItem>;
  bytes?: Buffer;
}

export interface DictionaryMember {
  key: string;
  raw: string;
  isList: boolean;
  items: StructuredItem[];
  params: Map<string, BareItem>;
}

class Cursor {
  index = 0;

  constructor(readonly text: string) {}

  get done(): boolean {
    return this.index >= this.text.length;
  }

  peek(): string {
    return this.text.charAt(this.index);
  }

  skipSpaces(): void {
    while (this.peek() === " " || this.peek() === "\t") {
      this.index += 1;
    }
  }
}

const KEY_START = /^[a-z*]$/;
const KEY_CHAR = /^[a-z0-9_.*-]$/;
const TOKEN = /^[A-Za-z*][A-Za-z0-9!#$%&'*+.^_`|~:/-]*/;
const NUMBER = /^-?\d{1,15}(?:\.\d{1,3})?/;
const BASE64 = /^[A-Za-z0-9+/]*={0,2}$/;

function parseKey(cursor: Cursor): string {
  if (!KEY_START.test(cursor.peek())) {
    throw new SyntaxError(`Invalid key at ${cursor.index}`);
  }
  const start = cursor.index;
  while (KEY_CHAR.test(cursor.peek())) {
    cursor.index += 1;
  }
  return cursor.text.slice(start, cursor.index);
}

function parseString(cursor: Cursor): string {
  cursor.index += 1;
  let output = "";
  while (!cursor.done) {
    const char = cursor.peek();
    cursor.index += 1;
    if (char === "\"") {
      return output;
    }
    if (char === "\\") {
      const escaped = cursor.peek();
      cursor.index += 1;
      if (escaped !== "\"" && escaped !== "\\") {
        throw new SyntaxError("Invalid escape in string");
      }
      output += escaped;
      continue;
    }
    const code = char.charCodeAt(0);
    if (code < 0x20 || code > 0x7e) {
      throw new SyntaxError("Invalid character in string");
    }
    output += char;
  }
  throw new SyntaxError("Unterminated string");
}

function parseBytes(cursor: Cursor): Buffer {
  const end = cursor.text.indexOf(":", cursor.index + 1);
  if (end === -1) {
    throw new SyntaxError("Unterminated byte sequence");
  }
  const encoded = cursor.text.slice(cursor.index + 1, end);
  if (!BASE64.test(encoded)) {
    throw new SyntaxError("Invalid byte sequence");
  }
  cursor.index = end + 1;
  return Buffer.from(encoded, "base64");
}

function parseBareItem(cursor: Cursor): { value: BareItem; bytes?: Buffer } {
  const char = cursor.peek();
  if (char === "\"") {
    return { value: parseString(cursor) };
  }
  if (char === ":") {
    const bytes = parseBytes(cursor);
    return { value: bytes.toString("base64"), bytes };
  }
  if (char === "?") {
    const flag = cursor.text.charAt(cursor.index + 1);
    if (flag !== "0" && flag !== "1") {
      throw new SyntaxError("Invalid boolean");
    }
    cursor.index += 2;
    return { value: flag === "1" };
  }
  const rest = cursor.text.slice(cursor.index);
  const number = NUMBER.exec(rest);
  if (number) {
    cursor.index += number[0].length;
    return { value: Number(number[0]) };
  }
  const token = TOKEN.exec(rest);
  if (token) {
    cursor.index += token[0].length;
    return { value: token[0] };
  }
  throw new SyntaxError(`Invalid item at ${cursor.index}`);
}

function parseParameters(cursor: Cursor): Map<string, BareItem> {
  const params = new Map<string, BareItem>();
  while (cursor.peek() === ";") {
    cursor.index += 1;
    cursor.skipSpaces();
    const key = parseKey(cursor);
    let value: BareItem = true;
    if (cursor.peek() === "=") {
      cursor.index += 1;
      value = parseBareItem(cursor).value;
    }
    params.set(key, value);
  }
  return params;
}

function parseItem(cursor: Cursor): StructuredItem {
  const { value, bytes } = parseBareItem(cursor);
  const params = parseParameters(cursor);
  return bytes ? { value, params, bytes } : { value, params };
}

function parseInnerList(cursor: Cursor): { items: StructuredItem[]; params: Map<string, BareItem> } {
  cursor.index += 1;
  const items: StructuredItem[] = [];
  for (;;) {
    cursor.skipSpaces();
    if (cursor.peek() === ")") {
      cursor.index += 1;
      return { items, params: parseParameters(cursor) };
    }
    if (cursor.done) {
      throw new SyntaxError("Unterminated inner list");
    }
    items.push(parseItem(cursor));
    if (cursor.peek() !== " " && cursor.peek() !== ")") {
      throw new SyntaxError(`Malformed inner list at ${cursor.index}`);
    }
  }
}

export function parseDictionary(input: string): DictionaryMember[] {
  const cursor = new Cursor(input);
  const members: DictionaryMember[] = [];
  cursor.skipSpaces();
  while (!cursor.done) {
    const key = parseKey(cursor);
    if (cursor.peek() !== "=") {
      const params = parseParameters(cursor);
      members.push({ key, raw: "?1", isList: false, items: [{ value: true, params }], params });
    } else {
      cursor.index += 1;
      const start = cursor.index;
      if (cursor.peek() === "(") {
        const { items, params } = parseInnerList(cursor);
        members.push({ key, raw: input.slice(start, cursor.index), isList: true, items, params });
      } else {
        const item = parseItem(cursor);
        members.push({ key, raw: input.slice(start, cursor.index), isList: false, items: [item], params: item.params });
      }
    }
    cursor.skipSpaces();
    if (cursor.done) {
      break;
    }
    if (cursor.peek() !== ",") {
      throw new SyntaxError(`Expected "," at ${cursor.index}`);
    }
    cursor.index += 1;
    cursor.skipSpaces();
    if (cursor.done) {
      throw new SyntaxError("Trailing comma in dictionary");
    }
  }
  return members;
}
