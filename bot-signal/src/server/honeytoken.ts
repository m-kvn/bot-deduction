import { createHmac, randomBytes } from "node:crypto";

export interface HoneytokenOptions {
  secret?: string;
  basePath?: string;
  rotate?: boolean;
  text?: string;
  now?: () => number;
}

export interface HoneytokenSnapshot {
  path: string;
  activePaths: readonly string[];
  linkHtml: string;
  linkAttributes: Readonly<Record<string, string>>;
}

export interface Honeytoken {
  readonly basePath: string;
  readonly rotate: boolean;
  readonly stable: boolean;
  current(): HoneytokenSnapshot;
}

export interface HoneypotFieldOptions {
  name?: string;
  label?: string;
  className?: string;
}

export interface HoneypotField {
  readonly name: string;
  readonly html: string;
  isFilled(value: unknown): boolean;
}

const DECOY_SEGMENTS: readonly string[] = [
  "archive",
  "files",
  "downloads",
  "export",
  "media",
  "reports",
  "records",
  "library",
];
const TOKEN_LENGTH = 12;
const DAY_MS = 86_400_000;
const HIDDEN_STYLE =
  "position:absolute;left:-9999px;top:auto;width:1px;height:1px;overflow:hidden";

export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function hmacHex(secret: string, label: string): string {
  return createHmac("sha256", secret).update(label).digest("hex");
}

function utcDay(timestamp: number): string {
  return new Date(timestamp).toISOString().slice(0, 10);
}

function linkAttributesFor(path: string): Record<string, string> {
  return {
    href: path,
    rel: "nofollow noindex",
    tabindex: "-1",
    "aria-hidden": "true",
    hidden: "",
    style: HIDDEN_STYLE,
  };
}

function linkHtmlFor(attributes: Record<string, string>, text: string): string {
  const rendered = Object.entries(attributes)
    .map(([name, value]) => (value === "" ? name : `${name}="${escapeHtml(value)}"`))
    .join(" ");
  return `<a ${rendered}>${escapeHtml(text)}</a>`;
}

export function createHoneytoken(options: HoneytokenOptions = {}): Honeytoken {
  const secret = options.secret ?? randomBytes(32).toString("hex");
  const basePath = (
    options.basePath ??
    `/${DECOY_SEGMENTS[parseInt(hmacHex(secret, "segment").slice(0, 2), 16) % DECOY_SEGMENTS.length]}`
  ).replace(/\/+$/, "");
  const rotate = options.rotate ?? false;
  const text = options.text ?? ".";
  const now = options.now ?? Date.now;
  const derive = (label: string) =>
    `${basePath}/${hmacHex(secret, label).slice(0, TOKEN_LENGTH)}`;
  let cachedKey: string | undefined;
  let cached: HoneytokenSnapshot | undefined;

  return {
    basePath,
    rotate,
    stable: options.secret !== undefined,
    current() {
      const timestamp = now();
      const key = rotate ? utcDay(timestamp) : "stable";
      if (cached && cachedKey === key) {
        return cached;
      }
      const path = derive(rotate ? `day:${key}` : "stable");
      const activePaths = rotate
        ? [...new Set([path, derive(`day:${utcDay(timestamp - DAY_MS)}`)])]
        : [path];
      const linkAttributes = linkAttributesFor(path);
      cachedKey = key;
      cached = {
        path,
        activePaths,
        linkAttributes,
        linkHtml: linkHtmlFor(linkAttributes, text),
      };
      return cached;
    },
  };
}

export function injectHoneytokenLink(html: string, linkHtml: string): string {
  if (!html || html.includes(linkHtml)) {
    return html;
  }

  const lower = html.toLowerCase();
  for (const closingTag of ["</body>", "</html>"]) {
    const index = lower.lastIndexOf(closingTag);
    if (index !== -1) {
      return `${html.slice(0, index)}${linkHtml}${html.slice(index)}`;
    }
  }
  return html;
}

export function isInjectableHtml(contentType: string | number | readonly string[] | undefined | null): boolean {
  if (typeof contentType !== "string") {
    return false;
  }
  const [mediaType, ...parameters] = contentType.toLowerCase().split(";");
  if (mediaType.trim() !== "text/html") {
    return false;
  }
  const charset = parameters
    .map((parameter) => parameter.trim())
    .find((parameter) => parameter.startsWith("charset="))
    ?.slice("charset=".length)
    .replace(/"/g, "");
  return charset === undefined || !/^(?:utf-?(?:16|32)|ucs-?[24])/.test(charset);
}

export function createHoneypotField(options: HoneypotFieldOptions = {}): HoneypotField {
  const name = options.name ?? "hp_check";
  const label = options.label ?? "Leave this field empty";
  const container = options.className
    ? `class="${escapeHtml(options.className)}"`
    : `style="${HIDDEN_STYLE}"`;

  return {
    name,
    html:
      `<div ${container} aria-hidden="true"><label>${escapeHtml(label)} ` +
      `<input type="text" name="${escapeHtml(name)}" value="" tabindex="-1" autocomplete="off"></label></div>`,
    isFilled: (value) =>
      value !== undefined && value !== null && String(value).trim() !== "",
  };
}
