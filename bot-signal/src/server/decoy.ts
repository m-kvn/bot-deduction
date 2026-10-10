import { createHmac, randomBytes } from "node:crypto";
import type { HeaderBag } from "./clientIp.js";
import { escapeHtml } from "./honeytoken.js";

export interface DecoyOptions {
  secret?: string;
  basePath?: string;
  credentialPrefix?: string;
  configId?: string;
}

export interface DecoyRequestParts {
  headers?: HeaderBag;
  query?: string;
  body?: string;
}

export type DecoyCredentialLocation = "header" | "query" | "body";

export interface Decoy {
  readonly path: string;
  readonly credential: string;
  readonly stable: boolean;
  readonly config: Readonly<{ apiBase: string; apiKey: string }>;
  readonly configHtml: string;
  matchesPath(path: string): boolean;
  findCredential(parts: DecoyRequestParts): DecoyCredentialLocation | undefined;
}

const DECOY_SEGMENTS: readonly string[] = ["internal", "admin", "private", "export", "debug", "backup", "legacy", "v0"];
const BROWSER_SUPPLIED_HEADERS: ReadonlySet<string> = new Set(["referer", "origin", "cookie"]);
const TOKEN_LENGTH = 12;
const CREDENTIAL_LENGTH = 32;

function hmacHex(secret: string, label: string): string {
  return createHmac("sha256", secret).update(label).digest("hex");
}

function safeDecode(value: string): string {
  try {
    return decodeURIComponent(value.replace(/\+/g, " "));
  } catch {
    return value;
  }
}

export function createDecoy(options: DecoyOptions = {}): Decoy {
  const secret = options.secret ?? randomBytes(32).toString("hex");
  const basePath = (
    options.basePath ??
    `/api/${DECOY_SEGMENTS[parseInt(hmacHex(secret, "decoy-segment").slice(0, 2), 16) % DECOY_SEGMENTS.length]}`
  ).replace(/\/+$/, "");
  const path = `${basePath}/${hmacHex(secret, "decoy-path").slice(0, TOKEN_LENGTH)}`;
  const credential = `${options.credentialPrefix ?? "key_live_"}${hmacHex(secret, "decoy-credential").slice(0, CREDENTIAL_LENGTH)}`;
  const config = Object.freeze({ apiBase: path, apiKey: credential });
  const lowerPath = path.toLowerCase();
  const configHtml =
    `<script type="application/json" id="${escapeHtml(options.configId ?? "api-config")}">` +
    `${JSON.stringify(config).replace(/</g, "\\u003c")}</script>`;

  return {
    path,
    credential,
    stable: options.secret !== undefined,
    config,
    configHtml,
    matchesPath(candidate) {
      const lower = candidate.toLowerCase();
      return lower === lowerPath || lower.startsWith(`${lowerPath}/`);
    },
    findCredential({ headers, query, body }) {
      const carriesKey = Object.entries(headers ?? {}).some(
        ([name, value]) =>
          !BROWSER_SUPPLIED_HEADERS.has(name.toLowerCase()) &&
          [value ?? []].flat().some((entry) => entry.includes(credential)),
      );
      if (carriesKey) {
        return "header";
      }
      if (query !== undefined && safeDecode(query).includes(credential)) {
        return "query";
      }
      if (body !== undefined && safeDecode(body).includes(credential)) {
        return "body";
      }
      return undefined;
    },
  };
}
