import { constants, generateKeyPairSync, sign } from "node:crypto";
import type { JsonWebKey, KeyObject } from "node:crypto";
import { jwkThumbprint } from "../../src/server/webBotAuth.js";

export interface TestKey {
  jwk: JsonWebKey;
  privateKey: KeyObject;
  keyId: string;
}

export function ed25519Key(): TestKey {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" });
  return { jwk, privateKey, keyId: jwkThumbprint(jwk) as string };
}

export function rsaKey(): TestKey {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = publicKey.export({ format: "jwk" });
  return { jwk, privateKey, keyId: jwkThumbprint(jwk) as string };
}

export interface SignOptions {
  key: TestKey;
  url: string;
  method?: string;
  components?: string[];
  created?: number;
  expires?: number | null;
  tag?: string;
  label?: string;
  keyId?: string | null;
  nonce?: string;
  alg?: string;
  rsa?: boolean;
  headers?: Record<string, string>;
  tamper?: boolean;
}

function authorityOf(url: URL): string {
  const host = url.hostname.toLowerCase();
  const standard = (url.protocol === "https:" && url.port === "443") || (url.protocol === "http:" && url.port === "80");
  return url.port && !standard ? `${host}:${url.port}` : host;
}

function componentOf(component: string, url: URL, method: string, headers: Record<string, string>): string {
  const [name, keyParam] = component.split(";key=");
  switch (name) {
    case "@authority":
      return authorityOf(url);
    case "@method":
      return method;
    case "@path":
      return url.pathname;
    case "@scheme":
      return url.protocol.slice(0, -1);
    case "@query":
      return url.search || "?";
    case "@target-uri":
      return `${url.protocol}//${authorityOf(url)}${url.pathname}${url.search}`;
    default:
      if (keyParam) {
        const wanted = keyParam.replace(/"/g, "");
        return headers[name].split(",").map((part) => part.trim()).find((part) => part.startsWith(`${wanted}=`))!.slice(wanted.length + 1);
      }
      return headers[name];
  }
}

export function signRequest(options: SignOptions): Record<string, string> {
  const url = new URL(options.url);
  const method = options.method ?? "GET";
  const now = Math.floor(Date.now() / 1000);
  const created = options.created ?? now;
  const components = options.components ?? ["@authority"];
  const params = [
    `created=${created}`,
    ...(options.expires === null ? [] : [`expires=${options.expires ?? created + 60}`]),
    ...(options.keyId === null ? [] : [`keyid="${options.keyId ?? options.key.keyId}"`]),
    ...(options.nonce ? [`nonce="${options.nonce}"`] : []),
    ...(options.alg ? [`alg="${options.alg}"`] : []),
    `tag="${options.tag ?? "web-bot-auth"}"`,
  ];
  const signatureParams = `(${components.map((component) => {
    const [name, keyParam] = component.split(";key=");
    return keyParam ? `"${name}";key=${keyParam}` : `"${name}"`;
  }).join(" ")});${params.join(";")}`;
  const headers = { ...options.headers };
  const base = [
    ...components.map((component) => {
      const [name, keyParam] = component.split(";key=");
      const id = keyParam ? `"${name}";key=${keyParam}` : `"${name}"`;
      return `${id}: ${componentOf(component, url, method, headers)}`;
    }),
    `"@signature-params": ${signatureParams}`,
  ].join("\n");
  const signature = options.rsa
    ? sign("sha512", Buffer.from(base), {
        key: options.key.privateKey,
        padding: constants.RSA_PKCS1_PSS_PADDING,
        saltLength: 64,
      })
    : sign(null, Buffer.from(base), options.key.privateKey);
  if (options.tamper) {
    signature[0] ^= 0xff;
  }
  const label = options.label ?? "sig1";
  return {
    ...headers,
    "signature-input": `${label}=${signatureParams}`,
    signature: `${label}=:${signature.toString("base64")}:`,
  };
}
