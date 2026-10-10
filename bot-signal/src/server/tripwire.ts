export const DEFAULT_TRIPWIRE_PATHS: readonly string[] = [
  "/.env",
  "/.env.local",
  "/.env.production",
  "/.env.development",
  "/.env.staging",
  "/.env.backup",
  "/.env.bak",
  "/.env.old",
  "/.git-credentials",
  "/.htpasswd",
  "/.npmrc",
  "/.DS_Store",
  "/.vscode/sftp.json",
  "/wp-config.php",
  "/config.php",
  "/phpinfo.php",
  "/server-status",
  "/actuator/env",
  "/backup.zip",
  "/backup.sql",
  "/database.sql",
  "/dump.sql",
  "/id_rsa",
];

export const DEFAULT_TRIPWIRE_PREFIXES: readonly string[] = [
  "/.git/",
  "/.svn/",
  "/.hg/",
  "/.aws/",
  "/.ssh/",
];

export interface TripwireOptions {
  paths?: readonly string[];
  prefixes?: readonly string[];
  patterns?: readonly RegExp[];
  includeDefaults?: boolean;
}

export type TripwireMatchKind = "path" | "prefix" | "pattern";

export interface TripwireMatch {
  path: string;
  matchedBy: TripwireMatchKind;
  isDefault: boolean;
}

export interface Tripwire {
  readonly paths: readonly string[];
  readonly prefixes: readonly string[];
  match(path: string): TripwireMatch | null;
}

function hexValue(code: number): number {
  if (code >= 48 && code <= 57) return code - 48;
  if (code >= 97 && code <= 102) return code - 87;
  if (code >= 65 && code <= 70) return code - 55;
  return -1;
}

function decodeAsciiPercentOnce(value: string): string {
  let output = "";
  for (let index = 0; index < value.length; index += 1) {
    if (value[index] === "%" && index + 2 < value.length) {
      const high = hexValue(value.charCodeAt(index + 1));
      const low = hexValue(value.charCodeAt(index + 2));
      const byte = (high << 4) | low;
      if (high >= 0 && low >= 0 && byte < 0x80) {
        output += String.fromCharCode(byte);
        index += 2;
        continue;
      }
    }
    output += value[index];
  }
  return output;
}

function resolveSegments(value: string): string {
  const trailingSlash = value.length > 1 && value.endsWith("/");
  const stack: string[] = [];
  for (const segment of value.replace(/\\/g, "/").split("/")) {
    if (segment === "" || segment === ".") {
      continue;
    }
    if (segment === "..") {
      stack.pop();
      continue;
    }
    stack.push(segment);
  }
  const resolved = `/${stack.join("/")}`;
  return trailingSlash && resolved !== "/" ? `${resolved}/` : resolved;
}

export function canonicalizeRequestPath(path: string): string {
  let value = path.split(/[?#]/, 1)[0];
  for (let pass = 0; pass < 4 && value.includes("%"); pass += 1) {
    const next = decodeAsciiPercentOnce(value);
    if (next === value) {
      break;
    }
    value = next;
  }
  return resolveSegments(value);
}

function normalizeEntry(entry: string): string {
  return canonicalizeRequestPath(entry).toLowerCase();
}

export function createTripwire(options: TripwireOptions = {}): Tripwire {
  const includeDefaults = options.includeDefaults ?? true;
  const customPaths = (options.paths ?? []).map(normalizeEntry);
  const customPrefixes = (options.prefixes ?? []).map(normalizeEntry);
  const defaultPaths = includeDefaults ? DEFAULT_TRIPWIRE_PATHS.map(normalizeEntry) : [];
  const defaultPrefixes = includeDefaults ? [...DEFAULT_TRIPWIRE_PREFIXES] : [];
  const exact = new Map<string, boolean>();
  for (const path of defaultPaths) exact.set(path, true);
  for (const path of customPaths) exact.set(path, false);
  const prefixes: Array<[string, boolean]> = [
    ...customPrefixes.map((prefix): [string, boolean] => [prefix, false]),
    ...defaultPrefixes.map((prefix): [string, boolean] => [prefix, true]),
  ];
  const patterns = (options.patterns ?? []).map(
    (pattern) => new RegExp(pattern.source, pattern.flags.replace(/[gy]/g, "")),
  );

  return {
    paths: [...exact.keys()],
    prefixes: prefixes.map(([prefix]) => prefix),
    match(path) {
      const canonical = canonicalizeRequestPath(path);
      const lower = canonical.toLowerCase();
      const exactDefault = exact.get(lower);
      if (exactDefault !== undefined) {
        return { path: canonical, matchedBy: "path", isDefault: exactDefault };
      }
      const prefix = prefixes.find(([candidate]) => lower.startsWith(candidate));
      if (prefix) {
        return { path: canonical, matchedBy: "prefix", isDefault: prefix[1] };
      }
      if (patterns.some((pattern) => pattern.test(canonical))) {
        return { path: canonical, matchedBy: "pattern", isDefault: false };
      }
      return null;
    },
  };
}
