export type AttackSignatureLocation = "path" | "query" | "body" | "headers";

export interface AttackSignatureInput {
  path?: string;
  query?: string;
  body?: string;
  headers?: Record<string, string | string[] | undefined>;
}

export interface AttackSignatureOptions {
  inspect?: readonly AttackSignatureLocation[];
  maxBytes?: number;
  exclude?: readonly string[];
}

export interface AttackSignatureMatch {
  id: string;
  label: string;
  where: string;
}

interface AttackSignature {
  id: string;
  label: string;
  test: RegExp;
}

const ATTACK_SIGNATURES: readonly AttackSignature[] = [
  {
    id: "sqli_union",
    label: "SQL UNION SELECT",
    test: /\bunion\b[\s/*()]+(?:all[\s/*()]+)?select\b[\s/*()]+(?:null\b|\d|\*|@@|0x|(?:concat|group_concat|char|version|database|user)\s*\(|[\w.`"'[\]]+[\s/*]*,|[\w.`"'[\]]+[\s/*]+from\b)/i,
  },
  {
    id: "sqli_tautology",
    label: "SQL tautology",
    test: /['"`]\s*(?:or|and)\s+(?:\d+\s*=\s*\d+|['"`][^'"`]{0,32}['"`]\s*=\s*['"`])/i,
  },
  {
    id: "sqli_stacked",
    label: "Stacked SQL statement",
    test: /;\s*(?:drop|truncate|alter|create|insert|update|delete)\s+(?:table|database|from|into)\b/i,
  },
  {
    id: "sqli_timing",
    label: "SQL timing function",
    test: /\b(?:pg_)?sleep\s*\(\s*\d+(?:\.\d+)?\s*\)|\bbenchmark\s*\(\s*\d+\s*,|\bwaitfor\s+delay\s+['"]/i,
  },
  { id: "sqli_probe", label: "SQL metadata probe", test: /\binformation_schema\.[a-z_]+/i },
  { id: "xss_script_tag", label: "Inline <script>", test: /<\s*script[\s>/]/i },
  { id: "xss_javascript_uri", label: "javascript: URI", test: /javascript\s*:[^\s]{0,64}\(/i },
  {
    id: "xss_event_handler",
    label: "Inline event handler",
    test: /<[a-z][a-z0-9]{0,15}[^>]{0,256}\son(?:error|load|click|mouseover|focus)\s*=/i,
  },
  { id: "xss_svg_onload", label: "SVG onload", test: /<\s*svg[^>]{0,128}\bonload\b/i },
  { id: "traversal", label: "Path traversal", test: /(?:\.\.[/\\]){3,}/ },
  {
    id: "traversal_sensitive",
    label: "Traversal to a sensitive file",
    test: /(?:\.\.[/\\])+(?:etc[/\\](?:passwd|shadow|hosts)\b|windows[/\\]win\.ini|boot\.ini|proc[/\\]self[/\\])/i,
  },
  { id: "traversal_etc", label: "Sensitive file path", test: /\/etc\/(?:passwd|shadow)\b/i },
  {
    id: "cmdi_shell",
    label: "Shell command injection",
    test: /[;|&`]\s*(?:cat|curl|wget|nc|ncat|bash|sh|zsh|python3?|perl|php|chmod)\s+(?:-{1,2}[a-z]|\/|~\/|https?:\/\/|\$)/i,
  },
  {
    id: "cmdi_subshell",
    label: "Shell substitution",
    test: /\$\((?:id|whoami|uname|cat|curl|wget|sleep|ls|pwd|echo)\b[^)]{0,64}\)/i,
  },
  { id: "ssti_jndi", label: "JNDI lookup (Log4Shell)", test: /\$\{\s*jndi\s*:/i },
  { id: "ssti_expression", label: "Template expression", test: /\{\{\s*[\w.]+\s*[(*]/ },
];

export const ATTACK_SIGNATURE_IDS: readonly string[] = ATTACK_SIGNATURES.map(
  (signature) => signature.id,
);

const DEFAULT_INSPECT: readonly AttackSignatureLocation[] = ["path", "query"];
const DEFAULT_MAX_BYTES = 16_384;
const ESCAPE_RUN = /(?:%[0-9a-f]{2})+/gi;
const ESCAPE = /%[0-9a-f]{2}/i;

function percentDecode(input: string): string {
  return input.replace(ESCAPE_RUN, (run) => {
    try {
      return decodeURIComponent(run);
    } catch {
      return Buffer.from(run.replace(/%/g, ""), "hex").toString("latin1");
    }
  });
}

function decodedForms(input: string, plusIsSpace: boolean): string[] {
  const forms = new Set([input]);
  let current = plusIsSpace ? input.replace(/\+/g, " ") : input;
  forms.add(current);
  for (let pass = 0; pass < 2 && ESCAPE.test(current); pass += 1) {
    current = percentDecode(current);
    forms.add(current);
  }
  return [...forms];
}

function windows(value: string, maxBytes: number): string[] {
  return value.length > maxBytes
    ? [value.slice(0, maxBytes), value.slice(-maxBytes)]
    : [value];
}

function inspectedParts(
  input: AttackSignatureInput,
  inspect: ReadonlySet<AttackSignatureLocation>,
): Array<[string, string | undefined, boolean]> {
  const parts: Array<[string, string | undefined, boolean]> = [];
  if (inspect.has("path")) parts.push(["path", input.path, false]);
  if (inspect.has("query")) parts.push(["query", input.query, true]);
  if (inspect.has("body")) parts.push(["body", input.body, false]);
  if (inspect.has("headers")) {
    for (const [name, value] of Object.entries(input.headers ?? {})) {
      if (name.toLowerCase() === "cookie") {
        continue;
      }
      parts.push([
        `header:${name.toLowerCase()}`,
        Array.isArray(value) ? value.join(", ") : value,
        false,
      ]);
    }
  }
  return parts;
}

export function findAttackSignature(
  input: AttackSignatureInput,
  options: AttackSignatureOptions = {},
): AttackSignatureMatch | null {
  const inspect = new Set(options.inspect ?? DEFAULT_INSPECT);
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;
  const excluded = new Set(options.exclude ?? []);
  const signatures = ATTACK_SIGNATURES.filter((signature) => !excluded.has(signature.id));

  for (const [where, raw, plusIsSpace] of inspectedParts(input, inspect)) {
    if (!raw) {
      continue;
    }
    for (const window of windows(raw, maxBytes)) {
      for (const form of decodedForms(window, plusIsSpace)) {
        const signature = signatures.find((candidate) => candidate.test.test(form));
        if (signature) {
          return { id: signature.id, label: signature.label, where };
        }
      }
    }
  }

  return null;
}
