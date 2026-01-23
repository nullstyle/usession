import { assertEquals } from "jsr:@std/assert";
import {
  clearCookie,
  parseCookieHeader,
  serializeCookie,
} from "./cookie.ts";

Deno.test("parseCookieHeader handles single cookie", () => {
  const result = parseCookieHeader("session=abc123");
  assertEquals(result, { session: "abc123" });
});

Deno.test("parseCookieHeader handles multiple cookies", () => {
  const result = parseCookieHeader("foo=bar; session=abc123; baz=qux");
  assertEquals(result, { foo: "bar", session: "abc123", baz: "qux" });
});

Deno.test("parseCookieHeader handles spacing variations", () => {
  const result = parseCookieHeader("foo=bar;session=abc123;  baz=qux  ");
  assertEquals(result, { foo: "bar", session: "abc123", baz: "qux" });
});

Deno.test("parseCookieHeader first occurrence wins for duplicates", () => {
  const result = parseCookieHeader("foo=first; foo=second");
  assertEquals(result, { foo: "first" });
});

Deno.test("parseCookieHeader handles null", () => {
  const result = parseCookieHeader(null);
  assertEquals(result, {});
});

Deno.test("parseCookieHeader handles empty string", () => {
  const result = parseCookieHeader("");
  assertEquals(result, {});
});

Deno.test("parseCookieHeader handles invalid pairs", () => {
  const result = parseCookieHeader("foo=bar; invalid; baz=qux");
  assertEquals(result, { foo: "bar", baz: "qux" });
});

Deno.test("serializeCookie basic", () => {
  const result = serializeCookie("session", "abc123", {});
  assertEquals(result, "session=abc123");
});

Deno.test("serializeCookie with all options", () => {
  const expires = new Date("2023-01-01T00:00:00.000Z");
  const result = serializeCookie("session", "abc123", {
    path: "/",
    domain: "example.com",
    httpOnly: true,
    secure: true,
    sameSite: "Strict",
    maxAge: 3600,
    partitioned: true,
    expires,
  });

  assertEquals(result.includes("Path=/"), true);
  assertEquals(result.includes("Domain=example.com"), true);
  assertEquals(result.includes("HttpOnly"), true);
  assertEquals(result.includes("Secure"), true);
  assertEquals(result.includes("SameSite=Strict"), true);
  assertEquals(result.includes("Max-Age=3600"), true);
  assertEquals(result.includes("Partitioned"), true);
  assertEquals(result.includes("Expires=Sun, 01 Jan 2023 00:00:00 GMT"), true);
});

Deno.test("serializeCookie secure false", () => {
    // Should NOT include Secure
    const result = serializeCookie("session", "val", { secure: false });
    assertEquals(result.includes("Secure"), false);
});

Deno.test("serializeCookie secure auto", () => {
    // "auto" is handled by manager/middleware usually, but serializeCookie passes it through?
    // Looking at code: `if (opts.secure === true)`.
    // So "auto" results in NO Secure flag here (it expects boolean true).
    const result = serializeCookie("session", "val", { secure: "auto" });
    assertEquals(result.includes("Secure"), false);
});

Deno.test("clearCookie produces expiring cookie", () => {
  const result = clearCookie("session", { path: "/" });
  assertEquals(result.includes("Max-Age=0"), true);
  assertEquals(result.includes("Expires=Thu, 01 Jan 1970 00:00:00 GMT"), true);
});
