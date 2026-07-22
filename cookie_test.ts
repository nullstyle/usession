import { assertEquals, assertMatch, assertThrows } from "@std/assert";
import {
  clearCookie,
  parseCookieHeader,
  parseCookieHeaderAll,
  serializeCookie,
} from "./cookie.ts";

// ---------------------------------------------------------------------------
// parseCookieHeader — basics
// ---------------------------------------------------------------------------

Deno.test("parseCookieHeader parses a single pair", () => {
  assertEquals(parseCookieHeader("foo=bar"), { foo: "bar" });
});

Deno.test("parseCookieHeader parses multiple pairs", () => {
  assertEquals(parseCookieHeader("a=1; b=2; c=3"), { a: "1", b: "2", c: "3" });
});

Deno.test("parseCookieHeader tolerates missing spaces after semicolons", () => {
  assertEquals(parseCookieHeader("a=1;b=2;c=3"), { a: "1", b: "2", c: "3" });
});

Deno.test("parseCookieHeader tolerates extra whitespace around pairs", () => {
  assertEquals(parseCookieHeader("   a = 1 ;   b =  2   "), {
    a: "1",
    b: "2",
  });
});

Deno.test("parseCookieHeader returns an empty object for null", () => {
  assertEquals(parseCookieHeader(null), {});
});

Deno.test("parseCookieHeader returns an empty object for an empty string", () => {
  assertEquals(parseCookieHeader(""), {});
});

Deno.test("parseCookieHeader skips pairs with no equals sign", () => {
  assertEquals(parseCookieHeader("novalue; a=1"), { a: "1" });
});

Deno.test("parseCookieHeader keeps everything after the first equals sign", () => {
  assertEquals(parseCookieHeader("token=v2.abc=def=ghi"), {
    token: "v2.abc=def=ghi",
  });
});

Deno.test("parseCookieHeader keeps a pair with an empty value", () => {
  assertEquals(parseCookieHeader("a=; b=2"), { a: "", b: "2" });
});

Deno.test("parseCookieHeader skips a pair with an empty name", () => {
  assertEquals(parseCookieHeader("=orphan; a=1"), { a: "1" });
});

Deno.test("parseCookieHeader ignores leading and trailing semicolons", () => {
  assertEquals(parseCookieHeader(";; a=1 ;;; b=2 ;;"), { a: "1", b: "2" });
});

Deno.test("parseCookieHeader returns an empty object for only semicolons", () => {
  assertEquals(parseCookieHeader(";;;"), {});
});

Deno.test("parseCookieHeader keeps inner spaces in a value", () => {
  assertEquals(parseCookieHeader("a=1 2 3; b=2"), { a: "1 2 3", b: "2" });
});

Deno.test("parseCookieHeader keeps a value that is only equals signs", () => {
  assertEquals(parseCookieHeader("a==="), { a: "==" });
});

// ---------------------------------------------------------------------------
// parseCookieHeader — prototype safety (regression)
// ---------------------------------------------------------------------------

Deno.test("parseCookieHeader returns both keys when one shadows toString", () => {
  const cookies = parseCookieHeader("foo=bar; toString=evil");
  assertEquals(cookies.foo, "bar");
  const shadowed: unknown = cookies["toString"];
  assertEquals(shadowed, "evil");
});

Deno.test("parseCookieHeader lists toString in Object.keys", () => {
  const cookies = parseCookieHeader("foo=bar; toString=evil");
  assertEquals(Object.keys(cookies).sort(), ["foo", "toString"]);
});

Deno.test("parseCookieHeader does not leave toString as a function", () => {
  const cookies = parseCookieHeader("toString=evil");
  const shadowed: unknown = cookies["toString"];
  assertEquals(typeof shadowed, "string");
});

Deno.test("parseCookieHeader captures a __proto__ cookie as a real entry", () => {
  const cookies = parseCookieHeader("foo=bar; __proto__=evil");
  assertEquals(Object.keys(cookies).sort(), ["__proto__", "foo"]);
  assertEquals(cookies["__proto__"], "evil");
});

Deno.test("parseCookieHeader captures a constructor cookie as a real entry", () => {
  const cookies = parseCookieHeader("foo=bar; constructor=evil");
  assertEquals(Object.keys(cookies).sort(), ["constructor", "foo"]);
  assertEquals(cookies["constructor"], "evil");
  assertEquals(typeof cookies["constructor"], "string");
});

Deno.test("parseCookieHeader does not pollute Object.prototype", () => {
  const before = Object.getOwnPropertyNames(Object.prototype).sort();
  parseCookieHeader("__proto__=polluted; constructor=polluted; a=1");
  parseCookieHeaderAll("__proto__=polluted; constructor=polluted; a=1");
  const probe = {} as Record<string, unknown>;
  assertEquals(probe["polluted"], undefined);
  assertEquals("polluted" in probe, false);
  assertEquals(Object.getPrototypeOf(probe), Object.prototype);
  assertEquals(Object.getOwnPropertyNames(Object.prototype).sort(), before);
});

Deno.test("parseCookieHeader stores shadowing names as own properties", () => {
  const cookies = parseCookieHeader("toString=a; __proto__=b; constructor=c");
  assertEquals(Object.hasOwn(cookies, "toString"), true);
  assertEquals(Object.hasOwn(cookies, "__proto__"), true);
  assertEquals(Object.hasOwn(cookies, "constructor"), true);
});

Deno.test("parseCookieHeaderAll captures __proto__ without pollution", () => {
  const all = parseCookieHeaderAll("__proto__=evil");
  assertEquals(all["__proto__"], ["evil"]);
  assertEquals(Object.keys(all), ["__proto__"]);
});

Deno.test("parseCookieHeaderAll returns a null-prototype map", () => {
  const all = parseCookieHeaderAll("foo=bar");
  assertEquals(Object.getPrototypeOf(all), null);
  assertEquals(all["toString"], undefined);
});

// ---------------------------------------------------------------------------
// Duplicates
// ---------------------------------------------------------------------------

Deno.test("parseCookieHeader keeps the first of duplicate names", () => {
  assertEquals(parseCookieHeader("s=first; s=second; s=third"), {
    s: "first",
  });
});

Deno.test("parseCookieHeaderAll keeps every duplicate in header order", () => {
  assertEquals(parseCookieHeaderAll("s=first; s=second; s=third"), {
    s: ["first", "second", "third"],
  });
});

Deno.test("parseCookieHeaderAll wraps a single value in an array", () => {
  assertEquals(parseCookieHeaderAll("a=1; b=2"), { a: ["1"], b: ["2"] });
});

Deno.test("parseCookieHeaderAll returns an empty map for null", () => {
  assertEquals(parseCookieHeaderAll(null), {});
  assertEquals(Object.keys(parseCookieHeaderAll(null)).length, 0);
});

Deno.test("parseCookieHeaderAll returns an empty map for an empty string", () => {
  assertEquals(parseCookieHeaderAll(""), {});
});

Deno.test("parseCookieHeaderAll preserves order across interleaved names", () => {
  assertEquals(parseCookieHeaderAll("s=a; other=x; s=b; other=y; s=c"), {
    s: ["a", "b", "c"],
    other: ["x", "y"],
  });
});

Deno.test("parseCookieHeader keeps a first duplicate whose value is empty", () => {
  assertEquals(parseCookieHeader("s=; s=second"), { s: "" });
});

// ---------------------------------------------------------------------------
// serializeCookie — happy paths
// ---------------------------------------------------------------------------

Deno.test("serializeCookie serializes a bare name and value", () => {
  assertEquals(serializeCookie("a", "1"), "a=1");
});

Deno.test("serializeCookie serializes an empty value", () => {
  assertEquals(serializeCookie("a", ""), "a=");
});

Deno.test("serializeCookie accepts a base64url token value", () => {
  const value = "v2.abc-_DEF123.ghi-_JKL456";
  assertEquals(serializeCookie("session", value), `session=${value}`);
});

Deno.test("serializeCookie emits every attribute at once in a stable order", () => {
  const header = serializeCookie("s", "v", {
    path: "/",
    domain: "example.com",
    maxAge: 60,
    expires: new Date(0),
    httpOnly: true,
    secure: true,
    sameSite: "Lax",
    partitioned: true,
  });
  assertEquals(
    header,
    "s=v; Path=/; Domain=example.com; Max-Age=60; " +
      "Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; " +
      "SameSite=Lax; Partitioned",
  );
});

Deno.test("serializeCookie emits Path alone", () => {
  assertEquals(serializeCookie("a", "1", { path: "/sub" }), "a=1; Path=/sub");
});

Deno.test("serializeCookie emits Domain alone", () => {
  assertEquals(
    serializeCookie("a", "1", { domain: "example.com" }),
    "a=1; Domain=example.com",
  );
});

Deno.test("serializeCookie emits Max-Age alone", () => {
  assertEquals(
    serializeCookie("a", "1", { maxAge: 3600 }),
    "a=1; Max-Age=3600",
  );
});

Deno.test("serializeCookie emits Expires alone", () => {
  assertEquals(
    serializeCookie("a", "1", { expires: new Date(0) }),
    "a=1; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
  );
});

Deno.test("serializeCookie emits HttpOnly alone", () => {
  assertEquals(serializeCookie("a", "1", { httpOnly: true }), "a=1; HttpOnly");
});

Deno.test("serializeCookie emits Secure alone", () => {
  assertEquals(serializeCookie("a", "1", { secure: true }), "a=1; Secure");
});

Deno.test("serializeCookie emits SameSite=Strict alone", () => {
  assertEquals(
    serializeCookie("a", "1", { sameSite: "Strict" }),
    "a=1; SameSite=Strict",
  );
});

Deno.test("serializeCookie emits SameSite=None alone", () => {
  assertEquals(
    serializeCookie("a", "1", { sameSite: "None" }),
    "a=1; SameSite=None",
  );
});

Deno.test("serializeCookie emits Partitioned alone", () => {
  assertEquals(
    serializeCookie("a", "1", { partitioned: true }),
    "a=1; Partitioned",
  );
});

Deno.test("serializeCookie omits Secure when secure is false", () => {
  assertEquals(serializeCookie("a", "1", { secure: false }), "a=1");
});

Deno.test("serializeCookie omits HttpOnly and Partitioned when false", () => {
  assertEquals(
    serializeCookie("a", "1", { httpOnly: false, partitioned: false }),
    "a=1",
  );
});

Deno.test("serializeCookie omits attributes left undefined", () => {
  assertEquals(
    serializeCookie("a", "1", {
      path: undefined,
      domain: undefined,
      maxAge: undefined,
      expires: undefined,
      sameSite: undefined,
    }),
    "a=1",
  );
});

Deno.test("serializeCookie emits Secure for an unresolved auto sentinel", () => {
  assertEquals(
    serializeCookie("a", "1", { secure: "auto" as never }),
    "a=1; Secure",
  );
});

Deno.test("serializeCookie accepts a base64 value with padding equals", () => {
  assertEquals(serializeCookie("s", "YWJjZA=="), "s=YWJjZA==");
});

Deno.test("serializeCookie accepts the full printable cookie-octet range", () => {
  const octets = [
    0x21,
    ...Array.from({ length: 0x2b - 0x23 + 1 }, (_, i) => 0x23 + i),
    ...Array.from({ length: 0x3a - 0x2d + 1 }, (_, i) => 0x2d + i),
    ...Array.from({ length: 0x5b - 0x3c + 1 }, (_, i) => 0x3c + i),
    ...Array.from({ length: 0x7e - 0x5d + 1 }, (_, i) => 0x5d + i),
  ];
  const value = octets.map((c) => String.fromCharCode(c)).join("");
  assertEquals(serializeCookie("s", value), `s=${value}`);
});

Deno.test("serializeCookie emits Expires from a real Date in UTC form", () => {
  assertEquals(
    serializeCookie("a", "1", { expires: new Date("2030-06-15T12:34:56Z") }),
    "a=1; Expires=Sat, 15 Jun 2030 12:34:56 GMT",
  );
});

// ---------------------------------------------------------------------------
// serializeCookie — name validation
// ---------------------------------------------------------------------------

Deno.test("serializeCookie rejects an empty name", () => {
  assertThrows(
    () => serializeCookie("", "1"),
    TypeError,
    "invalid cookie name",
  );
});

Deno.test("serializeCookie rejects a name containing a space", () => {
  assertThrows(() => serializeCookie("a b", "1"), TypeError);
});

Deno.test("serializeCookie rejects a name containing a semicolon", () => {
  assertThrows(() => serializeCookie("a;b", "1"), TypeError);
});

Deno.test("serializeCookie rejects a name containing an equals sign", () => {
  assertThrows(() => serializeCookie("a=b", "1"), TypeError);
});

Deno.test("serializeCookie rejects a name containing a comma", () => {
  assertThrows(() => serializeCookie("a,b", "1"), TypeError);
});

Deno.test("serializeCookie rejects a name containing a control char", () => {
  assertThrows(() => serializeCookie("a\nb", "1"), TypeError);
  assertThrows(() => serializeCookie("a\tb", "1"), TypeError);
});

Deno.test("serializeCookie rejects a NUL or DEL in the name", () => {
  assertThrows(
    () => serializeCookie(`a${String.fromCharCode(0)}b`, "1"),
    TypeError,
  );
  assertThrows(
    () => serializeCookie(`a${String.fromCharCode(0x7f)}b`, "1"),
    TypeError,
  );
});

Deno.test("serializeCookie rejects a non-ASCII name", () => {
  assertThrows(() => serializeCookie("café", "1"), TypeError);
});

Deno.test("serializeCookie accepts prefixed and punctuated token names", () => {
  assertEquals(serializeCookie("__Host-session", "1"), "__Host-session=1");
  assertEquals(serializeCookie("__Secure-s", "1"), "__Secure-s=1");
  assertEquals(serializeCookie("a.b_c~d!", "1"), "a.b_c~d!=1");
});

// ---------------------------------------------------------------------------
// serializeCookie — value validation
// ---------------------------------------------------------------------------

Deno.test("serializeCookie rejects attribute injection through the value", () => {
  assertThrows(
    () => serializeCookie("lang", "en; Domain=.evil.com; Max-Age=99999"),
    TypeError,
    "invalid cookie value",
  );
});

Deno.test("serializeCookie rejects a value containing a semicolon", () => {
  assertThrows(() => serializeCookie("a", "x;y"), TypeError);
});

Deno.test("serializeCookie rejects a value containing a comma", () => {
  assertThrows(() => serializeCookie("a", "x,y"), TypeError);
});

Deno.test("serializeCookie rejects a value containing a space", () => {
  assertThrows(() => serializeCookie("a", "x y"), TypeError);
});

Deno.test("serializeCookie rejects a value containing a double quote", () => {
  assertThrows(() => serializeCookie("a", 'x"y'), TypeError);
});

Deno.test("serializeCookie rejects a value containing a backslash", () => {
  assertThrows(() => serializeCookie("a", "x\\y"), TypeError);
});

Deno.test("serializeCookie rejects a value containing CR or LF", () => {
  assertThrows(() => serializeCookie("a", "x\ny"), TypeError);
  assertThrows(() => serializeCookie("a", "x\ry"), TypeError);
});

Deno.test("serializeCookie rejects a header-splitting value", () => {
  assertThrows(
    () => serializeCookie("a", "x\r\nSet-Cookie: evil=1"),
    TypeError,
  );
});

Deno.test("serializeCookie rejects a non-ASCII value", () => {
  assertThrows(() => serializeCookie("a", "café"), TypeError);
  assertThrows(() => serializeCookie("a", " "), TypeError);
});

// ---------------------------------------------------------------------------
// serializeCookie — attribute validation
// ---------------------------------------------------------------------------

Deno.test("serializeCookie rejects a NUL, DEL or TAB in the value", () => {
  assertThrows(
    () => serializeCookie("a", `x${String.fromCharCode(0)}y`),
    TypeError,
  );
  assertThrows(
    () => serializeCookie("a", `x${String.fromCharCode(0x7f)}y`),
    TypeError,
  );
  assertThrows(
    () => serializeCookie("a", `x${String.fromCharCode(9)}y`),
    TypeError,
  );
});

Deno.test("serializeCookie rejects a value that is a single plain space", () => {
  assertThrows(() => serializeCookie("a", " "), TypeError);
});

Deno.test("serializeCookie rejects a Path containing a semicolon", () => {
  assertThrows(
    () => serializeCookie("a", "1", { path: "/; Domain=.evil.com" }),
    TypeError,
    "invalid cookie Path",
  );
});

Deno.test("serializeCookie rejects a Path containing a control char", () => {
  assertThrows(() => serializeCookie("a", "1", { path: "/\r\n" }), TypeError);
});

Deno.test("serializeCookie rejects a Domain containing a semicolon", () => {
  assertThrows(
    () => serializeCookie("a", "1", { domain: "evil.com; Secure" }),
    TypeError,
    "invalid cookie Domain",
  );
});

Deno.test("serializeCookie rejects a Domain containing a control char", () => {
  assertThrows(
    () => serializeCookie("a", "1", { domain: "evil.com\n" }),
    TypeError,
  );
});

Deno.test("serializeCookie accepts a Path containing a space and equals", () => {
  assertEquals(
    serializeCookie("a", "1", { path: "/a b=c" }),
    "a=1; Path=/a b=c",
  );
});

Deno.test("serializeCookie rejects a non-integer Max-Age", () => {
  assertThrows(
    () => serializeCookie("a", "1", { maxAge: 1.5 }),
    TypeError,
    "Max-Age",
  );
});

Deno.test("serializeCookie rejects a NaN Max-Age", () => {
  assertThrows(() => serializeCookie("a", "1", { maxAge: NaN }), TypeError);
});

Deno.test("serializeCookie rejects an infinite Max-Age", () => {
  assertThrows(
    () => serializeCookie("a", "1", { maxAge: Infinity }),
    TypeError,
  );
  assertThrows(
    () => serializeCookie("a", "1", { maxAge: -Infinity }),
    TypeError,
  );
});

Deno.test("serializeCookie accepts a zero Max-Age", () => {
  assertEquals(serializeCookie("a", "1", { maxAge: 0 }), "a=1; Max-Age=0");
});

Deno.test("serializeCookie accepts a negative integer Max-Age", () => {
  assertEquals(serializeCookie("a", "1", { maxAge: -1 }), "a=1; Max-Age=-1");
});

Deno.test("serializeCookie rejects an invalid Date for Expires", () => {
  assertThrows(
    () => serializeCookie("a", "1", { expires: new Date("nope") }),
    TypeError,
    "Expires",
  );
  assertThrows(
    () => serializeCookie("a", "1", { expires: new Date(NaN) }),
    TypeError,
  );
});

Deno.test("serializeCookie rejects a non-number Max-Age", () => {
  assertThrows(
    // @ts-expect-error deliberately passing the wrong type
    () => serializeCookie("a", "1", { maxAge: "60" }),
    TypeError,
  );
});

Deno.test("serializeCookie rejects a NUL or DEL in Path or Domain", () => {
  assertThrows(
    () => serializeCookie("a", "1", { path: `/${String.fromCharCode(0)}` }),
    TypeError,
  );
  assertThrows(
    () =>
      serializeCookie("a", "1", { domain: `e${String.fromCharCode(0x7f)}` }),
    TypeError,
  );
});

Deno.test("serializeCookie accepts an empty Path", () => {
  assertEquals(serializeCookie("a", "1", { path: "" }), "a=1; Path=");
});

// ---------------------------------------------------------------------------
// clearCookie
// ---------------------------------------------------------------------------

Deno.test("clearCookie emits Max-Age=0 and the epoch Expires", () => {
  assertEquals(
    clearCookie("s"),
    "s=; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
  );
});

Deno.test("clearCookie emits an empty cookie value", () => {
  assertMatch(clearCookie("s"), /^s=;/);
  assertEquals(parseCookieHeader(clearCookie("s").split("; ")[0]), { s: "" });
});

Deno.test("clearCookie carries Partitioned through from opts", () => {
  assertEquals(
    clearCookie("s", { secure: true, partitioned: true }),
    "s=; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure; " +
      "Partitioned",
  );
});

Deno.test("clearCookie emits Secure for a __Host- prefixed name", () => {
  assertEquals(
    clearCookie("__Host-session", { path: "/", secure: true, httpOnly: true }),
    "__Host-session=; Path=/; Max-Age=0; " +
      "Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure",
  );
});

Deno.test("clearCookie preserves path, domain, secure and sameSite", () => {
  assertEquals(
    clearCookie("s", {
      path: "/app",
      domain: "example.com",
      secure: true,
      sameSite: "Strict",
      httpOnly: true,
    }),
    "s=; Path=/app; Domain=example.com; Max-Age=0; " +
      "Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; " +
      "SameSite=Strict",
  );
});

Deno.test("clearCookie overrides a caller-supplied maxAge and expires", () => {
  assertEquals(
    clearCookie("s", { maxAge: 600, expires: new Date(86_400_000) }),
    "s=; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
  );
});

Deno.test("clearCookie rejects an invalid name", () => {
  assertThrows(() => clearCookie(""), TypeError, "invalid cookie name");
  assertThrows(() => clearCookie("a;b"), TypeError);
});

// ---------------------------------------------------------------------------
// Round trip
// ---------------------------------------------------------------------------

Deno.test("a serialized cookie round-trips through parseCookieHeader", () => {
  const value = "v2.AAABBB-_.CCCDDD-_";
  const header = serializeCookie("session", value, {
    path: "/",
    httpOnly: true,
    secure: true,
    sameSite: "Lax",
  });
  const pair = header.split("; ")[0];
  assertEquals(parseCookieHeader(pair), { session: value });
});
