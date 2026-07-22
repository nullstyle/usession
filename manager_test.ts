import {
  assertEquals,
  assertMatch,
  assertNotEquals,
  assertRejects,
  assertStringIncludes,
  assertThrows,
} from "@std/assert";
import { SessionManager } from "./manager.ts";
import { deriveKey, seal } from "./seal.ts";
import { Session } from "./session.ts";

const SECRET = "test-secret-".padEnd(32, "x");
const SECRET_A = "secret-alpha-".padEnd(40, "a");
const SECRET_B = "secret-bravo-".padEnd(40, "b");

type Data = { uid?: string; blob?: string };

function mgr(
  extra: Partial<ConstructorParameters<typeof SessionManager>[0]> = {},
): SessionManager<Data> {
  return new SessionManager<Data>({
    secret: SECRET,
    cookieName: "sid",
    ...extra,
  });
}

/** Extract the cookie value out of a `Set-Cookie` header string. */
function cookieValue(setCookie: string): string {
  return setCookie.split(";")[0].split("=").slice(1).join("=");
}

/** Just the `name=value` pair, suitable for a `Cookie` request header. */
function pair(setCookie: string): string {
  return setCookie.split(";")[0];
}

/** Mint a `Set-Cookie` carrying `{ uid }`, over https by default. */
async function mintCookie(
  manager: SessionManager<Data>,
  uid: string,
  url = "https://example.com/",
): Promise<string> {
  const req = new Request(url);
  const session = await manager.load(req);
  session.set("uid", uid);
  const setCookie = await manager.persist(session, req);
  if (!setCookie) throw new Error("expected a Set-Cookie");
  return setCookie;
}

// ---------------------------------------------------------------------------
// Construction validation
// ---------------------------------------------------------------------------

Deno.test("constructor throws when secret is missing", () => {
  assertThrows(
    // @ts-expect-error deliberately omitting a required option
    () => new SessionManager({ cookieName: "sid" }),
    TypeError,
    "secret",
  );
});

Deno.test("constructor throws on an empty string secret", () => {
  assertThrows(
    () => new SessionManager({ secret: "", cookieName: "sid" }),
    TypeError,
    "secret",
  );
});

Deno.test("constructor throws on an empty secret array", () => {
  assertThrows(
    () => new SessionManager({ secret: [], cookieName: "sid" }),
    TypeError,
    "at least one secret",
  );
});

Deno.test("constructor throws when one array secret is empty", () => {
  assertThrows(
    () => new SessionManager({ secret: [SECRET_A, ""], cookieName: "sid" }),
    TypeError,
  );
});

Deno.test("constructor throws when cookieName is missing", () => {
  assertThrows(
    // @ts-expect-error deliberately omitting a required option
    () => new SessionManager({ secret: SECRET }),
    TypeError,
    "cookieName",
  );
});

Deno.test("constructor throws when cookieName is empty", () => {
  assertThrows(
    () => new SessionManager({ secret: SECRET, cookieName: "" }),
    TypeError,
    "cookieName",
  );
});

Deno.test("constructor throws on a non-integer ttlSeconds", () => {
  assertThrows(() => mgr({ ttlSeconds: 1.5 }), TypeError, "ttlSeconds");
});

Deno.test("constructor throws on a zero ttlSeconds", () => {
  assertThrows(() => mgr({ ttlSeconds: 0 }), TypeError, "ttlSeconds");
});

Deno.test("constructor throws on a negative ttlSeconds", () => {
  assertThrows(() => mgr({ ttlSeconds: -5 }), TypeError, "ttlSeconds");
});

Deno.test("constructor accepts ttlSeconds null", () => {
  assertEquals(mgr({ ttlSeconds: null }).toJSON().ttlSeconds, null);
});

Deno.test("constructor throws on a non-integer maxSessionAgeSeconds", () => {
  assertThrows(
    () => mgr({ maxSessionAgeSeconds: 10.5 }),
    TypeError,
    "maxSessionAgeSeconds",
  );
});

Deno.test("constructor throws on a zero maxSessionAgeSeconds", () => {
  assertThrows(
    () => mgr({ maxSessionAgeSeconds: 0 }),
    TypeError,
    "maxSessionAgeSeconds",
  );
});

Deno.test("constructor throws on a negative maxSessionAgeSeconds", () => {
  assertThrows(
    () => mgr({ maxSessionAgeSeconds: -1 }),
    TypeError,
    "maxSessionAgeSeconds",
  );
});

Deno.test("maxSessionAgeSeconds null leaves the session uncapped", async () => {
  const key = await deriveKey(SECRET, "session");
  const now = Math.floor(Date.now() / 1000);
  const token = seal({ uid: "u1" }, key, {
    cookieName: "sid",
    purpose: "session",
    ttlSeconds: 3600,
    iat0: now - 10_000_000,
  });
  const m = mgr({ maxSessionAgeSeconds: null, clockSkewSeconds: 0 });
  const session = await m.load(
    new Request("https://example.com/", {
      headers: { cookie: `sid=${token}` },
    }),
  );
  assertEquals(session.isInvalid, false);
  assertEquals(session.get("uid"), "u1");
});

Deno.test("a too-short secret is rejected at construction", () => {
  assertThrows(
    () => new SessionManager<Data>({ secret: "short", cookieName: "sid" }),
    TypeError,
    "at least",
  );
});

Deno.test("a too-short Uint8Array secret is rejected at construction", () => {
  assertThrows(
    () =>
      new SessionManager<Data>({
        secret: new Uint8Array(31),
        cookieName: "sid",
      }),
    TypeError,
    "at least",
  );
});

Deno.test("a too-short secret anywhere in the rotation list is rejected", () => {
  assertThrows(
    () =>
      new SessionManager<Data>({
        secret: [SECRET, "short"],
        cookieName: "sid",
      }),
    TypeError,
    "at least",
  );
});

Deno.test("an illegal cookie name is rejected at construction", () => {
  assertThrows(
    () => new SessionManager<Data>({ secret: SECRET, cookieName: "bad name" }),
    TypeError,
    "cookie name",
  );
});

// ---------------------------------------------------------------------------
// Cookie prefix invariants
// ---------------------------------------------------------------------------

Deno.test("__Host- cookie with a domain throws", () => {
  assertThrows(
    () =>
      new SessionManager({
        secret: SECRET,
        cookieName: "__Host-sid",
        cookie: { domain: "example.com" },
      }),
    Error,
    "domain",
  );
});

Deno.test("__Host- cookie with a non-root path throws", () => {
  assertThrows(
    () =>
      new SessionManager({
        secret: SECRET,
        cookieName: "__Host-sid",
        cookie: { path: "/app" },
      }),
    Error,
    "path",
  );
});

Deno.test("__Host- cookie with secure false throws", () => {
  assertThrows(
    () =>
      new SessionManager({
        secret: SECRET,
        cookieName: "__Host-sid",
        cookie: { secure: false },
      }),
    Error,
    "secure",
  );
});

Deno.test("__Secure- cookie with secure false throws", () => {
  assertThrows(
    () =>
      new SessionManager({
        secret: SECRET,
        cookieName: "__Secure-sid",
        cookie: { secure: false },
      }),
    Error,
    "secure",
  );
});

Deno.test("a valid __Host- configuration constructs", () => {
  const m = new SessionManager<Data>({
    secret: SECRET,
    cookieName: "__Host-sid",
  });
  assertEquals(m.toJSON().cookieName, "__Host-sid");
});

Deno.test("__Secure- cookie may set a domain", async () => {
  const m = new SessionManager<Data>({
    secret: SECRET,
    cookieName: "__Secure-sid",
    cookie: { domain: "example.com" },
  });
  assertEquals(m.toJSON().cookieName, "__Secure-sid");

  const req = new Request("https://example.com/");
  const session = await m.load(req);
  session.set("uid", "u1");
  const setCookie = await m.persist(session, req);
  assertStringIncludes(setCookie!, "Domain=example.com");
  assertStringIncludes(setCookie!, "Secure");
});

Deno.test("__Host- cookie over plain http throws at persist time", async () => {
  const m = new SessionManager<Data>({
    secret: SECRET,
    cookieName: "__Host-sid",
  });
  const req = new Request("http://example.com/");
  const session = await m.load(req);
  session.set("uid", "u1");
  await assertRejects(() => m.persist(session, req), Error, "insecure");
});

Deno.test("__Host- cookie can still be CLEARED over plain http", async () => {
  // Logout must not throw just because the request looked insecure.
  const m = new SessionManager<Data>({
    secret: SECRET,
    cookieName: "__Host-sid",
  });
  const req = new Request("http://example.com/");
  const session = await m.load(req);
  session.destroy();

  const setCookie = await m.persist(session, req);
  assertStringIncludes(setCookie!, "Max-Age=0");
  // The deletion still needs Secure, or the browser rejects the header.
  assertStringIncludes(setCookie!, "Secure");
});

Deno.test("__Host- cookie over https persists with Secure", async () => {
  const m = new SessionManager<Data>({
    secret: SECRET,
    cookieName: "__Host-sid",
  });
  const req = new Request("https://example.com/");
  const session = await m.load(req);
  session.set("uid", "u1");
  const setCookie = await m.persist(session, req);
  assertStringIncludes(setCookie!, "Secure");
  assertStringIncludes(setCookie!, "Path=/");
});

Deno.test("SameSite=None forces Secure even over http", async () => {
  const m = mgr({ cookie: { sameSite: "None" } });
  const req = new Request("http://example.com/");
  const session = await m.load(req);
  session.set("uid", "u1");
  const setCookie = await m.persist(session, req);
  assertStringIncludes(setCookie!, "Secure");
  assertStringIncludes(setCookie!, "SameSite=None");
});

Deno.test("partitioned forces Secure even over http", async () => {
  const m = mgr({ cookie: { partitioned: true } });
  const req = new Request("http://example.com/");
  const session = await m.load(req);
  session.set("uid", "u1");
  const setCookie = await m.persist(session, req);
  assertStringIncludes(setCookie!, "Secure");
  assertStringIncludes(setCookie!, "Partitioned");
});

// A prefixed cookie name plus an explicit `secure: false` is a contradiction
// even when `sameSite: "None"` would force Secure anyway. The constructor must
// report the caller's mistake rather than quietly overriding it.
Deno.test("a prefixed name rejects an explicit secure false even with SameSite=None", () => {
  assertThrows(
    () =>
      new SessionManager<Data>({
        secret: SECRET,
        cookieName: "__Host-sid",
        cookie: { secure: false, sameSite: "None" },
      }),
    Error,
    "secure",
  );
});

Deno.test("SameSite=None forces Secure on an unprefixed cookie over http", async () => {
  const m = new SessionManager<Data>({
    secret: SECRET,
    cookieName: "sid",
    cookie: { sameSite: "None" },
  });
  const req = new Request("http://example.com/");
  const session = await m.load(req);
  session.set("uid", "u1");
  assertStringIncludes((await m.persist(session, req))!, "Secure");
});

Deno.test("the default Set-Cookie carries Path, HttpOnly and SameSite", async () => {
  const setCookie = await mintCookie(mgr(), "u1");
  assertStringIncludes(setCookie, "Path=/");
  assertStringIncludes(setCookie, "HttpOnly");
  assertStringIncludes(setCookie, "SameSite=Lax");
});

Deno.test("cookie.httpOnly false omits HttpOnly", async () => {
  const setCookie = await mintCookie(
    mgr({ cookie: { httpOnly: false } }),
    "u1",
  );
  assertEquals(setCookie.includes("HttpOnly"), false);
});

Deno.test("a custom cookie path and domain reach the Set-Cookie", async () => {
  const m = mgr({ cookie: { path: "/app", domain: "example.com" } });
  const setCookie = await mintCookie(m, "u1");
  assertStringIncludes(setCookie, "Path=/app");
  assertStringIncludes(setCookie, "Domain=example.com");
});

Deno.test("the clearing cookie repeats Path and HttpOnly", async () => {
  const m = mgr({ cookie: { path: "/app" } });
  const req = new Request("https://example.com/");
  const session = await m.load(req);
  session.destroy();
  const cleared = await m.persist(session, req);
  assertStringIncludes(cleared!, "Path=/app");
  assertStringIncludes(cleared!, "HttpOnly");
  assertStringIncludes(cleared!, "Max-Age=0");
});

Deno.test("an illegal cookie.path surfaces as a TypeError at persist", async () => {
  const m = mgr({ cookie: { path: "/bad;path" } });
  const req = new Request("https://example.com/");
  const session = await m.load(req);
  session.set("uid", "u1");
  await assertRejects(() => m.persist(session, req), TypeError, "Path");
});

Deno.test("a plain cookie over http carries no Secure", async () => {
  const m = mgr();
  const req = new Request("http://example.com/");
  const session = await m.load(req);
  session.set("uid", "u1");
  const setCookie = await m.persist(session, req);
  assertEquals(setCookie!.includes("Secure"), false);
});

// ---------------------------------------------------------------------------
// load
// ---------------------------------------------------------------------------

Deno.test("load with no cookie yields a new, valid session", async () => {
  const session = await mgr().load(new Request("https://example.com/"));
  assertEquals(session.isNew, true);
  assertEquals(session.isInvalid, false);
  assertEquals(session.invalidReason, undefined);
});

Deno.test("load ignores a cookie with a different name", async () => {
  const session = await mgr().load(
    new Request("https://example.com/", { headers: { cookie: "other=abc" } }),
  );
  assertEquals(session.isNew, true);
  assertEquals(session.isInvalid, false);
});

Deno.test("load marks a garbage cookie invalid with a reason", async () => {
  const session = await mgr().load(
    new Request("https://example.com/", {
      headers: { cookie: "sid=not-a-token" },
    }),
  );
  assertEquals(session.isInvalid, true);
  assertNotEquals(session.invalidReason, undefined);
  assertEquals((session.invalidReason ?? "").length > 0, true);
});

Deno.test("load rejects an oversized cookie mentioning the size", async () => {
  const setCookie = await mintCookie(mgr(), "u1");
  const small = mgr({ maxCookieBytes: 16 });
  const session = await small.load(
    new Request("https://example.com/", {
      headers: { cookie: pair(setCookie) },
    }),
  );
  assertEquals(session.isInvalid, true);
  assertMatch(session.invalidReason ?? "", /too large/i);
  assertMatch(session.invalidReason ?? "", /bytes/);
});

Deno.test("load round-trips data from a valid cookie", async () => {
  const m = mgr();
  const setCookie = await mintCookie(m, "u-42");
  const session = await m.load(
    new Request("https://example.com/", {
      headers: { cookie: pair(setCookie) },
    }),
  );
  assertEquals(session.isNew, false);
  assertEquals(session.isInvalid, false);
  assertEquals(session.get("uid"), "u-42");
});

Deno.test("load round-trips flash messages", async () => {
  const m = mgr();
  const req = new Request("https://example.com/");
  const first = await m.load(req);
  first.flash("notice", "hi");
  const setCookie = await m.persist(first, req);
  const second = await m.load(
    new Request("https://example.com/", {
      headers: { cookie: pair(setCookie!) },
    }),
  );
  assertEquals(second.consumeFlash(), { notice: "hi" });
});

Deno.test("a tampered token is rejected", async () => {
  const m = mgr();
  const token = cookieValue(await mintCookie(m, "u1"));
  const [v, nonce, box] = token.split(".");
  const flipped = `${box[0] === "A" ? "B" : "A"}${box.slice(1)}`;
  const session = await m.loadFromCookieHeader(`sid=${v}.${nonce}.${flipped}`);
  assertEquals(session.isInvalid, true);
  assertEquals(session.get("uid"), undefined);
});

Deno.test('the default purpose is "session"', async () => {
  const setCookie = await mintCookie(mgr({ purpose: "session" }), "u1");
  const session = await mgr().loadFromCookieHeader(pair(setCookie));
  assertEquals(session.get("uid"), "u1");
});

Deno.test("a token minted under a different purpose is rejected", async () => {
  const setCookie = await mintCookie(mgr({ purpose: "one" }), "u1");
  const session = await mgr({ purpose: "two" }).load(
    new Request("https://example.com/", {
      headers: { cookie: pair(setCookie) },
    }),
  );
  assertEquals(session.isInvalid, true);
});

Deno.test("a token minted for a different cookie name is rejected", async () => {
  const setCookie = await mintCookie(mgr(), "u1");
  const other = new SessionManager<Data>({
    secret: SECRET,
    cookieName: "sid2",
  });
  const session = await other.load(
    new Request("https://example.com/", {
      headers: { cookie: `sid2=${cookieValue(setCookie)}` },
    }),
  );
  assertEquals(session.isInvalid, true);
});

// ---------------------------------------------------------------------------
// ttlSeconds
// ---------------------------------------------------------------------------

Deno.test("ttlSeconds null emits no Max-Age", async () => {
  const setCookie = await mintCookie(mgr({ ttlSeconds: null }), "u1");
  assertEquals(setCookie.includes("Max-Age"), false);
});

Deno.test("ttlSeconds null still loads the session back", async () => {
  const m = mgr({ ttlSeconds: null });
  const setCookie = await mintCookie(m, "u1");
  const session = await m.load(
    new Request("https://example.com/", {
      headers: { cookie: pair(setCookie) },
    }),
  );
  assertEquals(session.get("uid"), "u1");
});

Deno.test("a numeric ttlSeconds becomes Max-Age", async () => {
  const setCookie = await mintCookie(mgr({ ttlSeconds: 120 }), "u1");
  assertStringIncludes(setCookie, "Max-Age=120");
});

Deno.test("an expired token is rejected", async () => {
  const key = await deriveKey(SECRET, "session");
  const token = seal({ uid: "u1" }, key, {
    cookieName: "sid",
    purpose: "session",
    ttlSeconds: -3600,
  });
  const session = await mgr({ clockSkewSeconds: 0 }).load(
    new Request("https://example.com/", {
      headers: { cookie: `sid=${token}` },
    }),
  );
  assertEquals(session.isInvalid, true);
  assertMatch(session.invalidReason ?? "", /expired/i);
});

// ---------------------------------------------------------------------------
// Key rotation
// ---------------------------------------------------------------------------

Deno.test("a secondary secret unseals an existing cookie", async () => {
  const setCookie = await mintCookie(mgr({ secret: SECRET_B }), "u-rot");
  const session = await mgr({ secret: [SECRET_A, SECRET_B] }).load(
    new Request("https://example.com/", {
      headers: { cookie: pair(setCookie) },
    }),
  );
  assertEquals(session.get("uid"), "u-rot");
});

Deno.test("a session unsealed by a secondary secret is dirty", async () => {
  const setCookie = await mintCookie(mgr({ secret: SECRET_B }), "u-rot");
  const session = await mgr({ secret: [SECRET_A, SECRET_B] }).load(
    new Request("https://example.com/", {
      headers: { cookie: pair(setCookie) },
    }),
  );
  assertEquals(session.isDirty, true);
});

Deno.test("a re-minted cookie verifies under the primary secret", async () => {
  const setCookie = await mintCookie(mgr({ secret: SECRET_B }), "u-rot");
  const rotating = mgr({ secret: [SECRET_A, SECRET_B] });
  const req = new Request("https://example.com/", {
    headers: { cookie: pair(setCookie) },
  });
  const reminted = await rotating.persist(await rotating.load(req), req);
  assertMatch(cookieValue(reminted!), /^v2\./);

  const loaded = await mgr({ secret: [SECRET_A] }).load(
    new Request("https://example.com/", {
      headers: { cookie: pair(reminted!) },
    }),
  );
  assertEquals(loaded.get("uid"), "u-rot");
});

Deno.test("a re-minted cookie is rejected by the retired secret", async () => {
  const setCookie = await mintCookie(mgr({ secret: SECRET_B }), "u-rot");
  const rotating = mgr({ secret: [SECRET_A, SECRET_B] });
  const req = new Request("https://example.com/", {
    headers: { cookie: pair(setCookie) },
  });
  const reminted = await rotating.persist(await rotating.load(req), req);

  const loaded = await mgr({ secret: [SECRET_B] }).load(
    new Request("https://example.com/", {
      headers: { cookie: pair(reminted!) },
    }),
  );
  assertEquals(loaded.isInvalid, true);
});

Deno.test("a session unsealed by the primary secret is clean", async () => {
  const rotating = mgr({ secret: [SECRET_A, SECRET_B] });
  const setCookie = await mintCookie(rotating, "u1");
  const session = await rotating.load(
    new Request("https://example.com/", {
      headers: { cookie: pair(setCookie) },
    }),
  );
  assertEquals(session.isDirty, false);
});

// ---------------------------------------------------------------------------
// Duplicate cookie shadowing
// ---------------------------------------------------------------------------

Deno.test("a planted duplicate does not shadow the real cookie", async () => {
  const m = mgr();
  const setCookie = await mintCookie(m, "u-real");
  const session = await m.load(
    new Request("https://example.com/", {
      headers: { cookie: `sid=junk; sid=${cookieValue(setCookie)}` },
    }),
  );
  assertEquals(session.isInvalid, false);
  assertEquals(session.get("uid"), "u-real");
});

Deno.test("a trailing junk duplicate still loads the real session", async () => {
  const m = mgr();
  const setCookie = await mintCookie(m, "u-real");
  const session = await m.load(
    new Request("https://example.com/", {
      headers: { cookie: `${pair(setCookie)}; sid=junk` },
    }),
  );
  assertEquals(session.get("uid"), "u-real");
});

Deno.test("an oversized duplicate does not shadow the real cookie", async () => {
  const m = mgr({ maxCookieBytes: 300 });
  const setCookie = await mintCookie(m, "u-real");
  const session = await m.loadFromCookieHeader(
    `sid=${"y".repeat(400)}; ${pair(setCookie)}`,
  );
  assertEquals(session.isInvalid, false);
  assertEquals(session.get("uid"), "u-real");
});

Deno.test("all-invalid duplicates report an invalid session", async () => {
  const session = await mgr().load(
    new Request("https://example.com/", {
      headers: { cookie: "sid=junk1; sid=junk2" },
    }),
  );
  assertEquals(session.isInvalid, true);
});

// ---------------------------------------------------------------------------
// bindHost
// ---------------------------------------------------------------------------

Deno.test("bindHost round-trips on a request with no Host header", async () => {
  const m = mgr({ bindHost: true });
  const req = new Request("https://example.com/");
  const session = await m.load(req);
  session.set("uid", "u1");
  const setCookie = await m.persist(session, req);

  const back = await m.load(
    new Request("https://example.com/", {
      headers: { cookie: pair(setCookie!) },
    }),
  );
  assertEquals(back.isInvalid, false);
  assertEquals(back.get("uid"), "u1");
});

Deno.test("bindHost rejects a token bound to another host", async () => {
  const m = mgr({ bindHost: true });
  const setCookie = await mintCookie(m, "u1", "https://a.example.com/");
  const back = await m.load(
    new Request("https://b.example.com/", {
      headers: { cookie: pair(setCookie) },
    }),
  );
  assertEquals(back.isInvalid, true);
  assertMatch(back.invalidReason ?? "", /host/i);
});

Deno.test("bindHost comparison is case-insensitive", async () => {
  const m = mgr({ bindHost: true });
  const session = new Session<Data>({ uid: "u1" });
  session.touch();
  const setCookie = await m.serialize(session, {
    secure: true,
    host: "EXAMPLE.COM",
  });
  const back = await m.loadFromCookieHeader(pair(setCookie!), {
    host: "example.com",
  });
  assertEquals(back.isInvalid, false);
  assertEquals(back.get("uid"), "u1");
});

Deno.test("bindHost prefers the Host header over the URL host", async () => {
  const m = mgr({ bindHost: true });
  const req = new Request("https://example.com/", {
    headers: { host: "proxied.example" },
  });
  const session = await m.load(req);
  session.set("uid", "u1");
  const setCookie = await m.persist(session, req);

  const bound = await m.loadFromCookieHeader(pair(setCookie!), {
    host: "proxied.example",
  });
  assertEquals(bound.get("uid"), "u1");

  const wrong = await m.loadFromCookieHeader(pair(setCookie!), {
    host: "example.com",
  });
  assertEquals(wrong.isInvalid, true);
});

Deno.test("bindHost takes the first value of a multi-valued Host", async () => {
  const m = mgr({ bindHost: true });
  const req = new Request("https://example.com/", {
    headers: { host: "A.Example, b.example" },
  });
  const session = await m.load(req);
  session.set("uid", "u1");
  const setCookie = await m.persist(session, req);

  const bound = await m.loadFromCookieHeader(pair(setCookie!), {
    host: "a.example",
  });
  assertEquals(bound.get("uid"), "u1");
});

Deno.test("bindHost without any host throws on load", async () => {
  await assertRejects(
    () => mgr({ bindHost: true }).loadFromCookieHeader("sid=whatever", {}),
    Error,
    "bindHost",
  );
});

Deno.test("bindHost without any host throws on serialize", async () => {
  const m = mgr({ bindHost: true });
  const session = new Session<Data>({});
  session.set("uid", "u1");
  await assertRejects(
    () => m.serialize(session, { secure: true }),
    Error,
    "bindHost",
  );
});

// ---------------------------------------------------------------------------
// trustProxy
// ---------------------------------------------------------------------------

Deno.test("trustProxy honours X-Forwarded-Proto https", async () => {
  const m = mgr({ trustProxy: true });
  const req = new Request("http://example.com/", {
    headers: { "x-forwarded-proto": "https" },
  });
  const session = await m.load(req);
  session.set("uid", "u1");
  assertStringIncludes((await m.persist(session, req))!, "Secure");
});

Deno.test("trustProxy takes the first hop of X-Forwarded-Proto", async () => {
  const m = mgr({ trustProxy: true });
  const req = new Request("http://example.com/", {
    headers: { "x-forwarded-proto": "https, http" },
  });
  const session = await m.load(req);
  session.set("uid", "u1");
  assertStringIncludes((await m.persist(session, req))!, "Secure");
});

Deno.test("trustProxy accepts an uppercase X-Forwarded-Proto", async () => {
  const m = mgr({ trustProxy: true });
  const req = new Request("http://example.com/", {
    headers: { "x-forwarded-proto": "HTTPS" },
  });
  const session = await m.load(req);
  session.set("uid", "u1");
  assertStringIncludes((await m.persist(session, req))!, "Secure");
});

Deno.test("X-Forwarded-Proto is ignored when trustProxy is off", async () => {
  const m = mgr();
  const req = new Request("http://example.com/", {
    headers: { "x-forwarded-proto": "https" },
  });
  const session = await m.load(req);
  session.set("uid", "u1");
  assertEquals((await m.persist(session, req))!.includes("Secure"), false);
});

Deno.test("an https URL stays Secure despite X-Forwarded-Proto http", async () => {
  const m = mgr({ trustProxy: true });
  const req = new Request("https://example.com/", {
    headers: { "x-forwarded-proto": "http" },
  });
  const session = await m.load(req);
  session.set("uid", "u1");
  assertStringIncludes((await m.persist(session, req))!, "Secure");
});

Deno.test("trustProxy takes the first hop of X-Forwarded-Host", async () => {
  const m = mgr({ bindHost: true, trustProxy: true });
  const session = new Session<Data>({ uid: "u1" });
  session.touch();
  const setCookie = await m.serialize(session, {
    secure: true,
    host: "first.example",
  });
  const back = await m.load(
    new Request("https://origin.example/", {
      headers: {
        cookie: pair(setCookie!),
        "x-forwarded-host": "first.example, second.example",
      },
    }),
  );
  assertEquals(back.isInvalid, false);
  assertEquals(back.get("uid"), "u1");
});

Deno.test("X-Forwarded-Host is ignored when trustProxy is off", async () => {
  const m = mgr({ bindHost: true });
  const session = new Session<Data>({ uid: "u1" });
  session.touch();
  const setCookie = await m.serialize(session, {
    secure: true,
    host: "first.example",
  });
  const back = await m.load(
    new Request("https://origin.example/", {
      headers: {
        cookie: pair(setCookie!),
        "x-forwarded-host": "first.example",
      },
    }),
  );
  assertEquals(back.isInvalid, true);
});

// ---------------------------------------------------------------------------
// persist
// ---------------------------------------------------------------------------

Deno.test("persist on a destroyed session emits a clearing cookie", async () => {
  const m = mgr();
  const setCookie = await mintCookie(m, "u1");
  const req = new Request("https://example.com/", {
    headers: { cookie: pair(setCookie) },
  });
  const session = await m.load(req);
  session.destroy();
  const cleared = await m.persist(session, req);
  assertStringIncludes(cleared!, "sid=;");
  assertStringIncludes(cleared!, "Max-Age=0");
});

Deno.test("persist on a dirty session emits a v2 token", async () => {
  const setCookie = await mintCookie(mgr(), "u1");
  assertMatch(cookieValue(setCookie), /^v2\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
});

Deno.test("persist on a clean session returns null", async () => {
  const m = mgr();
  const req = new Request("https://example.com/");
  assertEquals(await m.persist(await m.load(req), req), null);
});

Deno.test("persist clears an invalid cookie by default", async () => {
  const m = mgr();
  const req = new Request("https://example.com/", {
    headers: { cookie: "sid=junk" },
  });
  const out = await m.persist(await m.load(req), req);
  assertStringIncludes(out!, "Max-Age=0");
});

Deno.test("persist ignores an invalid cookie when configured", async () => {
  const m = mgr({ onInvalidCookie: "ignore" });
  const req = new Request("https://example.com/", {
    headers: { cookie: "sid=junk" },
  });
  assertEquals(await m.persist(await m.load(req), req), null);
});

Deno.test("a second persist on the same session returns null", async () => {
  const m = mgr();
  const req = new Request("https://example.com/");
  const session = await m.load(req);
  session.set("uid", "u1");
  assertNotEquals(await m.persist(session, req), null);
  assertEquals(await m.persist(session, req), null);
});

Deno.test("a second persist on a destroyed session still clears", async () => {
  const m = mgr();
  const req = new Request("https://example.com/");
  const session = await m.load(req);
  session.destroy();
  const first = await m.persist(session, req);
  const second = await m.persist(session, req);
  assertStringIncludes(first!, "Max-Age=0");
  assertStringIncludes(second!, "Max-Age=0");
});

Deno.test("a regenerated session mints a fresh empty token", async () => {
  const m = mgr();
  const setCookie = await mintCookie(m, "u1");
  const req = new Request("https://example.com/", {
    headers: { cookie: pair(setCookie) },
  });
  const session = await m.load(req);
  session.regenerate();
  const out = await m.persist(session, req);
  const back = await m.load(
    new Request("https://example.com/", {
      headers: { cookie: pair(out!) },
    }),
  );
  assertEquals(back.isInvalid, false);
  assertEquals(back.get("uid"), undefined);
});

// ---------------------------------------------------------------------------
// rolling
// ---------------------------------------------------------------------------

Deno.test("rolling marks a loaded valid session dirty", async () => {
  const m = mgr({ rolling: true });
  const setCookie = await mintCookie(m, "u1");
  const session = await m.load(
    new Request("https://example.com/", {
      headers: { cookie: pair(setCookie) },
    }),
  );
  assertEquals(session.isDirty, true);
});

Deno.test("without rolling a loaded valid session stays clean", async () => {
  const m = mgr();
  const setCookie = await mintCookie(m, "u1");
  const session = await m.load(
    new Request("https://example.com/", {
      headers: { cookie: pair(setCookie) },
    }),
  );
  assertEquals(session.isDirty, false);
});

Deno.test("rolling with ttlSeconds null does not dirty the session", async () => {
  const m = mgr({ rolling: true, ttlSeconds: null });
  const setCookie = await mintCookie(m, "u1");
  const session = await m.load(
    new Request("https://example.com/", {
      headers: { cookie: pair(setCookie) },
    }),
  );
  assertEquals(session.isDirty, false);
});

// ---------------------------------------------------------------------------
// maxSessionAgeSeconds
// ---------------------------------------------------------------------------

Deno.test("a session past the absolute cap is rejected", async () => {
  const key = await deriveKey(SECRET, "session");
  const now = Math.floor(Date.now() / 1000);
  const token = seal({ uid: "u1" }, key, {
    cookieName: "sid",
    purpose: "session",
    ttlSeconds: 3600,
    iat0: now - 10_000,
  });
  const m = mgr({
    rolling: true,
    maxSessionAgeSeconds: 60,
    clockSkewSeconds: 0,
  });
  const session = await m.load(
    new Request("https://example.com/", {
      headers: { cookie: `sid=${token}` },
    }),
  );
  assertEquals(session.isInvalid, true);
  assertMatch(session.invalidReason ?? "", /maximum age/i);
});

Deno.test("a session within the absolute cap is accepted", async () => {
  const key = await deriveKey(SECRET, "session");
  const now = Math.floor(Date.now() / 1000);
  const token = seal({ uid: "u1" }, key, {
    cookieName: "sid",
    purpose: "session",
    ttlSeconds: 3600,
    iat0: now - 10,
  });
  const m = mgr({ maxSessionAgeSeconds: 3600, clockSkewSeconds: 0 });
  const session = await m.load(
    new Request("https://example.com/", {
      headers: { cookie: `sid=${token}` },
    }),
  );
  assertEquals(session.isInvalid, false);
  assertEquals(session.get("uid"), "u1");
});

Deno.test("iat0 survives a rolling re-seal", async () => {
  const key = await deriveKey(SECRET, "session");
  const now = Math.floor(Date.now() / 1000);
  const token = seal({ uid: "u1" }, key, {
    cookieName: "sid",
    purpose: "session",
    ttlSeconds: 3600,
    iat0: now - 500,
  });
  const m = mgr({
    rolling: true,
    maxSessionAgeSeconds: 600,
    clockSkewSeconds: 0,
  });
  const req = new Request("https://example.com/", {
    headers: { cookie: `sid=${token}` },
  });
  const reissued = await m.persist(await m.load(req), req);

  const strict = mgr({ maxSessionAgeSeconds: 60, clockSkewSeconds: 0 });
  const back = await strict.load(
    new Request("https://example.com/", {
      headers: { cookie: pair(reissued!) },
    }),
  );
  assertEquals(back.isInvalid, true);
});

// ---------------------------------------------------------------------------
// onOversize
// ---------------------------------------------------------------------------

const BIG = "x".repeat(6000);

Deno.test("onOversize throw rejects a large payload", async () => {
  const m = mgr({ onOversize: "throw" });
  const req = new Request("https://example.com/");
  const session = await m.load(req);
  session.set("blob", BIG);
  await assertRejects(() => m.persist(session, req), Error, "bytes");
});

Deno.test("onOversize warn does not throw", async () => {
  const m = mgr({ onOversize: "warn" });
  const original = console.warn;
  let warned = 0;
  console.warn = () => {
    warned++;
  };
  try {
    const req = new Request("https://example.com/");
    const session = await m.load(req);
    session.set("blob", BIG);
    assertNotEquals(await m.persist(session, req), null);
  } finally {
    console.warn = original;
  }
  assertEquals(warned, 1);
});

Deno.test("onOversize ignore is silent", async () => {
  let called = 0;
  const m = mgr({
    onOversize: "ignore",
    onOversizeCookie: () => {
      called++;
    },
  });
  const original = console.warn;
  let warned = 0;
  console.warn = () => {
    warned++;
  };
  try {
    const req = new Request("https://example.com/");
    const session = await m.load(req);
    session.set("blob", BIG);
    await m.persist(session, req);
  } finally {
    console.warn = original;
  }
  assertEquals(warned, 0);
  assertEquals(called, 0);
});

Deno.test("onOversizeCookie receives the size details", async () => {
  const seen: { bytes: number; limit: number; cookieName: string }[] = [];
  const m = mgr({ onOversizeCookie: (info) => seen.push(info) });
  const req = new Request("https://example.com/");
  const session = await m.load(req);
  session.set("blob", BIG);
  await m.persist(session, req);
  assertEquals(seen.length, 1);
  assertEquals(seen[0].cookieName, "sid");
  assertEquals(seen[0].limit, 4096);
  assertEquals(seen[0].bytes > 4096, true);
});

Deno.test("onOversizeCookie suppresses the default throw", async () => {
  let called = 0;
  const m = mgr({
    onOversize: "throw",
    onOversizeCookie: () => {
      called++;
    },
  });
  const req = new Request("https://example.com/");
  const session = await m.load(req);
  session.set("blob", BIG);
  assertNotEquals(await m.persist(session, req), null);
  assertEquals(called, 1);
});

Deno.test("a small cookie never triggers onOversizeCookie", async () => {
  let called = 0;
  const m = mgr({
    onOversize: "throw",
    onOversizeCookie: () => {
      called++;
    },
  });
  await mintCookie(m, "u1");
  assertEquals(called, 0);
});

// ---------------------------------------------------------------------------
// onInvalid
// ---------------------------------------------------------------------------

Deno.test("onInvalid is called with the reason, name and request", async () => {
  const seen: { reason: string; cookieName: string; request?: Request }[] = [];
  const m = mgr({ onInvalid: (info) => seen.push(info) });
  const req = new Request("https://example.com/", {
    headers: { cookie: "sid=junk" },
  });
  await m.load(req);
  assertEquals(seen.length, 1);
  assertEquals(seen[0].cookieName, "sid");
  assertEquals(seen[0].reason.length > 0, true);
  assertEquals(seen[0].request, req);
});

Deno.test("onInvalid reports an undefined request without a Request", async () => {
  const seen: { reason: string; request: Request | undefined }[] = [];
  const m = mgr({ onInvalid: (info) => seen.push(info) });
  await m.loadFromCookieHeader("sid=junk");
  assertEquals(seen.length, 1);
  assertEquals(seen[0].request, undefined);
  assertEquals(seen[0].reason.length > 0, true);
});

Deno.test("onInvalid reports the size for an oversized cookie", async () => {
  const seen: string[] = [];
  const setCookie = await mintCookie(mgr(), "u1");
  const m = mgr({ maxCookieBytes: 16, onInvalid: (i) => seen.push(i.reason) });
  await m.loadFromCookieHeader(pair(setCookie));
  assertEquals(seen.length, 1);
  assertMatch(seen[0], /too large/i);
});

Deno.test("onInvalid is not called for a valid cookie", async () => {
  let called = 0;
  const setCookie = await mintCookie(mgr(), "u1");
  await mgr({ onInvalid: () => called++ }).load(
    new Request("https://example.com/", {
      headers: { cookie: pair(setCookie) },
    }),
  );
  assertEquals(called, 0);
});

Deno.test("onInvalid is not called when no cookie is present", async () => {
  let called = 0;
  await mgr({ onInvalid: () => called++ }).load(
    new Request("https://example.com/"),
  );
  assertEquals(called, 0);
});

// ---------------------------------------------------------------------------
// apply
// ---------------------------------------------------------------------------

Deno.test("apply appends without clobbering an existing Set-Cookie", async () => {
  const m = mgr();
  const req = new Request("https://example.com/");
  const session = await m.load(req);
  session.set("uid", "u1");
  const out = await m.apply(
    session,
    req,
    new Response("ok", { headers: { "set-cookie": "other=1" } }),
  );
  assertEquals(out.headers.getSetCookie().length, 2);
});

Deno.test("apply adds Vary: Cookie", async () => {
  const m = mgr();
  const req = new Request("https://example.com/");
  const session = await m.load(req);
  session.set("uid", "u1");
  const out = await m.apply(session, req, new Response("ok"));
  assertStringIncludes(out.headers.get("vary") ?? "", "Cookie");
});

Deno.test("apply preserves status, statusText and body", async () => {
  const m = mgr();
  const req = new Request("https://example.com/");
  const session = await m.load(req);
  session.set("uid", "u1");
  const out = await m.apply(
    session,
    req,
    new Response("hello", { status: 201, statusText: "Created" }),
  );
  assertEquals(out.status, 201);
  assertEquals(out.statusText, "Created");
  assertEquals(await out.text(), "hello");
});

Deno.test("apply works on a redirect with immutable headers", async () => {
  const m = mgr();
  const req = new Request("https://example.com/");
  const session = await m.load(req);
  session.set("uid", "u1");
  const out = await m.apply(
    session,
    req,
    Response.redirect("https://example.com/next", 302),
  );
  assertEquals(out.status, 302);
  assertEquals(out.headers.get("location"), "https://example.com/next");
  assertEquals(out.headers.getSetCookie().length, 1);
  assertStringIncludes(out.headers.get("vary") ?? "", "Cookie");
});

Deno.test("apply adds Vary even when nothing is persisted", async () => {
  const m = mgr();
  const req = new Request("https://example.com/");
  const out = await m.apply(await m.load(req), req, new Response("ok"));
  assertEquals(out.headers.getSetCookie().length, 0);
  assertStringIncludes(out.headers.get("vary") ?? "", "Cookie");
});

Deno.test("apply preserves an existing Vary value", async () => {
  const m = mgr();
  const req = new Request("https://example.com/");
  const out = await m.apply(
    await m.load(req),
    req,
    new Response("ok", { headers: { vary: "Accept-Encoding" } }),
  );
  assertStringIncludes(out.headers.get("vary") ?? "", "Accept-Encoding");
  assertStringIncludes(out.headers.get("vary") ?? "", "Cookie");
});

// ---------------------------------------------------------------------------
// Request-free entry points
// ---------------------------------------------------------------------------

Deno.test("serialize and loadFromCookieHeader need no Request", async () => {
  const m = mgr();
  const session = new Session<Data>({});
  session.set("uid", "u-headless");
  const setCookie = await m.serialize(session, { secure: true });
  assertStringIncludes(setCookie!, "Secure");

  const back = await m.loadFromCookieHeader(pair(setCookie!));
  assertEquals(back.get("uid"), "u-headless");
});

Deno.test("serialize honours secure false in the context", async () => {
  const m = mgr();
  const session = new Session<Data>({});
  session.set("uid", "u1");
  const setCookie = await m.serialize(session, { secure: false });
  assertEquals(setCookie!.includes("Secure"), false);
});

Deno.test("an explicit cookie.secure overrides the context", async () => {
  const m = mgr({ cookie: { secure: true } });
  const session = new Session<Data>({});
  session.set("uid", "u1");
  const setCookie = await m.serialize(session, { secure: false });
  assertStringIncludes(setCookie!, "Secure");
});

Deno.test("loadFromCookieHeader with a null header yields a new session", async () => {
  const session = await mgr().loadFromCookieHeader(null);
  assertEquals(session.isNew, true);
  assertEquals(session.isInvalid, false);
});

Deno.test("serialize honours the host in the context", async () => {
  const m = mgr({ bindHost: true });
  const session = new Session<Data>({});
  session.set("uid", "u1");
  const setCookie = await m.serialize(session, {
    secure: true,
    host: "bound.example",
  });
  const ok = await m.loadFromCookieHeader(pair(setCookie!), {
    host: "bound.example",
  });
  assertEquals(ok.get("uid"), "u1");

  const bad = await m.loadFromCookieHeader(pair(setCookie!), {
    host: "other.example",
  });
  assertEquals(bad.isInvalid, true);
});

// ---------------------------------------------------------------------------
// Secret hygiene
// ---------------------------------------------------------------------------

Deno.test("JSON.stringify does not leak the secret", () => {
  const json = JSON.stringify(mgr());
  assertEquals(json.includes(SECRET), false);
  assertStringIncludes(json, "[redacted]");
});

Deno.test("Deno.inspect does not leak the secret", () => {
  const text = Deno.inspect(mgr());
  assertEquals(text.includes(SECRET), false);
  assertStringIncludes(text, "SessionManager");
});

Deno.test("toJSON reports the redacted secret and public options", () => {
  const json = mgr({ purpose: "custom", ttlSeconds: 99 }).toJSON();
  assertEquals(json.secret, "[redacted]");
  assertEquals(json.purpose, "custom");
  assertEquals(json.ttlSeconds, 99);
  assertEquals(json.cookieName, "sid");
});

Deno.test("rotating secrets are not leaked either", () => {
  const json = JSON.stringify(mgr({ secret: [SECRET_A, SECRET_B] }));
  assertEquals(json.includes(SECRET_A), false);
  assertEquals(json.includes(SECRET_B), false);
});

// ---------------------------------------------------------------------------
// Reuse and concurrency
// ---------------------------------------------------------------------------

Deno.test("one manager serves many concurrent round-trips", async () => {
  const m = mgr();
  const ids = Array.from({ length: 25 }, (_, i) => `u-${i}`);

  const cookies = await Promise.all(ids.map(async (uid) => {
    const req = new Request("https://example.com/");
    const session = await m.load(req);
    session.set("uid", uid);
    return await m.persist(session, req);
  }));

  const loaded = await Promise.all(cookies.map(async (setCookie) => {
    const back = await m.load(
      new Request("https://example.com/", {
        headers: { cookie: pair(setCookie!) },
      }),
    );
    return back.get("uid");
  }));

  assertEquals(loaded, ids);
});

Deno.test("a manager stays usable across sequential requests", async () => {
  const m = mgr();
  let cookie = cookieValue(await mintCookie(m, "u0"));
  for (let i = 1; i <= 3; i++) {
    const req = new Request("https://example.com/", {
      headers: { cookie: `sid=${cookie}` },
    });
    const session = await m.load(req);
    assertEquals(session.get("uid"), `u${i - 1}`);
    session.set("uid", `u${i}`);
    cookie = cookieValue((await m.persist(session, req))!);
  }
  const final = await m.loadFromCookieHeader(`sid=${cookie}`);
  assertEquals(final.get("uid"), "u3");
});
