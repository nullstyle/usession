import {
  assertEquals,
  assertMatch,
  assertNotEquals,
  assertRejects,
  assertStringIncludes,
  assertThrows,
} from "@std/assert";
import { SessionManager, type SessionOptions } from "./manager.ts";
import { deriveKey, seal, unseal } from "./seal.ts";
import { Session } from "./session.ts";
import { appEpoch, userEpoch } from "./epoch.ts";

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

// ---------------------------------------------------------------------------
// Epoch revocation tracks
// ---------------------------------------------------------------------------

/** Session shape for the epoch tests: a user axis and a tenant axis. */
type EData = { uid?: string; org?: string };

function emgr(
  extra: Partial<SessionOptions<EData>> = {},
): SessionManager<EData> {
  return new SessionManager<EData>({
    secret: SECRET,
    cookieName: "sid",
    ...extra,
  });
}

/** Mint a `Set-Cookie` carrying exactly `data`, always dirtying the session. */
async function mintWith(
  manager: SessionManager<EData>,
  data: EData,
): Promise<string> {
  const req = new Request("https://example.com/");
  const session = await manager.load(req);
  session.touch();
  for (const [key, value] of Object.entries(data)) {
    session.set(key as keyof EData, value);
  }
  const setCookie = await manager.persist(session, req);
  if (!setCookie) throw new Error("expected a Set-Cookie");
  return setCookie;
}

/** Load a previously minted `Set-Cookie` back through a manager. */
function loadCookie(manager: SessionManager<EData>, setCookie: string) {
  return manager.load(
    new Request("https://example.com/", {
      headers: { cookie: pair(setCookie) },
    }),
  );
}

/** The epoch stamp inside a minted cookie, or undefined when there is none. */
async function stampOf(
  setCookie: string,
  secret: string = SECRET,
): Promise<Record<string, number> | undefined> {
  const key = await deriveKey(secret, "session");
  const result = unseal<EData>(cookieValue(setCookie), key, {
    cookieName: "sid",
    purpose: "session",
  });
  if (!result.ok) throw new Error(result.error);
  return result.payload.ep;
}

// --- construction ----------------------------------------------------------

Deno.test("an epoch track with a malformed name throws from the constructor", () => {
  assertThrows(
    () => emgr({ epochTracks: [appEpoch<EData>(() => 1, "bad name")] }),
    TypeError,
    "epoch track name",
  );
});

Deno.test("duplicate epoch track names throw from the constructor", () => {
  assertThrows(
    () =>
      emgr({
        epochTracks: [
          appEpoch<EData>(() => 1, "a"),
          appEpoch<EData>(() => 2, "a"),
        ],
      }),
    TypeError,
    "duplicate epoch track",
  );
});

Deno.test("an epoch track without current() throws from the constructor", () => {
  assertThrows(
    () =>
      emgr({
        // @ts-expect-error deliberately omitting the required resolver
        epochTracks: [{ name: "a" }],
      }),
    TypeError,
    "current()",
  );
});

Deno.test("an epoch track with a non-function key throws from the constructor", () => {
  assertThrows(
    () =>
      emgr({
        // @ts-expect-error key must be a function
        epochTracks: [{ name: "a", key: "uid", current: () => 1 }],
      }),
    TypeError,
    "key",
  );
});

Deno.test("a resolver runs neither at construction nor without a cookie", async () => {
  let calls = 0;
  const m = emgr({
    epochTracks: [
      appEpoch<EData>(() => {
        calls++;
        return 1;
      }),
    ],
  });
  assertEquals(calls, 0);
  const session = await m.load(new Request("https://example.com/"));
  assertEquals(session.isNew, true);
  assertEquals(calls, 0);
});

// --- app track -------------------------------------------------------------

Deno.test("a cookie stamped at the current app epoch loads unchanged", async () => {
  const m = emgr({ epochTracks: [appEpoch<EData>(() => 3)] });
  const setCookie = await mintWith(m, { uid: "alice" });
  // The stamp is what the next load compares against, so pin it too: a test
  // that only checks "it loads" would pass with epoch checking removed.
  assertEquals(await stampOf(setCookie), { a: 3 });
  const session = await loadCookie(m, setCookie);
  assertEquals(session.isInvalid, false);
  assertEquals(session.get("uid"), "alice");
});

Deno.test("bumping the app epoch revokes every user at once", async () => {
  let epoch = 1;
  const m = emgr({ epochTracks: [appEpoch<EData>(() => epoch)] });
  const alice = await mintWith(m, { uid: "alice" });
  const bob = await mintWith(m, { uid: "bob" });
  epoch = 2;

  const first = await loadCookie(m, alice);
  assertEquals(first.isInvalid, true);
  assertEquals(first.invalidReason, "Epoch stale: a");

  const second = await loadCookie(m, bob);
  assertEquals(second.isInvalid, true);
  assertEquals(second.invalidReason, "Epoch stale: a");
  // The revoked session must not leak its identity to the app either.
  assertEquals(second.get("uid"), undefined);
});

// --- user track ------------------------------------------------------------

Deno.test("bumping one user's epoch invalidates that user's cookie", async () => {
  const epochs = new Map<string, number>();
  const m = emgr({
    epochTracks: [
      userEpoch<EData>((d) => d.uid ?? null, (uid) => epochs.get(uid) ?? 0),
    ],
  });
  const alice = await mintWith(m, { uid: "alice" });
  epochs.set("alice", 1);
  const session = await loadCookie(m, alice);
  assertEquals(session.isInvalid, true);
  assertEquals(session.invalidReason, "Epoch stale: u");
});

Deno.test("bumping one user's epoch leaves other users signed in", async () => {
  const epochs = new Map<string, number>();
  const m = emgr({
    epochTracks: [
      userEpoch<EData>((d) => d.uid ?? null, (uid) => epochs.get(uid) ?? 0),
    ],
  });
  const alice = await mintWith(m, { uid: "alice" });
  const bob = await mintWith(m, { uid: "bob" });
  epochs.set("alice", 1);

  assertEquals((await loadCookie(m, alice)).invalidReason, "Epoch stale: u");

  const other = await loadCookie(m, bob);
  assertEquals(other.isInvalid, false);
  assertEquals(other.get("uid"), "bob");
});

// --- custom track ----------------------------------------------------------

Deno.test("a custom track keyed on org revokes only that org", async () => {
  const orgs = new Map<string, number>();
  const m = emgr({
    epochTracks: [
      {
        name: "o",
        key: (d: EData) => d.org ?? null,
        current: (key: string | null) => orgs.get(key ?? "") ?? 0,
      },
    ],
  });
  const acme = await mintWith(m, { uid: "alice", org: "acme" });
  const globex = await mintWith(m, { uid: "bob", org: "globex" });
  orgs.set("acme", 4);

  assertEquals((await loadCookie(m, acme)).invalidReason, "Epoch stale: o");

  const untouched = await loadCookie(m, globex);
  assertEquals(untouched.isInvalid, false);
  assertEquals(untouched.get("org"), "globex");
});

// --- several tracks at once ------------------------------------------------

Deno.test("a cookie is stamped for every applicable track", async () => {
  const m = emgr({
    epochTracks: [
      appEpoch<EData>(() => 2),
      userEpoch<EData>((d) => d.uid ?? null, () => 5),
    ],
  });
  const setCookie = await mintWith(m, { uid: "alice" });
  assertEquals(await stampOf(setCookie), { a: 2, u: 5 });
});

Deno.test("a loaded session exposes the epochs and keys it was validated against", async () => {
  const m = emgr({
    epochTracks: [
      appEpoch<EData>(() => 2),
      userEpoch<EData>((d) => d.uid ?? null, () => 5),
    ],
  });
  const setCookie = await mintWith(m, { uid: "alice" });
  const session = await loadCookie(m, setCookie);
  // The keys are what stop alice's epoch being restamped onto bob's session.
  assertEquals(session.epochs, {
    values: { a: 2, u: 5 },
    keys: { a: null, u: "alice" },
  });
});

Deno.test("staleness on any one of several tracks rejects the session", async () => {
  const userEpochs = new Map<string, number>();
  const m = emgr({
    epochTracks: [
      appEpoch<EData>(() => 1),
      userEpoch<EData>((d) => d.uid ?? null, (uid) => userEpochs.get(uid) ?? 0),
    ],
  });
  const setCookie = await mintWith(m, { uid: "alice" });
  userEpochs.set("alice", 9);
  const session = await loadCookie(m, setCookie);
  assertEquals(session.isInvalid, true);
  assertEquals(session.invalidReason, "Epoch stale: u");
});

// --- anonymous sessions ----------------------------------------------------

Deno.test("an anonymous session loads fine with a user track configured", async () => {
  const m = emgr({
    epochTracks: [userEpoch<EData>((d) => d.uid ?? null, () => 1)],
  });
  const setCookie = await mintWith(m, {});
  const session = await loadCookie(m, setCookie);
  assertEquals(session.isInvalid, false);
  assertEquals(session.get("uid"), undefined);
});

Deno.test("an anonymous session's cookie carries no user stamp", async () => {
  const m = emgr({
    epochTracks: [userEpoch<EData>((d) => d.uid ?? null, () => 1)],
  });
  const setCookie = await mintWith(m, {});
  assertEquals(await stampOf(setCookie), undefined);
});

Deno.test("an empty-string key skips the track", async () => {
  let calls = 0;
  const m = emgr({
    epochTracks: [
      userEpoch<EData>((d) => d.uid ?? null, () => {
        calls++;
        return 1;
      }),
    ],
  });
  const setCookie = await mintWith(m, { uid: "" });
  assertEquals(await stampOf(setCookie), undefined);
  assertEquals(calls, 0);
});

// --- login mid-request -----------------------------------------------------

Deno.test("logging in mid-request stamps the new user's epoch", async () => {
  const epochs = new Map<string, number>([["bob", 7]]);
  const m = emgr({
    epochTracks: [
      userEpoch<EData>((d) => d.uid ?? null, (uid) => epochs.get(uid) ?? 0),
    ],
  });
  const anon = await mintWith(m, {});
  const req = new Request("https://example.com/", {
    headers: { cookie: pair(anon) },
  });
  const session = await m.load(req);
  session.set("uid", "bob");
  const setCookie = await m.persist(session, req);
  assertEquals(await stampOf(setCookie!), { u: 7 });
});

Deno.test("the cookie minted at login loads cleanly afterwards", async () => {
  const epochs = new Map<string, number>([["bob", 7]]);
  const m = emgr({
    epochTracks: [
      userEpoch<EData>((d) => d.uid ?? null, (uid) => epochs.get(uid) ?? 0),
    ],
  });
  const anon = await mintWith(m, {});
  const req = new Request("https://example.com/", {
    headers: { cookie: pair(anon) },
  });
  const session = await m.load(req);
  session.set("uid", "bob");
  const setCookie = await m.persist(session, req);

  const back = await loadCookie(m, setCookie!);
  assertEquals(back.isInvalid, false);
  assertEquals(back.get("uid"), "bob");
});

Deno.test("regenerate then set(uid) stamps the new identity", async () => {
  const epochs = new Map<string, number>([["alice", 1], ["bob", 4]]);
  const m = emgr({
    epochTracks: [
      userEpoch<EData>((d) => d.uid ?? null, (uid) => epochs.get(uid) ?? 0),
    ],
  });
  const alice = await mintWith(m, { uid: "alice" });
  const req = new Request("https://example.com/", {
    headers: { cookie: pair(alice) },
  });
  const session = await m.load(req);
  session.regenerate();
  session.set("uid", "bob");
  const setCookie = await m.persist(session, req);
  assertEquals(await stampOf(setCookie!), { u: 4 });

  const back = await loadCookie(m, setCookie!);
  assertEquals(back.isInvalid, false);
  assertEquals(back.get("uid"), "bob");
});

// --- missing stamps --------------------------------------------------------

Deno.test("a cookie minted without tracks is rejected once tracks exist", async () => {
  const plain = emgr();
  const setCookie = await mintWith(plain, { uid: "alice" });
  const tracked = emgr({ epochTracks: [appEpoch<EData>(() => 0)] });
  const session = await loadCookie(tracked, setCookie);
  assertEquals(session.isInvalid, true);
  assertEquals(session.invalidReason, "Epoch missing: a");
});

Deno.test("an untracked manager is unaffected by the missing stamp", async () => {
  const plain = emgr();
  const setCookie = await mintWith(plain, { uid: "alice" });
  const session = await loadCookie(plain, setCookie);
  assertEquals(session.isInvalid, false);
  assertEquals(session.get("uid"), "alice");
});

// --- resolver failure ------------------------------------------------------

Deno.test("a throwing resolver rejects the session by default", async () => {
  let boom = false;
  const m = emgr({
    epochTracks: [
      appEpoch<EData>(() => {
        if (boom) throw new Error("store down");
        return 1;
      }),
    ],
  });
  const setCookie = await mintWith(m, { uid: "alice" });
  boom = true;
  const session = await loadCookie(m, setCookie);
  assertEquals(session.isInvalid, true);
  assertEquals(session.invalidReason, "Epoch unavailable: a");
});

Deno.test("a resolver returning a non-number rejects the session", async () => {
  let broken = false;
  const m = emgr({
    epochTracks: [
      appEpoch<EData>(() => (broken ? ("nope" as unknown as number) : 1)),
    ],
  });
  const setCookie = await mintWith(m, { uid: "alice" });
  broken = true;
  const session = await loadCookie(m, setCookie);
  assertEquals(session.invalidReason, "Epoch unavailable: a");
});

Deno.test("a resolver returning NaN rejects the session", async () => {
  let broken = false;
  const m = emgr({
    epochTracks: [appEpoch<EData>(() => (broken ? NaN : 1))],
  });
  const setCookie = await mintWith(m, { uid: "alice" });
  broken = true;
  const session = await loadCookie(m, setCookie);
  assertEquals(session.invalidReason, "Epoch unavailable: a");
});

Deno.test('onEpochError returning "allow" lets the session load', async () => {
  let boom = false;
  const seen: string[] = [];
  const m = emgr({
    epochTracks: [
      appEpoch<EData>(() => {
        if (boom) throw new Error("store down");
        return 1;
      }),
    ],
    onEpochError: (info) => {
      seen.push(info.track);
      return "allow";
    },
  });
  const setCookie = await mintWith(m, { uid: "alice" });
  boom = true;
  const session = await loadCookie(m, setCookie);
  assertEquals(session.isInvalid, false);
  assertEquals(session.get("uid"), "alice");
  assertEquals(seen, ["a"]);
});

Deno.test("onEpochError receives the track, key and request", async () => {
  let boom = false;
  const seen: { track: string; key: string | null; request?: Request }[] = [];
  const m = emgr({
    epochTracks: [
      userEpoch<EData>((d) => d.uid ?? null, () => {
        if (boom) throw new Error("store down");
        return 1;
      }),
    ],
    onEpochError: (info) => {
      seen.push({ track: info.track, key: info.key, request: info.request });
      return "allow";
    },
  });
  const setCookie = await mintWith(m, { uid: "alice" });
  boom = true;
  const req = new Request("https://example.com/", {
    headers: { cookie: pair(setCookie) },
  });
  await m.load(req);
  assertEquals(seen.length, 1);
  assertEquals(seen[0].track, "u");
  assertEquals(seen[0].key, "alice");
  assertEquals(seen[0].request, req);
});

Deno.test("an onEpochError that throws propagates out of load", async () => {
  let boom = false;
  const m = emgr({
    epochTracks: [
      appEpoch<EData>(() => {
        if (boom) throw new Error("store down");
        return 1;
      }),
    ],
    onEpochError: () => {
      throw new Error("epoch policy exploded");
    },
  });
  const setCookie = await mintWith(m, { uid: "alice" });
  boom = true;
  await assertRejects(
    () => loadCookie(m, setCookie),
    Error,
    "epoch policy exploded",
  );
});

// --- lagging replicas ------------------------------------------------------

Deno.test("a resolver lagging behind the stamp still accepts the session", async () => {
  let epoch = 5;
  const m = emgr({ epochTracks: [appEpoch<EData>(() => epoch)] });
  const setCookie = await mintWith(m, { uid: "alice" });
  epoch = 2;
  const session = await loadCookie(m, setCookie);
  assertEquals(session.isInvalid, false);
  assertEquals(session.get("uid"), "alice");
});

// --- onInvalid -------------------------------------------------------------

Deno.test("onInvalid reports the epoch reason", async () => {
  let epoch = 1;
  const seen: string[] = [];
  const m = emgr({
    epochTracks: [appEpoch<EData>(() => epoch)],
    onInvalid: (info) => seen.push(info.reason),
  });
  const setCookie = await mintWith(m, { uid: "alice" });
  epoch = 2;
  await loadCookie(m, setCookie);
  assertEquals(seen, ["Epoch stale: a"]);
});

// --- resolution ordering vs planted cookies --------------------------------

Deno.test("planted junk cookies never reach the epoch resolver", async () => {
  let calls = 0;
  const m = emgr({
    epochTracks: [
      appEpoch<EData>(() => {
        calls++;
        return 1;
      }),
    ],
  });
  const header = Array.from({ length: 20 }, (_, i) => `sid=junk${i}`).join(
    "; ",
  );
  const session = await m.loadFromCookieHeader(header);
  assertEquals(session.isInvalid, true);
  assertEquals(calls, 0);
});

Deno.test("one junk cookie beside a valid one still loads with epochs", async () => {
  let calls = 0;
  const m = emgr({
    epochTracks: [
      appEpoch<EData>(() => {
        calls++;
        return 1;
      }),
    ],
  });
  const setCookie = await mintWith(m, { uid: "alice" });
  calls = 0;
  const session = await m.loadFromCookieHeader(
    `sid=junk; ${pair(setCookie)}`,
  );
  assertEquals(session.isInvalid, false);
  assertEquals(session.get("uid"), "alice");
  assertEquals(calls, 1);
});

Deno.test("a stale cookie beside a fresh one falls through to the fresh session", async () => {
  let epoch = 1;
  const m = emgr({ epochTracks: [appEpoch<EData>(() => epoch)] });
  const stale = await mintWith(m, { uid: "alice" });
  epoch = 2;
  const fresh = await mintWith(m, { uid: "bob" });

  const session = await m.loadFromCookieHeader(
    `${pair(stale)}; ${pair(fresh)}`,
  );
  assertEquals(session.isInvalid, false);
  assertEquals(session.get("uid"), "bob");
});

// --- persist reuse ---------------------------------------------------------

Deno.test("an unchanged key resolves a track once across load and persist", async () => {
  let calls = 0;
  const m = emgr({
    epochTracks: [
      userEpoch<EData>((d) => d.uid ?? null, () => {
        calls++;
        return 3;
      }),
    ],
  });
  const setCookie = await mintWith(m, { uid: "alice" });
  calls = 0;

  const req = new Request("https://example.com/", {
    headers: { cookie: pair(setCookie) },
  });
  const session = await m.load(req);
  session.touch();
  const reissued = await m.persist(session, req);

  assertEquals(calls, 1);
  assertEquals(await stampOf(reissued!), { u: 3 });
});

Deno.test("a changed key re-resolves the track on persist", async () => {
  const epochs = new Map<string, number>([["alice", 1], ["bob", 6]]);
  let calls = 0;
  const m = emgr({
    epochTracks: [
      userEpoch<EData>((d) => d.uid ?? null, (uid) => {
        calls++;
        return epochs.get(uid) ?? 0;
      }),
    ],
  });
  const setCookie = await mintWith(m, { uid: "alice" });
  calls = 0;

  const req = new Request("https://example.com/", {
    headers: { cookie: pair(setCookie) },
  });
  const session = await m.load(req);
  session.set("uid", "bob");
  const reissued = await m.persist(session, req);

  assertEquals(calls, 2);
  assertEquals(await stampOf(reissued!), { u: 6 });
});

Deno.test("a write-path resolver failure propagates with no error policy", async () => {
  // Nothing can be stamped, and an unstamped cookie is rejected on the very
  // next load, so persist must fail loudly rather than mint one.
  let boom = false;
  const m = emgr({
    epochTracks: [
      userEpoch<EData>((d) => d.uid ?? null, () => {
        if (boom) throw new Error("store down");
        return 1;
      }),
    ],
  });
  const anon = await mintWith(m, {});
  const req = new Request("https://example.com/", {
    headers: { cookie: pair(anon) },
  });
  const session = await m.load(req);
  session.set("uid", "bob");
  boom = true;
  await assertRejects(
    () => m.persist(session, req),
    Error,
    "Epoch unavailable: u",
  );
});

Deno.test("a login during an outage throws rather than minting an unstamped cookie", async () => {
  // There is no prior stamp to preserve for a brand-new identity, so "allow"
  // cannot save this one: minting an unstamped cookie would log the user out on
  // their next request instead, silently. Fail at the moment of failure.
  let boom = false;
  const m = emgr({
    epochTracks: [
      userEpoch<EData>((d) => d.uid ?? null, () => {
        if (boom) throw new Error("store down");
        return 1;
      }),
    ],
    onEpochError: () => "allow",
  });
  const anon = await mintWith(m, {});
  const req = new Request("https://example.com/", {
    headers: { cookie: pair(anon) },
  });
  const session = await m.load(req);
  session.set("uid", "bob");
  boom = true;

  await assertRejects(
    () => m.persist(session, req),
    Error,
    "Epoch unavailable",
  );
});

Deno.test('an existing session under "allow" keeps its stamp through an outage', async () => {
  // The point of "allow": a session that already carries a stamp goes on
  // working, and a re-seal preserves that stamp rather than dropping it.
  let boom = false;
  const m = emgr({
    epochTracks: [
      userEpoch<EData>((d) => d.uid ?? null, () => {
        if (boom) throw new Error("store down");
        return 7;
      }),
    ],
    onEpochError: () => "allow",
    rolling: true,
  });
  const alice = await mintWith(m, { uid: "alice" });
  assertEquals(await stampOf(alice), { u: 7 });

  boom = true;
  const req = new Request("https://example.com/", {
    headers: { cookie: pair(alice) },
  });
  const session = await m.load(req);
  assertEquals(session.isInvalid, false);
  assertEquals(session.get("uid"), "alice");

  // rolling re-seals every request; the stamp must survive it.
  const reissued = await m.persist(session, req);
  assertEquals(await stampOf(reissued!), { u: 7 });

  // ...and once the store recovers the session is still valid, not "missing".
  boom = false;
  const back = await loadCookie(m, reissued!);
  assertEquals(back.isInvalid, false);
  assertEquals(back.get("uid"), "alice");
});

// --- interaction with other features ---------------------------------------

Deno.test("epochs are checked on a cookie sealed under a rotated-out secret", async () => {
  let epoch = 1;
  const tracks = () => [appEpoch<EData>(() => epoch)];
  const old = new SessionManager<EData>({
    secret: SECRET_B,
    cookieName: "sid",
    epochTracks: tracks(),
  });
  const setCookie = await mintWith(old, { uid: "alice" });

  const rotating = new SessionManager<EData>({
    secret: [SECRET_A, SECRET_B],
    cookieName: "sid",
    epochTracks: tracks(),
  });
  epoch = 2;
  const session = await loadCookie(rotating, setCookie);
  assertEquals(session.isInvalid, true);
  assertEquals(session.invalidReason, "Epoch stale: a");
});

Deno.test("a rotated-in cookie keeps a valid epoch stamp", async () => {
  const old = new SessionManager<EData>({
    secret: SECRET_B,
    cookieName: "sid",
    epochTracks: [appEpoch<EData>(() => 1)],
  });
  const setCookie = await mintWith(old, { uid: "alice" });

  const rotating = new SessionManager<EData>({
    secret: [SECRET_A, SECRET_B],
    cookieName: "sid",
    epochTracks: [appEpoch<EData>(() => 1)],
  });
  const req = new Request("https://example.com/", {
    headers: { cookie: pair(setCookie) },
  });
  const session = await rotating.load(req);
  assertEquals(session.isDirty, true);
  const reminted = await rotating.persist(session, req);
  assertEquals(await stampOf(reminted!, SECRET_A), { a: 1 });
});

Deno.test("rolling re-issues a cookie that keeps its epoch stamp", async () => {
  let epoch = 2;
  const m = emgr({
    rolling: true,
    epochTracks: [appEpoch<EData>(() => epoch)],
  });
  const setCookie = await mintWith(m, { uid: "alice" });

  const req = new Request("https://example.com/", {
    headers: { cookie: pair(setCookie) },
  });
  const session = await m.load(req);
  assertEquals(session.isDirty, true);
  const reissued = await m.persist(session, req);
  assertEquals(await stampOf(reissued!), { a: 2 });

  epoch = 3;
  const stale = await loadCookie(m, reissued!);
  assertEquals(stale.invalidReason, "Epoch stale: a");
});

Deno.test("a destroyed session clears the cookie without resolving epochs", async () => {
  let calls = 0;
  const m = emgr({
    epochTracks: [
      appEpoch<EData>(() => {
        calls++;
        return 1;
      }),
    ],
  });
  const req = new Request("https://example.com/");
  const session = await m.load(req);
  session.destroy();
  const cleared = await m.persist(session, req);
  assertStringIncludes(cleared!, "Max-Age=0");
  assertEquals(calls, 0);
});
