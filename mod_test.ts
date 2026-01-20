import { assertEquals, assertNotEquals, assertThrows } from "jsr:@std/assert";
import { Hono } from "hono";
import {
  clearCookie,
  cookieSession,
  decodeBase64Url,
  deriveKey,
  encodeBase64Url,
  getSession,
  parseCookieHeader,
  seal,
  serializeCookie,
  Session,
  unseal,
} from "./mod.ts";

// =============================================================================
// Base64url tests
// =============================================================================

Deno.test("encodeBase64Url/decodeBase64Url roundtrip", () => {
  const testCases = [
    new Uint8Array([]),
    new Uint8Array([0]),
    new Uint8Array([0, 1, 2]),
    new Uint8Array([255, 254, 253]),
    crypto.getRandomValues(new Uint8Array(24)),
    crypto.getRandomValues(new Uint8Array(32)),
    crypto.getRandomValues(new Uint8Array(100)),
  ];

  for (const bytes of testCases) {
    const encoded = encodeBase64Url(bytes);
    const decoded = decodeBase64Url(encoded);
    assertEquals(decoded, bytes);
  }
});

Deno.test("encodeBase64Url produces URL-safe output", () => {
  // Generate bytes that would produce + and / in standard base64
  const bytes = new Uint8Array([251, 239, 190]);
  const encoded = encodeBase64Url(bytes);

  assertEquals(encoded.includes("+"), false);
  assertEquals(encoded.includes("/"), false);
});

Deno.test("decodeBase64Url handles padded input", () => {
  const bytes = new Uint8Array([1, 2, 3]);
  const encoded = encodeBase64Url(bytes);

  // Add padding
  const padded = encoded + "==";
  const decoded = decodeBase64Url(padded);
  assertEquals(decoded, bytes);
});

Deno.test("decodeBase64Url rejects invalid characters", () => {
  // Standard base64 characters (+/) are invalid in base64url
  assertThrows(() => decodeBase64Url("abc+def"), Error);
  assertThrows(() => decodeBase64Url("abc/def"), Error);
  assertThrows(() => decodeBase64Url("abc def"), Error);
});

// =============================================================================
// Cookie tests
// =============================================================================

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

Deno.test("serializeCookie basic", () => {
  const result = serializeCookie("session", "abc123", {});
  assertEquals(result, "session=abc123");
});

Deno.test("serializeCookie with all options", () => {
  const result = serializeCookie("session", "abc123", {
    path: "/",
    domain: "example.com",
    httpOnly: true,
    secure: true,
    sameSite: "Strict",
    maxAge: 3600,
    partitioned: true,
  });

  assertEquals(result.includes("Path=/"), true);
  assertEquals(result.includes("Domain=example.com"), true);
  assertEquals(result.includes("HttpOnly"), true);
  assertEquals(result.includes("Secure"), true);
  assertEquals(result.includes("SameSite=Strict"), true);
  assertEquals(result.includes("Max-Age=3600"), true);
  assertEquals(result.includes("Partitioned"), true);
});

Deno.test("clearCookie produces expiring cookie", () => {
  const result = clearCookie("session", { path: "/" });
  assertEquals(result.includes("Max-Age=0"), true);
  assertEquals(result.includes("Expires="), true);
});

// =============================================================================
// Seal/Unseal tests
// =============================================================================

Deno.test("seal/unseal roundtrip", async () => {
  const key = await deriveKey("test-secret", "session");
  const data = { uid: "user123", claims: { email: "test@example.com" } };

  const token = seal(data, key, {
    cookieName: "session",
    purpose: "session",
    ttlSeconds: 3600,
  });

  const result = unseal<typeof data>(token, key, {
    cookieName: "session",
    purpose: "session",
  });

  assertEquals(result.ok, true);
  if (result.ok) {
    assertEquals(result.payload.data, data);
    assertEquals(result.payload.ctx.cookieName, "session");
    assertEquals(result.payload.ctx.purpose, "session");
  }
});

Deno.test("unseal fails with wrong secret", async () => {
  const key1 = await deriveKey("secret1", "session");
  const key2 = await deriveKey("secret2", "session");
  const data = { uid: "user123" };

  const token = seal(data, key1, {
    cookieName: "session",
    purpose: "session",
  });

  const result = unseal<typeof data>(token, key2, {
    cookieName: "session",
    purpose: "session",
  });

  assertEquals(result.ok, false);
  if (!result.ok) {
    assertEquals(result.error.includes("Decryption failed"), true);
  }
});

Deno.test("unseal fails with tampered token", async () => {
  const key = await deriveKey("test-secret", "session");
  const data = { uid: "user123" };

  let token = seal(data, key, {
    cookieName: "session",
    purpose: "session",
  });

  // Tamper with the token
  const parts = token.split(".");
  parts[2] = parts[2].slice(0, -4) + "XXXX";
  token = parts.join(".");

  const result = unseal<typeof data>(token, key, {
    cookieName: "session",
    purpose: "session",
  });

  assertEquals(result.ok, false);
});

Deno.test("unseal fails with cookie name mismatch", async () => {
  const key = await deriveKey("test-secret", "session");
  const data = { uid: "user123" };

  const token = seal(data, key, {
    cookieName: "session",
    purpose: "session",
  });

  const result = unseal<typeof data>(token, key, {
    cookieName: "other-session",
    purpose: "session",
  });

  assertEquals(result.ok, false);
  if (!result.ok) {
    assertEquals(result.error.includes("Cookie name mismatch"), true);
  }
});

Deno.test("unseal fails with purpose mismatch", async () => {
  const key = await deriveKey("test-secret", "session");
  const data = { uid: "user123" };

  const token = seal(data, key, {
    cookieName: "session",
    purpose: "session",
  });

  const result = unseal<typeof data>(token, key, {
    cookieName: "session",
    purpose: "other-purpose",
  });

  assertEquals(result.ok, false);
  if (!result.ok) {
    assertEquals(result.error.includes("Purpose mismatch"), true);
  }
});

Deno.test("unseal enforces expiry", async () => {
  const key = await deriveKey("test-secret", "session");
  const data = { uid: "user123" };

  // Create a token that's already expired (ttl = -100 seconds ago)
  const token = seal(data, key, {
    cookieName: "session",
    purpose: "session",
    ttlSeconds: -100,
  });

  const result = unseal<typeof data>(token, key, {
    cookieName: "session",
    purpose: "session",
    clockSkewSeconds: 60,
  });

  assertEquals(result.ok, false);
  if (!result.ok) {
    assertEquals(result.error.includes("expired"), true);
  }
});

Deno.test("unseal allows clock skew", async () => {
  const key = await deriveKey("test-secret", "session");
  const data = { uid: "user123" };

  // Create a token that expired 30 seconds ago
  const token = seal(data, key, {
    cookieName: "session",
    purpose: "session",
    ttlSeconds: -30,
  });

  // Should succeed with 60 second clock skew
  const result = unseal<typeof data>(token, key, {
    cookieName: "session",
    purpose: "session",
    clockSkewSeconds: 60,
  });

  assertEquals(result.ok, true);
});

Deno.test("unseal validates host binding", async () => {
  const key = await deriveKey("test-secret", "session");
  const data = { uid: "user123" };

  const token = seal(data, key, {
    cookieName: "session",
    purpose: "session",
    host: "example.com",
  });

  const result = unseal<typeof data>(token, key, {
    cookieName: "session",
    purpose: "session",
    host: "other.com",
  });

  assertEquals(result.ok, false);
  if (!result.ok) {
    assertEquals(result.error.includes("Host mismatch"), true);
  }
});

Deno.test("unseal rejects invalid token format", async () => {
  const key = await deriveKey("test-secret", "session");

  const result = unseal("not.a.valid.token.format", key, {
    cookieName: "session",
    purpose: "session",
  });

  assertEquals(result.ok, false);
});

// =============================================================================
// Session tests
// =============================================================================

Deno.test("Session get/set", () => {
  const session = new Session<{ uid?: string }>({});

  assertEquals(session.get("uid"), undefined);
  assertEquals(session.isDirty, false);

  session.set("uid", "user123");

  assertEquals(session.get("uid"), "user123");
  assertEquals(session.isDirty, true);
});

Deno.test("Session unset", () => {
  const session = new Session<{ uid?: string }>({ uid: "user123" });

  session.unset("uid");

  assertEquals(session.get("uid"), undefined);
  assertEquals(session.isDirty, true);
});

Deno.test("Session destroy", () => {
  const session = new Session<{ uid?: string }>({ uid: "user123" });

  assertEquals(session.isDestroyed, false);

  session.destroy();

  assertEquals(session.isDestroyed, true);
  assertEquals(session.isDirty, true);
});

Deno.test("Session isNew flag", () => {
  const newSession = new Session<{ uid?: string }>({}, { isNew: true });
  const existingSession = new Session<{ uid?: string }>({}, { isNew: false });

  assertEquals(newSession.isNew, true);
  assertEquals(existingSession.isNew, false);
});

Deno.test("Session flash", () => {
  const session = new Session<{ flash?: Record<string, string> }>({});

  session.flash("notice", "Hello!");
  assertEquals(session.isDirty, true);

  const flash = session.consumeFlash();
  assertEquals(flash, { notice: "Hello!" });
  assertEquals(session.get("flash"), undefined);
});

Deno.test("Session touch marks dirty", () => {
  const session = new Session<{ uid?: string }>({});

  assertEquals(session.isDirty, false);

  session.touch();

  assertEquals(session.isDirty, true);
});

// =============================================================================
// Middleware integration tests
// =============================================================================

Deno.test("middleware attaches session to context", async () => {
  const app = new Hono();
  app.use("*", cookieSession({
    secret: "test-secret",
    cookieName: "session",
  }));
  app.get("/", (c) => {
    const session = getSession(c);
    return c.json({ isNew: session.isNew });
  });

  const res = await app.request("/");
  const data = await res.json();

  assertEquals(data.isNew, true);
});

Deno.test("middleware sets cookie on mutation", async () => {
  const app = new Hono();
  app.use("*", cookieSession({
    secret: "test-secret",
    cookieName: "session",
    ttlSeconds: 3600,
  }));
  app.get("/", (c) => {
    const session = getSession<{ uid?: string }>(c);
    session.set("uid", "user123");
    return c.text("OK");
  });

  const res = await app.request("/");
  const setCookie = res.headers.get("set-cookie");

  assertNotEquals(setCookie, null);
  assertEquals(setCookie?.includes("session=v1."), true);
  assertEquals(setCookie?.includes("Max-Age=3600"), true);
});

Deno.test("middleware does not set cookie without mutation", async () => {
  const app = new Hono();
  app.use("*", cookieSession({
    secret: "test-secret",
    cookieName: "session",
  }));
  app.get("/", (c) => {
    getSession(c);
    return c.text("OK");
  });

  const res = await app.request("/");
  const setCookie = res.headers.get("set-cookie");

  assertEquals(setCookie, null);
});

Deno.test("middleware reads existing session", async () => {
  const app = new Hono();
  app.use("*", cookieSession({
    secret: "test-secret",
    cookieName: "session",
  }));
  app.get("/set", (c) => {
    const session = getSession<{ uid?: string }>(c);
    session.set("uid", "user123");
    return c.text("OK");
  });
  app.get("/get", (c) => {
    const session = getSession<{ uid?: string }>(c);
    return c.json({ uid: session.get("uid"), isNew: session.isNew });
  });

  // First request sets the session
  const setRes = await app.request("/set");
  const setCookie = setRes.headers.get("set-cookie")!;
  const cookieValue = setCookie.split(";")[0];

  // Second request reads the session
  const getRes = await app.request("/get", {
    headers: { cookie: cookieValue },
  });
  const data = await getRes.json();

  assertEquals(data.uid, "user123");
  assertEquals(data.isNew, false);
});

Deno.test("middleware clears cookie on destroy", async () => {
  const app = new Hono();
  app.use("*", cookieSession({
    secret: "test-secret",
    cookieName: "session",
  }));
  app.get("/", (c) => {
    const session = getSession(c);
    session.destroy();
    return c.text("OK");
  });

  const res = await app.request("/");
  const setCookie = res.headers.get("set-cookie");

  assertNotEquals(setCookie, null);
  assertEquals(setCookie?.includes("Max-Age=0"), true);
});

Deno.test("middleware clears cookie on invalid (default behavior)", async () => {
  const app = new Hono();
  app.use("*", cookieSession({
    secret: "test-secret",
    cookieName: "session",
    onInvalidCookie: "clear",
  }));
  app.get("/", (c) => {
    getSession(c);
    return c.text("OK");
  });

  const res = await app.request("/", {
    headers: { cookie: "session=invalid-garbage" },
  });
  const setCookie = res.headers.get("set-cookie");

  assertNotEquals(setCookie, null);
  assertEquals(setCookie?.includes("Max-Age=0"), true);
});

Deno.test("middleware respects maxCookieBytes", async () => {
  const app = new Hono();
  app.use("*", cookieSession({
    secret: "test-secret",
    cookieName: "session",
    maxCookieBytes: 50,
    onInvalidCookie: "clear",
  }));
  app.get("/", (c) => {
    const session = getSession(c);
    return c.json({ isNew: session.isNew });
  });

  // Create a cookie value that's too long
  const longValue = "a".repeat(100);
  const res = await app.request("/", {
    headers: { cookie: `session=${longValue}` },
  });
  const data = await res.json();

  assertEquals(data.isNew, true);
});

Deno.test("middleware rolling expiry", async () => {
  const app = new Hono();
  app.use("*", cookieSession({
    secret: "test-secret",
    cookieName: "session",
    ttlSeconds: 3600,
    rolling: true,
  }));
  app.get("/set", (c) => {
    const session = getSession<{ uid?: string }>(c);
    session.set("uid", "user123");
    return c.text("OK");
  });
  app.get("/read", (c) => {
    const session = getSession<{ uid?: string }>(c);
    return c.json({ uid: session.get("uid") });
  });

  // First request sets the session
  const setRes = await app.request("/set");
  const setCookie = setRes.headers.get("set-cookie")!;
  const cookieValue = setCookie.split(";")[0];

  // Second request should refresh the cookie (rolling)
  const readRes = await app.request("/read", {
    headers: { cookie: cookieValue },
  });
  const newSetCookie = readRes.headers.get("set-cookie");

  // Should have set a new cookie due to rolling
  assertNotEquals(newSetCookie, null);
});

Deno.test("getSession throws if middleware not used", async () => {
  const app = new Hono();
  app.get("/", (c) => {
    try {
      getSession(c);
      return c.text("Should not reach here");
    } catch (e) {
      return c.text((e as Error).message, 500);
    }
  });

  const res = await app.request("/");
  const text = await res.text();

  assertEquals(text.includes("Session not found"), true);
});
