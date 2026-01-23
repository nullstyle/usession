import { assertEquals, assertNotEquals, assertThrows } from "jsr:@std/assert";
import {
  clearCookie,
  decodeBase64Url,
  deriveKey,
  encodeBase64Url,
  parseCookieHeader,
  seal,
  serializeCookie,
  Session,
  SessionManager,
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

// =============================================================================
// Cookie tests
// =============================================================================

Deno.test("parseCookieHeader handles single cookie", () => {
  const result = parseCookieHeader("session=abc123");
  assertEquals(result, { session: "abc123" });
});

// ... (keep other cookie tests if desired, or assume they are stable)

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
  }
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

// =============================================================================
// SessionManager integration tests
// =============================================================================

Deno.test("SessionManager loads new session when no cookie", async () => {
  const manager = new SessionManager({
    secret: "test-secret",
    cookieName: "session",
  });

  const req = new Request("http://localhost/");
  const session = await manager.load(req);

  assertEquals(session.isNew, true);
  assertEquals(session.isInvalid, false);
});

Deno.test("SessionManager loads existing session", async () => {
  const manager = new SessionManager({
    secret: "test-secret",
    cookieName: "session",
  });

  // Create a valid cookie manually
  const key = await deriveKey("test-secret", "session");
  const token = seal({ uid: "user123" }, key, {
    cookieName: "session",
    purpose: "session",
  });

  const req = new Request("http://localhost/", {
    headers: { cookie: `session=${token}` },
  });
  const session = await manager.load(req);

  assertEquals(session.isNew, false);
  assertEquals(session.get("uid"), "user123");
});

Deno.test("SessionManager persists dirty session", async () => {
  const manager = new SessionManager({
    secret: "test-secret",
    cookieName: "session",
    ttlSeconds: 3600,
  });

  const req = new Request("http://localhost/");
  const session = await manager.load(req);
  session.set("uid", "user123");

  const cookieVal = await manager.persist(session, req);
  assertNotEquals(cookieVal, null);
  assertEquals(cookieVal?.includes("session=v1."), true);
  assertEquals(cookieVal?.includes("Max-Age=3600"), true);
});

Deno.test("SessionManager does not persist clean session", async () => {
  const manager = new SessionManager({
    secret: "test-secret",
    cookieName: "session",
  });

  const req = new Request("http://localhost/");
  const session = await manager.load(req);
  
  const cookieVal = await manager.persist(session, req);
  assertEquals(cookieVal, null);
});

Deno.test("SessionManager rolling expiry touches session", async () => {
  const manager = new SessionManager({
    secret: "test-secret",
    cookieName: "session",
    rolling: true,
    ttlSeconds: 3600,
  });

  const key = await deriveKey("test-secret", "session");
  const token = seal({ uid: "user123" }, key, {
    cookieName: "session",
    purpose: "session",
  });

  const req = new Request("http://localhost/", {
    headers: { cookie: `session=${token}` },
  });
  const session = await manager.load(req);

  assertEquals(session.isDirty, true); // Rolling should mark dirty
});

Deno.test("SessionManager clears destroyed session", async () => {
  const manager = new SessionManager({
    secret: "test-secret",
    cookieName: "session",
  });

  const req = new Request("http://localhost/");
  const session = await manager.load(req);
  session.destroy();

  const cookieVal = await manager.persist(session, req);
  assertNotEquals(cookieVal, null);
  assertEquals(cookieVal?.includes("Max-Age=0"), true);
});

Deno.test("SessionManager handles invalid cookie (clear)", async () => {
  const manager = new SessionManager({
    secret: "test-secret",
    cookieName: "session",
    onInvalidCookie: "clear",
  });

  const req = new Request("http://localhost/", {
    headers: { cookie: "session=invalid" },
  });
  const session = await manager.load(req);

  assertEquals(session.isNew, true);
  assertEquals(session.isInvalid, true);

  const cookieVal = await manager.persist(session, req);
  assertNotEquals(cookieVal, null);
  assertEquals(cookieVal?.includes("Max-Age=0"), true);
});

Deno.test("SessionManager handles invalid cookie (ignore)", async () => {
  const manager = new SessionManager({
    secret: "test-secret",
    cookieName: "session",
    onInvalidCookie: "ignore",
  });

  const req = new Request("http://localhost/", {
    headers: { cookie: "session=invalid" },
  });
  const session = await manager.load(req);

  assertEquals(session.isNew, true);
  assertEquals(session.isInvalid, true);

  const cookieVal = await manager.persist(session, req);
  assertEquals(cookieVal, null);
});