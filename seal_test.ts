import {
  assertEquals,
  assertMatch,
  assertNotEquals,
  assertRejects,
  assertStringIncludes,
} from "@std/assert";
import { decodeBase64Url, encodeBase64Url } from "@std/encoding/base64url";
import nacl from "tweetnacl";

import {
  deriveKey,
  MIN_SECRET_BYTES,
  seal,
  type SealedPayload,
  unseal,
  type UnsealOptions,
} from "./seal.ts";

const SECRET = "test-secret-".padEnd(32, "x");
const OTHER_SECRET = "other-secret-".padEnd(32, "y");

const OPTS: UnsealOptions = { cookieName: "sid", purpose: "session" };

function key(purpose = "session", secret = SECRET): Promise<Uint8Array> {
  return deriveKey(secret, purpose);
}

/** Build a token from an arbitrary JSON value, bypassing `seal`'s shaping. */
function craft(value: unknown, keyBytes: Uint8Array): string {
  return craftRaw(JSON.stringify(value), keyBytes);
}

/** Build a token from a raw (possibly non-JSON) plaintext string. */
function craftRaw(text: string, keyBytes: Uint8Array): string {
  const plaintext = new TextEncoder().encode(text);
  const nonce = crypto.getRandomValues(new Uint8Array(24));
  const box = nacl.secretbox(plaintext, nonce, keyBytes);
  return `v2.${encodeBase64Url(nonce)}.${encodeBase64Url(box)}`;
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

function unwrap<T>(token: string, keyBytes: Uint8Array): SealedPayload<T> {
  const result = unseal<T>(token, keyBytes, OPTS);
  if (!result.ok) throw new Error(`expected ok, got: ${result.error}`);
  return result.payload;
}

function errorOf(
  token: string,
  keyBytes: Uint8Array,
  opts: UnsealOptions = OPTS,
): string {
  const result = unseal(token, keyBytes, opts);
  if (result.ok) throw new Error("expected failure, got ok");
  return result.error;
}

// ---------------------------------------------------------------------------
// deriveKey
// ---------------------------------------------------------------------------

Deno.test("MIN_SECRET_BYTES is 32", () => {
  assertEquals(MIN_SECRET_BYTES, 32);
});

Deno.test("deriveKey returns 32 bytes", async () => {
  const k = await deriveKey(SECRET, "session");
  assertEquals(k.length, 32);
});

Deno.test("deriveKey is deterministic", async () => {
  const a = await deriveKey(SECRET, "session");
  const b = await deriveKey(SECRET, "session");
  assertEquals(a, b);
});

Deno.test("deriveKey separates keys by purpose", async () => {
  const a = await deriveKey(SECRET, "session");
  const b = await deriveKey(SECRET, "csrf");
  assertNotEquals(a, b);
});

Deno.test("deriveKey separates keys by secret", async () => {
  const a = await deriveKey(SECRET, "session");
  const b = await deriveKey(OTHER_SECRET, "session");
  assertNotEquals(a, b);
});

Deno.test("deriveKey accepts a Uint8Array secret", async () => {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  const k = await deriveKey(bytes, "session");
  assertEquals(k.length, 32);
});

Deno.test("deriveKey treats a string and its UTF-8 bytes identically", async () => {
  const fromString = await deriveKey(SECRET, "session");
  const fromBytes = await deriveKey(
    new TextEncoder().encode(SECRET),
    "session",
  );
  assertEquals(fromString, fromBytes);
});

Deno.test("deriveKey accepts an exactly-32-byte secret", async () => {
  const k = await deriveKey("c".repeat(32), "session");
  assertEquals(k.length, 32);
});

Deno.test("deriveKey rejects a 31-byte string secret", async () => {
  const error = await assertRejects(
    () => deriveKey("c".repeat(31), "session"),
    TypeError,
  );
  assertStringIncludes(error.message, "at least 32 bytes");
});

Deno.test("deriveKey rejects a 31-byte Uint8Array secret", async () => {
  await assertRejects(
    () => deriveKey(new Uint8Array(31), "session"),
    TypeError,
  );
});

Deno.test("deriveKey rejects an empty string secret", async () => {
  await assertRejects(() => deriveKey("", "session"), TypeError);
});

Deno.test("deriveKey rejects an empty Uint8Array secret", async () => {
  await assertRejects(() => deriveKey(new Uint8Array(0), "session"), TypeError);
});

Deno.test("deriveKey counts UTF-8 bytes, not characters", async () => {
  // 20 characters but 80 UTF-8 bytes: accepted even though it is under 32
  // JS string units long.
  const k = await deriveKey("🔐".repeat(20), "session");
  assertEquals(k.length, 32);
});

Deno.test("deriveKey accepts an empty purpose", async () => {
  const k = await deriveKey(SECRET, "");
  assertEquals(k.length, 32);
});

Deno.test("deriveKey domain separation is injective across the delimiter", async () => {
  const a = await deriveKey("b|" + "c".repeat(32), "a");
  const b = await deriveKey("c".repeat(32), "a|b");
  assertNotEquals(a, b);
});

Deno.test("deriveKey purpose separation is injective for shifted delimiters", async () => {
  const a = await deriveKey(SECRET, "ab|c");
  const b = await deriveKey(SECRET, "a|bc");
  assertNotEquals(a, b);
});

Deno.test("deriveKey handles a unicode purpose", async () => {
  const a = await deriveKey(SECRET, "sessão-🔐");
  const b = await deriveKey(SECRET, "sessão-🔐");
  const c = await deriveKey(SECRET, "sessao-🔐");
  assertEquals(a, b);
  assertNotEquals(a, c);
});

// ---------------------------------------------------------------------------
// seal: token shape
// ---------------------------------------------------------------------------

Deno.test("seal produces a v2 three-segment token", async () => {
  const k = await key();
  const token = seal({ a: 1 }, k, OPTS);
  assertMatch(token, /^v2\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
  assertEquals(token.split(".").length, 3);
});

Deno.test("seal uses a 24-byte nonce", async () => {
  const k = await key();
  const token = seal({ a: 1 }, k, OPTS);
  assertEquals(decodeBase64Url(token.split(".")[1]).length, 24);
});

Deno.test("seal uses a fresh nonce per call", async () => {
  const k = await key();
  const a = seal({ a: 1 }, k, OPTS);
  const b = seal({ a: 1 }, k, OPTS);
  assertNotEquals(a.split(".")[1], b.split(".")[1]);
});

// ---------------------------------------------------------------------------
// seal / unseal round-trips
// ---------------------------------------------------------------------------

Deno.test("round-trips a flat object", async () => {
  const k = await key();
  const data = { userId: 7, name: "ada" };
  const token = seal(data, k, OPTS);
  assertEquals(unwrap<typeof data>(token, k).data, data);
});

Deno.test("round-trips a nested object", async () => {
  const k = await key();
  const data = { user: { id: 1, prefs: { theme: { mode: "dark" } } } };
  const token = seal(data, k, OPTS);
  assertEquals(unwrap<typeof data>(token, k).data, data);
});

Deno.test("round-trips arrays", async () => {
  const k = await key();
  const data = { roles: ["admin", "editor"], nums: [1, 2, [3, 4]] };
  const token = seal(data, k, OPTS);
  assertEquals(unwrap<typeof data>(token, k).data, data);
});

Deno.test("round-trips unicode and emoji strings", async () => {
  const k = await key();
  const data = { s: "héllo — 世界 🔐👩‍💻 end" };
  const token = seal(data, k, OPTS);
  assertEquals(unwrap<typeof data>(token, k).data, data);
});

Deno.test("round-trips an empty object", async () => {
  const k = await key();
  const token = seal({}, k, OPTS);
  assertEquals(unwrap<Record<string, never>>(token, k).data, {});
});

Deno.test("round-trips a number payload", async () => {
  const k = await key();
  const token = seal(42, k, OPTS);
  assertEquals(unwrap<number>(token, k).data, 42);
});

Deno.test("round-trips a string payload", async () => {
  const k = await key();
  const token = seal("hello", k, OPTS);
  assertEquals(unwrap<string>(token, k).data, "hello");
});

Deno.test("round-trips a null payload", async () => {
  const k = await key();
  const token = seal(null, k, OPTS);
  assertEquals(unwrap<null>(token, k).data, null);
});

Deno.test("round-trips an array payload", async () => {
  const k = await key();
  const token = seal([1, "two", { three: 3 }], k, OPTS);
  assertEquals(unwrap<unknown[]>(token, k).data, [1, "two", { three: 3 }]);
});

Deno.test("round-trip preserves the binding context", async () => {
  const k = await key();
  const token = seal({ a: 1 }, k, { ...OPTS, host: "example.com" });
  const payload = unwrap<{ a: number }>(token, k);
  assertEquals(payload.ctx, {
    v: 2,
    cookieName: "sid",
    purpose: "session",
    host: "example.com",
  });
});

Deno.test("round-trip stamps iat at roughly now", async () => {
  const k = await key();
  const before = nowSeconds();
  const token = seal({ a: 1 }, k, OPTS);
  const { iat } = unwrap<{ a: number }>(token, k);
  assertEquals(iat >= before && iat <= nowSeconds() + 1, true);
});

// ---------------------------------------------------------------------------
// unseal failure paths — none of these may throw
// ---------------------------------------------------------------------------

Deno.test("unseal rejects a token with too few segments", async () => {
  const k = await key();
  assertStringIncludes(errorOf("v2.abc", k), "3 segments");
});

Deno.test("unseal rejects a token with too many segments", async () => {
  const k = await key();
  const token = seal({ a: 1 }, k, OPTS);
  assertStringIncludes(errorOf(token + ".extra", k), "3 segments");
});

Deno.test("unseal rejects an empty token", async () => {
  const k = await key();
  assertStringIncludes(errorOf("", k), "3 segments");
});

Deno.test("unseal rejects a v1 token as an unsupported version", async () => {
  const k = await key();
  const token = seal({ a: 1 }, k, OPTS);
  const v1 = "v1." + token.split(".").slice(1).join(".");
  assertStringIncludes(errorOf(v1, k), "Unsupported token version");
});

Deno.test("unseal rejects an unknown future version", async () => {
  const k = await key();
  const token = seal({ a: 1 }, k, OPTS);
  const v9 = "v9." + token.split(".").slice(1).join(".");
  assertStringIncludes(errorOf(v9, k), "Unsupported token version");
});

Deno.test("unseal rejects a bad base64url nonce segment", async () => {
  const k = await key();
  const token = seal({ a: 1 }, k, OPTS);
  const bad = `v2.***.${token.split(".")[2]}`;
  assertStringIncludes(errorOf(bad, k), "Invalid base64url");
});

Deno.test("unseal rejects a bad base64url box segment", async () => {
  const k = await key();
  const token = seal({ a: 1 }, k, OPTS);
  const bad = `v2.${token.split(".")[1]}.***`;
  assertStringIncludes(errorOf(bad, k), "Invalid base64url");
});

Deno.test("unseal rejects a short nonce", async () => {
  const k = await key();
  const box = seal({ a: 1 }, k, OPTS).split(".")[2];
  const bad = `v2.${encodeBase64Url(new Uint8Array(8))}.${box}`;
  assertStringIncludes(errorOf(bad, k), "Invalid nonce length: 8");
});

Deno.test("unseal rejects a long nonce", async () => {
  const k = await key();
  const box = seal({ a: 1 }, k, OPTS).split(".")[2];
  const bad = `v2.${encodeBase64Url(new Uint8Array(32))}.${box}`;
  assertStringIncludes(errorOf(bad, k), "Invalid nonce length: 32");
});

Deno.test("unseal rejects an empty nonce", async () => {
  const k = await key();
  const box = seal({ a: 1 }, k, OPTS).split(".")[2];
  assertStringIncludes(errorOf(`v2..${box}`, k), "Invalid nonce length: 0");
});

Deno.test("unseal rejects a token sealed under a different key", async () => {
  const k = await key();
  const other = await deriveKey(OTHER_SECRET, "session");
  const token = seal({ a: 1 }, k, OPTS);
  assertStringIncludes(errorOf(token, other), "Decryption failed");
});

Deno.test("unseal rejects a token with a flipped byte in the box", async () => {
  const k = await key();
  const token = seal({ a: 1 }, k, OPTS);
  const [, nonceB64, boxB64] = token.split(".");
  const box = decodeBase64Url(boxB64);
  box[0] ^= 0x01;
  const tampered = `v2.${nonceB64}.${encodeBase64Url(box)}`;
  assertStringIncludes(errorOf(tampered, k), "Decryption failed");
});

Deno.test("unseal rejects a token with a flipped byte in the nonce", async () => {
  const k = await key();
  const token = seal({ a: 1 }, k, OPTS);
  const [, nonceB64, boxB64] = token.split(".");
  const nonce = decodeBase64Url(nonceB64);
  nonce[0] ^= 0x01;
  const tampered = `v2.${encodeBase64Url(nonce)}.${boxB64}`;
  assertStringIncludes(errorOf(tampered, k), "Decryption failed");
});

Deno.test("unseal rejects an empty box", async () => {
  const k = await key();
  const nonce = seal({ a: 1 }, k, OPTS).split(".")[1];
  assertStringIncludes(errorOf(`v2.${nonce}.`, k), "Decryption failed");
});

Deno.test("unseal rejects a truncated box", async () => {
  const k = await key();
  const token = seal({ a: 1 }, k, OPTS);
  const [, nonceB64, boxB64] = token.split(".");
  const box = decodeBase64Url(boxB64).slice(0, 20);
  assertStringIncludes(
    errorOf(`v2.${nonceB64}.${encodeBase64Url(box)}`, k),
    "Decryption failed",
  );
});

Deno.test("unseal rejects non-JSON plaintext", async () => {
  const k = await key();
  assertStringIncludes(errorOf(craftRaw("not json {{{", k), k), "Invalid JSON");
});

Deno.test("unseal rejects a literal null plaintext without throwing", async () => {
  const k = await key();
  assertStringIncludes(
    errorOf(craftRaw("null", k), k),
    "Invalid payload shape",
  );
});

Deno.test("unseal rejects a numeric plaintext", async () => {
  const k = await key();
  assertStringIncludes(errorOf(craftRaw("42", k), k), "Invalid payload shape");
});

Deno.test("unseal rejects a string plaintext", async () => {
  const k = await key();
  assertStringIncludes(
    errorOf(craftRaw('"str"', k), k),
    "Invalid payload shape",
  );
});

Deno.test("unseal rejects a boolean plaintext", async () => {
  const k = await key();
  assertStringIncludes(
    errorOf(craftRaw("true", k), k),
    "Invalid payload shape",
  );
});

Deno.test("unseal rejects an array plaintext", async () => {
  const k = await key();
  // `typeof [] === "object"`, so this gets past the shape guard and must be
  // caught by the context check instead of dereferencing into nothing.
  assertStringIncludes(errorOf(craft([1, 2, 3], k), k), "Invalid context");
});

Deno.test("unseal reports a distinct error for each failure mode", async () => {
  const k = await key();
  const other = await deriveKey(OTHER_SECRET, "session");
  const good = seal({ a: 1 }, k, OPTS);
  const [, nonceB64, boxB64] = good.split(".");

  const errors = [
    errorOf("v2.abc", k),
    errorOf(`v1.${nonceB64}.${boxB64}`, k),
    errorOf(`v2.***.${boxB64}`, k),
    errorOf(`v2.${encodeBase64Url(new Uint8Array(8))}.${boxB64}`, k),
    errorOf(good, other),
    errorOf(craftRaw("not json {{{", k), k),
    errorOf(craftRaw("null", k), k),
    errorOf(craft({ ctx: { v: 1 } }, k), k),
    errorOf(good, k, { cookieName: "other", purpose: "session" }),
    errorOf(good, k, { cookieName: "sid", purpose: "csrf" }),
    errorOf(good, k, { ...OPTS, host: "x" }),
    errorOf(seal({ a: 1 }, k, { ...OPTS, ttlSeconds: -600 }), k, OPTS),
  ];

  assertEquals(new Set(errors).size, errors.length);
});

Deno.test("unseal rejects a payload with no ctx", async () => {
  const k = await key();
  assertStringIncludes(
    errorOf(craft({ iat: nowSeconds(), data: {} }, k), k),
    "Invalid context version",
  );
});

Deno.test("unseal rejects a payload with a wrong ctx version", async () => {
  const k = await key();
  const token = craft({
    ctx: { v: 1, cookieName: "sid", purpose: "session" },
    iat: nowSeconds(),
    data: {},
  }, k);
  assertStringIncludes(errorOf(token, k), "Invalid context version");
});

Deno.test("unseal rejects a payload whose ctx is not an object", async () => {
  const k = await key();
  const token = craft({ ctx: "nope", iat: nowSeconds(), data: {} }, k);
  assertStringIncludes(errorOf(token, k), "Invalid context version");
});

Deno.test("unseal rejects a cookie name mismatch", async () => {
  const k = await key();
  const token = seal({ a: 1 }, k, OPTS);
  const error = errorOf(token, k, { cookieName: "other", purpose: "session" });
  assertStringIncludes(error, "Cookie name mismatch");
});

Deno.test("unseal rejects a purpose mismatch bound in the payload", async () => {
  const k = await key();
  // Same key on both sides, so the check under test is the ctx comparison
  // rather than decryption.
  const token = seal({ a: 1 }, k, OPTS);
  const error = errorOf(token, k, { cookieName: "sid", purpose: "csrf" });
  assertStringIncludes(error, "Purpose mismatch");
});

Deno.test("unseal cannot decrypt a token sealed under a different purpose key", async () => {
  const sessionKey = await key("session");
  const csrfKey = await key("csrf");
  const token = seal({ a: 1 }, sessionKey, OPTS);
  const error = errorOf(token, csrfKey, { cookieName: "sid", purpose: "csrf" });
  assertStringIncludes(error, "Decryption failed");
});

Deno.test("unseal rejects a host mismatch", async () => {
  const k = await key();
  const token = seal({ a: 1 }, k, { ...OPTS, host: "a.example" });
  const error = errorOf(token, k, { ...OPTS, host: "b.example" });
  assertStringIncludes(error, "Host mismatch");
});

// ---------------------------------------------------------------------------
// Host binding symmetry
// ---------------------------------------------------------------------------

Deno.test("host binding round-trips an empty host", async () => {
  const k = await key();
  const token = seal({ a: 1 }, k, { ...OPTS, host: "" });
  const result = unseal<{ a: number }>(token, k, { ...OPTS, host: "" });
  assertEquals(result.ok, true);
});

Deno.test("seal binds an empty host into the payload", async () => {
  const k = await key();
  const token = seal({ a: 1 }, k, { ...OPTS, host: "" });
  assertEquals(unwrap<{ a: number }>(token, k).ctx.host, "");
});

Deno.test("an unbound token is rejected when a host is required", async () => {
  const k = await key();
  const token = seal({ a: 1 }, k, OPTS);
  assertStringIncludes(
    errorOf(token, k, { ...OPTS, host: "x" }),
    "Host mismat",
  );
});

Deno.test("an empty-host token is rejected against a non-empty host", async () => {
  const k = await key();
  const token = seal({ a: 1 }, k, { ...OPTS, host: "" });
  assertStringIncludes(
    errorOf(token, k, { ...OPTS, host: "x" }),
    "Host mismat",
  );
});

Deno.test("a host-bound token passes when the host check is skipped", async () => {
  const k = await key();
  const token = seal({ a: 1 }, k, { ...OPTS, host: "a.example" });
  const result = unseal<{ a: number }>(token, k, OPTS);
  assertEquals(result.ok, true);
});

Deno.test("seal omits host from ctx when none is given", async () => {
  const k = await key();
  const token = seal({ a: 1 }, k, OPTS);
  assertEquals("host" in unwrap<{ a: number }>(token, k).ctx, false);
});

Deno.test("seal treats an explicit undefined host as no host", async () => {
  const k = await key();
  const token = seal({ a: 1 }, k, { ...OPTS, host: undefined });
  assertEquals("host" in unwrap<{ a: number }>(token, k).ctx, false);
});

Deno.test("an unbound token is rejected against an empty expected host", async () => {
  const k = await key();
  // Sealed unbound, checked against "": the two must not be conflated.
  const token = seal({ a: 1 }, k, OPTS);
  assertStringIncludes(errorOf(token, k, { ...OPTS, host: "" }), "Host mismat");
});

// ---------------------------------------------------------------------------
// Expiry
// ---------------------------------------------------------------------------

Deno.test("seal records exp as iat plus ttlSeconds", async () => {
  const k = await key();
  const token = seal({ a: 1 }, k, { ...OPTS, ttlSeconds: 3600 });
  const payload = unwrap<{ a: number }>(token, k);
  assertEquals(payload.exp, payload.iat + 3600);
});

Deno.test("unseal rejects an expired token", async () => {
  const k = await key();
  const token = seal({ a: 1 }, k, { ...OPTS, ttlSeconds: -3600 });
  const error = errorOf(token, k, { ...OPTS, clockSkewSeconds: 0 });
  assertStringIncludes(error, "Token expired");
});

Deno.test("clockSkewSeconds tolerates a recently expired token", async () => {
  const k = await key();
  const token = seal({ a: 1 }, k, { ...OPTS, ttlSeconds: -10 });
  const result = unseal<{ a: number }>(token, k, {
    ...OPTS,
    clockSkewSeconds: 60,
  });
  assertEquals(result.ok, true);
});

Deno.test("the default clock skew is 60 seconds", async () => {
  const k = await key();
  const inSkew = seal({ a: 1 }, k, { ...OPTS, ttlSeconds: -30 });
  const outOfSkew = seal({ a: 1 }, k, { ...OPTS, ttlSeconds: -600 });
  assertEquals(unseal(inSkew, k, OPTS).ok, true);
  assertEquals(unseal(outOfSkew, k, OPTS).ok, false);
});

Deno.test("a token expiring in the future is accepted", async () => {
  const k = await key();
  const token = seal({ a: 1 }, k, { ...OPTS, ttlSeconds: 3600 });
  const result = unseal<{ a: number }>(token, k, {
    ...OPTS,
    clockSkewSeconds: 0,
  });
  assertEquals(result.ok, true);
});

Deno.test("ttlSeconds null produces no exp claim", async () => {
  const k = await key();
  const token = seal({ a: 1 }, k, { ...OPTS, ttlSeconds: null });
  assertEquals(unwrap<{ a: number }>(token, k).exp, undefined);
});

Deno.test("a token with no exp never expires", async () => {
  const k = await key();
  const token = seal({ a: 1 }, k, { ...OPTS, ttlSeconds: null });
  const realNow = Date.now;
  try {
    const future = realNow() + 1000 * 365 * 24 * 3600 * 1000;
    Date.now = () => future;
    const result = unseal<{ a: number }>(token, k, {
      ...OPTS,
      clockSkewSeconds: 0,
    });
    assertEquals(result.ok, true);
  } finally {
    Date.now = realNow;
  }
});

Deno.test("ttlSeconds zero still stamps an exp claim", async () => {
  const k = await key();
  const token = seal({ a: 1 }, k, { ...OPTS, ttlSeconds: 0 });
  const payload = unwrap<{ a: number }>(token, k);
  assertEquals(payload.exp, payload.iat);
});

Deno.test("omitting ttlSeconds produces no exp claim", async () => {
  const k = await key();
  const token = seal({ a: 1 }, k, OPTS);
  assertEquals(unwrap<{ a: number }>(token, k).exp, undefined);
});

Deno.test("unseal rejects a non-numeric exp claim", async () => {
  const k = await key();
  const token = craft({
    ctx: { v: 2, cookieName: "sid", purpose: "session" },
    iat: nowSeconds(),
    exp: "soon",
    data: {},
  }, k);
  assertStringIncludes(errorOf(token, k), "Invalid exp claim");
});

Deno.test("unseal rejects a NaN exp claim serialized as null", async () => {
  const k = await key();
  // JSON.stringify turns NaN into null; a null exp must not be trusted.
  const token = craft({
    ctx: { v: 2, cookieName: "sid", purpose: "session" },
    iat: nowSeconds(),
    exp: NaN,
    data: {},
  }, k);
  assertStringIncludes(errorOf(token, k), "Invalid exp claim");
});

Deno.test("unseal rejects an Infinity exp claim", async () => {
  const k = await key();
  const token = craftRaw(
    '{"ctx":{"v":2,"cookieName":"sid","purpose":"session"},' +
      '"iat":0,"exp":1e999,"data":{}}',
    k,
  );
  assertStringIncludes(errorOf(token, k), "Invalid exp claim");
});

// ---------------------------------------------------------------------------
// iat0 and the absolute session-age cap
// ---------------------------------------------------------------------------

Deno.test("seal defaults iat0 to now", async () => {
  const k = await key();
  const before = nowSeconds();
  const token = seal({ a: 1 }, k, OPTS);
  const { iat0 } = unwrap<{ a: number }>(token, k);
  assertEquals(iat0 !== undefined && iat0 >= before, true);
});

Deno.test("seal carries a supplied iat0 through unchanged", async () => {
  const k = await key();
  const birth = nowSeconds() - 12_345;
  const token = seal({ a: 1 }, k, { ...OPTS, iat0: birth });
  const payload = unwrap<{ a: number }>(token, k);
  assertEquals(payload.iat0, birth);
  assertNotEquals(payload.iat, birth);
});

Deno.test("seal preserves a zero iat0 rather than defaulting it", async () => {
  const k = await key();
  const token = seal({ a: 1 }, k, { ...OPTS, iat0: 0 });
  assertEquals(unwrap<{ a: number }>(token, k).iat0, 0);
});

Deno.test("maxSessionAgeSeconds zero is enforced, not treated as unset", async () => {
  const k = await key();
  const token = seal({ a: 1 }, k, { ...OPTS, iat0: nowSeconds() - 100 });
  const error = errorOf(token, k, {
    ...OPTS,
    clockSkewSeconds: 0,
    maxSessionAgeSeconds: 0,
  });
  assertStringIncludes(error, "maximum age");
});

Deno.test("maxSessionAgeSeconds rejects a session older than the cap", async () => {
  const k = await key();
  const token = seal({ a: 1 }, k, { ...OPTS, iat0: nowSeconds() - 1000 });
  const error = errorOf(token, k, {
    ...OPTS,
    clockSkewSeconds: 0,
    maxSessionAgeSeconds: 100,
  });
  assertStringIncludes(error, "maximum age");
});

Deno.test("maxSessionAgeSeconds allows a session inside the cap", async () => {
  const k = await key();
  const token = seal({ a: 1 }, k, { ...OPTS, iat0: nowSeconds() - 100 });
  const result = unseal<{ a: number }>(token, k, {
    ...OPTS,
    clockSkewSeconds: 0,
    maxSessionAgeSeconds: 10_000,
  });
  assertEquals(result.ok, true);
});

Deno.test("maxSessionAgeSeconds null disables the cap", async () => {
  const k = await key();
  const token = seal({ a: 1 }, k, { ...OPTS, iat0: nowSeconds() - 1_000_000 });
  const result = unseal<{ a: number }>(token, k, {
    ...OPTS,
    clockSkewSeconds: 0,
    maxSessionAgeSeconds: null,
  });
  assertEquals(result.ok, true);
});

Deno.test("the session-age cap tolerates clock skew", async () => {
  const k = await key();
  const token = seal({ a: 1 }, k, { ...OPTS, iat0: nowSeconds() - 110 });
  const result = unseal<{ a: number }>(token, k, {
    ...OPTS,
    clockSkewSeconds: 60,
    maxSessionAgeSeconds: 100,
  });
  assertEquals(result.ok, true);
});

Deno.test("re-sealing cannot extend a session past the cap", async () => {
  const k = await key();
  const birth = nowSeconds() - 1000;
  // Re-seal with a fresh iat but the original iat0.
  const first = seal({ a: 1 }, k, { ...OPTS, iat0: birth });
  const carried = unwrap<{ a: number }>(first, k).iat0;
  const resealed = seal({ a: 2 }, k, { ...OPTS, iat0: carried });
  const error = errorOf(resealed, k, {
    ...OPTS,
    clockSkewSeconds: 0,
    maxSessionAgeSeconds: 100,
  });
  assertStringIncludes(error, "maximum age");
});

Deno.test("a payload without iat0 is not rejected by the cap", async () => {
  const k = await key();
  const token = craft({
    ctx: { v: 2, cookieName: "sid", purpose: "session" },
    iat: nowSeconds(),
    data: { a: 1 },
  }, k);
  const result = unseal<{ a: number }>(token, k, {
    ...OPTS,
    clockSkewSeconds: 0,
    maxSessionAgeSeconds: 1,
  });
  assertEquals(result.ok, true);
});

Deno.test("unseal rejects a non-numeric iat0 when a cap is set", async () => {
  const k = await key();
  const token = craft({
    ctx: { v: 2, cookieName: "sid", purpose: "session" },
    iat: nowSeconds(),
    iat0: "yesterday",
    data: {},
  }, k);
  const error = errorOf(token, k, { ...OPTS, maxSessionAgeSeconds: 100 });
  assertStringIncludes(error, "Invalid iat0 claim");
});

// ---------------------------------------------------------------------------
// flash
// ---------------------------------------------------------------------------

Deno.test("flash messages round-trip", async () => {
  const k = await key();
  const flash = { notice: "saved", alert: "careful — 🔥" };
  const token = seal({ a: 1 }, k, { ...OPTS, flash });
  assertEquals(unwrap<{ a: number }>(token, k).flash, flash);
});

Deno.test("an empty flash object is omitted from the payload", async () => {
  const k = await key();
  const token = seal({ a: 1 }, k, { ...OPTS, flash: {} });
  const payload = unwrap<{ a: number }>(token, k);
  assertEquals(payload.flash, undefined);
  assertEquals("flash" in payload, false);
});

Deno.test("no flash option means no flash key", async () => {
  const k = await key();
  const token = seal({ a: 1 }, k, OPTS);
  assertEquals("flash" in unwrap<{ a: number }>(token, k), false);
});

Deno.test("flash is stored outside the data object", async () => {
  const k = await key();
  const data = { a: 1 };
  const token = seal(data, k, { ...OPTS, flash: { notice: "hi" } });
  assertEquals(unwrap<typeof data>(token, k).data, { a: 1 });
});
