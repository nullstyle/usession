import { assertEquals } from "jsr:@std/assert";
import { deriveKey, seal, unseal } from "./seal.ts";
import nacl from "tweetnacl";
import { encodeBase64Url } from "@std/encoding/base64url";

const KEY = await deriveKey("test-secret", "session");

Deno.test("deriveKey produces 32-byte key", async () => {
  const key = await deriveKey("secret", "purpose");
  assertEquals(key.length, 32);
});

Deno.test("seal/unseal basic roundtrip", () => {
  const data = { foo: "bar" };
  const token = seal(data, KEY, { cookieName: "c", purpose: "p" });
  const result = unseal(token, KEY, { cookieName: "c", purpose: "p" });
  
  if (!result.ok) throw new Error(result.error);
  assertEquals(result.payload.data, data);
});

Deno.test("unseal fails: invalid token format", () => {
  const result = unseal("garbage", KEY, { cookieName: "c", purpose: "p" });
  assertEquals(result.ok, false);
  if (!result.ok) assertEquals(result.error.includes("expected 3 segments"), true);
});

Deno.test("unseal fails: wrong version", () => {
  const result = unseal("v2.nonce.box", KEY, { cookieName: "c", purpose: "p" });
  assertEquals(result.ok, false);
  if (!result.ok) assertEquals(result.error.includes("Unsupported token version"), true);
});

Deno.test("unseal fails: invalid base64", () => {
  const result = unseal("v1.bad+base64.box", KEY, { cookieName: "c", purpose: "p" });
  assertEquals(result.ok, false);
  if (!result.ok) assertEquals(result.error.includes("Invalid base64url"), true);
});

Deno.test("unseal fails: invalid nonce length", () => {
    // 24 bytes = 32 base64 chars approx.
    const shortNonce = encodeBase64Url(new Uint8Array(10));
    const token = `v1.${shortNonce}.box`;
    const result = unseal(token, KEY, { cookieName: "c", purpose: "p" });
    assertEquals(result.ok, false);
    if (!result.ok) assertEquals(result.error.includes("Invalid nonce length"), true);
});

Deno.test("unseal fails: decryption failed", () => {
    // valid format, but random box
    const nonce = encodeBase64Url(new Uint8Array(24));
    const box = encodeBase64Url(new Uint8Array(100)); // random junk
    const token = `v1.${nonce}.${box}`;
    const result = unseal(token, KEY, { cookieName: "c", purpose: "p" });
    assertEquals(result.ok, false);
    if (!result.ok) assertEquals(result.error.includes("Decryption failed"), true);
});

Deno.test("unseal fails: invalid JSON payload", () => {
    // We need to encrypt invalid JSON manually
    const nonce = new Uint8Array(24);
    const box = nacl.secretbox(new TextEncoder().encode("not json"), nonce, KEY);
    const token = `v1.${encodeBase64Url(nonce)}.${encodeBase64Url(box)}`;
    
    const result = unseal(token, KEY, { cookieName: "c", purpose: "p" });
    assertEquals(result.ok, false);
    if (!result.ok) assertEquals(result.error, "Invalid JSON payload");
});

Deno.test("unseal fails: context version mismatch", () => {
     // Encrypt payload with v: 2
     const payload = { ctx: { v: 2, cookieName: "c", purpose: "p" }, data: {} };
     const nonce = new Uint8Array(24);
     const box = nacl.secretbox(new TextEncoder().encode(JSON.stringify(payload)), nonce, KEY);
     const token = `v1.${encodeBase64Url(nonce)}.${encodeBase64Url(box)}`;
     
     const result = unseal(token, KEY, { cookieName: "c", purpose: "p" });
     assertEquals(result.ok, false);
     if (!result.ok) assertEquals(result.error, "Invalid context version");
});

Deno.test("unseal fails: cookie name mismatch", () => {
    const token = seal({}, KEY, { cookieName: "wrong", purpose: "p" });
    const result = unseal(token, KEY, { cookieName: "c", purpose: "p" });
    assertEquals(result.ok, false);
    if (!result.ok) assertEquals(result.error.includes("Cookie name mismatch"), true);
});

Deno.test("unseal fails: purpose mismatch", () => {
    const token = seal({}, KEY, { cookieName: "c", purpose: "wrong" });
    const result = unseal(token, KEY, { cookieName: "c", purpose: "p" });
    assertEquals(result.ok, false);
    if (!result.ok) assertEquals(result.error.includes("Purpose mismatch"), true);
});

Deno.test("unseal fails: host mismatch", () => {
    const token = seal({}, KEY, { cookieName: "c", purpose: "p", host: "foo.com" });
    const result = unseal(token, KEY, { cookieName: "c", purpose: "p", host: "bar.com" });
    assertEquals(result.ok, false);
    if (!result.ok) assertEquals(result.error.includes("Host mismatch"), true);
});

Deno.test("unseal fails: expired", () => {
    // ttl = -10
    const token = seal({}, KEY, { cookieName: "c", purpose: "p", ttlSeconds: -10 });
    const result = unseal(token, KEY, { cookieName: "c", purpose: "p", clockSkewSeconds: 0 });
    assertEquals(result.ok, false);
    if (!result.ok) assertEquals(result.error, "Token expired");
});

Deno.test("unseal succeeds: clock skew allows expired", () => {
    const token = seal({}, KEY, { cookieName: "c", purpose: "p", ttlSeconds: -10 });
    // allow 20s skew
    const result = unseal(token, KEY, { cookieName: "c", purpose: "p", clockSkewSeconds: 20 });
    assertEquals(result.ok, true);
});
