/**
 * Seal/unseal core using TweetNaCl secretbox (XSalsa20-Poly1305)
 */

import { decodeBase64Url, encodeBase64Url } from "@std/encoding/base64url";
import nacl from "tweetnacl";

const TOKEN_VERSION = "v1";
const NONCE_LENGTH = 24;

/**
 * Context bound inside encrypted payload for validation
 */
export type SealContext = {
  v: 1;
  cookieName: string;
  purpose: string;
  host?: string;
};

/**
 * Full payload structure stored in the sealed cookie
 */
export type SealedPayload<T> = {
  ctx: SealContext;
  iat: number; // unix seconds
  exp?: number; // unix seconds, omitted for session cookies
  data: T;
};

export type SealOptions = {
  cookieName: string;
  purpose: string;
  host?: string;
  ttlSeconds?: number | null;
};

export type UnsealOptions = {
  cookieName: string;
  purpose: string;
  host?: string;
  clockSkewSeconds?: number;
};

/**
 * Derive a 32-byte key from SESSION_SECRET using SHA-256
 */
export async function deriveKey(
  secret: string,
  purpose: string,
): Promise<Uint8Array> {
  const encoder = new TextEncoder();
  const input = encoder.encode(
    `hono-cookie-session/v1|${purpose}|${secret}`,
  );
  const hashBuffer = await crypto.subtle.digest("SHA-256", input);
  return new Uint8Array(hashBuffer);
}

/**
 * Seal data into an encrypted token string
 *
 * Format: v1.<nonce_b64u>.<box_b64u>
 */
export function seal<T>(
  data: T,
  keyBytes: Uint8Array,
  opts: SealOptions,
): string {
  const now = Math.floor(Date.now() / 1000);

  const payload: SealedPayload<T> = {
    ctx: {
      v: 1,
      cookieName: opts.cookieName,
      purpose: opts.purpose,
      ...(opts.host ? { host: opts.host } : {}),
    },
    iat: now,
    ...(opts.ttlSeconds != null ? { exp: now + opts.ttlSeconds } : {}),
    data,
  };

  const encoder = new TextEncoder();
  const plaintext = encoder.encode(JSON.stringify(payload));

  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LENGTH));
  const box = nacl.secretbox(plaintext, nonce, keyBytes);

  return `${TOKEN_VERSION}.${encodeBase64Url(nonce)}.${encodeBase64Url(box)}`;
}

export type UnsealResult<T> =
  | { ok: true; payload: SealedPayload<T> }
  | { ok: false; error: string };

/**
 * Unseal and validate a token string
 */
export function unseal<T>(
  token: string,
  keyBytes: Uint8Array,
  opts: UnsealOptions,
): UnsealResult<T> {
  const clockSkew = opts.clockSkewSeconds ?? 60;

  // Parse token segments
  const parts = token.split(".");
  if (parts.length !== 3) {
    return { ok: false, error: "Invalid token format: expected 3 segments" };
  }

  const [version, nonceB64, boxB64] = parts;

  if (version !== TOKEN_VERSION) {
    return { ok: false, error: `Unsupported token version: ${version}` };
  }

  // Decode base64url
  let nonce: Uint8Array;
  let box: Uint8Array;
  try {
    nonce = decodeBase64Url(nonceB64);
    box = decodeBase64Url(boxB64);
  } catch (e) {
    return {
      ok: false,
      error: `Invalid base64url encoding: ${(e as Error).message}`,
    };
  }

  if (nonce.length !== NONCE_LENGTH) {
    return { ok: false, error: `Invalid nonce length: ${nonce.length}` };
  }

  // Decrypt
  const plaintext = nacl.secretbox.open(box, nonce, keyBytes);
  if (plaintext === null) {
    return { ok: false, error: "Decryption failed: invalid key or tampered" };
  }

  // Parse JSON
  let payload: SealedPayload<T>;
  try {
    const decoder = new TextDecoder();
    payload = JSON.parse(decoder.decode(plaintext));
  } catch {
    return { ok: false, error: "Invalid JSON payload" };
  }

  // Validate context
  if (payload.ctx?.v !== 1) {
    return { ok: false, error: "Invalid context version" };
  }
  if (payload.ctx.cookieName !== opts.cookieName) {
    return {
      ok: false,
      error: `Cookie name mismatch: ${payload.ctx.cookieName} vs ${opts.cookieName}`,
    };
  }
  if (payload.ctx.purpose !== opts.purpose) {
    return {
      ok: false,
      error: `Purpose mismatch: ${payload.ctx.purpose} vs ${opts.purpose}`,
    };
  }
  if (opts.host !== undefined && payload.ctx.host !== opts.host) {
    return {
      ok: false,
      error: `Host mismatch: ${payload.ctx.host} vs ${opts.host}`,
    };
  }

  // Validate expiry
  if (payload.exp !== undefined) {
    const now = Math.floor(Date.now() / 1000);
    if (now > payload.exp + clockSkew) {
      return { ok: false, error: "Token expired" };
    }
  }

  return { ok: true, payload };
}
