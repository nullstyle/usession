/**
 * Seal/unseal core using TweetNaCl secretbox (XSalsa20-Poly1305).
 *
 * A token is `v2.<nonce_b64u>.<box_b64u>`, where the box is the authenticated
 * encryption of a JSON {@linkcode SealedPayload}. Everything that matters —
 * including the binding context and the expiry — lives *inside* the box, so it
 * is all covered by the Poly1305 tag.
 *
 * @module
 */

import { decodeBase64Url, encodeBase64Url } from "@std/encoding/base64url";
import nacl from "tweetnacl";

/** Wire format version. Bumped whenever the token layout or KDF changes. */
const TOKEN_VERSION = "v2";

/** XSalsa20-Poly1305 nonce length, in bytes. */
const NONCE_LENGTH = 24;

/**
 * HKDF domain-separation label.
 *
 * Changing this value invalidates every outstanding token, because it is mixed
 * into the derived key. Treat it as part of the wire format.
 */
const KDF_LABEL = "usession/v2";

/** Minimum accepted key material, in bytes. */
export const MIN_SECRET_BYTES = 32;

/**
 * Key material for {@linkcode deriveKey}.
 *
 * Prefer a `Uint8Array` of at least {@linkcode MIN_SECRET_BYTES} random bytes.
 * A string is accepted for convenience and is treated as UTF-8 input keying
 * material — it must carry real entropy, since HKDF adds domain separation but
 * no work factor.
 */
export type Secret = string | Uint8Array;

/**
 * Context bound inside the encrypted payload and re-checked on unseal.
 *
 * This is defense in depth: `purpose` already changes the derived key, so a
 * mismatch normally fails at decryption. The explicit check also covers callers
 * who use the exported {@linkcode seal}/{@linkcode unseal} directly with a key
 * they derived themselves.
 */
export type SealContext = {
  /** Payload schema version. */
  v: 2;
  /** Cookie the token was minted for. */
  cookieName: string;
  /** Key-separation label. */
  purpose: string;
  /** Host the token is bound to, when host binding is enabled. */
  host?: string;
};

/** Full payload structure stored inside the sealed cookie. */
export type SealedPayload<T> = {
  /** Binding context, validated on unseal. */
  ctx: SealContext;
  /** Issued-at, unix seconds. Restamped on every re-seal. */
  iat: number;
  /**
   * Session birth time, unix seconds. Unlike {@linkcode SealedPayload.iat} this
   * is carried forward across re-seals, so an absolute lifetime cap survives
   * rolling expiry.
   */
  iat0?: number;
  /** Expiry, unix seconds. Omitted for browser-session cookies. */
  exp?: number;
  /** Application data. */
  data: T;
  /**
   * Flash messages, held beside {@linkcode SealedPayload.data} rather than
   * inside it so the library never squats on an application key.
   */
  flash?: Record<string, string>;
};

/** Options for {@linkcode seal}. */
export type SealOptions = {
  /** Cookie name to bind into the payload. */
  cookieName: string;
  /** Key-separation label to bind into the payload. */
  purpose: string;
  /** Host to bind into the payload, when host binding is enabled. */
  host?: string;
  /** Lifetime in seconds. `null` mints a browser-session token with no `exp`. */
  ttlSeconds?: number | null;
  /** Session birth time to carry forward. Defaults to now. */
  iat0?: number;
  /** Flash messages to carry. */
  flash?: Record<string, string>;
};

/** Options for {@linkcode unseal}. */
export type UnsealOptions = {
  /** Cookie name the token must have been minted for. */
  cookieName: string;
  /** Key-separation label the token must have been minted for. */
  purpose: string;
  /** Host the token must be bound to. Omit to skip the host check. */
  host?: string;
  /** Tolerance applied to the expiry check, in seconds. Defaults to 60. */
  clockSkewSeconds?: number;
  /**
   * Absolute lifetime cap measured from {@linkcode SealedPayload.iat0}, in
   * seconds. Rejects sessions older than this regardless of rolling expiry.
   */
  maxSessionAgeSeconds?: number | null;
};

/**
 * Length-prefixed HKDF `info`, so that domain separation is injective.
 *
 * Naive `label + "|" + purpose` framing is ambiguous: a `purpose` containing the
 * delimiter can collide with a different label/purpose pair and silently reuse a
 * key across contexts.
 */
function kdfInfo(purpose: string): Uint8Array<ArrayBuffer> {
  const encoder = new TextEncoder();
  const label = encoder.encode(KDF_LABEL);
  const scope = encoder.encode(purpose);

  const info = new Uint8Array(4 + label.length + 4 + scope.length);
  const view = new DataView(info.buffer);

  view.setUint32(0, label.length);
  info.set(label, 4);
  view.setUint32(4 + label.length, scope.length);
  info.set(scope, 8 + label.length);

  return info;
}

/**
 * Derive a 32-byte secretbox key from a secret, separated by `purpose`.
 *
 * Uses HKDF-SHA256. Two managers sharing a secret but using different purposes
 * get unrelated keys, so a token from one is not merely rejected by the other —
 * it cannot be decrypted at all.
 *
 * @param secret Key material. See {@linkcode Secret}.
 * @param purpose Key-separation label.
 * @returns A 32-byte key suitable for {@linkcode seal} and {@linkcode unseal}.
 * @throws {TypeError} If the secret is shorter than {@linkcode MIN_SECRET_BYTES}.
 */
export async function deriveKey(
  secret: Secret,
  purpose: string,
): Promise<Uint8Array> {
  // Reject anything that is not genuinely a string or Uint8Array. Without this,
  // a value that slipped past the type checker (a JS caller, a number parsed
  // out of config) would hit `new Uint8Array(n)` and silently become n ZERO
  // bytes — key material an attacker can reproduce exactly.
  if (typeof secret !== "string" && !(secret instanceof Uint8Array)) {
    throw new TypeError(
      `usession: secret must be a string or Uint8Array, got ` +
        `${secret === null ? "null" : typeof secret}`,
    );
  }

  // `purpose` is the domain-separation input. A non-string would be coerced by
  // TextEncoder — every object collapsing to "[object Object]" — silently
  // collapsing distinct purposes onto one key.
  if (typeof purpose !== "string") {
    throw new TypeError(
      `usession: purpose must be a string, got ` +
        `${purpose === null ? "null" : typeof purpose}`,
    );
  }

  // Copy into a fresh ArrayBuffer: WebCrypto's BufferSource rejects a view
  // that might be backed by a SharedArrayBuffer.
  const ikm: Uint8Array<ArrayBuffer> = typeof secret === "string"
    ? new TextEncoder().encode(secret)
    : new Uint8Array(secret);

  if (ikm.length < MIN_SECRET_BYTES) {
    throw new TypeError(
      `usession: secret must be at least ${MIN_SECRET_BYTES} bytes ` +
        `(got ${ikm.length}); generate one with: openssl rand -base64 32`,
    );
  }

  const key = await crypto.subtle.importKey("raw", ikm, "HKDF", false, [
    "deriveBits",
  ]);

  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(0),
      info: kdfInfo(purpose),
    },
    key,
    256,
  );

  return new Uint8Array(bits);
}

/**
 * Seal data into an encrypted token string.
 *
 * @param data Application data to encrypt.
 * @param keyBytes A 32-byte key from {@linkcode deriveKey}.
 * @param opts Binding context and lifetime.
 * @returns A token of the form `v2.<nonce_b64u>.<box_b64u>`.
 */
export function seal<T>(
  data: T,
  keyBytes: Uint8Array,
  opts: SealOptions,
): string {
  const now = Math.floor(Date.now() / 1000);

  const payload: SealedPayload<T> = {
    ctx: {
      v: 2,
      cookieName: opts.cookieName,
      purpose: opts.purpose,
      // Bind an empty host too — `unseal` compares against `undefined`, so
      // dropping a falsy host here would make the token unverifiable.
      ...(opts.host !== undefined ? { host: opts.host } : {}),
    },
    iat: now,
    iat0: opts.iat0 ?? now,
    ...(opts.ttlSeconds != null ? { exp: now + opts.ttlSeconds } : {}),
    data,
    ...(opts.flash && Object.keys(opts.flash).length > 0
      ? { flash: opts.flash }
      : {}),
  };

  const plaintext = new TextEncoder().encode(JSON.stringify(payload));
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LENGTH));
  const box = nacl.secretbox(plaintext, nonce, keyBytes);

  return `${TOKEN_VERSION}.${encodeBase64Url(nonce)}.${encodeBase64Url(box)}`;
}

/** Result of {@linkcode unseal}. Never throws; inspect `ok`. */
export type UnsealResult<T> =
  | { ok: true; payload: SealedPayload<T> }
  | { ok: false; error: string };

/**
 * Unseal and validate a token string.
 *
 * Never throws — every failure is reported as `{ ok: false, error }` with a
 * distinct, loggable reason.
 *
 * @param token A token produced by {@linkcode seal}.
 * @param keyBytes A 32-byte key from {@linkcode deriveKey}.
 * @param opts Expected binding context and validation tolerances.
 */
export function unseal<T>(
  token: string,
  keyBytes: Uint8Array,
  opts: UnsealOptions,
): UnsealResult<T> {
  const clockSkew = opts.clockSkewSeconds ?? 60;

  const parts = token.split(".");
  if (parts.length !== 3) {
    return { ok: false, error: "Invalid token format: expected 3 segments" };
  }

  const [version, nonceB64, boxB64] = parts;

  if (version !== TOKEN_VERSION) {
    return { ok: false, error: `Unsupported token version: ${version}` };
  }

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

  // tweetnacl throws on a wrong-sized key rather than returning null, and this
  // function promises never to throw.
  let plaintext: Uint8Array | null;
  try {
    plaintext = nacl.secretbox.open(box, nonce, keyBytes);
  } catch (e) {
    return { ok: false, error: `Decryption failed: ${(e as Error).message}` };
  }
  if (plaintext === null) {
    return { ok: false, error: "Decryption failed: invalid key or tampered" };
  }

  let payload: SealedPayload<T>;
  try {
    payload = JSON.parse(new TextDecoder().decode(plaintext));
  } catch {
    return { ok: false, error: "Invalid JSON payload" };
  }

  // `JSON.parse` happily yields `null`, `42` or `"str"`. Guard before
  // dereferencing, so this stays a Result rather than throwing.
  if (typeof payload !== "object" || payload === null) {
    return { ok: false, error: "Invalid payload shape: expected an object" };
  }

  if (payload.ctx?.v !== 2) {
    return { ok: false, error: "Invalid context version" };
  }
  if (payload.ctx.cookieName !== opts.cookieName) {
    return {
      ok: false,
      error:
        `Cookie name mismatch: ${payload.ctx.cookieName} vs ${opts.cookieName}`,
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

  const now = Math.floor(Date.now() / 1000);

  if (payload.exp !== undefined) {
    if (typeof payload.exp !== "number" || !Number.isFinite(payload.exp)) {
      return { ok: false, error: "Invalid exp claim" };
    }
    if (now > payload.exp + clockSkew) {
      return { ok: false, error: "Token expired" };
    }
  }

  // Absolute cap, measured from the immutable birth timestamp so that rolling
  // expiry cannot extend a session indefinitely.
  if (opts.maxSessionAgeSeconds != null && payload.iat0 !== undefined) {
    if (typeof payload.iat0 !== "number" || !Number.isFinite(payload.iat0)) {
      return { ok: false, error: "Invalid iat0 claim" };
    }
    if (now > payload.iat0 + opts.maxSessionAgeSeconds + clockSkew) {
      return { ok: false, error: "Session exceeded maximum age" };
    }
  }

  return { ok: true, payload };
}
