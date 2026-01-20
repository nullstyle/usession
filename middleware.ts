/**
 * Hono middleware for cookie sessions
 */

import type { Context, MiddlewareHandler } from "hono";
import {
  clearCookie,
  type CookieOptions,
  parseCookieHeader,
  type SameSite,
  serializeCookie,
} from "./cookie.ts";
import { deriveKey, seal, unseal } from "./seal.ts";
import { type ISession, Session } from "./session.ts";

const SESSION_KEY = "session";

export type SessionOptions<T extends Record<string, unknown>> = {
  secret: string;
  cookieName: string;
  purpose?: string;
  ttlSeconds?: number | null;
  rolling?: boolean;
  clockSkewSeconds?: number;
  maxCookieBytes?: number;
  bindHost?: boolean;
  cookie?: CookieOptions;
  trustProxy?: boolean;
  onInvalidCookie?: "ignore" | "clear";
};

type ResolvedOptions<T extends Record<string, unknown>> = Required<
  Omit<SessionOptions<T>, "cookie">
> & {
  cookie: Required<Omit<CookieOptions, "maxAge" | "expires" | "domain">> & {
    domain?: string;
  };
};

function resolveOptions<T extends Record<string, unknown>>(
  opts: SessionOptions<T>,
): ResolvedOptions<T> {
  return {
    secret: opts.secret,
    cookieName: opts.cookieName,
    purpose: opts.purpose ?? "session",
    ttlSeconds: opts.ttlSeconds ?? 60 * 60 * 24 * 7, // 7 days default
    rolling: opts.rolling ?? false,
    clockSkewSeconds: opts.clockSkewSeconds ?? 60,
    maxCookieBytes: opts.maxCookieBytes ?? 4096 * 2,
    bindHost: opts.bindHost ?? false,
    trustProxy: opts.trustProxy ?? false,
    onInvalidCookie: opts.onInvalidCookie ?? "clear",
    cookie: {
      path: opts.cookie?.path ?? "/",
      domain: opts.cookie?.domain,
      httpOnly: opts.cookie?.httpOnly ?? true,
      secure: opts.cookie?.secure ?? "auto",
      sameSite: (opts.cookie?.sameSite ?? "Lax") as SameSite,
      partitioned: opts.cookie?.partitioned ?? false,
    },
  };
}

function isSecureRequest(c: Context, trustProxy: boolean): boolean {
  const url = new URL(c.req.url);
  if (url.protocol === "https:") return true;

  if (trustProxy) {
    const proto = c.req.header("x-forwarded-proto");
    if (proto === "https") return true;
  }

  return false;
}

function getHost(c: Context, trustProxy: boolean): string {
  if (trustProxy) {
    const forwardedHost = c.req.header("x-forwarded-host");
    if (forwardedHost) return forwardedHost;
  }
  return c.req.header("host") ?? "";
}

/**
 * Create cookie session middleware
 */
export function cookieSession<T extends Record<string, unknown>>(
  opts: SessionOptions<T>,
): MiddlewareHandler {
  const resolved = resolveOptions(opts);

  if (!resolved.secret) {
    throw new Error("cookieSession: secret is required");
  }

  // Key derivation is async, so we cache the promise
  let keyPromise: Promise<Uint8Array> | null = null;

  async function getKey(): Promise<Uint8Array> {
    if (!keyPromise) {
      keyPromise = deriveKey(resolved.secret, resolved.purpose);
    }
    return keyPromise;
  }

  return async (c, next) => {
    const keyBytes = await getKey();
    const cookieHeader = c.req.header("cookie") ?? null;
    const cookies = parseCookieHeader(cookieHeader);
    const cookieValue = cookies[resolved.cookieName];

    let session: Session<T>;
    let shouldClearOnInvalid = false;

    if (!cookieValue) {
      // No cookie, create new session
      session = new Session<T>({} as T, { isNew: true });
    } else if (cookieValue.length > resolved.maxCookieBytes) {
      // Cookie too large
      session = new Session<T>({} as T, { isNew: true });
      if (resolved.onInvalidCookie === "clear") {
        shouldClearOnInvalid = true;
      }
    } else {
      // Attempt to unseal
      const host = resolved.bindHost ? getHost(c, resolved.trustProxy) : undefined;
      const result = unseal<T>(cookieValue, keyBytes, {
        cookieName: resolved.cookieName,
        purpose: resolved.purpose,
        host,
        clockSkewSeconds: resolved.clockSkewSeconds,
      });

      if (result.ok) {
        session = new Session<T>(result.payload.data, { isNew: false });

        // Rolling expiry: touch the session to trigger re-seal
        if (resolved.rolling && resolved.ttlSeconds != null) {
          session.touch();
        }
      } else {
        // Invalid cookie
        session = new Session<T>({} as T, { isNew: true });
        if (resolved.onInvalidCookie === "clear") {
          shouldClearOnInvalid = true;
        }
      }
    }

    // Attach session to context
    c.set(SESSION_KEY, session);

    // Continue with request handling
    await next();

    // After handler: commit session if needed
    const isSecure = isSecureRequest(c, resolved.trustProxy);
    const cookieOpts: CookieOptions = {
      path: resolved.cookie.path,
      domain: resolved.cookie.domain,
      httpOnly: resolved.cookie.httpOnly,
      secure: resolved.cookie.secure === "auto" ? isSecure : resolved.cookie.secure,
      sameSite: resolved.cookie.sameSite,
      partitioned: resolved.cookie.partitioned,
    };

    if (session.isDestroyed || shouldClearOnInvalid) {
      // Clear the cookie
      const clearStr = clearCookie(resolved.cookieName, cookieOpts);
      c.res.headers.append("Set-Cookie", clearStr);
    } else if (session.isDirty) {
      // Seal and set cookie
      const host = resolved.bindHost ? getHost(c, resolved.trustProxy) : undefined;
      const token = seal(session.data, keyBytes, {
        cookieName: resolved.cookieName,
        purpose: resolved.purpose,
        host,
        ttlSeconds: resolved.ttlSeconds,
      });

      const setCookieOpts: CookieOptions = {
        ...cookieOpts,
        ...(resolved.ttlSeconds != null ? { maxAge: resolved.ttlSeconds } : {}),
      };

      const cookieStr = serializeCookie(resolved.cookieName, token, setCookieOpts);
      c.res.headers.append("Set-Cookie", cookieStr);
    }
  };
}

/**
 * Get the session from context
 */
export function getSession<T extends Record<string, unknown>>(
  c: Context,
): ISession<T> {
  const session = c.get(SESSION_KEY);
  if (!session) {
    throw new Error("Session not found. Did you forget to use cookieSession middleware?");
  }
  return session as ISession<T>;
}
