import {
  clearCookie,
  type CookieOptions,
  parseCookieHeader,
  type SameSite,
  serializeCookie,
} from "./cookie.ts";
import { deriveKey, seal, unseal } from "./seal.ts";
import { Session } from "./session.ts";

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

function isSecureRequest(req: Request, trustProxy: boolean): boolean {
  const url = new URL(req.url);
  if (url.protocol === "https:") return true;

  if (trustProxy) {
    const proto = req.headers.get("x-forwarded-proto");
    if (proto === "https") return true;
  }

  return false;
}

function getHost(req: Request, trustProxy: boolean): string {
  if (trustProxy) {
    const forwardedHost = req.headers.get("x-forwarded-host");
    if (forwardedHost) return forwardedHost;
  }
  return req.headers.get("host") ?? "";
}

export class SessionManager<T extends Record<string, unknown>> {
  private resolved: ResolvedOptions<T>;
  private keyPromise: Promise<Uint8Array> | null = null;

  constructor(options: SessionOptions<T>) {
    this.resolved = resolveOptions(options);
    if (!this.resolved.secret) {
      throw new Error("SessionManager: secret is required");
    }
  }

  private getKey(): Promise<Uint8Array> {
    if (!this.keyPromise) {
      this.keyPromise = deriveKey(this.resolved.secret, this.resolved.purpose);
    }
    return this.keyPromise;
  }

  async load(req: Request): Promise<Session<T>> {
    const keyBytes = await this.getKey();
    const cookieHeader = req.headers.get("cookie");
    const cookies = parseCookieHeader(cookieHeader);
    const cookieValue = cookies[this.resolved.cookieName];

    if (!cookieValue) {
      return new Session<T>({} as T, { isNew: true });
    }

    if (cookieValue.length > this.resolved.maxCookieBytes) {
      return new Session<T>({} as T, { isNew: true, isInvalid: true });
    }

    const host = this.resolved.bindHost
      ? getHost(req, this.resolved.trustProxy)
      : undefined;
      
    const result = unseal<T>(cookieValue, keyBytes, {
      cookieName: this.resolved.cookieName,
      purpose: this.resolved.purpose,
      host,
      clockSkewSeconds: this.resolved.clockSkewSeconds,
    });

    if (result.ok) {
      const session = new Session<T>(result.payload.data, { isNew: false });
      if (this.resolved.rolling && this.resolved.ttlSeconds != null) {
        session.touch();
      }
      return session;
    }

    return new Session<T>({} as T, { isNew: true, isInvalid: true });
  }

  /**
   * Generates the Set-Cookie header value if the session needs to be saved or cleared.
   * Returns null if no cookie header needs to be set.
   */
  async persist(session: Session<T>, req: Request): Promise<string | null> {
    const isSecure = isSecureRequest(req, this.resolved.trustProxy);
    const cookieOpts: CookieOptions = {
      path: this.resolved.cookie.path,
      domain: this.resolved.cookie.domain,
      httpOnly: this.resolved.cookie.httpOnly,
      secure: this.resolved.cookie.secure === "auto"
        ? isSecure
        : this.resolved.cookie.secure,
      sameSite: this.resolved.cookie.sameSite,
      partitioned: this.resolved.cookie.partitioned,
    };

    // Determine if we need to clear on invalid cookie from load time?
    // Actually, `load` doesn't return whether the cookie was invalid, it just returns a new session.
    // If we want to support `onInvalidCookie: "clear"`, we need to know if the previous cookie was invalid.
    // Use case: Browser sends bad cookie -> `load` returns new Session -> `persist` sees new session.
    // If the session is empty and new, do we clear?
    // If the session was modified, we set a new one, which overwrites the bad one.
    // If the session was NOT modified, we might leave the bad cookie there?
    // The original middleware tracked `shouldClearOnInvalid`.
    
    // To support `onInvalidCookie: "clear"`, we might need `load` to return more info or handle it.
    // But `persist` is called at the end.
    // If the session is dirty, we overwrite.
    // If the session is NOT dirty and NOT destroyed, we usually do nothing.
    // But if there was a bad cookie, we should probably clear it if configured.

    // Let's check how we can handle this.
    // Maybe `load` should check for invalidity?
    // But `load` returns a Session object.
    
    // Simplified logic:
    // If session is destroyed -> clear.
    // If session is dirty -> set.
    // If session is new (and empty?) and we had a bad cookie... we don't know if we had a bad cookie here.
    
    // If strict feature parity is needed for `onInvalidCookie`, we need to track it.
    // Maybe `Session` needs a flag? Or `load` returns a tuple?
    // Let's stick to standard behavior first.
    // If we overwrite (dirty), the bad cookie is gone.
    // If we destroy, it's gone.
    // If we do nothing, the bad cookie stays. This might be annoying if it causes errors on every request.
    // But since we successfully ignored it in `load`, it's just dead weight.
    
    // However, if the user modifies the session, it becomes dirty.
    
    if (session.isDestroyed) {
      return clearCookie(this.resolved.cookieName, cookieOpts);
    }

    if (session.isDirty) {
      const keyBytes = await this.getKey();
      const host = this.resolved.bindHost
        ? getHost(req, this.resolved.trustProxy)
        : undefined;
        
      const token = seal(session.data, keyBytes, {
        cookieName: this.resolved.cookieName,
        purpose: this.resolved.purpose,
        host,
        ttlSeconds: this.resolved.ttlSeconds,
      });

      const setCookieOpts: CookieOptions = {
        ...cookieOpts,
        ...(this.resolved.ttlSeconds != null
          ? { maxAge: this.resolved.ttlSeconds }
          : {}),
      };

      return serializeCookie(this.resolved.cookieName, token, setCookieOpts);
    }

    if (session.isInvalid && this.resolved.onInvalidCookie === "clear") {
      return clearCookie(this.resolved.cookieName, cookieOpts);
    }

    return null;
  }
}
