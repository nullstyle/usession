/**
 * The request-facing session manager.
 *
 * @module
 */

import {
  clearCookie,
  type CookieOptions,
  parseCookieHeaderAll,
  serializeCookie,
  type SessionCookieOptions,
} from "./cookie.ts";
import {
  deriveKey,
  MIN_SECRET_BYTES,
  seal,
  type Secret,
  unseal,
} from "./seal.ts";
import {
  type DefaultSessionData,
  type EpochState,
  type ISession,
  Session,
} from "./session.ts";
import {
  applicableTracks,
  assertValidTracks,
  type EpochContext,
  type EpochErrorAction,
  type EpochErrorInfo,
  type EpochTrack,
  EpochUnavailable,
  resolveEpoch,
} from "./epoch.ts";

/** Default session lifetime: 7 days. */
const DEFAULT_TTL_SECONDS = 60 * 60 * 24 * 7;

/**
 * The largest `name=value` a browser will store, per RFC 6265bis.
 *
 * Used both as the default read-side rejection threshold and as the write-side
 * warning threshold.
 */
const BROWSER_COOKIE_LIMIT = 4096;

/**
 * The reason `unseal` gives when a key simply does not match.
 *
 * Trying several keys during rotation produces this for every non-matching one,
 * so it is treated as the least informative diagnosis.
 */
const GENERIC_DECRYPT_ERROR = "Decryption failed: invalid key or tampered";

/** Context describing why a presented cookie was rejected. */
export type InvalidCookieInfo = {
  /** Diagnostic reason, e.g. `"Token expired"`. */
  reason: string;
  /** Cookie that was rejected. */
  cookieName: string;
  /** The request the cookie arrived on. */
  request: Request | undefined;
};

/** Context describing a cookie too large for browsers to store. */
export type OversizeCookieInfo = {
  /** Byte length of the `name=value` pair. */
  bytes: number;
  /** Threshold that was exceeded. */
  limit: number;
  /** Cookie that was too large. */
  cookieName: string;
};

/** Options for {@linkcode SessionManager}. */
export type SessionOptions<T extends object = DefaultSessionData> = {
  /**
   * Key material, or an ordered list for rotation.
   *
   * With a list, element 0 seals and every element is tried on unseal, so you
   * can roll a secret without logging everyone out: deploy `[next, current]`,
   * wait one full `ttlSeconds`, then deploy `[next]`. Sessions that unseal
   * under a non-primary key are re-issued under the primary one automatically.
   *
   * Must be at least 32 bytes. Generate one with `openssl rand -base64 32`.
   */
  secret: Secret | Secret[];
  /**
   * Cookie name.
   *
   * Prefer a `__Host-` prefix in production; its invariants (`Secure`, `Path=/`,
   * no `Domain`) are enforced by the constructor.
   */
  cookieName: string;
  /**
   * Key-separation label. Defaults to `"session"`.
   *
   * Two services sharing a secret **must** use different purposes, or each will
   * accept the other's tokens.
   */
  purpose?: string;
  /**
   * Lifetime in seconds, or `null` for a browser-session cookie that carries no
   * `Max-Age` and no `exp`. Defaults to 7 days.
   */
  ttlSeconds?: number | null;
  /**
   * Refresh the expiry on every request. Defaults to `false`.
   *
   * This re-issues the cookie on every request, so pair it with
   * {@linkcode SessionOptions.maxSessionAgeSeconds} unless you intend sessions
   * to live indefinitely.
   */
  rolling?: boolean;
  /**
   * Absolute lifetime cap in seconds, measured from when the session was first
   * created and unaffected by rolling expiry. Defaults to `null` (uncapped).
   */
  maxSessionAgeSeconds?: number | null;
  /** Tolerance applied to expiry checks, in seconds. Defaults to 60. */
  clockSkewSeconds?: number;
  /**
   * Largest incoming cookie value to attempt to unseal, in bytes.
   * Defaults to 4096.
   */
  maxCookieBytes?: number;
  /** What to do when an outgoing cookie exceeds the browser limit. */
  onOversize?: "warn" | "throw" | "ignore";
  /** Invoked when a presented cookie is rejected. Wire this to your logs. */
  onInvalid?: (info: InvalidCookieInfo) => void;
  /** Invoked when an outgoing cookie is too large for browsers to store. */
  onOversizeCookie?: (info: OversizeCookieInfo) => void;
  /** Bind the session to the request host. Defaults to `false`. */
  bindHost?: boolean;
  /** Cookie attributes. */
  cookie?: Omit<SessionCookieOptions, "maxAge" | "expires">;
  /**
   * Trust `X-Forwarded-Proto` and `X-Forwarded-Host`. Defaults to `false`.
   *
   * Enable this only behind a proxy that *overwrites* those headers. A proxy
   * that merely appends to them lets a client forge the value.
   */
  trustProxy?: boolean;
  /** Whether to delete a cookie that failed to unseal. Defaults to `"clear"`. */
  onInvalidCookie?: "ignore" | "clear";
  /**
   * Revocation tracks. See {@linkcode EpochTrack}, {@linkcode appEpoch} and
   * {@linkcode userEpoch}.
   *
   * Each track stamps a number into the cookie on write and re-checks it on
   * read, so advancing the number invalidates every session on that track
   * immediately. Sessions written before a track was configured carry no stamp
   * and are rejected, so enabling a track logs out everyone once.
   */
  epochTracks?: EpochTrack<T>[];
  /**
   * What to do when a track's `current()` fails or returns a non-number.
   *
   * Omit to fail closed — the session is rejected, which is safe but means an
   * outage in your epoch store logs everyone out. Return `"allow"` to let the
   * request through with that track unchecked. Throwing from here propagates.
   */
  onEpochError?: (info: EpochErrorInfo) => EpochErrorAction;
};

/** Request facts the manager needs, for the framework-agnostic entry points. */
export type RequestContext = {
  /** Whether the connection is secure, for `secure: "auto"`. */
  secure?: boolean;
  /** Host to bind against, when {@linkcode SessionOptions.bindHost} is set. */
  host?: string;
};

type ResolvedOptions = {
  cookieName: string;
  purpose: string;
  ttlSeconds: number | null;
  rolling: boolean;
  maxSessionAgeSeconds: number | null;
  clockSkewSeconds: number;
  maxCookieBytes: number;
  onOversize: "warn" | "throw" | "ignore";
  onInvalid: ((info: InvalidCookieInfo) => void) | undefined;
  onOversizeCookie: ((info: OversizeCookieInfo) => void) | undefined;
  bindHost: boolean;
  trustProxy: boolean;
  onInvalidCookie: "ignore" | "clear";
  epochTracks: readonly EpochTrack<object>[];
  onEpochError: ((info: EpochErrorInfo) => EpochErrorAction) | undefined;
  cookie:
    & Required<Omit<SessionCookieOptions, "maxAge" | "expires" | "domain">>
    & { domain?: string };
};

/** Take the first value of a possibly comma-joined forwarded header. */
function firstForwarded(value: string | null): string | null {
  if (!value) return null;
  const first = value.split(",")[0].trim().toLowerCase();
  return first || null;
}

function isSecureRequest(req: Request, trustProxy: boolean): boolean {
  if (
    trustProxy &&
    firstForwarded(req.headers.get("x-forwarded-proto")) === "https"
  ) {
    return true;
  }
  return new URL(req.url).protocol === "https:";
}

function getHost(req: Request, trustProxy: boolean): string {
  if (trustProxy) {
    const forwarded = firstForwarded(req.headers.get("x-forwarded-host"));
    if (forwarded) return forwarded;
  }
  const host = req.headers.get("host");
  if (host) return host.split(",")[0].trim().toLowerCase();
  // Hand-built `new Request(url)` objects carry no Host header; fall back to
  // the URL so host binding still round-trips.
  return new URL(req.url).host.toLowerCase();
}

function resolveOptions(opts: SessionOptions<object>): ResolvedOptions {
  const ttlSeconds = opts.ttlSeconds === undefined
    ? DEFAULT_TTL_SECONDS
    : opts.ttlSeconds;

  if (
    ttlSeconds !== null && (!Number.isInteger(ttlSeconds) || ttlSeconds <= 0)
  ) {
    throw new TypeError(
      `usession: ttlSeconds must be a positive integer number of seconds or ` +
        `null, got ${ttlSeconds}`,
    );
  }

  const clockSkewSeconds = opts.clockSkewSeconds ?? 60;
  if (!Number.isFinite(clockSkewSeconds) || clockSkewSeconds < 0) {
    throw new TypeError(
      `usession: clockSkewSeconds must be a non-negative finite number, got ` +
        `${clockSkewSeconds}`,
    );
  }

  const maxCookieBytes = opts.maxCookieBytes ?? BROWSER_COOKIE_LIMIT;
  if (!Number.isInteger(maxCookieBytes) || maxCookieBytes <= 0) {
    throw new TypeError(
      `usession: maxCookieBytes must be a positive integer, got ` +
        `${maxCookieBytes}`,
    );
  }

  const path = opts.cookie?.path ?? "/";
  if (!path.startsWith("/")) {
    throw new TypeError(
      `usession: cookie.path must start with "/", got ${JSON.stringify(path)}`,
    );
  }

  const maxSessionAgeSeconds = opts.maxSessionAgeSeconds ?? null;
  if (
    maxSessionAgeSeconds !== null &&
    (!Number.isInteger(maxSessionAgeSeconds) || maxSessionAgeSeconds <= 0)
  ) {
    throw new TypeError(
      `usession: maxSessionAgeSeconds must be a positive integer number of ` +
        `seconds or null, got ${maxSessionAgeSeconds}`,
    );
  }

  const sameSite = opts.cookie?.sameSite ?? "Lax";
  const partitioned = opts.cookie?.partitioned ?? false;

  // `SameSite=None` and `Partitioned` are both rejected by browsers without
  // `Secure`, so force it rather than emitting a cookie that gets dropped.
  const secure = sameSite === "None" || partitioned
    ? true
    : opts.cookie?.secure ?? "auto";

  return {
    cookieName: opts.cookieName,
    purpose: opts.purpose ?? "session",
    ttlSeconds,
    rolling: opts.rolling ?? false,
    maxSessionAgeSeconds,
    clockSkewSeconds,
    maxCookieBytes,
    onOversize: opts.onOversize ?? "warn",
    onInvalid: opts.onInvalid,
    onOversizeCookie: opts.onOversizeCookie,
    bindHost: opts.bindHost ?? false,
    trustProxy: opts.trustProxy ?? false,
    onInvalidCookie: opts.onInvalidCookie ?? "clear",
    epochTracks: opts.epochTracks ?? [],
    onEpochError: opts.onEpochError,
    cookie: {
      path,
      domain: opts.cookie?.domain,
      httpOnly: opts.cookie?.httpOnly ?? true,
      secure,
      sameSite,
      partitioned,
    },
  };
}

/**
 * Enforce the RFC 6265bis cookie-prefix invariants at construction time.
 *
 * Checks the caller's *explicit* `secure`, not the resolved value: with
 * `sameSite: "None"` the resolver forces `secure` to true, which would
 * otherwise swallow a contradictory `secure: false` instead of reporting it.
 */
function assertPrefixInvariants(
  o: ResolvedOptions,
  explicitSecure: boolean | "auto" | undefined,
): void {
  const { cookieName, cookie } = o;
  const isHost = cookieName.startsWith("__Host-");
  const isSecurePrefix = cookieName.startsWith("__Secure-");

  if (!isHost && !isSecurePrefix) return;

  if (explicitSecure === false || cookie.secure === false) {
    throw new Error(
      `usession: cookieName "${cookieName}" requires cookie.secure to be true ` +
        `or "auto"; browsers reject a prefixed cookie without Secure.`,
    );
  }

  if (isHost) {
    if (cookie.domain !== undefined) {
      throw new Error(
        `usession: cookieName "${cookieName}" must not set cookie.domain; ` +
          `__Host- cookies are host-only.`,
      );
    }
    if (cookie.path !== "/") {
      throw new Error(
        `usession: cookieName "${cookieName}" requires cookie.path to be "/", ` +
          `got ${JSON.stringify(cookie.path)}.`,
      );
    }
  }
}

/**
 * Loads and persists sealed cookie sessions.
 *
 * A manager is immutable, holds no per-request state, and is safe to share
 * across concurrent requests. Construct one at module scope.
 *
 * @typeParam T Shape of the application data.
 *
 * @example Loading and persisting
 * ```ts
 * import { SessionManager } from "@nullstyle/usession";
 *
 * type SessionData = { uid?: string };
 *
 * const sessions = new SessionManager<SessionData>({
 *   secret: Deno.env.get("SESSION_SECRET")!,
 *   cookieName: "__Host-session",
 * });
 *
 * const req = new Request("https://example.com/");
 * const session = await sessions.load(req);
 * session.set("uid", "u_123");
 * const response = await sessions.apply(session, req, new Response("ok"));
 * ```
 */
export class SessionManager<T extends object = DefaultSessionData> {
  // ECMAScript private fields, so neither the secret nor the derived keys are
  // reachable through `JSON.stringify`, `Object.keys` or `Deno.inspect`.
  #resolved: ResolvedOptions;
  #secrets: Secret[] | null;
  #keysPromise: Promise<Uint8Array[]> | null = null;

  /**
   * Construct a manager and validate its configuration.
   *
   * Configurations that browsers would silently reject — a `__Host-` cookie
   * with a `Domain`, say — throw here rather than at the first request.
   *
   * @param options See {@linkcode SessionOptions}.
   * @throws {Error} If the options are internally inconsistent.
   * @throws {TypeError} If `secret` is missing, empty or too short.
   */
  constructor(options: SessionOptions<T>) {
    const secrets = Array.isArray(options.secret)
      ? options.secret
      : [options.secret];

    if (secrets.length === 0) {
      throw new TypeError("usession: at least one secret is required");
    }
    // Validate eagerly. Deferring these to the first request would turn a typo
    // in configuration into a 500 on a user's first page view.
    for (const secret of secrets) {
      if (!secret) {
        throw new TypeError(
          "usession: secret is required and must be non-empty",
        );
      }
      if (typeof secret !== "string" && !(secret instanceof Uint8Array)) {
        throw new TypeError(
          `usession: secret must be a string or Uint8Array, got ` +
            `${typeof secret}`,
        );
      }
      const bytes = typeof secret === "string"
        ? new TextEncoder().encode(secret).byteLength
        : secret.byteLength;
      if (bytes < MIN_SECRET_BYTES) {
        throw new TypeError(
          `usession: secret must be at least ${MIN_SECRET_BYTES} bytes ` +
            `(got ${bytes}); generate one with: openssl rand -base64 32`,
        );
      }
    }

    if (!options.cookieName) {
      throw new TypeError("usession: cookieName is required");
    }
    // Reject an illegal cookie name here rather than from serializeCookie on
    // the first response.
    serializeCookie(options.cookieName, "");

    this.#resolved = resolveOptions(options as SessionOptions<object>);
    assertPrefixInvariants(this.#resolved, options.cookie?.secure);
    assertValidTracks(this.#resolved.epochTracks);
    this.#secrets = secrets;
  }

  /** Derive and memoize every accepted key. */
  #getKeys(): Promise<Uint8Array[]> {
    if (!this.#keysPromise) {
      const secrets = this.#secrets;
      if (!secrets) {
        throw new Error("usession: manager secrets are unavailable");
      }
      this.#keysPromise = Promise.all(
        secrets.map((s) => deriveKey(s, this.#resolved.purpose)),
      ).then((keys) => {
        // The plaintext secret is dead once the keys exist; drop the reference
        // so a heap dump or accidental log cannot surface it.
        this.#secrets = null;
        return keys;
      }).catch((e) => {
        // Do not cache the rejection — a transient WebCrypto failure should not
        // permanently poison the manager.
        this.#keysPromise = null;
        throw e;
      });
    }
    return this.#keysPromise;
  }

  /** The host to bind against, or `undefined` when binding is off. */
  #hostFor(
    req: Request | undefined,
    ctx: RequestContext | undefined,
  ): string | undefined {
    if (!this.#resolved.bindHost) return undefined;
    // An empty host is not a host. Binding to "" would silently put every
    // hostless request into one shared session scope.
    if (ctx?.host) return ctx.host.toLowerCase();
    if (req) return getHost(req, this.#resolved.trustProxy);
    throw new Error(
      "usession: bindHost is enabled but no host was supplied. Pass { host } " +
        "in the request context, or use load()/persist() with a Request.",
    );
  }

  #reportInvalid(reason: string, request: Request | undefined): void {
    this.#resolved.onInvalid?.({
      reason,
      cookieName: this.#resolved.cookieName,
      request,
    });
  }

  /**
   * Validate a decrypted payload's revocation epochs.
   *
   * Every applicable track must carry a stamp that is at least the current
   * value. A missing stamp is a rejection: a cookie minted before a track was
   * configured cannot be shown to be un-revoked, so enabling a track logs
   * everyone out exactly once.
   *
   * Comparison is `stored < current`, not `!==`, so a lagging read replica
   * returning an older number fails open on that axis rather than logging out
   * every user at once.
   */
  async #checkEpochs(
    data: T,
    stamped: Record<string, number> | undefined,
    request: Request | undefined,
  ): Promise<
    { ok: true; state: EpochState | undefined } | { ok: false; error: string }
  > {
    const o = this.#resolved;
    if (o.epochTracks.length === 0) return { ok: true, state: undefined };

    const tracks = applicableTracks(
      o.epochTracks as readonly EpochTrack<T>[],
      data,
    );
    if (tracks.length === 0) return { ok: true, state: undefined };

    const ctx: EpochContext = { request, cookieName: o.cookieName };

    let resolved: Array<number | null>;
    try {
      resolved = await Promise.all(
        tracks.map(({ track, key }) =>
          resolveEpoch(track, key, ctx, o.onEpochError)
        ),
      );
    } catch (e) {
      if (e instanceof EpochUnavailable) return { ok: false, error: e.message };
      throw e;
    }

    const state: EpochState = { values: {}, keys: {} };

    for (let i = 0; i < tracks.length; i++) {
      const { track, key } = tracks[i];
      const current = resolved[i];

      if (current === null) {
        // The error policy allowed this track to go unchecked. Carry the stamp
        // this cookie already had forward, so a re-seal preserves it: dropping
        // it would make the next load reject the session as missing, which is
        // the exact opposite of what "allow" is supposed to buy.
        const carried = stamped?.[track.name];
        if (typeof carried === "number" && Number.isFinite(carried)) {
          state.values[track.name] = carried;
          state.keys[track.name] = key;
        }
        continue;
      }

      const value = stamped?.[track.name];
      if (typeof value !== "number" || !Number.isFinite(value)) {
        return { ok: false, error: `Epoch missing: ${track.name}` };
      }
      if (value < current) {
        return { ok: false, error: `Epoch stale: ${track.name}` };
      }

      state.values[track.name] = current;
      state.keys[track.name] = key;
    }

    return { ok: true, state };
  }

  /**
   * Build the epoch stamp for a session about to be sealed.
   *
   * Reuses the value validated at load when the track's key has not changed —
   * that is the same epoch this session was just admitted under, and it saves a
   * second lookup. A changed key (the login case, where `uid` went from absent
   * to a real id) forces a fresh resolve.
   *
   * A resolver failure is never simply swallowed here. Under
   * `onEpochError: "allow"` an existing session keeps the stamp it arrived
   * with, so it goes on working through an outage; but a session with nothing
   * to preserve — a fresh login, or a track whose key just changed — throws,
   * because minting an unstamped cookie would log the user out on the very next
   * request instead, with nothing surfaced to the app. You cannot mint what you
   * cannot stamp.
   */
  async #stampEpochs(
    data: T,
    previous: EpochState | undefined,
    request: Request | undefined,
  ): Promise<Record<string, number> | undefined> {
    const o = this.#resolved;
    if (o.epochTracks.length === 0) return undefined;

    const tracks = applicableTracks(
      o.epochTracks as readonly EpochTrack<T>[],
      data,
    );
    if (tracks.length === 0) return undefined;

    const ctx: EpochContext = { request, cookieName: o.cookieName };
    const stamp: Record<string, number> = {};

    await Promise.all(tracks.map(async ({ track, key }) => {
      // Only reuse a value that belongs to this same key: an epoch resolved for
      // alice must not be restamped onto a session that has since become bob.
      const carried = previous?.keys[track.name] === key
        ? previous?.values[track.name]
        : undefined;

      if (carried !== undefined) {
        stamp[track.name] = carried;
        return;
      }

      const current = await resolveEpoch(track, key, ctx, o.onEpochError);
      if (current === null) {
        // Policy allowed the failure, but there is no prior stamp to preserve,
        // so any cookie we mint now would be rejected as missing next request.
        throw new EpochUnavailable(
          track.name,
          new Error("no prior epoch to preserve"),
        );
      }
      stamp[track.name] = current;
    }));

    return Object.keys(stamp).length > 0 ? stamp : undefined;
  }

  #invalidSession(reason: string, request: Request | undefined): Session<T> {
    this.#reportInvalid(reason, request);
    return new Session<T>({} as T, {
      isNew: true,
      isInvalid: true,
      invalidReason: reason,
    });
  }

  /**
   * Load the session from a request.
   *
   * Never throws for a malformed, tampered, expired or oversized cookie —
   * inspect {@linkcode ISession.isInvalid} and
   * {@linkcode ISession.invalidReason} instead.
   */
  load(req: Request): Promise<Session<T>> {
    return this.loadFromCookieHeader(req.headers.get("cookie"), {
      host: this.#resolved.bindHost
        ? getHost(req, this.#resolved.trustProxy)
        : undefined,
    }, req);
  }

  /**
   * Load the session from a raw `Cookie` header.
   *
   * For frameworks that expose a cookie store rather than a `Request`, and for
   * background jobs that have a cookie but no request.
   */
  async loadFromCookieHeader(
    header: string | null,
    ctx: RequestContext = {},
    req?: Request,
  ): Promise<Session<T>> {
    const keys = await this.#getKeys();
    const o = this.#resolved;

    // Resolve the host before the no-cookie shortcut, so a misconfigured
    // bindHost fails on every request rather than only on requests that happen
    // to carry a cookie.
    const host = this.#hostFor(req, ctx);

    const candidates = parseCookieHeaderAll(header)[o.cookieName] ?? [];
    if (candidates.length === 0) {
      return new Session<T>({} as T, { isNew: true });
    }

    let lastError = GENERIC_DECRYPT_ERROR;

    // Try every same-named cookie, not just the first. A planted duplicate on a
    // narrower path would otherwise shadow the real session and — with
    // onInvalidCookie: "clear" — get the genuine cookie deleted.
    for (const value of candidates) {
      const bytes = new TextEncoder().encode(`${o.cookieName}=${value}`)
        .byteLength;
      if (bytes > o.maxCookieBytes) {
        lastError = `Cookie too large: ${bytes} > ${o.maxCookieBytes} bytes`;
        continue;
      }

      for (let i = 0; i < keys.length; i++) {
        const result = unseal<T>(value, keys[i], {
          cookieName: o.cookieName,
          purpose: o.purpose,
          host,
          clockSkewSeconds: o.clockSkewSeconds,
          maxSessionAgeSeconds: o.maxSessionAgeSeconds,
        });

        if (!result.ok) {
          // Prefer a specific diagnosis over the generic one. Trying N keys
          // means the last attempt is usually just "wrong key"; a real cause
          // like "Token expired" surfaces on whichever key actually matched.
          if (
            lastError === GENERIC_DECRYPT_ERROR ||
            !result.error.startsWith("Decryption failed")
          ) {
            lastError = result.error;
          }
          continue;
        }

        const data = result.payload.data;
        if (typeof data !== "object" || data === null) {
          lastError = "Invalid payload data: expected an object";
          continue;
        }

        // Epoch checks run here, *below* unseal, so they only ever fire for a
        // cookie that already authenticated. A client planting N junk cookies
        // therefore cannot force N lookups against your epoch store.
        const epochCheck = await this.#checkEpochs(
          data,
          result.payload.ep,
          req,
        );
        if (!epochCheck.ok) {
          lastError = epochCheck.error;
          continue;
        }

        const session = new Session<T>(data, {
          isNew: false,
          flash: result.payload.flash,
          iat0: result.payload.iat0,
          epochs: epochCheck.state,
        });

        // Re-issue under the primary key so a rotated-out secret drains.
        if (i > 0) session.touch();
        if (o.rolling && o.ttlSeconds != null) session.touch();

        return session;
      }
    }

    return this.#invalidSession(lastError, req);
  }

  /**
   * Build the `Set-Cookie` value for a session, or `null` when there is nothing
   * to write.
   *
   * Precedence: destroyed clears the cookie, then dirty writes it, then an
   * invalid cookie is cleared when `onInvalidCookie` is `"clear"`.
   *
   * Call this at most once per request — it clears the dirty flag, so a second
   * call returns `null` rather than minting a second valid token.
   */
  persist(session: ISession<T>, req: Request): Promise<string | null> {
    return this.serialize(session, {
      secure: isSecureRequest(req, this.#resolved.trustProxy),
      host: this.#resolved.bindHost
        ? getHost(req, this.#resolved.trustProxy)
        : undefined,
    }, req);
  }

  /**
   * Build the `Set-Cookie` value from explicit request facts.
   *
   * The `Request`-free counterpart to {@linkcode SessionManager.persist}.
   */
  async serialize(
    session: ISession<T>,
    ctx: RequestContext = {},
    req?: Request,
  ): Promise<string | null> {
    const o = this.#resolved;

    const shouldClear = session.isDestroyed ||
      (session.isInvalid && o.onInvalidCookie === "clear");

    if (!session.isDirty && !shouldClear) {
      return null;
    }

    if (o.cookie.secure === "auto" && ctx.secure === undefined) {
      throw new TypeError(
        `usession: cookie.secure is "auto" but the request context does not ` +
          `say whether the connection is secure, so the cookie would silently ` +
          `be emitted without Secure. Pass { secure } to serialize(), or set ` +
          `cookie.secure to a boolean. persist() and apply() derive it from ` +
          `the Request for you.`,
      );
    }

    const isPrefixed = /^__(Host|Secure)-/.test(o.cookieName);

    const cookieOpts: CookieOptions = {
      path: o.cookie.path,
      domain: o.cookie.domain,
      httpOnly: o.cookie.httpOnly,
      // A prefixed cookie always carries Secure, including on the clear path:
      // without it the browser rejects the header outright, so the deletion
      // would silently do nothing.
      secure: isPrefixed ||
        (o.cookie.secure === "auto" ? ctx.secure === true : o.cookie.secure),
      sameSite: o.cookie.sameSite,
      partitioned: o.cookie.partitioned,
    };

    // Clearing is always allowed: a __Host- cookie cannot exist on an insecure
    // origin in the first place, so throwing here would only break logout.
    if (session.isDestroyed) {
      session.markPersisted();
      return clearCookie(o.cookieName, cookieOpts);
    }

    // A prefixed cookie is only storable over a secure connection. If the
    // request looked insecure, the app is misconfigured — say so rather than
    // emit a cookie the browser will drop on the floor.
    const requestLooksSecure = o.cookie.secure === "auto"
      ? ctx.secure === true
      : o.cookie.secure;

    if (isPrefixed && !requestLooksSecure) {
      throw new Error(
        `usession: refusing to emit "${o.cookieName}" over what looks like an ` +
          `insecure connection — the browser would discard it. Behind a ` +
          `TLS-terminating proxy set trustProxy: true, or set ` +
          `cookie.secure: true explicitly.`,
      );
    }

    if (session.isDirty) {
      const keys = await this.#getKeys();
      const epochs = await this.#stampEpochs(session.data, session.epochs, req);
      const token = seal(session.data, keys[0], {
        cookieName: o.cookieName,
        purpose: o.purpose,
        host: this.#hostFor(req, ctx),
        ttlSeconds: o.ttlSeconds,
        iat0: session.iat0,
        flash: session.peekFlash(),
        epochs,
      });

      const setCookie = serializeCookie(o.cookieName, token, {
        ...cookieOpts,
        ...(o.ttlSeconds != null ? { maxAge: o.ttlSeconds } : {}),
      });

      this.#checkSize(o.cookieName, token);
      session.markPersisted();
      return setCookie;
    }

    // Invalid cookie, nothing else to write.
    session.markPersisted();
    return clearCookie(o.cookieName, cookieOpts);
  }

  /** Warn or throw when an outgoing cookie is too large to survive a round trip. */
  #checkSize(cookieName: string, token: string): void {
    const o = this.#resolved;
    if (o.onOversize === "ignore") return;

    // Whichever is stricter: what browsers store, and what our own read side
    // will accept. A lowered `maxCookieBytes` must not let the manager mint a
    // cookie it would itself reject on the very next request.
    const limit = Math.min(BROWSER_COOKIE_LIMIT, o.maxCookieBytes);

    const bytes = new TextEncoder().encode(`${cookieName}=${token}`).byteLength;
    if (bytes <= limit) return;

    const info: OversizeCookieInfo = { bytes, limit, cookieName };

    if (o.onOversizeCookie) {
      o.onOversizeCookie(info);
      return;
    }

    const message = `usession: session cookie "${cookieName}" is ${bytes} ` +
      `bytes, over the ${limit}-byte limit. It will be discarded, logging the ` +
      `user out. Store less in the session, or keep large values server-side.`;

    if (o.onOversize === "throw") throw new Error(message);
    console.warn(message);
  }

  /**
   * Attach the session cookie to a response.
   *
   * Returns a response carrying `Set-Cookie` and `Vary: Cookie`. Prefer this
   * over hand-rolling the header — it appends rather than replaces (so it never
   * drops a cookie a route set), copies the headers first (so it works on
   * `Response.redirect()`, whose headers are immutable), and adds the `Vary`
   * that keeps shared caches from serving one user's page to another.
   */
  async apply(
    session: ISession<T>,
    req: Request,
    res: Response,
  ): Promise<Response> {
    // Rebuild first. `persist` clears the dirty flag, so if the rebuild threw
    // afterwards the session write would be lost with no way to retry.
    const out = new Response(res.body, {
      status: res.status,
      statusText: res.statusText,
      headers: new Headers(res.headers),
    });

    // `Vary` goes on unconditionally: `persist` reports whether the session was
    // *written*, which says nothing about whether the body depends on it.
    const setCookie = await this.persist(session, req);

    if (setCookie) out.headers.append("Set-Cookie", setCookie);
    out.headers.append("Vary", "Cookie");
    return out;
  }

  /** Redacted view — never expose the secret or the derived keys. */
  toJSON(): Record<string, unknown> {
    return {
      cookieName: this.#resolved.cookieName,
      purpose: this.#resolved.purpose,
      ttlSeconds: this.#resolved.ttlSeconds,
      secret: "[redacted]",
    };
  }

  /** Redacted view for `Deno.inspect` and `console.log`. */
  [Symbol.for("Deno.customInspect")](): string {
    return `SessionManager ${JSON.stringify(this.toJSON())}`;
  }
}
