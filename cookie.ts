/**
 * Cookie parsing and serialization utilities.
 *
 * These operate on raw cookie-octets: values are neither percent-encoded on
 * write nor decoded on read, matching `@std/http/cookie`. If you need to carry
 * arbitrary text, encode it yourself before calling
 * {@linkcode serializeCookie} and decode after {@linkcode parseCookieHeader}.
 *
 * @module
 */

/** `SameSite` attribute values. */
export type SameSite = "Lax" | "Strict" | "None";

/**
 * Attributes for a single `Set-Cookie` header.
 *
 * Note `secure` is a plain boolean here. The `"auto"` sentinel understood by
 * `SessionManager` lives on {@linkcode SessionCookieOptions}, because only the
 * manager has a request to resolve it against.
 */
export type CookieOptions = {
  /** `Path` attribute. */
  path?: string;
  /** `Domain` attribute. Omit for a host-only cookie. */
  domain?: string;
  /** `HttpOnly` attribute. */
  httpOnly?: boolean;
  /** `Secure` attribute. */
  secure?: boolean;
  /** `SameSite` attribute. */
  sameSite?: SameSite;
  /** `Partitioned` attribute (CHIPS). Requires `Secure`. */
  partitioned?: boolean;
  /** `Max-Age` attribute, in seconds. Must be an integer. */
  maxAge?: number;
  /** `Expires` attribute. */
  expires?: Date;
};

/**
 * Manager-facing cookie attributes.
 *
 * `secure: "auto"` resolves per-request from the request scheme (and
 * `X-Forwarded-Proto` when `trustProxy` is enabled).
 */
export type SessionCookieOptions = Omit<CookieOptions, "secure"> & {
  /** `Secure` attribute, or `"auto"` to derive it from the request. */
  secure?: boolean | "auto";
};

/** RFC 7230 `token` — the legal charset for a cookie name. */
const TOKEN_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

/**
 * RFC 6265 `cookie-octet` — US-ASCII excluding CTLs, whitespace, DQUOTE,
 * comma, semicolon and backslash.
 */
const COOKIE_OCTET_RE = /^[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]*$/;

/** Printable ASCII excluding CTLs and `;` — legal in `Path` and `Domain`. */
const ATTR_VALUE_RE = /^[\x20-\x3A\x3C-\x7E]*$/;

/**
 * Parse a `Cookie` header into a name/value map.
 *
 * When a name appears more than once the first occurrence wins. Browsers order
 * duplicates by descending path length, so the first is the most specific — but
 * see {@linkcode parseCookieHeaderAll} if you need to consider every candidate,
 * which is what `SessionManager` does to stay resilient against a planted
 * duplicate cookie.
 *
 * @param header Raw `Cookie` header value, or `null`.
 */
export function parseCookieHeader(
  header: string | null,
): Record<string, string> {
  const all = parseCookieHeaderAll(header);
  // Null-prototype, like `parseCookieHeaderAll`. With a plain `{}` a lookup for
  // a name that is *absent* from the header — `cookies["toString"]` — would
  // return an inherited function rather than `undefined`.
  const cookies: Record<string, string> = Object.create(null);

  for (const name of Object.keys(all)) {
    cookies[name] = all[name][0];
  }

  return cookies;
}

/**
 * Parse a `Cookie` header, keeping every value for each name in header order.
 *
 * @param header Raw `Cookie` header value, or `null`.
 */
export function parseCookieHeaderAll(
  header: string | null,
): Record<string, string[]> {
  // A null-prototype map, so cookie names like `toString` or `__proto__` are
  // real entries rather than colliding with `Object.prototype`.
  const cookies: Record<string, string[]> = Object.create(null);

  if (!header) {
    return cookies;
  }

  for (const pair of header.split(";")) {
    const trimmed = pair.trim();
    if (!trimmed) continue;

    const eqIdx = trimmed.indexOf("=");
    if (eqIdx === -1) continue;

    const name = trimmed.slice(0, eqIdx).trim();
    const value = trimmed.slice(eqIdx + 1).trim();
    if (!name) continue;

    if (Object.hasOwn(cookies, name)) {
      cookies[name].push(value);
    } else {
      cookies[name] = [value];
    }
  }

  return cookies;
}

/**
 * Serialize a cookie and its attributes into a `Set-Cookie` header value.
 *
 * Validates the name and value against RFC 6265 rather than interpolating them
 * blind: an unvalidated `;` in a value would let a caller passing user input
 * inject arbitrary attributes (`Domain`, `Max-Age`, `SameSite`).
 *
 * @throws {TypeError} If the name, value, path, domain or maxAge is malformed.
 */
export function serializeCookie(
  name: string,
  value: string,
  opts: CookieOptions = {},
): string {
  if (!TOKEN_RE.test(name)) {
    throw new TypeError(
      `usession: invalid cookie name ${JSON.stringify(name)}: ` +
        `must be a non-empty RFC 7230 token`,
    );
  }

  if (!COOKIE_OCTET_RE.test(value)) {
    throw new TypeError(
      `usession: invalid cookie value for ${JSON.stringify(name)}: ` +
        `must contain only RFC 6265 cookie-octets (no whitespace, comma, ` +
        `semicolon, backslash, quotes or control chars). ` +
        `Percent-encode the value first.`,
    );
  }

  const parts: string[] = [`${name}=${value}`];

  if (opts.path !== undefined) {
    if (!ATTR_VALUE_RE.test(opts.path)) {
      throw new TypeError(
        `usession: invalid cookie Path ${JSON.stringify(opts.path)}`,
      );
    }
    parts.push(`Path=${opts.path}`);
  }

  if (opts.domain !== undefined) {
    if (!ATTR_VALUE_RE.test(opts.domain)) {
      throw new TypeError(
        `usession: invalid cookie Domain ${JSON.stringify(opts.domain)}`,
      );
    }
    parts.push(`Domain=${opts.domain}`);
  }

  if (opts.maxAge !== undefined) {
    if (!Number.isInteger(opts.maxAge)) {
      throw new TypeError(
        `usession: cookie Max-Age must be an integer number of seconds, ` +
          `got ${opts.maxAge}`,
      );
    }
    parts.push(`Max-Age=${opts.maxAge}`);
  }

  if (opts.expires !== undefined) {
    if (Number.isNaN(opts.expires.getTime())) {
      throw new TypeError("usession: cookie Expires must be a valid Date");
    }
    parts.push(`Expires=${opts.expires.toUTCString()}`);
  }

  if (opts.httpOnly) {
    parts.push("HttpOnly");
  }

  // Truthiness rather than `=== true`, so an unresolved `"auto"` sentinel
  // leaking in from the manager layer fails closed (secure) rather than open.
  if (opts.secure) {
    parts.push("Secure");
  }

  if (opts.sameSite !== undefined) {
    parts.push(`SameSite=${opts.sameSite}`);
  }

  if (opts.partitioned) {
    parts.push("Partitioned");
  }

  return parts.join("; ");
}

/**
 * Build a `Set-Cookie` value that deletes a cookie.
 *
 * Browsers key deletion on name + `Domain` + `Path`, so `opts` must repeat the
 * attributes the cookie was originally set with or nothing is deleted — a
 * `clearCookie("session")` from a handler at `/auth/logout` leaves a `Path=/`
 * cookie in place, and the user stays logged in. For `__Host-`/`__Secure-`
 * names the header must also carry `Secure` (and, for `__Host-`, `Path=/` with
 * no `Domain`) or the browser rejects it before deleting anything.
 */
export function clearCookie(name: string, opts: CookieOptions = {}): string {
  return serializeCookie(name, "", {
    ...opts,
    maxAge: 0,
    expires: new Date(0),
  });
}
