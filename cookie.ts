/**
 * Cookie parsing and serialization utilities
 */

export type SameSite = "Lax" | "Strict" | "None";

export type CookieOptions = {
  path?: string;
  domain?: string;
  httpOnly?: boolean;
  secure?: boolean | "auto";
  sameSite?: SameSite;
  partitioned?: boolean;
  maxAge?: number;
  expires?: Date;
};

/**
 * Parse Cookie header into key-value map
 * Handles multiple cookies, spacing, and duplicates (first wins)
 */
export function parseCookieHeader(
  header: string | null,
): Record<string, string> {
  const cookies: Record<string, string> = {};

  if (!header) {
    return cookies;
  }

  const pairs = header.split(";");

  for (const pair of pairs) {
    const trimmed = pair.trim();
    if (!trimmed) continue;

    const eqIdx = trimmed.indexOf("=");
    if (eqIdx === -1) continue;

    const name = trimmed.slice(0, eqIdx).trim();
    const value = trimmed.slice(eqIdx + 1).trim();

    // First occurrence wins
    if (!(name in cookies)) {
      cookies[name] = value;
    }
  }

  return cookies;
}

/**
 * Serialize a cookie with its options into a Set-Cookie header value
 */
export function serializeCookie(
  name: string,
  value: string,
  opts: CookieOptions = {},
): string {
  const parts: string[] = [`${name}=${value}`];

  if (opts.path !== undefined) {
    parts.push(`Path=${opts.path}`);
  }

  if (opts.domain !== undefined) {
    parts.push(`Domain=${opts.domain}`);
  }

  if (opts.maxAge !== undefined) {
    parts.push(`Max-Age=${opts.maxAge}`);
  }

  if (opts.expires !== undefined) {
    parts.push(`Expires=${opts.expires.toUTCString()}`);
  }

  if (opts.httpOnly) {
    parts.push("HttpOnly");
  }

  if (opts.secure === true) {
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
 * Create a cookie clearing string (expires immediately)
 */
export function clearCookie(name: string, opts: CookieOptions = {}): string {
  return serializeCookie(name, "", {
    ...opts,
    maxAge: 0,
    expires: new Date(0),
  });
}
