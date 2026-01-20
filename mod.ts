/**
 * @module usession
 *
 * Rails-like sealed cookie sessions for Deno + Hono
 *
 * Uses TweetNaCl secretbox (XSalsa20-Poly1305) for authenticated encryption.
 * A single SESSION_SECRET environment variable is hashed (SHA-256) into a
 * 32-byte key for sealing/unsealing session payloads.
 *
 * @example Basic usage
 * ```ts
 * import { Hono } from "hono";
 * import { cookieSession, getSession } from "@nullstyle/usession";
 *
 * const app = new Hono();
 *
 * app.use("*", cookieSession({
 *   secret: Deno.env.get("SESSION_SECRET")!,
 *   cookieName: "__Host-session",
 *   ttlSeconds: 60 * 60 * 24 * 7,
 * }));
 *
 * app.get("/", (c) => {
 *   const session = getSession<{ uid?: string }>(c);
 *   if (session.get("uid")) {
 *     return c.text(`Hello, user ${session.get("uid")}`);
 *   }
 *   return c.text("Not logged in");
 * });
 * ```
 *
 * @example Hono typing hook
 * ```ts
 * declare module "hono" {
 *   interface ContextVariableMap {
 *     session: import("@nullstyle/usession").ISession<MySessionData>;
 *   }
 * }
 * ```
 */

// Cookie utilities
export {
  clearCookie,
  type CookieOptions,
  parseCookieHeader,
  type SameSite,
  serializeCookie,
} from "./cookie.ts";

// Seal/unseal core
export {
  deriveKey,
  seal,
  type SealContext,
  type SealedPayload,
  type SealOptions,
  unseal,
  type UnsealOptions,
  type UnsealResult,
} from "./seal.ts";

// Session
export {
  type DefaultSessionData,
  type ISession,
  Session,
} from "./session.ts";

// Middleware
export {
  cookieSession,
  getSession,
  type SessionOptions,
} from "./middleware.ts";

// OIDC helpers
export {
  beginOidcLogin,
  type BeginOidcLoginResult,
  completeOidcLogin,
  type CompleteOidcLoginParams,
  getOidcReturnTo,
  verifyOidcCallback,
  type VerifyOidcCallbackResult,
} from "./oidc.ts";

// Re-export base64url utilities from @std/encoding (useful for CSRF tokens, etc.)
export {
  decodeBase64Url,
  encodeBase64Url,
} from "@std/encoding/base64url";
