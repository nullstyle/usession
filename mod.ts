/**
 * @module usession
 *
 * Rails-like sealed cookie sessions for Deno.
 * Web-framework agnostic (works with Hono, Fresh, etc).
 *
 * Uses TweetNaCl secretbox (XSalsa20-Poly1305) for authenticated encryption.
 * A single SESSION_SECRET environment variable is hashed (SHA-256) into a
 * 32-byte key for sealing/unsealing session payloads.
 *
 * @example Hono Usage
 * ```ts
 * import { Hono } from "hono";
 * import { SessionManager } from "@nullstyle/usession";
 *
 * const app = new Hono();
 * const sessions = new SessionManager({
 *   secret: Deno.env.get("SESSION_SECRET")!,
 *   cookieName: "session",
 * });
 *
 * app.use("*", async (c, next) => {
 *   const session = await sessions.load(c.req.raw);
 *   c.set("session", session);
 *   await next();
 *   const setCookie = await sessions.persist(session, c.req.raw);
 *   if (setCookie) {
 *     c.header("Set-Cookie", setCookie);
 *   }
 * });
 * ```
 *
 * @example Fresh Usage
 * ```ts
 * // routes/_middleware.ts
 * import { FreshContext } from "$fresh/server.ts";
 * import { SessionManager } from "@nullstyle/usession";
 *
 * const sessions = new SessionManager({
 *   secret: Deno.env.get("SESSION_SECRET")!,
 *   cookieName: "session",
 * });
 *
 * export async function handler(req: Request, ctx: FreshContext) {
 *   const session = await sessions.load(req);
 *   ctx.state.session = session;
 *   const resp = await ctx.next();
 *   const setCookie = await sessions.persist(session, req);
 *   if (setCookie) {
 *     resp.headers.append("Set-Cookie", setCookie);
 *   }
 *   return resp;
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

// Manager
export {
  SessionManager,
  type SessionOptions,
} from "./manager.ts";



// Re-export base64url utilities from @std/encoding
export {
  decodeBase64Url,
  encodeBase64Url,
} from "@std/encoding/base64url";