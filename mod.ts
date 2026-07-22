/**
 * Rails-like sealed cookie sessions.
 *
 * The whole session lives in one encrypted cookie, sealed with TweetNaCl's
 * `secretbox` (XSalsa20-Poly1305) under a key derived from your secret with
 * HKDF-SHA256. There is no server-side store.
 *
 * Framework and runtime agnostic: the code uses only Web Crypto, `TextEncoder`
 * and the Fetch `Request`/`Response` types, so it runs on Deno, Bun, Node,
 * Cloudflare Workers and in browsers.
 *
 * @example Hono
 * ```ts ignore
 * import { Hono } from "hono";
 * import { type ISession, SessionManager } from "@nullstyle/usession";
 *
 * type SessionData = { uid?: string };
 *
 * declare module "hono" {
 *   interface ContextVariableMap {
 *     session: ISession<SessionData>;
 *   }
 * }
 *
 * const sessions = new SessionManager<SessionData>({
 *   secret: Deno.env.get("SESSION_SECRET")!,
 *   cookieName: "__Host-session",
 * });
 *
 * const app = new Hono();
 *
 * app.use("*", async (c, next) => {
 *   const session = await sessions.load(c.req.raw);
 *   c.set("session", session);
 *   try {
 *     await next();
 *   } finally {
 *     // Under Hono use persist() + append. Assigning `c.res` would re-apply
 *     // the old response's Set-Cookie headers and drop the session cookie.
 *     const setCookie = await sessions.persist(session, c.req.raw);
 *     if (setCookie) c.header("Set-Cookie", setCookie, { append: true });
 *     c.header("Vary", "Cookie", { append: true });
 *   }
 * });
 * ```
 *
 * @example Fresh
 * ```ts ignore
 * // routes/_middleware.ts
 * import { type FreshContext } from "$fresh/server.ts";
 * import { type ISession, SessionManager } from "@nullstyle/usession";
 *
 * type SessionData = { uid?: string };
 *
 * export type State = { session: ISession<SessionData> };
 *
 * const sessions = new SessionManager<SessionData>({
 *   secret: Deno.env.get("SESSION_SECRET")!,
 *   cookieName: "__Host-session",
 * });
 *
 * export async function handler(req: Request, ctx: FreshContext<State>) {
 *   const session = await sessions.load(req);
 *   ctx.state.session = session;
 *   // `apply` copies the headers, so this works on Response.redirect() too.
 *   return await sessions.apply(session, req, await ctx.next());
 * }
 * ```
 *
 * @module
 */

// Cookie utilities
export {
  clearCookie,
  type CookieOptions,
  parseCookieHeader,
  parseCookieHeaderAll,
  type SameSite,
  serializeCookie,
  type SessionCookieOptions,
} from "./cookie.ts";

// Seal/unseal core
export {
  deriveKey,
  MIN_SECRET_BYTES,
  seal,
  type SealContext,
  type SealedPayload,
  type SealOptions,
  type Secret,
  unseal,
  type UnsealOptions,
  type UnsealResult,
} from "./seal.ts";

// Session
export {
  type DefaultSessionData,
  type ISession,
  Session,
  type SessionInit,
} from "./session.ts";

// Manager
export {
  type InvalidCookieInfo,
  type OversizeCookieInfo,
  type RequestContext,
  SessionManager,
  type SessionOptions,
} from "./manager.ts";
