# usession

Rails-inspired sealed cookie sessions for Deno.
Web-framework agnostic (works with Hono, Fresh, etc).

Sessions are stored entirely in an encrypted cookie using TweetNaCl's `secretbox` (XSalsa20-Poly1305). A single `SESSION_SECRET` environment variable is hashed into a 32-byte key for sealing/unsealing payloads.

## Installation

```bash
deno add jsr:@nullstyle/usession
```

```ts
import { SessionManager } from "@nullstyle/usession";
```

## Usage with Hono

Since `usession` is framework-agnostic, you create a middleware using `SessionManager` that adapts to Hono's API.

```ts
import { Hono } from "jsr:@hono/hono";
import { SessionManager, type ISession } from "jsr:@nullstyle/usession";

// Define your session data shape
type SessionData = {
  uid?: string;
};

// Add type safety to Hono
declare module "hono" {
  interface ContextVariableMap {
    session: ISession<SessionData>;
  }
}

const app = new Hono();

// Initialize the manager
const sessions = new SessionManager<SessionData>({
  secret: Deno.env.get("SESSION_SECRET")!,
  cookieName: "session",
  ttlSeconds: 60 * 60 * 24 * 7, // 7 days
});

// Create middleware
app.use("*", async (c, next) => {
  const session = await sessions.load(c.req.raw);
  c.set("session", session);

  await next();

  const setCookie = await sessions.persist(session, c.req.raw);
  if (setCookie) {
    c.header("Set-Cookie", setCookie);
  }
});

// Use it in routes
app.get("/", (c) => {
  const session = c.get("session");
  if (session.get("uid")) {
    return c.text(`Hello, user ${session.get("uid")}`);
  }
  return c.text("Not logged in");
});

app.post("/login", (c) => {
  const session = c.get("session");
  session.set("uid", "user123");
  return c.text("Logged in");
});
```

## Usage with Deno Fresh

In Fresh, you can use a middleware to attach the session to `ctx.state`.

```ts
// routes/_middleware.ts
import { FreshContext } from "$fresh/server.ts";
import { SessionManager, type ISession } from "jsr:@nullstyle/usession";

type SessionData = {
  uid?: string;
};

export interface State {
  session: ISession<SessionData>;
}

const sessions = new SessionManager<SessionData>({
  secret: Deno.env.get("SESSION_SECRET")!,
  cookieName: "session",
});

export async function handler(req: Request, ctx: FreshContext<State>) {
  const session = await sessions.load(req);
  ctx.state.session = session;

  const resp = await ctx.next();

  const setCookie = await sessions.persist(session, req);
  if (setCookie) {
    resp.headers.append("Set-Cookie", setCookie);
  }

  return resp;
}
```

## Configuration

```ts
const sessions = new SessionManager({
  // Required
  secret: string,           // From SESSION_SECRET env var (must be high entropy)
  cookieName: string,       // e.g. "__Host-session" (prod) or "session" (dev)

  // Optional
  purpose?: string,         // Key separation (default: "session")
  ttlSeconds?: number,      // Session lifetime (default: 7 days, null for session cookie)
  rolling?: boolean,        // Refresh expiry on each request (default: false)
  clockSkewSeconds?: number,// Tolerance for expiry checks (default: 60)
  maxCookieBytes?: number,  // Reject oversized cookies (default: 8192)
  bindHost?: boolean,       // Bind session to host header (default: false)
  trustProxy?: boolean,     // Trust X-Forwarded-* headers (default: false)
  onInvalidCookie?: "ignore" | "clear", // Handle bad cookies (default: "clear")

  cookie?: {
    path?: string,          // Default: "/"
    domain?: string,        // Default: undefined (host-only)
    httpOnly?: boolean,     // Default: true
    secure?: boolean | "auto", // Default: "auto"
    sameSite?: "Lax" | "Strict" | "None", // Default: "Lax"
    partitioned?: boolean,  // Default: false
  },
});
```

## Session API

```ts
const session = await sessions.load(req);

// Read/write
session.get("key");           // Get value
session.set("key", value);    // Set value (marks dirty)
session.unset("key");         // Remove key (marks dirty)
session.data;                 // Direct access to data object

// State
session.isNew;                // True if no valid cookie was found
session.isDirty;              // True if any mutations occurred
session.isDestroyed;          // True if destroy() was called
session.isInvalid;            // True if cookie was present but invalid

// Flash messages (one-time values)
session.flash("notice", "Saved!");
const flashes = session.consumeFlash(); // { notice: "Saved!" }

// Lifecycle
session.destroy();            // Clear session, delete cookie
session.touch();              // Mark dirty without changing data (for rolling)
```



## Security Notes

- **SESSION_SECRET must be high entropy** - Use `openssl rand -base64 32` or similar
- **Cookie size limit** - Keep session data minimal (~4KB browser limit)
- **No server-side revocation** - Stateless cookies can't be revoked until expiry
- **SameSite=Lax default** - Compatible with OIDC redirects while providing CSRF protection
- **Use `__Host-` prefix in production** - Ensures Secure + host-only + path=/

## License

MIT