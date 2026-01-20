# usession

Rails-inspired sealed cookie sessions for Deno + Hono.

Sessions are stored entirely in an encrypted cookie using TweetNaCl's `secretbox` (XSalsa20-Poly1305). A single `SESSION_SECRET` environment variable is hashed into a 32-byte key for sealing/unsealing payloads.

## Installation

```ts
import { cookieSession, getSession } from "jsr:@nullstyle/usession";
```

## Quick Start

```ts
import { Hono } from "jsr:@hono/hono";
import { cookieSession, getSession } from "jsr:@nullstyle/usession";

const app = new Hono();

app.use("*", cookieSession({
  secret: Deno.env.get("SESSION_SECRET")!,
  cookieName: "__Host-session",
  ttlSeconds: 60 * 60 * 24 * 7, // 7 days
}));

app.get("/", (c) => {
  const session = getSession<{ uid?: string }>(c);
  if (session.get("uid")) {
    return c.text(`Hello, user ${session.get("uid")}`);
  }
  return c.text("Not logged in");
});

app.post("/login", (c) => {
  const session = getSession<{ uid?: string }>(c);
  session.set("uid", "user123");
  return c.text("Logged in");
});

app.post("/logout", (c) => {
  const session = getSession(c);
  session.destroy();
  return c.text("Logged out");
});

Deno.serve(app.fetch);
```

## Configuration

```ts
cookieSession({
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
const session = getSession<MySessionData>(c);

// Read/write
session.get("key");           // Get value
session.set("key", value);    // Set value (marks dirty)
session.unset("key");         // Remove key (marks dirty)
session.data;                 // Direct access to data object

// State
session.isNew;                // True if no valid cookie was found
session.isDirty;              // True if any mutations occurred
session.isDestroyed;          // True if destroy() was called

// Flash messages (one-time values)
session.flash("notice", "Saved!");
const flashes = session.consumeFlash(); // { notice: "Saved!" }

// Lifecycle
session.destroy();            // Clear session, delete cookie
session.touch();              // Mark dirty without changing data (for rolling)
```

## TypeScript Support

Extend Hono's context types for better autocomplete:

```ts
declare module "hono" {
  interface ContextVariableMap {
    session: import("@nullstyle/usession").ISession<{
      uid?: string;
      claims?: { email?: string; name?: string };
    }>;
  }
}
```

## OIDC Helpers

Built-in helpers for storing OIDC login state:

```ts
import {
  beginOidcLogin,
  verifyOidcCallback,
  completeOidcLogin,
  getOidcReturnTo,
} from "jsr:@nullstyle/usession";

// Start login - stores state/nonce/PKCE in session
app.get("/auth/login", async (c) => {
  const session = getSession(c);
  const { state, nonce, pkceChallenge } = await beginOidcLogin(session, {
    returnTo: c.req.query("returnTo"),
  });

  const url = new URL("https://provider.com/authorize");
  url.searchParams.set("state", state);
  url.searchParams.set("nonce", nonce);
  url.searchParams.set("code_challenge", pkceChallenge);
  url.searchParams.set("code_challenge_method", "S256");
  // ... other OIDC params

  return c.redirect(url.toString());
});

// Handle callback - verify state, complete login
app.get("/auth/callback", async (c) => {
  const session = getSession(c);
  const state = c.req.query("state") ?? "";

  const result = verifyOidcCallback(session, { state });
  if (!result.ok) {
    return c.text(result.error, 400);
  }

  // Use result.nonce and result.pkceVerifier with your OIDC library
  const claims = await exchangeCodeForClaims(c.req.query("code"), {
    nonce: result.nonce,
    pkceVerifier: result.pkceVerifier,
  });

  completeOidcLogin(session, {
    uid: claims.sub,
    sub: claims.sub,
    iss: claims.iss,
    claims: { email: claims.email, name: claims.name },
  });

  return c.redirect(result.returnTo ?? "/");
});
```

## Cap'n Web Integration

Works with `@hono/capnweb` for authenticated RPC:

```ts
import { Hono } from "jsr:@hono/hono";
import { upgradeWebSocket } from "jsr:@hono/hono/deno";
import { newRpcResponse } from "jsr:@hono/capnweb";
import { cookieSession, getSession } from "jsr:@nullstyle/usession";

const app = new Hono();

app.use("*", cookieSession({
  secret: Deno.env.get("SESSION_SECRET")!,
  cookieName: "__Host-session",
}));

app.all("/api", (c) => {
  const session = getSession<{ uid?: string }>(c);
  if (!session.get("uid")) {
    return c.text("Unauthorized", 401);
  }

  return newRpcResponse(c, createApiServer({ uid: session.get("uid")! }), {
    upgradeWebSocket,
  });
});
```

## Security Notes

- **SESSION_SECRET must be high entropy** - Use `openssl rand -base64 32` or similar
- **Cookie size limit** - Keep session data minimal (~4KB browser limit)
- **No server-side revocation** - Stateless cookies can't be revoked until expiry
- **SameSite=Lax default** - Compatible with OIDC redirects while providing CSRF protection
- **Use `__Host-` prefix in production** - Ensures Secure + host-only + path=/

## Token Format

```
v1.<nonce_base64url>.<ciphertext_base64url>
```

The encrypted payload contains:
```ts
{
  ctx: { v: 1, cookieName, purpose, host? },
  iat: number,  // issued at (unix seconds)
  exp?: number, // expiry (unix seconds)
  data: T,      // your session data
}
```

## License

MIT
