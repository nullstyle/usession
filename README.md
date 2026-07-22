# usession

Rails-inspired sealed cookie sessions.

The whole session lives in one encrypted cookie, sealed with TweetNaCl's
`secretbox` (XSalsa20-Poly1305) under a key derived from your secret with
HKDF-SHA256. There is no server-side store to run.

Framework and runtime agnostic: the code touches only Web Crypto, `TextEncoder`
and the Fetch `Request`/`Response` types, so it runs on Deno, Bun, Node,
Cloudflare Workers and in browsers.

## Installation

```bash
deno add jsr:@nullstyle/usession
```

```ts
import { SessionManager } from "@nullstyle/usession";
```

Generate a secret — it must be at least 32 bytes:

```bash
openssl rand -base64 32
```

## Hono

```ts ignore
import { Hono } from "hono";
import { type ISession, SessionManager } from "@nullstyle/usession";

type SessionData = {
  uid?: string;
};

declare module "hono" {
  interface ContextVariableMap {
    session: ISession<SessionData>;
  }
}

const sessions = new SessionManager<SessionData>({
  secret: Deno.env.get("SESSION_SECRET")!,
  cookieName: "__Host-session",
  ttlSeconds: 60 * 60 * 24 * 7,
});

const app = new Hono();

app.use("*", async (c, next) => {
  const session = await sessions.load(c.req.raw);
  c.set("session", session);
  try {
    await next();
  } finally {
    // `finally`, so a throwing handler still persists the session.
    // Note: do NOT use `c.res = await sessions.apply(...)` here. Hono's `c.res`
    // setter re-applies the *old* response's Set-Cookie headers over the new
    // one, which would discard the session cookie.
    const setCookie = await sessions.persist(session, c.req.raw);
    if (setCookie) c.header("Set-Cookie", setCookie, { append: true });
    c.header("Vary", "Cookie", { append: true });
  }
});

app.get("/", (c) => {
  const session = c.get("session");
  const uid = session.get("uid");
  return c.text(uid ? `Hello, user ${uid}` : "Not logged in");
});

app.post("/login", (c) => {
  const session = c.get("session");
  session.regenerate(); // prevent session fixation
  session.set("uid", "user123");
  return c.redirect("/");
});
```

Two Hono-specific traps, both of which silently lose a cookie:

- `c.header("Set-Cookie", …)` **replaces** by default, dropping any cookie your
  routes set (an OAuth `state` cookie, for instance). Always pass
  `{ append: true }`.
- Assigning `c.res` does not help. Hono's `c.res` setter copies the _previous_
  response's `Set-Cookie` headers onto the new one, deleting whatever the new
  one carried — so `c.res = await sessions.apply(…)` throws the session cookie
  away exactly when a route set a cookie of its own.

`apply()` is the right tool wherever the framework consumes a returned
`Response` (Fresh, plain `Deno.serve`); under Hono, use `persist()` with
`append: true` as shown above.

## Fresh

```ts ignore
// routes/_middleware.ts — targets Fresh 1.6+ (FreshContext)
import { type FreshContext } from "$fresh/server.ts";
import { type ISession, SessionManager } from "@nullstyle/usession";

type SessionData = {
  uid?: string;
};

export type State = {
  session: ISession<SessionData>;
};

const sessions = new SessionManager<SessionData>({
  secret: Deno.env.get("SESSION_SECRET")!,
  cookieName: "__Host-session",
});

export async function handler(req: Request, ctx: FreshContext<State>) {
  const session = await sessions.load(req);
  ctx.state.session = session;
  return await sessions.apply(session, req, await ctx.next());
}
```

`apply()` copies the response headers before appending, so it works on
`Response.redirect()` — whose headers are immutable, and which would otherwise
throw `TypeError: Cannot change header` on exactly the redirect a login
performs.

## Configuration

| Option                 | Type                            | Default     | Notes                                                                        |
| ---------------------- | ------------------------------- | ----------- | ---------------------------------------------------------------------------- |
| `secret`               | `Secret \| Secret[]`            | —           | Required. `string` or `Uint8Array`, min 32 bytes. An array enables rotation. |
| `cookieName`           | `string`                        | —           | Required. Prefer `__Host-session` in production.                             |
| `purpose`              | `string`                        | `"session"` | Key separation. Services sharing a secret **must** differ here.              |
| `ttlSeconds`           | `number \| null`                | `604800`    | Lifetime. `null` means a browser-session cookie.                             |
| `rolling`              | `boolean`                       | `false`     | Refresh expiry on every request.                                             |
| `maxSessionAgeSeconds` | `number \| null`                | `null`      | Absolute cap that `rolling` cannot extend.                                   |
| `clockSkewSeconds`     | `number`                        | `60`        | Tolerance on expiry checks.                                                  |
| `maxCookieBytes`       | `number`                        | `4096`      | Largest incoming cookie to attempt.                                          |
| `onOversize`           | `"warn" \| "throw" \| "ignore"` | `"warn"`    | What to do when an outgoing cookie exceeds the browser limit.                |
| `onInvalid`            | `(info) => void`                | —           | Called with the reason a cookie was rejected.                                |
| `onOversizeCookie`     | `(info) => void`                | —           | Called instead of the default warn/throw.                                    |
| `bindHost`             | `boolean`                       | `false`     | Bind the session to the request host.                                        |
| `trustProxy`           | `boolean`                       | `false`     | Trust `X-Forwarded-Proto` / `-Host`.                                         |
| `onInvalidCookie`      | `"ignore" \| "clear"`           | `"clear"`   | Whether to delete a cookie that failed to unseal.                            |
| `cookie.path`          | `string`                        | `"/"`       |                                                                              |
| `cookie.domain`        | `string`                        | —           | Omit for a host-only cookie.                                                 |
| `cookie.httpOnly`      | `boolean`                       | `true`      |                                                                              |
| `cookie.secure`        | `boolean \| "auto"`             | `"auto"`    | `"auto"` derives it from the request. See below.                             |
| `cookie.sameSite`      | `"Lax" \| "Strict" \| "None"`   | `"Lax"`     | `"None"` forces `Secure`.                                                    |
| `cookie.partitioned`   | `boolean`                       | `false`     | CHIPS. Forces `Secure`.                                                      |

A runnable configuration:

```ts
import { SessionManager } from "@nullstyle/usession";

const sessions = new SessionManager({
  secret: Deno.env.get("SESSION_SECRET")!,
  cookieName: "__Host-session",
  ttlSeconds: 60 * 60 * 24 * 7,
  maxSessionAgeSeconds: 60 * 60 * 24 * 30,
  rolling: true,
  trustProxy: true,
  onInvalid: (info) => console.warn("session rejected:", info.reason),
});
```

## Deploying behind a proxy

`cookie.secure` defaults to `"auto"`, which inspects the request scheme. A
TLS-terminating proxy (nginx, Caddy, ALB, Cloud Run, Fly) forwards to your
origin over plain HTTP, so `"auto"` sees `http:` and would omit `Secure` on a
fully-HTTPS site.

Set one of:

```ts
import { SessionManager } from "@nullstyle/usession";

const secret = Deno.env.get("SESSION_SECRET")!;

// Derive Secure from X-Forwarded-Proto — the proxy must OVERWRITE that header.
new SessionManager({ secret, cookieName: "__Host-session", trustProxy: true });

// Or just hard-code it.
new SessionManager({
  secret,
  cookieName: "__Host-session",
  cookie: { secure: true },
});
```

With a `__Host-` or `__Secure-` cookie name this is not silent: `persist()`
throws rather than emit a cookie the browser will discard.

Only enable `trustProxy` behind a proxy that overwrites `X-Forwarded-*`. A proxy
that merely appends lets a client forge the value — and with `bindHost` that
means forging the host a session is bound to.

## Session API

```ts ignore
const session = await sessions.load(req);

// Read and write
session.get("key");
session.set("key", value); // no-op if the value is unchanged
session.unset("key");
session.update((data) => data.cart.items.push(item)); // nested mutation
session.data; // read-only view — see the warning below

// State
session.isNew; // no valid cookie was presented
session.isDirty; // has unsaved changes
session.isDestroyed; // destroy() was called
session.isInvalid; // a cookie was presented but rejected
session.invalidReason; // why — for logs, not for users

// Flash messages
session.flash("notice", "Saved!");
session.peekFlash(); // read without consuming
session.consumeFlash(); // { notice: "Saved!" }, and clears

// Lifecycle
session.regenerate(); // new empty session — call on any privilege change
session.destroy(); // clear the session and delete the cookie
session.touch(); // mark dirty without changing anything
```

**`session.data` is a read-only view.** Mutating it directly does not mark the
session dirty, so the write is lost whenever nothing else dirties the session —
and, confusingly, it _is_ persisted when something else does (another `set()`,
or `rolling: true`). That makes direct mutation nondeterministic rather than
merely ineffective. Use `set()`, `unset()` or `update()`.

**Writes to a destroyed session throw.** `destroy()` always wins at persist
time, so a later `set()` would be discarded — logging the user out instead of
in. If you meant to start a fresh session, call `regenerate()`.

**Flash is not swept automatically.** Unlike Rails, a message survives until
`consumeFlash()` is called. If the browser's next request is a prefetch or a
favicon fetch, the flash waits for the request after that.

## Manager API

- `load(req)` — never throws for a bad cookie; check `isInvalid`.
- `persist(session, req)` — returns the `Set-Cookie` value or `null`. Call it at
  most once per request; it clears the dirty flag.
- `apply(session, req, res)` — the recommended path. Returns a response with
  `Set-Cookie` appended and `Vary: Cookie` set.
- `loadFromCookieHeader(header, ctx?)` / `serialize(session, ctx?)` — the same
  operations without a `Request`, for frameworks that expose a cookie store, for
  background jobs, and for tests. `ctx` is optional only when the manager does
  not need it: pass `{ secure }` unless `cookie.secure` is a boolean, and
  `{ host }` whenever `bindHost` is on. Both throw a `TypeError` naming the
  missing field rather than guessing.

The low-level primitives are also exported and supported: `deriveKey`, `seal`,
`unseal`, `parseCookieHeader`, `parseCookieHeaderAll`, `serializeCookie`,
`clearCookie`. The token format is `v2.<nonce_b64u>.<box_b64u>`.

## Rotating the secret

`secret` accepts an ordered array. Element 0 seals; every element is accepted on
unseal. A session that opens under a non-primary key is re-issued under the
primary one automatically, so sessions drain onto the new secret as users
browse.

```ts
// 1. Deploy with the new secret first, old secret still accepted.
{
  secret: [
    Deno.env.get("SESSION_SECRET_NEXT")!,
    Deno.env.get("SESSION_SECRET")!,
  ];
}

// 2. Wait one full ttlSeconds, so every outstanding cookie has either been
//    re-minted under the new secret or expired on its own.

// 3. Deploy with the old secret removed.
{
  secret: [Deno.env.get("SESSION_SECRET_NEXT")!];
}
```

## Caching

Any response whose content depends on the session **must** carry `Vary: Cookie`,
or a shared cache can serve one user's page to another. `apply()` sets it for
you. Per-user content should also carry `Cache-Control: private, no-store`.

## Security notes

- **Generate the secret properly** — `openssl rand -base64 32`. Secrets under 32
  bytes are rejected. HKDF gives domain separation, not a work factor, so a
  guessable secret is a guessable session.
- **Keep the session small.** The practical ceiling is roughly 2.8 KB of JSON:
  base64url plus the nonce, MAC and envelope inflate it by about 1.4x, against a
  ~4096-byte browser limit. `onOversize` warns by default; set it to `"throw"`
  to fail loudly.
- **There is no server-side revocation.** A captured cookie stays valid until it
  expires — `destroy()` clears the browser's copy, not an attacker's. Keep
  `ttlSeconds` short and set `maxSessionAgeSeconds`. For real revocation, store
  an epoch in the session and compare it against your own store.
- **Rotate on privilege change.** Call `regenerate()` on login,
  logout-then-login, role elevation, and starting or stopping impersonation.
- **`SameSite=Lax` is not full CSRF protection.** It blocks cross-site POST but
  top-level cross-site GET navigations still send the cookie. Use a CSRF token
  on state-changing routes.
- **Use `__Host-` in production.** It forces `Secure`, host-only scope and
  `Path=/`, which is what keeps a compromised sibling subdomain from planting a
  cookie that shadows yours. The invariants are enforced at construction.
- **Last write wins.** Two concurrent requests each re-encrypt the whole
  session, so the later response's cookie discards the other's writes entirely.
  Keep concurrently-written data out of the session.
- **The payload is never compressed,** which is deliberate — compressing
  attacker-influenced data alongside secrets is the CRIME/BREACH pattern.

Report vulnerabilities privately — see [SECURITY.md](./SECURITY.md).

## License

[MIT](./LICENSE)
