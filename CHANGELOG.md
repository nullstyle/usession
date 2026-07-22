# Changelog

## 0.2.0

A security and correctness pass over the whole library, following a full audit
of 0.1.0.

### ⚠️ Breaking

- **All existing cookies are invalidated.** The token format moves from `v1` to
  `v2` and the key derivation changed (see below). Old cookies are rejected with
  `Unsupported token version: v1` and, with the default
  `onInvalidCookie: "clear"`, cleared. Users are logged out once on upgrade.
- **Key derivation is now HKDF-SHA256** with a length-prefixed `info`, replacing
  a single unsalted SHA-256 over `label|purpose|secret`. The old framing was not
  injective — `deriveKey("b|c", "a")` and `deriveKey("c", "a|b")` produced the
  same key, so `purpose` did not actually separate keys. The KDF label also no
  longer says `hono-cookie-session`.
- **Secrets must be at least 32 bytes.** Shorter secrets throw. `secret` now
  also accepts a `Uint8Array`, and an array for rotation.
- **Writing to a destroyed session throws** instead of being silently discarded.
  `destroy()` now also wipes the data. Use `regenerate()` to start a fresh
  session.
- **`serializeCookie` validates its inputs** and throws `TypeError` on a
  malformed name, value, path, domain, maxAge or expires. A `;` in a value used
  to inject arbitrary cookie attributes.
- **`CookieOptions.secure` is now `boolean`.** The `"auto"` sentinel moved to
  the new `SessionCookieOptions`, used only by `SessionManager`.
- **`SessionOptions.cookie` no longer accepts `maxAge`/`expires`.** They were
  silently ignored; lifetime comes from `ttlSeconds`.
- **`maxCookieBytes` now defaults to 4096** (was 8192), matching the browser
  limit, and is measured over the whole `name=value` pair in bytes.
- **Flash messages moved out of the session data object.** They previously
  squatted on a `flash` key, which threw if your own session shape used that
  name.
- The base64url re-exports were removed from `mod.ts`. Import them from
  `@std/encoding` directly.
- `Session`'s type parameter is now `T extends object = DefaultSessionData`, so
  `interface`-declared session shapes are accepted.

### Fixed

- `ttlSeconds: null` is now an actual browser-session cookie. `??` treated it as
  unset, so it silently became the 7-day default.
- `bindHost: true` now round-trips when the request has no `Host` header. `seal`
  dropped an empty host while `unseal` required it to match, so the session was
  lost on every request.
- `secure: "auto"` no longer silently omits `Secure` behind a TLS-terminating
  proxy. Emitting a `__Host-`/`__Secure-` cookie without `Secure` now throws.
- `X-Forwarded-Proto`/`-Host` are parsed rather than compared verbatim, so
  multi-hop values (`"https, http"`) and uppercase schemes work.
- `__Host-`/`__Secure-` prefix invariants are validated at construction.
  `SameSite=None` and `Partitioned` now force `Secure`.
- Oversized cookies are detected at write time (`onOversize`) instead of being
  emitted for the browser to silently discard.
- `parseCookieHeader` no longer drops cookies named after `Object.prototype`
  members, and no longer returns functions.
- A duplicate cookie planted on a narrower path no longer locks the user out —
  every same-named cookie is tried.
- `unseal` no longer throws a `TypeError` on a decrypted plaintext of `null`,
  and validates the `exp` claim's type.
- `persist()` is idempotent within a request; it clears the dirty flag.
- `set()`/`unset()` no longer mark the session dirty for no-op writes.
- `SessionOptions<T>` used to ignore `T` entirely, so the documented constructor
  call inferred `Record<string, unknown>` and every key went unchecked.
- `ISession<T>` can now be passed to the manager, as the README always implied.
- The secret and derived keys are `#private`, so `console.log(manager)` and
  `JSON.stringify(manager)` no longer leak them. The secret reference is dropped
  once the keys are derived.
- `ttlSeconds`/`maxAge` are validated, so a `NaN` from an unset env var fails
  loudly instead of expiring every session immediately.
- Removed 33 lines of stale design deliberation from `manager.ts` that
  contradicted the shipped code.
- `clockSkewSeconds`, `maxCookieBytes` and `cookie.path` are validated, so a
  `NaN` skew can no longer silently disable expiry and the absolute-age cap.
- The secret's type and length, and the cookie name's charset, are validated in
  the constructor rather than on the first request.
- The write-side size check honours `maxCookieBytes`, so a lowered limit can no
  longer mint a cookie the same manager rejects on the next request.
- `serialize()` throws instead of silently emitting a cookie without `Secure`
  when `cookie.secure` is `"auto"` and the context does not say.
- `Session.set("__proto__", …)` stores an own property instead of rewiring the
  data object's prototype.
- A throwing `update()` callback rolls the session data back instead of leaving
  a partial mutation that a later write would persist.
- `unseal` no longer throws on a wrong-sized key, honouring its never-throws
  contract; `deriveKey` rejects a non-string `purpose` that would otherwise
  collapse every purpose onto one key.
- A rejected cookie's `isInvalid` flag is cleared once the session is re-sealed.
  Otherwise a second `persist`/`apply` emitted a clearing cookie that wiped the
  token the first call had just minted.
- Key rotation reports the specific rejection reason (`Token expired`) rather
  than the generic "invalid key or tampered" left behind by the last key tried.
- A `__Host-`/`__Secure-` cookie can be cleared over a plain-HTTP request
  (logout no longer throws), and the clearing header carries `Secure` so the
  browser actually honours it.
- `bindHost` with no resolvable host fails on every request rather than only on
  requests that happen to carry a cookie, and rejects an empty host.
- `apply()` builds the response before persisting, so a failure to rebuild
  cannot swallow the session write.

### Added

- **Key rotation.** `secret` accepts an ordered array: element 0 seals, all are
  accepted on unseal, and sessions opened under a non-primary key are re-issued
  under the primary one.
- **`SessionManager.apply(session, req, res)`** — attaches `Set-Cookie` by
  appending (never clobbering a route's cookie), copies headers so it works on
  `Response.redirect()`, and adds `Vary: Cookie`.
- **`loadFromCookieHeader()` / `serialize()`** — `Request`-free entry points.
- **`maxSessionAgeSeconds`** — an absolute lifetime cap that rolling expiry
  cannot extend, backed by a new immutable `iat0` claim.
- **`onInvalid` / `invalidReason`** — the reason a cookie was rejected is now
  surfaced instead of collapsed into a boolean.
- **`onOversize` / `onOversizeCookie`** — hooks for oversized cookies.
- **`Session.regenerate()`** — session fixation prevention on privilege change.
- **`Session.update()`** — dirty-tracked nested mutation.
- **`Session.peekFlash()`** — read flashes without consuming them.
- **`parseCookieHeaderAll()`** — every value for each cookie name.
- JSDoc across the entire public API; `deno doc --lint` is clean.
- `LICENSE`, `SECURITY.md`, CI and JSR OIDC publish workflows, `deno task`
  definitions, and a `publish.exclude` so tests no longer ship.

## 0.1.0

Initial release.
