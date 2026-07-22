# Security Policy

## Reporting a vulnerability

Please report security issues **privately**, not as a public GitHub issue.

Use [GitHub's private vulnerability reporting][gh-pvr] on this repository
(Security → Report a vulnerability). If that is unavailable to you, open a
public issue that says only that you have a security report and asks for a
private channel — do not include details.

Expect an initial response within 7 days. If a fix is warranted, we will
coordinate a release and credit you in the changelog unless you prefer
otherwise.

[gh-pvr]: https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability

## Supported versions

Only the latest minor release receives security fixes.

| Version | Supported |
| ------- | --------- |
| 0.2.x   | yes       |
| 0.1.x   | no        |

## Threat model

usession is a **stateless** session library. The entire session lives in an
encrypted cookie; there is no server-side store. That shapes what it can and
cannot defend against.

### What it protects

- **Confidentiality and integrity of session data.** The payload is sealed with
  XSalsa20-Poly1305 under a key derived from your secret via HKDF-SHA256. A
  client cannot read or forge session contents.
- **Context binding.** The cookie name, the `purpose` label and (optionally) the
  host are sealed inside the payload and re-checked on load, so a token minted
  for one cookie, service or host is not accepted by another.
- **No compression.** The payload is deliberately never compressed, which avoids
  the CRIME/BREACH class of attack against secrets held in the session. Do not
  add compression.

### What it does not protect

- **Revocation, unless you configure it.** By default a sealed cookie is valid
  until it expires: logging out clears the browser's copy but cannot invalidate
  a copy an attacker already captured. Configure `epochTracks` for immediate
  revocation — per app, per user, or on any axis you choose — and keep
  `ttlSeconds` short with `maxSessionAgeSeconds` set as a backstop.
- **A leaked secret.** Anyone holding the secret can mint a session for any
  user. Rotate with the array form of `secret` (see the README) and treat the
  secret as the highest-value key in your system.
- **CSRF.** `SameSite=Lax` is defense in depth, not a complete defense —
  top-level cross-site GET navigations still send the cookie. Use your own CSRF
  token on state-changing routes.
- **XSS.** `HttpOnly` keeps the cookie out of `document.cookie`, but script
  running on your origin can still act as the user.

## Deployment requirements

- Generate the secret with `openssl rand -base64 32` or equivalent. Secrets
  shorter than 32 bytes are rejected.
- Behind a TLS-terminating proxy, set `trustProxy: true` (with a proxy that
  _overwrites_ `X-Forwarded-*`) or `cookie: { secure: true }`.
- Use a `__Host-` cookie name in production.
- Give every service that shares a secret its own `purpose`.
- Configure at least a user `epochTrack` if you need password changes or "sign
  out everywhere" to take effect before the session expires. Note that a failing
  epoch resolver rejects sessions by default; override with `onEpochError` only
  if you would rather stay available than stay revocable during an outage.
