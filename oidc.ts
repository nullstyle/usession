/**
 * OIDC helper module for storing transient login state in session
 */

import { encodeBase64Url } from "@std/encoding/base64url";
import type { ISession } from "./session.ts";

type OidcSessionData = {
  oidc?: {
    state?: string;
    nonce?: string;
    pkceVerifier?: string;
    returnTo?: string;
  };
  uid?: string;
  sub?: string;
  iss?: string;
  claims?: {
    email?: string;
    name?: string;
  };
};

/**
 * Generate a random base64url string of given byte length
 */
function randomB64u(byteLength: number): string {
  const bytes = crypto.getRandomValues(new Uint8Array(byteLength));
  return encodeBase64Url(bytes);
}

/**
 * Compute PKCE challenge from verifier using S256 method
 */
async function computePkceChallenge(verifier: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return encodeBase64Url(new Uint8Array(hash));
}

export type BeginOidcLoginResult = {
  state: string;
  nonce: string;
  pkceVerifier: string;
  pkceChallenge: string;
};

/**
 * Begin OIDC login by storing transient state in session
 *
 * Returns the values needed for the authorization request
 */
export async function beginOidcLogin(
  session: ISession<OidcSessionData>,
  params: { returnTo?: string } = {},
): Promise<BeginOidcLoginResult> {
  const state = randomB64u(32);
  const nonce = randomB64u(32);
  const pkceVerifier = randomB64u(32);
  const pkceChallenge = await computePkceChallenge(pkceVerifier);

  session.set("oidc", {
    state,
    nonce,
    pkceVerifier,
    returnTo: params.returnTo,
  });

  return {
    state,
    nonce,
    pkceVerifier,
    pkceChallenge,
  };
}

export type VerifyOidcCallbackResult =
  | { ok: true; nonce: string; pkceVerifier: string; returnTo?: string }
  | { ok: false; error: string };

/**
 * Verify OIDC callback state matches session
 *
 * Returns the nonce and pkceVerifier for token verification
 */
export function verifyOidcCallback(
  session: ISession<OidcSessionData>,
  params: { state: string },
): VerifyOidcCallbackResult {
  const oidc = session.get("oidc");

  if (!oidc) {
    return { ok: false, error: "No OIDC state in session" };
  }

  if (!oidc.state) {
    return { ok: false, error: "No state in session OIDC data" };
  }

  if (oidc.state !== params.state) {
    return { ok: false, error: "State mismatch" };
  }

  return {
    ok: true,
    nonce: oidc.nonce ?? "",
    pkceVerifier: oidc.pkceVerifier ?? "",
    returnTo: oidc.returnTo,
  };
}

export type CompleteOidcLoginParams = {
  uid: string;
  sub: string;
  iss: string;
  claims?: {
    email?: string;
    name?: string;
  };
};

/**
 * Complete OIDC login by clearing handshake fields and setting identity
 */
export function completeOidcLogin(
  session: ISession<OidcSessionData>,
  params: CompleteOidcLoginParams,
): void {
  // Get returnTo before clearing oidc
  const returnTo = session.get("oidc")?.returnTo;

  // Clear OIDC handshake fields
  session.unset("oidc");

  // Set identity
  session.set("uid", params.uid);
  session.set("sub", params.sub);
  session.set("iss", params.iss);

  if (params.claims) {
    session.set("claims", params.claims);
  }
}

/**
 * Get the returnTo URL from session (call before completeOidcLogin clears it)
 */
export function getOidcReturnTo(
  session: ISession<OidcSessionData>,
): string | undefined {
  return session.get("oidc")?.returnTo;
}
