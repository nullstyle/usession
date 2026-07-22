/**
 * Epoch tracks — revocation for stateless sessions.
 *
 * A sealed cookie is normally valid until it expires: there is no server-side
 * store to delete it from, so `destroy()` clears the browser's copy but not a
 * copy an attacker captured. An epoch track closes that gap without giving up
 * statelessness.
 *
 * Each track stamps a number into the cookie when it is written, and compares
 * that number against a current value when the cookie is read. Advancing the
 * current value invalidates every cookie stamped before it — immediately, for
 * every session on that track.
 *
 * Tracks are named and independent, so one session can be revoked along several
 * axes at once:
 *
 * - an **app** track ({@linkcode appEpoch}) revokes everyone at once;
 * - a **user** track ({@linkcode userEpoch}) revokes one user's sessions, for a
 *   password change or "sign out everywhere";
 * - a **custom** track revokes any axis you care about — a suspended tenant, a
 *   permission-model change, a device family, a session-schema version.
 *
 * Where epochs live and how they advance is entirely yours: a track is just a
 * function that returns the current number. This module stores nothing.
 *
 * @module
 */

import type { DefaultSessionData } from "./session.ts";

/** Request-scoped context handed to an epoch resolver. */
export type EpochContext = {
  /** The request being served, when there is one. */
  request: Request | undefined;
  /** Cookie the session is stored in. */
  cookieName: string;
};

/**
 * One revocation axis.
 *
 * @typeParam T Shape of the application data.
 */
export type EpochTrack<T extends object = DefaultSessionData> = {
  /**
   * Short, stable name. It is stored as a key inside every cookie on this
   * track, so keep it to a character or three, and never reuse a name for a
   * different meaning.
   */
  name: string;
  /**
   * The identity this track keys on, derived from the session data.
   *
   * Return `null` or `undefined` to skip the track entirely — an anonymous
   * session has no user to revoke, so a user track simply does not apply to it.
   * Omit this for a track with a single global value.
   *
   * Must be a pure function of `data`: the stored epoch is only meaningful
   * because it is guaranteed to belong to the key derived from the same sealed
   * payload.
   */
  key?: (data: T) => string | null | undefined;
  /**
   * The current epoch for `key`, as a finite number. Larger means newer.
   *
   * Called once per request per applicable track, and only after the cookie has
   * been authenticated. Wrap it in your own cache if the lookup is expensive —
   * see the README; `SessionManager` deliberately holds no cache of its own.
   */
  current: (
    key: string | null,
    ctx: EpochContext,
  ) => number | Promise<number>;
};

/** Why an epoch could not be resolved, and for which track. */
export type EpochErrorInfo = {
  /** Track whose resolver failed. */
  track: string;
  /** Key that was being resolved, or `null` for a global track. */
  key: string | null;
  /** Whatever the resolver threw, or the invalid value it returned. */
  error: unknown;
  /** The request being served, when there is one. */
  request: Request | undefined;
};

/**
 * What to do when a resolver fails.
 *
 * `"reject"` treats the session as revoked — safe, but an outage in your epoch
 * store logs everyone out. `"allow"` lets the request through with that track
 * unchecked — available, but revocation stops working during exactly the
 * incident where you might need it.
 */
export type EpochErrorAction = "reject" | "allow";

/** Outcome of checking one session's epochs. */
export type EpochCheckResult =
  | { ok: true; epochs: Record<string, number>; keys: Record<string, string> }
  | { ok: false; error: string };

/** Track name charset: short and boring, because it ships in every cookie. */
const TRACK_NAME_RE = /^[A-Za-z0-9_-]{1,16}$/;

/**
 * A track revoking every session at once.
 *
 * Advance the value returned by `current` to log out the entire application —
 * after a secret leak, say.
 *
 * @param current Returns the current global epoch.
 * @param name Track name. Defaults to `"a"`.
 *
 * @example
 * ```ts
 * import { appEpoch } from "@nullstyle/usession";
 *
 * let globalEpoch = 1;
 * const track = appEpoch(() => globalEpoch);
 * ```
 */
export function appEpoch<T extends object = DefaultSessionData>(
  current: (key: null, ctx: EpochContext) => number | Promise<number>,
  name = "a",
): EpochTrack<T> {
  return {
    name,
    current: (key, ctx) => current(key as null, ctx),
  };
}

/**
 * A track revoking one user's sessions at a time.
 *
 * @param key Extracts the user id from session data. Return `null` for an
 * anonymous session, which skips the track.
 * @param current Returns that user's current epoch.
 * @param name Track name. Defaults to `"u"`.
 *
 * @example
 * ```ts
 * import { userEpoch } from "@nullstyle/usession";
 *
 * const epochs = new Map<string, number>();
 * const track = userEpoch(
 *   (data: { uid?: string }) => data.uid ?? null,
 *   (uid) => epochs.get(uid!) ?? 0,
 * );
 * ```
 */
export function userEpoch<T extends object = DefaultSessionData>(
  key: (data: T) => string | null | undefined,
  current: (key: string, ctx: EpochContext) => number | Promise<number>,
  name = "u",
): EpochTrack<T> {
  return {
    name,
    key,
    current: (k, ctx) => current(k as string, ctx),
  };
}

/**
 * Validate a set of tracks, throwing on a configuration mistake.
 *
 * Called from the `SessionManager` constructor so a typo surfaces at startup
 * rather than as a 500 on someone's first page view.
 *
 * @throws {TypeError} If a name is malformed or duplicated, or `current` is not
 * a function.
 */
export function assertValidTracks<T extends object>(
  tracks: readonly EpochTrack<T>[],
): void {
  const seen = new Set<string>();

  for (const track of tracks) {
    if (!track || typeof track !== "object") {
      throw new TypeError("usession: each epoch track must be an object");
    }
    if (!TRACK_NAME_RE.test(track.name ?? "")) {
      throw new TypeError(
        `usession: epoch track name ${JSON.stringify(track.name)} must be ` +
          `1-16 characters of [A-Za-z0-9_-]`,
      );
    }
    if (seen.has(track.name)) {
      throw new TypeError(
        `usession: duplicate epoch track name ${JSON.stringify(track.name)}`,
      );
    }
    seen.add(track.name);

    if (typeof track.current !== "function") {
      throw new TypeError(
        `usession: epoch track ${JSON.stringify(track.name)} needs a ` +
          `current() function`,
      );
    }
    if (track.key !== undefined && typeof track.key !== "function") {
      throw new TypeError(
        `usession: epoch track ${JSON.stringify(track.name)} has a key that ` +
          `is not a function`,
      );
    }
  }
}

/**
 * Which tracks apply to a given session, and under what key.
 *
 * A track whose `key` yields nothing does not apply: there is no identity to
 * revoke, so the session is neither stamped nor checked on that axis.
 */
export function applicableTracks<T extends object>(
  tracks: readonly EpochTrack<T>[],
  data: T,
): Array<{ track: EpochTrack<T>; key: string | null }> {
  const out: Array<{ track: EpochTrack<T>; key: string | null }> = [];

  for (const track of tracks) {
    if (!track.key) {
      out.push({ track, key: null });
      continue;
    }
    const key = track.key(data);
    if (key === null || key === undefined || key === "") continue;
    out.push({ track, key });
  }

  return out;
}

/**
 * Resolve one track's current epoch, applying the error policy.
 *
 * A resolver that throws, or returns something that is not a finite number, is
 * an error — never silently treated as `0`, which would read as "never
 * revoked".
 *
 * @returns The epoch, or `null` when the policy says to skip this track.
 * @throws Whatever `onError` throws, when the app chooses to hard-fail.
 */
export async function resolveEpoch<T extends object>(
  track: EpochTrack<T>,
  key: string | null,
  ctx: EpochContext,
  onError: ((info: EpochErrorInfo) => EpochErrorAction) | undefined,
): Promise<number | null> {
  const fail = (error: unknown): number | null => {
    const info: EpochErrorInfo = {
      track: track.name,
      key,
      error,
      request: ctx.request,
    };
    // No policy configured means fail closed: the safe outcome should be the
    // one you get by accident.
    const action = onError ? onError(info) : "reject";
    if (action === "allow") return null;
    throw new EpochUnavailable(track.name, error);
  };

  let value: number;
  try {
    value = await track.current(key, ctx);
  } catch (e) {
    return fail(e);
  }

  if (typeof value !== "number" || !Number.isFinite(value)) {
    return fail(
      new TypeError(
        `epoch track ${JSON.stringify(track.name)} returned ` +
          `${JSON.stringify(value)}; expected a finite number`,
      ),
    );
  }

  return value;
}

/**
 * Signals that a track's epoch could not be resolved and the policy is to
 * reject.
 *
 * Internal control flow: the manager turns this into an invalid session on the
 * read path, and rethrows it on the write path.
 */
export class EpochUnavailable extends Error {
  /** Track that could not be resolved. */
  readonly track: string;

  /**
   * @param track Track that could not be resolved.
   * @param cause The underlying failure.
   */
  constructor(track: string, cause: unknown) {
    super(`Epoch unavailable: ${track}`, { cause });
    this.name = "EpochUnavailable";
    this.track = track;
  }
}
