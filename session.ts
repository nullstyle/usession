/**
 * Session state with Rails-like accessors and dirty tracking.
 *
 * @module
 */

/**
 * A conventional session shape.
 *
 * Used as the default type argument for {@linkcode Session} and
 * `SessionManager`. Every field is application-managed — the library reads none
 * of them.
 */
export type DefaultSessionData = {
  /** Application schema version, for your own migrations. */
  v?: number;
  /** Internal user id. */
  uid?: string;
  /** CSRF token, if your app issues one. */
  csrf?: string;
};

/**
 * Read/write access to a session.
 *
 * `SessionManager.load` returns a {@linkcode Session}, and every manager method
 * accepts this interface, so framework state can be typed against it.
 */
export interface ISession<T extends object = DefaultSessionData> {
  /**
   * The underlying data object.
   *
   * Mutating this directly does **not** mark the session dirty, and such writes
   * are silently dropped at persist time. Use {@linkcode ISession.set},
   * {@linkcode ISession.unset} or {@linkcode ISession.update}; if you must
   * mutate nested state in place, call {@linkcode ISession.touch} afterwards.
   */
  readonly data: T;
  /** True when no valid session cookie was presented. */
  readonly isNew: boolean;
  /** True when the session has unsaved changes. */
  readonly isDirty: boolean;
  /** True when a cookie was presented but rejected. */
  readonly isInvalid: boolean;
  /** True after {@linkcode ISession.destroy}. */
  readonly isDestroyed: boolean;
  /**
   * Why the presented cookie was rejected, when {@linkcode ISession.isInvalid}.
   *
   * Distinguishes a rotated secret from clock skew from a renamed cookie —
   * suitable for logs and metrics, not for showing to end users.
   */
  readonly invalidReason: string | undefined;

  /** Read a value. */
  get<K extends keyof T>(key: K): T[K] | undefined;
  /** Write a value, marking the session dirty if it changed. */
  set<K extends keyof T>(key: K, value: T[K]): void;
  /** Remove a key, marking the session dirty if it was present. */
  unset<K extends keyof T>(key: K): void;
  /** Mutate the data object through a callback and mark the session dirty. */
  update(fn: (data: T) => void): void;

  /** Queue a flash message. */
  flash(key: string, value: string): void;
  /** Read and clear all flash messages. */
  consumeFlash(): Record<string, string>;
  /** Read flash messages without clearing them. */
  peekFlash(): Record<string, string>;

  /** Clear the session and delete the cookie. */
  destroy(): void;
  /** Replace the session with an empty one, keeping the cookie. */
  regenerate(): void;

  /** Mark dirty without changing anything, forcing a re-issued cookie. */
  touch(): void;

  /**
   * Session birth time in unix seconds, or `undefined` for a new session.
   *
   * Read by `SessionManager.persist` to carry an absolute lifetime across
   * re-seals. Implement it as a stored value you round-trip; do not synthesize
   * a fresh timestamp, or an absolute cap can never expire.
   */
  readonly iat0: number | undefined;

  /**
   * Revocation epochs validated when this session was loaded, keyed by track
   * name, together with the key each was resolved under.
   *
   * Read by `SessionManager.serialize` so a re-seal can restamp without a
   * second store lookup, and skipped when the track's key has changed (a login
   * mid-request). `undefined` on a session that was never loaded from a cookie.
   */
  readonly epochs: EpochState | undefined;

  /**
   * Clear the dirty flag after a successful persist.
   *
   * Called by `SessionManager.persist`; not part of normal application use.
   */
  markPersisted(): void;
}

/**
 * Epoch values carried by a loaded session, with the keys they belong to.
 *
 * The keys matter: an epoch resolved for user `alice` must not be restamped
 * onto a session that has since logged in as `bob`.
 */
export type EpochState = {
  /** Track name to the epoch validated at load. */
  values: Record<string, number>;
  /** Track name to the key that epoch was resolved under, `null` if global. */
  keys: Record<string, string | null>;
};

/** Options for the {@linkcode Session} constructor. */
export type SessionInit = {
  /** True when no valid cookie was presented. */
  isNew?: boolean;
  /** True when a cookie was presented but rejected. */
  isInvalid?: boolean;
  /** Why the cookie was rejected. */
  invalidReason?: string;
  /** Flash messages carried in from the sealed payload. */
  flash?: Record<string, string>;
  /** Session birth time in unix seconds, carried forward across re-seals. */
  iat0?: number;
  /** Revocation epochs validated at load, with the keys they belong to. */
  epochs?: EpochState;
};

/**
 * Session implementation with dirty tracking.
 *
 * @typeParam T Shape of the application data.
 */
export class Session<T extends object = DefaultSessionData>
  implements ISession<T> {
  #data: T;
  #flash: Record<string, string>;
  #isNew: boolean;
  #isDirty: boolean;
  #isInvalid: boolean;
  #isDestroyed: boolean;
  #invalidReason: string | undefined;
  #iat0: number | undefined;
  #epochs: EpochState | undefined;

  /**
   * Construct a session around an existing data object.
   *
   * Normally you get one from `SessionManager.load` rather than calling this;
   * it is public so that tests and custom adapters can build one directly.
   *
   * @param data Initial data. Ownership transfers to the session.
   * @param init Load-time state from the manager.
   */
  constructor(data: T, init: SessionInit = {}) {
    this.#data = data;
    this.#flash = init.flash ?? {};
    this.#isNew = init.isNew ?? false;
    this.#isDirty = false;
    this.#isInvalid = init.isInvalid ?? false;
    this.#isDestroyed = false;
    this.#invalidReason = init.invalidReason;
    this.#iat0 = init.iat0;
    this.#epochs = init.epochs;
  }

  /** {@inheritDoc ISession.data} */
  get data(): T {
    return this.#data;
  }

  /** {@inheritDoc ISession.isNew} */
  get isNew(): boolean {
    return this.#isNew;
  }

  /** {@inheritDoc ISession.isDirty} */
  get isDirty(): boolean {
    return this.#isDirty;
  }

  /** {@inheritDoc ISession.isInvalid} */
  get isInvalid(): boolean {
    return this.#isInvalid;
  }

  /** {@inheritDoc ISession.isDestroyed} */
  get isDestroyed(): boolean {
    return this.#isDestroyed;
  }

  /** {@inheritDoc ISession.invalidReason} */
  get invalidReason(): string | undefined {
    return this.#invalidReason;
  }

  /**
   * Session birth time in unix seconds, or `undefined` for a new session.
   *
   * Carried forward across re-seals so an absolute lifetime cap survives
   * rolling expiry.
   */
  get iat0(): number | undefined {
    return this.#iat0;
  }

  /** {@inheritDoc ISession.epochs} */
  get epochs(): EpochState | undefined {
    return this.#epochs;
  }

  /** Throw if the session has been destroyed. */
  #assertWritable(op: string): void {
    if (this.#isDestroyed) {
      throw new Error(
        `usession: cannot ${op}() a destroyed session. ` +
          `A destroyed session always clears the cookie, so the write would be ` +
          `silently discarded — call regenerate() first if you meant to start ` +
          `a fresh session (for example, logging in right after logging out).`,
      );
    }
  }

  /** {@inheritDoc ISession.get} */
  get<K extends keyof T>(key: K): T[K] | undefined {
    return this.#data[key];
  }

  /**
   * {@inheritDoc ISession.set}
   *
   * Writing a value identical to the current one (by `Object.is`) is a no-op,
   * so idioms like `set("csrf", get("csrf") ?? newToken())` do not re-issue a
   * cookie on every request.
   *
   * @throws {Error} If the session has been destroyed.
   */
  set<K extends keyof T>(key: K, value: T[K]): void {
    this.#assertWritable("set");
    if (Object.hasOwn(this.#data, key) && Object.is(this.#data[key], value)) {
      return;
    }
    // `defineProperty` rather than `data[key] = value`: a plain assignment to
    // "__proto__" invokes the inherited setter on some engines and rewires the
    // object's prototype instead of storing a value.
    Object.defineProperty(this.#data, key, {
      value,
      writable: true,
      enumerable: true,
      configurable: true,
    });
    this.#isDirty = true;
  }

  /**
   * {@inheritDoc ISession.unset}
   *
   * @throws {Error} If the session has been destroyed.
   */
  unset<K extends keyof T>(key: K): void {
    this.#assertWritable("unset");
    if (!Object.hasOwn(this.#data, key)) return;
    delete this.#data[key];
    this.#isDirty = true;
  }

  /**
   * {@inheritDoc ISession.update}
   *
   * The escape hatch for nested mutation, which plain property writes cannot
   * track: `session.update((d) => d.cart.items.push(item))`.
   *
   * @throws {Error} If the session has been destroyed.
   */
  update(fn: (data: T) => void): void {
    this.#assertWritable("update");

    // Snapshot first: a callback that mutates and then throws would otherwise
    // leave a half-applied change that gets persisted as soon as anything else
    // dirties the session (rolling expiry, say).
    let snapshot: T | undefined;
    try {
      snapshot = structuredClone(this.#data);
    } catch {
      // Not structured-cloneable; proceed without rollback rather than refuse.
      snapshot = undefined;
    }

    try {
      fn(this.#data);
    } catch (e) {
      if (snapshot !== undefined) {
        this.#wipeData();
        Object.assign(this.#data, snapshot);
      }
      throw e;
    }

    this.#isDirty = true;
  }

  /**
   * {@inheritDoc ISession.flash}
   *
   * Flash messages live beside the session data, not inside it, so a `flash`
   * key in your own session shape is untouched.
   *
   * Nothing sweeps flashes automatically — a message survives until
   * {@linkcode Session.consumeFlash} is called, which may be several requests
   * later if the next one is a prefetch or a redirect.
   *
   * @throws {Error} If the session has been destroyed.
   */
  flash(key: string, value: string): void {
    this.#assertWritable("flash");
    this.#flash[key] = value;
    this.#isDirty = true;
  }

  /** {@inheritDoc ISession.consumeFlash} */
  consumeFlash(): Record<string, string> {
    const flash = this.#flash;
    if (Object.keys(flash).length === 0) return {};
    this.#flash = {};
    this.#isDirty = true;
    return flash;
  }

  /** {@inheritDoc ISession.peekFlash} */
  peekFlash(): Record<string, string> {
    return { ...this.#flash };
  }

  /**
   * {@inheritDoc ISession.destroy}
   *
   * Wipes the data immediately, so later readers in the same request cannot see
   * stale identity. Subsequent writes throw; call
   * {@linkcode Session.regenerate} to start a fresh session instead.
   */
  destroy(): void {
    // Clear in place rather than rebinding, so a caller that already grabbed
    // `session.data` cannot keep reading the pre-destroy identity.
    this.#wipeData();
    this.#flash = {};
    this.#isDestroyed = true;
    this.#isDirty = true;
  }

  /** Remove every own key from the data object, in place. */
  #wipeData(): void {
    for (const key of Object.keys(this.#data)) {
      delete (this.#data as Record<string, unknown>)[key];
    }
  }

  /**
   * {@inheritDoc ISession.regenerate}
   *
   * Discards all state and mints a new session on the next persist, while
   * leaving the session usable. Call this on any privilege change — login,
   * logout-then-login, role elevation, starting or stopping impersonation.
   */
  regenerate(): void {
    this.#wipeData();
    this.#flash = {};
    this.#isNew = true;
    this.#isDestroyed = false;
    this.#isInvalid = false;
    this.#invalidReason = undefined;
    this.#iat0 = undefined;
    // Drop the cached epochs too: this is a different session now, possibly a
    // different user, so persist must resolve fresh values for it.
    this.#epochs = undefined;
    this.#isDirty = true;
  }

  /**
   * {@inheritDoc ISession.touch}
   *
   * @throws {Error} If the session has been destroyed.
   */
  touch(): void {
    this.#assertWritable("touch");
    this.#isDirty = true;
  }

  /**
   * {@inheritDoc ISession.markPersisted}
   *
   * Makes a second `persist` in the same request a no-op rather than minting a
   * second, independently valid token.
   */
  markPersisted(): void {
    this.#isDirty = false;
    // The rejected cookie has now been replaced or cleared, so the session is
    // no longer "invalid". Leaving the flag set would make a second persist
    // emit a clearing cookie that wipes the token the first one just minted.
    this.#isInvalid = false;
    this.#invalidReason = undefined;
  }
}
