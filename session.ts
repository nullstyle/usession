/**
 * Session class with Rails-like API and dirty tracking
 */

/**
 * Default session data shape (users can extend/customize)
 */
export type DefaultSessionData = {
  v?: number; // app schema version
  uid?: string; // internal user id
  csrf?: string;
  flash?: Record<string, string>;
};

/**
 * Session interface for type-safe access
 */
export interface ISession<T extends Record<string, unknown>> {
  readonly data: T;
  readonly isNew: boolean;
  readonly isDirty: boolean;
  readonly isInvalid: boolean;
  readonly isDestroyed: boolean;

  get<K extends keyof T>(key: K): T[K] | undefined;
  set<K extends keyof T>(key: K, value: T[K]): void;
  unset<K extends keyof T>(key: K): void;

  flash(key: string, value: string): void;
  consumeFlash(): Record<string, string>;

  destroy(): void;

  /** Mark as dirty (used by rolling expiry) */
  touch(): void;
}

/**
 * Session implementation with dirty tracking
 */
export class Session<T extends Record<string, unknown>>
  implements ISession<T> {
  private _data: T;
  private _isNew: boolean;
  private _isDirty: boolean;
  private _isInvalid: boolean;
  private _isDestroyed: boolean;

  constructor(
    data: T,
    opts: { isNew?: boolean; isInvalid?: boolean } = {},
  ) {
    this._data = data;
    this._isNew = opts.isNew ?? false;
    this._isDirty = false;
    this._isInvalid = opts.isInvalid ?? false;
    this._isDestroyed = false;
  }

  get data(): T {
    return this._data;
  }

  get isNew(): boolean {
    return this._isNew;
  }

  get isDirty(): boolean {
    return this._isDirty;
  }

  get isInvalid(): boolean {
    return this._isInvalid;
  }

  get isDestroyed(): boolean {
    return this._isDestroyed;
  }

  get<K extends keyof T>(key: K): T[K] | undefined {
    return this._data[key];
  }

  set<K extends keyof T>(key: K, value: T[K]): void {
    this._data[key] = value;
    this._isDirty = true;
  }

  unset<K extends keyof T>(key: K): void {
    delete this._data[key];
    this._isDirty = true;
  }

  flash(key: string, value: string): void {
    const flash = (this._data as Record<string, unknown>).flash as
      | Record<string, string>
      | undefined;
    if (flash) {
      flash[key] = value;
    } else {
      (this._data as Record<string, unknown>).flash = { [key]: value };
    }
    this._isDirty = true;
  }

  consumeFlash(): Record<string, string> {
    const flash = (this._data as Record<string, unknown>).flash as
      | Record<string, string>
      | undefined;
    if (flash) {
      delete (this._data as Record<string, unknown>).flash;
      this._isDirty = true;
      return flash;
    }
    return {};
  }

  destroy(): void {
    this._isDestroyed = true;
    this._isDirty = true;
  }

  touch(): void {
    this._isDirty = true;
  }
}
