import {
  assertEquals,
  assertMatch,
  assertNotStrictEquals,
  assertStrictEquals,
  assertThrows,
} from "@std/assert";
import { type DefaultSessionData, type ISession, Session } from "./session.ts";

type Data = {
  uid?: string;
  n?: number;
  obj?: { a: number };
  maybe?: string;
};

// --- construction -----------------------------------------------------------

Deno.test("constructor defaults leave the session clean and valid", () => {
  const s = new Session<Data>({});
  assertEquals(s.data, {});
  assertEquals(s.isNew, false);
  assertEquals(s.isDirty, false);
  assertEquals(s.isInvalid, false);
  assertEquals(s.isDestroyed, false);
  assertEquals(s.invalidReason, undefined);
  assertEquals(s.iat0, undefined);
  assertEquals(s.peekFlash(), {});
});

Deno.test("constructor takes ownership of the data object", () => {
  const data: Data = { uid: "u1" };
  const s = new Session<Data>(data);
  assertStrictEquals(s.data, data);
});

Deno.test("constructor honors isNew from SessionInit", () => {
  const s = new Session<Data>({}, { isNew: true });
  assertEquals(s.isNew, true);
});

Deno.test("constructor honors isInvalid and invalidReason from SessionInit", () => {
  const s = new Session<Data>({}, {
    isInvalid: true,
    invalidReason: "bad-mac",
  });
  assertEquals(s.isInvalid, true);
  assertEquals(s.invalidReason, "bad-mac");
});

Deno.test("constructor honors iat0 from SessionInit", () => {
  const s = new Session<Data>({}, { iat0: 1234 });
  assertEquals(s.iat0, 1234);
});

Deno.test("constructor honors flash from SessionInit", () => {
  const s = new Session<Data>({}, { flash: { notice: "hello" } });
  assertEquals(s.peekFlash(), { notice: "hello" });
  assertEquals(s.isDirty, false);
});

// --- get / set / unset ------------------------------------------------------

Deno.test("get returns undefined for an absent key", () => {
  const s = new Session<Data>({});
  assertEquals(s.get("uid"), undefined);
});

Deno.test("set then get round-trips a value", () => {
  const s = new Session<Data>({});
  s.set("uid", "u1");
  assertEquals(s.get("uid"), "u1");
  assertEquals(s.data.uid, "u1");
});

Deno.test("set on a fresh key marks the session dirty", () => {
  const s = new Session<Data>({});
  s.set("uid", "u1");
  assertEquals(s.isDirty, true);
});

Deno.test("unset removes a present key and marks dirty", () => {
  const s = new Session<Data>({ uid: "u1" });
  s.unset("uid");
  assertEquals(s.get("uid"), undefined);
  assertEquals(Object.hasOwn(s.data, "uid"), false);
  assertEquals(s.isDirty, true);
});

// --- no-op write guard ------------------------------------------------------

Deno.test("set to an Object.is-identical primitive does not dirty", () => {
  const s = new Session<Data>({ uid: "u1" });
  s.set("uid", "u1");
  assertEquals(s.isDirty, false);
});

Deno.test("set to a different primitive dirties", () => {
  const s = new Session<Data>({ uid: "u1" });
  s.set("uid", "u2");
  assertEquals(s.isDirty, true);
});

Deno.test("set to the identical object reference does not dirty", () => {
  const obj = { a: 1 };
  const s = new Session<Data>({ obj });
  s.set("obj", obj);
  assertEquals(s.isDirty, false);
});

Deno.test("set to a structurally equal but distinct object does dirty", () => {
  const s = new Session<Data>({ obj: { a: 1 } });
  s.set("obj", { a: 1 });
  assertEquals(s.isDirty, true);
});

Deno.test("set uses Object.is semantics for NaN", () => {
  const s = new Session<Data>({ n: NaN });
  s.set("n", NaN);
  assertEquals(s.isDirty, false);
});

Deno.test("set uses Object.is semantics for -0 vs 0", () => {
  const s = new Session<Data>({ n: 0 });
  s.set("n", -0);
  assertEquals(s.isDirty, true);
});

Deno.test("set undefined on an own property already holding undefined does not dirty", () => {
  const s = new Session<Data>({ maybe: undefined });
  assertEquals(Object.hasOwn(s.data, "maybe"), true);
  s.set("maybe", undefined);
  assertEquals(s.isDirty, false);
});

Deno.test("set undefined on an entirely absent key dirties and creates the property", () => {
  const s = new Session<Data>({});
  s.set("maybe", undefined);
  assertEquals(s.isDirty, true);
  assertEquals(Object.hasOwn(s.data, "maybe"), true);
});

Deno.test("unset on an absent key does not dirty", () => {
  const s = new Session<Data>({});
  s.unset("uid");
  assertEquals(s.isDirty, false);
});

Deno.test("unset on an own property holding undefined dirties", () => {
  const s = new Session<Data>({ maybe: undefined });
  s.unset("maybe");
  assertEquals(s.isDirty, true);
  assertEquals(Object.hasOwn(s.data, "maybe"), false);
});

Deno.test("a no-op set does not clear an already-set dirty flag", () => {
  const s = new Session<Data>({});
  s.set("uid", "u1");
  s.set("uid", "u1");
  assertEquals(s.isDirty, true);
});

Deno.test("a no-op unset does not clear an already-set dirty flag", () => {
  const s = new Session<Data>({});
  s.set("uid", "u1");
  s.unset("n");
  assertEquals(s.isDirty, true);
});

Deno.test("set does not treat an inherited property as present", () => {
  const proto = { uid: "inherited" };
  const s = new Session<Data>(Object.create(proto) as Data);
  s.set("uid", "inherited");
  assertEquals(s.isDirty, true);
  assertEquals(Object.hasOwn(s.data, "uid"), true);
});

// --- update -----------------------------------------------------------------

Deno.test("update runs the callback against the live data object", () => {
  const s = new Session<Data>({ obj: { a: 1 } });
  s.update((d) => {
    d.obj!.a = 2;
  });
  assertEquals(s.get("obj"), { a: 2 });
});

Deno.test("update marks dirty even when the callback changes nothing", () => {
  const s = new Session<Data>({});
  s.update(() => {});
  assertEquals(s.isDirty, true);
});

Deno.test("update receives the same object identity as session.data", () => {
  const s = new Session<Data>({});
  let seen: Data | undefined;
  s.update((d) => {
    seen = d;
  });
  assertStrictEquals(seen, s.data);
});

// --- documented footgun -----------------------------------------------------

Deno.test("direct session.data mutation does not mark dirty", () => {
  const s = new Session<Data>({});
  s.data.uid = "u1";
  assertEquals(s.get("uid"), "u1");
  assertEquals(s.isDirty, false);
});

Deno.test("touch after a direct data mutation marks dirty", () => {
  const s = new Session<Data>({});
  s.data.uid = "u1";
  s.touch();
  assertEquals(s.isDirty, true);
});

// --- destroy ----------------------------------------------------------------

Deno.test("destroy wipes data and flash and sets the flags", () => {
  const s = new Session<Data>({ uid: "u1" }, { flash: { notice: "hi" } });
  s.destroy();
  assertEquals(s.data, {});
  assertEquals(s.peekFlash(), {});
  assertEquals(s.isDestroyed, true);
  assertEquals(s.isDirty, true);
});

Deno.test("get returns undefined after destroy", () => {
  const s = new Session<Data>({ uid: "u1" });
  s.destroy();
  assertEquals(s.get("uid"), undefined);
});

Deno.test("set after destroy throws and mentions regenerate", () => {
  const s = new Session<Data>({});
  s.destroy();
  const err = assertThrows(() => s.set("uid", "u1"), Error);
  assertMatch(err.message, /regenerate\(\)/);
});

Deno.test("unset after destroy throws and mentions regenerate", () => {
  const s = new Session<Data>({ uid: "u1" });
  s.destroy();
  const err = assertThrows(() => s.unset("uid"), Error);
  assertMatch(err.message, /regenerate\(\)/);
});

Deno.test("update after destroy throws and mentions regenerate", () => {
  const s = new Session<Data>({});
  s.destroy();
  const err = assertThrows(() => s.update(() => {}), Error);
  assertMatch(err.message, /regenerate\(\)/);
});

Deno.test("flash after destroy throws and mentions regenerate", () => {
  const s = new Session<Data>({});
  s.destroy();
  const err = assertThrows(() => s.flash("notice", "hi"), Error);
  assertMatch(err.message, /regenerate\(\)/);
});

Deno.test("touch after destroy throws and mentions regenerate", () => {
  const s = new Session<Data>({});
  s.destroy();
  const err = assertThrows(() => s.touch(), Error);
  assertMatch(err.message, /regenerate\(\)/);
});

Deno.test("consumeFlash and peekFlash stay callable after destroy", () => {
  const s = new Session<Data>({}, { flash: { notice: "hi" } });
  s.destroy();
  assertEquals(s.peekFlash(), {});
  assertEquals(s.consumeFlash(), {});
});

Deno.test("destroy leaves load-time state (isNew, isInvalid, iat0) alone", () => {
  const s = new Session<Data>({ uid: "u1" }, {
    isNew: true,
    isInvalid: true,
    invalidReason: "bad-mac",
    iat0: 9,
  });
  s.destroy();
  assertEquals(s.isNew, true);
  assertEquals(s.isInvalid, true);
  assertEquals(s.invalidReason, "bad-mac");
  assertEquals(s.iat0, 9);
});

Deno.test("destroy wipes the data in place, so a held reference is cleared too", () => {
  const original: Data = { uid: "u1" };
  const s = new Session<Data>(original);
  s.destroy();
  // Same object identity, emptied — a caller holding `original` (framework
  // glue, or a handler that did `const d = session.data`) must not keep
  // reading the pre-destroy identity.
  assertStrictEquals(s.data, original);
  assertEquals(original.uid, undefined);
  assertEquals(s.data, {});
});

Deno.test("destroy is idempotent", () => {
  const s = new Session<Data>({ uid: "u1" });
  s.destroy();
  s.destroy();
  assertEquals(s.isDestroyed, true);
  assertEquals(s.data, {});
});

// --- regenerate -------------------------------------------------------------

Deno.test("regenerate clears data and flash and resets load-time state", () => {
  const s = new Session<Data>({ uid: "u1" }, {
    isInvalid: true,
    invalidReason: "bad-mac",
    flash: { notice: "hi" },
    iat0: 5,
  });
  s.regenerate();
  assertEquals(s.data, {});
  assertEquals(s.peekFlash(), {});
  assertEquals(s.isInvalid, false);
  assertEquals(s.invalidReason, undefined);
  assertEquals(s.iat0, undefined);
  assertEquals(s.isDestroyed, false);
  assertEquals(s.isNew, true);
  assertEquals(s.isDirty, true);
});

Deno.test("regenerate makes a destroyed session writable again", () => {
  const s = new Session<Data>({ uid: "u1" });
  s.destroy();
  s.regenerate();
  s.set("uid", "u2");
  assertEquals(s.get("uid"), "u2");
  assertEquals(s.isDestroyed, false);
});

Deno.test("regenerate leaves every writer usable", () => {
  const s = new Session<Data>({ uid: "u1" });
  s.regenerate();
  s.flash("notice", "hi");
  s.touch();
  s.update(() => {});
  s.set("uid", "u2");
  s.unset("uid");
  assertEquals(s.peekFlash(), { notice: "hi" });
  assertEquals(s.data, {});
});

Deno.test("regenerate wipes the data in place, so a held reference is cleared too", () => {
  const original: Data = { uid: "u1" };
  const s = new Session<Data>(original);
  s.regenerate();
  assertStrictEquals(s.data, original);
  assertEquals(original.uid, undefined);
  assertEquals(s.data, {});
});

Deno.test("regenerate on a clean session dirties it", () => {
  const s = new Session<Data>({});
  assertEquals(s.isDirty, false);
  s.regenerate();
  assertEquals(s.isDirty, true);
});

// --- flash ------------------------------------------------------------------

Deno.test("flash stores outside data so a flash data key is untouched", () => {
  type D = { flash?: string };
  const s = new Session<D>({});
  s.set("flash", "mine");
  s.flash("notice", "hi");
  assertEquals(s.get("flash"), "mine");
  assertEquals(s.data, { flash: "mine" });
  assertEquals(s.peekFlash(), { notice: "hi" });
});

Deno.test("flash messages do not leak into the data object", () => {
  type D = { flash?: string };
  const s = new Session<D>({});
  s.flash("notice", "hi");
  assertEquals(s.get("flash"), undefined);
  assertEquals(s.data, {});
});

Deno.test("consumeFlash does not remove a same-named data key", () => {
  type D = { flash?: string };
  const s = new Session<D>({ flash: "mine" });
  s.flash("notice", "hi");
  assertEquals(s.consumeFlash(), { notice: "hi" });
  assertEquals(s.get("flash"), "mine");
});

Deno.test("unset of a flash-named data key leaves flash messages intact", () => {
  type D = { flash?: string };
  const s = new Session<D>({ flash: "mine" }, { flash: { notice: "hi" } });
  s.unset("flash");
  assertEquals(s.data, {});
  assertEquals(s.peekFlash(), { notice: "hi" });
});

Deno.test("flash does not dirty via the data object", () => {
  type D = { flash?: string };
  const s = new Session<D>({ flash: "mine" });
  s.flash("flash", "message");
  assertEquals(s.get("flash"), "mine");
  assertEquals(s.peekFlash(), { flash: "message" });
});

Deno.test("flash marks the session dirty", () => {
  const s = new Session<Data>({});
  s.flash("notice", "hi");
  assertEquals(s.isDirty, true);
});

Deno.test("multiple flash keys accumulate", () => {
  const s = new Session<Data>({});
  s.flash("notice", "hi");
  s.flash("alert", "uh oh");
  assertEquals(s.peekFlash(), { notice: "hi", alert: "uh oh" });
});

Deno.test("flash overwrites a repeated key", () => {
  const s = new Session<Data>({});
  s.flash("notice", "one");
  s.flash("notice", "two");
  assertEquals(s.peekFlash(), { notice: "two" });
});

Deno.test("consumeFlash returns the messages and clears them", () => {
  const s = new Session<Data>({}, { flash: { notice: "hi" } });
  assertEquals(s.consumeFlash(), { notice: "hi" });
  assertEquals(s.peekFlash(), {});
});

Deno.test("consumeFlash with messages marks the session dirty", () => {
  const s = new Session<Data>({}, { flash: { notice: "hi" } });
  s.consumeFlash();
  assertEquals(s.isDirty, true);
});

Deno.test("consumeFlash on an empty store returns {} and does not dirty", () => {
  const s = new Session<Data>({});
  assertEquals(s.consumeFlash(), {});
  assertEquals(s.isDirty, false);
});

Deno.test("a second consumeFlash returns {} and does not re-dirty", () => {
  const s = new Session<Data>({}, { flash: { notice: "hi" } });
  s.consumeFlash();
  s.markPersisted();
  assertEquals(s.consumeFlash(), {});
  assertEquals(s.isDirty, false);
});

Deno.test("mutating the consumeFlash result does not revive session flash", () => {
  const s = new Session<Data>({}, { flash: { notice: "hi" } });
  const taken = s.consumeFlash();
  taken.notice = "tampered";
  assertEquals(s.peekFlash(), {});
});

Deno.test("peekFlash returns a copy that cannot mutate session state", () => {
  const s = new Session<Data>({}, { flash: { notice: "hi" } });
  const peeked = s.peekFlash();
  peeked.notice = "tampered";
  peeked.extra = "nope";
  assertEquals(s.peekFlash(), { notice: "hi" });
});

Deno.test("peekFlash returns a fresh object each call", () => {
  const s = new Session<Data>({}, { flash: { notice: "hi" } });
  assertNotStrictEquals(s.peekFlash(), s.peekFlash());
});

Deno.test("peekFlash does not dirty the session", () => {
  const s = new Session<Data>({}, { flash: { notice: "hi" } });
  s.peekFlash();
  assertEquals(s.isDirty, false);
});

// --- touch / markPersisted --------------------------------------------------

Deno.test("touch dirties without changing data", () => {
  const s = new Session<Data>({ uid: "u1" });
  s.touch();
  assertEquals(s.isDirty, true);
  assertEquals(s.data, { uid: "u1" });
});

Deno.test("markPersisted clears the dirty flag", () => {
  const s = new Session<Data>({});
  s.set("uid", "u1");
  s.markPersisted();
  assertEquals(s.isDirty, false);
});

Deno.test("a set after markPersisted dirties again", () => {
  const s = new Session<Data>({});
  s.set("uid", "u1");
  s.markPersisted();
  s.set("uid", "u2");
  assertEquals(s.isDirty, true);
});

Deno.test("a touch after markPersisted dirties again", () => {
  const s = new Session<Data>({});
  s.touch();
  s.markPersisted();
  s.touch();
  assertEquals(s.isDirty, true);
});

Deno.test("a flash after markPersisted dirties again", () => {
  const s = new Session<Data>({});
  s.flash("notice", "one");
  s.markPersisted();
  s.flash("notice", "two");
  assertEquals(s.isDirty, true);
});

Deno.test("markPersisted leaves data, flash and other flags alone", () => {
  const s = new Session<Data>({ uid: "u1" }, {
    isNew: true,
    flash: { notice: "hi" },
    iat0: 7,
  });
  s.touch();
  s.markPersisted();
  assertEquals(s.data, { uid: "u1" });
  assertEquals(s.peekFlash(), { notice: "hi" });
  assertEquals(s.isNew, true);
  assertEquals(s.iat0, 7);
});

Deno.test("markPersisted works on a destroyed session", () => {
  const s = new Session<Data>({});
  s.destroy();
  s.markPersisted();
  assertEquals(s.isDirty, false);
  assertEquals(s.isDestroyed, true);
});

// --- type ergonomics --------------------------------------------------------

Deno.test("Session works with the default type argument", () => {
  const data: DefaultSessionData = {};
  const s = new Session(data);
  s.set("uid", "u1");
  s.set("v", 1);
  assertEquals(s.get("uid"), "u1");
  assertEquals(s.get("v"), 1);
  assertEquals(s.get("csrf"), undefined);
});

Deno.test("Session accepts DefaultSessionData as an explicit type argument", () => {
  const s = new Session<DefaultSessionData>({});
  s.set("csrf", "tok");
  assertEquals(s.get("csrf"), "tok");
});

interface InterfaceShape {
  uid?: string;
  roles?: string[];
}

Deno.test("an interface-declared shape is accepted as the type argument", () => {
  const s = new Session<InterfaceShape>({ uid: "u1" });
  s.set("roles", ["admin"]);
  assertEquals(s.get("roles"), ["admin"]);
});

Deno.test("Session is assignable to ISession", () => {
  const s: ISession<InterfaceShape> = new Session<InterfaceShape>({});
  s.set("uid", "u1");
  assertEquals(s.get("uid"), "u1");
});

Deno.test("set is compile-time typed but does not validate at runtime", () => {
  const s = new Session<Data>({});
  // @ts-expect-error uid is declared as a string
  s.set("uid", 42);
  assertEquals(s.get("uid") as unknown, 42);
});

Deno.test("update on an ISession-typed reference tracks nested mutation", () => {
  const s: ISession<Data> = new Session<Data>({ obj: { a: 1 } });
  s.update((d) => {
    d.obj!.a = 2;
  });
  assertEquals(s.isDirty, true);
  assertEquals(s.get("obj"), { a: 2 });
});

Deno.test("get rejects a key outside the declared shape", () => {
  const s = new Session<Data>({});
  // @ts-expect-error nope is not a key of Data
  assertEquals(s.get("nope"), undefined);
});
