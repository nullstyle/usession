import { assertEquals } from "jsr:@std/assert";
import { Session } from "./session.ts";

Deno.test("Session get/set", () => {
  const session = new Session<{ uid?: string }>({});

  assertEquals(session.get("uid"), undefined);
  assertEquals(session.isDirty, false);

  session.set("uid", "user123");

  assertEquals(session.get("uid"), "user123");
  assertEquals(session.isDirty, true);
});

Deno.test("Session unset", () => {
  const session = new Session<{ uid?: string }>({ uid: "user123" });
  session.unset("uid");
  assertEquals(session.get("uid"), undefined);
  assertEquals(session.isDirty, true);
});

Deno.test("Session destroy", () => {
  const session = new Session<{ uid?: string }>({ uid: "user123" });
  assertEquals(session.isDestroyed, false);
  session.destroy();
  assertEquals(session.isDestroyed, true);
  assertEquals(session.isDirty, true);
});

Deno.test("Session isNew/isInvalid flags", () => {
  const s1 = new Session<{ uid?: string }>({}, { isNew: true, isInvalid: true });
  assertEquals(s1.isNew, true);
  assertEquals(s1.isInvalid, true);

  const s2 = new Session<{ uid?: string }>({}, { isNew: false, isInvalid: false });
  assertEquals(s2.isNew, false);
  assertEquals(s2.isInvalid, false);
});

Deno.test("Session flash", () => {
  const session = new Session<{ flash?: Record<string, string> }>({});

  // First flash
  session.flash("notice", "Hello!");
  assertEquals(session.isDirty, true);
  
  // Second flash (append to existing)
  session.flash("error", "Bad!");
  
  const flash = session.consumeFlash();
  assertEquals(flash, { notice: "Hello!", error: "Bad!" });
  assertEquals(session.get("flash"), undefined);
  assertEquals(session.isDirty, true);
});

Deno.test("Session consumeFlash empty", () => {
  const session = new Session<{ flash?: Record<string, string> }>({});
  const flash = session.consumeFlash();
  assertEquals(flash, {});
  assertEquals(session.isDirty, false); // No change if no flash
});

Deno.test("Session touch", () => {
    const session = new Session({});
    assertEquals(session.isDirty, false);
    session.touch();
    assertEquals(session.isDirty, true);
});
