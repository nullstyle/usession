import { assertEquals, assertNotEquals, assertThrows } from "jsr:@std/assert";
import { SessionManager } from "./manager.ts";
import { deriveKey, seal } from "./seal.ts";

Deno.test("SessionManager constructor throws if no secret", () => {
    // @ts-ignore: testing invalid input
    assertThrows(() => new SessionManager({}), Error, "secret is required");
});

Deno.test("SessionManager load: no cookie", async () => {
    const mgr = new SessionManager({ secret: "s", cookieName: "c" });
    const req = new Request("http://localhost/");
    const session = await mgr.load(req);
    assertEquals(session.isNew, true);
    assertEquals(session.isInvalid, false);
});

Deno.test("SessionManager load: cookie too large", async () => {
    const mgr = new SessionManager({ secret: "s", cookieName: "c", maxCookieBytes: 10 });
    const req = new Request("http://localhost/", {
        headers: { cookie: "c=123456789012345" }
    });
    const session = await mgr.load(req);
    assertEquals(session.isNew, true);
    assertEquals(session.isInvalid, true);
});

Deno.test("SessionManager load: valid cookie", async () => {
    const mgr = new SessionManager({ secret: "s", cookieName: "c" });
    const key = await deriveKey("s", "session");
    const token = seal({ u: 1 }, key, { cookieName: "c", purpose: "session" });
    
    const req = new Request("http://localhost/", {
        headers: { cookie: `c=${token}` }
    });
    const session = await mgr.load(req);
    assertEquals(session.isNew, false);
    assertEquals(session.get("u"), 1);
});

Deno.test("SessionManager load: host binding success", async () => {
    const mgr = new SessionManager({ secret: "s", cookieName: "c", bindHost: true });
    const key = await deriveKey("s", "session");
    const token = seal({ u: 1 }, key, { cookieName: "c", purpose: "session", host: "localhost:8000" });
    const req = new Request("http://localhost:8000/", {
        headers: { 
            cookie: `c=${token}`,
            host: "localhost:8000"
        }
    });
    const session = await mgr.load(req);
    assertEquals(session.isNew, false);
});

Deno.test("SessionManager load: host binding fail", async () => {
    const mgr = new SessionManager({ secret: "s", cookieName: "c", bindHost: true });
    const key = await deriveKey("s", "session");
    const token = seal({ u: 1 }, key, { cookieName: "c", purpose: "session", host: "other.com" });
    
    const req = new Request("http://localhost:8000/", {
        headers: { cookie: `c=${token}` }
    });
    const session = await mgr.load(req);
    assertEquals(session.isNew, true); // Failed to unseal
});

Deno.test("SessionManager load: trustProxy host", async () => {
    const mgr = new SessionManager({ secret: "s", cookieName: "c", bindHost: true, trustProxy: true });
    const key = await deriveKey("s", "session");
    const token = seal({ u: 1 }, key, { cookieName: "c", purpose: "session", host: "real.com" });
    
    const req = new Request("http://localhost/", {
        headers: { 
            cookie: `c=${token}`,
            "x-forwarded-host": "real.com"
        }
    });
    const session = await mgr.load(req);
    assertEquals(session.isNew, false);
});

Deno.test("SessionManager rolling expiry", async () => {
    const mgr = new SessionManager({ secret: "s", cookieName: "c", rolling: true, ttlSeconds: 100 });
    const key = await deriveKey("s", "session");
    const token = seal({}, key, { cookieName: "c", purpose: "session" });
    
    const req = new Request("http://localhost/", {
        headers: { cookie: `c=${token}` }
    });
    const session = await mgr.load(req);
    assertEquals(session.isDirty, true);
});

Deno.test("SessionManager persist: destroyed", async () => {
    const mgr = new SessionManager({ secret: "s", cookieName: "c" });
    const req = new Request("http://localhost/");
    const session = await mgr.load(req);
    session.destroy();
    
    const cookie = await mgr.persist(session, req);
    assertEquals(cookie?.includes("Max-Age=0"), true);
});

Deno.test("SessionManager persist: dirty", async () => {
    const mgr = new SessionManager({ secret: "s", cookieName: "c" });
    const req = new Request("http://localhost/");
    const session = await mgr.load(req);
    session.set("a", 1);
    
    const cookie = await mgr.persist(session, req);
    assertEquals(cookie?.includes("c=v1."), true);
});

Deno.test("SessionManager persist: invalid & clear", async () => {
    const mgr = new SessionManager({ secret: "s", cookieName: "c", onInvalidCookie: "clear" });
    const req = new Request("http://localhost/", {
        headers: { cookie: "c=garbage" }
    });
    const session = await mgr.load(req);
    assertEquals(session.isInvalid, true);
    
    const cookie = await mgr.persist(session, req);
    assertEquals(cookie?.includes("Max-Age=0"), true);
});

Deno.test("SessionManager persist: invalid & ignore", async () => {
    const mgr = new SessionManager({ secret: "s", cookieName: "c", onInvalidCookie: "ignore" });
    const req = new Request("http://localhost/", {
        headers: { cookie: "c=garbage" }
    });
    const session = await mgr.load(req);
    
    const cookie = await mgr.persist(session, req);
    assertEquals(cookie, null);
});

Deno.test("SessionManager persist: secure auto (https)", async () => {
    const mgr = new SessionManager({ secret: "s", cookieName: "c" });
    const req = new Request("https://localhost/");
    const session = await mgr.load(req);
    session.set("a", 1);
    
    const cookie = await mgr.persist(session, req);
    assertEquals(cookie?.includes("Secure"), true);
});

Deno.test("SessionManager persist: secure auto (http)", async () => {
    const mgr = new SessionManager({ secret: "s", cookieName: "c" });
    const req = new Request("http://localhost/");
    const session = await mgr.load(req);
    session.set("a", 1);
    
    const cookie = await mgr.persist(session, req);
    assertEquals(cookie?.includes("Secure"), false);
});

Deno.test("SessionManager persist: secure auto (proxy trusted)", async () => {
    const mgr = new SessionManager({ secret: "s", cookieName: "c", trustProxy: true });
    const req = new Request("http://localhost/", {
        headers: { "x-forwarded-proto": "https" }
    });
    const session = await mgr.load(req);
    session.set("a", 1);
    
    const cookie = await mgr.persist(session, req);
    assertEquals(cookie?.includes("Secure"), true);
});

Deno.test("SessionManager persist: secure auto (proxy not trusted)", async () => {
    const mgr = new SessionManager({ secret: "s", cookieName: "c", trustProxy: false });
    const req = new Request("http://localhost/", {
        headers: { "x-forwarded-proto": "https" }
    });
    const session = await mgr.load(req);
    session.set("a", 1);
    
    const cookie = await mgr.persist(session, req);
    assertEquals(cookie?.includes("Secure"), false);
});

Deno.test("SessionManager persist: explicit secure", async () => {
    const mgr = new SessionManager({ secret: "s", cookieName: "c", cookie: { secure: true } });
    const req = new Request("http://localhost/");
    const session = await mgr.load(req);
    session.set("a", 1);
    
    const cookie = await mgr.persist(session, req);
    assertEquals(cookie?.includes("Secure"), true);
});
