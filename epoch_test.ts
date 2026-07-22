import {
  assertEquals,
  assertInstanceOf,
  assertRejects,
  assertStrictEquals,
  assertStringIncludes,
  assertThrows,
} from "@std/assert";
import {
  appEpoch,
  applicableTracks,
  assertValidTracks,
  type EpochContext,
  type EpochErrorInfo,
  type EpochTrack,
  EpochUnavailable,
  resolveEpoch,
  userEpoch,
} from "./epoch.ts";

type User = { uid?: string };

function ctx(request?: Request): EpochContext {
  return { request, cookieName: "sid" };
}

// ---------------------------------------------------------------------------
// appEpoch
// ---------------------------------------------------------------------------

Deno.test("appEpoch defaults the track name to a", () => {
  assertEquals(appEpoch(() => 1).name, "a");
});

Deno.test("appEpoch accepts a custom track name", () => {
  assertEquals(appEpoch(() => 1, "glob").name, "glob");
});

Deno.test("appEpoch produces a track with no key property", () => {
  const track = appEpoch(() => 1);
  assertEquals(track.key, undefined);
  assertEquals("key" in track, false);
});

Deno.test("appEpoch current receives a null key and the context", async () => {
  const seen: Array<[string | null, EpochContext]> = [];
  const c = ctx(new Request("https://example.test/"));
  const track = appEpoch((key, got) => {
    seen.push([key, got]);
    return 7;
  });

  assertEquals(await track.current(null, c), 7);
  assertEquals(seen.length, 1);
  assertEquals(seen[0][0], null);
  assertStrictEquals(seen[0][1], c);
});

// ---------------------------------------------------------------------------
// userEpoch
// ---------------------------------------------------------------------------

Deno.test("userEpoch defaults the track name to u", () => {
  assertEquals(userEpoch<User>((d) => d.uid ?? null, () => 1).name, "u");
});

Deno.test("userEpoch accepts a custom track name", () => {
  const track = userEpoch<User>((d) => d.uid ?? null, () => 1, "usr");
  assertEquals(track.name, "usr");
});

Deno.test("userEpoch key extracts the id from session data", () => {
  const track = userEpoch<User>((d) => d.uid ?? null, () => 1);
  assertEquals(track.key?.({ uid: "alice" }), "alice");
});

Deno.test("userEpoch key yields null for data with no uid", () => {
  const track = userEpoch<User>((d) => d.uid ?? null, () => 1);
  assertEquals(track.key?.({}), null);
});

Deno.test("userEpoch current receives the key and the context", async () => {
  const seen: Array<[string, EpochContext]> = [];
  const c = ctx(new Request("https://example.test/x"));
  const track = userEpoch<User>((d) => d.uid ?? null, (key, got) => {
    seen.push([key, got]);
    return 42;
  });

  assertEquals(await track.current("alice", c), 42);
  assertEquals(seen.length, 1);
  assertEquals(seen[0][0], "alice");
  assertStrictEquals(seen[0][1], c);
});

// ---------------------------------------------------------------------------
// assertValidTracks
// ---------------------------------------------------------------------------

Deno.test("assertValidTracks accepts a valid set of tracks", () => {
  assertValidTracks<User>([
    appEpoch(() => 1),
    userEpoch<User>((d) => d.uid ?? null, () => 2),
    { name: "tenant-9_A", key: () => "t", current: () => 3 },
  ]);
});

Deno.test("assertValidTracks accepts an empty array", () => {
  assertValidTracks<User>([]);
});

Deno.test("assertValidTracks accepts an explicitly undefined key", () => {
  assertValidTracks<User>([{ name: "a", key: undefined, current: () => 1 }]);
});

Deno.test("assertValidTracks rejects an empty name", () => {
  assertThrows(
    () => assertValidTracks<User>([{ name: "", current: () => 1 }]),
    TypeError,
  );
});

Deno.test("assertValidTracks rejects a missing name", () => {
  assertThrows(
    // @ts-expect-error name is required
    () => assertValidTracks<User>([{ current: () => 1 }]),
    TypeError,
  );
});

Deno.test("assertValidTracks rejects a name containing a space", () => {
  assertThrows(
    () => assertValidTracks<User>([{ name: "a b", current: () => 1 }]),
    TypeError,
  );
});

Deno.test("assertValidTracks rejects a name containing an equals sign", () => {
  assertThrows(
    () => assertValidTracks<User>([{ name: "a=b", current: () => 1 }]),
    TypeError,
  );
});

Deno.test("assertValidTracks rejects a name containing a semicolon", () => {
  assertThrows(
    () => assertValidTracks<User>([{ name: "a;b", current: () => 1 }]),
    TypeError,
  );
});

Deno.test("assertValidTracks rejects a name containing a dot", () => {
  assertThrows(
    () => assertValidTracks<User>([{ name: "a.b", current: () => 1 }]),
    TypeError,
  );
});

Deno.test("assertValidTracks rejects a name longer than 16 characters", () => {
  const name = "x".repeat(17);
  assertEquals(name.length, 17);
  assertThrows(
    () => assertValidTracks<User>([{ name, current: () => 1 }]),
    TypeError,
  );
});

Deno.test("assertValidTracks accepts a name of exactly 16 characters", () => {
  assertValidTracks<User>([{ name: "x".repeat(16), current: () => 1 }]);
});

Deno.test("assertValidTracks rejects duplicate track names", () => {
  const err = assertThrows(
    () =>
      assertValidTracks<User>([
        { name: "u", current: () => 1 },
        { name: "u", current: () => 2 },
      ]),
    TypeError,
  );
  assertStringIncludes(err.message, "duplicate");
});

Deno.test("assertValidTracks rejects a missing current", () => {
  assertThrows(
    // @ts-expect-error current is required
    () => assertValidTracks<User>([{ name: "a" }]),
    TypeError,
  );
});

Deno.test("assertValidTracks rejects a non-function current", () => {
  assertThrows(
    // @ts-expect-error current must be a function
    () => assertValidTracks<User>([{ name: "a", current: 1 }]),
    TypeError,
  );
});

Deno.test("assertValidTracks rejects a non-function key", () => {
  assertThrows(
    () =>
      assertValidTracks<User>([
        // @ts-expect-error key must be a function
        { name: "a", key: "uid", current: () => 1 },
      ]),
    TypeError,
  );
});

Deno.test("assertValidTracks rejects a non-object track", () => {
  assertThrows(
    // @ts-expect-error a track must be an object
    () => assertValidTracks<User>(["a"]),
    TypeError,
  );
});

Deno.test("assertValidTracks rejects a null track", () => {
  assertThrows(
    // @ts-expect-error a track must be an object
    () => assertValidTracks<User>([null]),
    TypeError,
  );
});

// ---------------------------------------------------------------------------
// applicableTracks
// ---------------------------------------------------------------------------

Deno.test("applicableTracks applies a keyless track with a null key", () => {
  const track = appEpoch<User>(() => 1);
  const got = applicableTracks<User>([track], {});
  assertEquals(got.length, 1);
  assertStrictEquals(got[0].track, track);
  assertEquals(got[0].key, null);
});

Deno.test("applicableTracks never invokes current", () => {
  let calls = 0;
  const track: EpochTrack<User> = {
    name: "a",
    current: () => {
      calls += 1;
      return 1;
    },
  };
  applicableTracks<User>([track], { uid: "alice" });
  assertEquals(calls, 0);
});

Deno.test("applicableTracks hands the session data to key", () => {
  const data: User = { uid: "alice" };
  const seen: User[] = [];
  const track: EpochTrack<User> = {
    name: "u",
    key: (d) => {
      seen.push(d);
      return d.uid ?? null;
    },
    current: () => 1,
  };

  applicableTracks<User>([track], data);
  assertEquals(seen.length, 1);
  assertStrictEquals(seen[0], data);
});

Deno.test("applicableTracks applies a keyed track under its key", () => {
  const track = userEpoch<User>((d) => d.uid ?? null, () => 1);
  const got = applicableTracks<User>([track], { uid: "alice" });
  assertEquals(got.length, 1);
  assertStrictEquals(got[0].track, track);
  assertEquals(got[0].key, "alice");
});

Deno.test("applicableTracks skips a track whose key is null", () => {
  const track: EpochTrack<User> = {
    name: "u",
    key: () => null,
    current: () => 1,
  };
  assertEquals(applicableTracks<User>([track], {}), []);
});

Deno.test("applicableTracks skips a track whose key is undefined", () => {
  const track: EpochTrack<User> = {
    name: "u",
    key: () => undefined,
    current: () => 1,
  };
  assertEquals(applicableTracks<User>([track], {}), []);
});

Deno.test("applicableTracks skips a track whose key is empty string", () => {
  const track: EpochTrack<User> = {
    name: "u",
    key: () => "",
    current: () => 1,
  };
  assertEquals(applicableTracks<User>([track], {}), []);
});

Deno.test("applicableTracks preserves the order of the tracks", () => {
  const tracks: EpochTrack<User>[] = [
    { name: "one", current: () => 1 },
    { name: "two", key: () => "k", current: () => 2 },
    { name: "three", current: () => 3 },
  ];
  assertEquals(
    applicableTracks<User>(tracks, {}).map((a) => a.track.name),
    ["one", "two", "three"],
  );
});

Deno.test("applicableTracks returns only the applicable tracks in a mix", () => {
  const tracks: EpochTrack<User>[] = [
    { name: "app", current: () => 1 },
    { name: "anon", key: () => null, current: () => 2 },
    { name: "user", key: (d) => d.uid ?? null, current: () => 3 },
    { name: "blank", key: () => "", current: () => 4 },
  ];
  assertEquals(
    applicableTracks<User>(tracks, { uid: "alice" }).map((a) => [
      a.track.name,
      a.key,
    ]),
    [["app", null], ["user", "alice"]],
  );
});

// ---------------------------------------------------------------------------
// resolveEpoch — happy paths
// ---------------------------------------------------------------------------

Deno.test("resolveEpoch returns a synchronous number", async () => {
  const track: EpochTrack<User> = { name: "a", current: () => 5 };
  assertEquals(await resolveEpoch(track, null, ctx(), undefined), 5);
});

Deno.test("resolveEpoch awaits a promised number", async () => {
  const track: EpochTrack<User> = {
    name: "a",
    current: () => Promise.resolve(9),
  };
  assertEquals(await resolveEpoch(track, null, ctx(), undefined), 9);
});

Deno.test("resolveEpoch passes the key and context to the resolver", async () => {
  const c = ctx(new Request("https://example.test/here"));
  const seen: Array<[string | null, EpochContext]> = [];
  const track: EpochTrack<User> = {
    name: "u",
    key: (d) => d.uid ?? null,
    current: (key, got) => {
      seen.push([key, got]);
      return 3;
    },
  };

  assertEquals(await resolveEpoch(track, "alice", c, undefined), 3);
  assertEquals(seen.length, 1);
  assertEquals(seen[0][0], "alice");
  assertStrictEquals(seen[0][1], c);
});

Deno.test("resolveEpoch accepts zero and negative epochs", async () => {
  const zero: EpochTrack<User> = { name: "a", current: () => 0 };
  const neg: EpochTrack<User> = { name: "b", current: () => -3 };
  assertEquals(await resolveEpoch(zero, null, ctx(), undefined), 0);
  assertEquals(await resolveEpoch(neg, null, ctx(), undefined), -3);
});

// ---------------------------------------------------------------------------
// resolveEpoch — throwing resolver
// ---------------------------------------------------------------------------

Deno.test("resolveEpoch fails closed when a resolver throws and there is no onError", async () => {
  const track: EpochTrack<User> = {
    name: "u",
    current: () => {
      throw new Error("store down");
    },
  };
  const err = await assertRejects(
    () => resolveEpoch(track, "alice", ctx(), undefined),
    EpochUnavailable,
  );
  assertEquals(err.track, "u");
  assertEquals(err.message, "Epoch unavailable: u");
});

Deno.test("resolveEpoch rejects when a rejected promise resolver has no onError", async () => {
  const track: EpochTrack<User> = {
    name: "u",
    current: () => Promise.reject(new Error("store down")),
  };
  await assertRejects(
    () => resolveEpoch(track, "alice", ctx(), undefined),
    EpochUnavailable,
  );
});

Deno.test("resolveEpoch returns null when onError allows a throwing resolver", async () => {
  const track: EpochTrack<User> = {
    name: "u",
    current: () => {
      throw new Error("store down");
    },
  };
  assertEquals(await resolveEpoch(track, "alice", ctx(), () => "allow"), null);
});

Deno.test("resolveEpoch rejects when onError says reject", async () => {
  const track: EpochTrack<User> = {
    name: "u",
    current: () => {
      throw new Error("store down");
    },
  };
  const err = await assertRejects(
    () => resolveEpoch(track, "alice", ctx(), () => "reject"),
    EpochUnavailable,
  );
  assertEquals(err.track, "u");
});

Deno.test("resolveEpoch propagates an error thrown by onError itself", async () => {
  class AppPanic extends Error {}
  const track: EpochTrack<User> = {
    name: "u",
    current: () => {
      throw new Error("store down");
    },
  };
  const err = await assertRejects(
    () =>
      resolveEpoch(track, "alice", ctx(), () => {
        throw new AppPanic("nope");
      }),
    AppPanic,
  );
  assertEquals(err instanceof EpochUnavailable, false);
});

// ---------------------------------------------------------------------------
// resolveEpoch — invalid return values
// ---------------------------------------------------------------------------

const BAD_VALUES: Array<[string, unknown]> = [
  ["NaN", NaN],
  ["Infinity", Infinity],
  ["-Infinity", -Infinity],
  ["a string", "3"],
  ["null", null],
  ["undefined", undefined],
  ["an object", { epoch: 3 }],
];

for (const [label, value] of BAD_VALUES) {
  Deno.test(`resolveEpoch treats ${label} as an error, not zero`, async () => {
    const track: EpochTrack<User> = {
      name: "u",
      current: () => value as number,
    };
    const err = await assertRejects(
      () => resolveEpoch(track, "alice", ctx(), undefined),
      EpochUnavailable,
    );
    assertEquals(err.track, "u");
    assertInstanceOf(err.cause, TypeError);
  });
}

Deno.test("resolveEpoch lets onError allow an invalid return value", async () => {
  const track: EpochTrack<User> = {
    name: "u",
    current: () => NaN,
  };
  assertEquals(await resolveEpoch(track, "alice", ctx(), () => "allow"), null);
});

Deno.test("resolveEpoch reports a non-number return through onError with full info", async () => {
  const request = new Request("https://example.test/info");
  const seen: EpochErrorInfo[] = [];
  const track: EpochTrack<User> = {
    name: "u",
    current: () => "nope" as unknown as number,
  };

  const got = await resolveEpoch(track, "alice", ctx(request), (info) => {
    seen.push(info);
    return "allow";
  });

  assertEquals(got, null);
  assertEquals(seen.length, 1);
  assertEquals(seen[0].track, "u");
  assertEquals(seen[0].key, "alice");
  assertStrictEquals(seen[0].request, request);
  assertInstanceOf(seen[0].error, TypeError);
  assertStringIncludes(seen[0].error.message, "finite number");
});

Deno.test("resolveEpoch does not call onError when the resolver succeeds", async () => {
  let calls = 0;
  const track: EpochTrack<User> = { name: "u", current: () => 0 };

  assertEquals(
    await resolveEpoch(track, "alice", ctx(), () => {
      calls += 1;
      return "allow";
    }),
    0,
  );
  assertEquals(calls, 0);
});

Deno.test("resolveEpoch rejects when onError returns an unknown action", async () => {
  const track: EpochTrack<User> = {
    name: "u",
    current: () => {
      throw new Error("boom");
    },
  };
  await assertRejects(
    // @ts-expect-error only "reject" and "allow" are valid actions
    () => resolveEpoch(track, "alice", ctx(), () => "maybe"),
    EpochUnavailable,
  );
});

Deno.test("resolveEpoch reports a null key for a global track through onError", async () => {
  const seen: EpochErrorInfo[] = [];
  const track: EpochTrack<User> = {
    name: "a",
    current: () => {
      throw new Error("boom");
    },
  };

  await resolveEpoch(track, null, ctx(), (info) => {
    seen.push(info);
    return "allow";
  });

  assertEquals(seen.length, 1);
  assertEquals(seen[0].key, null);
  assertEquals(seen[0].request, undefined);
});

Deno.test("resolveEpoch hands onError the exact error the resolver threw", async () => {
  const thrown = new Error("store down");
  const seen: EpochErrorInfo[] = [];
  const track: EpochTrack<User> = {
    name: "u",
    current: () => {
      throw thrown;
    },
  };

  await resolveEpoch(track, "alice", ctx(), (info) => {
    seen.push(info);
    return "allow";
  });

  assertStrictEquals(seen[0].error, thrown);
});

Deno.test("resolveEpoch calls onError exactly once per failure", async () => {
  let calls = 0;
  const track: EpochTrack<User> = {
    name: "u",
    current: () => {
      throw new Error("boom");
    },
  };

  await resolveEpoch(track, "alice", ctx(), () => {
    calls += 1;
    return "allow";
  });

  assertEquals(calls, 1);
});

Deno.test("resolveEpoch calls the resolver exactly once on success", async () => {
  let calls = 0;
  const track: EpochTrack<User> = {
    name: "u",
    current: () => {
      calls += 1;
      return 4;
    },
  };

  assertEquals(await resolveEpoch(track, "alice", ctx(), undefined), 4);
  assertEquals(calls, 1);
});

// ---------------------------------------------------------------------------
// EpochUnavailable
// ---------------------------------------------------------------------------

Deno.test("EpochUnavailable is an Error named EpochUnavailable", () => {
  const err = new EpochUnavailable("u", new Error("boom"));
  assertEquals(err instanceof Error, true);
  assertEquals(err.name, "EpochUnavailable");
});

Deno.test("EpochUnavailable exposes the track name", () => {
  assertEquals(new EpochUnavailable("tenant", null).track, "tenant");
  assertEquals(
    new EpochUnavailable("tenant", null).message,
    "Epoch unavailable: tenant",
  );
});

Deno.test("EpochUnavailable sets cause to the underlying failure", () => {
  const cause = new Error("store down");
  assertStrictEquals(new EpochUnavailable("u", cause).cause, cause);
});

Deno.test("EpochUnavailable from resolveEpoch carries the resolver failure as cause", async () => {
  const cause = new Error("store down");
  const track: EpochTrack<User> = {
    name: "u",
    current: () => {
      throw cause;
    },
  };
  const err = await assertRejects(
    () => resolveEpoch(track, "alice", ctx(), undefined),
    EpochUnavailable,
  );
  assertStrictEquals(err.cause, cause);
});
