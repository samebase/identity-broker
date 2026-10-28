/// <reference types="vite-plus/client" />
import { convexTest } from "convex-test";
import { describe, expect, test } from "vite-plus/test";
import { api } from "./_generated/api.js";
import schema from "./schema.js";
import { sha256Base64Url } from "./crypto.js";

const modules = import.meta.glob(["./**/*.ts", "!./**/*.test.ts"]);

const now = 1_700_000_000_000;
const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
/** The request lives this long from /authorize; its code then lives `CODE_TTL`. */
const REQUEST_TTL = 600_000;
const CODE_TTL = 60_000;

/** A request /authorize sent to the "github" connector at `now`. */
async function upstreamRequest() {
  const t = convexTest(schema, modules);
  await t.mutation(api.authRequests.create, {
    appId: "app",
    clientId: "cl",
    redirectUri: "https://app.test/cb",
    scope: "openid",
    state: "s",
    codeChallenge: await sha256Base64Url(verifier),
    expiresAt: now + REQUEST_TTL,
    connector: "github",
    upstreamStateHash: "sh",
    upstreamCodeVerifier: "v",
  });
  return t;
}

type T = Awaited<ReturnType<typeof upstreamRequest>>;

const claim = (t: T, at: number, connector = "github") =>
  t.mutation(api.authRequests.claimUpstream, { upstreamStateHash: "sh", connector, now: at });

/** Claims the request and completes it at `at` with the code hash "ch". */
async function complete(t: T, at: number) {
  const claimed = await claim(t, at);
  if (claimed.status !== "claimed") {
    throw new Error(`expected a claim, got ${claimed.status}`);
  }
  return await t.mutation(api.authRequests.complete, {
    requestId: claimed.requestId,
    identity: { connector: "github", upstreamId: "42" },
    codeHash: "ch",
    codeExpiresAt: at + CODE_TTL,
    now: at,
  });
}

const exchange = (t: T, at: number, client: { clientId?: string; codeVerifier?: string } = {}) =>
  t.mutation(api.authRequests.exchangeCode, {
    codeHash: "ch",
    clientId: client.clientId ?? "cl",
    redirectUri: "https://app.test/cb",
    codeVerifier: client.codeVerifier ?? verifier,
    now: at,
  });

const requests = (t: T) => t.run(async (ctx) => await ctx.db.query("authRequests").collect());

describe("one request from /authorize to the token endpoint", () => {
  test("upstream, claimed, completed, redeemed once", async () => {
    const t = await upstreamRequest();
    // Another connector's callback cannot claim it, and the request keeps waiting.
    expect(await claim(t, now, "google")).toEqual({ status: "missing" });
    expect(await complete(t, now)).toBe(true);
    // The claim is single use.
    expect(await claim(t, now)).toEqual({ status: "missing" });

    // A wrong verifier or another client leaves the code redeemable.
    expect(await exchange(t, now, { codeVerifier: "x".repeat(43) })).toMatchObject({
      ok: false,
      description: expect.stringMatching(/code_verifier/),
    });
    expect(await exchange(t, now, { clientId: "other" })).toMatchObject({
      ok: false,
      description: expect.stringMatching(/another client/),
    });
    expect(await exchange(t, now)).toEqual({
      ok: true,
      appId: "app",
      scope: "openid",
      identity: { connector: "github", upstreamId: "42" },
    });
    // The redemption deleted the request, so the code cannot be redeemed again.
    expect(await requests(t)).toEqual([]);
    expect(await exchange(t, now)).toMatchObject({
      ok: false,
      description: expect.stringMatching(/already used/),
    });
  });

  test("each status runs out at its expiresAt", async () => {
    // Upstream: a late callback deletes the request and goes back with the redirect URI and state.
    const late = await upstreamRequest();
    expect(await claim(late, now + REQUEST_TTL)).toEqual({
      status: "expired",
      redirectUri: "https://app.test/cb",
      state: "s",
    });
    expect(await requests(late)).toEqual([]);

    // Claimed: an exchange upstream that outlasts the request completes nothing.
    const slow = await upstreamRequest();
    const claimed = await claim(slow, now + REQUEST_TTL - 1);
    if (claimed.status !== "claimed") {
      throw new Error(`expected a claim, got ${claimed.status}`);
    }
    expect(
      await slow.mutation(api.authRequests.complete, {
        requestId: claimed.requestId,
        identity: { connector: "github", upstreamId: "42" },
        codeHash: "ch",
        codeExpiresAt: now + REQUEST_TTL + CODE_TTL,
        now: now + REQUEST_TTL,
      }),
    ).toBe(false);

    // Completed: the code expires CODE_TTL after completion, even past the request's own lifetime,
    // and cleanup keeps the request until then.
    const finished = await upstreamRequest();
    const completedAt = now + REQUEST_TTL - 1;
    expect(await complete(finished, completedAt)).toBe(true);
    const codeExpiresAt = completedAt + CODE_TTL;
    await finished.mutation(api.lifecycle.cleanup, { now: codeExpiresAt });
    expect(await exchange(finished, codeExpiresAt)).toMatchObject({
      ok: false,
      description: expect.stringMatching(/expired/),
    });
    expect(await exchange(finished, codeExpiresAt - 1)).toMatchObject({ ok: true });
  });
});
