/// <reference types="vite-plus/client" />
import { convexTest } from "convex-test";
import { describe, expect, test } from "vite-plus/test";
import { api } from "./_generated/api.js";
import schema from "./schema.js";
import { sha256Base64Url } from "./crypto.js";

const modules = import.meta.glob(["./**/*.ts", "!./**/*.test.ts"]);

const now = 1_700_000_000_000;
const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

async function pendingRequest(requestId = "r1", t = convexTest(schema, modules)) {
  await t.mutation(api.authRequests.create, {
    requestId,
    appId: "app",
    clientId: "cl",
    redirectUri: "https://app.test/cb",
    scope: "openid",
    state: "s",
    codeChallenge: await sha256Base64Url(verifier),
    expiresAt: now + 600_000,
  });
  return t;
}

describe("upstream path", () => {
  test("pending, upstream, claimed, completed, exchanged", async () => {
    const t = await pendingRequest();
    const started = await t.mutation(api.authRequests.startUpstream, {
      requestId: "r1",
      connector: "github",
      upstreamStateHash: "sh",
      upstreamCodeVerifier: "v",
      now,
    });
    expect(started).toEqual({ ok: true, redirectUri: "https://app.test/cb", state: "s" });

    const claim = await t.mutation(api.authRequests.claimUpstream, {
      upstreamStateHash: "sh",
      connector: "github",
      now,
    });
    expect(claim.status).toBe("claimed");
    // The claim is single use.
    expect(
      await t.mutation(api.authRequests.claimUpstream, {
        upstreamStateHash: "sh",
        connector: "github",
        now,
      }),
    ).toEqual({ status: "missing" });
    // A claimed request cannot restart.
    const restart = await t.mutation(api.authRequests.startUpstream, {
      requestId: "r1",
      connector: "github",
      upstreamStateHash: "x",
      upstreamCodeVerifier: "v",
      now,
    });
    expect(restart).toMatchObject({ ok: false, error: "wrong_status" });

    const completed = await t.mutation(api.authRequests.complete, {
      requestId: "r1",
      identity: { connector: "github", upstreamId: "42", email: "a@b.co", emailVerified: true },
      codeHash: "ch",
      codeExpiresAt: now + 60_000,
      now,
    });
    expect(completed.ok).toBe(true);

    const wrongVerifier = await t.mutation(api.authRequests.exchangeCode, {
      codeHash: "ch",
      clientId: "cl",
      codeVerifier: "x".repeat(43),
      now,
    });
    expect(wrongVerifier).toMatchObject({
      ok: false,
      description: expect.stringMatching(/code_verifier/),
    });
    const exchanged = await t.mutation(api.authRequests.exchangeCode, {
      codeHash: "ch",
      clientId: "cl",
      redirectUri: "https://app.test/cb",
      codeVerifier: verifier,
      now,
    });
    expect(exchanged).toMatchObject({
      ok: true,
      appId: "app",
      identity: { upstreamId: "42" },
    });
    expect(await t.query(api.authRequests.get, { requestId: "r1" })).toBeNull();
    const replay = await t.mutation(api.authRequests.exchangeCode, {
      codeHash: "ch",
      clientId: "cl",
      codeVerifier: verifier,
      now,
    });
    expect(replay).toMatchObject({ ok: false, description: expect.stringMatching(/already used/) });
  });

  test("expiry at every step", async () => {
    const t = await pendingRequest();
    const late = now + 600_001;
    expect(
      await t.mutation(api.authRequests.startUpstream, {
        requestId: "r1",
        connector: "g",
        upstreamStateHash: "sh",
        upstreamCodeVerifier: "v",
        now: late,
      }),
    ).toMatchObject({ ok: false, error: "expired" });
    await t.mutation(api.authRequests.startUpstream, {
      requestId: "r1",
      connector: "g",
      upstreamStateHash: "sh",
      upstreamCodeVerifier: "v",
      now,
    });
    expect(
      await t.mutation(api.authRequests.claimUpstream, {
        upstreamStateHash: "sh",
        connector: "g",
        now: late,
      }),
    ).toEqual({
      status: "expired",
      requestId: "r1",
      redirectUri: "https://app.test/cb",
      state: "s",
    });
    expect(await t.query(api.authRequests.get, { requestId: "r1" })).toBeNull();
  });

  test("another connector's callback cannot claim the request", async () => {
    const t = await pendingRequest();
    await t.mutation(api.authRequests.startUpstream, {
      requestId: "r1",
      connector: "google",
      upstreamStateHash: "sh",
      upstreamCodeVerifier: "v",
      upstreamNonce: "n",
      now,
    });
    expect(
      await t.mutation(api.authRequests.claimUpstream, {
        upstreamStateHash: "sh",
        connector: "github",
        now,
      }),
    ).toEqual({ status: "missing" });
    expect(await t.query(api.authRequests.get, { requestId: "r1" })).toMatchObject({
      status: "upstream",
    });
    expect(
      await t.mutation(api.authRequests.claimUpstream, {
        upstreamStateHash: "sh",
        connector: "google",
        now,
      }),
    ).toMatchObject({ status: "claimed", connector: "google", upstreamNonce: "n" });
  });

  test("a completed request outlives its code, so cleanup keeps it until the code is gone", async () => {
    const t = await pendingRequest();
    // The request expires at now + 600_000; the user finishes just before that.
    const late = now + 599_000;
    await t.mutation(api.authRequests.startUpstream, {
      requestId: "r1",
      connector: "g",
      upstreamStateHash: "sh",
      upstreamCodeVerifier: "v",
      now: late,
    });
    await t.mutation(api.authRequests.claimUpstream, {
      upstreamStateHash: "sh",
      connector: "g",
      now: late,
    });
    await t.mutation(api.authRequests.complete, {
      requestId: "r1",
      identity: { connector: "g", upstreamId: "1" },
      codeHash: "ch",
      codeExpiresAt: late + 60_000,
      now: late,
    });
    const cleanup = (at: number) =>
      t.mutation(api.lifecycle.cleanup, {
        now: at,
        previewClientMaxAgeMs: 30 * 86_400_000,
        signInRetentionMs: 90 * 86_400_000,
      });
    expect(await cleanup(late + 59_000)).toMatchObject({ authRequests: 0 });
    expect(
      await t.mutation(api.authRequests.exchangeCode, {
        codeHash: "ch",
        clientId: "cl",
        codeVerifier: verifier,
        now: late + 59_000,
      }),
    ).toMatchObject({ ok: true });
  });

  test("an expired code is refused", async () => {
    const t = await pendingRequest();
    await t.mutation(api.authRequests.startUpstream, {
      requestId: "r1",
      connector: "g",
      upstreamStateHash: "sh",
      upstreamCodeVerifier: "v",
      now,
    });
    await t.mutation(api.authRequests.claimUpstream, {
      upstreamStateHash: "sh",
      connector: "g",
      now,
    });
    await t.mutation(api.authRequests.complete, {
      requestId: "r1",
      identity: { connector: "g", upstreamId: "1" },
      codeHash: "ch",
      codeExpiresAt: now + 60_000,
      now,
    });
    expect(
      await t.mutation(api.authRequests.exchangeCode, {
        codeHash: "ch",
        clientId: "cl",
        codeVerifier: verifier,
        now: now + 60_001,
      }),
    ).toMatchObject({ ok: false, description: expect.stringMatching(/expired/) });
  });
});
