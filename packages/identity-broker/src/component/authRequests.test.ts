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
    freshLogin: false,
    createdAt: now,
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
      authTime: now,
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
      authTime: now,
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
    ).toEqual({ status: "expired", redirectUri: "https://app.test/cb", state: "s" });
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
      authTime: late,
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
      authTime: now,
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

describe("email path", () => {
  const start = {
    requestId: "r1",
    connector: "email",
    email: "a@b.co",
    emailHash: "hash-of-a@b.co",
    emailCodeHash: "good",
    emailCodeExpiresAt: now + 600_000,
    maxAttempts: 3,
    now,
  };
  const verifyFor = (t: Awaited<ReturnType<typeof pendingRequest>>) => (emailCodeHash: string) =>
    t.mutation(api.authRequests.verifyEmailCode, {
      requestId: "r1",
      emailCodeHash,
      maxAttempts: 3,
      codeHash: "ch",
      codeExpiresAt: now + 60_000,
      now,
    });

  test("send, a wrong code, and a correct code", async () => {
    const t = await pendingRequest();
    expect(await t.mutation(api.authRequests.startEmail, start)).toMatchObject({ ok: true });
    const verify = verifyFor(t);
    expect(await verify("bad")).toMatchObject({ ok: false, error: "wrong_code" });
    expect(await verify("good")).toMatchObject({ ok: true });
    const exchanged = await t.mutation(api.authRequests.exchangeCode, {
      codeHash: "ch",
      clientId: "cl",
      codeVerifier: verifier,
      now,
    });
    expect(exchanged).toMatchObject({
      ok: true,
      identity: { connector: "email", upstreamId: "a@b.co", email: "a@b.co", emailVerified: true },
    });
  });

  test("attempts do not reset after a resend", async () => {
    const t = await pendingRequest();
    await t.mutation(api.authRequests.startEmail, start);
    const verify = verifyFor(t);
    expect(await verify("bad")).toMatchObject({ ok: false, error: "wrong_code" });
    expect(await verify("bad")).toMatchObject({ ok: false, error: "wrong_code" });
    expect(
      await t.mutation(api.authRequests.startEmail, {
        ...start,
        emailCodeHash: "fresh",
        now: now + 60_000,
      }),
    ).toMatchObject({ ok: true });
    expect(await verify("bad")).toMatchObject({ ok: false, error: "locked" });
    expect(await verify("fresh")).toMatchObject({ ok: false, error: "locked" });
    // A locked request sends no more codes.
    expect(
      await t.mutation(api.authRequests.startEmail, { ...start, now: now + 120_000 }),
    ).toMatchObject({ ok: false, error: "locked" });
  });

  test("a second send inside 60 seconds is refused", async () => {
    const t = await pendingRequest();
    await t.mutation(api.authRequests.startEmail, start);
    expect(
      await t.mutation(api.authRequests.startEmail, { ...start, now: now + 59_999 }),
    ).toMatchObject({ ok: false, error: "too_soon" });
    expect(
      await t.mutation(api.authRequests.startEmail, { ...start, now: now + 60_000 }),
    ).toMatchObject({ ok: true });
  });

  test("a fourth send is refused", async () => {
    const t = await pendingRequest();
    for (const at of [now, now + 60_000, now + 120_000]) {
      expect(await t.mutation(api.authRequests.startEmail, { ...start, now: at })).toMatchObject({
        ok: true,
      });
    }
    expect(
      await t.mutation(api.authRequests.startEmail, { ...start, now: now + 180_000 }),
    ).toMatchObject({ ok: false, error: "request_limit" });
  });

  test("a sixth send to one address within an hour is refused across two requests", async () => {
    const t = await pendingRequest("r1");
    await pendingRequest("r2", t);
    const send = (requestId: string, at: number, emailHash = start.emailHash) =>
      t.mutation(api.authRequests.startEmail, { ...start, requestId, emailHash, now: at });
    for (const [requestId, at] of [
      ["r1", now],
      ["r1", now + 60_000],
      ["r1", now + 120_000],
      ["r2", now + 180_000],
      ["r2", now + 240_000],
    ] as const) {
      expect(await send(requestId, at)).toMatchObject({ ok: true });
    }
    expect(await send("r2", now + 300_000)).toMatchObject({
      ok: false,
      error: "address_limit",
    });
    // The count is per address: another address still receives a code.
    expect(await send("r2", now + 300_000, "hash-of-c@d.co")).toMatchObject({ ok: true });
  });

  test("a send beyond 200 per hour across all addresses is refused", async () => {
    const t = await pendingRequest();
    await t.run(async (ctx) => {
      for (let index = 0; index < 200; index++) {
        await ctx.db.insert("emailSends", { emailHash: `hash-${index}`, at: now - 3_599_000 });
      }
    });
    expect(await t.mutation(api.authRequests.startEmail, start)).toMatchObject({
      ok: false,
      error: "global_limit",
    });
    // The rows leave the window an hour after they were written.
    expect(
      await t.mutation(api.authRequests.startEmail, { ...start, now: now + 1_000 }),
    ).toMatchObject({ ok: true });
  });

  test("an expired code asks for a new one", async () => {
    const t = await pendingRequest();
    await t.mutation(api.authRequests.startEmail, { ...start, emailCodeExpiresAt: now + 1_000 });
    expect(
      await t.mutation(api.authRequests.verifyEmailCode, {
        requestId: "r1",
        emailCodeHash: "good",
        maxAttempts: 3,
        codeHash: "ch",
        codeExpiresAt: now + 60_000,
        now: now + 2_000,
      }),
    ).toMatchObject({ ok: false, error: "code_expired" });
  });

  test("cleanup removes emailSends rows older than one hour", async () => {
    const t = await pendingRequest();
    await t.mutation(api.authRequests.startEmail, start);
    await t.mutation(api.authRequests.startEmail, { ...start, now: now + 60_000 });
    const cleanup = (at: number) =>
      t.mutation(api.lifecycle.cleanup, {
        now: at,
        previewClientMaxAgeMs: 30 * 86_400_000,
        signInRetentionMs: 90 * 86_400_000,
      });
    expect(await cleanup(now + 3_600_000)).toMatchObject({ emailSends: 0 });
    expect(await cleanup(now + 3_600_001)).toMatchObject({ emailSends: 1 });
    const rows = await t.run(async (ctx) => await ctx.db.query("emailSends").collect());
    expect(rows).toEqual([expect.objectContaining({ at: now + 60_000 })]);
  });
});
