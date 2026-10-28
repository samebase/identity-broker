/// <reference types="vite-plus/client" />
import { convexTest } from "convex-test";
import { describe, expect, test } from "vite-plus/test";
import { api } from "./_generated/api.js";
import schema from "./schema.js";
import { sha256Base64Url } from "./crypto.js";

const modules = import.meta.glob(["./**/*.ts", "!./**/*.test.ts"]);

const now = 1_700_000_000_000;
const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

async function pendingRequest(requestId = "r1") {
  const t = convexTest(schema, modules);
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
      now,
    });
    expect(claim.status).toBe("claimed");
    // The claim is single use.
    expect(
      await t.mutation(api.authRequests.claimUpstream, { upstreamStateHash: "sh", now }),
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
      await t.mutation(api.authRequests.claimUpstream, { upstreamStateHash: "sh", now: late }),
    ).toEqual({ status: "expired", redirectUri: "https://app.test/cb", state: "s" });
    expect(await t.query(api.authRequests.get, { requestId: "r1" })).toBeNull();
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
    await t.mutation(api.authRequests.claimUpstream, { upstreamStateHash: "sh", now });
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
  test("send, wrong codes, lock, and a correct code", async () => {
    const t = await pendingRequest();
    const start = {
      requestId: "r1",
      connector: "email",
      email: "a@b.co",
      emailCodeHash: "good",
      emailCodeExpiresAt: now + 600_000,
      now,
    };
    expect(await t.mutation(api.authRequests.startEmail, start)).toMatchObject({ ok: true });
    const verify = (emailCodeHash: string, at = now) =>
      t.mutation(api.authRequests.verifyEmailCode, {
        requestId: "r1",
        emailCodeHash,
        maxAttempts: 3,
        codeHash: "ch",
        codeExpiresAt: at + 60_000,
        now: at,
      });
    expect(await verify("bad")).toMatchObject({ ok: false, error: "wrong_code" });
    expect(await verify("bad")).toMatchObject({ ok: false, error: "wrong_code" });
    expect(await verify("bad")).toMatchObject({ ok: false, error: "locked" });
    expect(await verify("good")).toMatchObject({ ok: false, error: "locked" });
    // A new code resets the attempts.
    expect(
      await t.mutation(api.authRequests.startEmail, { ...start, emailCodeHash: "fresh" }),
    ).toMatchObject({ ok: true });
    expect(await verify("fresh")).toMatchObject({ ok: true });
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

  test("an expired code asks for a new one", async () => {
    const t = await pendingRequest();
    await t.mutation(api.authRequests.startEmail, {
      requestId: "r1",
      connector: "email",
      email: "a@b.co",
      emailCodeHash: "good",
      emailCodeExpiresAt: now + 1_000,
      now,
    });
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
});
