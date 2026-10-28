/// <reference types="vite-plus/client" />
import { convexTest } from "convex-test";
import { describe, expect, test } from "vite-plus/test";
import { api } from "./_generated/api.js";
import schema from "./schema.js";

const modules = import.meta.glob(["./**/*.ts", "!./**/*.test.ts"]);

const now = 1_700_000_000_000;

const client = (appId: string, clientId: string) => ({
  clientId,
  appId,
  secretHash: "h",
  redirectUri: "https://app.test/cb",
});

async function appWith(
  t: ReturnType<typeof convexTest>,
  args: { appId: string; clients: number; tokens: number },
) {
  await t.mutation(api.apps.create, { appId: args.appId, allowedCallbackHosts: ["app.test"] });
  for (let row = 0; row < args.tokens; row++) {
    await t.mutation(api.registration.mintToken, {
      tokenHash: `${args.appId}-token-${row}`,
      appId: args.appId,
      createdAt: now,
    });
  }
  for (let row = 0; row < args.clients; row++) {
    await t.mutation(api.clients.create, client(args.appId, `${args.appId}-client-${row}`));
  }
}

/** The rows of `appId` that are left: the app, its tokens and its clients. */
async function rowsOf(t: ReturnType<typeof convexTest>, appId: string) {
  return {
    app: (await t.query(api.apps.list, {})).some((app) => app.appId === appId),
    tokens: (await t.query(api.registration.listTokens, { appId })).length,
    clients: (await t.query(api.clients.listByApp, { appId })).length,
  };
}

describe("remove", () => {
  test("deletes the app, its tokens and its clients in one call, and nothing of another app", async () => {
    // [clients, tokens]: none, and a few of each.
    for (const [clients, tokens] of [
      [0, 0],
      [3, 2],
    ] as const) {
      const t = convexTest(schema, modules);
      await appWith(t, { appId: "bristol", clients, tokens });
      await appWith(t, { appId: "other", clients: 1, tokens: 1 });
      await t.mutation(api.apps.remove, { appId: "bristol" });
      expect(await rowsOf(t, "bristol")).toEqual({ app: false, tokens: 0, clients: 0 });
      expect(await rowsOf(t, "other")).toEqual({ app: true, tokens: 1, clients: 1 });
    }
  });

  test("an unknown app deletes nothing", async () => {
    const t = convexTest(schema, modules);
    await appWith(t, { appId: "other", clients: 1, tokens: 1 });
    await t.mutation(api.apps.remove, { appId: "bristol" });
    expect(await rowsOf(t, "other")).toEqual({ app: true, tokens: 1, clients: 1 });
  });

  test("a client is refused once its app is gone, so none outlives its app", async () => {
    const t = convexTest(schema, modules);
    await appWith(t, { appId: "bristol", clients: 0, tokens: 0 });
    await t.mutation(api.apps.remove, { appId: "bristol" });
    await expect(t.mutation(api.clients.create, client("bristol", "late"))).rejects.toThrow(
      'Unknown app "bristol"',
    );
  });
});
