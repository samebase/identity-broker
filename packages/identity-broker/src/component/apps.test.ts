/// <reference types="vite-plus/client" />
import { convexTest } from "convex-test";
import { afterEach, describe, expect, test, vi } from "vite-plus/test";
import { api } from "./_generated/api.js";
import schema from "./schema.js";

const modules = import.meta.glob(["./**/*.ts", "!./**/*.test.ts"]);

const now = 1_700_000_000_000;

afterEach(() => {
  vi.useRealTimers();
});

async function appWith(
  t: ReturnType<typeof convexTest>,
  args: { appId: string; clients: number; tokens: number },
) {
  await t.mutation(api.apps.create, {
    appId: args.appId,
    name: args.appId,
    firstParty: true,
    allowedCallbackHosts: ["app.test"],
    createdAt: now,
  });
  await t.run(async (ctx) => {
    for (let row = 0; row < args.tokens; row++) {
      await ctx.db.insert("registrationTokens", {
        tokenHash: `${args.appId}-token-${row}`,
        appId: args.appId,
        expiresAt: now + 86_400_000,
        createdAt: now,
      });
    }
    for (let row = 0; row < args.clients; row++) {
      await ctx.db.insert("clients", {
        clientId: `${args.appId}-client-${row}`,
        appId: args.appId,
        secretHash: "h",
        tokenEndpointAuthMethod: "client_secret_post",
        redirectUri: "https://app.test/cb",
        deploymentType: "preview",
        clientName: "c",
        softwareVersion: "v",
        createdAt: now,
      });
    }
  });
}

describe("remove", () => {
  test("deletes the app row at once and its tokens and clients in batches of 200", async () => {
    // [clients, tokens]: none, under a batch, exactly a batch, more than two batches of each.
    for (const [clients, tokens] of [
      [0, 0],
      [199, 3],
      [200, 3],
      [450, 3],
      [3, 450],
    ] as const) {
      vi.useFakeTimers();
      const t = convexTest(schema, modules);
      await appWith(t, { appId: "bristol", clients, tokens });
      await appWith(t, { appId: "other", clients: 1, tokens: 1 });

      await t.mutation(api.apps.remove, { appId: "bristol" });
      expect(await t.query(api.apps.get, { appId: "bristol" })).toBeNull();
      const clientsLeft = (await t.query(api.clients.listByApp, { appId: "bristol" })).length;
      const tokensLeft = (await t.query(api.registration.listTokens, { appId: "bristol" })).length;
      expect([clientsLeft, tokensLeft]).toEqual([
        Math.max(clients - 200, 0),
        Math.max(tokens - 200, 0),
      ]);

      await t.finishAllScheduledFunctions(vi.runAllTimers);
      expect(await t.query(api.clients.listByApp, { appId: "bristol" })).toEqual([]);
      expect(await t.query(api.registration.listTokens, { appId: "bristol" })).toEqual([]);
      expect(await t.query(api.apps.get, { appId: "other" })).not.toBeNull();
      expect(await t.query(api.clients.listByApp, { appId: "other" })).toHaveLength(1);
      expect(await t.query(api.registration.listTokens, { appId: "other" })).toHaveLength(1);
      vi.useRealTimers();
    }
  });

  test("an unknown app deletes nothing", async () => {
    const t = convexTest(schema, modules);
    await appWith(t, { appId: "other", clients: 1, tokens: 1 });
    await t.mutation(api.apps.remove, { appId: "bristol" });
    expect(await t.query(api.apps.list, {})).toHaveLength(1);
    expect(await t.query(api.clients.listByApp, { appId: "other" })).toHaveLength(1);
  });
});
