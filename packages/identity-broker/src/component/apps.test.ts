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

async function appWith(t: ReturnType<typeof convexTest>, args: { appId: string; clients: number }) {
  await t.mutation(api.apps.create, {
    appId: args.appId,
    name: args.appId,
    firstParty: true,
    createdAt: now,
  });
  await t.run(async (ctx) => {
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
  test("deletes the app row at once and its clients in batches of 200", async () => {
    // None, under a batch, exactly a batch, more than two batches.
    for (const clients of [0, 199, 200, 450]) {
      vi.useFakeTimers();
      const t = convexTest(schema, modules);
      await appWith(t, { appId: "bristol", clients });
      await appWith(t, { appId: "other", clients: 1 });

      await t.mutation(api.apps.remove, { appId: "bristol" });
      expect(await t.query(api.apps.get, { appId: "bristol" })).toBeNull();
      const clientsLeft = (await t.query(api.clients.listByApp, { appId: "bristol" })).length;
      expect(clientsLeft).toBe(Math.max(clients - 200, 0));

      await t.finishAllScheduledFunctions(vi.runAllTimers);
      expect(await t.query(api.clients.listByApp, { appId: "bristol" })).toEqual([]);
      expect(await t.query(api.apps.get, { appId: "other" })).not.toBeNull();
      expect(await t.query(api.clients.listByApp, { appId: "other" })).toHaveLength(1);
      vi.useRealTimers();
    }
  });

  test("an unknown app deletes nothing", async () => {
    const t = convexTest(schema, modules);
    await appWith(t, { appId: "other", clients: 1 });
    await t.mutation(api.apps.remove, { appId: "bristol" });
    expect(await t.query(api.apps.list, {})).toHaveLength(1);
    expect(await t.query(api.clients.listByApp, { appId: "other" })).toHaveLength(1);
  });
});
