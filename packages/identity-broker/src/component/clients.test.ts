/// <reference types="vite-plus/client" />
import { convexTest } from "convex-test";
import { describe, expect, test } from "vite-plus/test";
import { api } from "./_generated/api.js";
import schema from "./schema.js";

const modules = import.meta.glob(["./**/*.ts", "!./**/*.test.ts"]);

const now = 1_700_000_000_000;

async function withClients() {
  const t = convexTest(schema, modules);
  for (const [clientId, appId, deploymentType] of [
    ["cl_prod", "bristol", "production"],
    ["cl_dev", "bristol", "development"],
    ["cl_preview", "bristol", "preview"],
    ["cl_other", "other", "preview"],
  ] as const) {
    await t.mutation(api.clients.create, {
      clientId,
      appId,
      secretHash: "h",
      tokenEndpointAuthMethod: "client_secret_post",
      redirectUri: "https://app.test/cb",
      deploymentType,
      clientName: clientId,
      softwareVersion: "v",
      createdAt: now,
    });
  }
  return t;
}

describe("unregister", () => {
  test("the owning app deletes a client of any deployment type", async () => {
    const t = await withClients();
    for (const clientId of ["cl_prod", "cl_dev", "cl_preview"]) {
      expect(await t.mutation(api.clients.unregister, { clientId, appId: "bristol" })).toBe(true);
      expect(await t.query(api.clients.get, { clientId })).toBeNull();
    }
    expect(await t.query(api.clients.get, { clientId: "cl_other" })).not.toBeNull();
  });

  test("another app, an unknown client, and a deleted client delete nothing", async () => {
    const t = await withClients();
    expect(await t.mutation(api.clients.unregister, { clientId: "cl_prod", appId: "other" })).toBe(
      false,
    );
    expect(await t.query(api.clients.get, { clientId: "cl_prod" })).not.toBeNull();
    expect(
      await t.mutation(api.clients.unregister, { clientId: "cl_unknown", appId: "bristol" }),
    ).toBe(false);
    await t.mutation(api.clients.unregister, { clientId: "cl_dev", appId: "bristol" });
    expect(await t.mutation(api.clients.unregister, { clientId: "cl_dev", appId: "bristol" })).toBe(
      false,
    );
    expect((await t.query(api.clients.listByApp, { appId: "bristol" })).length).toBe(2);
  });
});
