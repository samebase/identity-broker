import { v } from "convex/values";
import { internal } from "./_generated/api";
import { internalMutation, mutation, query, type MutationCtx } from "./_generated/server";
import { BATCH } from "./lifecycle";

const { array, boolean, number, object, string } = v;

const vApp = object({
  appId: string(),
  name: string(),
  firstParty: boolean(),
  allowedCallbackHosts: array(string()),
  createdAt: number(),
});

/** Registers an app. Its clients come later, one per deployment, through registration tokens. */
export const create = mutation({
  args: {
    appId: string(),
    name: string(),
    firstParty: boolean(),
    allowedCallbackHosts: array(string()),
    createdAt: number(),
  },
  returns: v.null(),
  handler: async (ctx, args) => {
    const existing = await ctx.db
      .query("apps")
      .withIndex("by_app_id", (q) => q.eq("appId", args.appId))
      .unique();
    if (existing !== null) {
      throw new Error(`An app with id "${args.appId}" already exists`);
    }
    await ctx.db.insert("apps", {
      appId: args.appId,
      name: args.name,
      firstParty: args.firstParty,
      allowedCallbackHosts: args.allowedCallbackHosts,
      createdAt: args.createdAt,
    });
    return null;
  },
});

export const get = query({
  args: { appId: string() },
  returns: v.union(vApp, v.null()),
  handler: async (ctx, args) => {
    const app = await ctx.db
      .query("apps")
      .withIndex("by_app_id", (q) => q.eq("appId", args.appId))
      .unique();
    if (app === null) {
      return null;
    }
    return {
      appId: app.appId,
      name: app.name,
      firstParty: app.firstParty,
      allowedCallbackHosts: app.allowedCallbackHosts,
      createdAt: app.createdAt,
    };
  },
});

export const list = query({
  args: {},
  returns: array(vApp),
  handler: async (ctx) => {
    const apps = await ctx.db.query("apps").collect();
    return apps
      .map((app) => ({
        appId: app.appId,
        name: app.name,
        firstParty: app.firstParty,
        allowedCallbackHosts: app.allowedCallbackHosts,
        createdAt: app.createdAt,
      }))
      .sort((a, b) => a.createdAt - b.createdAt || a.appId.localeCompare(b.appId));
  },
});

/** Replaces the hosts a client callback may use, for example when an app gets a custom domain. */
export const setAllowedCallbackHosts = mutation({
  args: { appId: string(), allowedCallbackHosts: array(string()) },
  returns: v.null(),
  handler: async (ctx, args) => {
    const app = await ctx.db
      .query("apps")
      .withIndex("by_app_id", (q) => q.eq("appId", args.appId))
      .unique();
    if (app === null) {
      throw new Error(`Unknown app "${args.appId}"`);
    }
    await ctx.db.patch("apps", app._id, { allowedCallbackHosts: args.allowedCallbackHosts });
    return null;
  },
});

async function removeRows(ctx: MutationCtx, appId: string): Promise<void> {
  const tokens = await ctx.db
    .query("registrationTokens")
    .withIndex("by_app_id", (q) => q.eq("appId", appId))
    .take(BATCH);
  for (const token of tokens) {
    await ctx.db.delete("registrationTokens", token._id);
  }
  const clients = await ctx.db
    .query("clients")
    .withIndex("by_app_id", (q) => q.eq("appId", appId))
    .take(BATCH);
  for (const client of clients) {
    await ctx.db.delete("clients", client._id);
  }
  if (tokens.length === BATCH || clients.length === BATCH) {
    await ctx.scheduler.runAfter(0, internal.apps.continueRemove, { appId });
  }
}

/**
 * Deletes an app with its registration tokens and clients. This is the emergency revocation. The
 * app row goes first: registration, /authorize and /token refuse a token or client whose app is
 * gone, so this transaction revokes every token and client of the app, however many batches their
 * rows take to delete.
 */
export const remove = mutation({
  args: { appId: string() },
  returns: v.null(),
  handler: async (ctx, args) => {
    const app = await ctx.db
      .query("apps")
      .withIndex("by_app_id", (q) => q.eq("appId", args.appId))
      .unique();
    if (app !== null) {
      await ctx.db.delete("apps", app._id);
    }
    await removeRows(ctx, args.appId);
    return null;
  },
});

export const continueRemove = internalMutation({
  args: { appId: string() },
  returns: v.null(),
  handler: async (ctx, args) => {
    await removeRows(ctx, args.appId);
    return null;
  },
});
