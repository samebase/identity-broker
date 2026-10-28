import { v } from "convex/values";
import { mutation, query } from "./_generated/server";

const { array, object, string } = v;

/**
 * Registers an app. Its clients come later, one per deployment, through registration tokens. The
 * app id is chosen by the operator and kept for good: every `sub` of the app is derived from it.
 */
export const create = mutation({
  args: { appId: string(), allowedCallbackHosts: array(string()) },
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
      allowedCallbackHosts: args.allowedCallbackHosts,
    });
    return null;
  },
});

/** Every app, by app id. */
export const list = query({
  args: {},
  returns: array(object({ appId: string(), allowedCallbackHosts: array(string()) })),
  handler: async (ctx) => {
    const apps = await ctx.db.query("apps").withIndex("by_app_id").collect();
    return apps.map((app) => ({
      appId: app.appId,
      allowedCallbackHosts: app.allowedCallbackHosts,
    }));
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

/**
 * Deletes an app with its registration tokens and clients in one transaction. This is the
 * emergency revocation. One transaction holds them: an app has a client per live deployment, a
 * handful once previews unregister on destroy, and a token per deploy pipeline.
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
    const tokens = await ctx.db
      .query("registrationTokens")
      .withIndex("by_app_id", (q) => q.eq("appId", args.appId))
      .collect();
    for (const token of tokens) {
      await ctx.db.delete("registrationTokens", token._id);
    }
    const clients = await ctx.db
      .query("clients")
      .withIndex("by_app_id", (q) => q.eq("appId", args.appId))
      .collect();
    for (const client of clients) {
      await ctx.db.delete("clients", client._id);
    }
    return null;
  },
});
