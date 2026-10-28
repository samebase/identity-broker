import { v } from "convex/values";
import { mutation, query } from "./_generated/server";

const { array, boolean, number, object, string } = v;

/** Stores the hash of an initial access token (RFC 7591 section 3) that registers clients of one app. */
export const mintToken = mutation({
  args: { tokenHash: string(), appId: string(), expiresAt: number(), createdAt: number() },
  returns: v.null(),
  handler: async (ctx, args) => {
    const app = await ctx.db
      .query("apps")
      .withIndex("by_app_id", (q) => q.eq("appId", args.appId))
      .unique();
    if (app === null) {
      throw new Error(`Unknown app "${args.appId}"`);
    }
    await ctx.db.insert("registrationTokens", {
      tokenHash: args.tokenHash,
      appId: args.appId,
      expiresAt: args.expiresAt,
      createdAt: args.createdAt,
    });
    return null;
  },
});

/** The app a live registration token belongs to, or null for an unknown or expired token. */
export const readToken = query({
  args: { tokenHash: string(), now: number() },
  returns: v.union(
    object({
      appId: string(),
      name: string(),
      firstParty: boolean(),
      allowedCallbackHosts: array(string()),
    }),
    v.null(),
  ),
  handler: async (ctx, args) => {
    const token = await ctx.db
      .query("registrationTokens")
      .withIndex("by_token_hash", (q) => q.eq("tokenHash", args.tokenHash))
      .unique();
    if (token === null || token.expiresAt <= args.now) {
      return null;
    }
    const app = await ctx.db
      .query("apps")
      .withIndex("by_app_id", (q) => q.eq("appId", token.appId))
      .unique();
    if (app === null) {
      return null;
    }
    return {
      appId: app.appId,
      name: app.name,
      firstParty: app.firstParty,
      allowedCallbackHosts: app.allowedCallbackHosts,
    };
  },
});
