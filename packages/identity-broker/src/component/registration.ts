import { v } from "convex/values";
import { mutation, query } from "./_generated/server";

const { array, boolean, number, object, string } = v;

/**
 * Stores the hash of an initial access token (RFC 7591 section 3) that registers clients of one
 * app. It works until `revokeToken` or the app's deletion removes it.
 */
export const mintToken = mutation({
  args: { tokenHash: string(), appId: string(), createdAt: number() },
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
      createdAt: args.createdAt,
    });
    return null;
  },
});

/** The app a registration token belongs to, or null for an unknown token. */
export const readToken = query({
  args: { tokenHash: string() },
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
    if (token === null) {
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

/** The tokens of one app, as hashes: the plaintext is never stored. Oldest first. */
export const listTokens = query({
  args: { appId: string() },
  returns: array(object({ tokenHash: string(), createdAt: number() })),
  handler: async (ctx, args) => {
    const tokens = await ctx.db
      .query("registrationTokens")
      .withIndex("by_app_id", (q) => q.eq("appId", args.appId))
      .collect();
    return tokens
      .map((token) => ({ tokenHash: token.tokenHash, createdAt: token.createdAt }))
      .sort((a, b) => a.createdAt - b.createdAt || a.tokenHash.localeCompare(b.tokenHash));
  },
});

/** Deletes a registration token. Clients it registered stay. */
export const revokeToken = mutation({
  args: { tokenHash: string() },
  returns: v.null(),
  handler: async (ctx, args) => {
    const token = await ctx.db
      .query("registrationTokens")
      .withIndex("by_token_hash", (q) => q.eq("tokenHash", args.tokenHash))
      .unique();
    if (token !== null) {
      await ctx.db.delete("registrationTokens", token._id);
    }
    return null;
  },
});
