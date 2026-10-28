import { v } from "convex/values";
import { mutation } from "./_generated/server";

const { number, string } = v;

/** One audit row per issued id_token: no email, no name, no token. Also marks the client as used. */
export const record = mutation({
  args: { appId: string(), clientId: string(), connector: string(), sub: string(), at: number() },
  returns: v.null(),
  handler: async (ctx, args) => {
    await ctx.db.insert("signIns", {
      appId: args.appId,
      clientId: args.clientId,
      connector: args.connector,
      sub: args.sub,
      at: args.at,
    });
    const client = await ctx.db
      .query("clients")
      .withIndex("by_client_id", (q) => q.eq("clientId", args.clientId))
      .unique();
    if (client !== null) {
      await ctx.db.patch("clients", client._id, { lastSignInAt: args.at });
    }
    return null;
  },
});
