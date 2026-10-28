import { v } from "convex/values";
import { mutation } from "./_generated/server";
import { EMAIL_SEND_WINDOW_MS } from "./authRequests";

const { number, object } = v;

/** How many documents one run deletes per table, so a run stays well inside one transaction. */
const BATCH = 200;

/**
 * Deletes what has run out: expired requests, codes and registration tokens, preview clients
 * nobody used for `previewClientMaxAgeMs`, audit rows older than `signInRetentionMs`, and email send
 * rows outside the send window. The host calls this from a cron; production and development clients
 * are never touched.
 */
export const cleanup = mutation({
  args: { now: number(), previewClientMaxAgeMs: number(), signInRetentionMs: number() },
  returns: object({
    authRequests: number(),
    authorizationCodes: number(),
    registrationTokens: number(),
    previewClients: number(),
    signIns: number(),
    emailSends: number(),
  }),
  handler: async (ctx, args) => {
    const requests = await ctx.db
      .query("authRequests")
      .withIndex("by_expires_at", (q) => q.lt("expiresAt", args.now))
      .take(BATCH);
    for (const request of requests) {
      await ctx.db.delete("authRequests", request._id);
    }

    const codes = await ctx.db
      .query("authorizationCodes")
      .withIndex("by_expires_at", (q) => q.lt("expiresAt", args.now))
      .take(BATCH);
    for (const code of codes) {
      await ctx.db.delete("authorizationCodes", code._id);
    }

    const tokens = await ctx.db
      .query("registrationTokens")
      .withIndex("by_expires_at", (q) => q.lt("expiresAt", args.now))
      .take(BATCH);
    for (const token of tokens) {
      await ctx.db.delete("registrationTokens", token._id);
    }

    const previewCutoff = args.now - args.previewClientMaxAgeMs;
    const previewClients = (
      await ctx.db
        .query("clients")
        .withIndex("by_deployment_type", (q) => q.eq("deploymentType", "preview"))
        .collect()
    )
      .filter((client) => (client.lastSignInAt ?? client.createdAt) < previewCutoff)
      .slice(0, BATCH);
    for (const client of previewClients) {
      await ctx.db.delete("clients", client._id);
    }

    const signIns = await ctx.db
      .query("signIns")
      .withIndex("by_at", (q) => q.lt("at", args.now - args.signInRetentionMs))
      .take(BATCH);
    for (const signIn of signIns) {
      await ctx.db.delete("signIns", signIn._id);
    }

    const emailSends = await ctx.db
      .query("emailSends")
      .withIndex("by_at", (q) => q.lt("at", args.now - EMAIL_SEND_WINDOW_MS))
      .take(BATCH);
    for (const emailSend of emailSends) {
      await ctx.db.delete("emailSends", emailSend._id);
    }

    return {
      authRequests: requests.length,
      authorizationCodes: codes.length,
      registrationTokens: tokens.length,
      previewClients: previewClients.length,
      signIns: signIns.length,
      emailSends: emailSends.length,
    };
  },
});
