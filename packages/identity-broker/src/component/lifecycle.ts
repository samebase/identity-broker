import { v, type Infer } from "convex/values";
import { internal } from "./_generated/api";
import { internalMutation, mutation, type MutationCtx } from "./_generated/server";
import { EMAIL_SEND_WINDOW_MS } from "./authRequests";

const { number, object, optional } = v;

/** How many documents one batch deletes per table, so a batch stays well inside one transaction. */
export const BATCH = 200;

const vCleanupArgs = object({
  now: number(),
  /** Absent: preview clients are never deleted. */
  previewClientMaxAgeMs: optional(number()),
  signInRetentionMs: number(),
});

const vCleanupCounts = object({
  authRequests: number(),
  authorizationCodes: number(),
  registrationTokens: number(),
  previewClients: number(),
  signIns: number(),
  emailSends: number(),
});

/**
 * Deletes one batch of what has run out. A table that filled its batch may hold more, so the batch
 * schedules the next one with the same `now`, until no table fills a batch. The cutoff never moves,
 * so the run ends: a row written after the run began, a registration token minted with a positive
 * lifetime included, runs out after `now`, and the rows that had run out by then are a fixed set.
 */
async function cleanupBatch(
  ctx: MutationCtx,
  args: Infer<typeof vCleanupArgs>,
): Promise<Infer<typeof vCleanupCounts>> {
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

  const { previewClientMaxAgeMs } = args;
  const previewClients =
    previewClientMaxAgeMs === undefined
      ? []
      : (
          await ctx.db
            .query("clients")
            .withIndex("by_deployment_type", (q) => q.eq("deploymentType", "preview"))
            .collect()
        )
          .filter(
            (client) =>
              (client.lastSignInAt ?? client.createdAt) < args.now - previewClientMaxAgeMs,
          )
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

  const counts = {
    authRequests: requests.length,
    authorizationCodes: codes.length,
    registrationTokens: tokens.length,
    previewClients: previewClients.length,
    signIns: signIns.length,
    emailSends: emailSends.length,
  };
  if (Object.values(counts).some((count) => count === BATCH)) {
    await ctx.scheduler.runAfter(0, internal.lifecycle.continueCleanup, {
      now: args.now,
      ...(previewClientMaxAgeMs === undefined ? {} : { previewClientMaxAgeMs }),
      signInRetentionMs: args.signInRetentionMs,
    });
  }
  return counts;
}

/**
 * Deletes what has run out: expired requests, codes and registration tokens, preview clients
 * nobody used for `previewClientMaxAgeMs` when the host passes it, audit rows older than
 * `signInRetentionMs`, and email send rows outside the send window. The host schedules this daily
 * from a cron; production and development clients are never touched. The counts are this call's
 * batch: a full batch schedules the next one, so one call drains everything older than `now`.
 */
export const cleanup = mutation({
  args: vCleanupArgs,
  returns: vCleanupCounts,
  handler: async (ctx, args) => await cleanupBatch(ctx, args),
});

/** The next batch of a `cleanup` call that filled a batch. */
export const continueCleanup = internalMutation({
  args: vCleanupArgs,
  returns: v.null(),
  handler: async (ctx, args) => {
    await cleanupBatch(ctx, args);
    return null;
  },
});
