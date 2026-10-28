import { v, type Infer } from "convex/values";
import { internal } from "./_generated/api";
import { internalMutation, mutation, type MutationCtx } from "./_generated/server";
import { EMAIL_SEND_WINDOW_MS } from "./authRequests";

const { number, object } = v;

/** How many documents one batch deletes per table, so a batch stays well inside one transaction. */
const BATCH = 200;
/** How many batches one `cleanup` call schedules after its own, so a backlog cannot loop forever. */
const MAX_CONTINUATIONS = 50;

const vCleanupArgs = object({
  now: number(),
  previewClientMaxAgeMs: number(),
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
 * schedules the next one, with the same `now`, until `MAX_CONTINUATIONS` batches followed the first.
 */
async function cleanupBatch(
  ctx: MutationCtx,
  args: Infer<typeof vCleanupArgs>,
  continuation: number,
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

  const counts = {
    authRequests: requests.length,
    authorizationCodes: codes.length,
    registrationTokens: tokens.length,
    previewClients: previewClients.length,
    signIns: signIns.length,
    emailSends: emailSends.length,
  };
  if (continuation < MAX_CONTINUATIONS && Object.values(counts).some((count) => count === BATCH)) {
    await ctx.scheduler.runAfter(0, internal.lifecycle.continueCleanup, {
      now: args.now,
      previewClientMaxAgeMs: args.previewClientMaxAgeMs,
      signInRetentionMs: args.signInRetentionMs,
      continuation: continuation + 1,
    });
  }
  return counts;
}

/**
 * Deletes what has run out: expired requests, codes and registration tokens, preview clients
 * nobody used for `previewClientMaxAgeMs`, audit rows older than `signInRetentionMs`, and email send
 * rows outside the send window. The host schedules this daily from a cron; production and
 * development clients are never touched. The counts are this call's batch: a full batch schedules
 * the next one, so one call drains the backlog.
 */
export const cleanup = mutation({
  args: vCleanupArgs,
  returns: vCleanupCounts,
  handler: async (ctx, args) => await cleanupBatch(ctx, args, 0),
});

/** The next batch of a `cleanup` call that filled a batch. */
export const continueCleanup = internalMutation({
  args: { ...vCleanupArgs.fields, continuation: number() },
  returns: v.null(),
  handler: async (ctx, args) => {
    await cleanupBatch(
      ctx,
      {
        now: args.now,
        previewClientMaxAgeMs: args.previewClientMaxAgeMs,
        signInRetentionMs: args.signInRetentionMs,
      },
      args.continuation,
    );
    return null;
  },
});
