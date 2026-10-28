import { v } from "convex/values";
import { internal } from "./_generated/api";
import { internalMutation, mutation, type MutationCtx } from "./_generated/server";

const { number } = v;

/** How many documents one batch deletes, so a batch stays well inside one transaction. */
const BATCH = 200;

/**
 * Deletes one batch of the authorization requests that ran out before `now`. A full batch may
 * leave more, so it schedules the next one with the same `now`. The cutoff never moves, so the run
 * ends: a request written after the run began runs out after `now`, and the requests that had run
 * out by then are a fixed set.
 */
async function cleanupBatch(ctx: MutationCtx, now: number): Promise<void> {
  const requests = await ctx.db
    .query("authRequests")
    .withIndex("by_expires_at", (q) => q.lt("expiresAt", now))
    .take(BATCH);
  for (const request of requests) {
    await ctx.db.delete("authRequests", request._id);
  }
  if (requests.length === BATCH) {
    await ctx.scheduler.runAfter(0, internal.lifecycle.continueCleanup, { now });
  }
}

/**
 * Deletes the authorization requests that ran out before `now`: unfinished sign-ins, and completed
 * ones whose code expired. The host schedules this daily from a cron; one call drains them all.
 */
export const cleanup = mutation({
  args: { now: number() },
  returns: v.null(),
  handler: async (ctx, args) => {
    await cleanupBatch(ctx, args.now);
    return null;
  },
});

/** The next batch of a `cleanup` call that filled a batch. */
export const continueCleanup = internalMutation({
  args: { now: number() },
  returns: v.null(),
  handler: async (ctx, args) => {
    await cleanupBatch(ctx, args.now);
    return null;
  },
});
