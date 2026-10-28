import { v, type Infer } from "convex/values";
import { mutation, query, type MutationCtx } from "./_generated/server";
import type { Doc } from "./_generated/dataModel";
import { sha256Base64Url } from "./crypto";
import { vAuthRequest, vUpstreamIdentity } from "./schema";

const { literal, number, object, optional, string, union } = v;

/** Where the user goes back to once a request fails or finishes: the client's exact redirect URI. */
const vReturn = object({ redirectUri: string(), state: optional(string()) });

const vTransitionResult = union(
  object({ ok: literal(true), ...vReturn.fields }),
  object({
    ok: literal(false),
    error: union(literal("expired"), literal("wrong_status")),
    ...vReturn.fields,
  }),
  object({ ok: literal(false), error: literal("not_found") }),
);
type TransitionResult = Infer<typeof vTransitionResult>;

async function findByRequestId(ctx: MutationCtx, requestId: string) {
  return await ctx.db
    .query("authRequests")
    .withIndex("by_request_id", (q) => q.eq("requestId", requestId))
    .unique();
}

/** Stores a validated /authorize request. The caller has already checked the client and redirect URI. */
export const create = mutation({
  args: {
    requestId: string(),
    appId: string(),
    clientId: string(),
    redirectUri: string(),
    scope: string(),
    state: optional(string()),
    nonce: optional(string()),
    codeChallenge: string(),
    expiresAt: number(),
  },
  returns: v.null(),
  handler: async (ctx, args) => {
    await ctx.db.insert("authRequests", {
      status: "pending",
      requestId: args.requestId,
      appId: args.appId,
      clientId: args.clientId,
      redirectUri: args.redirectUri,
      scope: args.scope,
      ...optionalField("state", args.state),
      ...optionalField("nonce", args.nonce),
      codeChallenge: args.codeChallenge,
      expiresAt: args.expiresAt,
    });
    return null;
  },
});

export const get = query({
  args: { requestId: string() },
  returns: union(vAuthRequest, v.null()),
  handler: async (ctx, args) => {
    const request = await ctx.db
      .query("authRequests")
      .withIndex("by_request_id", (q) => q.eq("requestId", args.requestId))
      .unique();
    if (request === null) {
      return null;
    }
    const { _id, _creationTime, ...fields } = request;
    return fields;
  },
});

/** The request now waits for its connector's callback. */
export const startUpstream = mutation({
  args: {
    requestId: string(),
    connector: string(),
    upstreamStateHash: string(),
    upstreamCodeVerifier: string(),
    upstreamNonce: optional(string()),
    now: number(),
  },
  returns: vTransitionResult,
  handler: async (ctx, args): Promise<TransitionResult> => {
    const request = await findByRequestId(ctx, args.requestId);
    if (request === null) {
      return { ok: false, error: "not_found" };
    }
    const back = returnTo(request);
    if (request.expiresAt <= args.now) {
      return { ok: false, error: "expired", ...back };
    }
    // Any status but pending or upstream means the flow already moved on.
    if (request.status !== "pending" && request.status !== "upstream") {
      return { ok: false, error: "wrong_status", ...back };
    }
    await ctx.db.replace("authRequests", request._id, {
      status: "upstream",
      ...baseFields(request),
      connector: args.connector,
      upstreamStateHash: args.upstreamStateHash,
      upstreamCodeVerifier: args.upstreamCodeVerifier,
      ...optionalField("upstreamNonce", args.upstreamNonce),
    });
    return { ok: true, ...back };
  },
});

const vClaimResult = union(
  object({
    status: literal("claimed"),
    requestId: string(),
    connector: string(),
    upstreamCodeVerifier: string(),
    upstreamNonce: optional(string()),
    ...vReturn.fields,
  }),
  object({ status: literal("expired"), requestId: string(), ...vReturn.fields }),
  object({ status: literal("missing") }),
);
type ClaimResult = Infer<typeof vClaimResult>;

/**
 * The callback of `connector` arrived with its state. Claiming moves the request to `claimed` in
 * the same mutation that finds it, so a replayed or raced callback finds nothing to claim. A
 * request started for another connector is not claimed: its state cannot finish elsewhere.
 */
export const claimUpstream = mutation({
  args: {
    upstreamStateHash: string(),
    connector: string(),
    now: number(),
  },
  returns: vClaimResult,
  handler: async (ctx, args): Promise<ClaimResult> => {
    const request = await ctx.db
      .query("authRequests")
      .withIndex("by_upstream_state_hash", (q) => q.eq("upstreamStateHash", args.upstreamStateHash))
      .unique();
    if (request === null || request.status !== "upstream" || request.connector !== args.connector) {
      return { status: "missing" };
    }
    const back = returnTo(request);
    if (request.expiresAt <= args.now) {
      await ctx.db.delete("authRequests", request._id);
      return { status: "expired", requestId: request.requestId, ...back };
    }
    await ctx.db.replace("authRequests", request._id, {
      status: "claimed",
      ...baseFields(request),
      connector: request.connector,
    });
    return {
      status: "claimed",
      requestId: request.requestId,
      connector: request.connector,
      upstreamCodeVerifier: request.upstreamCodeVerifier,
      ...optionalField("upstreamNonce", request.upstreamNonce),
      ...back,
    };
  },
});

/** The connector attested the identity after a claim; the authorization code can be handed out. */
export const complete = mutation({
  args: {
    requestId: string(),
    identity: vUpstreamIdentity,
    codeHash: string(),
    codeExpiresAt: number(),
    now: number(),
  },
  returns: vTransitionResult,
  handler: async (ctx, args): Promise<TransitionResult> => {
    const request = await findByRequestId(ctx, args.requestId);
    if (request === null) {
      return { ok: false, error: "not_found" };
    }
    const back = returnTo(request);
    if (request.expiresAt <= args.now) {
      return { ok: false, error: "expired", ...back };
    }
    if (request.status !== "claimed") {
      return { ok: false, error: "wrong_status", ...back };
    }
    await ctx.db.replace("authRequests", request._id, {
      status: "completed",
      ...baseFields(request),
      expiresAt: completedExpiresAt(request, args.codeExpiresAt),
      identity: args.identity,
    });
    await ctx.db.insert("authorizationCodes", {
      codeHash: args.codeHash,
      authRequestId: request._id,
      clientId: request.clientId,
      expiresAt: args.codeExpiresAt,
    });
    return { ok: true, ...back };
  },
});

/** Deletes a request whose upstream exchange failed. */
export const abandon = mutation({
  args: { requestId: string() },
  returns: union(vReturn, v.null()),
  handler: async (ctx, args) => {
    const request = await findByRequestId(ctx, args.requestId);
    if (request === null) {
      return null;
    }
    await ctx.db.delete("authRequests", request._id);
    return returnTo(request);
  },
});

const vExchangeResult = union(
  object({
    ok: literal(true),
    appId: string(),
    clientId: string(),
    scope: string(),
    nonce: optional(string()),
    identity: vUpstreamIdentity,
  }),
  object({ ok: literal(false), description: string() }),
);
type ExchangeResult = Infer<typeof vExchangeResult>;

/**
 * Redeems an authorization code: single use, bound to the client, the redirect URI and the PKCE
 * challenge of its request (OAuth 2.1 section 4.1.3). On success the code and the request are gone.
 */
export const exchangeCode = mutation({
  args: {
    codeHash: string(),
    clientId: string(),
    redirectUri: optional(string()),
    codeVerifier: string(),
    now: number(),
  },
  returns: vExchangeResult,
  handler: async (ctx, args): Promise<ExchangeResult> => {
    const code = await ctx.db
      .query("authorizationCodes")
      .withIndex("by_code_hash", (q) => q.eq("codeHash", args.codeHash))
      .unique();
    if (code === null) {
      return { ok: false, description: "The authorization code is unknown." };
    }
    if (code.usedAt !== undefined) {
      // Replay: the code and its request are revoked (RFC 9700 section 4.5.3).
      await ctx.db.delete("authorizationCodes", code._id);
      const request = await ctx.db.get("authRequests", code.authRequestId);
      if (request !== null) {
        await ctx.db.delete("authRequests", request._id);
      }
      return { ok: false, description: "The authorization code was already used." };
    }
    if (code.expiresAt <= args.now) {
      return { ok: false, description: "The authorization code expired." };
    }
    if (code.clientId !== args.clientId) {
      return { ok: false, description: "The authorization code belongs to another client." };
    }
    const request = await ctx.db.get("authRequests", code.authRequestId);
    if (request === null || request.status !== "completed") {
      return { ok: false, description: "The authorization request is gone." };
    }
    if (args.redirectUri !== undefined && args.redirectUri !== request.redirectUri) {
      return { ok: false, description: "redirect_uri does not match the authorization request." };
    }
    if ((await sha256Base64Url(args.codeVerifier)) !== request.codeChallenge) {
      return { ok: false, description: "code_verifier does not match code_challenge." };
    }
    await ctx.db.patch("authorizationCodes", code._id, { usedAt: args.now });
    await ctx.db.delete("authRequests", request._id);
    return {
      ok: true,
      appId: request.appId,
      clientId: request.clientId,
      scope: request.scope,
      ...optionalField("nonce", request.nonce),
      identity: request.identity,
    };
  },
});

function optionalField<K extends string, T>(key: K, value: T | undefined) {
  return value === undefined ? {} : ({ [key]: value } as { [P in K]: T });
}

/**
 * A completed request outlives its authorization code by a minute, so `lifecycle.cleanup` never
 * deletes the request while its code can still be redeemed.
 */
function completedExpiresAt(request: Doc<"authRequests">, codeExpiresAt: number) {
  return Math.max(request.expiresAt, codeExpiresAt + 60 * 1000);
}

function returnTo(request: Doc<"authRequests">) {
  return { redirectUri: request.redirectUri, ...optionalField("state", request.state) };
}

/**
 * The fields shared by every status, taken from a stored request. `replace` needs the whole
 * document, and the status-specific fields of the old status must not leak into the new one.
 */
function baseFields(request: Doc<"authRequests">) {
  return {
    requestId: request.requestId,
    appId: request.appId,
    clientId: request.clientId,
    redirectUri: request.redirectUri,
    scope: request.scope,
    ...optionalField("state", request.state),
    ...optionalField("nonce", request.nonce),
    codeChallenge: request.codeChallenge,
    expiresAt: request.expiresAt,
  };
}
