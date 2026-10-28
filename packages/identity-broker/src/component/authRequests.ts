import { v, type Infer } from "convex/values";
import { mutation } from "./_generated/server";
import type { Doc } from "./_generated/dataModel";
import { sha256Base64Url } from "./crypto";
import { vTokenEndpointAuthMethod, vUpstreamIdentity } from "./schema";

const { boolean, literal, number, object, optional, string, union } = v;

/**
 * Stores a validated /authorize request as it redirects to the connector. The caller has checked
 * the client and the redirect URI and generated the upstream state, PKCE verifier and nonce.
 */
export const create = mutation({
  args: {
    appId: string(),
    clientId: string(),
    redirectUri: string(),
    scope: string(),
    state: optional(string()),
    nonce: optional(string()),
    codeChallenge: string(),
    expiresAt: number(),
    connector: string(),
    upstreamStateHash: string(),
    upstreamCodeVerifier: string(),
    upstreamNonce: optional(string()),
  },
  returns: v.null(),
  handler: async (ctx, args) => {
    await ctx.db.insert("authRequests", {
      status: "upstream",
      appId: args.appId,
      clientId: args.clientId,
      redirectUri: args.redirectUri,
      scope: args.scope,
      ...(args.state === undefined ? {} : { state: args.state }),
      ...(args.nonce === undefined ? {} : { nonce: args.nonce }),
      codeChallenge: args.codeChallenge,
      expiresAt: args.expiresAt,
      connector: args.connector,
      upstreamStateHash: args.upstreamStateHash,
      upstreamCodeVerifier: args.upstreamCodeVerifier,
      ...(args.upstreamNonce === undefined ? {} : { upstreamNonce: args.upstreamNonce }),
    });
    return null;
  },
});

/** Where the user goes back to once a request fails or finishes: the client's exact redirect URI. */
const vReturn = { redirectUri: string(), state: optional(string()) };

const vClaimResult = union(
  object({
    status: literal("claimed"),
    requestId: v.id("authRequests"),
    upstreamCodeVerifier: string(),
    upstreamNonce: optional(string()),
    ...vReturn,
  }),
  object({ status: literal("expired"), ...vReturn }),
  object({ status: literal("missing") }),
);

/**
 * The callback of `connector` arrived with its state. Claiming moves the request to `claimed` in
 * the same mutation that finds it, so a replayed or raced callback finds nothing to claim. A
 * request started for another connector is not claimed: its state cannot finish elsewhere.
 */
export const claimUpstream = mutation({
  args: { upstreamStateHash: string(), connector: string(), now: number() },
  returns: vClaimResult,
  handler: async (ctx, args): Promise<Infer<typeof vClaimResult>> => {
    const request = await ctx.db
      .query("authRequests")
      .withIndex("by_upstream_state_hash", (q) => q.eq("upstreamStateHash", args.upstreamStateHash))
      .unique();
    if (request === null || request.status !== "upstream" || request.connector !== args.connector) {
      return { status: "missing" };
    }
    const back = {
      redirectUri: request.redirectUri,
      ...(request.state === undefined ? {} : { state: request.state }),
    };
    if (request.expiresAt <= args.now) {
      await ctx.db.delete("authRequests", request._id);
      return { status: "expired", ...back };
    }
    await ctx.db.replace("authRequests", request._id, {
      status: "claimed",
      ...baseFields(request),
    });
    return {
      status: "claimed",
      requestId: request._id,
      upstreamCodeVerifier: request.upstreamCodeVerifier,
      ...(request.upstreamNonce === undefined ? {} : { upstreamNonce: request.upstreamNonce }),
      ...back,
    };
  },
});

/**
 * The connector attested the identity after a claim: the request now holds the hash of its
 * authorization code and lives until the code expires. False when the request is gone, expired,
 * or not claimed; a request whose upstream exchange failed stays claimed until cleanup.
 */
export const complete = mutation({
  args: {
    requestId: v.id("authRequests"),
    identity: vUpstreamIdentity,
    codeHash: string(),
    codeExpiresAt: number(),
    now: number(),
  },
  returns: boolean(),
  handler: async (ctx, args) => {
    const request = await ctx.db.get("authRequests", args.requestId);
    if (request === null || request.status !== "claimed" || request.expiresAt <= args.now) {
      return false;
    }
    await ctx.db.replace("authRequests", request._id, {
      status: "completed",
      ...baseFields(request),
      expiresAt: args.codeExpiresAt,
      codeHash: args.codeHash,
      identity: args.identity,
    });
    return true;
  },
});

const vExchangeResult = union(
  object({
    ok: literal(true),
    appId: string(),
    scope: string(),
    nonce: optional(string()),
    identity: vUpstreamIdentity,
  }),
  object({
    ok: literal(false),
    error: union(literal("invalid_client"), literal("invalid_grant")),
    description: string(),
  }),
);

/**
 * Authenticates the client and redeems an authorization code: bound to the client, the redirect
 * URI and the PKCE challenge of its request (OAuth 2.1 section 4.1.3). The client and its app are
 * read in this transaction, so deleting either commits wholly before the redemption or after it.
 * The redemption deletes the request that holds the code, so a second one finds nothing.
 */
export const exchangeCode = mutation({
  args: {
    clientId: string(),
    /** SHA-256 hex of the client secret the token request carried. */
    clientSecretHash: string(),
    tokenEndpointAuthMethod: vTokenEndpointAuthMethod,
    codeHash: string(),
    redirectUri: optional(string()),
    codeVerifier: string(),
    now: number(),
  },
  returns: vExchangeResult,
  handler: async (ctx, args): Promise<Infer<typeof vExchangeResult>> => {
    const client = await ctx.db
      .query("clients")
      .withIndex("by_client_id", (q) => q.eq("clientId", args.clientId))
      .unique();
    const app =
      client === null
        ? null
        : await ctx.db
            .query("apps")
            .withIndex("by_app_id", (q) => q.eq("appId", client.appId))
            .unique();
    if (
      client === null ||
      app === null ||
      client.secretHash !== args.clientSecretHash ||
      client.tokenEndpointAuthMethod !== args.tokenEndpointAuthMethod
    ) {
      return { ok: false, error: "invalid_client", description: "Client authentication failed." };
    }
    const request = await ctx.db
      .query("authRequests")
      .withIndex("by_code_hash", (q) => q.eq("codeHash", args.codeHash))
      .unique();
    // Only a completed request holds a code hash.
    if (request === null || request.status !== "completed") {
      return {
        ok: false,
        error: "invalid_grant",
        description: "The authorization code is unknown or was already used.",
      };
    }
    if (request.expiresAt <= args.now) {
      return {
        ok: false,
        error: "invalid_grant",
        description: "The authorization code expired.",
      };
    }
    if (request.clientId !== args.clientId) {
      return {
        ok: false,
        error: "invalid_grant",
        description: "The authorization code belongs to another client.",
      };
    }
    if (args.redirectUri !== undefined && args.redirectUri !== request.redirectUri) {
      return {
        ok: false,
        error: "invalid_grant",
        description: "redirect_uri does not match the authorization request.",
      };
    }
    if ((await sha256Base64Url(args.codeVerifier)) !== request.codeChallenge) {
      return {
        ok: false,
        error: "invalid_grant",
        description: "code_verifier does not match code_challenge.",
      };
    }
    await ctx.db.delete("authRequests", request._id);
    return {
      ok: true,
      appId: request.appId,
      scope: request.scope,
      ...(request.nonce === undefined ? {} : { nonce: request.nonce }),
      identity: request.identity,
    };
  },
});

/**
 * The fields shared by every status, taken from a stored request. `replace` needs the whole
 * document, and the status-specific fields of the old status must not leak into the new one.
 */
function baseFields(request: Doc<"authRequests">) {
  return {
    appId: request.appId,
    clientId: request.clientId,
    redirectUri: request.redirectUri,
    scope: request.scope,
    ...(request.state === undefined ? {} : { state: request.state }),
    ...(request.nonce === undefined ? {} : { nonce: request.nonce }),
    codeChallenge: request.codeChallenge,
    expiresAt: request.expiresAt,
  };
}
