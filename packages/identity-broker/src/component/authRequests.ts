import { v, type Infer } from "convex/values";
import { mutation, query, type MutationCtx } from "./_generated/server";
import type { Doc } from "./_generated/dataModel";
import { sha256Base64Url } from "./crypto";
import { vAuthRequest, vUpstreamIdentity } from "./schema";

const { array, boolean, literal, number, object, optional, string, union } = v;

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
    freshLogin: boolean(),
    txnCookieHash: optional(string()),
    createdAt: number(),
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
      freshLogin: args.freshLogin,
      ...optionalField("txnCookieHash", args.txnCookieHash),
      createdAt: args.createdAt,
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

/** The user chose an OAuth or OIDC connector; the request now waits for that connector's callback. */
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
    // A chooser page can be reloaded, so a pending request may start upstream more than once; the
    // newest state hash wins. Any other status means the flow already moved on.
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
    freshLogin: boolean(),
    /** When /authorize stored the request: an upstream `auth_time` before it is an old session. */
    createdAt: number(),
    ...vReturn.fields,
  }),
  object({ status: literal("expired"), requestId: string(), ...vReturn.fields }),
  object({ status: literal("unbound") }),
  object({ status: literal("missing") }),
);
type ClaimResult = Infer<typeof vClaimResult>;

/**
 * The callback of `connector` arrived with its state. Claiming moves the request to `claimed` in
 * the same mutation that finds it, so a replayed or raced callback finds nothing to claim. A
 * request started for another connector is not claimed: its state cannot finish elsewhere. A
 * request that went through the chooser is claimed only from the browser that holds its
 * transaction cookie; any other browser gets `unbound` and the request keeps waiting.
 */
export const claimUpstream = mutation({
  args: {
    upstreamStateHash: string(),
    connector: string(),
    /** SHA-256 hex of each transaction cookie the callback request carried. */
    txnCookieHashes: array(string()),
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
    if (
      request.txnCookieHash !== undefined &&
      !args.txnCookieHashes.includes(request.txnCookieHash)
    ) {
      return { status: "unbound" };
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
      freshLogin: request.freshLogin,
      createdAt: request.createdAt,
      ...back,
    };
  },
});

/** Codes one request may send. */
const EMAIL_SENDS_PER_REQUEST = 3;
/** The least time between two sends of one request. */
const EMAIL_SEND_INTERVAL_MS = 60 * 1000;
/** Codes one address may receive in `EMAIL_SEND_WINDOW_MS`, across all requests. */
const EMAIL_SENDS_PER_ADDRESS = 5;
/** Codes the broker sends in `EMAIL_SEND_WINDOW_MS`, across all addresses. */
const EMAIL_SENDS_GLOBAL = 200;
/** The rolling window of the per-address count; `lifecycle.cleanup` drops older `emailSends` rows. */
export const EMAIL_SEND_WINDOW_MS = 60 * 60 * 1000;

const vStartEmailResult = union(
  object({ ok: literal(true), ...vReturn.fields }),
  object({
    ok: literal(false),
    error: union(
      literal("expired"),
      literal("wrong_status"),
      literal("locked"),
      literal("too_soon"),
      literal("request_limit"),
      literal("address_limit"),
      literal("global_limit"),
    ),
    ...vReturn.fields,
  }),
  object({ ok: literal(false), error: literal("not_found") }),
);
type StartEmailResult = Infer<typeof vStartEmailResult>;

/**
 * The user chose the email connector and typed an address; a code may be sent to it. A request
 * sends at most `EMAIL_SENDS_PER_REQUEST` codes, `EMAIL_SEND_INTERVAL_MS` apart, an address
 * receives at most `EMAIL_SENDS_PER_ADDRESS` codes per `EMAIL_SEND_WINDOW_MS`, and the broker sends
 * at most `EMAIL_SENDS_GLOBAL` in that window. A resend replaces the code and keeps the attempt
 * count, so a request locked by `maxAttempts` wrong codes stays locked.
 */
export const startEmail = mutation({
  args: {
    requestId: string(),
    connector: string(),
    email: string(),
    /** SHA-256 hex of the canonical address. */
    emailHash: string(),
    emailCodeHash: string(),
    emailCodeExpiresAt: number(),
    maxAttempts: number(),
    now: number(),
  },
  returns: vStartEmailResult,
  handler: async (ctx, args): Promise<StartEmailResult> => {
    const request = await findByRequestId(ctx, args.requestId);
    if (request === null) {
      return { ok: false, error: "not_found" };
    }
    const back = returnTo(request);
    if (request.expiresAt <= args.now) {
      return { ok: false, error: "expired", ...back };
    }
    if (request.status !== "pending" && request.status !== "emailSent") {
      return { ok: false, error: "wrong_status", ...back };
    }
    const sent =
      request.status === "emailSent"
        ? {
            sends: request.emailSends,
            lastSentAt: request.emailLastSentAt,
            attempts: request.emailAttempts,
          }
        : { sends: 0, lastSentAt: undefined, attempts: 0 };
    if (sent.attempts >= args.maxAttempts) {
      return { ok: false, error: "locked", ...back };
    }
    if (sent.sends >= EMAIL_SENDS_PER_REQUEST) {
      return { ok: false, error: "request_limit", ...back };
    }
    if (sent.lastSentAt !== undefined && args.now - sent.lastSentAt < EMAIL_SEND_INTERVAL_MS) {
      return { ok: false, error: "too_soon", ...back };
    }
    const recentToAddress = await ctx.db
      .query("emailSends")
      .withIndex("by_email_hash_and_at", (q) =>
        q.eq("emailHash", args.emailHash).gt("at", args.now - EMAIL_SEND_WINDOW_MS),
      )
      .take(EMAIL_SENDS_PER_ADDRESS);
    if (recentToAddress.length >= EMAIL_SENDS_PER_ADDRESS) {
      return { ok: false, error: "address_limit", ...back };
    }
    const recent = await ctx.db
      .query("emailSends")
      .withIndex("by_at", (q) => q.gt("at", args.now - EMAIL_SEND_WINDOW_MS))
      .take(EMAIL_SENDS_GLOBAL);
    if (recent.length >= EMAIL_SENDS_GLOBAL) {
      return { ok: false, error: "global_limit", ...back };
    }
    await ctx.db.insert("emailSends", { emailHash: args.emailHash, at: args.now });
    await ctx.db.replace("authRequests", request._id, {
      status: "emailSent",
      ...baseFields(request),
      connector: args.connector,
      email: args.email,
      emailCodeHash: args.emailCodeHash,
      emailCodeExpiresAt: args.emailCodeExpiresAt,
      emailAttempts: sent.attempts,
      emailSends: sent.sends + 1,
      emailLastSentAt: args.now,
    });
    return { ok: true, ...back };
  },
});

const vVerifyEmailResult = union(
  object({ ok: literal(true), ...vReturn.fields }),
  object({
    ok: literal(false),
    error: union(
      literal("wrong_code"),
      literal("locked"),
      literal("code_expired"),
      literal("expired"),
      literal("wrong_status"),
    ),
    ...vReturn.fields,
  }),
  object({ ok: literal(false), error: literal("not_found") }),
);
type VerifyEmailResult = Infer<typeof vVerifyEmailResult>;

/**
 * Checks a typed email code. A match completes the request with the canonical address as the
 * upstream identity and issues the authorization code; a miss counts an attempt, and the request
 * locks at `maxAttempts`.
 */
export const verifyEmailCode = mutation({
  args: {
    requestId: string(),
    emailCodeHash: string(),
    maxAttempts: number(),
    codeHash: string(),
    codeExpiresAt: number(),
    now: number(),
  },
  returns: vVerifyEmailResult,
  handler: async (ctx, args): Promise<VerifyEmailResult> => {
    const request = await findByRequestId(ctx, args.requestId);
    if (request === null) {
      return { ok: false, error: "not_found" };
    }
    const back = returnTo(request);
    if (request.expiresAt <= args.now) {
      return { ok: false, error: "expired", ...back };
    }
    if (request.status !== "emailSent") {
      return { ok: false, error: "wrong_status", ...back };
    }
    if (request.emailCodeExpiresAt <= args.now) {
      return { ok: false, error: "code_expired", ...back };
    }
    if (request.emailAttempts >= args.maxAttempts) {
      return { ok: false, error: "locked", ...back };
    }
    if (request.emailCodeHash !== args.emailCodeHash) {
      const attempts = request.emailAttempts + 1;
      await ctx.db.patch("authRequests", request._id, { emailAttempts: attempts });
      return { ok: false, error: attempts >= args.maxAttempts ? "locked" : "wrong_code", ...back };
    }
    await ctx.db.replace("authRequests", request._id, {
      status: "completed",
      ...baseFields(request),
      expiresAt: completedExpiresAt(request, args.codeExpiresAt),
      identity: {
        connector: request.connector,
        upstreamId: request.email,
        email: request.email,
        emailVerified: true,
      },
      authTime: args.now,
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

/** The connector attested the identity after a claim; the authorization code can be handed out. */
export const complete = mutation({
  args: {
    requestId: string(),
    identity: vUpstreamIdentity,
    authTime: number(),
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
      authTime: args.authTime,
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

/** Deletes a request the user abandoned at the hub, such as a declined consent. */
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
    authTime: number(),
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
      authTime: request.authTime,
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
    freshLogin: request.freshLogin,
    ...optionalField("txnCookieHash", request.txnCookieHash),
    createdAt: request.createdAt,
    expiresAt: request.expiresAt,
  };
}
