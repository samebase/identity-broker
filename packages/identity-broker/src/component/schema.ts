import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";

const { array, boolean, literal, number, object, optional, string, union } = v;

/** How a client authenticates at the token endpoint. Public clients are not supported yet. */
export const vTokenEndpointAuthMethod = union(
  literal("client_secret_post"),
  literal("client_secret_basic"),
);

/** The deployment a client stands for. */
export const vDeploymentType = union(
  literal("production"),
  literal("development"),
  literal("preview"),
);

/**
 * What a connector attested about the user. `upstreamId` is the connector's own stable id for the
 * account (the GitHub user id, the OIDC `sub`, the canonical email address). The pairwise subject
 * is derived from it on the host, where the salt lives.
 */
export const vUpstreamIdentity = object({
  connector: string(),
  upstreamId: string(),
  email: optional(string()),
  emailVerified: optional(boolean()),
  name: optional(string()),
  picture: optional(string()),
});

/** The fields every authorization request carries from `/authorize` until it is deleted. */
const authRequestFields = {
  requestId: string(),
  appId: string(),
  clientId: string(),
  redirectUri: string(),
  scope: string(),
  state: optional(string()),
  nonce: optional(string()),
  codeChallenge: string(),
  /** `prompt=login` or `max_age` was sent: the connector must reauthenticate or refuse. */
  freshLogin: boolean(),
  /**
   * SHA-256 hex of the request's transaction cookie, set by `/authorize`. `/continue`, the connector
   * callback, and the email steps need the cookie, so only the browser that started the request can
   * move it on.
   */
  txnCookieHash: string(),
  createdAt: number(),
  expiresAt: number(),
};

export const vAuthRequest = union(
  // Stored by /authorize; the user has not chosen a connector yet.
  object({ status: literal("pending"), ...authRequestFields }),
  // Redirected to an OAuth or OIDC connector; its callback claims the request by the state hash.
  object({
    status: literal("upstream"),
    ...authRequestFields,
    connector: string(),
    upstreamStateHash: string(),
    upstreamCodeVerifier: string(),
    upstreamNonce: optional(string()),
  }),
  // The connector callback arrived and the code exchange is running; a replay finds this and stops.
  object({ status: literal("claimed"), ...authRequestFields, connector: string() }),
  // An email code was sent; the user types it. A resend replaces the code and keeps the counts.
  object({
    status: literal("emailSent"),
    ...authRequestFields,
    connector: string(),
    email: string(),
    emailCodeHash: string(),
    emailCodeExpiresAt: number(),
    /** Wrong codes typed, across every code sent for this request. */
    emailAttempts: number(),
    /** Codes sent for this request. */
    emailSends: number(),
    emailLastSentAt: number(),
  }),
  // The connector attested the identity; the authorization code points here until it is exchanged.
  object({
    status: literal("completed"),
    ...authRequestFields,
    identity: vUpstreamIdentity,
    authTime: number(),
  }),
);

export default defineSchema({
  apps: defineTable({
    appId: string(),
    name: string(),
    firstParty: boolean(),
    /** No longer read. The rows of a hub from before 0.8.0 still hold it. */
    allowedCallbackHosts: optional(array(string())),
    createdAt: number(),
  }).index("by_app_id", ["appId"]),

  clients: defineTable({
    clientId: string(),
    appId: string(),
    secretHash: string(),
    tokenEndpointAuthMethod: vTokenEndpointAuthMethod,
    redirectUri: string(),
    deploymentType: vDeploymentType,
    clientName: string(),
    softwareVersion: string(),
    createdAt: number(),
    lastSignInAt: optional(number()),
  })
    .index("by_client_id", ["clientId"])
    .index("by_app_id", ["appId"])
    .index("by_deployment_type", ["deploymentType"]),

  authRequests: defineTable(vAuthRequest)
    .index("by_request_id", ["requestId"])
    .index("by_upstream_state_hash", ["upstreamStateHash"])
    .index("by_expires_at", ["expiresAt"]),

  authorizationCodes: defineTable({
    codeHash: string(),
    authRequestId: v.id("authRequests"),
    clientId: string(),
    expiresAt: number(),
    usedAt: optional(number()),
  })
    .index("by_code_hash", ["codeHash"])
    .index("by_expires_at", ["expiresAt"]),

  /** One row per email code sent, kept for the rolling send window; no address, only its hash. */
  emailSends: defineTable({
    /** SHA-256 hex of the canonical address. */
    emailHash: string(),
    at: number(),
  })
    .index("by_email_hash_and_at", ["emailHash", "at"])
    .index("by_at", ["at"]),

  signIns: defineTable({
    appId: string(),
    clientId: string(),
    connector: string(),
    sub: string(),
    at: number(),
  })
    .index("by_app_id_and_at", ["appId", "at"])
    .index("by_at", ["at"]),
});
