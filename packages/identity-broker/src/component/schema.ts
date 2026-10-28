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
 * account (the GitHub user id, the OIDC `sub`). The pairwise subject is derived from it on the
 * host, where the salt lives.
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
  appId: string(),
  clientId: string(),
  redirectUri: string(),
  scope: string(),
  state: optional(string()),
  nonce: optional(string()),
  codeChallenge: string(),
  expiresAt: number(),
};

const vAuthRequest = union(
  // Stored by /authorize as it redirects to the connector; its callback claims it by the state hash.
  object({
    status: literal("upstream"),
    ...authRequestFields,
    connector: string(),
    upstreamStateHash: string(),
    upstreamCodeVerifier: string(),
    upstreamNonce: optional(string()),
  }),
  // The connector callback arrived and the code exchange is running; a replay finds this and stops.
  object({ status: literal("claimed"), ...authRequestFields }),
  // The connector attested the identity. `codeHash` is the SHA-256 hex of the authorization code,
  // and `expiresAt` is the code's expiry: the token endpoint deletes the request as it redeems it.
  object({
    status: literal("completed"),
    ...authRequestFields,
    codeHash: string(),
    identity: vUpstreamIdentity,
  }),
);

export default defineSchema({
  apps: defineTable({
    /** The app's identity namespace: every `sub` of the app is derived from it. */
    appId: string(),
    /** Exact hosts or `*.suffix` patterns a client callback may use, e.g. `*.convex.site`. */
    allowedCallbackHosts: array(string()),
  }).index("by_app_id", ["appId"]),

  registrationTokens: defineTable({
    tokenHash: string(),
    appId: string(),
    createdAt: number(),
  })
    .index("by_token_hash", ["tokenHash"])
    .index("by_app_id", ["appId"]),

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
    .index("by_upstream_state_hash", ["upstreamStateHash"])
    .index("by_code_hash", ["codeHash"])
    .index("by_expires_at", ["expiresAt"]),

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
