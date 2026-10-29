import * as oauth from "oauth4webapi";
import type { OauthConnector, OidcConnector, UpstreamIdentity } from "./types.js";

const discovered = new Map<string, Promise<oauth.AuthorizationServer>>();

/**
 * Discovery, once per issuer per isolate: RFC 8414 metadata for a plain OAuth connector, OIDC
 * Discovery for an OIDC one. oauth4webapi then holds each callback to that metadata, so a provider
 * that advertises `authorization_response_iss_parameter_supported` must send `iss` (RFC 9207).
 */
function authorizationServer(
  connector: OauthConnector | OidcConnector,
): Promise<oauth.AuthorizationServer> {
  const cached = discovered.get(connector.issuer);
  if (cached !== undefined) {
    return cached;
  }
  const issuer = new URL(connector.issuer);
  const pending = oauth
    .discoveryRequest(issuer, { algorithm: connector.kind === "oauth" ? "oauth2" : "oidc" })
    .then((response) => oauth.processDiscoveryResponse(issuer, response));
  discovered.set(connector.issuer, pending);
  pending.catch(() => discovered.delete(connector.issuer));
  return pending;
}

export type UpstreamStart = {
  url: string;
  state: string;
  codeVerifier: string;
  nonce: string | undefined;
};

/** The authorization URL for a connector, with fresh state, PKCE pair and, for OIDC, a nonce. */
export async function startUpstream(args: {
  connector: OauthConnector | OidcConnector;
  callbackUrl: string;
  freshLogin: boolean;
}): Promise<UpstreamStart> {
  const as = await authorizationServer(args.connector);
  if (as.authorization_endpoint === undefined) {
    throw new Error(`Connector "${args.connector.name}" has no authorization endpoint`);
  }
  const state = oauth.generateRandomState();
  const codeVerifier = oauth.generateRandomCodeVerifier();
  const nonce = args.connector.kind === "oidc" ? oauth.generateRandomNonce() : undefined;
  const url = new URL(as.authorization_endpoint);
  url.searchParams.set("client_id", args.connector.clientId());
  url.searchParams.set("redirect_uri", args.callbackUrl);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", args.connector.scopes.join(" "));
  url.searchParams.set("code_challenge", await oauth.calculatePKCECodeChallenge(codeVerifier));
  url.searchParams.set("code_challenge_method", "S256");
  url.searchParams.set("state", state);
  if (nonce !== undefined) {
    url.searchParams.set("nonce", nonce);
  }
  if (args.freshLogin && args.connector.kind === "oidc") {
    // With max_age the provider must return auth_time (OIDC Core 3.1.2.1), which the callback
    // checks; prompt=login asks for the login itself.
    url.searchParams.set("prompt", "login");
    url.searchParams.set("max_age", "0");
  }
  return { url: url.toString(), state, codeVerifier, nonce };
}

export type UpstreamFinish = {
  identity: UpstreamIdentity;
  /**
   * The id_token's `auth_time`, in seconds: when the provider last authenticated the user. A plain
   * OAuth connector has no id_token and an OIDC provider may omit the claim, so it can be absent.
   */
  authTimeSeconds: number | undefined;
};

/**
 * The connector callback: validate the response, exchange the code, and read the identity. Errors
 * propagate; the caller turns them into a redirect back to the client.
 */
export async function finishUpstream(args: {
  connector: OauthConnector | OidcConnector;
  callbackUrl: string;
  currentUrl: URL;
  state: string;
  codeVerifier: string;
  nonce: string | undefined;
}): Promise<UpstreamFinish> {
  const as = await authorizationServer(args.connector);
  const client: oauth.Client = { client_id: args.connector.clientId() };
  const clientAuth = oauth.ClientSecretPost(args.connector.clientSecret());
  const params = oauth.validateAuthResponse(as, client, args.currentUrl, args.state);
  const response = await oauth.authorizationCodeGrantRequest(
    as,
    client,
    clientAuth,
    params,
    args.callbackUrl,
    args.codeVerifier,
  );
  if (args.connector.kind === "oauth") {
    const tokens = await oauth.processAuthorizationCodeResponse(as, client, response);
    return {
      identity: await args.connector.identity(tokens.access_token),
      authTimeSeconds: undefined,
    };
  }
  const tokens = await oauth.processAuthorizationCodeResponse(as, client, response, {
    requireIdToken: true,
    ...(args.nonce === undefined ? {} : { expectedNonce: args.nonce }),
  });
  const claims = oauth.getValidatedIdTokenClaims(tokens);
  if (claims === undefined) {
    throw new Error(`Connector "${args.connector.name}" returned no id_token`);
  }
  const identity: UpstreamIdentity = { upstreamId: claims.sub };
  if (typeof claims["email"] === "string") {
    identity.email = claims["email"];
  }
  if (typeof claims["email_verified"] === "boolean") {
    identity.emailVerified = claims["email_verified"];
  }
  if (typeof claims["name"] === "string") {
    identity.name = claims["name"];
  }
  if (typeof claims["picture"] === "string") {
    identity.picture = claims["picture"];
  }
  // oauth4webapi rejects an id_token whose `auth_time` is present and not a non-negative number.
  return { identity, authTimeSeconds: claims.auth_time };
}
