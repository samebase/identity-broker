import {
  httpActionGeneric,
  internalMutationGeneric,
  internalQueryGeneric,
  type GenericActionCtx,
  type GenericDataModel,
  type HttpRouter,
  type PublicHttpAction,
} from "convex/server";
import { v } from "convex/values";
import * as oauth from "oauth4webapi";
import type { ComponentApi } from "../component/_generated/component.js";
import type {
  Connector,
  OauthConnector,
  OidcConnector,
  UpstreamIdentity,
} from "./connectors/types.js";
import { finishUpstream, startUpstream } from "./connectors/upstream.js";
import { errorPage } from "./html.js";
import {
  signAccessToken,
  signIdToken,
  TOKEN_TTL_SECONDS,
  verifyAccessToken,
  type IdentityClaims,
} from "./jwt.js";
import { parseKeySet, publicJwks, SIGNING_ALGORITHM, type KeySet } from "./keys.js";
import {
  hostAllowed,
  readBearerToken,
  readClientAuthentication,
  validateAuthorizeRest,
  validateAuthorizeTarget,
  validateRegistration,
  validateTokenRequest,
} from "./protocol.js";
import {
  authorizationError,
  authorizationResponse,
  json,
  oauthError,
  readParameters,
  redirect,
} from "./responses.js";
import { pairwiseSubject, randomToken, sha256Hex } from "./subject.js";

export type {
  Connector,
  OauthConnector,
  OidcConnector,
  UpstreamIdentity,
} from "./connectors/types.js";
export { github } from "./connectors/github.js";
export { google } from "./connectors/google.js";
export { createKeySet, parseKeySet, rotateKeySet, type KeySet } from "./keys.js";
export { assertKeySetUsable } from "./jwt.js";

export type IdentityBrokerConfig = {
  /** `components.identityBroker` of the host app. */
  component: ComponentApi;
  /** The issuer URL, such as `https://auth.example.com`. */
  issuer: string;
  /** The content of `IDENTITY_BROKER_KEYS`, read in the request. */
  keys: () => string | undefined;
  connectors: Connector[];
  /**
   * Days without a sign-in after which `cleanup` deletes a preview client. Absent: `cleanup` deletes
   * no client, because a deployment whose client was deleted does not register again by itself.
   */
  previewClientIdleDays?: number;
};

/** A request lives this long from /authorize to the code redirect. */
const AUTH_REQUEST_TTL_MS = 10 * 60 * 1000;
/** A code is redeemed by the client's callback at once. */
const CODE_TTL_MS = 60 * 1000;
/** The scopes the broker grants; any other requested scope is dropped. */
const SCOPES = ["openid", "email", "profile"];
/** How long `cleanup` keeps an audit row of an issued id_token. */
export const SIGN_IN_RETENTION_MS = 90 * 24 * 60 * 60 * 1000;

type Ctx = GenericActionCtx<GenericDataModel>;

export function defineIdentityBroker(config: IdentityBrokerConfig) {
  const issuerUrl = new URL(config.issuer);
  if (issuerUrl.search !== "" || issuerUrl.hash !== "") {
    throw new Error("The issuer must not have a query or fragment");
  }
  const issuer = issuerUrl.href.replace(/\/$/, "");
  const prefix = issuerUrl.pathname.replace(/\/$/, "");
  const path = (suffix: string) => `${prefix}${suffix}`;
  const component = config.component;
  const connectors = new Map(config.connectors.map((connector) => [connector.name, connector]));
  if (connectors.size !== config.connectors.length) {
    throw new Error("Connector names must be unique");
  }
  if (connectors.size === 0) {
    throw new Error("At least one connector is required");
  }
  const { previewClientIdleDays } = config;
  // Zero or less would delete every preview client at the next cleanup.
  if (previewClientIdleDays !== undefined && !(previewClientIdleDays > 0)) {
    throw new Error("previewClientIdleDays must be a positive number of days");
  }

  const keySet = (): KeySet => parseKeySet(config.keys());
  const callbackUrl = (connector: OauthConnector | OidcConnector) =>
    `${issuer}/connectors/${connector.name}/callback`;

  const metadata = () => ({
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    userinfo_endpoint: `${issuer}/userinfo`,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
    registration_endpoint: `${issuer}/register`,
    scopes_supported: SCOPES,
    response_types_supported: ["code"],
    response_modes_supported: ["query"],
    grant_types_supported: ["authorization_code"],
    subject_types_supported: ["pairwise"],
    id_token_signing_alg_values_supported: [SIGNING_ALGORITHM],
    token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic"],
    code_challenge_methods_supported: ["S256"],
    claims_supported: [
      "sub",
      "iss",
      "aud",
      "exp",
      "iat",
      "nonce",
      "email",
      "email_verified",
      "name",
      "picture",
      "connector",
    ],
    authorization_response_iss_parameter_supported: true,
    claims_parameter_supported: false,
    request_parameter_supported: false,
    request_uri_parameter_supported: false,
  });

  const discovery = httpActionGeneric(async () =>
    json(metadata(), 200, { "Cache-Control": "public, max-age=300" }),
  );

  const jwks = httpActionGeneric(async () =>
    json(publicJwks(keySet()), 200, { "Cache-Control": "public, max-age=300" }),
  );

  const authorize = httpActionGeneric(async (ctx, request) => {
    const params = await readParameters(request);
    if (params === null) {
      return oauthError(
        415,
        "invalid_request",
        "A POST must be application/x-www-form-urlencoded.",
      );
    }
    const target = validateAuthorizeTarget(params);
    if (!target.ok) {
      return errorPage("Invalid sign-in request", target.description, target.status);
    }
    const client = await ctx.runQuery(component.clients.get, { clientId: target.value.clientId });
    if (client === null) {
      return errorPage(
        "Unknown client",
        "The client_id is not registered with this provider.",
        400,
      );
    }
    // Exact string comparison, and no redirect to a URI that is not registered (RFC 9700 4.1.3).
    if (client.redirectUri !== target.value.redirectUri) {
      return errorPage(
        "Invalid redirect URI",
        "The redirect_uri is not the one registered for this client.",
        400,
      );
    }
    const back = {
      redirectUri: client.redirectUri,
      issuer,
      state: params.get("state") ?? undefined,
    };
    const rest = validateAuthorizeRest(params, target.value);
    if (!rest.ok) {
      return authorizationError({ ...back, error: rest.error, description: rest.description });
    }
    // The consumer names the connector; the broker shows no page to choose one.
    const connector = connectors.get(rest.value.connector);
    if (connector === undefined) {
      return authorizationError({
        ...back,
        error: "invalid_request",
        description: "connector must name a connector of this provider.",
      });
    }
    const scopes = SCOPES.filter((scope) => rest.value.scopes.includes(scope));
    const now = Date.now();
    const requestId = randomToken(24);
    await ctx.runMutation(component.authRequests.create, {
      requestId,
      appId: client.appId,
      clientId: client.clientId,
      redirectUri: client.redirectUri,
      scope: scopes.join(" "),
      ...(rest.value.state === undefined ? {} : { state: rest.value.state }),
      ...(rest.value.nonce === undefined ? {} : { nonce: rest.value.nonce }),
      codeChallenge: rest.value.codeChallenge,
      expiresAt: now + AUTH_REQUEST_TTL_MS,
    });
    const start = await startUpstream({ connector, callbackUrl: callbackUrl(connector) });
    const result = await ctx.runMutation(component.authRequests.startUpstream, {
      requestId,
      connector: connector.name,
      upstreamStateHash: await sha256Hex(start.state),
      upstreamCodeVerifier: start.codeVerifier,
      ...(start.nonce === undefined ? {} : { upstreamNonce: start.nonce }),
      now,
    });
    if (!result.ok) {
      return result.error === "not_found"
        ? errorPage(
            "Sign-in not found",
            "This sign-in is unknown. Return to the app and try again.",
            404,
          )
        : authorizationError({
            ...back,
            error: "access_denied",
            description: `The sign-in ${result.error === "expired" ? "expired" : "already moved on"}.`,
          });
    }
    return redirect(start.url);
  });

  function upstreamCallback(connector: OauthConnector | OidcConnector): PublicHttpAction {
    return httpActionGeneric(async (ctx, request) => {
      const url = new URL(request.url);
      const state = url.searchParams.get("state");
      if (state === null) {
        return errorPage("Invalid callback", "The provider sent no state.", 400);
      }
      const now = Date.now();
      const claim = await ctx.runMutation(component.authRequests.claimUpstream, {
        upstreamStateHash: await sha256Hex(state),
        connector: connector.name,
        now,
      });
      if (claim.status === "missing") {
        return errorPage(
          "Sign-in link used",
          "This sign-in link is invalid or was already used. Return to the app and try again.",
          400,
        );
      }
      const back = { redirectUri: claim.redirectUri, issuer, state: claim.state };
      if (claim.status === "expired") {
        return authorizationError({
          ...back,
          error: "access_denied",
          description: "The sign-in expired.",
        });
      }
      let identity: UpstreamIdentity;
      try {
        identity = await finishUpstream({
          connector,
          callbackUrl: callbackUrl(connector),
          currentUrl: url,
          state,
          codeVerifier: claim.upstreamCodeVerifier,
          nonce: claim.upstreamNonce,
        });
      } catch (error) {
        await ctx.runMutation(component.authRequests.abandon, { requestId: claim.requestId });
        // The provider's error code picks one fixed answer; nothing the provider wrote is echoed.
        if (error instanceof oauth.AuthorizationResponseError && error.error === "access_denied") {
          return authorizationError({
            ...back,
            error: "access_denied",
            description: `${connector.label} sign-in was declined.`,
          });
        }
        if (
          error instanceof oauth.AuthorizationResponseError &&
          error.error === "temporarily_unavailable"
        ) {
          return authorizationError({
            ...back,
            error: "temporarily_unavailable",
            description: `${connector.label} is temporarily unavailable.`,
          });
        }
        // Only the class name: provider errors carry token responses and decoded claims.
        console.error(
          `Connector "${connector.name}" failed: ${error instanceof Error ? error.constructor.name : typeof error}`,
        );
        return authorizationError({
          ...back,
          error: "server_error",
          description: `${connector.label} sign-in failed.`,
        });
      }
      const code = randomToken(32);
      const completed = await ctx.runMutation(component.authRequests.complete, {
        requestId: claim.requestId,
        identity: { connector: connector.name, ...identity },
        codeHash: await sha256Hex(code),
        codeExpiresAt: now + CODE_TTL_MS,
        now,
      });
      if (!completed.ok) {
        return authorizationError({
          ...back,
          error: "access_denied",
          description: "The sign-in expired.",
        });
      }
      return authorizationResponse({ ...back, params: { code } });
    });
  }

  /** The app of a registration token, or its 401. */
  async function registrationApp(ctx: Ctx, request: Request) {
    const token = readBearerToken(request.headers.get("authorization"));
    if (token === null) {
      return {
        ok: false,
        response: oauthError(
          401,
          "invalid_token",
          "A registration token is required as a Bearer token.",
        ),
      } as const;
    }
    const app = await ctx.runQuery(component.registration.readToken, {
      tokenHash: await sha256Hex(token),
    });
    if (app === null) {
      return {
        ok: false,
        response: oauthError(401, "invalid_token", "The registration token is unknown."),
      } as const;
    }
    return { ok: true, app } as const;
  }

  const register = httpActionGeneric(async (ctx, request) => {
    const now = Date.now();
    const auth = await registrationApp(ctx, request);
    if (!auth.ok) {
      return auth.response;
    }
    const { app } = auth;
    let payload: unknown;
    try {
      payload = await request.json();
    } catch {
      return oauthError(400, "invalid_client_metadata", "The request body must be JSON.");
    }
    const validation = validateRegistration(payload);
    if (!validation.ok) {
      return oauthError(validation.status, validation.error, validation.description);
    }
    const host = new URL(validation.value.redirectUri).hostname;
    if (!hostAllowed(host, app.allowedCallbackHosts)) {
      return oauthError(
        400,
        "invalid_redirect_uri",
        `The host "${host}" is not allowed for this app.`,
      );
    }
    const clientId = `cl_${randomToken(16)}`;
    const clientSecret = randomToken(32);
    await ctx.runMutation(component.clients.create, {
      clientId,
      appId: app.appId,
      secretHash: await sha256Hex(clientSecret),
      tokenEndpointAuthMethod: validation.value.tokenEndpointAuthMethod,
      redirectUri: validation.value.redirectUri,
      deploymentType: validation.value.deploymentType,
      clientName: validation.value.clientName,
      softwareVersion: validation.value.softwareVersion,
      createdAt: now,
    });
    return json(
      {
        client_id: clientId,
        client_secret: clientSecret,
        client_id_issued_at: Math.floor(now / 1000),
        client_secret_expires_at: 0,
        redirect_uris: [validation.value.redirectUri],
        client_name: validation.value.clientName,
        software_id: app.appId,
        software_version: validation.value.softwareVersion,
        deployment_type: validation.value.deploymentType,
        token_endpoint_auth_method: validation.value.tokenEndpointAuthMethod,
        grant_types: ["authorization_code"],
        response_types: ["code"],
      },
      201,
    );
  });

  const registerPrefix = path("/register/");

  /**
   * `DELETE <prefix>/register/<client_id>` deletes a client of the token's app, of any deployment
   * type. The segment is compared as sent: `/register` issues `cl_` and base64url, which a path
   * carries as is. A client that is gone and a client of another app both answer 404, never 403,
   * so a token learns nothing about another app's clients.
   */
  const unregister = httpActionGeneric(async (ctx, request) => {
    const auth = await registrationApp(ctx, request);
    if (!auth.ok) {
      return auth.response;
    }
    const deleted = await ctx.runMutation(component.clients.unregister, {
      clientId: new URL(request.url).pathname.slice(registerPrefix.length),
      appId: auth.app.appId,
    });
    if (!deleted) {
      return oauthError(
        404,
        "invalid_client",
        "No client with this id belongs to the app of this registration token.",
      );
    }
    return new Response(null, { status: 204 });
  });

  const token = httpActionGeneric(async (ctx, request) => {
    const contentType = request.headers.get("content-type")?.toLowerCase() ?? "";
    if (!contentType.startsWith("application/x-www-form-urlencoded")) {
      return oauthError(
        415,
        "invalid_request",
        "The body must be application/x-www-form-urlencoded.",
      );
    }
    const params = new URLSearchParams(await request.text());
    const authorization = request.headers.get("authorization");
    // RFC 6749 section 5.2: a client that authenticated with the header gets a 401 with a challenge.
    const challenge: Record<string, string> =
      authorization === null ? {} : { "WWW-Authenticate": 'Basic realm="token"' };
    const clientAuth = readClientAuthentication(authorization, params);
    if (!clientAuth.ok) {
      return oauthError(
        clientAuth.status,
        clientAuth.error,
        clientAuth.description,
        clientAuth.status === 401 ? challenge : {},
      );
    }
    const validation = validateTokenRequest(params, clientAuth.value);
    if (!validation.ok) {
      return oauthError(validation.status, validation.error, validation.description);
    }
    const client = await ctx.runQuery(component.clients.get, {
      clientId: clientAuth.value.clientId,
    });
    if (
      client === null ||
      client.tokenEndpointAuthMethod !== clientAuth.value.method ||
      client.secretHash !== (await sha256Hex(clientAuth.value.clientSecret))
    ) {
      return oauthError(401, "invalid_client", "Client authentication failed.", challenge);
    }
    const now = Date.now();
    const exchange = await ctx.runMutation(component.authRequests.exchangeCode, {
      codeHash: await sha256Hex(validation.value.code),
      clientId: client.clientId,
      ...(validation.value.redirectUri === undefined
        ? {}
        : { redirectUri: validation.value.redirectUri }),
      codeVerifier: validation.value.codeVerifier,
      now,
    });
    if (!exchange.ok) {
      return oauthError(400, "invalid_grant", exchange.description);
    }
    const keys = keySet();
    const sub = await pairwiseSubject({
      appId: exchange.appId,
      connector: exchange.identity.connector,
      upstreamId: exchange.identity.upstreamId,
      salt: keys.pairwiseSalt,
    });
    // Claims follow the granted scopes (OIDC Core 5.4); userinfo reads them from the access token.
    const scopes = exchange.scope.split(" ");
    const claims: IdentityClaims = { sub, connector: exchange.identity.connector };
    if (scopes.includes("email") && exchange.identity.email !== undefined) {
      claims.email = exchange.identity.email;
      claims.email_verified = exchange.identity.emailVerified === true;
    }
    if (scopes.includes("profile") && exchange.identity.name !== undefined) {
      claims.name = exchange.identity.name;
    }
    if (scopes.includes("profile") && exchange.identity.picture !== undefined) {
      claims.picture = exchange.identity.picture;
    }
    const [idToken, accessToken] = await Promise.all([
      signIdToken({
        keySet: keys,
        issuer,
        clientId: client.clientId,
        claims,
        nonce: exchange.nonce,
      }),
      signAccessToken({ keySet: keys, issuer, clientId: client.clientId, claims }),
    ]);
    await ctx.runMutation(component.signIns.record, {
      appId: exchange.appId,
      clientId: client.clientId,
      connector: exchange.identity.connector,
      sub,
      at: now,
    });
    return json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: TOKEN_TTL_SECONDS,
      id_token: idToken,
      scope: exchange.scope,
    });
  });

  const userinfo = httpActionGeneric(async (_ctx, request) => {
    const bearer = readBearerToken(request.headers.get("authorization"));
    const claims =
      bearer === null ? null : await verifyAccessToken({ keySet: keySet(), issuer, token: bearer });
    if (claims === null) {
      return json(
        {
          error: "invalid_token",
          error_description: "The access token is missing, invalid or expired.",
        },
        401,
        {
          "WWW-Authenticate": 'Bearer error="invalid_token"',
        },
      );
    }
    return json(claims);
  });

  return {
    /** Mounts every endpoint on the host's router. */
    addHttpRoutes(http: HttpRouter): void {
      http.route({
        path: path("/.well-known/openid-configuration"),
        method: "GET",
        handler: discovery,
      });
      http.route({
        path: `/.well-known/oauth-authorization-server${prefix}`,
        method: "GET",
        handler: discovery,
      });
      http.route({ path: path("/.well-known/jwks.json"), method: "GET", handler: jwks });
      http.route({ path: path("/authorize"), method: "GET", handler: authorize });
      http.route({ path: path("/authorize"), method: "POST", handler: authorize });
      http.route({ path: path("/register"), method: "POST", handler: register });
      http.route({ pathPrefix: registerPrefix, method: "DELETE", handler: unregister });
      http.route({ path: path("/token"), method: "POST", handler: token });
      http.route({ path: path("/userinfo"), method: "GET", handler: userinfo });
      http.route({ path: path("/userinfo"), method: "POST", handler: userinfo });
      for (const connector of connectors.values()) {
        http.route({
          path: path(`/connectors/${connector.name}/callback`),
          method: "GET",
          handler: upstreamCallback(connector),
        });
      }
    },

    /**
     * Administration as internal functions of the host, for `npx convex run`: export them from a
     * host module such as `convex/identityBroker.ts`.
     */
    admin() {
      const { array, string } = v;
      return {
        createApp: internalMutationGeneric({
          args: { appId: string(), allowedCallbackHosts: array(string()) },
          returns: v.null(),
          handler: async (ctx, args) => {
            await ctx.runMutation(component.apps.create, {
              appId: args.appId,
              allowedCallbackHosts: args.allowedCallbackHosts,
            });
            return null;
          },
        }),
        mintRegistrationToken: internalMutationGeneric({
          args: { appId: string() },
          returns: v.object({ token: string() }),
          handler: async (ctx, args) => {
            const token = `rt_${randomToken(32)}`;
            await ctx.runMutation(component.registration.mintToken, {
              tokenHash: await sha256Hex(token),
              appId: args.appId,
              createdAt: Date.now(),
            });
            return { token };
          },
        }),
        setAllowedCallbackHosts: internalMutationGeneric({
          args: { appId: string(), allowedCallbackHosts: array(string()) },
          returns: v.null(),
          handler: async (ctx, args) => {
            await ctx.runMutation(component.apps.setAllowedCallbackHosts, {
              appId: args.appId,
              allowedCallbackHosts: args.allowedCallbackHosts,
            });
            return null;
          },
        }),
        listRegistrationTokens: internalQueryGeneric({
          args: { appId: string() },
          handler: async (ctx, args) =>
            await ctx.runQuery(component.registration.listTokens, { appId: args.appId }),
        }),
        revokeRegistrationToken: internalMutationGeneric({
          args: { tokenHash: string() },
          returns: v.null(),
          handler: async (ctx, args) => {
            await ctx.runMutation(component.registration.revokeToken, {
              tokenHash: args.tokenHash,
            });
            return null;
          },
        }),
        deleteClient: internalMutationGeneric({
          args: { clientId: string() },
          returns: v.null(),
          handler: async (ctx, args) => {
            await ctx.runMutation(component.clients.remove, { clientId: args.clientId });
            return null;
          },
        }),
        deleteApp: internalMutationGeneric({
          args: { appId: string() },
          returns: v.null(),
          handler: async (ctx, args) => {
            await ctx.runMutation(component.apps.remove, { appId: args.appId });
            return null;
          },
        }),
        listApps: internalQueryGeneric({
          args: {},
          handler: async (ctx) => await ctx.runQuery(component.apps.list, {}),
        }),
        listClients: internalQueryGeneric({
          args: { appId: string() },
          handler: async (ctx, args) =>
            await ctx.runQuery(component.clients.listByApp, { appId: args.appId }),
        }),
        cleanup: internalMutationGeneric({
          args: {},
          handler: async (ctx) =>
            await ctx.runMutation(component.lifecycle.cleanup, {
              now: Date.now(),
              ...(previewClientIdleDays === undefined
                ? {}
                : { previewClientMaxAgeMs: previewClientIdleDays * 24 * 60 * 60 * 1000 }),
              signInRetentionMs: SIGN_IN_RETENTION_MS,
            }),
        }),
      };
    },
  };
}
