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
  EmailConnector,
  OauthConnector,
  OidcConnector,
} from "./connectors/types.js";
import { finishUpstream, startUpstream, type UpstreamFinish } from "./connectors/upstream.js";
import { chooserPage, emailAddressPage, emailCodePage, errorPage } from "./html.js";
import {
  signAccessToken,
  signIdToken,
  TOKEN_TTL_SECONDS,
  verifyAccessToken,
  type IdentityClaims,
} from "./jwt.js";
import { parseKeySet, publicJwks, SIGNING_ALGORITHM, type KeySet } from "./keys.js";
import {
  canonicalEmail,
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
import { pairwiseSubject, randomDigits, randomToken, sha256Hex } from "./subject.js";

export type {
  Connector,
  EmailConnector,
  OauthConnector,
  OidcConnector,
  SendEmailCode,
  UpstreamIdentity,
} from "./connectors/types.js";
export { github } from "./connectors/github.js";
export { google } from "./connectors/google.js";
export { email } from "./connectors/email.js";
export { createKeySet, parseKeySet, rotateKeySet, type KeySet } from "./keys.js";
export { assertKeySetUsable } from "./jwt.js";

export type IdentityBrokerConfig = {
  /** `components.identityBroker` of the host app. */
  component: ComponentApi;
  /** The issuer URL, host-only or with a path, e.g. `https://auth.example.com`. */
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
const EMAIL_CODE_TTL_MS = 10 * 60 * 1000;
/** How far an upstream `auth_time` may sit outside the request's lifetime: the clocks differ. */
const AUTH_TIME_SKEW_SECONDS = 60;
const EMAIL_MAX_ATTEMPTS = 5;
/** The scopes the broker grants; any other requested scope is dropped. */
const SCOPES = ["openid", "email", "profile"];
const REGISTRATION_TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000;
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
  /**
   * The chooser binds its request to the browser that saw it with one cookie per request, named
   * after the request id, so two sign-ins in one browser keep their own. `__Host-` needs Path=/, so
   * a path issuer uses a plain name scoped to its path.
   */
  const txnCookiePrefix = prefix === "" ? "__Host-broker_txn_" : "broker_txn_";
  const txnCookieAttributes = `Path=${prefix === "" ? "/" : prefix}; HttpOnly; Secure; SameSite=Lax`;
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

  /** The transaction cookies the browser sent, by request id. */
  function readTxnCookies(request: Request): Map<string, string> {
    const cookies = new Map<string, string>();
    for (const pair of request.headers.get("cookie")?.split(";") ?? []) {
      const separator = pair.indexOf("=");
      const name = pair.slice(0, separator).trim();
      if (separator > 0 && name.startsWith(txnCookiePrefix)) {
        cookies.set(name.slice(txnCookiePrefix.length), pair.slice(separator + 1).trim());
      }
    }
    return cookies;
  }

  /**
   * Whether the browser holds the cookie whose hash a chooser request stores. A first-party request
   * that skipped the chooser stores none and needs none.
   */
  async function browserBound(
    request: Request,
    stored: { requestId: string; txnCookieHash?: string },
  ): Promise<boolean> {
    if (stored.txnCookieHash === undefined) {
      return true;
    }
    const cookie = readTxnCookies(request).get(stored.requestId);
    return cookie !== undefined && (await sha256Hex(cookie)) === stored.txnCookieHash;
  }

  /** The Set-Cookie value that deletes a request's cookie, when the browser sent one. */
  function clearTxnCookie(request: Request, requestId: string): string | undefined {
    return readTxnCookies(request).has(requestId)
      ? `${txnCookiePrefix}${requestId}=; ${txnCookieAttributes}; Max-Age=0`
      : undefined;
  }

  const unboundPage = () =>
    errorPage(
      "Sign-in not continued",
      "This sign-in did not start in this browser. Return to the app and try again.",
      400,
    );

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
      "auth_time",
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

  /** Sends the user to a connector for a stored request, or shows the email form. */
  async function startConnector(
    ctx: Ctx,
    args: {
      connector: Connector;
      request: {
        requestId: string;
        appId: string;
        redirectUri: string;
        state: string | undefined;
        freshLogin: boolean;
      };
      appName: string;
      clearCookie: string | undefined;
    },
  ): Promise<Response> {
    const { connector, request } = args;
    const back = {
      redirectUri: request.redirectUri,
      issuer,
      state: request.state,
      clearCookie: args.clearCookie,
    };
    if (connector.kind === "email") {
      return emailAddressPage({
        appName: args.appName,
        action: path("/connectors/email"),
        requestId: request.requestId,
      });
    }
    // Freshness is honored only as prompt=login upstream; a connector without it is refused, never
    // pretended.
    if (request.freshLogin && (connector.kind === "oauth" || !connector.promptLogin)) {
      return authorizationError({
        ...back,
        error: "login_required",
        description: `${connector.label} cannot reauthenticate the user, which prompt=login or max_age asked for.`,
      });
    }
    const start = await startUpstream({
      connector,
      callbackUrl: callbackUrl(connector),
      freshLogin: request.freshLogin,
    });
    const now = Date.now();
    const result = await ctx.runMutation(component.authRequests.startUpstream, {
      requestId: request.requestId,
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
  }

  async function readApp(ctx: Ctx, appId: string) {
    return await ctx.runQuery(component.apps.get, { appId });
  }

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
      clearCookie: undefined,
    };
    const rest = validateAuthorizeRest(params, target.value);
    if (!rest.ok) {
      return authorizationError({ ...back, error: rest.error, description: rest.description });
    }
    const app = await readApp(ctx, client.appId);
    if (app === null) {
      return authorizationError({
        ...back,
        error: "server_error",
        description: "The client's app is gone.",
      });
    }
    if (rest.value.prompt.includes("none")) {
      // The broker keeps no session, so it can never answer without interaction.
      return authorizationError({
        ...back,
        error: "login_required",
        description: "This provider has no session to reuse.",
      });
    }
    const freshLogin = rest.value.prompt.includes("login") || rest.value.maxAge !== undefined;
    const scopes = SCOPES.filter((scope) => rest.value.scopes.includes(scope));
    // A first-party app may skip the chooser: the one it named, or the only one. A third-party app
    // always gets the page, which doubles as consent (RFC 9700 4.11).
    const named =
      rest.value.connector === undefined ? undefined : connectors.get(rest.value.connector);
    const only = connectors.size === 1 ? [...connectors.values()][0] : undefined;
    const chosen = app.firstParty ? (named ?? only) : undefined;
    // The request moves on only with this cookie, so a client that fetches the chooser itself cannot
    // send a user's browser on from it.
    const txnCookie = randomToken(32);
    const now = Date.now();
    const requestId = randomToken(24);
    await ctx.runMutation(component.authRequests.create, {
      requestId,
      appId: app.appId,
      clientId: client.clientId,
      redirectUri: client.redirectUri,
      scope: scopes.join(" "),
      ...(rest.value.state === undefined ? {} : { state: rest.value.state }),
      ...(rest.value.nonce === undefined ? {} : { nonce: rest.value.nonce }),
      codeChallenge: rest.value.codeChallenge,
      freshLogin,
      ...(chosen === undefined ? { txnCookieHash: await sha256Hex(txnCookie) } : {}),
      createdAt: now,
      expiresAt: now + AUTH_REQUEST_TTL_MS,
    });
    if (chosen !== undefined) {
      return await startConnector(ctx, {
        connector: chosen,
        request: {
          requestId,
          appId: app.appId,
          redirectUri: client.redirectUri,
          state: rest.value.state,
          freshLogin,
        },
        appName: app.name,
        clearCookie: undefined,
      });
    }
    const page = chooserPage({
      appName: app.name,
      firstParty: app.firstParty,
      scopes,
      connectors: [...connectors.values()].map((connector) => ({
        name: connector.name,
        label: connector.label,
        href: `${path("/continue")}?request=${encodeURIComponent(requestId)}&connector=${encodeURIComponent(connector.name)}`,
      })),
      denyHref: `${path("/continue")}?request=${encodeURIComponent(requestId)}&deny=1`,
    });
    page.headers.append(
      "Set-Cookie",
      `${txnCookiePrefix}${requestId}=${txnCookie}; ${txnCookieAttributes}; Max-Age=${AUTH_REQUEST_TTL_MS / 1000}`,
    );
    return page;
  });

  /** A chooser click: start the chosen connector, or abandon the request on deny. */
  const continueSignIn = httpActionGeneric(async (ctx, request) => {
    const url = new URL(request.url);
    const requestId = url.searchParams.get("request") ?? "";
    const stored = await ctx.runQuery(component.authRequests.get, { requestId });
    if (stored === null) {
      return errorPage(
        "Sign-in not found",
        "This sign-in is unknown or finished. Return to the app and try again.",
        404,
      );
    }
    // Only a request that showed the chooser has links to continue.
    if (stored.txnCookieHash === undefined || !(await browserBound(request, stored))) {
      return unboundPage();
    }
    const back = {
      redirectUri: stored.redirectUri,
      issuer,
      state: stored.state,
      clearCookie: clearTxnCookie(request, requestId),
    };
    if (url.searchParams.get("deny") !== null) {
      await ctx.runMutation(component.authRequests.abandon, { requestId });
      return authorizationError({
        ...back,
        error: "access_denied",
        description: "The user cancelled the sign-in.",
      });
    }
    if (stored.status === "completed" || stored.status === "claimed") {
      return errorPage(
        "Sign-in finished",
        "This sign-in already finished. Return to the app.",
        409,
      );
    }
    const connector = connectors.get(url.searchParams.get("connector") ?? "");
    if (connector === undefined) {
      return errorPage("Unknown connector", "That sign-in method is not configured.", 404);
    }
    const app = await readApp(ctx, stored.appId);
    if (app === null) {
      return authorizationError({
        ...back,
        error: "server_error",
        description: "The client's app is gone.",
      });
    }
    return await startConnector(ctx, {
      connector,
      request: {
        requestId,
        appId: stored.appId,
        redirectUri: stored.redirectUri,
        state: stored.state,
        freshLogin: stored.freshLogin,
      },
      appName: app.name,
      clearCookie: back.clearCookie,
    });
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
        txnCookieHashes: await Promise.all(
          [...readTxnCookies(request).values()].map((cookie) => sha256Hex(cookie)),
        ),
        now,
      });
      if (claim.status === "missing") {
        return errorPage(
          "Sign-in link used",
          "This sign-in link is invalid or was already used. Return to the app and try again.",
          400,
        );
      }
      if (claim.status === "unbound") {
        return unboundPage();
      }
      const back = {
        redirectUri: claim.redirectUri,
        issuer,
        state: claim.state,
        clearCookie: clearTxnCookie(request, claim.requestId),
      };
      if (claim.status === "expired") {
        return authorizationError({
          ...back,
          error: "access_denied",
          description: "The sign-in expired.",
        });
      }
      let upstream: UpstreamFinish;
      try {
        upstream = await finishUpstream({
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
      let authTime = now;
      if (claim.freshLogin) {
        // prompt=login and max_age=0 went upstream, but a provider can still reuse its session;
        // only the id_token's auth_time attests a login during this request. It must fall between
        // the request's creation and now, each widened by the clock skew; auth_time is in whole
        // seconds. A plain OAuth connector has no auth_time, and startConnector already refused it.
        const { authTimeSeconds } = upstream;
        if (
          authTimeSeconds === undefined ||
          authTimeSeconds < Math.floor(claim.createdAt / 1000) - AUTH_TIME_SKEW_SECONDS ||
          authTimeSeconds > Math.floor(now / 1000) + AUTH_TIME_SKEW_SECONDS
        ) {
          await ctx.runMutation(component.authRequests.abandon, { requestId: claim.requestId });
          return authorizationError({
            ...back,
            error: "login_required",
            description: `${connector.label} did not confirm a new login, which prompt=login or max_age asked for.`,
          });
        }
        authTime = authTimeSeconds * 1000;
      }
      const code = randomToken(32);
      const completed = await ctx.runMutation(component.authRequests.complete, {
        requestId: claim.requestId,
        identity: { connector: connector.name, ...upstream.identity },
        authTime,
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

  const emailConnector = [...connectors.values()].find(
    (connector): connector is EmailConnector => connector.kind === "email",
  );

  const emailStep = httpActionGeneric(async (ctx, request) => {
    if (emailConnector === undefined) {
      return errorPage("Not configured", "Email sign-in is not configured.", 404);
    }
    const params = await readParameters(request);
    if (params === null) {
      return errorPage("Invalid form", "The form must be application/x-www-form-urlencoded.", 415);
    }
    const requestId = params.get("request") ?? "";
    const stored = await ctx.runQuery(component.authRequests.get, { requestId });
    if (stored === null) {
      return errorPage(
        "Sign-in not found",
        "This sign-in is unknown or finished. Return to the app and try again.",
        404,
      );
    }
    // Every step moves the request on, so every step needs the browser that saw the chooser.
    if (!(await browserBound(request, stored))) {
      return unboundPage();
    }
    const back = {
      redirectUri: stored.redirectUri,
      issuer,
      state: stored.state,
      clearCookie: clearTxnCookie(request, requestId),
    };
    const app = await readApp(ctx, stored.appId);
    if (app === null) {
      return authorizationError({
        ...back,
        error: "server_error",
        description: "The client's app is gone.",
      });
    }
    const action = path("/connectors/email");
    const now = Date.now();
    const step = params.get("step");
    if (step === "send") {
      const address = canonicalEmail(params.get("email") ?? "");
      if (address === null) {
        return emailAddressPage({
          appName: app.name,
          action,
          requestId,
          error: "Enter a valid email address.",
        });
      }
      const code = randomDigits(6);
      const started = await ctx.runMutation(component.authRequests.startEmail, {
        requestId,
        connector: emailConnector.name,
        email: address,
        emailHash: await sha256Hex(address),
        emailCodeHash: await sha256Hex(code),
        emailCodeExpiresAt: now + EMAIL_CODE_TTL_MS,
        maxAttempts: EMAIL_MAX_ATTEMPTS,
        now,
      });
      if (!started.ok) {
        switch (started.error) {
          case "not_found":
            return errorPage(
              "Sign-in not found",
              "This sign-in is unknown. Return to the app and try again.",
              404,
            );
          case "expired":
          case "wrong_status":
            return authorizationError({
              ...back,
              error: "access_denied",
              description: "The sign-in expired.",
            });
          case "locked":
            return authorizationError({
              ...back,
              error: "access_denied",
              description: "Too many wrong codes.",
            });
          case "too_soon":
          case "request_limit":
          case "address_limit":
          case "global_limit": {
            // The page the user is on, with one neutral line: nothing says whether the address is
            // known, and neither the address nor a code is logged.
            const error =
              started.error === "too_soon"
                ? "Wait a minute before asking for another code."
                : "Too many codes were sent. Try again later.";
            return stored.status === "emailSent"
              ? emailCodePage({
                  appName: app.name,
                  action,
                  requestId,
                  email: stored.email,
                  error,
                  status: 429,
                })
              : emailAddressPage({ appName: app.name, action, requestId, error, status: 429 });
          }
          default:
            return started satisfies never;
        }
      }
      try {
        await ctx.runAction(emailConnector.send, { to: address, code, appName: app.name });
      } catch (error) {
        // Only the class name: a delivery error can carry the address or the code.
        console.error(
          `Connector "${emailConnector.name}" could not send a code: ${error instanceof Error ? error.constructor.name : typeof error}`,
        );
        return errorPage(
          "Email not sent",
          "The code could not be sent. Try again in a moment.",
          502,
        );
      }
      return emailCodePage({ appName: app.name, action, requestId, email: address });
    }
    if (step === "verify") {
      if (stored.status !== "emailSent") {
        return emailAddressPage({
          appName: app.name,
          action,
          requestId,
          error: "Request a code first.",
        });
      }
      const typed = (params.get("code") ?? "").trim();
      const authorizationCode = randomToken(32);
      const result = await ctx.runMutation(component.authRequests.verifyEmailCode, {
        requestId,
        emailCodeHash: await sha256Hex(typed),
        maxAttempts: EMAIL_MAX_ATTEMPTS,
        codeHash: await sha256Hex(authorizationCode),
        codeExpiresAt: now + CODE_TTL_MS,
        now,
      });
      if (result.ok) {
        return authorizationResponse({ ...back, params: { code: authorizationCode } });
      }
      switch (result.error) {
        case "wrong_code":
          return emailCodePage({
            appName: app.name,
            action,
            requestId,
            email: stored.email,
            error: "That code is not right.",
          });
        case "code_expired":
          return emailAddressPage({
            appName: app.name,
            action,
            requestId,
            error: "The code expired. Request a new one.",
          });
        case "locked":
          return authorizationError({
            ...back,
            error: "access_denied",
            description: "Too many wrong codes.",
          });
        case "expired":
          return authorizationError({
            ...back,
            error: "access_denied",
            description: "The sign-in expired.",
          });
        case "wrong_status":
          return emailAddressPage({
            appName: app.name,
            action,
            requestId,
            error: "Request a code first.",
          });
        case "not_found":
          return errorPage(
            "Sign-in not found",
            "This sign-in is unknown. Return to the app and try again.",
            404,
          );
        default:
          return result satisfies never;
      }
    }
    return errorPage("Invalid form", "Unknown step.", 400);
  });

  const register = httpActionGeneric(async (ctx, request) => {
    const token = readBearerToken(request.headers.get("authorization"));
    if (token === null) {
      return oauthError(
        401,
        "invalid_token",
        "A registration token is required as a Bearer token.",
      );
    }
    const now = Date.now();
    const app = await ctx.runQuery(component.registration.readToken, {
      tokenHash: await sha256Hex(token),
      now,
    });
    if (app === null) {
      return oauthError(401, "invalid_token", "The registration token is unknown or expired.");
    }
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
        authTime: exchange.authTime,
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
      http.route({ path: path("/continue"), method: "GET", handler: continueSignIn });
      http.route({ path: path("/register"), method: "POST", handler: register });
      http.route({ path: path("/token"), method: "POST", handler: token });
      http.route({ path: path("/userinfo"), method: "GET", handler: userinfo });
      http.route({ path: path("/userinfo"), method: "POST", handler: userinfo });
      for (const connector of connectors.values()) {
        if (connector.kind === "email") {
          http.route({ path: path("/connectors/email"), method: "POST", handler: emailStep });
        } else {
          http.route({
            path: path(`/connectors/${connector.name}/callback`),
            method: "GET",
            handler: upstreamCallback(connector),
          });
        }
      }
    },

    /**
     * Administration as internal functions of the host, for `npx convex run`: export them from a
     * host module such as `convex/identityBroker.ts`.
     */
    admin() {
      const { array, boolean, number, optional, string } = v;
      return {
        createApp: internalMutationGeneric({
          args: { name: string(), firstParty: boolean(), allowedCallbackHosts: array(string()) },
          returns: v.object({ appId: string() }),
          handler: async (ctx, args) => {
            const slug =
              args.name
                .toLowerCase()
                .replace(/[^a-z0-9]+/g, "-")
                .replace(/^-|-$/g, "") || "app";
            const appId = `${slug}-${randomToken(4)
              .toLowerCase()
              .replace(/[^a-z0-9]/g, "")
              .slice(0, 5)}`;
            await ctx.runMutation(component.apps.create, {
              appId,
              name: args.name,
              firstParty: args.firstParty,
              allowedCallbackHosts: args.allowedCallbackHosts,
              createdAt: Date.now(),
            });
            return { appId };
          },
        }),
        mintRegistrationToken: internalMutationGeneric({
          args: { appId: string(), expiresInDays: optional(number()) },
          returns: v.object({ token: string(), expiresAt: number() }),
          handler: async (ctx, args) => {
            const token = `rt_${randomToken(32)}`;
            const now = Date.now();
            const expiresAt =
              now +
              (args.expiresInDays === undefined
                ? REGISTRATION_TOKEN_TTL_MS
                : args.expiresInDays * 24 * 60 * 60 * 1000);
            await ctx.runMutation(component.registration.mintToken, {
              tokenHash: await sha256Hex(token),
              appId: args.appId,
              expiresAt,
              createdAt: now,
            });
            return { token, expiresAt };
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
