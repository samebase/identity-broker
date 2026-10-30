/* eslint-disable */
/**
 * Generated `ComponentApi` utility.
 *
 * THIS CODE IS AUTOMATICALLY GENERATED.
 *
 * To regenerate, run `npx convex dev`.
 * @module
 */

import type { FunctionReference } from "convex/server";

/**
 * A utility for referencing a Convex component's exposed API.
 *
 * Useful when expecting a parameter like `components.myComponent`.
 * Usage:
 * ```ts
 * async function myFunction(ctx: QueryCtx, component: ComponentApi) {
 *   return ctx.runQuery(component.someFile.someQuery, { ...args });
 * }
 * ```
 */
export type ComponentApi<Name extends string | undefined = string | undefined> =
  {
    apps: {
      create: FunctionReference<
        "mutation",
        "internal",
        { appId: string; createdAt: number; firstParty: boolean; name: string },
        null,
        Name
      >;
      get: FunctionReference<
        "query",
        "internal",
        { appId: string },
        {
          appId: string;
          createdAt: number;
          firstParty: boolean;
          name: string;
        } | null,
        Name
      >;
      list: FunctionReference<
        "query",
        "internal",
        {},
        Array<{
          appId: string;
          createdAt: number;
          firstParty: boolean;
          name: string;
        }>,
        Name
      >;
      remove: FunctionReference<
        "mutation",
        "internal",
        { appId: string },
        null,
        Name
      >;
    };
    authRequests: {
      abandon: FunctionReference<
        "mutation",
        "internal",
        { requestId: string },
        { redirectUri: string; state?: string } | null,
        Name
      >;
      claimUpstream: FunctionReference<
        "mutation",
        "internal",
        {
          connector: string;
          now: number;
          txnCookieHashes: Array<string>;
          upstreamStateHash: string;
        },
        | {
            connector: string;
            createdAt: number;
            freshLogin: boolean;
            redirectUri: string;
            requestId: string;
            state?: string;
            status: "claimed";
            upstreamCodeVerifier: string;
            upstreamNonce?: string;
          }
        | {
            redirectUri: string;
            requestId: string;
            state?: string;
            status: "expired";
          }
        | { status: "unbound" }
        | { status: "missing" },
        Name
      >;
      complete: FunctionReference<
        "mutation",
        "internal",
        {
          authTime: number;
          codeExpiresAt: number;
          codeHash: string;
          identity: {
            connector: string;
            email?: string;
            emailVerified?: boolean;
            name?: string;
            picture?: string;
            upstreamId: string;
          };
          now: number;
          requestId: string;
        },
        | { ok: true; redirectUri: string; state?: string }
        | {
            error: "expired" | "wrong_status";
            ok: false;
            redirectUri: string;
            state?: string;
          }
        | { error: "not_found"; ok: false },
        Name
      >;
      create: FunctionReference<
        "mutation",
        "internal",
        {
          appId: string;
          clientId: string;
          codeChallenge: string;
          createdAt: number;
          expiresAt: number;
          freshLogin: boolean;
          nonce?: string;
          redirectUri: string;
          requestId: string;
          scope: string;
          state?: string;
          txnCookieHash: string;
        },
        null,
        Name
      >;
      exchangeCode: FunctionReference<
        "mutation",
        "internal",
        {
          clientId: string;
          clientSecretHash: string;
          codeHash: string;
          codeVerifier: string;
          now: number;
          redirectUri?: string;
          tokenEndpointAuthMethod: "client_secret_post" | "client_secret_basic";
        },
        | {
            appId: string;
            authTime: number;
            clientId: string;
            firstParty: boolean;
            identity: {
              connector: string;
              email?: string;
              emailVerified?: boolean;
              name?: string;
              picture?: string;
              upstreamId: string;
            };
            nonce?: string;
            ok: true;
            scope: string;
          }
        | {
            description: string;
            error: "invalid_client" | "invalid_grant";
            ok: false;
          },
        Name
      >;
      get: FunctionReference<
        "query",
        "internal",
        { requestId: string },
        | {
            appId: string;
            clientId: string;
            codeChallenge: string;
            createdAt: number;
            expiresAt: number;
            freshLogin: boolean;
            nonce?: string;
            redirectUri: string;
            requestId: string;
            scope: string;
            state?: string;
            status: "pending";
            txnCookieHash: string;
          }
        | {
            appId: string;
            clientId: string;
            codeChallenge: string;
            connector: string;
            createdAt: number;
            expiresAt: number;
            freshLogin: boolean;
            nonce?: string;
            redirectUri: string;
            requestId: string;
            scope: string;
            state?: string;
            status: "upstream";
            txnCookieHash: string;
            upstreamCodeVerifier: string;
            upstreamNonce?: string;
            upstreamStateHash: string;
          }
        | {
            appId: string;
            clientId: string;
            codeChallenge: string;
            connector: string;
            createdAt: number;
            expiresAt: number;
            freshLogin: boolean;
            nonce?: string;
            redirectUri: string;
            requestId: string;
            scope: string;
            state?: string;
            status: "claimed";
            txnCookieHash: string;
          }
        | {
            appId: string;
            clientId: string;
            codeChallenge: string;
            connector: string;
            createdAt: number;
            email: string;
            emailAttempts: number;
            emailCodeExpiresAt: number;
            emailCodeHash: string;
            emailLastSentAt: number;
            emailSends: number;
            expiresAt: number;
            freshLogin: boolean;
            nonce?: string;
            redirectUri: string;
            requestId: string;
            scope: string;
            state?: string;
            status: "emailSent";
            txnCookieHash: string;
          }
        | {
            appId: string;
            authTime: number;
            clientId: string;
            codeChallenge: string;
            createdAt: number;
            expiresAt: number;
            freshLogin: boolean;
            identity: {
              connector: string;
              email?: string;
              emailVerified?: boolean;
              name?: string;
              picture?: string;
              upstreamId: string;
            };
            nonce?: string;
            redirectUri: string;
            requestId: string;
            scope: string;
            state?: string;
            status: "completed";
            txnCookieHash: string;
          }
        | null,
        Name
      >;
      startEmail: FunctionReference<
        "mutation",
        "internal",
        {
          connector: string;
          email: string;
          emailCodeExpiresAt: number;
          emailCodeHash: string;
          emailHash: string;
          maxAttempts: number;
          now: number;
          requestId: string;
        },
        | { ok: true; redirectUri: string; state?: string }
        | {
            error:
              | "expired"
              | "wrong_status"
              | "locked"
              | "too_soon"
              | "request_limit"
              | "address_limit"
              | "global_limit";
            ok: false;
            redirectUri: string;
            state?: string;
          }
        | { error: "not_found"; ok: false },
        Name
      >;
      startUpstream: FunctionReference<
        "mutation",
        "internal",
        {
          connector: string;
          now: number;
          requestId: string;
          upstreamCodeVerifier: string;
          upstreamNonce?: string;
          upstreamStateHash: string;
        },
        | { ok: true; redirectUri: string; state?: string }
        | {
            error: "expired" | "wrong_status";
            ok: false;
            redirectUri: string;
            state?: string;
          }
        | { error: "not_found"; ok: false },
        Name
      >;
      verifyEmailCode: FunctionReference<
        "mutation",
        "internal",
        {
          codeExpiresAt: number;
          codeHash: string;
          emailCodeHash: string;
          maxAttempts: number;
          now: number;
          requestId: string;
        },
        | { ok: true; redirectUri: string; state?: string }
        | {
            error:
              | "wrong_code"
              | "locked"
              | "code_expired"
              | "expired"
              | "wrong_status";
            ok: false;
            redirectUri: string;
            state?: string;
          }
        | { error: "not_found"; ok: false },
        Name
      >;
    };
    clients: {
      create: FunctionReference<
        "mutation",
        "internal",
        {
          appId: string;
          clientId: string;
          clientName: string;
          createdAt: number;
          deploymentType: "production" | "development" | "preview";
          redirectUri: string;
          secretHash: string;
          softwareVersion: string;
          tokenEndpointAuthMethod: "client_secret_post" | "client_secret_basic";
        },
        null,
        Name
      >;
      get: FunctionReference<
        "query",
        "internal",
        { clientId: string },
        {
          appId: string;
          clientId: string;
          clientName: string;
          createdAt: number;
          deploymentType: "production" | "development" | "preview";
          lastSignInAt?: number;
          redirectUri: string;
          secretHash: string;
          softwareVersion: string;
          tokenEndpointAuthMethod: "client_secret_post" | "client_secret_basic";
        } | null,
        Name
      >;
      listByApp: FunctionReference<
        "query",
        "internal",
        { appId: string },
        Array<{
          appId: string;
          clientId: string;
          clientName: string;
          createdAt: number;
          deploymentType: "production" | "development" | "preview";
          lastSignInAt?: number;
          redirectUri: string;
          secretHash: string;
          softwareVersion: string;
          tokenEndpointAuthMethod: "client_secret_post" | "client_secret_basic";
        }>,
        Name
      >;
      remove: FunctionReference<
        "mutation",
        "internal",
        { clientId: string },
        null,
        Name
      >;
    };
    lifecycle: {
      cleanup: FunctionReference<
        "mutation",
        "internal",
        {
          now: number;
          previewClientMaxAgeMs?: number;
          signInRetentionMs: number;
        },
        {
          authRequests: number;
          authorizationCodes: number;
          emailSends: number;
          previewClients: number;
          signIns: number;
        },
        Name
      >;
    };
    signIns: {
      record: FunctionReference<
        "mutation",
        "internal",
        {
          appId: string;
          at: number;
          clientId: string;
          connector: string;
          sub: string;
        },
        null,
        Name
      >;
    };
  };
