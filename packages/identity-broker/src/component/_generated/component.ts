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
        { allowedCallbackHosts: Array<string>; appId: string },
        null,
        Name
      >;
      list: FunctionReference<
        "query",
        "internal",
        {},
        Array<{ allowedCallbackHosts: Array<string>; appId: string }>,
        Name
      >;
      remove: FunctionReference<
        "mutation",
        "internal",
        { appId: string },
        null,
        Name
      >;
      setAllowedCallbackHosts: FunctionReference<
        "mutation",
        "internal",
        { allowedCallbackHosts: Array<string>; appId: string },
        null,
        Name
      >;
    };
    authRequests: {
      claimUpstream: FunctionReference<
        "mutation",
        "internal",
        { connector: string; now: number; upstreamStateHash: string },
        | {
            redirectUri: string;
            requestId: string;
            state?: string;
            status: "claimed";
            upstreamCodeVerifier: string;
            upstreamNonce?: string;
          }
        | { redirectUri: string; state?: string; status: "expired" }
        | { status: "missing" },
        Name
      >;
      complete: FunctionReference<
        "mutation",
        "internal",
        {
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
        boolean,
        Name
      >;
      create: FunctionReference<
        "mutation",
        "internal",
        {
          appId: string;
          clientId: string;
          codeChallenge: string;
          connector: string;
          expiresAt: number;
          nonce?: string;
          redirectUri: string;
          scope: string;
          state?: string;
          upstreamCodeVerifier: string;
          upstreamNonce?: string;
          upstreamStateHash: string;
        },
        null,
        Name
      >;
      exchangeCode: FunctionReference<
        "mutation",
        "internal",
        {
          clientId: string;
          codeHash: string;
          codeVerifier: string;
          now: number;
          redirectUri?: string;
        },
        | {
            appId: string;
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
        | { description: string; ok: false },
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
          redirectUri: string;
          secretHash: string;
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
          redirectUri: string;
          secretHash: string;
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
          redirectUri: string;
          secretHash: string;
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
      unregister: FunctionReference<
        "mutation",
        "internal",
        { appId: string; clientId: string },
        boolean,
        Name
      >;
    };
    lifecycle: {
      cleanup: FunctionReference<
        "mutation",
        "internal",
        { now: number },
        null,
        Name
      >;
    };
    registration: {
      listTokens: FunctionReference<
        "query",
        "internal",
        { appId: string },
        Array<{ createdAt: number; tokenHash: string }>,
        Name
      >;
      mintToken: FunctionReference<
        "mutation",
        "internal",
        { appId: string; createdAt: number; tokenHash: string },
        null,
        Name
      >;
      readToken: FunctionReference<
        "query",
        "internal",
        { tokenHash: string },
        { allowedCallbackHosts: Array<string>; appId: string } | null,
        Name
      >;
      revokeToken: FunctionReference<
        "mutation",
        "internal",
        { tokenHash: string },
        null,
        Name
      >;
    };
  };
