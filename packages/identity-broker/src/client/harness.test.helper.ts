/// <reference types="vite-plus/client" />
import { convexTest } from "convex-test";
import { anyApi, httpRouter, ROUTABLE_HTTP_METHODS } from "convex/server";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { vi } from "vite-plus/test";
import type { ComponentApi } from "../component/_generated/component.js";
import { api } from "../component/_generated/api.js";
import schema from "../component/schema.js";
import type { Connector, OidcConnector } from "./connectors/types.js";
import { defineIdentityBroker } from "./index.js";
import { createKeySet, type KeySet } from "./keys.js";

export const modules = import.meta.glob(["../component/**/*.ts", "!../component/**/*.test.ts"]);

/**
 * The component's functions as the host reaches them through `components.identityBroker`. In
 * convex-test the component is the app under test, so `anyApi` paths resolve to its functions; the
 * leaves are untyped, hence the one declared gap.
 */
// @ts-expect-error anyApi leaves are AnyModuleDirOrFunc | undefined; at runtime each path names a registered function.
export const component: ComponentApi = anyApi;

export const ISSUER = "https://auth.test";

export type Harness = Awaited<ReturnType<typeof createHarness>>;

/**
 * The broker mounted on a router, driven through `fetchBroker`: each request runs its handler in a
 * convex-test action, the way a Convex HTTP action runs.
 */
export async function createHarness(options: {
  connectors: Connector[];
  issuer?: string;
  keySet?: KeySet;
  previewClientIdleDays?: number;
  /** Replaces `ctx.runAction` for the request, to capture the email code send. */
  runAction?: (reference: unknown, args: unknown) => Promise<unknown>;
}) {
  const t = convexTest(schema, modules);
  const keySet = options.keySet ?? (await createKeySet());
  const issuer = options.issuer ?? ISSUER;
  const broker = defineIdentityBroker({
    component,
    issuer,
    keys: () => JSON.stringify(keySet),
    connectors: options.connectors,
    ...(options.previewClientIdleDays === undefined
      ? {}
      : { previewClientIdleDays: options.previewClientIdleDays }),
  });
  const http = httpRouter();
  broker.addHttpRoutes(http);

  async function fetchBroker(input: string | URL, init?: RequestInit): Promise<Response> {
    const request = new Request(input, init);
    const url = new URL(request.url);
    const method = ROUTABLE_HTTP_METHODS.find((candidate) => candidate === request.method);
    const match = method === undefined ? null : http.lookup(url.pathname, method);
    if (method === undefined || match === null) {
      return new Response(`No route for ${request.method} ${url.pathname}`, { status: 404 });
    }
    const [handler] = match;
    const body = method === "GET" ? undefined : await request.text();
    const headers = Object.fromEntries(request.headers.entries());
    const result = await t.action(async (ctx) => {
      if (options.runAction !== undefined) {
        vi.spyOn(ctx, "runAction").mockImplementation(options.runAction as typeof ctx.runAction);
      }
      const replay = new Request(
        url,
        body === undefined ? { method, headers } : { method, headers, body },
      );
      // @ts-expect-error httpActionGeneric keeps the function as _handler; PublicHttpAction does not declare it.
      const response: Response = await handler._handler(ctx, replay);
      return {
        status: response.status,
        headers: [...response.headers.entries()],
        body: await response.text(),
      };
    });
    // The Response constructor refuses any body for a 204, an empty one included.
    return new Response(result.status === 204 ? null : result.body, {
      status: result.status,
      headers: result.headers,
    });
  }

  /** The admin function `registerClient`, as `npx convex run` or a stack runs it. */
  async function runRegisterClient(args: {
    appId: string;
    redirectUri: string;
    deploymentType: "production" | "development" | "preview";
    tokenEndpointAuthMethod: "client_secret_post" | "client_secret_basic";
  }): Promise<{ issuer: string; clientId: string; clientSecret: string }> {
    const { registerClient: admin } = broker.admin();
    return await t.action(
      async (ctx) =>
        // @ts-expect-error internalMutationGeneric keeps the function as _handler; RegisteredMutation does not declare it.
        await admin._handler(ctx, { ...args, clientName: "dev", softwareVersion: "dev-1" }),
    );
  }

  /** An app and one client with `redirectUri`, through the admin function that a stack runs. */
  async function registerClient(args: {
    appName: string;
    firstParty: boolean;
    redirectUri: string;
    /** As @samebase/alchemy-convex registers: Convex Auth posts the client credentials. */
    tokenEndpointAuthMethod?: "client_secret_post" | "client_secret_basic";
    deploymentType?: "production" | "development" | "preview";
  }) {
    const appId = `${args.appName.toLowerCase()}-test`;
    await t.mutation(api.apps.create, {
      appId,
      name: args.appName,
      firstParty: args.firstParty,
      createdAt: Date.now(),
    });
    const client = await runRegisterClient({
      appId,
      redirectUri: args.redirectUri,
      deploymentType: args.deploymentType ?? "development",
      tokenEndpointAuthMethod: args.tokenEndpointAuthMethod ?? "client_secret_post",
    });
    return { appId, clientId: client.clientId, clientSecret: client.clientSecret };
  }

  return { t, broker, http, fetchBroker, registerClient, runRegisterClient, keySet, issuer };
}

/** The `Cookie` header of the browser that received `response`, with its transaction cookie. */
export function txnCookie(response: Response): { Cookie: string } {
  return { Cookie: (response.headers.get("set-cookie") ?? "").split(";")[0] ?? "" };
}

export async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** PKCE values for a client-side test. */
export async function pkce() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  const verifier = btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  const challenge = btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  return { verifier, challenge };
}

/**
 * A fake plain-OAuth provider behind the global fetch: RFC 8414 metadata without `iss` support, a
 * token endpoint and a user endpoint. Returns the connector pointing at it and the stub, so a test
 * can inspect the calls.
 */
export function fakeUpstream(options: { userId?: string } = {}) {
  const calls: Request[] = [];
  const fetchStub = vi.fn(
    async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const request = new Request(input, init);
      calls.push(request);
      const url = new URL(request.url);
      if (url.href === "https://upstream.test/.well-known/oauth-authorization-server") {
        return Response.json({
          issuer: "https://upstream.test",
          authorization_endpoint: "https://upstream.test/authorize",
          token_endpoint: "https://upstream.test/token",
          response_types_supported: ["code"],
        });
      }
      if (
        url.origin === "https://upstream.test" &&
        url.pathname === "/token" &&
        request.method === "POST"
      ) {
        const body = new URLSearchParams(await request.text());
        if (body.get("code") !== "upstream-code" || body.get("client_secret") !== "up-secret") {
          return Response.json({ error: "invalid_grant" }, { status: 400 });
        }
        return Response.json({ access_token: "up-access", token_type: "bearer" });
      }
      if (url.origin === "https://api.upstream.test" && url.pathname === "/user") {
        if (request.headers.get("authorization") !== "Bearer up-access") {
          return new Response("unauthorized", { status: 401 });
        }
        return Response.json({
          id: options.userId ?? "42",
          name: "Octo Cat",
          email: "octo@example.com",
        });
      }
      return new Response(`unexpected ${request.method} ${url.href}`, { status: 599 });
    },
  );
  vi.stubGlobal("fetch", fetchStub);
  const connector: Connector = {
    kind: "oauth",
    name: "fake",
    label: "Fake",
    issuer: "https://upstream.test",
    scopes: ["read:user"],
    clientId: () => "up-client",
    clientSecret: () => "up-secret",
    identity: async (accessToken) => {
      const response = await fetch("https://api.upstream.test/user", {
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      const user: { id: string; name: string; email: string } = await response.json();
      return {
        upstreamId: String(user.id),
        name: user.name,
        email: user.email,
        emailVerified: true,
      };
    },
  };
  return { connector, calls, fetchStub };
}

/**
 * A fake OpenID provider behind the global fetch: discovery, JWKS, and a token endpoint that signs
 * an id_token. Its issuer, client, subject and `acr` come from the example ID Token of OpenID
 * Connect Core 1.0 section 2; `nextIdToken` sets the nonce and the `auth_time` of the next one
 * (`undefined`: the claim is left out). The connector documents `prompt=login`.
 */
export async function fakeOidcUpstream() {
  const issuer = "https://server.example.com";
  const { privateKey, publicKey } = await generateKeyPair("RS256");
  const jwk = { ...(await exportJWK(publicKey)), kid: "k1", alg: "RS256", use: "sig" };
  let next: { nonce: string; authTime: number | undefined } | undefined;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const request = new Request(input, init);
      const url = new URL(request.url);
      if (url.href === `${issuer}/.well-known/openid-configuration`) {
        return Response.json({
          issuer,
          authorization_endpoint: `${issuer}/authorize`,
          token_endpoint: `${issuer}/token`,
          jwks_uri: `${issuer}/jwks`,
          response_types_supported: ["code"],
          subject_types_supported: ["public"],
          id_token_signing_alg_values_supported: ["RS256"],
          code_challenge_methods_supported: ["S256"],
        });
      }
      if (url.href === `${issuer}/jwks`) {
        return Response.json({ keys: [jwk] });
      }
      if (url.href === `${issuer}/token` && request.method === "POST" && next !== undefined) {
        const body = new URLSearchParams(await request.text());
        if (body.get("code") !== "upstream-code" || body.get("client_secret") !== "idp-secret") {
          return Response.json({ error: "invalid_grant" }, { status: 400 });
        }
        const idToken = await new SignJWT({
          nonce: next.nonce,
          ...(next.authTime === undefined ? {} : { auth_time: next.authTime }),
          acr: "urn:mace:incommon:iap:silver",
        })
          .setProtectedHeader({ alg: "RS256", kid: "k1" })
          .setIssuer(issuer)
          .setSubject("24400320")
          .setAudience("s6BhdRkqt3")
          .setIssuedAt()
          .setExpirationTime("5m")
          .sign(privateKey);
        return Response.json({
          access_token: "idp-access",
          token_type: "Bearer",
          id_token: idToken,
        });
      }
      return new Response(`unexpected ${request.method} ${url.href}`, { status: 599 });
    }),
  );
  const connector: OidcConnector = {
    kind: "oidc",
    name: "idp",
    label: "IdP",
    issuer,
    scopes: ["openid"],
    promptLogin: true,
    clientId: () => "s6BhdRkqt3",
    clientSecret: () => "idp-secret",
  };
  return {
    connector,
    nextIdToken: (value: { nonce: string; authTime: number | undefined }) => {
      next = value;
    },
  };
}
