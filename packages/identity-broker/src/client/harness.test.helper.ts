/// <reference types="vite-plus/client" />
import { convexTest } from "convex-test";
import { anyApi, httpRouter, ROUTABLE_HTTP_METHODS } from "convex/server";
import { vi } from "vite-plus/test";
import type { ComponentApi } from "../component/_generated/component.js";
import { api } from "../component/_generated/api.js";
import schema from "../component/schema.js";
import type { Connector } from "./connectors/types.js";
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
export const REDIRECT_URI = "https://app.test/oauth/hub/callback";

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

  /** An app, a registration token for it, and one registered client with `REDIRECT_URI`. */
  async function registerClient(appId: string) {
    await t.mutation(api.apps.create, { appId, allowedCallbackHosts: ["app.test"] });
    const token = `rt_test-${appId}`;
    await t.mutation(api.registration.mintToken, {
      tokenHash: await sha256Hex(token),
      appId,
      createdAt: Date.now(),
    });
    const response = await fetchBroker(`${issuer}/register`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        redirect_uris: [REDIRECT_URI],
        client_name: `${appId} dev`,
        software_version: "dev-1",
        deployment_type: "development",
        // As @samebase/alchemy-identity-hub registers: Convex Auth posts the client credentials.
        token_endpoint_auth_method: "client_secret_post",
      }),
    });
    if (response.status !== 201) {
      throw new Error(`Registration failed: ${response.status} ${await response.text()}`);
    }
    const client = await response.json();
    return {
      appId,
      token,
      clientId: String(client.client_id),
      clientSecret: String(client.client_secret),
    };
  }

  return { t, broker, http, fetchBroker, registerClient, keySet, issuer };
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
 * A fake plain-OAuth provider behind the global fetch: a token endpoint and a user endpoint.
 * Returns the connector pointing at it and the stub, so a test can inspect the calls.
 */
export function fakeUpstream(options: { userId?: string } = {}) {
  const calls: Request[] = [];
  const fetchStub = vi.fn(
    async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const request = new Request(input, init);
      calls.push(request);
      const url = new URL(request.url);
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
    authorizationEndpoint: "https://upstream.test/authorize",
    tokenEndpoint: "https://upstream.test/token",
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
