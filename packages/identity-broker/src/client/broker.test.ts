/// <reference types="vite-plus/client" />
import { decodeJwt } from "jose";
import { afterEach, describe, expect, test, vi } from "vite-plus/test";
import { api } from "../component/_generated/api.js";
import { email } from "./connectors/email.js";
import { createHarness, fakeUpstream, ISSUER, pkce, type Harness } from "./harness.test.helper.js";

const REDIRECT_URI = "https://app.test/oauth/hub/callback";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function authorizeUrl(
  h: Harness,
  args: { clientId: string; challenge: string; extra?: Record<string, string> },
) {
  const url = new URL(`${h.issuer}/authorize`);
  url.search = new URLSearchParams({
    client_id: args.clientId,
    redirect_uri: REDIRECT_URI,
    response_type: "code",
    scope: "openid email profile",
    state: "client-state",
    nonce: "client-nonce",
    code_challenge: args.challenge,
    code_challenge_method: "S256",
    ...args.extra,
  }).toString();
  return url;
}

/** Runs the fake provider's half: follows the upstream redirect back into the broker callback. */
async function completeUpstream(h: Harness, authorizeResponse: Response) {
  expect(authorizeResponse.status).toBe(302);
  const upstream = new URL(authorizeResponse.headers.get("location") ?? "");
  expect(upstream.origin).toBe("https://upstream.test");
  expect(upstream.searchParams.get("code_challenge_method")).toBe("S256");
  const state = upstream.searchParams.get("state") ?? "";
  const callback = new URL(upstream.searchParams.get("redirect_uri") ?? "");
  callback.searchParams.set("code", "upstream-code");
  callback.searchParams.set("state", state);
  return await h.fetchBroker(callback);
}

async function exchange(
  h: Harness,
  args: {
    code: string;
    clientId: string;
    clientSecret: string;
    verifier: string;
    redirectUri?: string;
  },
) {
  return await h.fetchBroker(`${h.issuer}/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: args.code,
      code_verifier: args.verifier,
      client_id: args.clientId,
      client_secret: args.clientSecret,
      ...(args.redirectUri === undefined ? {} : { redirect_uri: args.redirectUri }),
    }).toString(),
  });
}

describe("metadata", () => {
  test("both discovery documents and the JWKS", async () => {
    const h = await createHarness({ connectors: [fakeUpstream().connector] });
    for (const path of [
      "/.well-known/openid-configuration",
      "/.well-known/oauth-authorization-server",
    ]) {
      const response = await h.fetchBroker(`${ISSUER}${path}`);
      expect(response.status).toBe(200);
      const metadata = await response.json();
      expect(metadata.issuer).toBe(ISSUER);
      expect(metadata.jwks_uri).toBe(`${ISSUER}/.well-known/jwks.json`);
      expect(metadata.subject_types_supported).toEqual(["pairwise"]);
      expect(metadata.code_challenge_methods_supported).toEqual(["S256"]);
      expect(metadata.authorization_response_iss_parameter_supported).toBe(true);
    }
    const jwks = await (await h.fetchBroker(`${ISSUER}/.well-known/jwks.json`)).json();
    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0].d).toBeUndefined();
  });

  test("a path issuer serves the RFC 8414 location with the path after the segment", async () => {
    const h = await createHarness({
      connectors: [fakeUpstream().connector],
      issuer: "https://samebase.test/identity",
    });
    expect(
      (await h.fetchBroker("https://samebase.test/identity/.well-known/openid-configuration"))
        .status,
    ).toBe(200);
    expect(
      (await h.fetchBroker("https://samebase.test/.well-known/oauth-authorization-server/identity"))
        .status,
    ).toBe(200);
    expect(
      (await h.fetchBroker("https://samebase.test/.well-known/openid-configuration")).status,
    ).toBe(404);
  });
});

describe("registration", () => {
  test("a host allowed later registers", async () => {
    const h = await createHarness({ connectors: [fakeUpstream().connector] });
    const { appId, token } = await h.registerClient({
      appName: "Bristol",
      firstParty: true,
      redirectUri: REDIRECT_URI,
    });
    const register = () =>
      h.fetchBroker(`${ISSUER}/register`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({
          redirect_uris: ["https://bristol.example/oauth/hub/callback"],
          client_name: "prod",
          deployment_type: "production",
        }),
      });
    expect((await register()).status).toBe(400);
    await h.t.mutation(api.apps.setAllowedCallbackHosts, {
      appId,
      allowedCallbackHosts: ["bristol.example"],
    });
    expect((await register()).status).toBe(201);
  });

  test("needs a live token and an allowed host", async () => {
    const h = await createHarness({ connectors: [fakeUpstream().connector] });
    const { token } = await h.registerClient({
      appName: "Bristol",
      firstParty: true,
      redirectUri: REDIRECT_URI,
    });
    const noToken = await h.fetchBroker(`${ISSUER}/register`, { method: "POST", body: "{}" });
    expect(noToken.status).toBe(401);
    const badHost = await h.fetchBroker(`${ISSUER}/register`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        redirect_uris: ["https://evil.example/cb"],
        client_name: "x",
        deployment_type: "preview",
      }),
    });
    expect(badHost.status).toBe(400);
    expect((await badHost.json()).error).toBe("invalid_redirect_uri");
    const expired = await h.fetchBroker(`${ISSUER}/register`, {
      method: "POST",
      headers: { Authorization: "Bearer rt_unknown", "Content-Type": "application/json" },
      body: "{}",
    });
    expect(expired.status).toBe(401);
  });
});

describe("authorization code flow with an OAuth connector", () => {
  test("first-party app with one connector goes straight upstream and back with a code", async () => {
    const upstream = fakeUpstream();
    const h = await createHarness({ connectors: [upstream.connector] });
    const { appId, clientId, clientSecret } = await h.registerClient({
      appName: "Bristol",
      firstParty: true,
      redirectUri: REDIRECT_URI,
    });
    const { verifier, challenge } = await pkce();

    const started = await h.fetchBroker(authorizeUrl(h, { clientId, challenge }));
    const back = await completeUpstream(h, started);
    expect(back.status).toBe(302);
    const location = new URL(back.headers.get("location") ?? "");
    expect(location.origin + location.pathname).toBe(REDIRECT_URI);
    expect(location.searchParams.get("state")).toBe("client-state");
    expect(location.searchParams.get("iss")).toBe(ISSUER);
    const code = location.searchParams.get("code") ?? "";
    expect(code.length).toBeGreaterThan(20);

    const tokens = await exchange(h, {
      code,
      clientId,
      clientSecret,
      verifier,
      redirectUri: REDIRECT_URI,
    });
    expect(tokens.status).toBe(200);
    const body = await tokens.json();
    expect(body.token_type).toBe("Bearer");
    expect(body.scope).toBe("openid email profile");
    const claims = decodeJwt(body.id_token);
    expect(claims.iss).toBe(ISSUER);
    expect(claims.aud).toBe(clientId);
    expect(claims.nonce).toBe("client-nonce");
    expect(claims["email"]).toBe("octo@example.com");
    expect(claims["email_verified"]).toBe(true);
    expect(claims["connector"]).toBe("fake");
    expect(typeof claims.auth_time).toBe("number");
    expect(claims).not.toHaveProperty("connector_account_id");

    const userinfo = await h.fetchBroker(`${ISSUER}/userinfo`, {
      headers: { Authorization: `Bearer ${body.access_token}` },
    });
    expect(userinfo.status).toBe(200);
    expect((await userinfo.json()).sub).toBe(claims.sub);

    const signIns = await h.t.run(async (ctx) => await ctx.db.query("signIns").collect());
    expect(signIns).toHaveLength(1);
    expect(signIns[0]).toMatchObject({ appId, clientId, connector: "fake", sub: claims.sub });
    expect(signIns[0]).not.toHaveProperty("email");

    // The subject is pairwise per app: another app of the same user gets another subject.
    const other = await h.registerClient({
      appName: "Other",
      firstParty: true,
      redirectUri: REDIRECT_URI,
    });
    const otherPkce = await pkce();
    const otherBack = await completeUpstream(
      h,
      await h.fetchBroker(
        authorizeUrl(h, { clientId: other.clientId, challenge: otherPkce.challenge }),
      ),
    );
    const otherCode =
      new URL(otherBack.headers.get("location") ?? "").searchParams.get("code") ?? "";
    const otherTokens = await (
      await exchange(h, {
        code: otherCode,
        clientId: other.clientId,
        clientSecret: other.clientSecret,
        verifier: otherPkce.verifier,
      })
    ).json();
    expect(decodeJwt(otherTokens.id_token).sub).not.toBe(claims.sub);
  });

  test("a code is single use, bound to the client and the verifier; replay revokes it", async () => {
    const upstream = fakeUpstream();
    const h = await createHarness({ connectors: [upstream.connector] });
    const { clientId, clientSecret } = await h.registerClient({
      appName: "Bristol",
      firstParty: true,
      redirectUri: REDIRECT_URI,
    });
    const other = await h.registerClient({
      appName: "Other",
      firstParty: true,
      redirectUri: REDIRECT_URI,
    });
    const { verifier, challenge } = await pkce();
    const back = await completeUpstream(
      h,
      await h.fetchBroker(authorizeUrl(h, { clientId, challenge })),
    );
    const code = new URL(back.headers.get("location") ?? "").searchParams.get("code") ?? "";

    const wrongVerifier = await exchange(h, {
      code,
      clientId,
      clientSecret,
      verifier: `${verifier.slice(0, -1)}x`,
    });
    expect(wrongVerifier.status).toBe(400);
    expect((await wrongVerifier.json()).error).toBe("invalid_grant");

    const wrongClient = await exchange(h, {
      code,
      clientId: other.clientId,
      clientSecret: other.clientSecret,
      verifier,
    });
    expect((await wrongClient.json()).error).toBe("invalid_grant");

    const wrongSecret = await exchange(h, { code, clientId, clientSecret: "nope", verifier });
    expect(wrongSecret.status).toBe(401);

    const wrongRedirect = await exchange(h, {
      code,
      clientId,
      clientSecret,
      verifier,
      redirectUri: "https://app.test/other",
    });
    expect((await wrongRedirect.json()).error).toBe("invalid_grant");

    expect((await exchange(h, { code, clientId, clientSecret, verifier })).status).toBe(200);
    const replay = await exchange(h, { code, clientId, clientSecret, verifier });
    expect(replay.status).toBe(400);
    expect((await replay.json()).error_description).toMatch(/already used/);
  });

  test("errors before the client is known are pages; after, they redirect with error and iss", async () => {
    const h = await createHarness({ connectors: [fakeUpstream().connector] });
    const { clientId } = await h.registerClient({
      appName: "Bristol",
      firstParty: true,
      redirectUri: REDIRECT_URI,
    });
    const { challenge } = await pkce();

    const unknownClient = await h.fetchBroker(
      authorizeUrl(h, { clientId: "cl_unknown", challenge }),
    );
    expect(unknownClient.status).toBe(400);
    expect(unknownClient.headers.get("content-type")).toMatch(/text\/html/);

    const otherRedirect = authorizeUrl(h, { clientId, challenge });
    otherRedirect.searchParams.set("redirect_uri", "https://evil.example/cb");
    const badRedirect = await h.fetchBroker(otherRedirect);
    expect(badRedirect.status).toBe(400);
    expect(badRedirect.headers.get("location")).toBeNull();

    const noOpenid = await h.fetchBroker(
      authorizeUrl(h, { clientId, challenge, extra: { scope: "email" } }),
    );
    expect(noOpenid.status).toBe(302);
    const noOpenidUrl = new URL(noOpenid.headers.get("location") ?? "");
    expect(noOpenidUrl.searchParams.get("error")).toBe("invalid_scope");
    expect(noOpenidUrl.searchParams.get("state")).toBe("client-state");
    expect(noOpenidUrl.searchParams.get("iss")).toBe(ISSUER);

    const none = await h.fetchBroker(
      authorizeUrl(h, { clientId, challenge, extra: { prompt: "none" } }),
    );
    expect(new URL(none.headers.get("location") ?? "").searchParams.get("error")).toBe(
      "login_required",
    );

    // An OAuth connector cannot force a fresh login.
    const fresh = await h.fetchBroker(
      authorizeUrl(h, { clientId, challenge, extra: { prompt: "login" } }),
    );
    expect(new URL(fresh.headers.get("location") ?? "").searchParams.get("error")).toBe(
      "login_required",
    );
  });

  test("a replayed or unknown upstream state is refused, a denied upstream goes back as access_denied", async () => {
    const upstream = fakeUpstream();
    const h = await createHarness({ connectors: [upstream.connector] });
    const { clientId } = await h.registerClient({
      appName: "Bristol",
      firstParty: true,
      redirectUri: REDIRECT_URI,
    });
    const { challenge } = await pkce();
    const started = await h.fetchBroker(authorizeUrl(h, { clientId, challenge }));
    const upstreamUrl = new URL(started.headers.get("location") ?? "");
    const callback = new URL(upstreamUrl.searchParams.get("redirect_uri") ?? "");
    callback.searchParams.set("state", upstreamUrl.searchParams.get("state") ?? "");

    const denied = new URL(callback);
    denied.searchParams.set("error", "access_denied");
    const deniedResponse = await h.fetchBroker(denied);
    expect(deniedResponse.status).toBe(302);
    expect(new URL(deniedResponse.headers.get("location") ?? "").searchParams.get("error")).toBe(
      "access_denied",
    );

    // The claim consumed the request: the same state cannot be used again.
    callback.searchParams.set("code", "upstream-code");
    const replay = await h.fetchBroker(callback);
    expect(replay.status).toBe(400);
    const unknown = new URL(callback);
    unknown.searchParams.set("state", "nope");
    expect((await h.fetchBroker(unknown)).status).toBe(400);
  });

  test("a third-party app sees the chooser, and deny returns access_denied", async () => {
    const h = await createHarness({ connectors: [fakeUpstream().connector] });
    const { clientId } = await h.registerClient({
      appName: "Stranger",
      firstParty: false,
      redirectUri: REDIRECT_URI,
    });
    const { challenge } = await pkce();
    const page = await h.fetchBroker(authorizeUrl(h, { clientId, challenge }));
    expect(page.status).toBe(200);
    const html = await page.text();
    expect(html).toContain("Continue with Fake");
    expect(html).toContain("will receive your identity");
    const deny = html.match(/href="([^"]*deny=1)"/)?.[1]?.replace(/&amp;/g, "&") ?? "";
    const denied = await h.fetchBroker(`${ISSUER}${deny}`);
    expect(new URL(denied.headers.get("location") ?? "").searchParams.get("error")).toBe(
      "access_denied",
    );
    const again = await h.fetchBroker(`${ISSUER}${deny}`);
    expect(again.status).toBe(404);
  });
});

describe("email connector", () => {
  test("sends a code, verifies it, locks after five misses", async () => {
    const sent: Array<{ to: string; code: string; appName: string }> = [];
    const send = { functionHandle: "test" } as unknown;
    const h = await createHarness({
      // @ts-expect-error a stand-in function reference; the harness replaces ctx.runAction.
      connectors: [email({ send })],
      runAction: async (_reference, args) => {
        sent.push(args as { to: string; code: string; appName: string });
        return null;
      },
    });
    const { clientId, clientSecret } = await h.registerClient({
      appName: "Bristol",
      firstParty: true,
      redirectUri: REDIRECT_URI,
    });
    const { verifier, challenge } = await pkce();
    const page = await h.fetchBroker(authorizeUrl(h, { clientId, challenge }));
    expect(page.status).toBe(200);
    const requestId = (await page.text()).match(/name="request" value="([^"]+)"/)?.[1] ?? "";
    const post = (fields: Record<string, string>) =>
      h.fetchBroker(`${ISSUER}/connectors/email`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ request: requestId, ...fields }).toString(),
      });

    const badAddress = await post({ step: "send", email: "nope" });
    expect(await badAddress.text()).toContain("valid email");
    const codePage = await post({ step: "send", email: " Nicu@Example.com " });
    expect(codePage.status).toBe(200);
    expect(sent).toHaveLength(1);
    expect(sent[0]).toMatchObject({ to: "nicu@example.com", appName: "Bristol" });
    expect(sent[0]?.code).toMatch(/^\d{6}$/);

    for (let attempt = 0; attempt < 4; attempt++) {
      const wrong = await post({
        step: "verify",
        code: "000000" === sent[0]?.code ? "111111" : "000000",
      });
      expect(await wrong.text()).toContain("not right");
    }
    const ok = await post({ step: "verify", code: sent[0]?.code ?? "" });
    expect(ok.status).toBe(302);
    const code = new URL(ok.headers.get("location") ?? "").searchParams.get("code") ?? "";
    const tokens = await exchange(h, { code, clientId, clientSecret, verifier });
    expect(tokens.status).toBe(200);
    const claims = decodeJwt((await tokens.json()).id_token);
    expect(claims["email"]).toBe("nicu@example.com");
    expect(claims["email_verified"]).toBe(true);
    expect(claims["connector"]).toBe("email");
  });

  test("the fifth miss locks the request", async () => {
    const sent: Array<{ code: string }> = [];
    const send = { functionHandle: "test" } as unknown;
    const h = await createHarness({
      // @ts-expect-error a stand-in function reference; the harness replaces ctx.runAction.
      connectors: [email({ send })],
      runAction: async (_reference, args) => {
        sent.push(args as { code: string });
        return null;
      },
    });
    const { clientId } = await h.registerClient({
      appName: "Bristol",
      firstParty: true,
      redirectUri: REDIRECT_URI,
    });
    const { challenge } = await pkce();
    const requestId =
      (await (await h.fetchBroker(authorizeUrl(h, { clientId, challenge }))).text()).match(
        /name="request" value="([^"]+)"/,
      )?.[1] ?? "";
    const post = (fields: Record<string, string>) =>
      h.fetchBroker(`${ISSUER}/connectors/email`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ request: requestId, ...fields }).toString(),
      });
    await post({ step: "send", email: "a@b.co" });
    const wrongCode = sent[0]?.code === "000000" ? "111111" : "000000";
    let last: Response | undefined;
    for (let attempt = 0; attempt < 5; attempt++) {
      last = await post({ step: "verify", code: wrongCode });
    }
    expect(last?.status).toBe(302);
    expect(new URL(last?.headers.get("location") ?? "").searchParams.get("error")).toBe(
      "access_denied",
    );
    const requests = await h.t.query(api.authRequests.get, { requestId });
    expect(requests?.status).toBe("emailSent");
  });
});

describe("cleanup", () => {
  test("drops expired requests and codes, idle preview clients, old audit rows", async () => {
    const h = await createHarness({ connectors: [fakeUpstream().connector] });
    const now = Date.now();
    await h.t.mutation(api.apps.create, {
      appId: "a",
      name: "A",
      firstParty: true,
      allowedCallbackHosts: ["app.test"],
      createdAt: now,
    });
    const client = {
      appId: "a",
      secretHash: "h",
      tokenEndpointAuthMethod: "client_secret_post" as const,
      redirectUri: REDIRECT_URI,
      clientName: "c",
      softwareVersion: "v",
    };
    await h.t.mutation(api.clients.create, {
      ...client,
      clientId: "preview-old",
      deploymentType: "preview",
      createdAt: now - 40 * 86_400_000,
    });
    await h.t.mutation(api.clients.create, {
      ...client,
      clientId: "preview-new",
      deploymentType: "preview",
      createdAt: now,
    });
    await h.t.mutation(api.clients.create, {
      ...client,
      clientId: "prod-old",
      deploymentType: "production",
      createdAt: now - 400 * 86_400_000,
    });
    await h.t.mutation(api.authRequests.create, {
      requestId: "r-old",
      appId: "a",
      clientId: "prod-old",
      redirectUri: REDIRECT_URI,
      scope: "openid",
      codeChallenge: "c",
      freshLogin: false,
      createdAt: now - 3_600_000,
      expiresAt: now - 1,
    });
    await h.t.mutation(api.signIns.record, {
      appId: "a",
      clientId: "prod-old",
      connector: "fake",
      sub: "s",
      at: now - 100 * 86_400_000,
    });
    const counts = await h.t.mutation(api.lifecycle.cleanup, {
      now,
      previewClientMaxAgeMs: 30 * 86_400_000,
      signInRetentionMs: 90 * 86_400_000,
    });
    expect(counts).toEqual({
      authRequests: 1,
      authorizationCodes: 0,
      previewClients: 1,
      signIns: 1,
    });
    const remaining = await h.t.query(api.clients.listByApp, { appId: "a" });
    expect(remaining.map((c) => c.clientId).sort()).toEqual(["preview-new", "prod-old"]);
  });
});
