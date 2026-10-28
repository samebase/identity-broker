/// <reference types="vite-plus/client" />
import { decodeJwt } from "jose";
import { afterEach, describe, expect, test, vi } from "vite-plus/test";
import { api } from "../component/_generated/api.js";
import { email } from "./connectors/email.js";
import { google } from "./connectors/google.js";
import {
  createHarness,
  fakeOidcUpstream,
  fakeUpstream,
  ISSUER,
  pkce,
  sha256Hex,
  type Harness,
} from "./harness.test.helper.js";

const REDIRECT_URI = "https://app.test/oauth/hub/callback";

afterEach(() => {
  vi.useRealTimers();
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
    const registered = await register();
    expect(registered.status).toBe(201);
    // RFC 7591 section 2: without token_endpoint_auth_method, the client uses Basic.
    expect((await registered.json()).token_endpoint_auth_method).toBe("client_secret_basic");
  });

  test("tokens are listed as hashes and can be revoked; a client can be deleted", async () => {
    const h = await createHarness({ connectors: [fakeUpstream().connector] });
    const { appId, token, clientId } = await h.registerClient({
      appName: "Bristol",
      firstParty: true,
      redirectUri: REDIRECT_URI,
    });
    const tokens = await h.t.query(api.registration.listTokens, { appId });
    expect(tokens).toEqual([
      {
        tokenHash: await sha256Hex(token),
        expiresAt: expect.any(Number),
        createdAt: expect.any(Number),
      },
    ]);
    expect(JSON.stringify(tokens)).not.toContain(token);
    await h.t.mutation(api.registration.revokeToken, { tokenHash: await sha256Hex(token) });
    const revoked = await h.fetchBroker(`${ISSUER}/register`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        redirect_uris: [REDIRECT_URI],
        client_name: "x",
        deployment_type: "preview",
      }),
    });
    expect(revoked.status).toBe(401);
    await h.t.mutation(api.clients.remove, { clientId });
    const { challenge } = await pkce();
    expect((await h.fetchBroker(authorizeUrl(h, { clientId, challenge }))).status).toBe(400);
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
    // A first-party request that skips the chooser sets no cookie and completes without one.
    expect(started.headers.get("set-cookie")).toBeNull();
    const back = await completeUpstream(h, started);
    expect(back.status).toBe(302);
    expect(back.headers.get("set-cookie")).toBeNull();
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

    // A repeated parameter of any name is a local page: an ambiguous target is never redirected to.
    for (const [name, value] of [
      ["redirect_uri", "https://evil.example/cb"],
      ["client_id", "cl_other"],
      ["state", "other-state"],
    ] as const) {
      const repeated = authorizeUrl(h, { clientId, challenge });
      repeated.searchParams.append(name, value);
      const response = await h.fetchBroker(repeated);
      expect(response.status).toBe(400);
      expect(response.headers.get("location")).toBeNull();
      expect(response.headers.get("content-type")).toMatch(/text\/html/);
      expect(await response.text()).toContain("A parameter is repeated.");
    }

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

    // An OAuth connector cannot force a fresh login, whether prompt=login or max_age asked for it:
    // the answer goes back to the client before anything goes upstream.
    for (const extra of [{ prompt: "login" }, { max_age: "300" }]) {
      const fresh = await h.fetchBroker(authorizeUrl(h, { clientId, challenge, extra }));
      const location = new URL(fresh.headers.get("location") ?? "");
      expect(location.origin + location.pathname).toBe(REDIRECT_URI);
      expect(location.searchParams.get("error")).toBe("login_required");
    }
  });

  test("Google documents no prompt=login, so a fresh login through it is refused", async () => {
    const h = await createHarness({
      connectors: [google({ clientId: () => "google-client", clientSecret: () => "s" })],
    });
    const { clientId } = await h.registerClient({
      appName: "Bristol",
      firstParty: true,
      redirectUri: REDIRECT_URI,
    });
    for (const extra of [{ prompt: "login" }, { max_age: "0" }]) {
      const { challenge } = await pkce();
      const response = await h.fetchBroker(authorizeUrl(h, { clientId, challenge, extra }));
      const location = new URL(response.headers.get("location") ?? "");
      expect(location.origin + location.pathname).toBe(REDIRECT_URI);
      expect(location.searchParams.get("error")).toBe("login_required");
      expect(location.searchParams.get("error_description")).toBe(
        "Google cannot reauthenticate the user, which prompt=login or max_age asked for.",
      );
    }
  });

  /**
   * One sign-in through the fake OIDC provider. `authTime` gets the second the request was created
   * in and returns the `auth_time` the provider signs (`undefined`: none).
   */
  async function oidcSignIn(
    h: Harness,
    idp: Awaited<ReturnType<typeof fakeOidcUpstream>>,
    args: {
      clientId: string;
      extra: Record<string, string>;
      authTime: (createdSecond: number) => number | undefined;
    },
  ) {
    const { challenge, verifier } = await pkce();
    const started = await h.fetchBroker(
      authorizeUrl(h, { clientId: args.clientId, challenge, extra: args.extra }),
    );
    const upstream = new URL(started.headers.get("location") ?? "");
    expect(upstream.origin).toBe("https://server.example.com");
    const state = upstream.searchParams.get("state") ?? "";
    const stateHash = await sha256Hex(state);
    const stored = await h.t.run(
      async (ctx) =>
        await ctx.db
          .query("authRequests")
          .withIndex("by_upstream_state_hash", (q) => q.eq("upstreamStateHash", stateHash))
          .unique(),
    );
    if (stored === null) {
      throw new Error("/authorize stored no request for the upstream state");
    }
    const createdSecond = Math.floor(stored.createdAt / 1000);
    idp.nextIdToken({
      nonce: upstream.searchParams.get("nonce") ?? "",
      authTime: args.authTime(createdSecond),
    });
    const callback = new URL(upstream.searchParams.get("redirect_uri") ?? "");
    callback.searchParams.set("code", "upstream-code");
    callback.searchParams.set("state", state);
    const back = await h.fetchBroker(callback);
    expect(back.status).toBe(302);
    return {
      prompt: upstream.searchParams.get("prompt"),
      maxAge: upstream.searchParams.get("max_age"),
      location: new URL(back.headers.get("location") ?? ""),
      verifier,
      requestId: stored.requestId,
      createdSecond,
    };
  }

  test("a fresh login completes only with an upstream auth_time inside the request, give or take 60 seconds", async () => {
    // The clock stands still, so the request is created and its callback runs in one second.
    vi.useFakeTimers({ now: 1_800_000_000_500, toFake: ["Date"] });
    const idp = await fakeOidcUpstream();
    const h = await createHarness({ connectors: [idp.connector] });
    const { clientId, clientSecret } = await h.registerClient({
      appName: "Bristol",
      firstParty: true,
      redirectUri: REDIRECT_URI,
    });
    // Both ways to ask for a fresh login, against an upstream auth_time that is missing, or this
    // many seconds from the request's second: past each edge of the 60-second skew, on it, inside.
    const accepted = new Map([
      [-61, false],
      [-60, true],
      [-1, true],
      [0, true],
      [60, true],
      [61, false],
    ]);
    for (const extra of [{ prompt: "login" }, { max_age: "300" }]) {
      for (const offset of [undefined, ...accepted.keys()]) {
        const signIn = await oidcSignIn(h, idp, {
          clientId,
          extra,
          authTime: (created) => (offset === undefined ? undefined : created + offset),
        });
        expect(signIn.createdSecond).toBe(1_800_000_000);
        expect(signIn.prompt).toBe("login");
        expect(signIn.maxAge).toBe("0");
        if (offset === undefined || !accepted.get(offset)) {
          expect(signIn.location.origin + signIn.location.pathname).toBe(REDIRECT_URI);
          expect(signIn.location.searchParams.get("error")).toBe("login_required");
          expect(signIn.location.searchParams.get("error_description")).toBe(
            "IdP did not confirm a new login, which prompt=login or max_age asked for.",
          );
          expect(signIn.location.searchParams.get("code")).toBeNull();
          // The request is abandoned: nothing is left to finish.
          expect(await h.t.query(api.authRequests.get, { requestId: signIn.requestId })).toBeNull();
          continue;
        }
        const code = signIn.location.searchParams.get("code") ?? "";
        expect(code).not.toBe("");
        const tokens = await exchange(h, {
          code,
          clientId,
          clientSecret,
          verifier: signIn.verifier,
        });
        expect(tokens.status).toBe(200);
        const idToken = decodeJwt((await tokens.json()).id_token);
        expect(idToken.auth_time).toBe(signIn.createdSecond + offset);
      }
    }
  });

  test("without a fresh login, the sign-in completes at the hub's time, upstream auth_time or not", async () => {
    const idp = await fakeOidcUpstream();
    const h = await createHarness({ connectors: [idp.connector] });
    const { clientId, clientSecret } = await h.registerClient({
      appName: "Bristol",
      firstParty: true,
      redirectUri: REDIRECT_URI,
    });
    for (const offset of [undefined, -3600]) {
      const signIn = await oidcSignIn(h, idp, {
        clientId,
        extra: {},
        authTime: (created) => (offset === undefined ? undefined : created + offset),
      });
      expect(signIn.prompt).toBeNull();
      expect(signIn.maxAge).toBeNull();
      const code = signIn.location.searchParams.get("code") ?? "";
      expect(code).not.toBe("");
      const tokens = await exchange(h, { code, clientId, clientSecret, verifier: signIn.verifier });
      expect(tokens.status).toBe(200);
      const idToken = decodeJwt((await tokens.json()).id_token);
      // The callback's time, never the upstream's hour-old value.
      expect(idToken.auth_time).toBeGreaterThanOrEqual(signIn.createdSecond);
    }
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

  test("a state started for one connector does not finish through another's callback", async () => {
    const upstream = fakeUpstream();
    const other = { ...upstream.connector, name: "other", label: "Other" };
    const h = await createHarness({ connectors: [upstream.connector, other] });
    const { clientId } = await h.registerClient({
      appName: "Bristol",
      firstParty: true,
      redirectUri: REDIRECT_URI,
    });
    const { challenge } = await pkce();
    const started = await h.fetchBroker(
      authorizeUrl(h, { clientId, challenge, extra: { connector: "fake" } }),
    );
    const upstreamUrl = new URL(started.headers.get("location") ?? "");
    const crossed = new URL(`${ISSUER}/connectors/other/callback`);
    crossed.searchParams.set("code", "upstream-code");
    crossed.searchParams.set("state", upstreamUrl.searchParams.get("state") ?? "");
    expect((await h.fetchBroker(crossed)).status).toBe(400);
    // The request is still waiting for its own connector.
    const back = await completeUpstream(h, started);
    expect(new URL(back.headers.get("location") ?? "").searchParams.get("code")).toBeTruthy();
  });

  test("provider errors are logged by class name and answered with a fixed description", async () => {
    const h = await createHarness({ connectors: [fakeUpstream().connector] });
    const { clientId } = await h.registerClient({
      appName: "Bristol",
      firstParty: true,
      redirectUri: REDIRECT_URI,
    });
    const logged = vi.spyOn(console, "error").mockImplementation(() => {});
    const callback = async (params: Record<string, string>) => {
      const { challenge } = await pkce();
      const started = await h.fetchBroker(authorizeUrl(h, { clientId, challenge }));
      const upstreamUrl = new URL(started.headers.get("location") ?? "");
      const url = new URL(upstreamUrl.searchParams.get("redirect_uri") ?? "");
      url.searchParams.set("state", upstreamUrl.searchParams.get("state") ?? "");
      for (const [key, value] of Object.entries(params)) {
        url.searchParams.set(key, value);
      }
      const location = new URL((await h.fetchBroker(url)).headers.get("location") ?? "");
      return {
        error: location.searchParams.get("error"),
        description: location.searchParams.get("error_description"),
      };
    };
    // The provider refuses the code; its token response body travels in the thrown error.
    expect(await callback({ code: "refused-code" })).toEqual({
      error: "server_error",
      description: "Fake sign-in failed.",
    });
    expect(logged).toHaveBeenCalledTimes(1);
    expect(logged.mock.calls[0]).toEqual([expect.stringMatching(/^Connector "fake" failed: \w+$/)]);
    expect(
      await callback({ error: "temporarily_unavailable", error_description: "Upstream detail" }),
    ).toEqual({
      error: "temporarily_unavailable",
      description: "Fake is temporarily unavailable.",
    });
    expect(
      await callback({ error: "invalid_scope", error_description: "Upstream detail" }),
    ).toEqual({ error: "server_error", description: "Fake sign-in failed." });
  });

  test("a failed Basic authentication answers 401 with a Basic challenge", async () => {
    const h = await createHarness({ connectors: [fakeUpstream().connector] });
    const { clientId, clientSecret } = await h.registerClient({
      appName: "Bristol",
      firstParty: true,
      redirectUri: REDIRECT_URI,
    });
    const { verifier } = await pkce();
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code: "c",
      code_verifier: verifier,
    }).toString();
    const post = (headers: Record<string, string>, form = body) =>
      h.fetchBroker(`${ISSUER}/token`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded", ...headers },
        body: form,
      });
    for (const authorization of [
      // The client registered for client_secret_post.
      `Basic ${btoa(`${clientId}:${clientSecret}`)}`,
      `Basic ${btoa("a:%E0%A4%A")}`,
    ]) {
      const response = await post({ Authorization: authorization });
      expect(response.status).toBe(401);
      expect(response.headers.get("www-authenticate")).toBe('Basic realm="token"');
      expect((await response.json()).error).toBe("invalid_client");
    }
    const inBody = await post(
      {},
      `${body}&${new URLSearchParams({ client_id: clientId, client_secret: "wrong" })}`,
    );
    expect(inBody.status).toBe(401);
    expect(inBody.headers.get("www-authenticate")).toBeNull();
  });

  test("claims and the granted scope follow the requested scopes", async () => {
    const h = await createHarness({ connectors: [fakeUpstream().connector] });
    const { clientId, clientSecret } = await h.registerClient({
      appName: "Bristol",
      firstParty: true,
      redirectUri: REDIRECT_URI,
    });
    for (const [scope, granted, claimed] of [
      ["openid", "openid", []],
      ["openid email offline_access", "openid email", ["email", "email_verified"]],
      ["profile openid", "openid profile", ["name"]],
    ] as const) {
      const { verifier, challenge } = await pkce();
      const back = await completeUpstream(
        h,
        await h.fetchBroker(authorizeUrl(h, { clientId, challenge, extra: { scope } })),
      );
      const code = new URL(back.headers.get("location") ?? "").searchParams.get("code") ?? "";
      const tokens = await (await exchange(h, { code, clientId, clientSecret, verifier })).json();
      expect(tokens.scope).toBe(granted);
      const userinfo = await (
        await h.fetchBroker(`${ISSUER}/userinfo`, {
          headers: { Authorization: `Bearer ${tokens.access_token}` },
        })
      ).json();
      for (const claims of [decodeJwt(tokens.id_token), userinfo]) {
        expect(
          Object.keys(claims).filter((name) =>
            ["email", "email_verified", "name", "picture"].includes(name),
          ),
        ).toEqual(claimed);
      }
    }
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
    const setCookie = page.headers.get("set-cookie") ?? "";
    expect(setCookie).toMatch(
      /^__Host-broker_txn_[\w-]{32}=[\w-]{43}; Path=\/; HttpOnly; Secure; SameSite=Lax; Max-Age=600$/,
    );
    const cookie = setCookie.split(";")[0] ?? "";
    const html = await page.text();
    expect(html).toContain("Continue with Fake");
    expect(html).toContain(
      "from the provider you choose: a stable id, your name and picture, and your verified email address.",
    );
    const deny = html.match(/href="([^"]*deny=1)"/)?.[1]?.replace(/&amp;/g, "&") ?? "";
    const requestId = new URL(`${ISSUER}${deny}`).searchParams.get("request") ?? "";
    expect(cookie.startsWith(`__Host-broker_txn_${requestId}=`)).toBe(true);
    const denied = await h.fetchBroker(`${ISSUER}${deny}`, { headers: { Cookie: cookie } });
    expect(new URL(denied.headers.get("location") ?? "").searchParams.get("error")).toBe(
      "access_denied",
    );
    // The abandoned request deletes its cookie.
    expect(denied.headers.get("set-cookie")).toBe(
      `__Host-broker_txn_${requestId}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`,
    );
    const again = await h.fetchBroker(`${ISSUER}${deny}`, { headers: { Cookie: cookie } });
    expect(again.status).toBe(404);
    // The consent names only what the requested scopes release.
    const openidOnly = await h.fetchBroker(
      authorizeUrl(h, { clientId, challenge, extra: { scope: "openid" } }),
    );
    expect(await openidOnly.text()).toContain("from the provider you choose: a stable id.");
  });

  test("the chooser's links work only in the browser that saw the chooser", async () => {
    const h = await createHarness({ connectors: [fakeUpstream().connector] });
    const { clientId } = await h.registerClient({
      appName: "Stranger",
      firstParty: false,
      redirectUri: REDIRECT_URI,
    });
    const { challenge } = await pkce();
    const page = await h.fetchBroker(authorizeUrl(h, { clientId, challenge }));
    const cookie = (page.headers.get("set-cookie") ?? "").split(";")[0] ?? "";
    const html = await page.text();
    const link = (pattern: RegExp) =>
      `${ISSUER}${html.match(pattern)?.[1]?.replace(/&amp;/g, "&") ?? ""}`;
    const choose = link(/href="([^"]*connector=fake)"/);
    const deny = link(/href="([^"]*deny=1)"/);
    const requestId = new URL(choose).searchParams.get("request") ?? "";
    for (const headers of [
      {},
      { Cookie: `__Host-broker_txn_${requestId}=forged` },
      // The right value under another request's name is not this request's cookie.
      { Cookie: `__Host-broker_txn_other=${cookie.split("=")[1] ?? ""}` },
    ]) {
      expect((await h.fetchBroker(choose, { headers })).status).toBe(400);
      expect((await h.fetchBroker(deny, { headers })).status).toBe(400);
    }
    expect((await h.t.query(api.authRequests.get, { requestId }))?.status).toBe("pending");
    const chosen = await h.fetchBroker(choose, { headers: { Cookie: `theme=dark; ${cookie}` } });
    expect(chosen.status).toBe(302);
    expect(new URL(chosen.headers.get("location") ?? "").origin).toBe("https://upstream.test");
  });

  test("a path issuer scopes the chooser cookie to its path", async () => {
    const h = await createHarness({
      connectors: [fakeUpstream().connector],
      issuer: "https://samebase.test/identity",
    });
    const { clientId } = await h.registerClient({
      appName: "Stranger",
      firstParty: false,
      redirectUri: REDIRECT_URI,
    });
    const { challenge } = await pkce();
    const page = await h.fetchBroker(authorizeUrl(h, { clientId, challenge }));
    expect(page.headers.get("set-cookie")).toMatch(
      /^broker_txn_[\w-]{32}=[\w-]{43}; Path=\/identity; HttpOnly; Secure; SameSite=Lax; Max-Age=600$/,
    );
  });

  test("two sign-ins in one browser keep their own cookies", async () => {
    const h = await createHarness({ connectors: [fakeUpstream().connector] });
    const { clientId } = await h.registerClient({
      appName: "Stranger",
      firstParty: false,
      redirectUri: REDIRECT_URI,
    });
    const chooser = async () => {
      const { challenge } = await pkce();
      const page = await h.fetchBroker(authorizeUrl(h, { clientId, challenge }));
      const cookie = (page.headers.get("set-cookie") ?? "").split(";")[0] ?? "";
      const href = (await page.text()).match(/href="([^"]*connector=fake)"/)?.[1] ?? "";
      return { cookie, choose: `${ISSUER}${href.replace(/&amp;/g, "&")}` };
    };
    const first = await chooser();
    const second = await chooser();
    expect(first.cookie.split("=")[0]).not.toBe(second.cookie.split("=")[0]);
    const jar = { Cookie: `${first.cookie}; ${second.cookie}` };
    for (const { choose } of [first, second]) {
      const chosen = await h.fetchBroker(choose, { headers: jar });
      expect(chosen.status).toBe(302);
      expect(new URL(chosen.headers.get("location") ?? "").origin).toBe("https://upstream.test");
    }
  });

  test("a chooser request's callback without the cookie is refused and stays claimable", async () => {
    const h = await createHarness({ connectors: [fakeUpstream().connector] });
    const { clientId, clientSecret } = await h.registerClient({
      appName: "Stranger",
      firstParty: false,
      redirectUri: REDIRECT_URI,
    });
    const { verifier, challenge } = await pkce();
    // A client can fetch the chooser and continue it itself, then send a user the upstream URL.
    const page = await h.fetchBroker(authorizeUrl(h, { clientId, challenge }));
    const cookie = (page.headers.get("set-cookie") ?? "").split(";")[0] ?? "";
    const choose = (await page.text()).match(/href="([^"]*connector=fake)"/)?.[1] ?? "";
    const chooseUrl = `${ISSUER}${choose.replace(/&amp;/g, "&")}`;
    const requestId = new URL(chooseUrl).searchParams.get("request") ?? "";
    const started = await h.fetchBroker(chooseUrl, { headers: { Cookie: cookie } });
    const upstreamUrl = new URL(started.headers.get("location") ?? "");
    const callback = new URL(upstreamUrl.searchParams.get("redirect_uri") ?? "");
    callback.searchParams.set("code", "upstream-code");
    callback.searchParams.set("state", upstreamUrl.searchParams.get("state") ?? "");

    for (const headers of [{}, { Cookie: `__Host-broker_txn_${requestId}=forged` }]) {
      const refused = await h.fetchBroker(callback, { headers });
      expect(refused.status).toBe(400);
      expect(refused.headers.get("location")).toBeNull();
      expect((await h.t.query(api.authRequests.get, { requestId }))?.status).toBe("upstream");
    }

    // The browser that saw the chooser finishes the sign-in, and the cookie is deleted.
    const back = await h.fetchBroker(callback, { headers: { Cookie: cookie } });
    expect(back.status).toBe(302);
    expect(back.headers.get("set-cookie")).toBe(
      `__Host-broker_txn_${requestId}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`,
    );
    const code = new URL(back.headers.get("location") ?? "").searchParams.get("code") ?? "";
    expect((await exchange(h, { code, clientId, clientSecret, verifier })).status).toBe(200);
  });

  test("every page refuses to be framed", async () => {
    const h = await createHarness({ connectors: [fakeUpstream().connector] });
    const { clientId } = await h.registerClient({
      appName: "Stranger",
      firstParty: false,
      redirectUri: REDIRECT_URI,
    });
    const { challenge } = await pkce();
    for (const response of [
      await h.fetchBroker(authorizeUrl(h, { clientId, challenge })),
      await h.fetchBroker(authorizeUrl(h, { clientId: "cl_unknown", challenge })),
    ]) {
      expect(response.headers.get("content-security-policy")).toBe("frame-ancestors 'none'");
      expect(response.headers.get("x-frame-options")).toBe("DENY");
    }
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

  test("a chooser request's email steps need the cookie, even with the right code", async () => {
    const codes: string[] = [];
    const h = await createHarness({
      // @ts-expect-error a stand-in function reference; the harness replaces ctx.runAction.
      connectors: [email({ send: "stand-in" })],
      runAction: async (_reference, args) => {
        if (
          typeof args === "object" &&
          args !== null &&
          "code" in args &&
          typeof args.code === "string"
        ) {
          codes.push(args.code);
        }
        return null;
      },
    });
    const { clientId } = await h.registerClient({
      appName: "Stranger",
      firstParty: false,
      redirectUri: REDIRECT_URI,
    });
    const { challenge } = await pkce();
    const page = await h.fetchBroker(authorizeUrl(h, { clientId, challenge }));
    const cookie = (page.headers.get("set-cookie") ?? "").split(";")[0] ?? "";
    const choose = (await page.text()).match(/href="([^"]*connector=email)"/)?.[1] ?? "";
    const chooseUrl = `${ISSUER}${choose.replace(/&amp;/g, "&")}`;
    const requestId = new URL(chooseUrl).searchParams.get("request") ?? "";
    expect((await h.fetchBroker(chooseUrl, { headers: { Cookie: cookie } })).status).toBe(200);
    const post = (fields: Record<string, string>, headers: Record<string, string>) =>
      h.fetchBroker(`${ISSUER}/connectors/email`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded", ...headers },
        body: new URLSearchParams({ request: requestId, ...fields }).toString(),
      });

    expect((await post({ step: "send", email: "a@b.co" }, {})).status).toBe(400);
    expect(codes).toHaveLength(0);
    expect((await post({ step: "send", email: "a@b.co" }, { Cookie: cookie })).status).toBe(200);
    expect(codes).toHaveLength(1);

    const refused = await post({ step: "verify", code: codes[0] ?? "" }, {});
    expect(refused.status).toBe(400);
    expect(refused.headers.get("location")).toBeNull();
    expect(await h.t.query(api.authRequests.get, { requestId })).toMatchObject({
      status: "emailSent",
      emailAttempts: 0,
    });

    const ok = await post({ step: "verify", code: codes[0] ?? "" }, { Cookie: cookie });
    expect(ok.status).toBe(302);
    expect(new URL(ok.headers.get("location") ?? "").searchParams.get("code")).toBeTruthy();
    expect(ok.headers.get("set-cookie")).toBe(
      `__Host-broker_txn_${requestId}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`,
    );
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

describe("email send limits", () => {
  /**
   * A first-party app with only the email connector, and a clock the test moves. `codes` collects
   * every code sent; `signIn` starts one sign-in and returns a poster for its email form.
   */
  async function emailSetup() {
    const clock = { now: Date.now() };
    vi.spyOn(Date, "now").mockImplementation(() => clock.now);
    const codes: string[] = [];
    const h = await createHarness({
      // @ts-expect-error a stand-in function reference; the harness replaces ctx.runAction.
      connectors: [email({ send: "stand-in" })],
      runAction: async (_reference, args) => {
        if (
          typeof args === "object" &&
          args !== null &&
          "code" in args &&
          typeof args.code === "string"
        ) {
          codes.push(args.code);
        }
        return null;
      },
    });
    const { clientId } = await h.registerClient({
      appName: "Bristol",
      firstParty: true,
      redirectUri: REDIRECT_URI,
    });
    async function signIn() {
      const { challenge } = await pkce();
      const page = await h.fetchBroker(authorizeUrl(h, { clientId, challenge }));
      const requestId = (await page.text()).match(/name="request" value="([^"]+)"/)?.[1] ?? "";
      return (fields: Record<string, string>) =>
        h.fetchBroker(`${ISSUER}/connectors/email`, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({ request: requestId, ...fields }).toString(),
        });
    }
    return { clock, codes, signIn };
  }

  test("a second send inside 60 seconds is refused with 429 on the same page", async () => {
    const { clock, codes, signIn } = await emailSetup();
    const post = await signIn();
    expect((await post({ step: "send", email: "a@b.co" })).status).toBe(200);
    clock.now += 59_000;
    const refused = await post({ step: "send", email: "a@b.co" });
    expect(refused.status).toBe(429);
    const html = await refused.text();
    expect(html).toContain("Check your email");
    expect(html).toContain("Wait a minute before asking for another code.");
    expect(codes).toHaveLength(1);
    clock.now += 1_000;
    expect((await post({ step: "send", email: "a@b.co" })).status).toBe(200);
    expect(codes).toHaveLength(2);
  });

  test("a fourth send for one request is refused", async () => {
    const { clock, codes, signIn } = await emailSetup();
    const post = await signIn();
    for (let send = 0; send < 3; send++) {
      expect((await post({ step: "send", email: "a@b.co" })).status).toBe(200);
      clock.now += 60_000;
    }
    const refused = await post({ step: "send", email: "a@b.co" });
    expect(refused.status).toBe(429);
    expect(await refused.text()).toContain("Too many codes were sent. Try again later.");
    expect(codes).toHaveLength(3);
  });

  test("a sixth send to one address within an hour is refused across two requests", async () => {
    const { clock, codes, signIn } = await emailSetup();
    const first = await signIn();
    const second = await signIn();
    for (const post of [first, first, first, second, second]) {
      expect((await post({ step: "send", email: "a@b.co" })).status).toBe(200);
      clock.now += 60_000;
    }
    const refused = await second({ step: "send", email: "A@b.co" });
    expect(refused.status).toBe(429);
    expect(await refused.text()).toContain("Too many codes were sent. Try again later.");
    expect(codes).toHaveLength(5);
    // The same request can still send to another address.
    expect((await second({ step: "send", email: "c@d.co" })).status).toBe(200);
  });

  test("attempts do not reset after a resend", async () => {
    const { clock, codes, signIn } = await emailSetup();
    const post = await signIn();
    await post({ step: "send", email: "a@b.co" });
    const wrong = (code: string | undefined) => (code === "000000" ? "111111" : "000000");
    for (let attempt = 0; attempt < 4; attempt++) {
      expect(await (await post({ step: "verify", code: wrong(codes[0]) })).text()).toContain(
        "not right",
      );
    }
    clock.now += 60_000;
    expect((await post({ step: "send", email: "a@b.co" })).status).toBe(200);
    const locked = await post({ step: "verify", code: wrong(codes[1]) });
    expect(locked.status).toBe(302);
    expect(new URL(locked.headers.get("location") ?? "").searchParams.get("error")).toBe(
      "access_denied",
    );
    // A locked request sends no more codes.
    clock.now += 60_000;
    const resend = await post({ step: "send", email: "a@b.co" });
    expect(new URL(resend.headers.get("location") ?? "").searchParams.get("error")).toBe(
      "access_denied",
    );
    expect(codes).toHaveLength(2);
  });
});

describe("cleanup", () => {
  test("drops expired requests, codes and tokens, idle preview clients, old audit rows", async () => {
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
    await h.t.mutation(api.registration.mintToken, {
      tokenHash: "expired-token-hash",
      appId: "a",
      expiresAt: now - 1,
      createdAt: now - 86_400_000,
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
      registrationTokens: 1,
      previewClients: 1,
      signIns: 1,
      emailSends: 0,
    });
    const remaining = await h.t.query(api.clients.listByApp, { appId: "a" });
    expect(remaining.map((c) => c.clientId).sort()).toEqual(["preview-new", "prod-old"]);
  });

  test("one call drains a table that holds more than one batch", async () => {
    const h = await createHarness({ connectors: [fakeUpstream().connector] });
    vi.useFakeTimers();
    const now = Date.now();
    await h.t.run(async (ctx) => {
      for (let row = 0; row < 450; row++) {
        await ctx.db.insert("emailSends", { emailHash: `hash-${row}`, at: now - 2 * 3_600_000 });
      }
      await ctx.db.insert("emailSends", { emailHash: "recent", at: now });
    });
    const counts = await h.t.mutation(api.lifecycle.cleanup, {
      now,
      previewClientMaxAgeMs: 30 * 86_400_000,
      signInRetentionMs: 90 * 86_400_000,
    });
    expect(counts.emailSends).toBe(200);
    await h.t.finishAllScheduledFunctions(vi.runAllTimers);
    const left = await h.t.run(async (ctx) => await ctx.db.query("emailSends").collect());
    expect(left.map((row) => row.emailHash)).toEqual(["recent"]);
  });
});
