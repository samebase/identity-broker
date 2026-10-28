/// <reference types="vite-plus/client" />
import { decodeJwt } from "jose";
import { afterEach, describe, expect, test, vi } from "vite-plus/test";
import { api } from "../component/_generated/api.js";
import { google } from "./connectors/google.js";
import { defineIdentityBroker } from "./index.js";
import {
  component,
  createHarness,
  fakeOidcUpstream,
  fakeUpstream,
  ISSUER,
  pkce,
  REDIRECT_URI,
  sha256Hex,
  type Harness,
} from "./harness.test.helper.js";

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
    connector: "fake",
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
    const { appId, token } = await h.registerClient("bristol");
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
    const { appId, token, clientId } = await h.registerClient("bristol");
    const tokens = await h.t.query(api.registration.listTokens, { appId });
    expect(tokens).toEqual([{ tokenHash: await sha256Hex(token), createdAt: expect.any(Number) }]);
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

  test("needs a known token and an allowed host", async () => {
    const h = await createHarness({ connectors: [fakeUpstream().connector] });
    const { token } = await h.registerClient("bristol");
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
    const unknown = await h.fetchBroker(`${ISSUER}/register`, {
      method: "POST",
      headers: { Authorization: "Bearer rt_unknown", "Content-Type": "application/json" },
      body: "{}",
    });
    expect(unknown.status).toBe(401);
  });

  test("DELETE /register/<client_id> deletes a client only with its app's token", async () => {
    const h = await createHarness({ connectors: [fakeUpstream().connector] });
    const bristol = await h.registerClient("bristol");
    const other = await h.registerClient("other");
    const unregister = (clientId: string, token: string | undefined) =>
      h.fetchBroker(`${ISSUER}/register/${clientId}`, {
        method: "DELETE",
        headers: token === undefined ? {} : { Authorization: `Bearer ${token}` },
      });
    const exists = async (clientId: string) =>
      (await h.t.query(api.clients.get, { clientId })) !== null;

    for (const token of [undefined, "rt_unknown"]) {
      const refused = await unregister(bristol.clientId, token);
      expect(refused.status).toBe(401);
      expect((await refused.json()).error).toBe("invalid_token");
    }
    // Another app's live token gets the answer an unknown client gets, so it learns nothing.
    const otherApp = await unregister(bristol.clientId, other.token);
    const unknown = await unregister("cl_unknown", bristol.token);
    expect(otherApp.status).toBe(404);
    expect(unknown.status).toBe(404);
    expect(await otherApp.json()).toEqual(await unknown.json());
    expect(await exists(bristol.clientId)).toBe(true);

    const deleted = await unregister(bristol.clientId, bristol.token);
    expect(deleted.status).toBe(204);
    expect(await deleted.text()).toBe("");
    expect(await exists(bristol.clientId)).toBe(false);
    expect(await exists(other.clientId)).toBe(true);
    // A client that is already gone is 404.
    expect((await unregister(bristol.clientId, bristol.token)).status).toBe(404);
  });

  test("DELETE /register/<client_id> deletes a client of any deployment type, under a path issuer too", async () => {
    for (const issuer of [ISSUER, "https://samebase.test/identity"]) {
      const h = await createHarness({ connectors: [fakeUpstream().connector], issuer });
      const { token } = await h.registerClient("bristol");
      for (const deploymentType of ["production", "development", "preview"]) {
        const registered = await h.fetchBroker(`${issuer}/register`, {
          method: "POST",
          headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
          body: JSON.stringify({
            redirect_uris: [REDIRECT_URI],
            client_name: deploymentType,
            deployment_type: deploymentType,
          }),
        });
        const clientId = String((await registered.json()).client_id);
        const deleted = await h.fetchBroker(`${issuer}/register/${clientId}`, {
          method: "DELETE",
          headers: { Authorization: `Bearer ${token}` },
        });
        expect(deleted.status).toBe(204);
        expect(await h.t.query(api.clients.get, { clientId })).toBeNull();
      }
    }
  });
});

describe("authorization code flow with an OAuth connector", () => {
  test("a sign-in goes upstream through the named connector and back with a code", async () => {
    const upstream = fakeUpstream();
    const h = await createHarness({ connectors: [upstream.connector] });
    const { appId, clientId, clientSecret } = await h.registerClient("bristol");
    const { verifier, challenge } = await pkce();

    const back = await completeUpstream(
      h,
      await h.fetchBroker(authorizeUrl(h, { clientId, challenge })),
    );
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
    const other = await h.registerClient("other");
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
    const { clientId, clientSecret } = await h.registerClient("bristol");
    const other = await h.registerClient("other");
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
    const { clientId } = await h.registerClient("bristol");
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

    // The consumer names its connector: a missing or unknown one goes back as invalid_request.
    for (const connector of ["", "other"]) {
      const response = await h.fetchBroker(
        authorizeUrl(h, { clientId, challenge, extra: { connector } }),
      );
      const location = new URL(response.headers.get("location") ?? "");
      expect(location.origin + location.pathname).toBe(REDIRECT_URI);
      expect(location.searchParams.get("error")).toBe("invalid_request");
      expect(location.searchParams.get("error_description")).toBe(
        "connector must name a connector of this provider.",
      );
    }

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
    const { clientId } = await h.registerClient("bristol");
    for (const extra of [{ prompt: "login" }, { max_age: "0" }]) {
      const { challenge } = await pkce();
      const response = await h.fetchBroker(
        authorizeUrl(h, { clientId, challenge, extra: { ...extra, connector: "google" } }),
      );
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
      authorizeUrl(h, {
        clientId: args.clientId,
        challenge,
        extra: { ...args.extra, connector: "idp" },
      }),
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
    const { clientId, clientSecret } = await h.registerClient("bristol");
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
    const { clientId, clientSecret } = await h.registerClient("bristol");
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
    const { clientId } = await h.registerClient("bristol");
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
    const { clientId } = await h.registerClient("bristol");
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
    const { clientId } = await h.registerClient("bristol");
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
    const { clientId, clientSecret } = await h.registerClient("bristol");
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
    const { clientId, clientSecret } = await h.registerClient("bristol");
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

  test("an error page refuses to be framed", async () => {
    const h = await createHarness({ connectors: [fakeUpstream().connector] });
    const { challenge } = await pkce();
    for (const response of [
      await h.fetchBroker(authorizeUrl(h, { clientId: "cl_unknown", challenge })),
      await h.fetchBroker(`${ISSUER}/connectors/fake/callback`),
    ]) {
      expect(response.headers.get("content-security-policy")).toBe("frame-ancestors 'none'");
      expect(response.headers.get("x-frame-options")).toBe("DENY");
    }
  });
});

describe("cleanup", () => {
  test("drops expired requests and codes and old audit rows; idle preview clients only when asked", async () => {
    const h = await createHarness({ connectors: [fakeUpstream().connector] });
    const now = Date.now();
    await h.t.mutation(api.apps.create, { appId: "a", allowedCallbackHosts: ["app.test"] });
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
    const clientIds = async () =>
      (await h.t.query(api.clients.listByApp, { appId: "a" })).map((c) => c.clientId).sort();
    // Without previewClientMaxAgeMs, no client goes, however idle.
    expect(
      await h.t.mutation(api.lifecycle.cleanup, { now, signInRetentionMs: 90 * 86_400_000 }),
    ).toEqual({
      authRequests: 1,
      authorizationCodes: 0,
      previewClients: 0,
      signIns: 1,
    });
    expect(await clientIds()).toEqual(["preview-new", "preview-old", "prod-old"]);
    // With it, the preview client idle longer goes; the production client stays.
    expect(
      await h.t.mutation(api.lifecycle.cleanup, {
        now,
        previewClientMaxAgeMs: 30 * 86_400_000,
        signInRetentionMs: 90 * 86_400_000,
      }),
    ).toEqual({
      authRequests: 0,
      authorizationCodes: 0,
      previewClients: 1,
      signIns: 0,
    });
    expect(await clientIds()).toEqual(["preview-new", "prod-old"]);
  });

  test("the host's cleanup deletes idle preview clients only with previewClientIdleDays", async () => {
    for (const previewClientIdleDays of [undefined, 30, 50]) {
      const h = await createHarness({
        connectors: [fakeUpstream().connector],
        ...(previewClientIdleDays === undefined ? {} : { previewClientIdleDays }),
      });
      const now = Date.now();
      await h.t.mutation(api.apps.create, { appId: "a", allowedCallbackHosts: ["app.test"] });
      await h.t.mutation(api.clients.create, {
        clientId: "preview-40-days",
        appId: "a",
        secretHash: "h",
        tokenEndpointAuthMethod: "client_secret_post",
        redirectUri: REDIRECT_URI,
        deploymentType: "preview",
        clientName: "c",
        softwareVersion: "v",
        createdAt: now - 40 * 86_400_000,
      });
      const { cleanup } = h.broker.admin();
      // @ts-expect-error internalMutationGeneric keeps the function as _handler; RegisteredMutation does not declare it. Its handler only calls ctx.runMutation, which an action ctx has.
      const counts = await h.t.action(async (ctx) => await cleanup._handler(ctx, {}));
      expect(counts).toMatchObject({ previewClients: previewClientIdleDays === 30 ? 1 : 0 });
    }
  });

  test("previewClientIdleDays must be a positive number of days", () => {
    for (const previewClientIdleDays of [0, -1, Number.NaN]) {
      expect(() =>
        defineIdentityBroker({
          component,
          issuer: ISSUER,
          keys: () => undefined,
          connectors: [fakeUpstream().connector],
          previewClientIdleDays,
        }),
      ).toThrow("previewClientIdleDays must be a positive number of days");
    }
  });

  test("one call drains more expired requests than the 51 batches 0.4.0 stopped after", async () => {
    const h = await createHarness({ connectors: [fakeUpstream().connector] });
    vi.useFakeTimers();
    const now = Date.now();
    const request = {
      status: "pending",
      appId: "a",
      clientId: "c",
      redirectUri: REDIRECT_URI,
      scope: "openid",
      codeChallenge: "c",
      freshLogin: false,
      createdAt: now - 600_000,
    } as const;
    await h.t.run(async (ctx) => {
      // 0.4.0 ran the first batch and at most 50 continuations, 200 rows each.
      for (let row = 0; row < 51 * 200 + 1; row++) {
        await ctx.db.insert("authRequests", {
          ...request,
          requestId: `r-${row}`,
          expiresAt: now - 1,
        });
      }
      await ctx.db.insert("authRequests", { ...request, requestId: "live", expiresAt: now + 1 });
    });
    await h.t.mutation(api.lifecycle.cleanup, { now, signInRetentionMs: 90 * 86_400_000 });
    await h.t.finishAllScheduledFunctions(vi.runAllTimers);
    const left = await h.t.run(async (ctx) => await ctx.db.query("authRequests").collect());
    expect(left.map((row) => row.requestId)).toEqual(["live"]);
  });
});
