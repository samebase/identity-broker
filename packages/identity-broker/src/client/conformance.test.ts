/// <reference types="vite-plus/client" />
// openid-client, an OpenID-certified relying party, against the broker: discovery, the code flow
// with PKCE and nonce, id_token validation against the JWKS, userinfo.
import * as client from "openid-client";
import { afterEach, expect, test, vi } from "vite-plus/test";
import { createHarness, fakeUpstream, ISSUER } from "./harness.test.helper.js";

const REDIRECT_URI = "https://app.test/oauth/hub/callback";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

test("openid-client completes a sign-in through the broker", async () => {
  const upstream = fakeUpstream();
  const h = await createHarness({ connectors: [upstream.connector] });
  const { clientId, clientSecret } = await h.registerClient({
    appName: "Bristol",
    firstParty: true,
    redirectUri: REDIRECT_URI,
  });

  // Every request openid-client makes goes to the broker's handlers.
  const brokerFetch: client.CustomFetch = async (url, options) => {
    // openid-client posts strings and URLSearchParams; nothing else crosses this stub.
    const body =
      typeof options.body === "string" || options.body instanceof URLSearchParams
        ? options.body
        : undefined;
    const init: RequestInit = { method: options.method, headers: options.headers };
    return await h.fetchBroker(url, body === undefined ? init : { ...init, body });
  };
  const config = await client.discovery(
    new URL(ISSUER),
    clientId,
    undefined,
    client.ClientSecretPost(clientSecret),
    {
      [client.customFetch]: brokerFetch,
    },
  );
  expect(config.serverMetadata().issuer).toBe(ISSUER);
  expect(config.serverMetadata().supportsPKCE()).toBe(true);

  const codeVerifier = client.randomPKCECodeVerifier();
  const state = client.randomState();
  const nonce = client.randomNonce();
  const authorizationUrl = client.buildAuthorizationUrl(config, {
    redirect_uri: REDIRECT_URI,
    scope: "openid email profile",
    code_challenge: await client.calculatePKCECodeChallenge(codeVerifier),
    code_challenge_method: "S256",
    state,
    nonce,
  });

  // The browser: the broker sends the user upstream, the fake provider sends them back.
  const started = await h.fetchBroker(authorizationUrl);
  expect(started.status).toBe(302);
  const upstreamUrl = new URL(started.headers.get("location") ?? "");
  const callback = new URL(upstreamUrl.searchParams.get("redirect_uri") ?? "");
  callback.searchParams.set("code", "upstream-code");
  callback.searchParams.set("state", upstreamUrl.searchParams.get("state") ?? "");
  const back = await h.fetchBroker(callback);
  expect(back.status).toBe(302);
  const currentUrl = new URL(back.headers.get("location") ?? "");
  expect(currentUrl.origin + currentUrl.pathname).toBe(REDIRECT_URI);

  const tokens = await client.authorizationCodeGrant(config, currentUrl, {
    pkceCodeVerifier: codeVerifier,
    expectedState: state,
    expectedNonce: nonce,
    idTokenExpected: true,
  });
  const claims = tokens.claims();
  expect(claims?.iss).toBe(ISSUER);
  expect(claims?.aud).toBe(clientId);
  expect(claims?.nonce).toBe(nonce);
  expect(claims?.["email"]).toBe("octo@example.com");

  const userinfo = await client.fetchUserInfo(config, tokens.access_token, claims?.sub ?? "");
  expect(userinfo.sub).toBe(claims?.sub);
  expect(userinfo["email"]).toBe("octo@example.com");
});
