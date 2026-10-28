// An OIDC connector against a fake provider: discovery, PKCE, and the state, nonce and claims of the
// id_token, which oauth4webapi checks. It does not check the id_token's signature: the token comes
// from the token endpoint over TLS.
import { generateKeyPair, SignJWT } from "jose";
import { afterEach, expect, test, vi } from "vite-plus/test";
import type { OidcConnector } from "./types.js";
import { finishUpstream, startUpstream } from "./upstream.js";

const ISSUER = "https://idp.test";
const CALLBACK = "https://auth.test/connectors/idp/callback";

afterEach(() => {
  vi.unstubAllGlobals();
});

/**
 * The fake provider signs the nonce the test hands it after `startUpstream`, the way a real
 * provider echoes the nonce of the authorization request it saw.
 */
async function fakeProvider() {
  const { privateKey } = await generateKeyPair("RS256");
  let nonce: string | undefined;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init);
      const url = new URL(request.url);
      if (url.pathname === "/.well-known/openid-configuration") {
        return Response.json({
          issuer: ISSUER,
          authorization_endpoint: `${ISSUER}/authorize`,
          token_endpoint: `${ISSUER}/token`,
          response_types_supported: ["code"],
          subject_types_supported: ["public"],
          id_token_signing_alg_values_supported: ["RS256"],
          code_challenge_methods_supported: ["S256"],
        });
      }
      if (url.pathname === "/token") {
        const body = new URLSearchParams(await request.text());
        if (
          body.get("code") !== "idp-code" ||
          body.get("client_secret") !== "s" ||
          body.get("code_verifier") === null
        ) {
          return Response.json({ error: "invalid_grant" }, { status: 400 });
        }
        const idToken = await new SignJWT({
          ...(nonce === undefined ? {} : { nonce }),
          email: "ada@example.com",
          email_verified: true,
          name: "Ada",
        })
          .setProtectedHeader({ alg: "RS256", kid: "k1" })
          .setIssuer(ISSUER)
          .setAudience("c")
          .setSubject("idp-sub-1")
          .setIssuedAt()
          .setExpirationTime("5m")
          .sign(privateKey);
        return Response.json({ access_token: "idp-at", token_type: "Bearer", id_token: idToken });
      }
      return new Response("unexpected", { status: 599 });
    }),
  );
  return {
    setNonce: (value: string | undefined) => {
      nonce = value;
    },
  };
}

const connector: OidcConnector = {
  kind: "oidc",
  name: "idp",
  label: "IdP",
  issuer: ISSUER,
  scopes: ["openid", "email", "profile"],
  clientId: () => "c",
  clientSecret: () => "s",
};

test("start carries PKCE and nonce; finish validates the id_token and reads the claims", async () => {
  const provider = await fakeProvider();
  const start = await startUpstream({ connector, callbackUrl: CALLBACK });
  const url = new URL(start.url);
  expect(url.origin + url.pathname).toBe(`${ISSUER}/authorize`);
  expect(url.searchParams.get("code_challenge_method")).toBe("S256");
  expect(url.searchParams.get("nonce")).toBe(start.nonce);

  provider.setNonce(start.nonce);
  const current = new URL(`${CALLBACK}?code=idp-code&state=${encodeURIComponent(start.state)}`);
  const finish = await finishUpstream({
    connector,
    callbackUrl: CALLBACK,
    currentUrl: current,
    state: start.state,
    codeVerifier: start.codeVerifier,
    nonce: start.nonce,
  });
  expect(finish).toEqual({
    upstreamId: "idp-sub-1",
    email: "ada@example.com",
    emailVerified: true,
    name: "Ada",
  });
});

test("a wrong nonce or a wrong state is refused", async () => {
  const provider = await fakeProvider();
  const start = await startUpstream({ connector, callbackUrl: CALLBACK });
  provider.setNonce("someone-else");
  const current = new URL(`${CALLBACK}?code=idp-code&state=${encodeURIComponent(start.state)}`);
  await expect(
    finishUpstream({
      connector,
      callbackUrl: CALLBACK,
      currentUrl: current,
      state: start.state,
      codeVerifier: start.codeVerifier,
      nonce: start.nonce,
    }),
  ).rejects.toThrow();
  const wrongState = new URL(`${CALLBACK}?code=idp-code&state=other`);
  await expect(
    finishUpstream({
      connector,
      callbackUrl: CALLBACK,
      currentUrl: wrongState,
      state: start.state,
      codeVerifier: start.codeVerifier,
      nonce: start.nonce,
    }),
  ).rejects.toThrow();
});
