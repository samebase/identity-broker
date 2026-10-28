import { describe, expect, test } from "vite-plus/test";
import {
  canonicalEmail,
  hostAllowed,
  parseRedirectUri,
  readClientAuthentication,
  validateAuthorizeRest,
  validateAuthorizeTarget,
  validateRegistration,
  validateTokenRequest,
} from "./protocol.js";

const CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

describe("redirect URIs", () => {
  test("https without fragment, or http on loopback", () => {
    expect(parseRedirectUri("https://app.example.com/oauth/hub/callback")).not.toBeNull();
    expect(parseRedirectUri("http://127.0.0.1:3210/oauth/hub/callback")).not.toBeNull();
    expect(parseRedirectUri("http://localhost:3210/cb")).not.toBeNull();
    expect(parseRedirectUri("http://app.example.com/cb")).toBeNull();
    expect(parseRedirectUri("https://app.example.com/cb#frag")).toBeNull();
    expect(parseRedirectUri("not a url")).toBeNull();
  });

  test("allowed hosts: exact or one wildcard label", () => {
    const allowed = ["*.convex.site", "127.0.0.1"];
    expect(hostAllowed("happy-otter-123.convex.site", allowed)).toBe(true);
    expect(hostAllowed("a.b.convex.site", allowed)).toBe(false);
    expect(hostAllowed("convex.site", allowed)).toBe(false);
    expect(hostAllowed("127.0.0.1", allowed)).toBe(true);
    expect(hostAllowed("evil.com", allowed)).toBe(false);
    expect(hostAllowed("evilconvex.site", allowed)).toBe(false);
  });
});

describe("registration", () => {
  const good = {
    redirect_uris: ["https://happy-otter-123.convex.site/oauth/hub/callback"],
    client_name: "Bristol",
    software_version: "happy-otter-123",
    deployment_type: "preview",
  };

  test("accepts one redirect URI and the extension field", () => {
    const result = validateRegistration(good);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.tokenEndpointAuthMethod).toBe("client_secret_post");
      expect(result.value.deploymentType).toBe("preview");
    }
  });

  test("rejects two redirect URIs, bad types, other grants", () => {
    const two = validateRegistration({
      ...good,
      redirect_uris: [good.redirect_uris[0], "https://b/c"],
    });
    expect(two.ok).toBe(false);
    expect(validateRegistration({ ...good, deployment_type: "staging" }).ok).toBe(false);
    expect(validateRegistration({ ...good, grant_types: ["refresh_token"] }).ok).toBe(false);
    expect(validateRegistration({ ...good, token_endpoint_auth_method: "none" }).ok).toBe(false);
    expect(validateRegistration("nope").ok).toBe(false);
  });
});

describe("authorize", () => {
  const base = {
    client_id: "cl_1",
    redirect_uri: "https://app.test/cb",
    response_type: "code",
    scope: "openid email",
    code_challenge: CHALLENGE,
    code_challenge_method: "S256",
  };

  test("target then rest", () => {
    const params = new URLSearchParams({
      ...base,
      state: "s",
      nonce: "n",
      prompt: "login",
      max_age: "0",
    });
    const target = validateAuthorizeTarget(params);
    expect(target.ok).toBe(true);
    if (!target.ok) return;
    const rest = validateAuthorizeRest(params, target.value);
    expect(rest.ok).toBe(true);
    if (rest.ok) {
      expect(rest.value.prompt).toEqual(["login"]);
      expect(rest.value.maxAge).toBe(0);
      expect(rest.value.scopes).toEqual(["openid", "email"]);
    }
  });

  test("errors name the OAuth error code", () => {
    const target = { clientId: "cl_1", redirectUri: base.redirect_uri };
    const noOpenid = validateAuthorizeRest(
      new URLSearchParams({ ...base, scope: "email" }),
      target,
    );
    expect(noOpenid.ok).toBe(false);
    if (!noOpenid.ok) expect(noOpenid.error).toBe("invalid_scope");
    const token = validateAuthorizeRest(
      new URLSearchParams({ ...base, response_type: "token" }),
      target,
    );
    if (!token.ok) expect(token.error).toBe("unsupported_response_type");
    const plain = validateAuthorizeRest(
      new URLSearchParams({ ...base, code_challenge_method: "plain" }),
      target,
    );
    expect(plain.ok).toBe(false);
    const noPkce = new URLSearchParams(base);
    noPkce.delete("code_challenge");
    expect(validateAuthorizeRest(noPkce, target).ok).toBe(false);
    const mixed = validateAuthorizeRest(
      new URLSearchParams({ ...base, prompt: "none login" }),
      target,
    );
    expect(mixed.ok).toBe(false);
  });
});

describe("token", () => {
  test("client credentials from the body or Basic", () => {
    const post = readClientAuthentication(
      null,
      new URLSearchParams({ client_id: "a", client_secret: "b" }),
    );
    expect(post.ok && post.value.method).toBe("client_secret_post");
    const basic = readClientAuthentication(`Basic ${btoa("a:b%3Ac")}`, new URLSearchParams());
    expect(basic.ok && basic.value.clientSecret).toBe("b:c");
    expect(readClientAuthentication("Bearer x", new URLSearchParams()).ok).toBe(false);
    expect(readClientAuthentication(null, new URLSearchParams({ client_id: "a" })).ok).toBe(false);
  });

  test("authorization_code only, with a verifier", () => {
    const client = { clientId: "a", clientSecret: "b", method: "client_secret_post" as const };
    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const ok = validateTokenRequest(
      new URLSearchParams({ grant_type: "authorization_code", code: "c", code_verifier: verifier }),
      client,
    );
    expect(ok.ok).toBe(true);
    const refresh = validateTokenRequest(
      new URLSearchParams({ grant_type: "refresh_token", refresh_token: "r" }),
      client,
    );
    expect(refresh.ok).toBe(false);
    if (!refresh.ok) expect(refresh.error).toBe("unsupported_grant_type");
    const short = validateTokenRequest(
      new URLSearchParams({ grant_type: "authorization_code", code: "c", code_verifier: "short" }),
      client,
    );
    expect(short.ok).toBe(false);
  });
});

test("canonical email", () => {
  expect(canonicalEmail("  Nicu@Example.COM ")).toBe("nicu@example.com");
  expect(canonicalEmail("nope")).toBeNull();
  expect(canonicalEmail("a@")).toBeNull();
  expect(canonicalEmail("@b")).toBeNull();
});
