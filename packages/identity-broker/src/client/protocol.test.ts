import { describe, expect, test } from "vite-plus/test";
import {
  canonicalEmail,
  parseRedirectUri,
  readClientAuthentication,
  validateAuthorizeRest,
  validateAuthorizeTarget,
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

  test("a repeated parameter of any name is refused before the target is read", () => {
    for (const name of ["client_id", "redirect_uri", "scope"]) {
      const params = new URLSearchParams(base);
      params.append(name, "again");
      expect(validateAuthorizeTarget(params)).toMatchObject({
        ok: false,
        error: "invalid_request",
        description: "A parameter is repeated.",
      });
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
    for (const prompt of ["consent", "login select_account"]) {
      expect(validateAuthorizeRest(new URLSearchParams({ ...base, prompt }), target)).toMatchObject(
        {
          ok: false,
          error: "invalid_request",
          description: "prompt value not supported",
        },
      );
    }
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

  test("one method, no repeated parameter, and a malformed Basic header is invalid_client", () => {
    expect(
      readClientAuthentication(
        `Basic ${btoa("a:b")}`,
        new URLSearchParams({ client_id: "a", client_secret: "b" }),
      ),
    ).toMatchObject({ ok: false, status: 400, error: "invalid_request" });
    // RFC 6749 section 3.2: a parameter without a value is omitted, so this is Basic alone.
    expect(
      readClientAuthentication(`Basic ${btoa("a:b")}`, new URLSearchParams("client_secret=")),
    ).toEqual({
      ok: true,
      value: { clientId: "a", clientSecret: "b", method: "client_secret_basic" },
    });
    expect(
      readClientAuthentication(
        null,
        new URLSearchParams("client_id=a&client_secret=b&code=1&code=2"),
      ),
    ).toMatchObject({ ok: false, status: 400, error: "invalid_request" });
    expect(
      readClientAuthentication(`Basic ${btoa("a:%E0%A4%A")}`, new URLSearchParams()),
    ).toMatchObject({ ok: false, status: 401, error: "invalid_client" });
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
