/**
 * Request validation for the OpenID Provider endpoints: pure functions over URLs, form bodies and
 * headers, with the error shapes the handlers turn into OAuth responses.
 */

export type Validation<T> =
  | { ok: true; value: T }
  | { ok: false; status: number; error: string; description: string };

const MAX_STATE_LENGTH = 4096;
const MAX_REDIRECT_URI_LENGTH = 2048;
const pkceValuePattern = /^[A-Za-z0-9\-._~]{43,128}$/;

export type TokenEndpointAuthMethod = "client_secret_post" | "client_secret_basic";

/** The own enumerable entries of a JSON value, or an empty record for anything but an object. */
export function asRecord(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return {};
  }
  return Object.fromEntries(Object.entries(value));
}

function invalid<T>(status: number, error: string, description: string): Validation<T> {
  return { ok: false, status, error, description };
}

/** RFC 6749 sections 3.1 and 3.2: a request parameter must not be included more than once. */
function hasRepeatedParameter(params: URLSearchParams): boolean {
  const names = [...params.keys()];
  return new Set(names).size !== names.length;
}

function isLoopbackHost(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]";
}

/** https, or http on a loopback host for local development. */
export function isSecureUrl(url: URL): boolean {
  return url.protocol === "https:" || (url.protocol === "http:" && isLoopbackHost(url.hostname));
}

/** A redirect URI: absolute, no fragment, and secure. */
export function parseRedirectUri(value: string): URL | null {
  if (value.length === 0 || value.length > MAX_REDIRECT_URI_LENGTH) {
    return null;
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  return url.hash.length === 0 && isSecureUrl(url) ? url : null;
}

export type AuthorizeInput = {
  clientId: string;
  redirectUri: string;
  scopes: string[];
  state: string | undefined;
  nonce: string | undefined;
  codeChallenge: string;
  prompt: string[];
  maxAge: number | undefined;
  connector: string | undefined;
};

/**
 * The first half of /authorize validation: the parameters that identify the client and where to
 * send errors. Everything else is checked by `validateAuthorizeRest` once the client is known, so
 * those errors can go back to the registered redirect URI. A repeated parameter of any name is
 * refused first, so an ambiguous `client_id` or `redirect_uri` never picks a redirect target.
 */
export function validateAuthorizeTarget(
  params: URLSearchParams,
): Validation<{ clientId: string; redirectUri: string }> {
  if (hasRepeatedParameter(params)) {
    return invalid(400, "invalid_request", "A parameter is repeated.");
  }
  const clientId = params.get("client_id")?.trim() ?? "";
  if (clientId.length === 0) {
    return invalid(400, "invalid_request", "client_id is required.");
  }
  const redirectUri = params.get("redirect_uri") ?? "";
  if (parseRedirectUri(redirectUri) === null) {
    return invalid(400, "invalid_request", "redirect_uri is missing or invalid.");
  }
  return { ok: true, value: { clientId, redirectUri } };
}

export function validateAuthorizeRest(
  params: URLSearchParams,
  target: { clientId: string; redirectUri: string },
): Validation<AuthorizeInput> {
  // Discovery says neither is supported, and OIDC Core sections 6.1 and 6.2 name these errors.
  if (params.has("request")) {
    return invalid(400, "request_not_supported", "Request Objects are not supported.");
  }
  if (params.has("request_uri")) {
    return invalid(400, "request_uri_not_supported", "request_uri is not supported.");
  }
  if (params.get("response_type") !== "code") {
    return invalid(400, "unsupported_response_type", 'response_type must be "code".');
  }
  const scopes = (params.get("scope") ?? "").split(/\s+/).filter((scope) => scope.length > 0);
  if (!scopes.includes("openid")) {
    return invalid(400, "invalid_scope", 'scope must include "openid".');
  }
  const state = params.get("state") ?? undefined;
  if (state !== undefined && state.length > MAX_STATE_LENGTH) {
    return invalid(400, "invalid_request", `state must be at most ${MAX_STATE_LENGTH} characters.`);
  }
  const nonce = params.get("nonce") ?? undefined;
  if (nonce !== undefined && nonce.length > MAX_STATE_LENGTH) {
    return invalid(400, "invalid_request", `nonce must be at most ${MAX_STATE_LENGTH} characters.`);
  }
  const codeChallenge = params.get("code_challenge") ?? "";
  if (!pkceValuePattern.test(codeChallenge)) {
    return invalid(
      400,
      "invalid_request",
      "code_challenge is required: 43 to 128 URL-safe characters.",
    );
  }
  if (params.get("code_challenge_method") !== "S256") {
    return invalid(400, "invalid_request", 'code_challenge_method must be "S256".');
  }
  const prompt = (params.get("prompt") ?? "").split(/\s+/).filter((value) => value.length > 0);
  if (prompt.some((value) => value !== "none" && value !== "login")) {
    return invalid(400, "invalid_request", "prompt value not supported");
  }
  if (prompt.includes("none") && prompt.length > 1) {
    return invalid(400, "invalid_request", "prompt=none cannot be combined with other values.");
  }
  const maxAgeRaw = params.get("max_age");
  let maxAge: number | undefined;
  if (maxAgeRaw !== null) {
    maxAge = Number(maxAgeRaw);
    if (!Number.isInteger(maxAge) || maxAge < 0) {
      return invalid(400, "invalid_request", "max_age must be a non-negative integer.");
    }
  }
  const connector = params.get("connector")?.trim() || undefined;
  return {
    ok: true,
    value: {
      clientId: target.clientId,
      redirectUri: target.redirectUri,
      scopes,
      state,
      nonce,
      codeChallenge,
      prompt,
      maxAge,
      connector,
    },
  };
}

export type TokenInput = {
  code: string;
  redirectUri: string | undefined;
  codeVerifier: string;
  client: { clientId: string; clientSecret: string; method: TokenEndpointAuthMethod };
};

/**
 * Client credentials from HTTP Basic (RFC 6749 section 2.3.1) or the form body. The first look at a
 * token request, so it also refuses a repeated parameter (RFC 6749 section 3.2) and a request that
 * uses both methods (section 2.3): an Authorization header and a `client_secret` in the body. A
 * `client_id` in the body names the client and is not a method; an empty `client_secret` counts as
 * omitted (section 3.2).
 */
export function readClientAuthentication(
  authorization: string | null,
  params: URLSearchParams,
): Validation<TokenInput["client"]> {
  if (hasRepeatedParameter(params)) {
    return invalid(400, "invalid_request", "A parameter is repeated.");
  }
  if (authorization !== null) {
    if (params.get("client_secret")) {
      return invalid(400, "invalid_request", "Use one client authentication method, not two.");
    }
    const match = authorization.trim().match(/^basic\s+(.+)$/i);
    if (match === null || match[1] === undefined) {
      return invalid(401, "invalid_client", "Only HTTP Basic client authentication is supported.");
    }
    let decoded: string;
    try {
      decoded = atob(match[1]);
    } catch {
      return invalid(401, "invalid_client", "The Authorization header is not valid Base64.");
    }
    const separator = decoded.indexOf(":");
    if (separator <= 0) {
      return invalid(
        401,
        "invalid_client",
        "The Authorization header must hold client_id:client_secret.",
      );
    }
    try {
      return {
        ok: true,
        value: {
          clientId: decodeURIComponent(decoded.slice(0, separator)),
          clientSecret: decodeURIComponent(decoded.slice(separator + 1)),
          method: "client_secret_basic",
        },
      };
    } catch {
      return invalid(401, "invalid_client", "The Authorization header is not valid form encoding.");
    }
  }
  const clientId = params.get("client_id") ?? "";
  const clientSecret = params.get("client_secret") ?? "";
  if (clientId.length === 0 || clientSecret.length === 0) {
    return invalid(401, "invalid_client", "client_id and client_secret are required.");
  }
  return { ok: true, value: { clientId, clientSecret, method: "client_secret_post" } };
}

export function validateTokenRequest(
  params: URLSearchParams,
  client: TokenInput["client"],
): Validation<TokenInput> {
  const grantType = params.get("grant_type");
  if (grantType !== "authorization_code") {
    return invalid(400, "unsupported_grant_type", 'grant_type must be "authorization_code".');
  }
  const code = params.get("code")?.trim() ?? "";
  if (code.length === 0) {
    return invalid(400, "invalid_request", "code is required.");
  }
  const redirectUri = params.get("redirect_uri") ?? undefined;
  if (redirectUri !== undefined && parseRedirectUri(redirectUri) === null) {
    return invalid(400, "invalid_request", "redirect_uri is invalid.");
  }
  const codeVerifier = params.get("code_verifier") ?? "";
  if (!pkceValuePattern.test(codeVerifier)) {
    return invalid(
      400,
      "invalid_request",
      "code_verifier is required: 43 to 128 URL-safe characters.",
    );
  }
  return { ok: true, value: { code, redirectUri, codeVerifier, client } };
}

export function readBearerToken(authorization: string | null): string | null {
  const match = authorization?.trim().match(/^bearer\s+(.+)$/i);
  return match?.[1]?.trim() || null;
}

/** An email address as the broker identifies it: trimmed, NFC-normalized, lowercased. */
export function canonicalEmail(value: string): string | null {
  const email = value.trim().normalize("NFC").toLowerCase();
  const at = email.indexOf("@");
  if (at <= 0 || at === email.length - 1 || email.includes(" ") || email.length > 320) {
    return null;
  }
  return email;
}
