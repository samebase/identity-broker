/**
 * Request validation for the OpenID Provider endpoints: pure functions over URLs, form bodies and
 * headers, with the error shapes the handlers turn into OAuth responses.
 */

export type Validation<T> =
  | { ok: true; value: T }
  | { ok: false; status: number; error: string; description: string };

const MAX_STATE_LENGTH = 4096;
const MAX_REDIRECT_URI_LENGTH = 2048;
const MAX_CLIENT_NAME_LENGTH = 120;
const pkceValuePattern = /^[A-Za-z0-9\-._~]{43,128}$/;

export const TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_post", "client_secret_basic"] as const;
export type TokenEndpointAuthMethod = (typeof TOKEN_ENDPOINT_AUTH_METHODS)[number];

export const DEPLOYMENT_TYPES = ["production", "development", "preview"] as const;
export type DeploymentType = (typeof DEPLOYMENT_TYPES)[number];

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

/** A redirect URI: absolute, no fragment, https, or http on a loopback host for local development. */
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
  if (url.hash.length > 0) {
    return null;
  }
  if (url.protocol === "https:") {
    return url;
  }
  if (url.protocol === "http:" && isLoopbackHost(url.hostname)) {
    return url;
  }
  return null;
}

/**
 * Whether `hostname` is covered by one of an app's allowed callback hosts: an exact host, or a
 * `*.suffix` pattern whose wildcard stands for exactly one leading label.
 */
export function hostAllowed(hostname: string, allowedHosts: readonly string[]): boolean {
  const host = hostname.toLowerCase();
  return allowedHosts.some((allowed) => {
    const pattern = allowed.toLowerCase();
    if (!pattern.startsWith("*.")) {
      return host === pattern;
    }
    const suffix = pattern.slice(1);
    if (!host.endsWith(suffix)) {
      return false;
    }
    const label = host.slice(0, host.length - suffix.length);
    return label.length > 0 && !label.includes(".");
  });
}

export type RegistrationInput = {
  redirectUri: string;
  clientName: string;
  softwareVersion: string;
  deploymentType: DeploymentType;
  tokenEndpointAuthMethod: TokenEndpointAuthMethod;
};

function readString(value: unknown, maxLength: number): string | null {
  if (typeof value !== "string") {
    return null;
  }
  const trimmed = value.trim();
  return trimmed.length === 0 || trimmed.length > maxLength ? null : trimmed;
}

/** RFC 7591 registration metadata as this provider accepts it: one redirect URI per client. */
export function validateRegistration(payload: unknown): Validation<RegistrationInput> {
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
    return invalid(400, "invalid_client_metadata", "The request body must be a JSON object.");
  }
  const record = asRecord(payload);

  const redirectUris = record["redirect_uris"];
  if (!Array.isArray(redirectUris) || redirectUris.length !== 1) {
    return invalid(
      400,
      "invalid_redirect_uri",
      "redirect_uris must hold exactly one URI: a client is one deployment.",
    );
  }
  const redirectUri = typeof redirectUris[0] === "string" ? redirectUris[0] : "";
  if (parseRedirectUri(redirectUri) === null) {
    return invalid(
      400,
      "invalid_redirect_uri",
      "The redirect URI must be an absolute https URL without a fragment, or http on a loopback host.",
    );
  }

  const clientName = readString(record["client_name"], MAX_CLIENT_NAME_LENGTH);
  if (clientName === null) {
    return invalid(400, "invalid_client_metadata", "client_name is required.");
  }

  const softwareVersion = readString(record["software_version"] ?? "unknown", 200);
  if (softwareVersion === null) {
    return invalid(400, "invalid_client_metadata", "software_version must be a non-empty string.");
  }

  const deploymentType = DEPLOYMENT_TYPES.find((type) => type === record["deployment_type"]);
  if (deploymentType === undefined) {
    return invalid(
      400,
      "invalid_client_metadata",
      `deployment_type must be one of ${DEPLOYMENT_TYPES.join(", ")}.`,
    );
  }

  // RFC 7591 section 2: the default is client_secret_basic.
  const authMethod = TOKEN_ENDPOINT_AUTH_METHODS.find(
    (method) => method === (record["token_endpoint_auth_method"] ?? "client_secret_basic"),
  );
  if (authMethod === undefined) {
    return invalid(
      400,
      "invalid_client_metadata",
      `token_endpoint_auth_method must be one of ${TOKEN_ENDPOINT_AUTH_METHODS.join(", ")}.`,
    );
  }

  const grantTypes = record["grant_types"];
  if (
    grantTypes !== undefined &&
    (!Array.isArray(grantTypes) ||
      grantTypes.length !== 1 ||
      grantTypes[0] !== "authorization_code")
  ) {
    return invalid(400, "invalid_client_metadata", 'grant_types must be ["authorization_code"].');
  }
  const responseTypes = record["response_types"];
  if (
    responseTypes !== undefined &&
    (!Array.isArray(responseTypes) || responseTypes.length !== 1 || responseTypes[0] !== "code")
  ) {
    return invalid(400, "invalid_client_metadata", 'response_types must be ["code"].');
  }

  return {
    ok: true,
    value: {
      redirectUri,
      clientName,
      softwareVersion,
      deploymentType,
      tokenEndpointAuthMethod: authMethod,
    },
  };
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
 * uses both methods (section 2.3).
 */
export function readClientAuthentication(
  authorization: string | null,
  params: URLSearchParams,
): Validation<TokenInput["client"]> {
  if (hasRepeatedParameter(params)) {
    return invalid(400, "invalid_request", "A parameter is repeated.");
  }
  if (authorization !== null) {
    if (params.has("client_secret")) {
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
