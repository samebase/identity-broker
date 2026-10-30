/** Response helpers shared by the endpoints. */

export function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      Pragma: "no-cache",
      ...headers,
    },
  });
}

/** An OAuth error body (RFC 6749 section 5.2), for the endpoints that answer the client directly. */
export function oauthError(
  status: number,
  error: string,
  description: string,
  headers: Record<string, string> = {},
): Response {
  return json({ error, error_description: description }, status, headers);
}

export function redirect(location: string): Response {
  return new Response(null, {
    status: 302,
    headers: { Location: location, "Cache-Control": "no-store" },
  });
}

/**
 * The authorization response (OAuth 2.1 section 4.1.2): parameters on the registered redirect URI,
 * with `iss` on every response (RFC 9207) and `state` when the client sent one.
 */
export function authorizationResponse(args: {
  redirectUri: string;
  issuer: string;
  state: string | undefined;
  /**
   * The Set-Cookie value that deletes the request's transaction cookie, when the browser holds
   * one: sending the browser back to the client ends the request there.
   */
  clearCookie: string | undefined;
  params: Record<string, string>;
}): Response {
  const url = new URL(args.redirectUri);
  for (const [key, value] of Object.entries(args.params)) {
    url.searchParams.set(key, value);
  }
  if (args.state !== undefined) {
    url.searchParams.set("state", args.state);
  }
  url.searchParams.set("iss", args.issuer);
  const response = redirect(url.toString());
  if (args.clearCookie !== undefined) {
    response.headers.append("Set-Cookie", args.clearCookie);
  }
  return response;
}

export function authorizationError(args: {
  redirectUri: string;
  issuer: string;
  state: string | undefined;
  clearCookie: string | undefined;
  error: string;
  description: string;
}): Response {
  return authorizationResponse({
    redirectUri: args.redirectUri,
    issuer: args.issuer,
    state: args.state,
    clearCookie: args.clearCookie,
    params: { error: args.error, error_description: args.description },
  });
}

/**
 * The parameters of a GET query or a form POST, which the authorization endpoint accepts alike. A
 * parameter sent without a value counts as omitted (RFC 6749 section 3.1).
 */
export async function readParameters(request: Request): Promise<URLSearchParams | null> {
  const contentType = request.headers.get("content-type")?.toLowerCase() ?? "";
  if (request.method !== "GET" && !contentType.startsWith("application/x-www-form-urlencoded")) {
    return null;
  }
  const params =
    request.method === "GET"
      ? new URL(request.url).searchParams
      : new URLSearchParams(await request.text());
  return new URLSearchParams([...params].filter(([, value]) => value !== ""));
}
