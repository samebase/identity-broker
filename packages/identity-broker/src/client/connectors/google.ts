import type { OidcConnector } from "./types.js";

/**
 * Google as an OIDC connector: discovery and id_token claims. Google documents no `login` value
 * for `prompt`, only `none`, `consent`, and `select_account`, so a fresh login through it answers
 * `login_required`.
 */
export function google(credentials: {
  clientId: () => string;
  clientSecret: () => string;
  name?: string;
}): OidcConnector {
  return {
    kind: "oidc",
    name: credentials.name ?? "google",
    label: "Google",
    issuer: "https://accounts.google.com",
    scopes: ["openid", "email", "profile"],
    promptLogin: false,
    clientId: credentials.clientId,
    clientSecret: credentials.clientSecret,
  };
}
