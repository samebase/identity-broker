import type { OidcConnector } from "./types.js";

/** Google as an OIDC connector: discovery, id_token claims, `prompt=login` for fresh logins. */
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
    clientId: credentials.clientId,
    clientSecret: credentials.clientSecret,
  };
}
