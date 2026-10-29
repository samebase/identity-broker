import type { FunctionReference } from "convex/server";

/** What a connector attested about the user. `upstreamId` is the connector's stable account id. */
export type UpstreamIdentity = {
  upstreamId: string;
  email?: string;
  emailVerified?: boolean;
  name?: string;
  picture?: string;
};

type Credentials = {
  /** Read lazily, in the request, so a missing env var fails that request and not the deploy. */
  clientId: () => string;
  clientSecret: () => string;
};

/**
 * A plain OAuth 2.0 provider found through its RFC 8414 metadata: identity comes from an API call
 * with the access token.
 */
export type OauthConnector = Credentials & {
  kind: "oauth";
  name: string;
  /** Shown on the chooser button, e.g. "GitHub". */
  label: string;
  issuer: string;
  scopes: string[];
  identity: (accessToken: string) => Promise<UpstreamIdentity>;
};

/** An OpenID Connect provider found through discovery: identity comes from the id_token. */
export type OidcConnector = Credentials & {
  kind: "oidc";
  name: string;
  label: string;
  issuer: string;
  scopes: string[];
  /**
   * The provider documents `prompt=login`, so a fresh login (`prompt=login` or `max_age`) is sent
   * upstream as that. Without it, a fresh login answers `login_required`.
   */
  promptLogin: boolean;
};

/** The host action that delivers a code. The broker never sees how. */
export type SendEmailCode = FunctionReference<
  "action",
  "internal",
  { to: string; code: string; appName: string },
  null
>;

export type EmailConnector = {
  kind: "email";
  name: string;
  label: string;
  send: SendEmailCode;
};

export type Connector = OauthConnector | OidcConnector | EmailConnector;
