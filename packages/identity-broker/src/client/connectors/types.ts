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

/** A plain OAuth 2.0 provider: identity comes from an API call with the access token. */
export type OauthConnector = Credentials & {
  kind: "oauth";
  name: string;
  /** Shown on the chooser button, e.g. "GitHub". */
  label: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
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
};

export type Connector = OauthConnector | OidcConnector;
