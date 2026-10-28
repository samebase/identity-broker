# Design

The broker is a federated OpenID Provider in the shape of Dex: upstream connectors, no accounts.

## What is stored

Apps (an app id and its allowed callback hosts), their registration tokens (hashed), clients (one
per deployment: exact redirect URI, hashed secret), and authorization requests. A request lives ten
minutes from `/authorize`; once the connector attests the user, it holds the hash of its
authorization code and lives the sixty seconds of the code, and redeeming the code deletes it.
Nothing about a user outlives the request that carried it.

The host schedules the component's `cleanup` daily from a cron, as the
[identity-hub](https://github.com/samebase/identity-hub) template does; nothing else deletes expired
requests. One run drains them: a batch deletes at most 200, and a full batch schedules the next one
at once with the same cutoff. The cutoff is the time the run began, so the run ends: requests
written during it run out after the cutoff.

Clients stay until `DELETE /register/<client_id>` or `deleteClient` removes them, or their app is
deleted. Registration tokens do not expire: one stays until `revokeRegistrationToken` or `deleteApp`
removes it.

## Registration

`POST /register` (RFC 7591) registers one deployment of an app as a client, with the app's
registration token as a Bearer token. `DELETE /register/<client_id>` with a token of the same app
deletes that client and answers 204. A missing or unknown token answers 401. A client that is gone
and a client of another app both answer 404, not 403, so a token learns nothing about another app's
clients. The delete has the shape of RFC 7592's, which the broker does not implement: no
registration access token per client, and a missing client answers 404 rather than 401.

`deleteApp` deletes the app, its registration tokens and its clients in one transaction: an app has
a client per live deployment, a handful once previews unregister on destroy. A registration that
read its token before the deletion cannot create its client after it, so no client outlives its app.

## Issuer and connectors

The issuer is an https origin with the broker at `/`, such as `https://auth.example.com` or the hub
deployment's `CONVEX_SITE_URL`. `defineIdentityBroker` and `IdentityHub.Client` refuse anything
else.

A consumer names the connector in its authorization request, `connector=google`; a missing or
unknown name answers `invalid_request` on the client's redirect URI. Every app of a hub is the hub
owner's, so the broker shows no chooser and no consent: its only page is the error page for a
request without a trusted redirect target.

## Subjects

`sub` is pairwise per app (OIDC Core 8.1), computed as
`base64url(SHA-256(appId || connector || upstreamId || salt))`. The salt is created once with the
key set and never rotated: a new salt is a new identity for everyone.

App ids and connector names are identity namespaces. Recreating an app (a new app id) or renaming a
connector changes every `sub` it produces. The salt lives only in `IDENTITY_BROKER_KEYS`, so back up
the key set: a lost salt cannot be recreated.

Every id_token also carries `connector` and `connector_account_id`, the connector's own id for the
account: the GitHub user id, or Google's `sub`. An app whose existing users are keyed by provider
and account id maps them by this pair. The pair is the same in every app, so the apps of a hub can
correlate a user, which the pairwise `sub` alone prevents: every app of a hub is the hub owner's.

## Named departures from the specifications

- No refresh tokens, no `offline_access`: apps keep their own sessions.
- No sessions at the broker: `prompt=none` returns `login_required`; there is no logout protocol.
- `response_type=code` only, so the "dynamic OP" profile of OIDC Core 15.2 is not met.
- Pairwise subjects use the app, not a `sector_identifier_uri`, as the sector, so previews on random
  hosts keep the same subjects.
- No loopback exception on redirect URIs: a local deployment registers its exact
  `http://127.0.0.1:<port>/...` URI.
- `client_secret_post` is the only client authentication: no `client_secret_basic`, which RFC 6749
  2.3.1 requires, and registration requires `client_secret_post` instead of defaulting to Basic (RFC
  7591 2).
- `/authorize` accepts GET only, not the POST that OIDC Core 3.1.2.1 requires.
- No UserInfo endpoint (OIDC Core 5.3) and no `userinfo_endpoint` in discovery (OIDC Discovery 3):
  the claims the scopes release are in the id_token, not delivered through UserInfo (OIDC Core 5.4).
- The token response's `access_token` (RFC 6749 5.1, OIDC Core 3.1.3.3) is an opaque random value
  that grants nothing: the broker has no protected resource.
- `prompt=login` and `max_age` answer `invalid_request` (OIDC Core 3.1.2.1), and no id_token carries
  `auth_time` (OIDC Core 2): the broker cannot attest when the user last authenticated upstream.
- Discovery is at `/.well-known/openid-configuration` (OIDC Discovery 4) only, not at
  `/.well-known/oauth-authorization-server` (RFC 8414 3).
- A replayed authorization code is refused, since its redemption deleted it, and revokes nothing
  (RFC 6749 4.1.2): the id_token cannot be recalled and the access token grants nothing.

## Keys

`IDENTITY_BROKER_KEYS` holds one current RS256 private key, the public halves of retired keys with
their retirement time, and the salt. The host parses it in each request and refuses a salt shorter
than 16 bytes or a key without its RSA members. The JWKS publishes each key under its entry's kid,
the kid the signer writes into a token header, with `alg` RS256 and `use` sig.

`keys --rotate` checks its output: a test id_token signed with the new current key must verify
against the JWKS the broker publishes, and each retired key there must be RSA of 2048 bits or more.
So a current key the signer refuses can still be rotated out, and a weak retired key is dropped with
`--no-overlap`.

The retired public key stays in the JWKS for ten minutes from `keys --rotate`: the five-minute
id_token lifetime, so a token the old key signed just before the hub read the new key set verifies
until it expires, plus the JWKS's five-minute max-age as the margin for verifier caches and clocks
and for setting the output on the hub, which should follow at once. After a key compromise,
`keys --rotate --no-overlap` drops the retired keys at once, so every token signed before stops
verifying; the salt is kept.
