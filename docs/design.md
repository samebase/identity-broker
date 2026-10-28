# Design

The broker is a federated OpenID Provider in the shape of Dex: upstream connectors, no accounts.

## What is stored

Apps, their registration tokens (hashed), clients (one per deployment: exact redirect URI, hashed
secret), authorization requests for ten minutes, authorization codes for sixty seconds and one use,
an audit row per issued `id_token` (app, client, connector, pairwise subject, time), and a row per
email code sent (SHA-256 of the canonical address, time) for one hour. Apart from those send rows,
nothing about a user outlives the request that carried it.

The host schedules the component's `cleanup` from a cron; nothing else deletes these rows. The
[identity-hub](https://github.com/samebase/identity-hub) template runs it daily. A completed request
lives until one minute after its authorization code expires, so cleanup never removes a request
whose code can still be redeemed.

## Email send limits

A request sends at most 3 codes, at least 60 seconds apart; an address receives at most 5 codes per
rolling hour across all requests; and the broker sends at most 200 codes per rolling hour in all.
Wrong codes count across resends, so a locked request sends no more codes. A refused send answers
429 on the page the user is on, with one neutral line.

## Subjects

`sub` is pairwise per app (OIDC Core 8.1), computed as
`base64url(SHA-256(appId || connector || upstreamId || salt))`. The salt is created once with the
key set and never rotated: a new salt is a new identity for everyone.

App ids and connector names are identity namespaces. Recreating an app (a new app id) or renaming a
connector changes every `sub` it produces. The salt lives only in `IDENTITY_BROKER_KEYS`, so back up
the key set: a lost salt cannot be recreated.

## Named departures from the specifications

- No refresh tokens, no `offline_access`: apps keep their own sessions.
- No sessions at the broker: `prompt=none` returns `login_required`; there is no logout protocol.
- `response_type=code` only, so the "dynamic OP" profile of OIDC Core 15.2 is not met.
- `prompt=login` and `max_age` are forwarded to OIDC connectors and always satisfied by the email
  code; a plain OAuth connector such as GitHub cannot reauthenticate and answers `login_required`.
  Other `prompt` values, such as `consent` and `select_account`, answer `invalid_request`.
- Pairwise subjects use the app, not a `sector_identifier_uri`, as the sector, so previews on random
  hosts keep the same subjects.
- Dynamically registered clients inherit the trust of their app: a first-party app's deployments
  skip the chooser and consent, because every deployment of a first-party app registers dynamically.
- No loopback exception on redirect URIs: a local deployment registers its exact
  `http://127.0.0.1:<port>/...` URI.
- Email codes have no standard; the result is `email_verified: true`, no `amr`.
- `auth_time` is the time the broker completed the sign-in, after the connector answered; it is not
  the upstream provider's authentication time. `max_age` is honored only by sending `prompt=login`
  upstream, never by comparing an upstream `auth_time`.
- A replayed authorization code revokes the code and its request, but nothing already issued: an
  access token for `/userinfo` keeps its five minutes.

## Keys

`IDENTITY_BROKER_KEYS` holds one current RS256 private key, the public halves of retired keys with
their retirement time, and the salt. `keys --rotate` keeps the retired public key in the JWKS for 14
days. After a key compromise, `keys --rotate --no-overlap` drops the retired keys at once, so every
token signed before stops verifying; the salt is kept.
