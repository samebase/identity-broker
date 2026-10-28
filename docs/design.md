# Design

The broker is a federated OpenID Provider in the shape of Dex: upstream connectors, no accounts.

## What is stored

Apps, their registration tokens (hashed), clients (one per deployment: exact redirect URI, hashed
secret), authorization requests for ten minutes, authorization codes for sixty seconds and one use,
an audit row per issued `id_token` (app, client, connector, pairwise subject, time), and a row per
email code sent (SHA-256 of the canonical address, time) for one hour. Apart from those send rows,
nothing about a user outlives the request that carried it.

## Email send limits

A request sends at most 3 codes, at least 60 seconds apart, and an address receives at most 5 codes
per rolling hour across all requests. Wrong codes count across resends. A refused send answers 429
on the page the user is on, with one neutral line.

## Subjects

`sub` is pairwise per app (OIDC Core 8.1), computed as
`base64url(SHA-256(appId || connector || upstreamId || salt))`. The salt is created once with the
key set and never rotated: a new salt is a new identity for everyone.

## Named departures from the specifications

- No refresh tokens, no `offline_access`: apps keep their own sessions.
- No sessions at the broker: `prompt=none` returns `login_required`; there is no logout protocol.
- `response_type=code` only, so the "dynamic OP" profile of OIDC Core 15.2 is not met.
- `prompt=login` and `max_age` are forwarded to OIDC connectors and always satisfied by the email
  code; a plain OAuth connector such as GitHub cannot reauthenticate and answers `login_required`.
- Pairwise subjects use the app, not a `sector_identifier_uri`, as the sector, so previews on random
  hosts keep the same subjects.
- Dynamically registered clients inherit the trust of their app: a first-party app's deployments
  skip the chooser and consent, because every deployment of a first-party app registers dynamically.
- No loopback exception on redirect URIs: a local deployment registers its exact
  `http://127.0.0.1:<port>/...` URI.
- Email codes have no standard; the result is `email_verified: true`, no `amr`.

## Keys

`IDENTITY_BROKER_KEYS` holds one current RS256 private key, the public halves of retired keys with
their retirement time, and the salt. Retired keys stay in the JWKS for 14 days.
