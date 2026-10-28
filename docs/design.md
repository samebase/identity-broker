# Design

The broker is a federated OpenID Provider in the shape of Dex: upstream connectors, no accounts.

## What is stored

Apps, their registration tokens (hashed), clients (one per deployment: exact redirect URI, hashed
secret), authorization requests for ten minutes, authorization codes for sixty seconds and one use,
an audit row per issued `id_token` (app, client, connector, pairwise subject, time), and a row per
email code sent (SHA-256 of the canonical address, time) for one hour. Apart from those send rows,
nothing about a user outlives the request that carried it.

The host schedules the component's `cleanup` daily from a cron, as the
[identity-hub](https://github.com/samebase/identity-hub) template does; nothing else deletes these
rows. One run drains: a batch deletes at most 200 rows per table, and a full batch schedules the
next one at once with the same cutoff, until no table fills a batch. The cutoff is the time the run
began, so the run ends: rows written during it run out after the cutoff. A completed request lives
until one minute after its authorization code expires, so cleanup never removes a request whose code
can still be redeemed.

Clients stay until `DELETE /register/<client_id>` or `deleteClient` removes them, or their app is
deleted. A host that sets `previewClientIdleDays` also has cleanup delete a preview client with no
sign-in for that many days. It is off by default, because a deployment whose client was deleted does
not register again by itself. A deployment that deletes its own client when it goes away, as
`IdentityHub.Client` of `@samebase/alchemy-identity-hub` does on destroy since 0.3.0, leaves no idle
client behind, so pruning has no reason to run for it.

## Registration

`POST /register` (RFC 7591) registers one deployment of an app as a client, with the app's
registration token as a Bearer token. `DELETE /register/<client_id>` with a token of the same app
deletes that client, of any deployment type, and answers 204. A missing, unknown or expired token
answers 401. A client that is gone and a client of another app both answer 404, not 403, so a token
learns nothing about another app's clients. The delete has the shape of RFC 7592's, which the broker
does not implement: no registration access token per client, and a missing client answers 404 rather
than 401.

`deleteApp` deletes an app's registration tokens and clients in batches of 200 per table, each
scheduling the next at once, and the app row after the last batch. An app with up to 200 clients
loses them all in the first transaction.

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
- `max_age` is honored only as a fresh login: `prompt=login` or any `max_age` sends `prompt=login`
  and `max_age=0` to an OIDC connector whose provider documents `prompt=login`, and the email code
  always satisfies it. `max_age` obliges the provider to return `auth_time` (OIDC Core 3.1.2.1), and
  a provider can still reuse its session, so the OIDC sign-in completes only when that `auth_time`
  falls between the second the request was created and now, each widened by 60 seconds of clock
  skew; a missing, older, or later `auth_time` answers `login_required`. A connector that cannot
  reauthenticate answers `login_required` before anything goes upstream: a plain OAuth connector
  such as GitHub, which has no `auth_time` to check, and Google, which documents no `login` value
  for `prompt`. A freshness request against these is refused rather than pretended. Other `prompt`
  values, such as `consent` and `select_account`, answer `invalid_request`.
- Pairwise subjects use the app, not a `sector_identifier_uri`, as the sector, so previews on random
  hosts keep the same subjects.
- Dynamically registered clients inherit the trust of their app: a first-party app's deployments
  skip the chooser and consent, because every deployment of a first-party app registers dynamically.
- No loopback exception on redirect URIs: a local deployment registers its exact
  `http://127.0.0.1:<port>/...` URI.
- Email codes have no standard; the result is `email_verified: true`, no `amr`.
- `auth_time` is the hub's completion time: when the broker completed the sign-in, after the
  connector answered. After a fresh login through an OIDC connector it is the provider's `auth_time`
  instead, which the broker checked against the request's lifetime. The broker never compares an
  upstream `auth_time` with the value of `max_age`.
- A replayed authorization code revokes the code and its request, but nothing already issued: an
  access token for `/userinfo` keeps its five minutes.

## Keys

`IDENTITY_BROKER_KEYS` holds one current RS256 private key, the public halves of retired keys with
their retirement time, and the salt. The host parses it in each request and refuses a salt shorter
than 16 bytes or a key without its RSA members. The JWKS publishes each key under its entry's kid,
the kid the signer writes into a token header. `keys --rotate` only parses its input, so a current
key the signer refuses, such as RSA under the 2048 bits RS256 needs, can still be rotated out. It
checks its output instead: a test id_token signed with the new current key must verify against the
JWKS the broker publishes, and each retired key there must be RSA of 2048 bits or more; a weak key
carried over as retired is dropped with `--no-overlap`. `keys --rotate` keeps the retired public key
in the JWKS for 14 days. After a key compromise, `keys --rotate --no-overlap` drops the retired keys
at once, so every token signed before stops verifying; the salt is kept.
