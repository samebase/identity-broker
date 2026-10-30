# Design

The broker is a federated OpenID Provider in the shape of Dex: upstream connectors, no accounts.

## What is stored

Apps, clients (one per deployment: exact redirect URI, hashed secret), authorization requests for
ten minutes, authorization codes for sixty seconds and one use, an audit row per issued `id_token`
(app, client, connector, pairwise subject, time), and a row per email code sent (SHA-256 of the
canonical address, time) for one hour. Apart from those audit and send rows, nothing about a user
outlives the request that carried it. The audit rows keep the pairwise subject for 90 days.

The host schedules the component's `cleanup` daily from a cron, as the
[team-base](https://github.com/samebase/team-base) template does; nothing else deletes these rows.
One run drains: a batch deletes at most 200 rows per table, and a full batch schedules the next one
at once with the same cutoff, until no table fills a batch. The cutoff is the time the run began, so
the run ends: rows written during it run out after the cutoff. A completed request lives until one
minute after its authorization code expires, so cleanup never removes a request whose code can still
be redeemed.

Clients stay until `deleteClient` removes them, or their app is deleted. A host that sets
`previewClientIdleDays` also has cleanup delete a preview client with no sign-in for that many days.
It is off by default, because a deployment whose client was deleted does not register again by
itself.

## Registration

`registerClient` is an internal function: it needs the hub's deploy key, and it registers one
deployment of an app as a client. There is no public registration endpoint, and no token of its own:
in a team base, everyone who may register a client already holds the Convex credential of the team,
so a second credential would guard nothing. For the same reason an app has no list of allowed
callback hosts. The first client of an app id creates the app as a first-party app.

## Token endpoint

A client authenticates with the one method it registered, `client_secret_basic` or
`client_secret_post`. A request that carries an `Authorization` header and a non-empty
`client_secret` in the body answers `invalid_request`, even when both are right (RFC 6749 section
2.3); an empty parameter counts as omitted (section 3.2). The mutation that redeems the
authorization code also reads the client and its app and checks the secret and the method, so a
deletion of either commits wholly before a redemption or after it, a failed authentication leaves
the code redeemable, and a code redeems once.

## Issuer

The issuer is https, or http on a loopback host for local development. The supported configuration
is a dedicated hostname with the issuer at `/`, such as `https://auth.example.com`. There the
transaction cookies carry the `__Host-` prefix, so a subdomain or a narrower path cannot set them.
Another handler on the same hostname can, so the hostname serves the broker alone. An issuer under a
path, such as `https://example.com/identity`, uses plain cookies scoped to that path, and is not
verified in browsers.

## Browser binding

`/authorize` sets one transaction cookie per request, and every later step needs it: `/continue`,
the connector callback, and the email steps (RFC 9700 section 2.1.1). A first-party request skips
the chooser, not this binding. A link or a callback that reaches another browser gets an error page,
and the request keeps waiting for the browser that started it.

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

Every id_token and every UserInfo response also carry `connector`, the connector's name. Those of a
first-party app carry `connector_account_id` too: the connector's own id for the account, the GitHub
user id, the upstream OIDC `sub`, or the canonical address for the email connector. An app whose
users are keyed by provider and account id maps them by this pair. The pair is as stable as the
provider's id: a new address is a new email account, and an upstream OIDC provider with pairwise
subjects gives the hub other ids than it gave an app's own client.

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
- `connector_account_id` goes to first-party apps only, the same in each and with every scope. Those
  apps can correlate a user with each other and with the provider account, which pairwise subjects
  (OIDC Core 8.1) exist to prevent, and for the email connector it is the address, even without the
  `email` scope. A third-party app gets only the pairwise `sub`, the stable id its consent names.
- Clients inherit the trust of their app: a first-party app's deployments skip the chooser and
  consent, because every deployment of a first-party app registers at deploy time.
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
