# Design

The broker is a federated OpenID Provider in the shape of Dex: upstream connectors, no accounts.

## What is stored

Apps (an app id and its allowed callback hosts), their registration tokens (hashed), clients (one
per deployment: exact redirect URI, hashed secret, token endpoint authentication method), and
authorization requests. A request lives ten minutes from `/authorize`; once the connector attests
the user, it holds the hash of its authorization code and lives the sixty seconds of the code, and
redeeming the code deletes it. Nothing about a user outlives the request that carried it.

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

`deleteApp` deletes the app, its registration tokens and its clients in one transaction. An app with
many clients can exceed what one Convex transaction may write; previews unregister themselves on
destroy, so an app keeps a handful, one per live deployment. A registration that read its token
before the deletion cannot create its client after it, so no client outlives its app. The token
endpoint reads the client and its app in the same transaction that redeems the code, so a deletion
lands wholly before a redemption or after it.

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
- No UserInfo endpoint (OIDC Core 5.3) and no `userinfo_endpoint` in discovery (OIDC Discovery 3):
  the claims the scopes release are in the id_token, not delivered through UserInfo (OIDC Core 5.4).
- The token response's `access_token` (RFC 6749 5.1, OIDC Core 3.1.3.3) is an opaque random value
  that grants nothing: the broker has no protected resource.
- `prompt=login` and `max_age` answer `invalid_request` (OIDC Core 3.1.2.1), and no id_token carries
  `auth_time` (OIDC Core 2): the broker cannot attest when the user last authenticated upstream.
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
`keys --rotate --no-overlap` drops the retired keys from the JWKS at once; the salt is kept. A
verifier that fetched the JWKS before still accepts the tokens they signed until its copy expires,
at most the five-minute max-age later.

## Moving a hub from 0.5.0 to 0.6.0

A push validates every existing document of a table the schema lists, and fails on a field the
schema no longer declares. Rows that 0.5.0 wrote in `apps`, `registrationTokens`, `clients` and
`authRequests` carry such fields, and 0.5.0's schema requires most of them, so no mutation of 0.5.0
can strip them, and 0.5.0 has no command that would. The move therefore takes the rows out through a
backup and brings them back without the removed fields.

The app ids, client ids, client secret hashes, registration token hashes, the salt and the connector
names are what the subjects and the credentials depend on. All of them come back unchanged: the rows
from the backup, the salt from `IDENTITY_BROKER_KEYS`, which the move leaves alone, and the
connector names from the hub's code, which keeps them. So every `sub` stays the same, and no
deployment registers again. Sign-ins and registrations fail between the empty import and the
restore; pause the stacks that register clients until then.

1. Take a complete backup and keep it:

   ```sh
   npx convex export --prod --path hub-0.5.0.zip
   unzip -l hub-0.5.0.zip | grep identityBroker
   ```

   The listing shows the component's tables as `<dir>/<table>/documents.jsonl`. If it shows none,
   stop: the backup does not hold the component.

2. Project the three durable tables to the 0.6.0 fields. An expired token is left out, because 0.6.0
   tokens do not expire:

   ```sh
   dir=<the directory the listing shows>
   table() { unzip -p hub-0.5.0.zip "$dir/$1/documents.jsonl"; }
   table apps | jq -c '{appId, allowedCallbackHosts}' > apps.jsonl
   table registrationTokens | jq -c --argjson now "$(date +%s)000" \
     'select(.expiresAt > $now) | {tokenHash, appId, createdAt}' > registrationTokens.jsonl
   table clients | jq -c '{clientId, appId, secretHash, tokenEndpointAuthMethod, redirectUri}' \
     > clients.jsonl
   ```

3. With 0.5.0 still deployed, empty the four changing tables by importing an empty array:

   ```sh
   echo '[]' > empty.json
   for t in apps registrationTokens clients authRequests; do
     npx convex import --prod --component identityBroker --table "$t" --replace empty.json
   done
   ```

4. Push 0.6.0, with the hub's `email()` connector and `previewClientIdleDays` removed.
5. Import the projected rows:

   ```sh
   for t in apps registrationTokens clients; do
     npx convex import --prod --component identityBroker --table "$t" --replace "$t.jsonl"
   done
   ```

6. Verify the counts. Each import reports the documents it wrote; it must equal `wc -l < $t.jsonl`.
   Each file must have as many lines as `table $t | wc -l` in the backup, less the expired tokens.
7. Delete the tables 0.6.0 no longer names, `authorizationCodes`, `signIns` and `emailSends`, in the
   dashboard (the component dropdown, then Delete table). The push keeps them: Convex's schema docs
   say a schema validates only the tables it lists, and documents in other tables stay. They hold
   code hashes, pairwise subjects and email address hashes.
8. Resume the stacks. Consumers must now send the connector: `connector=<name>` on the authorize
   URL.
