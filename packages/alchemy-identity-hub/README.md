# @samebase/alchemy-identity-hub

An [Alchemy](https://alchemy.run) v2 resource that registers one Convex deployment as an OAuth
client of an identity hub, an OpenID Provider built with
[`@samebase/identity-broker`](https://github.com/samebase/identity-broker). It replaces a register
script: the stack posts the deployment's callback URL to the hub and writes the client to the
deployment with `@samebase/alchemy-convex`, and destroying the stage deletes the client on the hub.

<!-- prettier-ignore -->
```ts
import * as IdentityHub from "@samebase/alchemy-identity-hub";
import * as Convex from "@samebase/alchemy-convex";

// In the stack's generator. Its providers: Layer.mergeAll(Convex.providers(), IdentityHub.providers())
const client = yield* IdentityHub.Client("HubClient", {
  issuer: "https://secret-chickadee-10.convex.site",
  registrationToken: yield* Config.Redacted("HUB_REGISTRATION_TOKEN"),
  redirectUri: Output.map(deployment.siteUrl, (url) => `${url}/oauth/hub/callback`),
  deploymentType: "preview",
  clientName: "Bristol preview",
  softwareVersion: deployment.name, // optional
});
yield* Convex.EnvironmentVariable("HubClientId", { deployment: deployment.name, deployKey: key.deployKey, name: "HUB_CLIENT_ID", value: client.clientId });
yield* Convex.EnvironmentVariable("HubClientSecret", { deployment: deployment.name, deployKey: key.deployKey, name: "HUB_CLIENT_SECRET", value: client.clientSecret });
```

The attributes are `issuer`, `redirectUri`, `deploymentType`, `clientName`, `clientId`, and
`clientSecret` (Redacted). `issuer` is normalized as the hub normalizes its own: origin plus path,
without a trailing slash, so `https://HUB.EXAMPLE:443/` is `https://hub.example`. It must be an
`https` URL, or `http` on `127.0.0.1` or `localhost`, without credentials, query, or fragment. The
registration token is never an attribute.

Alchemy state stores the props, the registration token included, and the attributes, the client
secret included. Redacted keeps the token and the secret out of logs; how the state is encrypted is
up to the state store. Peer dependencies: `alchemy` `2.0.0-beta.84` and `effect` `^4.0.5`.

## Lifecycle

The hub registers a client at `POST <issuer>/register` (RFC 7591) and deletes one at
`DELETE <issuer>/register/<client id>`, both with the app's registration token as a Bearer token. It
has no endpoint to read or change a client. Each request times out after 15 seconds and does not
follow redirects.

- First deploy: `POST <issuer>/register`. It asks for `client_secret_post`, because Convex Auth's
  generic OAuth method posts the client credentials in the body; the hub's default is
  `client_secret_basic`.
- A changed normalized `issuer`, `redirectUri`, or `deploymentType` replaces the resource: a new
  client is registered, and the replaced client is deleted on the hub.
- A changed `registrationToken` is stored in state with no hub call, so a later delete sends the
  newest token. A changed `clientName` or `softwareVersion` makes no hub call and keeps the
  attributes.
- Read returns the state as it is.
- Destroy sends `DELETE <issuer>/register/<client id>` with the token in state. A 204, or the hub's
  404 with the error `invalid_client` for a client that is already gone, ends the resource. A 401
  means that token is expired or wrong, and a retry with it cannot succeed: the resource ends, the
  client stays on the hub, and a warning names `identityBroker:deleteClient` to delete it there. A
  network error or any other answer fails with `DeletionFailed` and keeps the resource in state, so
  the next destroy tries again.
- A `redirectUri` that resolves only during the deploy registers in place: the new client at the new
  `issuer` with the new token, then a delete of the old client at the old `issuer` with the old
  token. The new client is kept whatever the delete answers; a failed delete is a warning that names
  `identityBroker:deleteClient`.
- Within one deploy, a registration is never retried, because each successful request creates a
  client.

## Limits

- Deleting needs `@samebase/identity-broker` 0.5.0 or later on the hub. An older hub has no delete
  route: its 404 has no `invalid_client` error, so destroy fails with `DeletionFailed` until the hub
  is upgraded.
- A stage whose token in state has expired leaves its client on the hub when destroyed. Deploy it
  once with a fresh token first: the deploy stores the token without a hub call.
- A deploy that fails after the hub created the client and before Alchemy saved the client to state
  leaves that client on the hub. The next deploy registers another client.
- Two separate `Convex.EnvironmentVariable` resources write the client id and the client secret. A
  failure between the two writes can leave a mismatched pair on the deployment until the next
  deploy.

## Errors

- `InvalidProps`: a prop failed a check before any request: `issuer` is not an allowed URL, or
  `issuer` or `registrationToken` contains a control character. The message names the prop, not its
  value.
- `RegistrationTokenRejected`: the hub answered 401, so the token is expired or wrong. Mint a new
  one on the hub with `npx convex run --prod identityBroker:mintRegistrationToken` (an
  `expiresInDays` argument sets its lifetime).
- `RegistrationRejected`: the hub answered 400 with an OAuth error, such as `invalid_redirect_uri`
  for a host the app does not allow (`identityBroker:setAllowedCallbackHosts` on the hub). The
  message is a fixed sentence for `invalid_redirect_uri`, `invalid_client_metadata`,
  `invalid_request`, and `invalid_token`, and says "unknown error code" for any other code. It never
  includes the hub's description.
- `RegistrationFailed`: the hub could not be reached within 15 seconds, redirected, or gave another
  answer. The message carries only the status, or the error name and code, such as `ECONNREFUSED`.
  Check `issuer`.
- `DeletionFailed`: a delete could not reach the hub within 15 seconds, was redirected, or got an
  answer other than 204, the hub's `invalid_client` 404, or 401. A 404 without that error reads "the
  hub has no delete route". The message carries only the status, or the error name and code. The
  resource stays in state, and the next deploy or destroy tries again.

No message or log line contains the token, the client secret, or any text from the hub's answer.

## License

Apache-2.0.
