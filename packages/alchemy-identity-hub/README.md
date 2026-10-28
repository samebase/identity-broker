# @samebase/alchemy-identity-hub

An [Alchemy](https://alchemy.run) v2 resource that registers one Convex deployment as an OAuth
client of an identity hub, an OpenID Provider built with
[`@samebase/identity-broker`](https://github.com/samebase/identity-broker). It replaces a register
script: the stack posts the deployment's callback URL to the hub and writes the client to the
deployment with `@samebase/alchemy-convex`.

<!-- prettier-ignore -->
```ts
import * as IdentityHub from "@samebase/alchemy-identity-hub";
import * as Convex from "@samebase/alchemy-convex";

// In the stack's generator. Its providers: Layer.mergeAll(Convex.providers(), IdentityHub.providers())
const client = yield* IdentityHub.Client("HubClient", {
  issuer: "https://secret-chickadee-10.convex.site",
  registrationToken: yield* Config.redacted("HUB_REGISTRATION_TOKEN"),
  redirectUri: Output.map(deployment.siteUrl, (url) => `${url}/oauth/hub/callback`),
  deploymentType: "preview",
  clientName: "Bristol preview",
  softwareVersion: deployment.name, // optional
});
yield* Convex.EnvironmentVariable("HubClientId", { deployment: deployment.name, deployKey: key.deployKey, name: "HUB_CLIENT_ID", value: client.clientId });
yield* Convex.EnvironmentVariable("HubClientSecret", { deployment: deployment.name, deployKey: key.deployKey, name: "HUB_CLIENT_SECRET", value: client.clientSecret });
```

The attributes are `issuer` (without a trailing slash), `redirectUri`, `deploymentType`,
`clientName`, `clientId`, and `clientSecret` (Redacted). The registration token is never an
attribute. Peer dependencies: `alchemy` `2.0.0-beta.80` and `effect` `^4.0.0`.

## Lifecycle

The hub implements RFC 7591 registration only. It has no endpoint to read, change, or delete a
client.

- First deploy: `POST <issuer>/register` with the token as a Bearer token.
- A changed `issuer`, `redirectUri`, or `deploymentType` replaces the resource: a new client is
  registered. The old client stays on the hub, which removes a preview client after 30 days without
  a sign-in and keeps a production or development client until the app is deleted there.
- A changed `clientName`, `softwareVersion`, or `registrationToken` makes no hub call and keeps the
  attributes. The token is used only to register.
- Read returns the state as it is. Destroy makes no hub call and logs that the client stays.
- A registration is never retried, because each successful request creates a client.

## Errors

- `RegistrationTokenRejected`: the hub answered 401, so the token is expired or wrong. Mint a new
  one on the hub with `npx convex run --prod identityBroker:mintRegistrationToken` (an
  `expiresInDays` argument sets its lifetime).
- `RegistrationRejected`: the hub answered 400 with an OAuth error, such as `invalid_redirect_uri`
  for a host the app does not allow (`identityBroker:setAllowedCallbackHosts` on the hub).
- `RegistrationFailed`: the hub could not be reached or gave another answer. Check `issuer`.

No message or log line contains the token, the client secret, or the body of a 401 answer.

## License

Apache-2.0.
