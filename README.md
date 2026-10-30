# identity-broker

An OpenID Provider that runs on [Convex](https://convex.dev). One deployment holds a team's sign-in
connections once, such as GitHub, Google and email codes, and signs users in to many small apps. The
broker keeps no user accounts and no sessions: every sign-in goes upstream again, and each app
creates its own user from the `id_token` it receives.

Why: every new app otherwise needs its own OAuth app registrations and its own email sender, and a
preview deployment with a fresh callback URL cannot have them at all. With the broker, an app
registers each deployment as a client at deploy time and never touches GitHub or Google.

## What it is

- `@samebase/identity-broker`: a Convex component plus the host-side endpoints. Authorization code
  flow with PKCE, discovery, JWKS, userinfo, and an internal function that registers a client. RS256
  `id_token`s with pairwise subjects per app; a first-party app also gets the connector's own id for
  the account in `connector_account_id`.
- Connectors are configuration: any OAuth 2.0 provider that publishes RFC 8414 metadata, any OpenID
  Connect provider, and an email code sent by your own action. `github()`, `google()` and `email()`
  are included.
- A hub is a small Convex app that mounts the component. Fork
  [samebase/team-base](https://github.com/samebase/team-base) for one.
- `Convex.HubClient` of [`@samebase/alchemy-convex`](https://github.com/samebase/alchemy-convex), an
  Alchemy v2 resource, registers a deployment as a client at deploy time.

## Mount it

```ts
// convex/convex.config.ts
import { defineApp } from "convex/server";
import identityBroker from "@samebase/identity-broker/convex.config";

const app = defineApp();
app.use(identityBroker);
export default app;
```

```ts
// convex/http.ts
import { httpRouter } from "convex/server";
import { defineIdentityBroker, email, github, google } from "@samebase/identity-broker";
import { components, internal } from "./_generated/api";

export const broker = defineIdentityBroker({
  component: components.identityBroker,
  issuer: process.env.ISSUER ?? process.env.CONVEX_SITE_URL!,
  keys: () => process.env.IDENTITY_BROKER_KEYS,
  connectors: [
    github({
      clientId: () => process.env.GITHUB_CLIENT_ID!,
      clientSecret: () => process.env.GITHUB_CLIENT_SECRET!,
    }),
    google({
      clientId: () => process.env.GOOGLE_CLIENT_ID!,
      clientSecret: () => process.env.GOOGLE_CLIENT_SECRET!,
    }),
    email({ send: internal.email.sendCode }),
  ],
});

const http = httpRouter();
broker.addHttpRoutes(http);
export default http;
```

```ts
// convex/identityBroker.ts: administration for `npx convex run`
import { broker } from "./http";
export const {
  createApp,
  registerClient,
  deleteClient,
  deleteApp,
  listApps,
  listClients,
  cleanup,
} = broker.admin();
```

Keys: `npx identity-broker keys` prints the value for `IDENTITY_BROKER_KEYS`; `keys --rotate`
advances it, and `keys --rotate --no-overlap` replaces a compromised key at once. Back up the key
set: its salt makes every `sub`. `parseKeySet` checks a value's shape before a deploy, and
`assertKeySetUsable` signs a test token with it and verifies that token against its JWKS.

## Register an app's deployments

Registration is an internal function of the hub, so it needs the hub's deploy key and no token of
its own:

```sh
npx convex run identityBroker:registerClient '{"appId":"bristol","redirectUri":"https://bristol.example/oauth/hub/callback","deploymentType":"production","clientName":"prod","softwareVersion":"1","tokenEndpointAuthMethod":"client_secret_post"}'
```

The reply holds the `issuer`, the `clientId`, and the `clientSecret`, which only this reply carries.
The first client of an `appId` creates the app as a first-party app. For an app that is not your
own, run `createApp` with `firstParty` false first. A Convex Auth v2 app points its generic OAuth
method at `<issuer>/authorize` and `<issuer>/token`; see the [docs](docs/consumers.md).

When a deployment goes away, `identityBroker:deleteClient` deletes its client. A client that is gone
is no error.

## Standards

OAuth 2.0 and the OAuth 2.1 draft (code flow, PKCE S256, exact redirect URIs, `iss` on responses),
OpenID Connect Core and Discovery, RFC 8414, RFC 9207, RFC 9700, and the JWT, JWS, JWK and cookie
standards under them. A client gets its credentials out of band, which RFC 6749 section 2 leaves
open. [docs/standards.md](docs/standards.md) lists each with its sections and status, and departures
are named in [docs/design.md](docs/design.md).

## License

Apache-2.0.
