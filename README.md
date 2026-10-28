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
  flow with PKCE, discovery, JWKS, dynamic client registration (RFC 7591) gated by per-app tokens,
  userinfo. RS256 `id_token`s with pairwise subjects per app.
- Connectors are configuration: any OAuth 2.0 or OpenID Connect provider, and an email code sent by
  your own action. `github()`, `google()` and `email()` are included.
- A hub is a small Convex app that mounts the component. Fork
  [samebase/identity-hub](https://github.com/samebase/identity-hub) for one.
- `@samebase/alchemy-identity-hub`: an Alchemy v2 resource, `IdentityHub.Client`, that registers a
  deployment as a client at deploy time. See
  [packages/alchemy-identity-hub](https://github.com/samebase/identity-broker/tree/main/packages/alchemy-identity-hub).

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
  mintRegistrationToken,
  listRegistrationTokens,
  revokeRegistrationToken,
  setAllowedCallbackHosts,
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
`assertKeySetUsable` imports its keys.

## Register an app's deployments

```sh
npx convex run identityBroker:createApp '{"name":"Bristol","firstParty":true,"allowedCallbackHosts":["*.convex.site","127.0.0.1"]}'
npx convex run identityBroker:mintRegistrationToken '{"appId":"bristol-ab12c"}'
```

Each deployment then posts its callback URL to `/register` with that token as a Bearer token and
gets a `client_id` and `client_secret`. A Convex Auth v2 app points its generic OAuth method at
`<issuer>/authorize` and `<issuer>/token`; see the [docs](docs/consumers.md).

## Standards

OAuth 2.1 (code flow, PKCE S256, exact redirect URIs, `iss` on responses), OpenID Connect Core and
Discovery, RFC 7591, RFC 8414, RFC 9207, RFC 9700. Departures are named in
[docs/design.md](docs/design.md).

## License

Apache-2.0.
