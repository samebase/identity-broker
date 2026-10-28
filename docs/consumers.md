# Consuming the broker from a Convex Auth v2 app

The broker is a plain OpenID Provider, so Convex Auth v2's generic OAuth method is the whole
integration.

```ts
// convex/convex.config.ts
app.use(oauth, {
  name: "authHub",
  httpPrefix: "/oauth/hub",
  env: { CLIENT_ID: app.env.HUB_CLIENT_ID, CLIENT_SECRET: app.env.HUB_CLIENT_SECRET },
});
```

```ts
// convex/auth.ts
import { setupOauth } from "@convex-dev/auth/methods/oauth/server";

const HUB = "https://auth.example.com";

export const { startSignIn: startSignInWithHub, completeSignIn: completeSignInWithHub } =
  setupOauth(
    auth,
    "hub",
    {
      // The hub has no page to choose a connector: the authorize URL names one.
      authorizationEndpoint: `${HUB}/authorize?connector=google`,
      tokenEndpoint: `${HUB}/token`,
      issuer: HUB,
      scopes: ["openid", "email", "profile"],
      profile: (claims) => ({
        id: claims.sub,
        email:
          claims.email_verified === true && typeof claims.email === "string"
            ? claims.email
            : undefined,
        name: typeof claims.name === "string" ? claims.name : undefined,
      }),
    },
    { createUser: internal.users.createUser, onSignIn: internal.users.onSignIn },
    { component: components.authHub, allowedRedirectOrigins: [process.env.SITE_URL!] },
  );
```

Register the deployment once, after it exists, with the app's registration token:

```sh
curl -sS -X POST "$HUB/register" \
  -H "Authorization: Bearer $HUB_REGISTRATION_TOKEN" -H "Content-Type: application/json" \
  -d "{\"redirect_uris\":[\"$CONVEX_SITE_URL/oauth/hub/callback\"],\"token_endpoint_auth_method\":\"client_secret_post\"}"
```

`client_secret_post` because Convex Auth's generic OAuth method posts the client credentials in the
body; without it the client gets the RFC 7591 default, `client_secret_basic`.

Store the returned `client_id` and `client_secret` on that deployment as `HUB_CLIENT_ID` and
`HUB_CLIENT_SECRET` (`npx convex env set --deployment <name> ...`). Keep the registration token in
CI secrets next to the deploy key, never in a deployment's env.

When the deployment goes away, delete its client with a token of the same app (204, or 404 for a
client that is already gone):

```sh
curl -sS -X DELETE "$HUB/register/$HUB_CLIENT_ID" -H "Authorization: Bearer $HUB_REGISTRATION_TOKEN"
```

In an Alchemy v2 stack, the `IdentityHub.Client` resource of `@samebase/alchemy-identity-hub` makes
these requests: it registers at deploy time and deletes on destroy. `Convex.EnvironmentVariable`
stores the client on the deployment.

## The connector and the claims

The `connector` query parameter on `/authorize` names the connector, such as `connector=github`. A
missing or unknown name comes back to the redirect URI as `invalid_request`.

- `sub` is pairwise: each app sees its own.
- `connector` and `connector_account_id` are the connector's name and its own id for the account:
  the GitHub user id, or Google's `sub`. An app whose existing users are keyed by provider and
  account id maps them by this pair. The pair is the same in every app of the hub.
- `email` and `email_verified` come with the `email` scope, `name` and `picture` with `profile`.

Each app owns admission and account linking by email. A user can edit the authorize URL, so
`connector=google` does not enforce a Google-only policy: an app that admits one provider checks the
`connector` claim.
