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
      authorizationEndpoint: `${HUB}/authorize`,
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
  -d "{\"redirect_uris\":[\"$CONVEX_SITE_URL/oauth/hub/callback\"],\"client_name\":\"Bristol\",\"software_version\":\"$DEPLOYMENT\",\"deployment_type\":\"preview\",\"token_endpoint_auth_method\":\"client_secret_post\"}"
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

The `connector` query parameter on `/authorize` (`connector=github`) skips the chooser for a
first-party app. Each app sees its own pairwise `sub`, and `profile` above passes `email` only when
`email_verified` is true.

Each app owns admission and account linking by that email. `connector=google` in the authorize URL
selects a connector for the chooser skip and does not enforce a Google-only policy; the app's
admission does.
