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
        email: typeof claims.email === "string" ? claims.email : undefined,
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
  -d "{\"redirect_uris\":[\"$CONVEX_SITE_URL/oauth/hub/callback\"],\"client_name\":\"Bristol\",\"software_version\":\"$DEPLOYMENT\",\"deployment_type\":\"preview\"}"
```

Store the returned `client_id` and `client_secret` on that deployment as `HUB_CLIENT_ID` and
`HUB_CLIENT_SECRET` (`npx convex env set --deployment <name> ...`). Keep the registration token in
CI secrets next to the deploy key, never in a deployment's env.

The `connector` query parameter on `/authorize` (`connector=github`) skips the chooser for a
first-party app. Each app sees its own pairwise `sub`; the `email` claim is the app's to use or not.
