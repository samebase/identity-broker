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

Register the deployment once, after it exists, with the hub's deploy key:

```sh
npx convex run identityBroker:registerClient "{\"appId\":\"bristol\",\"redirectUri\":\"$CONVEX_SITE_URL/oauth/hub/callback\",\"deploymentType\":\"preview\",\"clientName\":\"Bristol\",\"softwareVersion\":\"$DEPLOYMENT\",\"tokenEndpointAuthMethod\":\"client_secret_post\"}"
```

`client_secret_post` because Convex Auth's generic OAuth method posts the client credentials in the
body.

Store the returned `issuer`, `clientId`, and `clientSecret` on that deployment as `HUB_ISSUER`,
`HUB_CLIENT_ID`, and `HUB_CLIENT_SECRET` (`npx convex env set --deployment <name> ...`). When the
deployment goes away, `identityBroker:deleteClient '{"clientId":"..."}'` deletes its client.

In an Alchemy v2 stack, the `Convex.HubClient` resource of `@samebase/alchemy-convex` makes these
calls with a short-lived key of the base: it registers at deploy time and deletes on destroy. The
`env` of `Convex.Deployment` stores the client on the deployment. The `alchemy-convex hub-client`
command does the same for a development deployment.

The `connector` query parameter on `/authorize` (`connector=github`) skips the chooser for a
first-party app. Each app sees its own pairwise `sub`.

The id_token also carries `connector`, the connector's name, and for a first-party app
`connector_account_id`, the connector's own id for the account. For GitHub and Google that is the
provider's own user id or `sub`, the one an app saw when it signed users in to GitHub or Google
directly, so an app whose existing users are keyed by provider and account id maps them by this
pair. The pair is the same in every first-party app of the hub.

Each app owns admission and account linking by email. `connector=google` in the authorize URL
selects a connector for the chooser skip and does not enforce a Google-only policy; the app's
admission does.
