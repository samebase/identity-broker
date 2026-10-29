# Identity hub consumers: one small surface

Research proposal, 2026-10-29, revised the same day on `origin/main` of identity-broker. Read-only:
no repository changed. No command ran against a Convex deployment or the hub.

## Packaging decision (operator, 2026-10-29)

One package, not three. Everything hub-related lives in `@samebase/identity-broker` as entry points by runtime: `.` and `./convex.config` (the component, as now), `./alchemy` (the stack resource, folded in from `@samebase/alchemy-identity-hub`, which is then retired), `./consumer` (the Convex Auth method, validator and profile of section 2.3), `./react` (the Google mark), and `./dev` (the development registration of section 2.2 D). `alchemy`, `effect`, `@convex-dev/auth` and `react` are optional peer dependencies, each needed only by its entry point; a Convex bundle imports none of the stack or React entries. Convex Auth already depends on `jose`, so the broker's runtime dependencies add only `oauth4webapi` to an app. Read "new package" in sections 2.3, 4 and 5 as "entry point of `@samebase/identity-broker`", and open question 4 as decided. The proposal itself stays on hold (see the operator's note of the same evening): no package work starts before the team base design or a fourth app.

## On hold: the team base changes the registration itself (operator, 2026-10-29)

A hub client is recorded twice today: the hub keeps it, and the Alchemy state keeps a copy with the secret, in the team's `alchemy-state` project. The registration token exists only because those two live in different deployments, so the hub needs its own proof that a deployment belongs to the team. The team base idea (one Convex deployment per team that holds the hub, the Alchemy state and, later, the other team-level pieces) puts them in one deployment. The stack then registers a client with the Convex credential it already holds, the hub reads the client from the same database, and the registration token, the repository secret, the token in the env file and the development registration all disappear. The developer's own deployment registers with the Convex login the CLI already has.

That removes more than this proposal does, and it removes the part of this proposal that a token-based development command would polish. What survives either way: the shared Convex Auth method with one validator (section 2.3), and the stack helper that turns a client into the three deployment variables (section 2.2 B). Decision: no package work starts; the team base design comes first (its first step is the hub and the state store in one deployment), or a fourth app, whichever comes first.

## 0. What I read

- identity-broker (https://github.com/samebase/identity-broker) `origin/main` at `b8758ef` (PR 15).
  `@samebase/identity-broker` 0.6.1 and `@samebase/alchemy-identity-hub` 0.3.0, both on npm. The
  live hub has the chooser, first-party apps, registration tokens that expire, sign-in records, and
  it requires the client metadata `client_name` and `deployment_type`
  (`packages/identity-broker/src/client/protocol.ts:126-143`).
- identity-hub (https://github.com/samebase/identity-hub) `main` at `ed69617`, on broker 0.6.1.
- Bristol (https://github.com/nicu-chiciuc/bristol_tsx) `main` at `9b3d2be`.
- Samebase (https://github.com/samebase/samebase) `origin/main` at `8c4b9db37`.
- Scout (https://github.com/samebase/scout) `main` at `eb76fdb` (v338, PR 251 merged). The hub files
  on `main` are the same as on the PR branch, so the line numbers below are those of `main`.
- `@samebase/convex-auth-tanstack-start` 0.1.1 (convex-hosting `origin/main`), the type declarations
  of Convex Auth 2.0.0-beta.0 (`methods/oauth/server`, `methods/google/server`), and
  `@samebase/alchemy-convex` 0.11.0.

The hub does not change in this proposal.

## 1. Inventory

### 1.1 Pieces that two or more consumers repeat

Line ranges are inclusive. Counts include the comments of each piece.

| Piece | Bristol | Samebase (`origin/main`) | Scout (`main`) |
| --- | --- | --- | --- |
| Development registration script | `scripts/register-hub-client.ts` 179 + test 177 | `apps/samebase/scripts/register-hub-client.ts` 126 + test 145 | `apps/scout/scripts/register-hub-client.ts` 101, no test |
| Call of that script | `package.json:10` (`deploy:dev` build) | `scripts/predev.ts:124-126` | `scripts/run-primary-dev.ts:8, 13`, `package.json:20` |
| Stack: read issuer and token | `alchemy.run.ts:79-81` | `alchemy.run.ts:69-73` | `alchemy.run.ts:39-44` |
| Stack: client metadata | `clientName` `Bristol ${profile}` (`:82`), `deploymentType` and `softwareVersion` (deployment name) at `:117-118, 156-157` | `clientName: stage`, `softwareVersion: commit` (`:74-75`), `deploymentType` at `:99, 146` | `clientName: stage`, `softwareVersion: commit` (`:45-46`), `deploymentType` at `:101, 132` |
| Stack: callback path constant | `alchemy.run.ts:49-50` (`/oauth/hub/callback`) | `alchemy.run.ts:46-47` (`/auth/hub/callback`) | `alchemy.run.ts:23-24` (`/auth/hub/callback`) |
| Stack: production client and its 3 env lines | `alchemy.run.ts:114-119, 123-127` (11) | `alchemy.run.ts:142-147, 159-161` (9) | `alchemy.run.ts:95-102, 109-111` (11) |
| Stack: preview pattern ("Preview", client, "Site" with adopt) | `alchemy.run.ts:137-169` (33, same 8-line comment) | `alchemy.run.ts:85-116` (32, same comment) | `alchemy.run.ts:118-146` (29, same comment) |
| Workflow: `HUB_ISSUER` variable and `HUB_REGISTRATION_TOKEN` secret on each Alchemy step | `alchemy.yml:6-8, 78-79, 104-107, 114-115` (11) | `alchemy.yml:12-14, 142-143, 174-175, 237-238` (9) | `alchemy.yml:77-78, 119-120` (4) |
| Workflow: shell check of both values | none | `alchemy.yml:112-128, 213-229` (34) | `alchemy.yml:39-55, 88-104` (34) |
| `convex.config.ts`: 3 env lines and the `oauth` mount `authHub` | `convex/convex.config.ts:20-22, 37-48` (15) | `apps/samebase/convex/convex.config.ts:27-29, 48-61` (17) | `apps/scout/convex/convex.config.ts:25-27, 60-71` (15) |
| `auth.ts`: `setupOauth` with endpoints, scopes, type-cycle annotation | `convex/auth.ts:26-82` (57) | `apps/samebase/convex/auth.ts:36-70` (35) | `apps/scout/convex/auth.ts:489-513` (25) |
| Claims validator and profile reader | inline, `convex/auth.ts:42-56`, `@ts-expect-error`, no validator, no connector check | `convex/identity/signIn.ts:22-61` (40) + test `signIn.convex.test.ts:465-479` (15) | `convex/auth.ts:401-438` (38) + tests |
| Callback argument validator | `convex/hubAccounts.ts:6-12` (7) | `convex/identity/signIn.ts:63-74` (12) | `convex/auth.ts:439-447` (9) |
| Link rule (`createUser`, `onSignIn`) | `convex/hubAccounts.ts:31-79` (49), owner only | `convex/identity/signIn.ts:98-116, 214-320` (~125) | `convex/auth.ts:449-487` (39) |
| Server allowlist (`signIn` of `setupConvexAuthServer`) | `src/server.ts:33` (1) | `apps/samebase/src/server.ts:45-46` (2) | `apps/scout/src/server.ts:29` (1) |
| Hook, button, flow error text | `src/routes/signin.tsx:61-84, 111-136` (~50) | `src/authClient.ts:51-79` (29), `src/SignInWithOAuth.tsx` (77) | `src/components/auth-panel.tsx` (~55 lines for the hub) |
| Google mark | `src/components/GoogleMark.tsx` (23) | none (no icon on the Google button) | `src/components/google-mark.tsx` (23, same paths) |
| No-hub values | `scripts/lib/anonymous-convex-local.ts:167-181` (15) | `scripts/lib/convexAuthKeys.ts:36-46` (11), used at `ci-bootstrap-convex.ts:85`, `convex-seed-dev-auth.ts:174` | none |
| Docs | `README.md:26-34`, `docs/deployment.md` (~50 lines) | `README.md:206-220, 252-257, 261-286` (~47) | `docs/deploy.md` (16 lines), `docs/local-setup.md` (17 lines) |

The three development scripts do the same steps in the same order: read the stored
`HUB_ISSUER`, `HUB_CLIENT_ID` and `HUB_CLIENT_SECRET` one at a time; keep a complete client of the
same issuer; read `CONVEX_SITE_URL` with `convex run --inline-query`; post to `<issuer>/register`
with `client_secret_post` and the metadata that the hub requires; write the three variables with one
`convex env set --force` on standard input. The metadata differs only in the name: Bristol sends
`client_name` "Bristol development", Samebase and Scout send "development". All three send
`deployment_type` "development" and the site's host as `software_version`.

### 1.2 What differs, and why

- Connectors. Samebase has GitHub and Google: two `setupOauth` calls share one component
  (`auth.ts:43-70`), with method names `hub-github` and `hub-google`. Bristol and Scout have Google
  only, with the method name `hub`.
- Callback prefix. Bristol uses `/oauth/hub` (`convex.config.ts:43`), as the broker docs example
  does (`docs/consumers.md:10`). Samebase and Scout use `/auth/hub`.
- First-party chooser skip. All three apps are first-party apps of the hub, and their authorize URL
  names the connector, so the hub sends the browser straight to the connector (Bristol
  `auth.ts:28-31`, `signin.tsx:119-120`; Scout `auth.ts:490-491`; Samebase `README.md:262-266`).
  The hub sends `connector_account_id` only to a first-party app, and Samebase needs it to find its
  users from before the hub. This stays.
- Link rule. Bristol admits one owner address and joins the owner's older password user
  (`hubAccounts.ts:14-79`). Samebase finds the user by connector and `connector_account_id` first,
  then by verified email, and checks the GitHub App identity (`identity/signIn.ts:214-320`). Scout
  links by verified email, else creates an approved user, and grants credits (`auth.ts:449-487`).
  This is the app's data model and admission policy.
- Verified email. All three require it, in three places: Bristol in `onSignIn`
  (`hubAccounts.ts:74`), Samebase in `readHubIdentity` (`identity/signIn.ts:104-108`), Scout in the
  profile (`auth.ts:425-429`).
- Claims check. Samebase and Scout validate the claims and the `connector` claim. Bristol does not
  check `connector`. The broker guide says that `connector=google` does not enforce a Google-only
  policy and that the app's admission does (`docs/consumers.md:79-81`).
- Client metadata. Bristol names its clients "Bristol production" and "Bristol preview" and records
  the deployment name. Samebase and Scout name them by the stage and record the commit. The hub
  shows the app's name on its pages, not the client name (`client/index.ts:382-393`), so the client
  name is only for the operator's `listClients`.
- Linked worktrees. Samebase and Bristol run a local backend in a linked worktree and write no-hub
  values. The reason: no registration token reaches an agent worktree. Both worktree setups write a
  fresh `.env.local`. Scout worktrees use their own cloud development deployment, and each one
  registers a client.
- Token on a laptop. Bristol keeps it in the shell only (`docs/deployment.md:161`). Samebase and
  Scout keep it in the app's `.env.local`.
- Redirect origins. Bristol adds the Vite ports on its development profile (`auth.ts:68-78`).
  Samebase and Scout use `SITE_URL` and `CONVEX_SITE_URL`. This is the app's list of its own sites.
- Production site. Bristol and Samebase register on a custom domain. Scout registers on its
  `.convex.site` URL (`alchemy.run.ts:22`). Bristol also checks the production deployment name and
  hangs that check on its `softwareVersion` prop (`alchemy.run.ts:103-119`).
- Workflow checks. Samebase and Scout check both hub values in a shell step on deploy and destroy.
  The stack already reads both values before any resource (`Config.NonEmptyString`), so the step
  repeats that check with a longer message.

### 1.3 Defects found during the read

1. Version drift. Bristol uses `alchemy-identity-hub` 0.2.1 (`package.json:67`). Its destroy makes
   no hub call, so each closed pull request leaves a client on the hub. Samebase and Scout use
   0.3.0, which deletes the client.
2. Production client not retained. Scout retains it (`alchemy.run.ts:98-102`). Samebase
   (`alchemy.run.ts:143-147`) and Bristol (`alchemy.run.ts:114-119`) do not. There,
   `alchemy destroy --stage prod` deletes the client that production signs in with, and the
   deployment stays.
3. Stale package docs. On `main`, `packages/alchemy-identity-hub/README.md:23-24` writes the client
   with `Convex.EnvironmentVariable`, `README.md:75-77` lists a limit of those two resources, and
   `docs/consumers.md:67-68` says that `Convex.EnvironmentVariable` stores the client.
   `@samebase/alchemy-convex` 0.11.0 has no such resource. All consumers use the `env` of
   `Convex.Deployment`.
4. Bristol `alchemy.yml:106-107` says the hub client is "forgotten, not deleted". This is true only
   on 0.2.1.

## 2. Proposal

### 2.1 Fixed conventions

These are decisions, not options. The packages below depend on them.

- Callback prefix `/auth/hub`, so the callback is `<site>/auth/hub/callback`. Two of three
  consumers use it. The session package puts provider prefixes under `/auth`, next to the core
  (`convex-auth-tanstack-start/README.md:187-189`).
- The deployment variables are `HUB_ISSUER`, `HUB_CLIENT_ID` and `HUB_CLIENT_SECRET`, and one write
  sets all three. The issuer stays on the deployment next to its client, so a client of one hub
  never meets the endpoints of another hub.
- The app is a first-party app of the hub, and its authorize URL names the connector.
- The Convex Auth method name is `hub-<connector>`, such as `hub-google`. Samebase uses this now
  (`auth.ts:48`).
- A hub sign-in requires a verified email. All three consumers require it now.
- The registration token is a credential of the stack, as `CONVEX_ACCESS_TOKEN` is. It is not a
  prop of a client.
- The client metadata comes from the stack, not from the app's code (2.2 B).
- The issuer is a constant in the app's code, not a repository variable (open question 1).

### 2.2 `@samebase/alchemy-identity-hub` 0.4.0, cut from `main`

This package already holds the registration request, its errors and its token checks
(`src/index.ts:52-290` on `main`). Release 0.4.0 gets four changes.

A. The token moves into the provider layer.

```ts
// IdentityHub.providers() reads HUB_REGISTRATION_TOKEN with Config.redacted, non-empty,
// as Convex.providers() reads CONVEX_ACCESS_TOKEN. Its error names the repository secret.
providers: Layer.mergeAll(Convex.providers(), IdentityHub.providers()),
```

Reason: one stack is one app, and every client of the app uses the same token. Now the token is a
prop, so Alchemy state stores it. `diff` has an `update` action only to store a new token
(`index.ts:300-303`), and the deletes send the token from state (`index.ts:323-327, 339`). Tokens
expire (30 days unless `expiresInDays` says otherwise, identity-hub `README.md:68-69`), so the
package README tells the operator to deploy a stage once with a fresh token before a destroy
(`README.md:49-51, 71-72`). With the token in the provider, every request sends the current secret.
This deletes the `registrationToken` prop, the `update` path, the token compare, that README limit,
and the two workflow check steps in Samebase and Scout.

B. `Client` takes the issuer and the site URL. The package fills the client metadata.

```ts
/**
`IdentityHub.Client(id, props)`, a function over the resource, as `Convex.Deployment` of
@samebase/alchemy-convex is. Pipe a removal policy on it as on the resource.
*/
export const Client: (
  id: string,
  props: {
    /** The hub's issuer. */
    readonly issuer: string;
    /** The deployment's site, such as `https://samebase.com` or a preview's `.convex.site` URL. */
    readonly siteUrl: Input<string>;
  },
) => Effect.Effect<Client, never, Providers | Alchemy.Stack>;
```

The function fills the resource props that the hub needs, and the app passes none of them:

- `redirectUri`: `${siteUrl}/auth/hub/callback`.
- `clientName`: the stage, from `Alchemy.Stack`, such as `prod` or `pr-123`. Samebase and Scout use
  this now. The hub shows the app's name to users, so the client name is for `listClients` only.
- `deploymentType`: `production` for the stage `prod`, `preview` for every other stage. Reason: the
  deploy standard has exactly these two kinds of stage (`docs/alchemy-deploy-standard.md:23-25`), and
  the production client registers before its deployment exists, because the deployment's `env`
  needs the client. So there is no Convex deployment type to read at that time. A development
  deployment never goes through a stack (C below).
- `softwareVersion`: the commit, from `git rev-parse HEAD` in the stack's directory, read once for
  each run. Reason: every stack of the team already needs git (its name comes from the origin
  remote, deploy standard rule 3), so this adds no input. A prop with a default would be an
  optional prop that two of three apps fill with the same value. If git fails, the function fails
  with a clear error.

The resource itself does not change its props or its state shape: `registeredFor` still compares
the issuer, the redirect URI and the deployment type (`index.ts:187-190`), and a changed client name
or commit makes no hub call. A client of Samebase or Scout in state today has the same three values,
so the first deploy on 0.4.0 makes no request.

```ts
/** The deployment variables of a client, for the `env` of `Convex.Deployment`. */
export const convexEnv = (client: Client) => ({
  HUB_ISSUER: client.issuer,
  HUB_CLIENT_ID: client.clientId,
  HUB_CLIENT_SECRET: client.clientSecret,
});
```

This deletes from each stack the hub object with its four values, the callback path constant, the
`Output.map` of the redirect URI, the `deploymentType` line of each call, and the three env lines at
each call site. The preview pattern stays in the app: a helper that also creates the deployments
must pass through every `Convex.Deployment` prop (`project`, `type`, `name`, `rootDir`, `env`,
`source`, adoption, removal policy), and production is different in each app (custom domain, name
check, retention). `docs/consumers.md` explains the pattern once, and each stack keeps a one-line
comment.

C. A destroy that the hub answers 401 fails.

Today `unregister` warns on a 401 and the resource ends (`index.ts:274-279`): the token in state can
be an old one, and a retry with it cannot succeed. With the token in the provider, the request sends
the newest token, so a 401 means that the secret itself is expired or wrong. The destroy then fails
with `DeletionFailed`, the resource stays in state, and the message says: mint a new token, set
`HUB_REGISTRATION_TOKEN`, and run the destroy again. The replace path in `reconcile`
(`index.ts:322-328`) keeps its warning: there the new client already exists and is kept.

D. A development entry: `@samebase/alchemy-identity-hub/dev`.

```ts
/** The variables of a deployment without a hub: a linked worktree's local backend, CI. */
export const NO_HUB_ENVIRONMENT = {
  HUB_ISSUER: "http://127.0.0.1:1",
  HUB_CLIENT_ID: "no-hub",
  HUB_CLIENT_SECRET: "no-hub",
} as const;

/**
Registers the deployment that the Convex CLI of `appDir` selects, once.
- A deployment whose HUB_CLIENT_ID is `no-hub` stays as it is.
- A complete client of `issuer` stays.
- Else it reads HUB_REGISTRATION_TOKEN from `<appDir>/.env.local`, reads CONVEX_SITE_URL, and posts
  `<site>/auth/hub/callback` with `client_name` "development", `deployment_type` "development" and
  the site's host as `software_version`, as the three scripts do today. It writes the three
  variables with one `convex env set --force` on standard input.
*/
export function registerDevelopmentClient(options: { appDir: string; issuer: string }): Promise<void>;
```

It finds the app's own Convex CLI as `@samebase/alchemy-convex` does (`installedCli`,
`src/Push.ts:281-293`): `node <convex bin>`, no `npx`, so it works on macOS, Linux and Windows. The
Convex CLI process never gets the token. The log names the client id and the callback, never the
secret. The registration request, the issuer check and the control-character check are the same
code as in the resource: move `register` and its errors to `src/register.ts`, which both entries
import.

This deletes the three registration scripts and their tests, and the two no-hub constants.

### 2.3 New package `@samebase/convex-auth-identity-hub`: Convex Auth method and Google mark

Location: `packages/convex-auth-identity-hub` in identity-broker. Its entries mirror Convex Auth's
built-in providers (`@convex-dev/auth/methods/google/server` and `/react`). Peer dependencies:
`@convex-dev/auth` 2.0.0-beta.0, `convex`, `react`.

`./server`:

```ts
/** The profile of a hub sign-in. `id` is the pairwise `sub`. `email` is verified. */
export const vHubProfile = v.object({
  id: v.string(),
  connector: v.string(),
  connector_account_id: v.string(),
  email: v.string(),
  name: v.optional(v.string()),
  picture: v.optional(v.string()),
});
export type HubProfile = Infer<typeof vHubProfile>;

export function setupIdentityHub<Connector extends string, UsersTable extends string>(
  core: AuthCore<UsersTable>,
  options: {
    issuer: string; // env.HUB_ISSUER
    connector: Connector; // "google"
    component: ComponentApi; // components.authHub
    allowedRedirectOrigins: string[];
  },
): {
  attachUserCallbacks(callbacks: HubUserCallbacks<Connector, UsersTable>): {
    startSignIn: StartSignIn;
    completeSignIn: CompleteSignIn;
  };
};
```

It calls ``setupOauth(core, `hub-${connector}`, catalog, callbacks, options)`` with:

- `authorizationEndpoint` `${issuer}/authorize?connector=${connector}`, which skips the chooser for
  a first-party app, `tokenEndpoint` `${issuer}/token`, `issuer`, and the scopes
  `openid email profile`.
- A `profile` that validates the claims with one Convex validator. It requires
  `connector_account_id`, which the hub sends only to a first-party app (design `docs/design.md:75-80`).
  It refuses a `connector` claim other than the method's connector, because a user can edit the
  authorize URL. It refuses a missing or unverified email. It returns a `HubProfile`. A refusal is a
  `ConvexError` with a fixed sentence, which the page gets as `OTHER_ERROR`.

`HubUserCallbacks` is the fourth parameter type of `setupOauth` for `hub-${Connector}`, `HubProfile`
and `UsersTable`, because beta.0 does not export `UserCallbacks`.

Why `attachUserCallbacks`: its return type does not depend on the callbacks. Each app now writes
`const hub: ReturnType<typeof setupOauth>` to stop the type cycle through `internal` (Bristol
`auth.ts:32-34`, Samebase `auth.ts:39-45`, Scout `auth.ts:494-496`). Convex Auth's `setupGoogle` uses
the same two-step shape. Step 1 of the migration confirms this with `tsc`.

Why it returns `startSignIn` and `completeSignIn`, not `startSignInWithHubGoogle`: names built from
the connector need computed keys, and TypeScript gives those a `string` key. A typed result then
needs an assertion, which the guardrails forbid. The app names its two exports.

What stays in the app, and why:

- `createUser` and `onSignIn`: they read and write the app's tables and decide admission.
- `allowedRedirectOrigins`: the app's own sites.
- `component`: `components.authHub` is the app's generated API.
- `issuer`: `env.HUB_ISSUER` gets its type from the app's `convex.config.ts`.

`./react`:

```tsx
/** Google's "G" mark in its four colors, for a "Continue with Google" button. */
export function GoogleMark(): JSX.Element;
```

Only the mark. The button stays in the app: it uses the app's `Button`, copy and `flowError` text.
A shared button needs styling pass-through, which the guardrails forbid. The `useOauthSignIn` call
is five lines and stays.

The broker emits the claims. A test in identity-broker signs an id_token with the broker's signer
and maps it with the profile of `setupIdentityHub`, so the two packages cannot drift.

### 2.4 `@samebase/convex-auth-tanstack-start`: no change

The `signIn` list of `src/server.ts` is the security list of every mutation that mints a session.
It is one line for each connector, and it stays in the app.

### 2.5 Docs

- identity-broker `docs/consumers.md` becomes the one adoption guide: the first-party hub app and its
  token, the repository secret, the stack, `convex.config.ts`, `auth.ts`, the callbacks with the
  recommended link rule (link by verified email only to a user whose own email is verified), the
  server allowlist, the button, the development deployment, deployments without a hub, and the
  preview pattern with its reason.
- Fix `packages/alchemy-identity-hub/README.md`: no `Convex.EnvironmentVariable`, the new `Client`
  props, the token in the provider, and a 401 on destroy that fails.
- Each consumer keeps one short paragraph that links the guide and states its own rule: Bristol
  admits the owner only; Samebase checks the GitHub App identity; Scout grants credits and needs
  `SITE_URL` set to the Vite origin on a development deployment.

### 2.6 What an app writes after consolidation

Hub operator, once for each app: `createApp` with `firstParty: true` and `mintRegistrationToken`
with a long `expiresInDays` (identity-hub `README.md:58-75`). Then set the repository secret
`HUB_REGISTRATION_TOKEN`, and put the token in `<app>/.env.local`. A rotation is: mint, set the
secret, run the workflow. No state step.

`identity-hub.ts` next to `alchemy.run.ts` (1 line):

```ts
export const HUB_ISSUER = "https://auth.samebase.com";
```

Workflow (1 line on each Alchemy step, deploy and destroy):

```yaml
HUB_REGISTRATION_TOKEN: ${{ secrets.HUB_REGISTRATION_TOKEN }}
```

`alchemy.run.ts`:

```ts
providers: Layer.mergeAll(Convex.providers(), IdentityHub.providers()),

// Stage prod
const client = yield* IdentityHub.Client("HubClient", {
  issuer: HUB_ISSUER,
  siteUrl: PRODUCTION_SITE_URL,
}).pipe(Alchemy.RemovalPolicy.retain());
const site = yield* Convex.Deployment("Site", {
  project,
  type: "prod",
  env: { ...IdentityHub.convexEnv(client), SCOUT_COMMIT: commit },
  source,
});

// A preview: docs/consumers.md#previews gives the reason for two Deployment resources.
const preview = yield* Convex.Deployment("Preview", { project, type: "preview", name: stage }).pipe(
  adopt(true),
  Alchemy.RemovalPolicy.destroy(),
);
const client = yield* IdentityHub.Client("HubClient", { issuer: HUB_ISSUER, siteUrl: preview.siteUrl });
const site = yield* Convex.Deployment("Site", {
  project,
  type: "preview",
  name: stage,
  env: IdentityHub.convexEnv(client),
  source,
}).pipe(adopt(true), Alchemy.RemovalPolicy.destroy());
```

`convex/convex.config.ts` (6 lines):

```ts
import oauth from "@convex-dev/auth/components/oauth/convex.config";
// in defineApp({ env }):
HUB_ISSUER: v.string(), HUB_CLIENT_ID: v.string(), HUB_CLIENT_SECRET: v.string(),
// after app.use(auth, ...):
app.use(oauth, {
  name: "authHub",
  httpPrefix: "/auth/hub",
  env: { CLIENT_ID: app.env.HUB_CLIENT_ID, CLIENT_SECRET: app.env.HUB_CLIENT_SECRET },
});
```

`convex/auth.ts` (8 lines for each connector):

```ts
import { setupIdentityHub } from "@samebase/convex-auth-identity-hub/server";

const google = setupIdentityHub(core, {
  issuer: env.HUB_ISSUER,
  connector: "google",
  component: components.authHub,
  allowedRedirectOrigins: [new URL(env.SITE_URL).origin],
}).attachUserCallbacks({ createUser: internal.users.createHubUser, onSignIn: internal.users.onHubSignIn });
export const startSignInWithHubGoogle = google.startSignIn;
export const completeSignInWithHubGoogle = google.completeSignIn;
```

The app's callbacks take
`provider: v.object({ name: v.literal("hub-google"), accountId: v.string(), profile: vHubProfile })`.

`src/server.ts` (1 line for each connector): `api.auth.completeSignInWithHubGoogle` in `signIn`.

Sign-in page: `useOauthSignIn({ providerName: "hub-google", startSignIn, completeSignIn })`, a
button with `<GoogleMark />`, and the app's own `flowError` text.

Development, in the app's dev script before the first push (3 lines):

```ts
import { registerDevelopmentClient } from "@samebase/alchemy-identity-hub/dev";
import { HUB_ISSUER } from "../../../identity-hub.ts";
await registerDevelopmentClient({ appDir: fileURLToPath(new URL("..", import.meta.url)), issuer: HUB_ISSUER });
```

A deployment without a hub: its setup writes `NO_HUB_ENVIRONMENT`, and its sign-in page hides the
hub button.

## 3. Alternatives considered and rejected

1. A `dev` stage in the stack. `Convex.Deployment` accepts `type: "dev"` with a name
   (`@samebase/alchemy-convex` 0.11.0, `DeploymentProps`). Rejected. Deciding reason: a development
   deployment belongs to one developer and one checkout, and `convex dev` pushes it at each save. A
   stage for each developer puts personal deployments in the team state under the repository's
   stack, needs the team token or an Alchemy login before `pnpm run dev`, and its source push races
   `convex dev`. The need is one registration for each deployment, once. A function with the Convex
   CLI login does it. Known cost: a development client stays on the hub when its deployment goes
   away, as today. The function logs the client id for `identityBroker:deleteClient`.
2. A starter template that carries the files. Rejected as the home of the logic. Deciding reason: a
   template copies code into each app, and the copies drift. Bristol's copy is already one version
   behind and leaves preview clients on the hub (1.3, item 1). A package update reaches every app.
   The template can carry the few lines of 2.6.
3. Everything in Convex Auth. Rejected. Deciding reason: the repeated parts are hub-specific: the
   `connector` parameter and claim, `connector_account_id`, pairwise subjects, the client metadata,
   and RFC 7591 registration at deploy time. Convex Auth is a pinned beta that the team does not
   control, and the team closes gaps in its own packages. The generic part that Convex Auth could
   own, OIDC discovery in place of the two endpoints, saves two lines.
4. The hub registers clients without a token, for example loopback callbacks. Rejected. Deciding
   reason: the token is the only proof that a deployment belongs to an app, and the app selects
   the pairwise namespace and the first-party claims. `*.convex.site` in `allowedCallbackHosts`
   admits every Convex deployment of every team (identity-hub `README.md:66-67`), so a registration
   without a token lets anyone make a client of the app. Also, the development deployments that
   register are cloud `.convex.site` deployments, not loopback. The loopback deployments (linked
   worktrees) have no hub on purpose. And the `oauth` component of Convex Auth requires
   `CLIENT_SECRET`.
5. Client ID Metadata Documents. The client id is an https URL of a JSON document that lists the
   redirect URIs. The hub fetches it at `/authorize`. There is no registration and no secret for
   each deployment. What it needs: the hub must fetch and cache documents from a Convex action with
   SSRF and size limits, map a client id URL to an app, take the client name and deployment type
   from the document, and accept `token_endpoint_auth_method` `none` with PKCE, or
   `private_key_jwt` with keys from the document. Convex Auth 2.0.0-beta.0 must compute the client
   id from the site URL at run time, serve the document on a route, and send a token request
   without `client_secret_post` (its `oauth` component requires `CLIENT_ID` and `CLIENT_SECRET`
   now). Rejected. Deciding reason: previews live on random hosts of the shared `*.convex.site`
   domain. A document there cannot prove which app it belongs to, so the hub needs a statement that
   the app signs, and that is the registration token in another form. The work goes into the hub
   and a Convex Auth change, and the trust setup of the app stays the same.
6. Smaller rejections:
   - A stack helper that also creates the deployments: it passes through every `Convex.Deployment`
     prop (2.2 B).
   - A `Push` resource in `@samebase/alchemy-convex` (create, then push). It would delete the
     two-Deployment preview pattern in every app, but it is outside these four repositories and
     changes rule 6 of `docs/alchemy-deploy-standard.md:26-30`. It needs its own decision.
   - Keep the token as a `Client` prop: state then stores a secret, and an expired token in state
     leaves clients on the hub.
   - Keep the client metadata as app props: three apps write four lines each for values that the
     stage and the checkout already give.
   - A shared hub button: it needs styling pass-through.
   - Keep the workflow check steps: the provider's token error replaces them.

## 4. Migration order

1. identity-broker, one pull request from `main`. No hub change.
   - `alchemy-identity-hub` 0.4.0: the token in the provider, a 401 on destroy that fails, the
     `Client({ issuer, siteUrl })` function that fills the metadata, `convexEnv`, the `./dev` entry
     with `registerDevelopmentClient` and `NO_HUB_ENVIRONMENT`, and `register` in its own module.
   - `convex-auth-identity-hub` 0.1.0: `./server` and `./react`, a conformance test with the broker.
   - `docs/consumers.md` as the one guide; the `alchemy-identity-hub` README fixed.
   - Estimate: about +570 lines (sources, tests, docs) and about -35 (token-in-state paths and the
     README limit).
2. Scout, a follow-up pull request on `main` (`eb76fdb`). The issuer, redirect URI and deployment
   type of each client stay the same, so no client registers again. The method name changes from
   `hub` to `hub-google`: each user's next sign-in adds a core account that `createHubUser` joins to
   the same user by its verified email. Deletes about 280 lines: the registration script (-98), the
   stack (-25), the check steps and the issuer variable (-36), the claims, profile and setup in
   `auth.ts` (-61), the profile tests (-15), `google-mark.tsx` (-23), docs (-23).
3. Samebase, one pull request. No client registers again, and the development deployment keeps its
   client. Method names do not change. Deletes about 470 lines: the registration script and test
   (-268), `NO_HUB_ENVIRONMENT` (-10), the stack (-28), the check steps and the issuer variable
   (-42), `auth.ts` (-21), `identity/signIn.ts` claims, profile and the email check (-52), the
   profile test (-15), README (-39).
4. Bristol, one pull request, from 0.2.1. The prefix moves from `/oauth/hub` to `/auth/hub`, so each
   stage registers a new client (named by its stage) and deletes the old one. The preview clients
   that 0.2.1 left stay on the hub: the operator deletes them with `identityBroker:listClients` and
   `deleteClient`. On the development deployment, remove `HUB_CLIENT_ID` once, so the dev command
   registers the new callback. The method name changes to `hub-google`: the owner's next sign-in adds
   a core account that `createUser` joins to the same user. The production name check moves from
   `softwareVersion` to `siteUrl` (`Output.map(productionDeployment, () => PRODUCTION_SITE_URL)`).
   Deletes about 500 lines: the registration script and test (-352), the no-hub writer (-13), the
   stack with its client metadata (-30), the workflow issuer lines and comment (-5), `auth.ts`
   (-51), `hubAccounts.ts` (-4), `GoogleMark.tsx` (-23), docs (-41).

In total the consumers lose about 1,270 lines and identity-broker gains about 535.

## 5. Open questions for the operator

1. Issuer as a code constant (`identity-hub.ts`) in place of the repository variable `HUB_ISSUER`
   and the `.env.local` line? Recommendation: yes. The issuer is one team value, not a secret, and
   not specific to a deployment. The change deletes the variable and its plumbing in three
   workflows and two `.env.local` files. Each deployment still stores `HUB_ISSUER` next to its
   client.
2. Where does the token live on a laptop? Recommendation: `<app>/.env.local`, read only by
   `registerDevelopmentClient`. Bristol moves it from the shell. The file is ignored by git, the
   Convex CLI already reads it, `pnpm run dev` then needs no shell export, and the worktree setups of
   Samebase and Bristol write a fresh `.env.local` without the token.
3. Rename the method of Bristol and Scout from `hub` to `hub-google`, and their exports to
   `startSignInWithHubGoogle` and `completeSignInWithHubGoogle`? Recommendation: yes. Each hub user
   of Bristol and Scout gets a second core account row at the next sign-in, joined to the same user
   by the app's own `createUser`. No user loses access.
4. A new package `@samebase/convex-auth-identity-hub`, or a subpath of `@samebase/identity-broker`?
   Recommendation: the new package, in the identity-broker repository. The broker package is the
   hub's server: as a subpath, every app installs `jose` and `oauth4webapi`, and the hub package
   takes a Convex Auth beta and React as peers. One repository keeps one release and the
   conformance test.
5. Cut `alchemy-identity-hub` 0.4.0 from `main` now? Recommendation: yes. npm's latest is 0.3.0, so
   0.4.0 is free. The `Client` props change in one step (no token, no metadata, `siteUrl`), and each
   consumer changes its stack once, Bristol from 0.2.1 and the others from 0.3.0.

## Summary

- Repeated now: three development registration scripts (406 lines, plus 322 lines of tests), the
  same preview pattern, client metadata and env triple in three stacks, two pairs of workflow check
  steps (68 lines), three claims readers with three different strengths, two identical Google
  marks, two no-hub constants, and three sets of docs.
- Proposal: `alchemy-identity-hub` 0.4.0 from `main` holds the token as a provider credential,
  fails a destroy on a 401, takes `{ issuer, siteUrl }` and fills `clientName` (stage),
  `deploymentType` (stage) and `softwareVersion` (commit) itself, gives `convexEnv(client)`, and
  adds `registerDevelopmentClient` and `NO_HUB_ENVIRONMENT`. A new `convex-auth-identity-hub` gives
  `setupIdentityHub`, `vHubProfile` and `GoogleMark`. `docs/consumers.md` becomes the one guide.
  The hub does not change.
- The app keeps: the issuer constant, one secret line for each workflow step, about 10 stack
  lines, 6 config lines, 8 `auth.ts` lines for each connector, its own link rule, one allowlist
  line, its button, and a 3-line dev call.
- Order: identity-broker, then a Scout follow-up on `main`, then Samebase, then Bristol. Consumers
  lose about 1,270 lines.
- Defects found: Bristol on 0.2.1 leaves preview clients on the hub; Samebase and Bristol do not
  retain the production client; the package README and the consumer guide on `main` show
  `Convex.EnvironmentVariable`, which does not exist; a Bristol workflow comment is true only on
  0.2.1.
