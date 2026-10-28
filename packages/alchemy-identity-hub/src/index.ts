// IdentityHub.Client: one Convex deployment registered as an OAuth client of an identity hub, an
// OpenID Provider built with @samebase/identity-broker.
//
// The hub implements RFC 7591 registration only: POST <issuer>/register with the app's
// registration token as a Bearer token answers 201 with a client_id and a client_secret. It has no
// endpoint to read, change, or delete a client (no RFC 7592), so:
// - A changed issuer, redirectUri, or deploymentType replaces the resource: it registers a new
//   client. The old client stays on the hub. The hub removes a preview client after 30 days without
//   a sign-in, and keeps a production or development client until the app is deleted there.
// - A changed clientName, softwareVersion, or registrationToken makes no hub call, and the
//   attributes stay the ones the client was registered with. The token is used only to register.
// - read returns the state as it is, and delete makes no hub call.
// A registration is never retried: each request that succeeds creates one more client.
import { Resource } from "alchemy";
import { isResolved } from "alchemy/Diff";
import * as Provider from "alchemy/Provider";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Redacted from "effect/Redacted";
import * as Schema from "effect/Schema";

export type DeploymentType = "production" | "development" | "preview";

export interface ClientProps {
  /** The hub's issuer URL, such as `https://secret-chickadee-10.convex.site`. A trailing slash is removed. */
  readonly issuer: string;
  /** A token from the hub's `mintRegistrationToken` for the app. Used only to register a client. */
  readonly registrationToken: Redacted.Redacted<string>;
  /** The deployment's callback URL, such as `<deployment site URL>/oauth/hub/callback`. */
  readonly redirectUri: string;
  readonly deploymentType: DeploymentType;
  /** The name the hub records for the client. */
  readonly clientName: string;
  /** Recorded on the hub's client, such as the deployment name. The hub records "unknown" without it. */
  readonly softwareVersion?: string;
}

export interface ClientAttributes {
  /** The issuer without a trailing slash. */
  readonly issuer: string;
  readonly redirectUri: string;
  readonly deploymentType: DeploymentType;
  /** The name the client was registered with. */
  readonly clientName: string;
  readonly clientId: string;
  /** Returned by the hub only at registration. */
  readonly clientSecret: Redacted.Redacted<string>;
}

export type Client = Resource<
  "IdentityHub.Client",
  ClientProps,
  ClientAttributes,
  never,
  Providers
>;
export const Client = Resource<Client>("IdentityHub.Client");

/** The hub answered 401: the registration token is expired or wrong. */
export class RegistrationTokenRejected extends Schema.TaggedError<RegistrationTokenRejected>()(
  "RegistrationTokenRejected",
  { issuer: Schema.String },
) {
  override get message() {
    return `The identity hub at ${this.issuer} rejected the registration token: it is expired or wrong. Mint a new one on the hub with \`npx convex run --prod identityBroker:mintRegistrationToken '{"appId":"<app id>"}'\` (an expiresInDays argument sets its lifetime) and pass it as registrationToken.`;
  }
}

/** The hub answered 400 with an OAuth error: it refused the client metadata. */
export class RegistrationRejected extends Schema.TaggedError<RegistrationRejected>()(
  "RegistrationRejected",
  {
    issuer: Schema.String,
    redirectUri: Schema.String,
    /** The OAuth error code, such as `invalid_redirect_uri`. */
    code: Schema.String,
    description: Schema.String,
  },
) {
  override get message() {
    const fix =
      this.code === "invalid_redirect_uri"
        ? `Fix redirectUri, or allow its host for the app on the hub with \`npx convex run --prod identityBroker:setAllowedCallbackHosts '{"appId":"<app id>","allowedCallbackHosts":[...]}'\`, which replaces the list.`
        : "Fix the prop that the description names.";
    return `The identity hub at ${this.issuer} refused to register ${this.redirectUri}: ${this.code}: ${this.description} ${fix}`;
  }
}

/** The hub could not be reached, or answered neither with a client nor with an OAuth error. */
export class RegistrationFailed extends Schema.TaggedError<RegistrationFailed>()(
  "RegistrationFailed",
  { issuer: Schema.String, reason: Schema.String },
) {
  override get message() {
    return `Registration at ${this.issuer}/register failed: ${this.reason}. Check that issuer is the hub's issuer URL, the "issuer" of ${this.issuer}/.well-known/openid-configuration, and that the hub is deployed.`;
  }
}

/** RFC 7591 3.2.1, the fields this resource keeps. */
const RegisteredClient = Schema.Struct({ client_id: Schema.String, client_secret: Schema.String });
/** RFC 7591 3.2.2. */
const RegistrationError = Schema.Struct({
  error: Schema.String,
  error_description: Schema.String,
});

const issuerOf = (props: ClientProps) => props.issuer.replace(/\/$/, "");

/** True when the client in state was registered for the issuer, redirect URI, and deployment type of `props`. */
const registeredFor = (output: ClientAttributes, props: ClientProps) =>
  output.issuer === issuerOf(props) &&
  output.redirectUri === props.redirectUri &&
  output.deploymentType === props.deploymentType;

/** One registration. The token goes only into the request header, never into an error. */
const register = (issuer: string, props: ClientProps) =>
  Effect.gen(function* () {
    const response = yield* Effect.tryPromise({
      try: () =>
        fetch(`${issuer}/register`, {
          method: "POST",
          headers: {
            Authorization: `Bearer ${Redacted.value(props.registrationToken)}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            redirect_uris: [props.redirectUri],
            client_name: props.clientName,
            software_version: props.softwareVersion,
            deployment_type: props.deploymentType,
          }),
        }),
      catch: (cause) =>
        new RegistrationFailed({
          issuer,
          reason: `the request failed (${cause instanceof Error ? cause.message : String(cause)})`,
        }),
    });
    if (response.status === 401) {
      return yield* new RegistrationTokenRejected({ issuer });
    }
    // A body that is not JSON reads as undefined and fails the checks below.
    const body: unknown = yield* Effect.promise(() => response.json().catch(() => undefined));
    if (response.status === 201 && Schema.is(RegisteredClient)(body)) {
      return { clientId: body.client_id, clientSecret: Redacted.make(body.client_secret) };
    }
    if (response.status === 400 && Schema.is(RegistrationError)(body)) {
      return yield* new RegistrationRejected({
        issuer,
        redirectUri: props.redirectUri,
        code: body.error,
        description: body.error_description,
      });
    }
    return yield* new RegistrationFailed({
      issuer,
      reason:
        response.status === 201
          ? "the hub answered 201 without a client_id and a client_secret"
          : `the hub answered ${response.status}`,
    });
  });

/** The info line for a client that this resource no longer tracks. */
const leaveOnHub = (output: ClientAttributes) =>
  Effect.logInfo(
    `Client ${output.clientId} stays registered on ${output.issuer}: the hub has no endpoint to delete it. ${
      output.deploymentType === "preview"
        ? "The hub removes a preview client after 30 days without a sign-in."
        : `The hub keeps a ${output.deploymentType} client until the app is deleted there.`
    }`,
  );

const ClientProvider = Provider.succeed(Client, {
  diff: ({ news, output }) =>
    Effect.succeed(
      // Props that are unresolved at plan time, such as a redirectUri from a deployment that this
      // run creates, are compared in reconcile.
      !isResolved(news) || output === undefined
        ? undefined
        : registeredFor(output, news)
          ? ({ action: "noop" } as const)
          : ({ action: "replace" } as const),
    ),

  // The hub has no endpoint to read a client, so the state is the only record.
  read: ({ output }) => Effect.succeed(output),

  reconcile: Effect.fn(function* ({ news, output }) {
    if (output !== undefined && registeredFor(output, news)) return output;
    const issuer = issuerOf(news);
    const { clientId, clientSecret } = yield* register(issuer, news);
    // An update whose props were unresolved at plan time registers in place of a replacement.
    if (output !== undefined) yield* leaveOnHub(output);
    return {
      issuer,
      redirectUri: news.redirectUri,
      deploymentType: news.deploymentType,
      clientName: news.clientName,
      clientId,
      clientSecret,
    };
  }),

  delete: ({ output }) => leaveOnHub(output),
});

export class Providers extends Provider.ProviderCollection<Providers>()("IdentityHub") {}

/** The identity hub resource providers, for `providers: Layer.mergeAll(..., IdentityHub.providers())`. */
export const providers = () =>
  Layer.effect(Providers, Provider.collection([Client])).pipe(Layer.provide(ClientProvider));
