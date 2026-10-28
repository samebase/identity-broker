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
// A registration is never retried within one deploy: each request that succeeds creates one more
// client.
import { Resource } from "alchemy";
import { isResolved } from "alchemy/Diff";
import * as Provider from "alchemy/Provider";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Redacted from "effect/Redacted";
import * as Schema from "effect/Schema";

export type DeploymentType = "production" | "development" | "preview";

export interface ClientProps {
  /**
   * The hub's issuer URL, such as `https://secret-chickadee-10.convex.site`. Normalized as the hub
   * does: origin plus path, without a trailing slash.
   */
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
  /** The normalized issuer: origin plus path, without a trailing slash. */
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

/** A prop failed a check before any request. The message names the prop, never its value. */
export class InvalidProps extends Schema.TaggedError<InvalidProps>()("InvalidProps", {
  reason: Schema.String,
}) {
  override get message() {
    return `IdentityHub.Client: ${this.reason}.`;
  }
}

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
    /** The hub's error_description as one line of printable characters, at most 200. */
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
const RegisteredClient = Schema.Struct({
  client_id: Schema.NonEmptyString,
  client_secret: Schema.NonEmptyString,
});
/** RFC 7591 3.2.2. */
const RegistrationError = Schema.Struct({
  error: Schema.String,
  error_description: Schema.String,
});
/** The part of a fetch error's cause that is a local diagnostic, such as `ECONNREFUSED`. */
const ErrorCode = Schema.Struct({ code: Schema.String });

/** C0 and C1 control characters, DEL included. */
const CONTROL = /\p{Cc}/u;

/**
 * The issuer as the hub canonicalizes its own in `defineIdentityBroker`: origin plus path, without a
 * trailing slash. Diff compares this value, so `https://HUB.EXAMPLE:443/` is `https://hub.example`.
 */
const normalizeIssuer = (issuer: string) =>
  Effect.gen(function* () {
    // The URL parser drops tabs and newlines without an error, so the raw string is checked first.
    if (CONTROL.test(issuer)) {
      return yield* new InvalidProps({ reason: "issuer contains a control character" });
    }
    const url = yield* Effect.try({
      try: () => new URL(issuer),
      catch: () => new InvalidProps({ reason: "issuer is not a URL" }),
    });
    if (url.search !== "" || url.hash !== "") {
      return yield* new InvalidProps({ reason: "issuer has a query or a fragment" });
    }
    if (url.username !== "" || url.password !== "") {
      return yield* new InvalidProps({ reason: "issuer contains credentials" });
    }
    const loopback =
      url.protocol === "http:" && (url.hostname === "127.0.0.1" || url.hostname === "localhost");
    if (url.protocol !== "https:" && !loopback) {
      return yield* new InvalidProps({
        reason: "issuer must be an https URL, or http on 127.0.0.1 or localhost",
      });
    }
    return `${url.origin}${url.pathname.replace(/\/$/, "")}`;
  });

/** True when the client in state was registered for `issuer` and the redirect URI and deployment type of `props`. */
const registeredFor = (output: ClientAttributes, issuer: string, props: ClientProps) =>
  output.issuer === issuer &&
  output.redirectUri === props.redirectUri &&
  output.deploymentType === props.deploymentType;

/**
 * One registration. The token goes only into the request header. An error carries local
 * diagnostics only: the status, an error name and code, and the hub's OAuth error made one line.
 */
const register = (issuer: string, props: ClientProps) =>
  Effect.gen(function* () {
    const token = Redacted.value(props.registrationToken);
    // fetch refuses such a header value with an error message that quotes the value.
    if (CONTROL.test(token)) {
      return yield* new InvalidProps({ reason: "registrationToken contains a control character" });
    }
    const response = yield* Effect.tryPromise({
      try: () =>
        fetch(`${issuer}/register`, {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            redirect_uris: [props.redirectUri],
            client_name: props.clientName,
            software_version: props.softwareVersion,
            deployment_type: props.deploymentType,
          }),
          redirect: "error",
          signal: AbortSignal.timeout(15_000),
        }),
      // The error's message can quote the request, so only its name and its cause's code are kept.
      catch: (cause) => {
        const name = cause instanceof Error ? cause.name : "unknown error";
        const code =
          cause instanceof Error && Schema.is(ErrorCode)(cause.cause)
            ? `, ${cause.cause.code}`
            : "";
        return new RegistrationFailed({ issuer, reason: `the request failed (${name}${code})` });
      },
    });
    if (response.status === 401) {
      return yield* new RegistrationTokenRejected({ issuer });
    }
    if (response.status !== 201 && response.status !== 400) {
      return yield* new RegistrationFailed({
        issuer,
        reason: `the hub answered ${response.status}`,
      });
    }
    // A body that is not JSON reads as undefined and fails the checks below.
    const body: unknown = yield* Effect.promise(() => response.json().catch(() => undefined));
    if (response.status === 201) {
      if (Schema.is(RegisteredClient)(body)) {
        return { clientId: body.client_id, clientSecret: Redacted.make(body.client_secret) };
      }
      return yield* new RegistrationFailed({
        issuer,
        reason: "the hub answered 201 without a non-empty client_id and client_secret",
      });
    }
    if (Schema.is(RegistrationError)(body)) {
      return yield* new RegistrationRejected({
        issuer,
        redirectUri: props.redirectUri,
        code: body.error,
        // Code points, so the cut never splits a surrogate pair.
        description: Array.from(body.error_description.replace(/[\s\p{C}]+/gu, " ").trim())
          .slice(0, 200)
          .join(""),
      });
    }
    return yield* new RegistrationFailed({
      issuer,
      reason: "the hub answered 400 without an OAuth error",
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
  diff: Effect.fn(function* ({ news, output }) {
    // Props that are unresolved at plan time, such as a redirectUri from a deployment that this run
    // creates, are compared in reconcile.
    if (!isResolved(news) || output === undefined) return undefined;
    return registeredFor(output, yield* normalizeIssuer(news.issuer), news)
      ? ({ action: "noop" } as const)
      : ({ action: "replace" } as const);
  }),

  // The hub has no endpoint to read a client, so the state is the only record.
  read: ({ output }) => Effect.succeed(output),

  reconcile: Effect.fn(function* ({ news, output }) {
    const issuer = yield* normalizeIssuer(news.issuer);
    if (output !== undefined && registeredFor(output, issuer, news)) return output;
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
