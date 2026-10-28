// IdentityHub.Client: one Convex deployment registered as an OAuth client of an identity hub, an
// OpenID Provider built with @samebase/identity-broker.
//
// The hub registers a client at POST <issuer>/register (RFC 7591), answering 201 with a client_id
// and a client_secret, and deletes one at DELETE <issuer>/register/<client id>, answering 204. Both
// take the app's registration token as a Bearer token. It has no endpoint to read or change a
// client, so:
// - A changed issuer, redirectUri, or deploymentType replaces the resource: it registers a new
//   client, and the replaced client is deleted on the hub.
// - A changed registrationToken updates the state without a hub call, so a later delete sends the
//   newest token. A changed clientName or softwareVersion makes no hub call, and the attributes stay
//   the ones the client was registered with.
// - read returns the state as it is.
// - delete deletes the client on the hub. A 404 means it is already gone. A 401 means the token in
//   state can never delete it: the client stays on the hub, and a warning names the hub command
//   that deletes it. A network error or any other answer fails the delete, and the resource stays
//   in state, so the next deploy or destroy tries again.
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
  /**
   * A token from the hub's `mintRegistrationToken` for the app. It registers the client, and the
   * token in state at the time deletes it.
   */
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

/**
 * The hub's 400 error codes, each with a local sentence. The hub's own text is never repeated: a
 * code outside this list is "unknown", and the error_description is not read.
 */
const REJECTIONS = {
  invalid_redirect_uri: `the app does not allow the host of redirectUri (invalid_redirect_uri). Fix redirectUri, or allow its host for the app on the hub with \`npx convex run --prod identityBroker:setAllowedCallbackHosts '{"appId":"<app id>","allowedCallbackHosts":[...]}'\`, which replaces the list.`,
  invalid_client_metadata:
    "the hub refused the client metadata (invalid_client_metadata). Check clientName, softwareVersion, and deploymentType.",
  invalid_request:
    "the hub found the registration request malformed (invalid_request). Check that issuer is the hub's issuer URL.",
  invalid_token: `the hub rejected the registration token (invalid_token). Mint a new one on the hub with \`npx convex run --prod identityBroker:mintRegistrationToken '{"appId":"<app id>"}'\` and pass it as registrationToken.`,
  unknown:
    "the hub answered with an unknown error code. Check that issuer is the hub's issuer URL and that the hub runs @samebase/identity-broker.",
} as const;

const RejectionCode = Schema.Literals([
  "invalid_redirect_uri",
  "invalid_client_metadata",
  "invalid_request",
  "invalid_token",
  "unknown",
]);

/** The hub answered 400 with an OAuth error: it refused the registration. */
export class RegistrationRejected extends Schema.TaggedError<RegistrationRejected>()(
  "RegistrationRejected",
  {
    issuer: Schema.String,
    redirectUri: Schema.String,
    /** The hub's OAuth error code when this resource knows it, otherwise `unknown`. */
    code: RejectionCode,
  },
) {
  override get message() {
    return `The identity hub at ${this.issuer} refused to register ${this.redirectUri}: ${REJECTIONS[this.code]}`;
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

/**
 * The hub could not be reached to delete a client, or answered other than 204, 404, or 401. The
 * resource stays in state, so the next deploy or destroy tries again.
 */
export class DeletionFailed extends Schema.TaggedError<DeletionFailed>()("DeletionFailed", {
  issuer: Schema.String,
  clientId: Schema.String,
  reason: Schema.String,
}) {
  override get message() {
    return `Deleting client ${this.clientId} at ${this.issuer}/register/${this.clientId} failed: ${this.reason}. The client stays in state, and the next deploy or destroy tries again.`;
  }
}

/** RFC 7591 3.2.1, the fields this resource keeps. */
const RegisteredClient = Schema.Struct({
  client_id: Schema.NonEmptyString,
  client_secret: Schema.NonEmptyString,
});
/** RFC 7591 3.2.2, the field this resource reads. */
const RegistrationError = Schema.Struct({ error: Schema.String });
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

/**
 * The registration token as a header value. fetch refuses a control character with an error
 * message that quotes the value, so it is refused here first.
 */
const headerToken = (registrationToken: Redacted.Redacted<string>) =>
  Effect.gen(function* () {
    const token = Redacted.value(registrationToken);
    if (CONTROL.test(token)) {
      return yield* new InvalidProps({ reason: "registrationToken contains a control character" });
    }
    return token;
  });

/**
 * A failed fetch as local diagnostics. Its message can quote the request, so only its name and its
 * cause's code are kept, such as `(TypeError, ECONNREFUSED)`.
 */
const requestFailure = (cause: unknown) => {
  const name = cause instanceof Error ? cause.name : "unknown error";
  const code =
    cause instanceof Error && Schema.is(ErrorCode)(cause.cause) ? `, ${cause.cause.code}` : "";
  return `the request failed (${name}${code})`;
};

/** True when the client in state was registered for `issuer` and the redirect URI and deployment type of `props`. */
const registeredFor = (output: ClientAttributes, issuer: string, props: ClientProps) =>
  output.issuer === issuer &&
  output.redirectUri === props.redirectUri &&
  output.deploymentType === props.deploymentType;

/**
 * One registration. The token goes only into the request header. An error carries local
 * diagnostics only: the status, an error name and code, or a known OAuth error code.
 */
const register = (issuer: string, token: string, props: ClientProps) =>
  Effect.gen(function* () {
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
            // Convex Auth's generic OAuth method posts the client credentials in the body; the
            // RFC 7591 default is client_secret_basic.
            token_endpoint_auth_method: "client_secret_post",
          }),
          redirect: "error",
          signal: AbortSignal.timeout(15_000),
        }),
      catch: (cause) => new RegistrationFailed({ issuer, reason: requestFailure(cause) }),
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
        code: Schema.is(RejectionCode)(body.error) ? body.error : "unknown",
      });
    }
    return yield* new RegistrationFailed({
      issuer,
      reason: "the hub answered 400 without an OAuth error",
    });
  });

/**
 * Deletes a client on its hub. 204 deletes it, and 404 means it is already gone. A 401 means the
 * token is expired or wrong, and the same token never succeeds on a retry, so the client stays on
 * the hub with a warning. Anything else fails with DeletionFailed. The token goes only into the
 * request header, and the hub's answer is never read.
 */
const unregister = (output: ClientAttributes, token: string) =>
  Effect.gen(function* () {
    const { issuer, clientId } = output;
    const response = yield* Effect.tryPromise({
      try: () =>
        fetch(`${issuer}/register/${encodeURIComponent(clientId)}`, {
          method: "DELETE",
          headers: { Authorization: `Bearer ${token}` },
          redirect: "error",
          signal: AbortSignal.timeout(15_000),
        }),
      catch: (cause) => new DeletionFailed({ issuer, clientId, reason: requestFailure(cause) }),
    });
    if (response.status === 204 || response.status === 404) return;
    if (response.status === 401) {
      return yield* Effect.logWarning(
        `Client ${clientId} stays registered on ${issuer}: the hub rejected the registration token, which is expired or wrong. Delete the client on the hub with \`npx convex run --prod identityBroker:deleteClient '{"clientId":"${clientId}"}'\`.`,
      );
    }
    return yield* new DeletionFailed({
      issuer,
      clientId,
      reason: `the hub answered ${response.status}`,
    });
  });

const ClientProvider = Provider.succeed(Client, {
  diff: Effect.fn(function* ({ news, olds, output }) {
    // Props that are unresolved at plan time, such as a redirectUri from a deployment that this run
    // creates, are compared in reconcile.
    if (!isResolved(news) || output === undefined) return undefined;
    if (!registeredFor(output, yield* normalizeIssuer(news.issuer), news)) {
      return { action: "replace" } as const;
    }
    // A delete sends the token in state, so a new token is stored by an update with no hub call.
    return Redacted.value(news.registrationToken) === Redacted.value(olds.registrationToken)
      ? ({ action: "noop" } as const)
      : ({ action: "update" } as const);
  }),

  // The hub has no endpoint to read a client, so the state is the only record.
  read: ({ output }) => Effect.succeed(output),

  reconcile: Effect.fn(function* ({ news, output }) {
    const issuer = yield* normalizeIssuer(news.issuer);
    // Checked even when nothing registers: the token is stored for a later delete.
    const token = yield* headerToken(news.registrationToken);
    if (output !== undefined && registeredFor(output, issuer, news)) return output;
    const { clientId, clientSecret } = yield* register(issuer, token, news);
    // An update whose props were unresolved at plan time registers in place of a replacement, so
    // it deletes the client it replaces, as a replacement's delete does.
    if (output !== undefined) yield* unregister(output, token);
    return {
      issuer,
      redirectUri: news.redirectUri,
      deploymentType: news.deploymentType,
      clientName: news.clientName,
      clientId,
      clientSecret,
    };
  }),

  delete: ({ olds, output }) => unregister(output, Redacted.value(olds.registrationToken)),
});

export class Providers extends Provider.ProviderCollection<Providers>()("IdentityHub") {}

/** The identity hub resource providers, for `providers: Layer.mergeAll(..., IdentityHub.providers())`. */
export const providers = () =>
  Layer.effect(Providers, Provider.collection([Client])).pipe(Layer.provide(ClientProvider));
