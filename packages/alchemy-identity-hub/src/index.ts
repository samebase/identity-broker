import { Resource } from "alchemy";
import { isResolved } from "alchemy/Diff";
import * as Provider from "alchemy/Provider";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Redacted from "effect/Redacted";
import * as Schema from "effect/Schema";

export interface ClientProps {
  /**
   * The hub's issuer, an https origin such as `https://secret-chickadee-10.convex.site`. Compared
   * as its origin, so `https://HUB.EXAMPLE:443/` is `https://hub.example`.
   */
  readonly issuer: string;
  /**
   * A token from the hub's `mintRegistrationToken` for the app. It registers the client, and the
   * token in state at the time deletes it.
   */
  readonly registrationToken: Redacted.Redacted<string>;
  /** The deployment's callback URL, such as `<deployment site URL>/oauth/hub/callback`. */
  readonly redirectUri: string;
}

export interface ClientAttributes {
  /** The issuer's origin. */
  readonly issuer: string;
  readonly redirectUri: string;
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

/** The hub answered 401: the registration token is wrong or revoked. */
export class RegistrationTokenRejected extends Schema.TaggedError<RegistrationTokenRejected>()(
  "RegistrationTokenRejected",
  { issuer: Schema.String },
) {
  override get message() {
    return `The identity hub at ${this.issuer} rejected the registration token: it is wrong or revoked. Mint a new one on the hub with \`npx convex run --prod identityBroker:mintRegistrationToken '{"appId":"<app id>"}'\` and pass it as registrationToken.`;
  }
}

/**
 * The hub's 400 error codes, each with a local sentence. The hub's own text is never repeated: a
 * code outside this list is "unknown", and the error_description is not read.
 */
const REJECTIONS = {
  invalid_redirect_uri: `the app does not allow the host of redirectUri (invalid_redirect_uri). Fix redirectUri, or allow its host for the app on the hub with \`npx convex run --prod identityBroker:setAllowedCallbackHosts '{"appId":"<app id>","allowedCallbackHosts":[...]}'\`, which replaces the list.`,
  invalid_client_metadata:
    "the hub refused the client metadata (invalid_client_metadata). Check that the hub runs @samebase/identity-broker 0.6.0 or later.",
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

/** The hub could not delete the client; the resource stays in state. */
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
/** The broker's 404 for a client it does not hold. A hub without the delete route answers text. */
const ClientGone = Schema.Struct({ error: Schema.Literal("invalid_client") });
/** The part of a fetch error's cause that is a local diagnostic, such as `ECONNREFUSED`. */
const ErrorCode = Schema.Struct({ code: Schema.String });

/** C0 and C1 control characters, DEL included. */
const CONTROL = /\p{Cc}/u;

/**
 * The issuer as `defineIdentityBroker` accepts it: an https origin, compared as its origin. Diff
 * compares this value, so `https://HUB.EXAMPLE:443/` is `https://hub.example`.
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
    // An origin's href is the origin and "/": a path, query, fragment or credentials add to it.
    if (url.protocol !== "https:" || url.href !== `${url.origin}/`) {
      return yield* new InvalidProps({
        reason: "issuer must be an https origin, without a path, credentials, query, or fragment",
      });
    }
    return url.origin;
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

/** True when the client in state was registered for `issuer` and the redirect URI of `props`. */
const registeredFor = (output: ClientAttributes, issuer: string, props: ClientProps) =>
  output.issuer === issuer && output.redirectUri === props.redirectUri;

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
            // The hub's only client authentication, and the one Convex Auth's generic OAuth method
            // uses: the client credentials in the token request body.
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

/** The warning for a client this resource stops tracking without deleting it on the hub. */
const leftOnHub = (output: ClientAttributes, reason: string) =>
  Effect.logWarning(
    `Client ${output.clientId} stays registered on ${output.issuer}: ${reason}. Delete it on the hub with \`npx convex run --prod identityBroker:deleteClient '{"clientId":"${output.clientId}"}'\`.`,
  );

/** 204 or the broker's invalid_client 404 is done; 401 warns; anything else fails. */
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
    if (response.status === 204) return;
    if (response.status === 401) {
      return yield* leftOnHub(
        output,
        "the hub rejected the registration token, which is wrong or revoked",
      );
    }
    if (response.status === 404) {
      const body: unknown = yield* Effect.promise(() => response.json().catch(() => undefined));
      if (Schema.is(ClientGone)(body)) return;
      return yield* new DeletionFailed({ issuer, clientId, reason: "the hub has no delete route" });
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

  reconcile: Effect.fn(function* ({ news, olds, output }) {
    const issuer = yield* normalizeIssuer(news.issuer);
    const token = Redacted.value(news.registrationToken);
    // fetch refuses a control character in a header with an error message that quotes the value.
    // Checked even when nothing registers: the token is stored for a later delete.
    if (CONTROL.test(token)) {
      return yield* new InvalidProps({ reason: "registrationToken contains a control character" });
    }
    if (output !== undefined && registeredFor(output, issuer, news)) return output;
    const { clientId, clientSecret } = yield* register(issuer, token, news);
    // An update whose props were unresolved at plan time registers in place of a replacement. The
    // old client lives at the old issuer under the old token. The new client is returned whatever
    // happens to the old one, so a failed delete only warns.
    if (output !== undefined) {
      yield* unregister(
        output,
        // @ts-expect-error olds is undefined only for an adopted resource, and read returns the state's output, so this resource is never adopted.
        Redacted.value(olds.registrationToken),
      ).pipe(Effect.catchTag("DeletionFailed", (error) => leftOnHub(output, error.reason)));
    }
    return {
      issuer,
      redirectUri: news.redirectUri,
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
