// @vitest-environment node
import * as Output from "alchemy/Output";
import * as Test from "alchemy/Test/Vitest";
import * as Effect from "effect/Effect";
import * as Redacted from "effect/Redacted";
import { afterEach, expect, vi } from "vite-plus/test";
import * as IdentityHub from "./index.js";

const issuer = "https://secret-chickadee-10.convex.site";
const token = "rt_registration-token";
const redirectUri = "https://happy-otter-123.convex.site/oauth/hub/callback";

const props = {
  issuer: `${issuer}/`,
  registrationToken: Redacted.make(token),
  redirectUri,
  deploymentType: "preview",
  clientName: "Bristol preview",
  softwareVersion: "happy-otter-123",
} satisfies IdentityHub.ClientProps;

/**
 * A hub behind a stubbed fetch. POST <issuer>/register answers as the `register` handler of
 * @samebase/identity-broker does: 401 for an unknown token, 201 with the client otherwise.
 */
const fakeHub = () => {
  const requests: { url: string; authorization: string | null; body: unknown }[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init);
      if (request.method !== "POST" || request.url !== `${issuer}/register`) {
        return new Response("No matching routes found", { status: 404 });
      }
      const body: unknown = await request.json();
      requests.push({
        url: request.url,
        authorization: request.headers.get("authorization"),
        body,
      });
      if (request.headers.get("authorization") !== `Bearer ${token}`) {
        return Response.json(
          {
            error: "invalid_token",
            error_description: "The registration token is unknown or expired.",
          },
          { status: 401 },
        );
      }
      return Response.json(
        {
          client_id: `cl_${requests.length}`,
          client_secret: `secret-${requests.length}`,
          client_id_issued_at: 1793174400,
          client_secret_expires_at: 0,
          redirect_uris: [redirectUri],
          client_name: "Bristol preview",
          software_id: "bristol-ab12c",
          software_version: "happy-otter-123",
          deployment_type: "preview",
          token_endpoint_auth_method: "client_secret_post",
          grant_types: ["authorization_code"],
          response_types: ["code"],
        },
        { status: 201 },
      );
    }),
  );
  return requests;
};

afterEach(() => {
  vi.unstubAllGlobals();
});

const { test } = Test.make({ providers: IdentityHub.providers() });

/** Deploys one client and returns its attributes with the secret revealed. */
const deployClient = (stack: Test.ScratchStack, clientProps: IdentityHub.ClientProps) =>
  stack
    .deploy(IdentityHub.Client("HubClient", clientProps))
    .pipe(
      Effect.map((client) => ({ ...client, clientSecret: Redacted.value(client.clientSecret) })),
    );

test.provider("the first deploy registers the deployment and outputs the client", (stack) =>
  Effect.gen(function* () {
    const requests = fakeHub();
    const client = yield* deployClient(stack, props);
    expect(requests).toEqual([
      {
        url: `${issuer}/register`,
        authorization: `Bearer ${token}`,
        body: {
          redirect_uris: [redirectUri],
          client_name: "Bristol preview",
          software_version: "happy-otter-123",
          deployment_type: "preview",
        },
      },
    ]);
    expect(client).toMatchObject({
      issuer,
      redirectUri,
      deploymentType: "preview",
      clientName: "Bristol preview",
      clientId: "cl_1",
      clientSecret: "secret-1",
    });
    expect(client).not.toHaveProperty("registrationToken");
  }),
);

test.provider("a second deploy with the same props makes no request, also with --force", (stack) =>
  Effect.gen(function* () {
    const requests = fakeHub();
    const first = yield* deployClient(stack, props);
    const second = yield* deployClient(stack, props);
    // --force turns the noop into an update, so reconcile runs with the client in state.
    const forced = yield* stack.deploy(IdentityHub.Client("HubClient", props), { force: true });
    expect(requests).toHaveLength(1);
    expect(second).toEqual(first);
    expect(forced.clientId).toBe(first.clientId);
  }),
);

test.provider("a changed redirectUri registers a new client", (stack) =>
  Effect.gen(function* () {
    const requests = fakeHub();
    yield* deployClient(stack, props);
    const moved = "https://brave-lynx-456.convex.site/oauth/hub/callback";
    const client = yield* deployClient(stack, { ...props, redirectUri: moved });
    expect(requests.map((request) => request.body)).toMatchObject([
      { redirect_uris: [redirectUri] },
      { redirect_uris: [moved] },
    ]);
    expect(client).toMatchObject({
      redirectUri: moved,
      clientId: "cl_2",
      clientSecret: "secret-2",
    });
  }),
);

test.provider(
  "a redirectUri that resolves only during the deploy registers a new client when it changed",
  (stack) =>
    Effect.gen(function* () {
      const requests = fakeHub();
      // The second client's redirectUri derives from the first client's id, which a replacement
      // of the first client leaves unresolved until the deploy runs.
      const pair = (firstRedirectUri: string) =>
        Effect.gen(function* () {
          const first = yield* IdentityHub.Client("First", {
            ...props,
            redirectUri: firstRedirectUri,
          });
          const second = yield* IdentityHub.Client("Second", {
            ...props,
            redirectUri: Output.map(first.clientId, (id) => `${redirectUri}?for=${id}`),
          });
          return { first: first.clientId, second: second.clientId, uri: second.redirectUri };
        });
      expect(yield* stack.deploy(pair(redirectUri))).toEqual({
        first: "cl_1",
        second: "cl_2",
        uri: `${redirectUri}?for=cl_1`,
      });
      expect(
        yield* stack.deploy(pair("https://brave-lynx-456.convex.site/oauth/hub/callback")),
      ).toEqual({ first: "cl_3", second: "cl_4", uri: `${redirectUri}?for=cl_3` });
      expect(requests).toHaveLength(4);
    }),
);

test.provider(
  "a changed clientName, softwareVersion, or registrationToken makes no request",
  (stack) =>
    Effect.gen(function* () {
      const requests = fakeHub();
      const first = yield* deployClient(stack, props);
      const second = yield* deployClient(stack, {
        ...props,
        clientName: "Bristol review",
        softwareVersion: "happy-otter-124",
        registrationToken: Redacted.make("rt_another-token"),
      });
      expect(requests).toHaveLength(1);
      expect(second).toEqual(first);
    }),
);

test.provider("a rejected registration token fails with a message that names the fix", (stack) =>
  Effect.gen(function* () {
    const requests = fakeHub();
    const expired = "rt_expired-token";
    const error = yield* Effect.flip(
      deployClient(stack, { ...props, registrationToken: Redacted.make(expired) }),
    );
    expect(requests).toHaveLength(1);
    expect(error).toBeInstanceOf(IdentityHub.RegistrationTokenRejected);
    expect(error.message).toContain("identityBroker:mintRegistrationToken");
    expect(error.message).not.toContain(expired);
    expect(error.message).not.toContain("unknown or expired");
  }),
);

test.provider("destroy makes no request", (stack) =>
  Effect.gen(function* () {
    const requests = fakeHub();
    yield* deployClient(stack, props);
    yield* stack.destroy();
    expect(requests).toHaveLength(1);
  }),
);
