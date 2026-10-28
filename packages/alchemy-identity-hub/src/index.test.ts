// @vitest-environment node
import * as Output from "alchemy/Output";
import * as Test from "alchemy/Test/Vitest";
import * as Cause from "effect/Cause";
import * as Effect from "effect/Effect";
import * as Logger from "effect/Logger";
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

type SeenRequest = { url: string; authorization: string | null; redirect: string };

const hubs = new Map<string, (request: Request) => Promise<Response>>();

const fakeHub = (
  options: { origin?: string; tokens?: readonly string[]; answer?: () => Response } = {},
) => {
  const origin = options.origin ?? issuer;
  const tokens = options.tokens ?? [token];
  const clients = new Set<string>();
  const hub: {
    registrations: (SeenRequest & { body: unknown })[];
    deletions: SeenRequest[];
    deleteAnswer: (() => Response) | undefined;
  } = { registrations: [], deletions: [], deleteAnswer: undefined };
  const invalidToken = () =>
    Response.json(
      {
        error: "invalid_token",
        error_description: "The registration token is unknown.",
      },
      { status: 401 },
    );
  hubs.set(origin, async (request) => {
    const seen = {
      url: request.url,
      authorization: request.headers.get("authorization"),
      redirect: request.redirect,
    };
    const authorized = tokens.some((known) => seen.authorization === `Bearer ${known}`);
    if (request.method === "DELETE" && request.url.startsWith(`${origin}/register/`)) {
      hub.deletions.push(seen);
      if (!authorized) return invalidToken();
      if (hub.deleteAnswer !== undefined) return hub.deleteAnswer();
      if (!clients.delete(request.url.slice(`${origin}/register/`.length))) {
        return Response.json(
          {
            error: "invalid_client",
            error_description:
              "No client with this id belongs to the app of this registration token.",
          },
          { status: 404 },
        );
      }
      return new Response(null, { status: 204 });
    }
    if (request.method !== "POST" || request.url !== `${origin}/register`) {
      return new Response("No matching routes found", { status: 404 });
    }
    const body: unknown = await request.json();
    hub.registrations.push({ ...seen, body });
    if (!authorized) return invalidToken();
    if (options.answer !== undefined) return options.answer();
    const clientId = `cl_${hub.registrations.length}`;
    clients.add(clientId);
    return Response.json(
      {
        client_id: clientId,
        client_secret: `secret-${hub.registrations.length}`,
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
  });
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init);
      const serve = hubs.get(new URL(request.url).origin);
      return serve === undefined
        ? new Response("No matching routes found", { status: 404 })
        : await serve(request);
    }),
  );
  return hub;
};

const deletion = (clientId: string, bearer = token, origin = issuer) => ({
  url: `${origin}/register/${clientId}`,
  authorization: `Bearer ${bearer}`,
  redirect: "error",
});

const hubB = "https://hub-b.example";
const tokenB = "rt_hub-b-token";

/**
 * First, and Second at `second`'s hub. Second's redirectUri derives from First's client id, which a
 * replacement of First leaves unresolved until the deploy runs, so Second updates in place.
 */
const pair = (
  firstRedirectUri: string,
  second: Pick<IdentityHub.ClientProps, "issuer" | "registrationToken"> = props,
) =>
  Effect.gen(function* () {
    const first = yield* IdentityHub.Client("First", { ...props, redirectUri: firstRedirectUri });
    const client = yield* IdentityHub.Client("Second", {
      ...props,
      issuer: second.issuer,
      registrationToken: second.registrationToken,
      redirectUri: Output.map(first.clientId, (id) => `${redirectUri}?for=${id}`),
    });
    return { first: first.clientId, second: client.clientId, uri: client.redirectUri };
  });

const moved = "https://brave-lynx-456.convex.site/oauth/hub/callback";

const warningsOf = <A, E, R>(effect: Effect.Effect<A, E, R>) =>
  Effect.gen(function* () {
    const warnings: unknown[] = [];
    const capture = Logger.make(({ logLevel, message }) => {
      if (logLevel === "Warn") warnings.push(message);
    });
    const value = yield* effect.pipe(
      Effect.provide(Logger.layer([capture], { mergeWithExisting: true })),
    );
    return { value, warnings };
  });

afterEach(() => {
  hubs.clear();
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
    const hub = fakeHub();
    const client = yield* deployClient(stack, props);
    expect(hub.registrations).toEqual([
      {
        url: `${issuer}/register`,
        authorization: `Bearer ${token}`,
        redirect: "error",
        body: {
          redirect_uris: [redirectUri],
          client_name: "Bristol preview",
          software_version: "happy-otter-123",
          deployment_type: "preview",
          token_endpoint_auth_method: "client_secret_post",
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
    const hub = fakeHub();
    const first = yield* deployClient(stack, props);
    const second = yield* deployClient(stack, props);
    // --force turns the noop into an update, so reconcile runs with the client in state.
    const forced = yield* stack.deploy(IdentityHub.Client("HubClient", props), { force: true });
    expect(hub.registrations).toHaveLength(1);
    expect(hub.deletions).toHaveLength(0);
    expect(second).toEqual(first);
    expect(forced.clientId).toBe(first.clientId);
  }),
);

test.provider(
  "a changed redirectUri registers a new client and deletes the replaced one",
  (stack) =>
    Effect.gen(function* () {
      const hub = fakeHub();
      yield* deployClient(stack, props);
      const moved = "https://brave-lynx-456.convex.site/oauth/hub/callback";
      const client = yield* deployClient(stack, { ...props, redirectUri: moved });
      expect(hub.registrations.map((request) => request.body)).toMatchObject([
        { redirect_uris: [redirectUri] },
        { redirect_uris: [moved] },
      ]);
      expect(hub.deletions).toEqual([deletion("cl_1")]);
      expect(client).toMatchObject({
        redirectUri: moved,
        clientId: "cl_2",
        clientSecret: "secret-2",
      });
    }),
);

test.provider(
  "a redirectUri that resolves only during the deploy registers a new client when it changed and deletes the old one",
  (stack) =>
    Effect.gen(function* () {
      const hub = fakeHub();
      expect(yield* stack.deploy(pair(redirectUri))).toEqual({
        first: "cl_1",
        second: "cl_2",
        uri: `${redirectUri}?for=cl_1`,
      });
      expect(yield* stack.deploy(pair(moved))).toEqual({
        first: "cl_3",
        second: "cl_4",
        uri: `${redirectUri}?for=cl_3`,
      });
      expect(hub.registrations).toHaveLength(4);
      // First is replaced, so its replacement's delete removes cl_1; Second registers in place and
      // removes cl_2 itself.
      expect(hub.deletions.map((request) => request.url).sort()).toEqual([
        deletion("cl_1").url,
        deletion("cl_2").url,
      ]);
    }),
);

test.provider(
  "a changed clientName, softwareVersion, or registrationToken makes no request, and destroy sends the newest token",
  (stack) =>
    Effect.gen(function* () {
      const rotated = "rt_another-token";
      const hub = fakeHub({ tokens: [token, rotated] });
      const first = yield* deployClient(stack, props);
      const second = yield* deployClient(stack, {
        ...props,
        clientName: "Bristol review",
        softwareVersion: "happy-otter-124",
        registrationToken: Redacted.make(rotated),
      });
      expect(hub.registrations).toHaveLength(1);
      expect(second).toEqual(first);
      yield* stack.destroy();
      expect(hub.deletions).toEqual([deletion("cl_1", rotated)]);
    }),
);

test.provider("a rejected registration token fails with a message that names the fix", (stack) =>
  Effect.gen(function* () {
    const hub = fakeHub();
    const revoked = "rt_revoked-token";
    const error = yield* Effect.flip(
      deployClient(stack, { ...props, registrationToken: Redacted.make(revoked) }),
    );
    expect(hub.registrations).toHaveLength(1);
    expect(error).toBeInstanceOf(IdentityHub.RegistrationTokenRejected);
    expect(error.message).toContain("identityBroker:mintRegistrationToken");
    expect(error.message).not.toContain(revoked);
    expect(error.message).not.toContain("is unknown");
  }),
);

test.provider("the issuer is normalized as the hub normalizes its own", (stack) =>
  Effect.gen(function* () {
    const hub = fakeHub({ origin: "https://hub.example" });
    const client = yield* deployClient(stack, { ...props, issuer: "https://HUB.EXAMPLE:443/" });
    expect(client.issuer).toBe("https://hub.example");
    expect(hub.registrations.map((request) => request.url)).toEqual([
      "https://hub.example/register",
    ]);
    // The same normalized issuer is no change.
    yield* deployClient(stack, { ...props, issuer: "https://hub.example" });
    expect(hub.registrations).toHaveLength(1);
  }),
);

test.provider("an issuer with credentials, a query, or plain http is refused locally", (stack) =>
  Effect.gen(function* () {
    const hub = fakeHub();
    for (const [bad, reason] of [
      ["https://user:pass@hub.example", "credentials"],
      ["https://hub.example/?x=1", "a query"],
      ["https://hub.example/#x", "a fragment"],
      ["http://hub.example", "https"],
      ["https://hub.example/\n", "control character"],
    ] as const) {
      const error = yield* Effect.flip(deployClient(stack, { ...props, issuer: bad }));
      expect(error).toBeInstanceOf(IdentityHub.InvalidProps);
      expect(error.message).toContain(reason);
      expect(error.message).not.toContain("pass");
      expect(error.message).not.toContain(token);
    }
    expect(hub.registrations).toHaveLength(0);
    fakeHub({ origin: "http://localhost:3211" });
    const local = yield* deployClient(stack, { ...props, issuer: "http://localhost:3211" });
    expect(local.issuer).toBe("http://localhost:3211");
  }),
);

test.provider("a registration token with a newline is refused before any request", (stack) =>
  Effect.gen(function* () {
    const hub = fakeHub();
    const broken = `${token}\nX-Injected: 1`;
    const error = yield* Effect.flip(
      deployClient(stack, { ...props, registrationToken: Redacted.make(broken) }),
    );
    expect(hub.registrations).toHaveLength(0);
    expect(error).toBeInstanceOf(IdentityHub.InvalidProps);
    expect(error.message).toContain("registrationToken");
    expect(error.message).not.toContain(token);
  }),
);

test.provider("a failed request reports the error name and code, not its message", (stack) =>
  Effect.gen(function* () {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new TypeError(`fetch failed for Bearer ${token}`, {
          cause: Object.assign(new Error(`connect ECONNREFUSED, Bearer ${token}`), {
            code: "ECONNREFUSED",
          }),
        });
      }),
    );
    const error = yield* Effect.flip(deployClient(stack, props));
    expect(error).toBeInstanceOf(IdentityHub.RegistrationFailed);
    expect(error.message).toContain("(TypeError, ECONNREFUSED)");
    expect(error.message).not.toContain(token);
  }),
);

test.provider("a 500 fails with the status alone", (stack) =>
  Effect.gen(function* () {
    const hub = fakeHub({
      answer: () => new Response(`Internal error near Bearer ${token}`, { status: 500 }),
    });
    const error = yield* Effect.flip(deployClient(stack, props));
    expect(hub.registrations).toHaveLength(1);
    expect(error).toBeInstanceOf(IdentityHub.RegistrationFailed);
    expect(error.message).toContain("the hub answered 500");
    expect(error.message).not.toContain("Internal error");
    expect(error.message).not.toContain(token);
  }),
);

test.provider("a 201 with an empty client_secret fails", (stack) =>
  Effect.gen(function* () {
    fakeHub({
      answer: () => Response.json({ client_id: "cl_1", client_secret: "" }, { status: 201 }),
    });
    const error = yield* Effect.flip(deployClient(stack, props));
    expect(error).toBeInstanceOf(IdentityHub.RegistrationFailed);
    expect(error.message).toContain("201");
    expect(error.message).not.toContain(token);
  }),
);

test.provider("a 400 with a known code fails with a local sentence, not the hub's text", (stack) =>
  Effect.gen(function* () {
    const secret = "hub-secret-7f3a";
    fakeHub({
      answer: () =>
        Response.json(
          {
            error: "invalid_redirect_uri",
            error_description: `The host is not allowed.\r\n\u001b[31mForged log line ${secret}`,
          },
          { status: 400 },
        ),
    });
    const error = yield* Effect.flip(deployClient(stack, props));
    if (!(error instanceof IdentityHub.RegistrationRejected)) {
      return expect.unreachable(`expected RegistrationRejected, got ${error._tag}`);
    }
    expect(error.code).toBe("invalid_redirect_uri");
    expect(error.message).toContain("identityBroker:setAllowedCallbackHosts");
    expect(error.message).not.toContain("The host is not allowed");
    expect(error.message).not.toContain(secret);
    expect(error.message).not.toMatch(/\p{Cc}/u);
    expect(error.message).not.toContain(token);
  }),
);

test.provider("a 400 never repeats the hub's error code or description", (stack) =>
  Effect.gen(function* () {
    const secret = "hub-secret-7f3a";
    fakeHub({
      answer: () =>
        Response.json(
          { error: `invalid_${secret}`, error_description: `Leaked ${secret}` },
          { status: 400 },
        ),
    });
    const error = yield* Effect.flip(deployClient(stack, props));
    if (!(error instanceof IdentityHub.RegistrationRejected)) {
      return expect.unreachable(`expected RegistrationRejected, got ${error._tag}`);
    }
    expect(error.code).toBe("unknown");
    expect(error.message).toContain("unknown error code");
    expect(error.message).not.toContain(secret);
    expect(JSON.stringify(error)).not.toContain(secret);
    expect(error.message).not.toContain(token);
  }),
);

test.provider("destroy deletes the client on the hub", (stack) =>
  Effect.gen(function* () {
    const hub = fakeHub();
    yield* deployClient(stack, props);
    yield* stack.destroy();
    expect(hub.deletions).toEqual([deletion("cl_1")]);
    // The state is empty: the next deploy registers a new client.
    expect((yield* deployClient(stack, props)).clientId).toBe("cl_2");
  }),
);

test.provider("destroy succeeds when the hub no longer has the client", (stack) =>
  Effect.gen(function* () {
    fakeHub();
    yield* deployClient(stack, props);
    // Another hub instance holds no client, so it answers 404.
    const hub = fakeHub();
    yield* stack.destroy();
    // The state is empty: a second destroy makes no request.
    yield* stack.destroy();
    expect(hub.deletions).toEqual([deletion("cl_1")]);
  }),
);

test.provider(
  "destroy with a token the hub rejects leaves the client there and succeeds",
  (stack) =>
    Effect.gen(function* () {
      fakeHub();
      yield* deployClient(stack, props);
      // The token was revoked since the deploy.
      const hub = fakeHub({ tokens: [] });
      const { warnings } = yield* warningsOf(stack.destroy());
      // The state is empty: a second destroy makes no request.
      yield* stack.destroy();
      expect(hub.deletions).toEqual([deletion("cl_1")]);
      expect(warnings).toEqual([
        [expect.stringContaining(`identityBroker:deleteClient '{"clientId":"cl_1"}'`)],
      ]);
      expect(JSON.stringify(warnings)).not.toContain(token);
    }),
);

test.provider(
  "a delete that fails keeps the client in state, and the next destroy deletes it",
  (stack) =>
    Effect.gen(function* () {
      for (const [failure, reason] of [
        [
          () => new Response(`Internal error near Bearer ${token}`, { status: 500 }),
          "answered 500",
        ],
        [
          () => {
            throw new TypeError(`fetch failed for Bearer ${token}`, {
              cause: Object.assign(new Error(`connect ECONNREFUSED, Bearer ${token}`), {
                code: "ECONNREFUSED",
              }),
            });
          },
          "(TypeError, ECONNREFUSED)",
        ],
        [
          () => new Response("No matching routes found", { status: 404 }),
          "the hub has no delete route",
        ],
      ] as const) {
        const hub = fakeHub();
        yield* deployClient(stack, props);
        hub.deleteAnswer = failure;
        const error = yield* Effect.flip(stack.destroy());
        const cause = Cause.squash(error.failures[0].cause);
        if (!(cause instanceof IdentityHub.DeletionFailed)) {
          return expect.unreachable(`expected DeletionFailed, got ${String(cause)}`);
        }
        expect(cause.message).toContain(reason);
        for (const message of [cause.message, error.message]) {
          expect(message).not.toContain("Internal error");
          expect(message).not.toContain(token);
        }
        hub.deleteAnswer = undefined;
        yield* stack.destroy();
        expect(hub.deletions).toEqual([deletion("cl_1"), deletion("cl_1")]);
      }
    }),
);

test.provider(
  "an in-place re-registration at another hub deletes the old client at the old hub with the old token",
  (stack) =>
    Effect.gen(function* () {
      const hubA = fakeHub();
      const b = fakeHub({ origin: hubB, tokens: [tokenB] });
      yield* stack.deploy(pair(redirectUri));
      expect(
        yield* stack.deploy(
          pair(moved, { issuer: hubB, registrationToken: Redacted.make(tokenB) }),
        ),
      ).toMatchObject({ second: "cl_1" });
      expect(b.registrations).toHaveLength(1);
      expect(b.deletions).toEqual([]);
      // First's replacement deletes cl_1; Second's old client, cl_2, goes with hub A's token.
      expect(hubA.deletions.sort((x, y) => x.url.localeCompare(y.url))).toEqual([
        deletion("cl_1"),
        deletion("cl_2"),
      ]);
    }),
);

test.provider(
  "an in-place re-registration keeps the new client when the old client's delete fails, and warns",
  (stack) =>
    Effect.gen(function* () {
      fakeHub();
      const b = fakeHub({ origin: hubB, tokens: [tokenB] });
      const atB = { issuer: hubB, registrationToken: Redacted.make(tokenB) };
      expect(yield* stack.deploy(pair(redirectUri, atB))).toMatchObject({ second: "cl_1" });
      b.deleteAnswer = () => new Response(`Internal error near Bearer ${tokenB}`, { status: 500 });
      const { value, warnings } = yield* warningsOf(stack.deploy(pair(moved, atB)));
      expect(value).toMatchObject({ second: "cl_2" });
      expect(b.deletions).toEqual([deletion("cl_1", tokenB, hubB)]);
      expect(warnings).toEqual([
        [
          expect.stringContaining(
            `the hub answered 500. Delete it on the hub with \`npx convex run --prod identityBroker:deleteClient '{"clientId":"cl_1"}'\``,
          ),
        ],
      ]);
      expect(JSON.stringify(warnings)).not.toContain("Internal error");
      expect(JSON.stringify(warnings)).not.toContain(tokenB);
      // The state holds the new client: the same props make no request.
      yield* stack.deploy(pair(moved, atB));
      expect(b.registrations).toHaveLength(2);
    }),
);
