import { afterEach, expect, test, vi } from "vite-plus/test";
import { github } from "./github.js";

// GitHub's documented example responses for GET /user and GET /user/emails
// (docs.github.com/en/rest/users/users and docs.github.com/en/rest/users/emails), trimmed to the
// fields the connector reads plus a few it ignores.
const octocat = {
  login: "octocat",
  id: 1,
  node_id: "MDQ6VXNlcjE=",
  avatar_url: "https://github.com/images/error/octocat_happy.gif",
  type: "User",
  name: "monalisa octocat",
  company: "GitHub",
  email: "octocat@github.com",
  public_repos: 2,
};
const emails = [
  { email: "octocat@github.com", verified: true, primary: true, visibility: "public" },
  { email: "octocat-old@github.com", verified: false, primary: false, visibility: null },
];

afterEach(() => {
  vi.unstubAllGlobals();
});

function stubGitHub(user: unknown, emailList: unknown) {
  const seen: Request[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init);
      seen.push(request);
      if (request.headers.get("authorization") !== "Bearer gho_token") {
        return new Response("Bad credentials", { status: 401 });
      }
      const path = new URL(request.url).pathname;
      if (path === "/user") return Response.json(user);
      if (path === "/user/emails") return Response.json(emailList);
      return new Response("not found", { status: 404 });
    }),
  );
  return seen;
}

const connector = github({ clientId: () => "id", clientSecret: () => "secret" });

test("the real payloads give the id, the name, the avatar and the verified primary email", async () => {
  const seen = stubGitHub(octocat, emails);
  const identity = await connector.identity("gho_token");
  expect(identity).toEqual({
    upstreamId: "1",
    name: "monalisa octocat",
    picture: "https://github.com/images/error/octocat_happy.gif",
    email: "octocat@github.com",
    emailVerified: true,
  });
  expect(seen.map((request) => new URL(request.url).pathname)).toEqual(["/user", "/user/emails"]);
  expect(seen[0]?.headers.get("user-agent")).toBe("identity-broker");
});

test("no verified primary address means no email claim, whatever /user says", async () => {
  // The primary address is unverified; a verified secondary one is not taken in its place.
  stubGitHub(octocat, [
    { email: "octocat@github.com", verified: false, primary: true, visibility: "public" },
    { email: "octocat-work@github.com", verified: true, primary: false, visibility: null },
  ]);
  const identity = await connector.identity("gho_token");
  expect(identity.email).toBeUndefined();
  expect(identity.emailVerified).toBeUndefined();
});

test("a user without a display name falls back to the login", async () => {
  stubGitHub({ ...octocat, name: null }, emails);
  expect((await connector.identity("gho_token")).name).toBe("octocat");
});

test("a /user response without an id is an error", async () => {
  stubGitHub({ login: "octocat" }, emails);
  await expect(connector.identity("gho_token")).rejects.toThrow(/no id/);
});
