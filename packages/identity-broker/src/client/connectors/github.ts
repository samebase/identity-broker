import * as oauth from "oauth4webapi";
import { asRecord } from "../protocol.js";
import type { OauthConnector, UpstreamIdentity } from "./types.js";

const USER_URL = "https://api.github.com/user";
const EMAILS_URL = "https://api.github.com/user/emails";

async function githubJson(accessToken: string, url: string): Promise<unknown> {
  const response = await oauth.protectedResourceRequest(
    accessToken,
    "GET",
    new URL(url),
    new Headers({ Accept: "application/vnd.github+json", "User-Agent": "identity-broker" }),
  );
  if (!response.ok) {
    throw new Error(`GitHub ${url} answered ${response.status}`);
  }
  return await response.json();
}

/**
 * The GitHub user and a verified email. GitHub's `/user` email is whatever the user made public,
 * so the verified primary address from `/user/emails` is used instead; a user with no verified
 * address gets no email claim.
 */
async function githubIdentity(accessToken: string): Promise<UpstreamIdentity> {
  const user = asRecord(await githubJson(accessToken, USER_URL));
  const id = user["id"];
  if (typeof id !== "number" && typeof id !== "string") {
    throw new Error("GitHub /user returned no id");
  }
  const identity: UpstreamIdentity = { upstreamId: String(id) };
  const name = user["name"] ?? user["login"];
  if (typeof name === "string" && name.length > 0) {
    identity.name = name;
  }
  if (typeof user["avatar_url"] === "string") {
    identity.picture = user["avatar_url"];
  }
  const emails = await githubJson(accessToken, EMAILS_URL);
  if (Array.isArray(emails)) {
    const entries = emails.map((entry) => asRecord(entry));
    const verified = entries.filter((entry) => entry["verified"] === true);
    const primary = verified.find((entry) => entry["primary"] === true) ?? verified[0];
    if (primary !== undefined && typeof primary["email"] === "string") {
      identity.email = primary["email"];
      identity.emailVerified = true;
    }
  }
  return identity;
}

/** GitHub as an OAuth connector. The callback must be registered on the OAuth App or GitHub App. */
export function github(credentials: {
  clientId: () => string;
  clientSecret: () => string;
  name?: string;
}): OauthConnector {
  return {
    kind: "oauth",
    name: credentials.name ?? "github",
    label: "GitHub",
    // GitHub publishes RFC 8414 metadata for this issuer and sends it as `iss` on its
    // authorization response (RFC 9207).
    issuer: "https://github.com/login/oauth",
    scopes: ["read:user", "user:email"],
    clientId: credentials.clientId,
    clientSecret: credentials.clientSecret,
    identity: githubIdentity,
  };
}
