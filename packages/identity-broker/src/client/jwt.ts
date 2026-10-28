import { createLocalJWKSet, jwtVerify, SignJWT, type JWTPayload } from "jose";
import { importSigningKey, publicJwks, SIGNING_ALGORITHM, type KeySet } from "./keys.js";

/** Both tokens live this long: the app's callback redeems the code and the id_token at once. */
export const TOKEN_TTL_SECONDS = 5 * 60;

export type IdentityClaims = {
  sub: string;
  connector: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  picture?: string;
};

async function sign(keySet: KeySet, payload: JWTPayload, issuer: string, audience: string) {
  const { kid, key } = await importSigningKey(keySet);
  return await new SignJWT(payload)
    .setProtectedHeader({ alg: SIGNING_ALGORITHM, kid, typ: "JWT" })
    .setIssuer(issuer)
    .setAudience(audience)
    .setIssuedAt()
    .setExpirationTime(`${TOKEN_TTL_SECONDS}s`)
    .sign(key);
}

export async function signIdToken(args: {
  keySet: KeySet;
  issuer: string;
  clientId: string;
  claims: IdentityClaims;
  authTime: number;
  nonce: string | undefined;
}): Promise<string> {
  return await sign(
    args.keySet,
    {
      ...args.claims,
      auth_time: Math.floor(args.authTime / 1000),
      ...(args.nonce === undefined ? {} : { nonce: args.nonce }),
    },
    args.issuer,
    args.clientId,
  );
}

/** The access token for /userinfo: the same claims, with the issuer itself as the audience. */
export async function signAccessToken(args: {
  keySet: KeySet;
  issuer: string;
  clientId: string;
  claims: IdentityClaims;
}): Promise<string> {
  return await sign(
    args.keySet,
    { ...args.claims, client_id: args.clientId },
    args.issuer,
    args.issuer,
  );
}

export async function verifyAccessToken(args: {
  keySet: KeySet;
  issuer: string;
  token: string;
}): Promise<IdentityClaims | null> {
  try {
    const { payload } = await jwtVerify(args.token, createLocalJWKSet(publicJwks(args.keySet)), {
      issuer: args.issuer,
      audience: args.issuer,
      algorithms: [SIGNING_ALGORITHM],
    });
    if (typeof payload.sub !== "string" || typeof payload["connector"] !== "string") {
      return null;
    }
    const claims: IdentityClaims = { sub: payload.sub, connector: payload["connector"] };
    if (typeof payload["email"] === "string") {
      claims.email = payload["email"];
    }
    if (typeof payload["email_verified"] === "boolean") {
      claims.email_verified = payload["email_verified"];
    }
    if (typeof payload["name"] === "string") {
      claims.name = payload["name"];
    }
    if (typeof payload["picture"] === "string") {
      claims.picture = payload["picture"];
    }
    return claims;
  } catch {
    return null;
  }
}
