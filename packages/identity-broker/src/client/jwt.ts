import { createLocalJWKSet, jwtVerify, SignJWT, type JWTPayload } from "jose";
import {
  currentKey,
  importSigningKey,
  publicJwks,
  SIGNING_ALGORITHM,
  type KeySet,
} from "./keys.js";

/** Both tokens live this long: the app's callback redeems the code and the id_token at once. */
export const TOKEN_TTL_SECONDS = 5 * 60;

export type IdentityClaims = {
  sub: string;
  connector: string;
  /** The connector's own id for the account, `upstreamId`, for a first-party app only. */
  connector_account_id?: string;
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
    if (typeof payload["connector_account_id"] === "string") {
      claims.connector_account_id = payload["connector_account_id"];
    }
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

function reason(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Proves a key set the way the broker uses it: an id_token from `signIdToken` must verify against
 * the JWKS that /.well-known/jwks.json publishes, its key found by kid, and each retired key there
 * must resolve as a relying party resolves it, as an RSA key that RS256 verifies with. `parseKeySet`
 * checks only the shape, so it passes an RSA key under the 2048 bits RS256 needs. For
 * `identity-broker keys`; the host reads its keys per request and skips this.
 */
export async function assertKeySetUsable(keySet: KeySet): Promise<void> {
  const { kid } = currentKey(keySet);
  const issuer = "urn:identity-broker:key-check";
  let token: string;
  try {
    token = await signIdToken({
      keySet,
      issuer,
      clientId: issuer,
      claims: { sub: "key-check", connector: "key-check" },
      authTime: Date.now(),
      nonce: undefined,
    });
  } catch (error) {
    throw new Error(`IDENTITY_BROKER_KEYS key "${kid}" fails at sign: ${reason(error)}`);
  }
  const document = publicJwks(keySet);
  const jwks = createLocalJWKSet(document);
  try {
    await jwtVerify(token, jwks, { issuer, audience: issuer, algorithms: [SIGNING_ALGORITHM] });
  } catch (error) {
    throw new Error(`IDENTITY_BROKER_KEYS key "${kid}" fails at verify: ${reason(error)}`);
  }
  for (const { kid: published } of document.keys) {
    // The current key verified above.
    if (published !== kid) {
      const { algorithm } = await jwks({ alg: SIGNING_ALGORITHM, kid: published }).catch(
        (error: unknown) => {
          throw new Error(
            `IDENTITY_BROKER_KEYS key "${published}" fails at verify: ${reason(error)}`,
          );
        },
      );
      // Resolving does not check the size, but jose refuses to verify RS256 with RSA under 2048 bits.
      if (
        !("modulusLength" in algorithm) ||
        typeof algorithm.modulusLength !== "number" ||
        algorithm.modulusLength < 2048
      ) {
        throw new Error(
          `IDENTITY_BROKER_KEYS key "${published}" fails at verify: RS256 requires key modulusLength to be 2048 bits or larger`,
        );
      }
    }
  }
}
