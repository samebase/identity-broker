import { createLocalJWKSet, jwtVerify, SignJWT } from "jose";
import {
  currentKey,
  ID_TOKEN_TTL_SECONDS,
  publicJwks,
  SIGNING_ALGORITHM,
  type KeySet,
} from "./keys.js";

export type IdentityClaims = {
  sub: string;
  connector: string;
  /**
   * The connector's own id for the account, such as the GitHub user id or Google's `sub`: with
   * `connector`, the key an app that already keys users by provider and account id maps them by.
   */
  connector_account_id: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  picture?: string;
};

export async function signIdToken(args: {
  keySet: KeySet;
  issuer: string;
  clientId: string;
  claims: IdentityClaims;
  nonce: string | undefined;
}): Promise<string> {
  // jose imports the private JWK for RS256, the algorithm of the header.
  const { kid, privateJwk } = currentKey(args.keySet);
  return await new SignJWT({
    ...args.claims,
    ...(args.nonce === undefined ? {} : { nonce: args.nonce }),
  })
    .setProtectedHeader({ alg: SIGNING_ALGORITHM, kid, typ: "JWT" })
    .setIssuer(args.issuer)
    .setAudience(args.clientId)
    .setIssuedAt()
    .setExpirationTime(`${ID_TOKEN_TTL_SECONDS}s`)
    .sign(privateJwk);
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
      claims: { sub: "key-check", connector: "key-check", connector_account_id: "key-check" },
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
