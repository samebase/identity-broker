import { exportJWK, generateKeyPair, importJWK, type CryptoKey, type JWK } from "jose";
import { asRecord } from "./protocol.js";

export const SIGNING_ALGORITHM = "RS256";

/** How long a retired key's public half stays in the JWKS: longer than any token it signed lives. */
export const KEY_OVERLAP_MS = 14 * 24 * 60 * 60 * 1000;

/**
 * The content of the `IDENTITY_BROKER_KEYS` env var: one current private key, the public halves of
 * recently retired keys, and the pairwise salt. `identity-broker keys` writes it.
 */
export type KeySet = {
  version: 1;
  /** Created once with the first key set and never rotated: a new salt changes every subject. */
  pairwiseSalt: string;
  keys: Array<
    | { kid: string; status: "current"; privateJwk: JWK }
    | { kid: string; status: "retired"; retiredAt: number; publicJwk: JWK }
  >;
};

const PRIVATE_MEMBERS = ["d", "p", "q", "dp", "dq", "qi", "oth"] as const;

function publicHalf(jwk: JWK): JWK {
  const copy: JWK = { ...jwk };
  for (const member of PRIVATE_MEMBERS) {
    delete copy[member];
  }
  return copy;
}

function randomKid(): string {
  const bytes = new Uint8Array(12);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function randomSalt(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function freshKey(): Promise<{ kid: string; privateJwk: JWK }> {
  const kid = randomKid();
  const { privateKey } = await generateKeyPair(SIGNING_ALGORITHM, { extractable: true });
  const privateJwk = await exportJWK(privateKey);
  return { kid, privateJwk: { ...privateJwk, kid, alg: SIGNING_ALGORITHM, use: "sig" } };
}

/** A new key set: one current key and a salt. */
export async function createKeySet(): Promise<KeySet> {
  const key = await freshKey();
  return { version: 1, pairwiseSalt: randomSalt(), keys: [{ status: "current", ...key }] };
}

/**
 * Rotation: the current key keeps only its public half and a retirement time, a new key becomes
 * current, and keys retired longer than the overlap window drop out. The salt never changes.
 */
export async function rotateKeySet(keySet: KeySet, now = Date.now()): Promise<KeySet> {
  const key = await freshKey();
  const kept = keySet.keys.flatMap((entry) => {
    if (entry.status === "current") {
      return [
        {
          kid: entry.kid,
          status: "retired" as const,
          retiredAt: now,
          publicJwk: publicHalf(entry.privateJwk),
        },
      ];
    }
    return entry.retiredAt + KEY_OVERLAP_MS > now ? [entry] : [];
  });
  return {
    version: 1,
    pairwiseSalt: keySet.pairwiseSalt,
    keys: [{ status: "current", ...key }, ...kept],
  };
}

/**
 * Rotation after a key compromise: a new current key and no retired keys, so every token signed
 * before stops verifying at once. The salt never changes.
 */
export async function rotateKeySetWithoutOverlap(keySet: KeySet): Promise<KeySet> {
  const key = await freshKey();
  return { version: 1, pairwiseSalt: keySet.pairwiseSalt, keys: [{ status: "current", ...key }] };
}

/**
 * Unpadded base64url (RFC 7515 section 2) of a length that decodes, so not 4k + 1: the encoding of
 * JWK members (RFC 7518 section 6.3) and of the pairwise salt.
 */
const BASE64URL = /^(?:[A-Za-z0-9_-]{4})*[A-Za-z0-9_-]{2,4}$/;

/** The members of an RSA private JWK (RFC 7518 section 6.3); a current key carries every one. */
const RSA_PRIVATE_MEMBERS = ["n", "e", "d", "p", "q", "dp", "dq", "qi"] as const;
const RSA_PUBLIC_MEMBERS = ["n", "e"] as const;
/** What `createKeySet` writes beside the key material, and the JWKS publishes. */
const JWK_PARAMETERS = ["kid", "alg", "use"] as const;

/**
 * An RSA JWK whose `members` are base64url strings, rebuilt from those members and the string
 * parameters, so a private member left in a retired public key never reaches the JWKS. `where`
 * names the JWK in the error.
 */
function rsaJwk(
  value: unknown,
  where: string,
  members: ReadonlyArray<(typeof RSA_PRIVATE_MEMBERS)[number]>,
): JWK {
  const record = asRecord(value);
  if (record["kty"] !== "RSA") {
    throw new Error(`${where}.kty must be "RSA"`);
  }
  const jwk: JWK = { kty: "RSA" };
  for (const name of members) {
    const member = record[name];
    if (typeof member !== "string" || !BASE64URL.test(member)) {
      throw new Error(`${where}.${name} must be a non-empty base64url string`);
    }
    jwk[name] = member;
  }
  for (const name of JWK_PARAMETERS) {
    const parameter = record[name];
    if (typeof parameter === "string") {
      jwk[name] = parameter;
    } else if (parameter !== undefined) {
      throw new Error(`${where}.${name} must be a string`);
    }
  }
  return jwk;
}

/**
 * Parses the env var. Throws on anything that is not a complete key set: a hub without keys is
 * down. It checks the shape only; `assertKeySetUsable` signs and verifies with the keys.
 */
export function parseKeySet(raw: string | undefined): KeySet {
  if (raw === undefined || raw.trim().length === 0) {
    throw new Error(
      "IDENTITY_BROKER_KEYS is not set; run `identity-broker keys` and store its output",
    );
  }
  const record = asRecord(JSON.parse(raw));
  if (record["version"] !== 1 || !Array.isArray(record["keys"])) {
    throw new Error("IDENTITY_BROKER_KEYS is not a version 1 key set");
  }
  // `createKeySet` writes 32 random bytes. A short salt lets anyone who knows an upstream id, such
  // as a public GitHub user id, compute its subject for an app.
  const salt = record["pairwiseSalt"];
  if (typeof salt !== "string" || !BASE64URL.test(salt) || Math.floor((salt.length * 3) / 4) < 16) {
    throw new Error("IDENTITY_BROKER_KEYS pairwiseSalt must be base64url of at least 16 bytes");
  }
  const keys = record["keys"].map((entry: unknown): KeySet["keys"][number] => {
    const key = asRecord(entry);
    const kid = key["kid"];
    if (typeof kid !== "string") {
      throw new Error("IDENTITY_BROKER_KEYS has a key without kid");
    }
    const where = `IDENTITY_BROKER_KEYS key "${kid}"`;
    if (key["status"] === "current") {
      return {
        kid,
        status: "current",
        privateJwk: rsaJwk(key["privateJwk"], `${where} privateJwk`, RSA_PRIVATE_MEMBERS),
      };
    }
    if (key["status"] === "retired" && typeof key["retiredAt"] === "number") {
      return {
        kid,
        status: "retired",
        retiredAt: key["retiredAt"],
        publicJwk: rsaJwk(key["publicJwk"], `${where} publicJwk`, RSA_PUBLIC_MEMBERS),
      };
    }
    throw new Error(`${where} is neither current nor retired`);
  });
  if (keys.filter((key) => key.status === "current").length !== 1) {
    throw new Error("IDENTITY_BROKER_KEYS must hold exactly one current key");
  }
  return { version: 1, pairwiseSalt: salt, keys };
}

export function currentKey(keySet: KeySet): { kid: string; privateJwk: JWK } {
  const key = keySet.keys.find((entry) => entry.status === "current");
  if (key === undefined || key.status !== "current") {
    throw new Error("The key set has no current key");
  }
  return { kid: key.kid, privateJwk: key.privateJwk };
}

export async function importSigningKey(keySet: KeySet): Promise<{ kid: string; key: CryptoKey }> {
  const { kid, privateJwk } = currentKey(keySet);
  const key = await importJWK(privateJwk, SIGNING_ALGORITHM);
  if (typeof key === "string" || !("type" in key)) {
    throw new Error("The current key is not an asymmetric key");
  }
  return { kid, key };
}

/**
 * The public JWKS: the current key and the retired keys still inside the overlap window, each under
 * its entry's kid, the kid the signer writes into a token header, whatever kid its JWK carries.
 */
export function publicJwks(
  keySet: KeySet,
  now = Date.now(),
): { keys: Array<JWK & { kid: string }> } {
  return {
    keys: keySet.keys.flatMap((entry) => {
      if (entry.status === "current") {
        return [{ ...publicHalf(entry.privateJwk), kid: entry.kid }];
      }
      return entry.retiredAt + KEY_OVERLAP_MS > now ? [{ ...entry.publicJwk, kid: entry.kid }] : [];
    }),
  };
}
