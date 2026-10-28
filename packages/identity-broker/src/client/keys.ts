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

function isJwk(value: unknown): value is JWK {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as { kty?: unknown }).kty === "string"
  );
}

/** Parses the env var. Throws on anything that is not a complete key set: a hub without keys is down. */
export function parseKeySet(raw: string | undefined): KeySet {
  if (raw === undefined || raw.trim().length === 0) {
    throw new Error(
      "IDENTITY_BROKER_KEYS is not set; run `identity-broker keys` and store its output",
    );
  }
  const record = asRecord(JSON.parse(raw));
  if (
    record["version"] !== 1 ||
    typeof record["pairwiseSalt"] !== "string" ||
    !Array.isArray(record["keys"])
  ) {
    throw new Error("IDENTITY_BROKER_KEYS is not a version 1 key set");
  }
  const keys = record["keys"].map((entry: unknown): KeySet["keys"][number] => {
    const key = asRecord(entry);
    if (typeof key["kid"] !== "string") {
      throw new Error("IDENTITY_BROKER_KEYS has a key without kid");
    }
    if (key["status"] === "current" && isJwk(key["privateJwk"])) {
      return { kid: key["kid"], status: "current", privateJwk: key["privateJwk"] };
    }
    if (
      key["status"] === "retired" &&
      typeof key["retiredAt"] === "number" &&
      isJwk(key["publicJwk"])
    ) {
      return {
        kid: key["kid"],
        status: "retired",
        retiredAt: key["retiredAt"],
        publicJwk: key["publicJwk"],
      };
    }
    throw new Error(`IDENTITY_BROKER_KEYS key "${key["kid"]}" is neither current nor retired`);
  });
  if (keys.filter((key) => key.status === "current").length !== 1) {
    throw new Error("IDENTITY_BROKER_KEYS must hold exactly one current key");
  }
  return { version: 1, pairwiseSalt: record["pairwiseSalt"], keys };
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

/** The public JWKS: the current key and the retired keys still inside the overlap window. */
export function publicJwks(keySet: KeySet, now = Date.now()): { keys: JWK[] } {
  return {
    keys: keySet.keys.flatMap((entry) => {
      if (entry.status === "current") {
        return [publicHalf(entry.privateJwk)];
      }
      return entry.retiredAt + KEY_OVERLAP_MS > now ? [{ ...entry.publicJwk, kid: entry.kid }] : [];
    }),
  };
}
