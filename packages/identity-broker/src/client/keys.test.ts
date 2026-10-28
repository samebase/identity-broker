import { createLocalJWKSet, decodeProtectedHeader, jwtVerify } from "jose";
import { describe, expect, test } from "vite-plus/test";
import { assertKeySetUsable, signIdToken } from "./jwt.js";
import {
  createKeySet,
  currentKey,
  KEY_OVERLAP_MS,
  parseKeySet,
  publicJwks,
  rotateKeySet,
  rotateKeySetWithoutOverlap,
} from "./keys.js";

describe("key set", () => {
  test("create, serialize, parse", async () => {
    const keySet = await createKeySet();
    expect(keySet.keys).toHaveLength(1);
    const parsed = parseKeySet(JSON.stringify(keySet));
    expect(parsed.pairwiseSalt).toBe(keySet.pairwiseSalt);
    const jwks = publicJwks(parsed);
    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0]).not.toHaveProperty("d");
    expect(jwks.keys[0]).toHaveProperty("kid");
  });

  test("rotation keeps the salt, retires the public half, drops it after the overlap", async () => {
    const first = await createKeySet();
    const now = 1_700_000_000_000;
    const rotated = await rotateKeySet(first, now);
    expect(rotated.pairwiseSalt).toBe(first.pairwiseSalt);
    expect(rotated.keys.map((key) => key.status)).toEqual(["current", "retired"]);
    const retired = rotated.keys[1];
    expect(retired?.status === "retired" && "d" in retired.publicJwk).toBe(false);
    expect(publicJwks(rotated, now).keys).toHaveLength(2);
    expect(publicJwks(rotated, now + KEY_OVERLAP_MS + 1).keys).toHaveLength(1);
    const again = await rotateKeySet(rotated, now + KEY_OVERLAP_MS + 1);
    expect(again.keys).toHaveLength(2);
  });

  test("rotation without overlap keeps the salt and only the new key", async () => {
    const first = await rotateKeySet(await createKeySet());
    const replaced = await rotateKeySetWithoutOverlap(first);
    expect(replaced.pairwiseSalt).toBe(first.pairwiseSalt);
    expect(replaced.keys.map((key) => key.status)).toEqual(["current"]);
    const oldKids = first.keys.map((key) => key.kid);
    expect(oldKids).not.toContain(replaced.keys[0]?.kid);
    expect(publicJwks(replaced).keys).toHaveLength(1);
  });

  test("refuses incomplete sets", async () => {
    expect(() => parseKeySet(undefined)).toThrow(/IDENTITY_BROKER_KEYS/);
    expect(() => parseKeySet("{}")).toThrow(/version 1/);
    const keySet = await createKeySet();
    const noCurrent = { ...keySet, keys: [] };
    expect(() => parseKeySet(JSON.stringify(noCurrent))).toThrow(/exactly one current/);
  });
});

describe("key set validation", () => {
  const RSA_PRIVATE_MEMBERS = ["n", "e", "d", "p", "q", "dp", "dq", "qi"] as const;

  /** The key set as JSON, with its one current key's privateJwk replaced. */
  function withPrivateJwk(
    keySet: Awaited<ReturnType<typeof createKeySet>>,
    privateJwk: Record<string, unknown>,
  ) {
    const { kid } = currentKey(keySet);
    return JSON.stringify({ ...keySet, keys: [{ kid, status: "current", privateJwk }] });
  }

  function without(record: Record<string, unknown>, name: string) {
    return Object.fromEntries(Object.entries(record).filter(([member]) => member !== name));
  }

  test("a key set from createKeySet, and its rotation, parse back unchanged and sign and verify", async () => {
    const created = await createKeySet();
    const rotated = await rotateKeySet(created);
    for (const keySet of [created, rotated]) {
      const parsed = parseKeySet(JSON.stringify(keySet));
      expect(parsed).toEqual(keySet);
      await expect(assertKeySetUsable(parsed)).resolves.toBeUndefined();
    }
  });

  test("the review's key set, an empty salt and a bare RSA key, is refused", async () => {
    const review = {
      version: 1,
      pairwiseSalt: "",
      keys: [{ kid: "k", status: "current", privateJwk: { kty: "RSA" } }],
    };
    expect(() => parseKeySet(JSON.stringify(review))).toThrow(
      "IDENTITY_BROKER_KEYS pairwiseSalt must be base64url of at least 16 bytes",
    );
    const { pairwiseSalt } = await createKeySet();
    expect(() => parseKeySet(JSON.stringify({ ...review, pairwiseSalt }))).toThrow(
      'IDENTITY_BROKER_KEYS key "k" privateJwk.n must be a non-empty base64url string',
    );
  });

  test("the salt must be base64url of at least 16 bytes", async () => {
    const keySet = await createKeySet();
    const parse = (pairwiseSalt: unknown) =>
      parseKeySet(JSON.stringify({ ...keySet, pairwiseSalt }));
    // 22 characters decode to 16 bytes, 21 to 15; a length of 4k + 1 decodes to nothing.
    for (const salt of [
      undefined,
      42,
      "",
      "A".repeat(21),
      "A".repeat(25),
      `${"A".repeat(22)}==`,
      `${"A".repeat(21)}+`,
    ]) {
      expect(() => parse(salt)).toThrow(/pairwiseSalt must be base64url of at least 16 bytes/);
    }
    expect(parse("A".repeat(22)).pairwiseSalt).toBe("A".repeat(22));
  });

  test("the current key must be an RSA private JWK with every member", async () => {
    const keySet = await createKeySet();
    const { kid, privateJwk } = currentKey(keySet);
    const where = `IDENTITY_BROKER_KEYS key "${kid}" privateJwk`;
    expect(() => parseKeySet(withPrivateJwk(keySet, { ...privateJwk, kty: "EC" }))).toThrow(
      `${where}.kty must be "RSA"`,
    );
    for (const member of RSA_PRIVATE_MEMBERS) {
      for (const jwk of [
        without(privateJwk, member),
        { ...privateJwk, [member]: "" },
        { ...privateJwk, [member]: 65537 },
        { ...privateJwk, [member]: "a+b/" },
      ]) {
        expect(() => parseKeySet(withPrivateJwk(keySet, jwk))).toThrow(
          `${where}.${member} must be a non-empty base64url string`,
        );
      }
    }
    expect(() => parseKeySet(withPrivateJwk(keySet, { ...privateJwk, alg: 256 }))).toThrow(
      `${where}.alg must be a string`,
    );
  });

  test("a retired key must be an RSA public JWK, and only its public members are kept", async () => {
    const rotated = await rotateKeySet(await createKeySet());
    const [current, retired] = rotated.keys;
    if (retired?.status !== "retired") {
      throw new Error("rotateKeySet retires the old key second");
    }
    const withPublicJwk = (publicJwk: Record<string, unknown>) =>
      JSON.stringify({ ...rotated, keys: [current, { ...retired, publicJwk }] });
    const where = `IDENTITY_BROKER_KEYS key "${retired.kid}" publicJwk`;
    expect(() => parseKeySet(withPublicJwk(without(retired.publicJwk, "kty")))).toThrow(
      `${where}.kty must be "RSA"`,
    );
    expect(() => parseKeySet(withPublicJwk({ ...retired.publicJwk, n: "" }))).toThrow(
      `${where}.n must be a non-empty base64url string`,
    );
    expect(() => parseKeySet(withPublicJwk(without(retired.publicJwk, "e")))).toThrow(
      `${where}.e must be a non-empty base64url string`,
    );
    const leaked = parseKeySet(withPublicJwk({ ...retired.publicJwk, d: "AQAB" }));
    expect(leaked.keys[1]).toEqual(retired);
    expect(publicJwks(leaked).keys[1]).not.toHaveProperty("d");
  });

  test("an RSA key under 2048 bits passes the shape check and fails at signing", async () => {
    const keySet = await createKeySet();
    const { kid } = currentKey(keySet);
    const small = await crypto.subtle.generateKey(
      {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 1024,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["sign", "verify"],
    );
    const privateJwk = await crypto.subtle.exportKey("jwk", small.privateKey);
    const parsed = parseKeySet(withPrivateJwk(keySet, { ...privateJwk, kid, use: "sig" }));
    await expect(assertKeySetUsable(parsed)).rejects.toThrow(
      `IDENTITY_BROKER_KEYS key "${kid}" fails at sign: RS256 requires key modulusLength to be 2048 bits or larger`,
    );
  });

  test("the JWKS publishes the current key under its entry's kid, so a token signed with it verifies", async () => {
    const keySet = await createKeySet();
    const { kid, privateJwk } = currentKey(keySet);
    const parsed = parseKeySet(withPrivateJwk(keySet, { ...privateJwk, kid: "another-kid" }));
    expect(publicJwks(parsed).keys.map((jwk) => jwk.kid)).toEqual([kid]);
    const token = await signIdToken({
      keySet: parsed,
      issuer: "https://auth.test",
      clientId: "cl_test",
      claims: { sub: "s", connector: "fake" },
      authTime: Date.now(),
      nonce: undefined,
    });
    expect(decodeProtectedHeader(token).kid).toBe(kid);
    await expect(
      jwtVerify(token, createLocalJWKSet(publicJwks(parsed)), {
        issuer: "https://auth.test",
        audience: "cl_test",
      }),
    ).resolves.toMatchObject({ payload: { sub: "s" } });
    await expect(assertKeySetUsable(parsed)).resolves.toBeUndefined();
  });

  test("a key the JWKS publishes for another algorithm fails at verification, current or retired", async () => {
    const rotated = await rotateKeySet(await createKeySet());
    const [current, retired] = rotated.keys;
    if (current?.status !== "current" || retired?.status !== "retired") {
      throw new Error("rotateKeySet puts the new key first and the retired key second");
    }
    await expect(
      assertKeySetUsable({
        ...rotated,
        keys: [{ ...current, privateJwk: { ...current.privateJwk, alg: "RS512" } }, retired],
      }),
    ).rejects.toThrow(`IDENTITY_BROKER_KEYS key "${current.kid}" fails at verify`);
    await expect(
      assertKeySetUsable({
        ...rotated,
        keys: [current, { ...retired, publicJwk: { ...retired.publicJwk, alg: "RS512" } }],
      }),
    ).rejects.toThrow(`IDENTITY_BROKER_KEYS key "${retired.kid}" fails at verify`);
  });
});
