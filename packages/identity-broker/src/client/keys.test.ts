import { describe, expect, test } from "vite-plus/test";
import { createKeySet, KEY_OVERLAP_MS, parseKeySet, publicJwks, rotateKeySet } from "./keys.js";

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

  test("refuses incomplete sets", async () => {
    expect(() => parseKeySet(undefined)).toThrow(/IDENTITY_BROKER_KEYS/);
    expect(() => parseKeySet("{}")).toThrow(/version 1/);
    const keySet = await createKeySet();
    const noCurrent = { ...keySet, keys: [] };
    expect(() => parseKeySet(JSON.stringify(noCurrent))).toThrow(/exactly one current/);
  });
});
