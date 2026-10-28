import { expect, test } from "vite-plus/test";
import { assertKeySetUsable } from "../client/jwt.js";
import { createKeySet, currentKey, parseKeySet } from "../client/keys.js";
import { rotateKeys } from "./rotate.js";

/** A key set whose current key is RSA 1024: `parseKeySet` accepts it, the signer refuses it. */
async function weakKeySet(): Promise<string> {
  const keySet = await createKeySet();
  const { kid } = currentKey(keySet);
  const pair = await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 1024,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  );
  const privateJwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
  return JSON.stringify({
    ...keySet,
    keys: [{ kid, status: "current", privateJwk: { ...privateJwk, kid, use: "sig" } }],
  });
}

test("rotation checks its output, so a key that cannot sign leaves with --no-overlap", async () => {
  const usable = JSON.stringify(await createKeySet());
  const weak = await weakKeySet();
  await expect(assertKeySetUsable(parseKeySet(weak))).rejects.toThrow(/fails at sign/);
  // The input is usable or its current key cannot sign; the rotation keeps the retired key or not.
  for (const [input, overlap, statuses] of [
    [usable, true, ["current", "retired"]],
    [usable, false, ["current"]],
    [weak, false, ["current"]],
  ] as const) {
    const rotated = await rotateKeys(input, { overlap });
    expect(rotated.keys.map((key) => key.status)).toEqual(statuses);
    expect(rotated.pairwiseSalt).toBe(parseKeySet(input).pairwiseSalt);
    await expect(assertKeySetUsable(rotated)).resolves.toBeUndefined();
  }
  const { kid } = currentKey(parseKeySet(weak));
  await expect(rotateKeys(weak, { overlap: true })).rejects.toThrow(
    `IDENTITY_BROKER_KEYS key "${kid}" fails at verify: RS256 requires key modulusLength to be 2048 bits or larger. That key is carried over as retired; rotate with --rotate --no-overlap to drop the retired keys at once.`,
  );
  // An input that is not a key set is refused before anything rotates.
  for (const overlap of [true, false]) {
    await expect(rotateKeys("{}", { overlap })).rejects.toThrow(/not a version 1 key set/);
  }
});
