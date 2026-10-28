import { assertKeySetUsable } from "../client/jwt.js";
import {
  parseKeySet,
  rotateKeySet,
  rotateKeySetWithoutOverlap,
  type KeySet,
} from "../client/keys.js";

/**
 * `identity-broker keys --rotate`. The input is only parsed, so a key set whose current key cannot
 * sign, such as RSA under 2048 bits, can still be rotated out; the output must be usable. Its new
 * current key is fresh, so with overlap a failure comes from a key carried over as retired, which
 * only `--no-overlap` drops.
 */
export async function rotateKeys(raw: string, options: { overlap: boolean }): Promise<KeySet> {
  const input = parseKeySet(raw);
  if (!options.overlap) {
    const rotated = await rotateKeySetWithoutOverlap(input);
    await assertKeySetUsable(rotated);
    return rotated;
  }
  const rotated = await rotateKeySet(input);
  try {
    await assertKeySetUsable(rotated);
  } catch (error) {
    throw new Error(
      `${error instanceof Error ? error.message : String(error)}. That key is carried over as retired; rotate with --rotate --no-overlap to drop the retired keys at once.`,
      { cause: error },
    );
  }
  return rotated;
}
