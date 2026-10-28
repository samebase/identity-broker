#!/usr/bin/env node
import { createKeySet } from "../client/keys.js";
import { rotateKeys } from "./rotate.js";

const USAGE = `identity-broker keys                         print a new key set for IDENTITY_BROKER_KEYS
identity-broker keys --rotate                read the current key set on stdin, print the
                                             rotated one once it signs and verifies; the
                                             retired public key stays for 14 days
identity-broker keys --rotate --no-overlap   the same after a key compromise: retired keys are
                                             dropped at once; the salt is kept`;

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function main(argv: string[]): Promise<number> {
  if (argv[0] !== "keys") {
    console.error(USAGE);
    return 2;
  }
  const rotate = argv.includes("--rotate");
  const noOverlap = argv.includes("--no-overlap");
  // Without --rotate, --no-overlap would print a new key set with a new salt: every sub changes.
  if (noOverlap && !rotate) {
    console.error(USAGE);
    return 2;
  }
  if (rotate) {
    const rotated = await rotateKeys(await readStdin(), { overlap: !noOverlap });
    process.stdout.write(`${JSON.stringify(rotated)}\n`);
    return 0;
  }
  process.stdout.write(`${JSON.stringify(await createKeySet())}\n`);
  return 0;
}

process.exitCode = await main(process.argv.slice(2));
