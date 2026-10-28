#!/usr/bin/env node
import { createKeySet, parseKeySet, rotateKeySet } from "../client/keys.js";

const USAGE = `identity-broker keys            print a new key set for IDENTITY_BROKER_KEYS
identity-broker keys --rotate   read the current key set on stdin, print the rotated one`;

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
  if (argv.includes("--rotate")) {
    const rotated = await rotateKeySet(parseKeySet(await readStdin()));
    process.stdout.write(`${JSON.stringify(rotated)}\n`);
    return 0;
  }
  process.stdout.write(`${JSON.stringify(await createKeySet())}\n`);
  return 0;
}

process.exitCode = await main(process.argv.slice(2));
