import type { EmailConnector, SendEmailCode } from "./types.js";

/** A six-digit code sent by the host's action. The canonical address is the identity. */
export function email(options: { send: SendEmailCode; name?: string }): EmailConnector {
  return { kind: "email", name: options.name ?? "email", label: "Email", send: options.send };
}
