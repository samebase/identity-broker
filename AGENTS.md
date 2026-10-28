# AGENTS.md

An OpenID Provider for Convex that keeps no user accounts. See README.md for what it does and
docs/design.md for the decisions.

## Layout

- `packages/identity-broker/src/component`: the Convex component: tables and the state machine of an
  authorization request. Runs inside the component; cannot read env or `ctx.auth`.
- `packages/identity-broker/src/client`: the host-side endpoints (`defineIdentityBroker`), the
  connectors, key handling and JWT signing. Runs in the host's HTTP actions.
- `packages/identity-broker/src/cli`: `identity-broker keys`.
- `packages/alchemy-identity-hub/src`: `IdentityHub.Client`, the Alchemy v2 resource that registers
  a deployment at the hub's `/register`. Its peer is the `alchemy` version that consumers pin.
- `_generated` is Convex codegen output: `pnpm run codegen` after a schema or function change, from
  an anonymous local deployment (`CONVEX_AGENT_MODE=anonymous npx convex dev --once` first).

## Commands

From the repository root, with pnpm 12 and the Node version in `.node-version`:

- `pnpm install`, then `pnpm run check`: format check, lint, typecheck, tests.
- `pnpm run format`, `pnpm run lint`, `pnpm run test`, `pnpm run build`.

## Rules

- Never use the U+2014 em dash character anywhere in the repository.
- Standards first: OAuth 2.1, OIDC Core and Discovery, RFC 7591, RFC 8414, RFC 9207, RFC 9700. A
  departure is a named decision in docs/design.md, not an accident.
- No `any`, no type assertions except `as const`; declare a type gap with the narrowest
  `@ts-expect-error` and the runtime fact.
- Validate everything that comes from a request or an upstream provider at runtime.
- Delete-first: no helper, flag or compatibility path that the current design does not need. No
  backwards compatibility with earlier versions of this package.
- Tests use real provider payloads, mutated only for negative cases, and `openid-client` as the
  independent relying party.
- Never log tokens, codes, secrets or email addresses.
