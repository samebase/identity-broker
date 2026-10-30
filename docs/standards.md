# Standards

The broker invents as little as it can. This page lists every standard it relies on, the sections it
relies on, and how far it goes. "Implemented" describes the use named in the row, not the whole
document. A deliberate difference is a named departure in [design.md](design.md).

## Protocol

| Standard                                                                                                 | Sections                       | Used for                                                                  | Status                                               |
| -------------------------------------------------------------------------------------------------------- | ------------------------------ | ------------------------------------------------------------------------- | ---------------------------------------------------- |
| [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749.html), OAuth 2.0                                       | 2, 3, 4.1, 5, Appendix B       | Confidential clients, Basic and body credentials, the code grant, errors  | Partly: the code grant and confidential clients only |
| [OAuth 2.1, draft 16](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/16/)                        | 2.4, 4.1                       | The code flow with mandatory S256, and `iss` on responses                 | Partly: a draft, so it can change                    |
| [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html), PKCE                                            | 4.1 to 4.6                     | S256 challenge and verifier, in both directions                           | Implemented, S256 only                               |
| [OpenID Connect Core 1.0, errata set 2](https://openid.net/specs/openid-connect-core-1_0.html)           | 2, 3.1, 5.1 to 5.4, 8.1, 9, 10 | ID Tokens, claims, UserInfo, pairwise subjects, signing                   | Partly: see the departures in [design.md](design.md) |
| [OpenID Connect Discovery 1.0, errata set 2](https://openid.net/specs/openid-connect-discovery-1_0.html) | 3, 4                           | The provider's metadata, and reading an upstream provider's               | Implemented                                          |
| [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414.html)                                                  | 2, 3                           | OAuth server metadata and its well-known location                         | Implemented                                          |
| [RFC 9207](https://www.rfc-editor.org/rfc/rfc9207.html)                                                  | 2, 3                           | `iss` on authorization responses, and checking it upstream                | Implemented                                          |
| [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html), OAuth security BCP                              | 2.1.1, 4.1.3, 4.4, 4.7, 4.16   | PKCE, exact redirects, mix-up and CSRF defenses, browser binding, framing | Implemented for these sections                       |
| [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750.html), Bearer tokens                                   | 2.1, 3                         | The UserInfo endpoint and its challenges                                  | Implemented, the header method only                  |

## Tokens and keys

The broker signs and verifies through [`jose`](https://github.com/panva/jose), and talks to upstream
providers through [`oauth4webapi`](https://github.com/panva/oauth4webapi).

| Standard                                                     | Sections | Used for                          | Status                  |
| ------------------------------------------------------------ | -------- | --------------------------------- | ----------------------- |
| [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519.html), JWT | 4, 7     | Token claims, signing, validation | Implemented             |
| [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.html), JWS | 2, 4, 5  | Compact signatures and headers    | Implemented             |
| [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html), JWA | 3.3, 6.3 | RS256 and RSA key parameters      | Implemented, RS256 only |
| [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517.html), JWK | 4, 5     | Keys and the public key set       | Implemented             |

## The web underneath

| Standard                                                                                                                                                                  | Sections                   | Used for                                            | Status                          |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------- | --------------------------------------------------- | ------------------------------- |
| [RFC 6265](https://www.rfc-editor.org/rfc/rfc6265.html) and [6265bis, draft 22](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis-22)                   | 4.1, 4.2; 4.1.2.7, 4.1.3.2 | `Secure`, `HttpOnly`, `SameSite=Lax`, and `__Host-` | Implemented; 6265bis is a draft |
| [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html), HTTP                                                                                                             | 8.3, 11.6.1, 15.5.2        | Media types, authentication, status codes           | Implemented                     |
| [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986.html), [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648.html), [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259.html) | 6.2.1; 5; 4, 8.1           | URI comparison, base64url, JSON                     | Implemented                     |

## Client registration

A client gets its id and secret from the administrator of the hub, through the internal function
`registerClient`. No standard covers this step, and none needs to: RFC 6749 section 2 leaves the
means of registration open, as in a provider's own console. After that, the client is an ordinary
confidential OAuth client.

## Not implemented

- RFC 7591 and RFC 7592, and OpenID Connect Dynamic Client Registration: there is no public
  registration endpoint.
- Refresh tokens: apps keep their own sessions.
- Request Objects: `request` and `request_uri` answer `request_not_supported` and
  `request_uri_not_supported`.
- The implicit and hybrid flows, and session management and logout.

## Certification

The broker is not OpenID Certified, and the conformance suite has not been run against it. The
Config OP profile is the realistic first target. The Basic OP test plan cannot pass as it stands,
because its requests omit PKCE, which the broker requires.
