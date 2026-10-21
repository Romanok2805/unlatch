# Threat model

What Unlatch protects, from whom, and where in [the architecture](architecture.md) each defence is
described.

## What an attacker wants

Passwords, TOTP secrets and recovery codes; sessions, authorization codes and tokens; the private
signing keys and the key that encrypts secrets in the database; administrator access. Any of these
opens the services behind Unlatch.

## Who might attack

- Anyone on the internet who can open the sign-in page.
- An application connected to Unlatch that is malicious or has been hacked.
- A user of one connected service who wants into another.
- Someone with a copy of the database or a backup.
- The author of a malicious dependency.

## Boundaries

```
browser ── reverse proxy ── Unlatch ── SQLite file
                               │  └─── encryption key (file or environment)
                               ├─── outside sign-in providers
                               └─── connected applications (back-channel logout)
```

We trust the machine Unlatch runs on, its configuration and its administrator. Everything that
arrives over the network is untrusted, including connected applications and outside providers.

## Threats

| Threat | Defence |
|---|---|
| Guessing passwords, credential stuffing | [Attempt limits, Argon2id, TOTP](architecture.md#signing-in) |
| Finding out which accounts exist | [Dummy hash for unknown names](architecture.md#signing-in) |
| Guessing or reusing a TOTP code | [Single-use codes, attempt limits](architecture.md#signing-in) |
| Taking over a fresh installation | [One-time setup token](architecture.md#signing-in) |
| Taking over an account through an outside provider | [Linking by issuer and subject](architecture.md#signing-in) |
| Stealing or fixing a session | [Cookie flags, new ID at sign-in, expiry](architecture.md#sessions-and-pages) |
| Cross-site request forgery | [CSRF tokens](architecture.md#sessions-and-pages) |
| Cross-site scripting | [`Html` type, CSP, Trusted Types](architecture.md#sessions-and-pages) |
| Showing the sign-in page in a hidden frame | [Framing forbidden by CSP](architecture.md#sessions-and-pages) |
| Malicious uploaded files | [PNG and WebP only, sandbox](architecture.md#sessions-and-pages) |
| Making Unlatch fetch internal addresses | [No fetching of user-supplied addresses](architecture.md#sessions-and-pages) |
| Open redirects, altered redirect URIs | [Exact match, error page](architecture.md#openid-connect) |
| Mixing up responses from two providers | [`iss` in responses](architecture.md#openid-connect) |
| Intercepted or replayed authorization codes | [PKCE, single-use codes](architecture.md#tokens) |
| Using a token at the wrong service | [Audience, `at+jwt`](architecture.md#tokens) |
| Stolen refresh token | [Rotation, reuse revokes the session](architecture.md#tokens) |
| Keeping access after removal from a group | [Checks on every refresh](architecture.md#tokens) |
| Stolen signing key | [Rotation](architecture.md#tokens), [encryption at rest](architecture.md#storage) |
| Stolen database or backup | [Hashes and encryption](architecture.md#storage) |
| Faked identity headers in forward auth | [Proxy removes them](architecture.md#forward-authentication) |
| Faked `X-Forwarded-*` or `Host` headers | [Trusted proxy list, fixed issuer](architecture.md#network) |
| Running out of memory or connections | [Limits](architecture.md#network), [hashing queue](architecture.md#signing-in) |
| Malicious dependency | [Dependency review](../CONTRIBUTING.md#adding-a-dependency), `deny.toml`, CI actions pinned by commit |

## Not covered

- An attacker who controls the server, its configuration or the encryption key.
- A malicious administrator.
- A hacked browser or device on the user's side.
- Vulnerabilities in the connected applications themselves.
