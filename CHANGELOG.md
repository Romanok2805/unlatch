# Changelog

## Unreleased

- The log warns when sign-in attempts hit their limit and when an authorization code or refresh
  token is used a second time, which revokes its grant. Both can mean an attack, and before they
  were refused without a word to the operator.

## 0.3.1 - 2026-10-23

- When it stops, Unlatch closes the database before exiting, so the database file is complete on
  its own and no write-ahead log is left next to it.

## 0.3.0 - 2026-10-23

- A sign-in provider can skip the two-factor code, for providers whose accounts have two-factor
  sign-in of their own. Administration still asks for it. The database moves to schema
  version 4.
- The copy of the database that Unlatch saves before a migration is readable only by its owner,
  like the database itself.

## 0.2.0 - 2026-10-22

- Buttons for GitHub sign-in show the GitHub mark, as Google's show Google's.
- TOTP secrets that use SHA-256, for accounts moved from another provider. The database
  moves to schema version 2, which records each user's algorithm.
- The account page lists the applications the user may use, with links to them.
- The recovery code page links back to the code from the authenticator app.
- Passkeys. People add them on their account page and sign in with one in place of a password and
  a code; administration takes one in place of a code. The database moves to schema version 3.
- On the consent page, each permission stands next to its icon again.
- Buttons that need scripts stay hidden when scripts are off.

## 0.1.0 - 2026-10-22

The first release.

- Sign-in with a password and TOTP, recovery codes, and outside providers: any OpenID Connect
  provider and GitHub.
- OpenID Connect for applications: the authorization code flow with PKCE, refresh tokens,
  client credentials, userinfo, introspection, revocation, `form_post`, RP-initiated and
  back-channel logout.
- Pushed authorization requests (RFC 9126) and DPoP-bound tokens (RFC 9449).
- Forward authentication for Caddy, Traefik and nginx.
- A web interface for applications, users, groups, sessions and sign-in providers,
  in English and Russian.
- Optional built-in TLS that picks up renewed certificates.
- Static Linux binaries for x86-64 and ARM64 and a container image.
