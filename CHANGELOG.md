# Changelog

## Unreleased

- Buttons for GitHub sign-in show the GitHub mark, as Google's show Google's.

## 0.1.0

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
