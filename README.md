# Unlatch

Unlatch is a single sign-on server you host yourself. It speaks OpenID Connect, so people sign in
once and can then use every service you connect to it, such as Grafana, Forgejo or Nextcloud. It is
written in Rust with few dependencies and runs as one binary with one SQLite file.

It is at an early stage: the design is written, the code is not.

## Planned features

- Sign-in with a password and a code from an authenticator app, or with Google and other OpenID
  providers.
- OpenID Connect for applications that support it.
- Forward authentication through nginx, Traefik or Caddy for applications that don't.
- A web interface for managing applications, users, groups and sessions.

## Documentation

- [Architecture](docs/architecture.md): how Unlatch works, why, and what is left out on purpose.
- [Threat model](docs/threat-model.md): what it protects against and what it doesn't.
- [Contributing](CONTRIBUTING.md)
- [Reporting a vulnerability](SECURITY.md)

## License

[MIT](LICENSE)
