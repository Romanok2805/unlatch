# Unlatch

Unlatch is a single sign-on server you host yourself. It speaks OpenID Connect, so people sign in
once and can then use every service you connect to it, such as Grafana, Forgejo or Nextcloud. It is
written in Rust with few dependencies and runs as one binary with one SQLite file.

Unlatch is young: it hasn't been audited or certified yet.

## Features

- Sign-in with a password and a code from an authenticator app, or with Google, GitHub and other
  OpenID providers.
- OpenID Connect for applications that support it.
- Forward authentication through nginx, Traefik or Caddy for applications that don't.
- A web interface for applications, users, groups, sessions and sign-in providers.

## Getting started

Build it with `cargo build --release`, then create a master key and start it:

```sh
unlatch generate-key > /etc/unlatch/key
UNLATCH_ISSUER=https://login.example.com UNLATCH_KEY_FILE=/etc/unlatch/key unlatch
```

The log shows a link that creates the first administrator. The administrator then adds
applications in the web interface, where each shows the values to copy into it.

## Documentation

- [Running Unlatch](docs/running.md): systemd, reverse proxy and backups.
- [Configuration](docs/configuration.md): every setting.
- [Forward authentication](docs/forward-auth.md): protecting services without OpenID Connect.
- [Architecture](docs/architecture.md): how Unlatch works, why, and what is left out on purpose.
- [Threat model](docs/threat-model.md): what it protects against and what it doesn't.
- [Contributing](CONTRIBUTING.md)
- [Reporting a vulnerability](SECURITY.md)

## License

[MIT](LICENSE)
