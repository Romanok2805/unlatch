# Comparison

How Unlatch 0.3 differs from other single sign-on servers you can host yourself. What this page
says about the others comes from their own documentation and code as of 23 October 2026; the
versions and sources are [at the end](#sources). If something is wrong or out of date, please open
an issue.

| | Unlatch | Pocket ID | Authelia | Kanidm | Rauthy | authentik |
|---|---|---|---|---|---|---|
| **Running it** | | | | | | |
| Written in | Rust | Go | Go | Rust | Rust | Python, Rust, Go |
| Parts | One binary, SQLite | One binary, SQLite or PostgreSQL | One binary, SQLite, PostgreSQL or MySQL | One server with its own database | One binary, its own database or PostgreSQL | Server, worker, PostgreSQL |
| Memory | 6.5–7.3 MiB | 64–69 MiB | 106–125 MiB | 64 KB per entry | 40–57 MB | Hosts from 2 GB |
| Administration | Browser | Browser | Configuration files | Mostly command line | Browser | Browser |
| Users kept in | Its database | Its database, or synced from LDAP | A file or LDAP | Its database | Its database | Its database, LDAP and others |
| Needs email | No | No | Yes | No | For some tasks | No |
| Several servers | No | No | Yes | Two at most | Yes | Yes |
| **Signing in** | | | | | | |
| Passkeys | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Password and TOTP | ✓ | – | ✓ | ✓ | Password, no TOTP | ✓ |
| Google, GitHub, OpenID | ✓ | – | – | – | ✓ | ✓ |
| **For applications** | | | | | | |
| OpenID Connect | ✓ | ✓ | Beta | ✓ | ✓ | ✓ |
| Forward auth | ✓ | – | ✓ | – | ✓ | ✓ |
| LDAP | – | – | – | Read-only | – | ✓ |
| SAML | – | – | – | – | – | ✓ |
| PAR | ✓ | ✓ | ✓ | – | – | – |
| DPoP | ✓ | – | – | – | ✓ | ID tokens only |
| Sign-out | Both | Both | – | – | Both | Both |
| Device sign-in | – | ✓ | ✓ | – | ✓ | ✓ |
| **Trust** | | | | | | |
| OpenID certified | – | ✓ | ✓ | – | – | ✓ |
| Published audit | – | – | – | – | ✓ | ✓ |
| License | MIT | BSD-2-Clause | Apache-2.0 | MPL-2.0 | Apache-2.0 | MIT, parts enterprise |

*Sign-out* is RP-initiated and back-channel logout; *Both* means an application can end the
session at the server and hear when it ends there. *Device sign-in* is the device authorization
grant, for TVs and command line tools.

The memory of Unlatch 0.2.0, Pocket ID 2.19.1 and Authelia 4.39.28 was measured on one machine,
from their Linux release binaries with default settings, Authelia with OpenID Connect and one
client: resident memory 30 seconds after start, then its peak while 20 clients fetched the sign-in
page 6,000 times. Each figure is the median of three runs. Pocket ID and Authelia answer with a page
that a script finishes in the browser, Unlatch with the finished form. Authelia drops to about 87
MiB after five minutes at rest. The other three figures are what their documentation states.

## Where Unlatch stands out

- **Small.** One 9 MB binary and one SQLite file, 6.5 MiB of memory at rest. In the same test
  Pocket ID held 64 MiB and Authelia 106 MiB; Rauthy states 40 to 57 MB, and authentik asks for a
  host with 2 GB.
- **Everything in the browser, nothing by email.** Applications, users, groups, sessions and
  sign-in providers are managed in the web interface. Invitations and lost passwords are links an
  administrator hands over, so there is no mail server to set up.
- **All the usual ways to sign in at once.** Passkeys, a password with a code from an
  authenticator app, and Google, GitHub or any OpenID provider. Pocket ID has only passkeys;
  Authelia and Kanidm don't offer sign-in through other providers.
- **Current OAuth security.** Pushed authorization requests and DPoP-bound tokens. Of the others,
  Pocket ID and Authelia have the first and Rauthy the second.
- **Forward authentication built in**, for services that don't speak OpenID Connect.

## When to choose something else

Unlatch is young. It hasn't been audited or certified, runs on one server, and has no LDAP, SAML
or device sign-in. Choose:

- **Pocket ID** if everyone signs in with passkeys and you want an OpenID certified server.
- **Authelia** if your users are already in LDAP and you mostly protect sites through a reverse
  proxy.
- **Kanidm** if you also need LDAP, RADIUS, or Unix and SSH accounts from the same server.
- **Rauthy** if you need several servers and an audited code base.
- **authentik** if you need SAML, LDAP, RADIUS or sign-in flows of your own design, and have the
  memory to spare.
- **Keycloak** or **Zitadel** for a large organisation with many tenants. Both have SAML and much
  more, and both need a separate database. Keycloak, in Java, recommends 2 GB of memory for a small
  production setup; Zitadel, in Go under the AGPL, takes about 512 MB besides PostgreSQL.

## Sources

- **Pocket ID 2.19.1**: [documentation](https://pocket-id.org/docs),
  [sign-in methods](https://pocket-id.org/docs/guides/sign-in-methods),
  [proxy services](https://pocket-id.org/docs/guides/proxy-services),
  [discovery document](https://github.com/pocket-id/pocket-id/blob/v2.19.1/backend/internal/controller/well_known_controller.go),
  [several instances](https://github.com/pocket-id/pocket-id/issues/1549).
- **Authelia 4.39.28**: [OpenID Connect support](https://www.authelia.com/integration/openid-connect/introduction/),
  [OpenID Connect roadmap](https://www.authelia.com/roadmap/active/openid-connect-1.0-provider/),
  [sign-in with other providers](https://www.authelia.com/roadmap/planning/openid-connect-1.0-relying-party/),
  [admin dashboard](https://www.authelia.com/roadmap/active/dashboard-control-panel-and-cli-for-admins/),
  [notifications](https://www.authelia.com/configuration/notifications/introduction/),
  [several servers](https://www.authelia.com/overview/authorization/statelessness/),
  [passkeys](https://www.authelia.com/configuration/second-factor/webauthn/).
- **Kanidm 1.11.2**: [supported features](https://github.com/kanidm/kanidm/blob/v1.11.2/book/src/supported_features.md),
  [OAuth2](https://github.com/kanidm/kanidm/blob/v1.11.2/book/src/integrations/oauth2.md),
  [deployment](https://github.com/kanidm/kanidm/blob/v1.11.2/book/src/preparing_for_your_deployment.md),
  [replication](https://github.com/kanidm/kanidm/blob/v1.11.2/book/src/repl/planning.md),
  [README](https://github.com/kanidm/kanidm/blob/v1.11.2/README.md),
  [forward auth](https://github.com/kanidm/kanidm/issues/2774),
  [RP-initiated logout](https://github.com/kanidm/kanidm/issues/4240).
- **Rauthy 0.37.2**: [README](https://github.com/sebadob/rauthy/blob/v0.37.2/README.md),
  [configuration](https://sebadob.github.io/rauthy/config/config.html),
  [forward auth](https://sebadob.github.io/rauthy/work/forward_auth.html),
  [discovery document](https://github.com/sebadob/rauthy/blob/v0.37.2/src/data/src/entity/well_known.rs),
  [high availability](https://sebadob.github.io/rauthy/config/ha.html),
  [audit](https://raw.githubusercontent.com/sebadob/rauthy/refs/heads/main/assets/security_audit_report_v0.32.pdf).
- **authentik 2026.8.5**: [requirements](https://docs.goauthentik.io/install-config/install/docker-compose/),
  [OAuth2 provider](https://docs.goauthentik.io/add-secure-apps/providers/oauth2/),
  [key binding](https://docs.goauthentik.io/add-secure-apps/providers/oauth2/key-binding/),
  [high availability](https://docs.goauthentik.io/install-config/high-availability/),
  [audits](https://docs.goauthentik.io/security/audits-and-certs/),
  [enterprise features](https://docs.goauthentik.io/enterprise/enterprise-features/).
- **Keycloak 26.8.1**: [containers](https://www.keycloak.org/server/containers),
  [features](https://www.keycloak.org/server/features). **Zitadel 4.20.0**:
  [production setup](https://zitadel.com/docs/self-hosting/manage/production).
- **OpenID Foundation**: [certified providers](https://openid.net/certification/certified-openid-providers-profiles/),
  [certified logout](https://openid.net/certification/certified-openid-providers-for-logout-profiles/).
  Unlatch passes the [conformance tests](../conformance/README.md) but isn't certified.
