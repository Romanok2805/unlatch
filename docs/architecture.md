# Architecture

This is the design of Unlatch. Most of it isn't built yet, and the document changes when the design
does.

Unlatch is one process with one SQLite database, normally running behind a reverse proxy. It serves
the sign-in pages, the OpenID Connect endpoints, forward-auth checks for the proxy and a web
interface for the administrator.

## Ground rules

Features that are unsafe by design are not implemented. No setting can turn them on, because there
is no code to turn on.

Input is checked once, where it enters the program: a request, a database row, the configuration
file. From then on it lives in a type that can only hold valid values, so the rest of the code never
sees an unchecked redirect URI or user name.

The code doesn't panic. A panic takes the server down for everyone, so every failure is an ordinary
error value with a defined response. Every queue, cache and buffer has a size limit, so heavy traffic
can slow Unlatch down but can't make it run out of memory.

Some rules are enforced by types, so the compiler catches what a reviewer could miss:

| Type | What it prevents |
|---|---|
| `Secret<T>` | Secrets leaking into logs or responses. It has no `Debug`, `Display` or `Serialize`, compares in constant time and is wiped on drop. |
| `Html` | Injected markup. It can only be made by escaping text or from our own templates. |
| `RedirectUri` | Redirects to addresses nobody registered. |
| `ClientId`, `UserId`, `GroupId` | Passing one kind of ID where another is expected. |
| `Anonymous` → `PasswordChecked` → `SignedIn` | Starting a session or issuing a code before every factor the account needs has been checked. |
| `TokenHash` | Keeping usable tokens in the database. Only their SHA-256 hashes are stored. |

## OpenID Connect

Applications use the authorization code flow, and every client must use PKCE with S256. Unlatch
also provides discovery, JWKS, userinfo, token revocation (RFC 7009), introspection (RFC 7662),
RP-initiated and back-channel logout, and the client credentials grant for services that call each
other. Authorization responses include `iss` (RFC 9207), so a client can't be tricked into mixing up
responses from two providers. Pushed authorization requests (RFC 9126), DPoP (RFC 9449) and
`form_post` responses will come later.

Left out on purpose:

- the implicit and hybrid flows and the password grant, which put tokens or passwords where they can
  leak;
- `alg: none` and ID tokens signed with the client secret;
- request objects and dynamic client registration, which add attack surface that a self-hosted
  setup doesn't need;
- front-channel logout, which relies on third-party frames.

A redirect URI must match a registered one character for character. The only exception comes from
RFC 8252: a native app on the user's machine may use any port on a loopback address. When the client
or redirect URI is unknown, Unlatch shows an error page instead of redirecting, so it can't be used
as an open redirect.

### Tokens

| Token | Format | Lifetime | If someone uses it twice |
|---|---|---|---|
| Authorization code | Random | 60 seconds | Everything issued from it is revoked |
| Access token | JWT | 5 minutes | Nothing happens; it is a bearer token |
| Refresh token | Sealed, not stored | Until the session ends | The grant is revoked |
| ID token | JWT | 5 minutes | Nothing happens; it only proves sign-in |

Access tokens have `typ: at+jwt` (RFC 9068). A service can check them without asking Unlatch, and an
ID token can't be passed off as one. A service that needs revocation to take effect at once can use
introspection instead.

Every access token names its audience: the client it was issued to, or an API the administrator
registered for that client (RFC 8707). A token for one service is useless at another, and refreshing
never widens the audience. A refresh also checks that the user is still active and still in a group
allowed to use the client, so removing someone from a group takes effect within five minutes.

ID tokens are signed with RS256 by default, because the OpenID Connect specification requires it. A
client can ask for ES256 or EdDSA instead. Signing keys rotate: a new key appears in JWKS before it
signs anything, and an old one stays there until the last token it signed has expired.

## Signing in

Passwords are hashed with Argon2id. Each hash needs tens of megabytes of memory for a moment, so only
a few run at once and the rest wait their turn. This caps memory use and keeps the login form from
being used to overload the server. For a user name that doesn't exist, Unlatch hashes a dummy
password anyway, so the response time doesn't reveal which accounts exist. Password rules follow
NIST SP 800-63B-4: a minimum length, no "must contain a digit" rules, and a check against a list of
common passwords.

The second factor is a TOTP code from an authenticator app: RFC 6238 with SHA-1, six digits and
30-second steps, because that is what the apps support. Codes from the previous and next step are
accepted to allow for clock drift. Each code works once, and the number of attempts is limited.
Users also get recovery codes.

People can sign in with Google, Microsoft, GitLab or any other OpenID provider, and with GitHub
through its own OAuth API. An outside account is linked to a local one by its issuer and subject
only, and only by a user who is already signed in. Accounts are never matched by email address,
because that would let whoever controls the address at the provider take over the local account.
Creating accounts on the first outside sign-in is off by default. When the administrator turns it
on, the provider must confirm the email address and its domain must be on the allowed list, which
for Google Workspace means the `hd` claim. An account with TOTP still asks for a code after an
outside sign-in.

The first version doesn't send email. The administrator gives people one-time links to join or to
reset their password, and users who lose their authenticator get in with a recovery code.

The first administrator is created with a one-time setup token that Unlatch prints to its log or
that the command line produces. There is no setup page waiting for whoever finds the server first.

## Sessions and pages

The session cookie has the `__Host-` prefix and is `Secure` and `HttpOnly`. It is `SameSite=Lax`
rather than `Strict`, because people arrive at Unlatch by following a link from another site, and
with `Strict` the browser wouldn't send the cookie and they would look signed out. Forged form posts
from other sites are stopped by a CSRF token in every form. The session ID changes at sign-in.

Sessions end after a period of inactivity and after a fixed maximum. Users can see their sessions and
end any of them. Disabling a user ends all of theirs.

Pages are HTML forms rendered on the server, and they work without JavaScript. Scripts are our own,
come from our own origin and only make things more convenient. Every response has a Content Security
Policy that allows scripts only from our origin, requires Trusted Types and forbids framing, and also
sets HSTS, `Referrer-Policy: no-referrer` and `X-Content-Type-Options: nosniff`.

The administrator must use TOTP and enters a code again before sensitive changes. Every change is
recorded in the audit log.

Logos are uploaded by the administrator as PNG or WebP and served with a sandboxing CSP. Unlatch
never downloads anything from an address a user gave it.

The interface uses the system font, a small set of icons and light and dark themes, with an accent
colour the administrator can change. It comes in English and Russian.

## Forward authentication

Some services don't support OpenID Connect. For them, the reverse proxy asks Unlatch about each
request (nginx `auth_request`, Traefik `forwardAuth`, Caddy `forward_auth`) and passes the user on
to the service in the `Remote-User`, `Remote-Email` and `Remote-Groups` headers. The proxy has to
remove these headers from incoming requests, or a client could set them itself.

Each protected host gets its own `__Host-` cookie, set through a callback path that the proxy routes
to Unlatch, so no cookie is shared between subdomains. Protected hosts are listed in the
configuration, and after sign-in the user is sent back only to the host they came from.

## Storage

The database is SQLite in WAL mode. One thread owns the only connection and runs the queries that
request handlers send it, so the async runtime never waits on the disk and queries never
interleave. For a single organisation that is fast enough and keeps memory low.

Codes, sessions and recovery codes are stored only as hashes. Refresh tokens aren't stored at all:
each is sealed and names its grant and a generation number, and the database keeps only the
current generation. An older generation means the token was copied, so the grant is revoked. TOTP secrets, the client
secrets for outside providers and the private signing keys are encrypted with AES-256-GCM. The key
for that is read from a file or an environment variable, never from the database, so a stolen
database file is not enough to use them.

Migrations only go forward and make a backup before they run. Backups are made with `VACUUM INTO`.
Audit log entries are deleted after a configurable period, because they contain IP addresses.

## Network

By default Unlatch speaks plain HTTP/1.1 to a reverse proxy, which takes care of TLS, HTTP/2 and
certificates. Unlatch can also serve TLS itself with rustls from PEM files and picks up new
certificates without a restart.

`X-Forwarded-For` and related headers are trusted only from proxy addresses listed in the
configuration, and by default from none. Otherwise anyone could fake their IP address and get around
the attempt limits. The issuer URL is set in the configuration too and never built from the `Host`
header.

Request and header sizes, the number of connections and every timeout are limited.

## Memory

The target is about 10 MB when idle. The async runtime uses one or two threads. Static files are
built into the binary and cached by browsers under names that include their hash. The peak is set
mostly by how many password hashes may run at once. CI measures memory and response times so that
regressions get noticed.

## Dependencies

| Need | Crate | Why not write it ourselves |
|---|---|---|
| HTTP | `hyper`, `tokio` | A home-made HTTP parser is an easy way to get request smuggling. |
| TLS | `rustls` | Needed to talk to outside providers anyway. |
| Cryptography | `aws-lc-rs` | Reviewed implementations of signatures, encryption, HMAC, hashing and random numbers, including RSA key generation, which RS256 needs and `ring` lacks. |
| Passwords | `argon2` | `aws-lc-rs` has no Argon2. |
| Database | `rusqlite` with bundled SQLite | SQLite is very well tested; we only need the binding. |
| JSON | `serde`, `serde_json` | Parsers are easy to get wrong. |

Configuration comes from environment variables, so no configuration file format is needed; see
[configuration.md](configuration.md).

We write the small parts ourselves when that is easier to review than a dependency: JWS for the
algorithms we accept, base64url, form decoding, TOTP, migrations, logging and HTML templates.

## Roadmap

0. Repository, design documents and interface design.
1. Core types, secrets, cryptography and keys.
2. Storage, migrations and backups.
3. HTTP server, limits, trusted proxies, optional TLS, security headers.
4. Passwords, sessions, TOTP, recovery codes, invitations and the first administrator.
5. OpenID Connect endpoints, checked with the OpenID conformance suite.
6. Web administration and the account page.
7. Sign-in with outside providers.
8. Forward authentication.
9. Pushed authorization requests, DPoP and `form_post`.
10. Fuzzing, memory and load benchmarks, the first release and OpenID certification.
