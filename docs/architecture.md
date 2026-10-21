# Architecture

How Unlatch works and why. The document changes when the design does.

Unlatch is one process with one SQLite database, normally running behind a reverse proxy. It serves
the sign-in pages, the OpenID Connect endpoints, forward-auth checks for the proxy and a web
interface for the administrator.

## Ground rules

Features that are unsafe by design are not implemented. No setting can turn them on, because there
is no code to turn on.

Input is checked once, where it enters the program: a request, a database row, the environment.
From then on it lives in a type that can only hold valid values, so the rest of the code never sees
an unchecked redirect URI or user name.

The code doesn't panic. A panic takes the server down for everyone, so every failure is an ordinary
error value with a defined response. Every queue, cache and buffer has a size limit, so heavy traffic
can slow Unlatch down but can't make it run out of memory.

Some rules are enforced by types, so the compiler catches what a reviewer could miss:

| Type | What it prevents |
|---|---|
| `Secret<T>` | Secrets leaking into logs or responses. It has no `Debug`, `Display`, `Clone` or `Serialize`, and is wiped on drop. |
| `Html` | Injected markup. Markup can only come from string literals in our source; everything else is escaped. |
| `RedirectUri` | Redirects to addresses nobody registered. |
| `UserId`, `AppId`, `GroupId`, `SessionId` | Passing one kind of ID where another is expected. |
| `FirstFactor` → `SignedIn` | Starting a session before every factor the account needs has been checked. Only the sign-in module can make either. |
| `TokenHash` | Keeping usable tokens in the database. Only their SHA-256 hashes are stored. |

## OpenID Connect

Applications use the authorization code flow, and every client must use PKCE with S256. Unlatch
also provides discovery, JWKS, userinfo, token revocation (RFC 7009), introspection (RFC 7662),
RP-initiated and back-channel logout, the client credentials grant for services that call each
other, and the `form_post` response mode. Authorization responses include `iss` (RFC 9207), so a
client can't be tricked into mixing up responses from two providers. Browser apps may call the
token, userinfo and revocation endpoints from the origin of one of their redirect URIs.

An authorization request is checked, then carried sealed through sign-in and consent instead of
being stored, so requests that are never finished cost nothing. Each step checks it again against
the application as registered at that moment.

Left out on purpose:

- the implicit and hybrid flows and the password grant, which put tokens or passwords where they can
  leak;
- `alg: none` and ID tokens signed with the client secret;
- request objects and dynamic client registration, which add attack surface that a self-hosted
  setup doesn't need;
- front-channel logout, which relies on third-party frames.

Not yet built: pushed authorization requests (RFC 9126) and DPoP (RFC 9449).

A redirect URI must match a registered one character for character. The only exception comes from
RFC 8252: a native app on the user's machine may use any port on a loopback address. When the client
or redirect URI is unknown, Unlatch shows an error page instead of redirecting, so it can't be used
as an open redirect. Any program on the device could claim the redirect URI of a native app
without a secret, so for such an app the user is asked every time, even after consenting before.

### Tokens

| Token | Format | Lifetime | If someone uses it twice |
|---|---|---|---|
| Authorization code | Random | 60 seconds | Everything issued from it is revoked |
| Access token | JWT | 5 minutes | Nothing happens; it is a bearer token |
| Refresh token | Sealed, not stored | Until the session ends | The grant is revoked |
| ID token | JWT | 5 minutes | Nothing happens; it only proves sign-in |

Access tokens have `typ: at+jwt` (RFC 9068). A service can check them without asking Unlatch, and an
ID token can't be passed off as one. A service that needs revocation to take effect at once can use
introspection instead. Userinfo and introspection refuse tokens of a session that has ended.

Every access token names its audience: the client it was issued to, or an API the administrator
registered for that client (RFC 8707). A token for one service is useless at another, and refreshing
never widens the audience. A refresh also checks that the user is still active and still in a group
allowed to use the client, so removing someone from a group takes effect within five minutes.

The `sub` of a user is derived from the account with a key, so it is stable but reveals neither the
order of accounts nor how many there are.

ID tokens are signed with RS256 by default, because the OpenID Connect specification requires it. A
client can ask for ES256 or EdDSA instead. Signing keys rotate every 90 days: a new key appears in
JWKS a day before it signs anything, and an old one stays there for a week after it stops.

## Signing in

Passwords are hashed with Argon2id. Each hash needs tens of megabytes of memory for a moment, so only
two run at once and the rest wait their turn. This caps memory use and keeps the login form from
being used to overload the server. For a user name that doesn't exist, Unlatch hashes a dummy
password anyway, so the response time doesn't reveal which accounts exist. Password rules follow
NIST SP 800-63B-4: at least 12 characters, no "must contain a digit" rules, and a check against
common passwords and the user name.

The second factor is a TOTP code from an authenticator app: RFC 6238 with SHA-1, six digits and
30-second steps, because that is what the apps support. Codes from the previous and next step are
accepted to allow for clock drift. Each code works once, and attempts are limited per quarter hour
and per day. Users also get recovery codes.

People can sign in with any OpenID Connect provider, such as Google, and with GitHub through its own
OAuth API. An outside account is linked to a local one by provider and subject only, and only by a
user who is already signed in. Accounts are never matched by email address, because that would let
whoever controls the address at the provider take over the local account. Creating accounts on the
first outside sign-in is off by default. When the administrator lists email domains for it, the
provider must confirm the address and its domain must be on the list. With Google the account must
also belong to that domain's Google Workspace, because a personal Google account can have a
confirmed address at any domain. An account with TOTP still asks for a code after an outside
sign-in.

Unlatch doesn't send email. The administrator gives people one-time links to join or to reset their
password, and users who lose their authenticator get in with a recovery code.

While there are no accounts, Unlatch prints a one-time link to its log at start-up, which creates
the first administrator. There is no setup page waiting for whoever finds the server first.

## Sessions and pages

The session cookie has the `__Host-` prefix and is `Secure` and `HttpOnly`. It is `SameSite=Lax`
rather than `Strict`, because people arrive at Unlatch by following a link from another site, and
with `Strict` the browser wouldn't send the cookie and they would look signed out. Forged form posts
from other sites are stopped by a CSRF token in every form. The session ID changes at sign-in.

Sessions end after a week of inactivity and a month after sign-in. Users can see their sessions and
end any of them. Disabling a user ends all of theirs.

Pages are HTML forms rendered on the server, and they work without JavaScript. Scripts are our own,
come from our own origin and only make things more convenient. Every response has a Content Security
Policy that allows scripts and styles only from our origin, requires Trusted Types and forbids
framing, and also sets HSTS, `Referrer-Policy: no-referrer` and `X-Content-Type-Options: nosniff`.

Administration needs TOTP and a code entered within the last 12 hours to look and the last 30
minutes to change anything. To everyone else its pages don't exist. Every change is recorded in the
audit log.

Unlatch only sends requests to addresses an administrator configured: sign-in providers and
back-channel logout URIs of applications.

The interface uses the system font, a small set of icons and light and dark themes, with an accent
colour the administrator can change. It comes in English and Russian.

## Forward authentication

Some services don't support OpenID Connect. For them, the reverse proxy asks Unlatch about each
request (nginx `auth_request`, Traefik `forwardAuth`, Caddy `forward_auth`) and passes the user on
to the service in the `Remote-User`, `Remote-Name`, `Remote-Email` and `Remote-Groups` headers.
Unlatch answers only proxies listed as trusted, because it relies on their `X-Forwarded-*` headers.

Each protected host gets its own cookie, so no cookie is shared between subdomains. After sign-in
Unlatch sends the browser to `/_unlatch/callback` on the protected host, which the proxy routes to
Unlatch, with a code that works once within a minute and is traded for a new token there. A cookie
set on the protected host when the sign-in starts ties the code to that browser, so nobody can
plant a code of their own session on someone else. The configuration of each proxy is in
[forward-auth.md](forward-auth.md).

## Storage

The database is SQLite in WAL mode. One thread owns the only connection and runs the queries that
request handlers send it, so the async runtime never waits on the disk and queries never
interleave. For a single organisation that is fast enough and keeps memory low.

Codes and sessions are stored only as hashes. Recovery codes are short enough to guess against a
copy of the database, so their hashes are keyed with the master key. Refresh tokens aren't stored at
all: each is sealed and names its grant and a generation number, and the database keeps only the
current generation. An older generation means the token was copied, so the grant is revoked. TOTP
secrets, the client secrets of sign-in providers and the private signing keys are encrypted with
AES-256-GCM. The key for that is read from a file, never from the database, so a stolen database
file is not enough to use them.

Migrations only go forward and make a backup before they run. Audit log entries are deleted after
180 days, because they contain IP addresses.

## Network

By default Unlatch speaks plain HTTP/1.1 to a reverse proxy, which takes care of TLS, HTTP/2 and
certificates. Unlatch can also serve TLS itself with rustls from PEM files and picks up a renewed
certificate without a restart.

`X-Forwarded-For` and related headers are trusted only from proxy addresses listed in the
configuration, and by default from none. Otherwise anyone could fake their IP address and get around
the attempt limits. The issuer URL is set in the configuration too and never built from the `Host`
header.

Request and header sizes, the number of connections and every timeout are limited.

## Memory

Measured with the release build on Windows: the binary is 7 MB, and the server holds about 7 MB of
memory at rest. Serving 4,000 sign-in pages to 20 clients at once, at about 4,000 a second, it
stays under 8 MB. Password checks raise it to about 46 MB for a moment, two hashes of 19 MB each,
and it drops back when they finish.

The async runtime uses two worker threads. Static files are built into the binary and cached by
browsers under names that include their hash.

## Dependencies

| Need | Crate | Why not write it ourselves |
|---|---|---|
| HTTP | `hyper`, `hyper-util`, `http-body-util`, `tokio` | A home-made HTTP parser is an easy way to get request smuggling. |
| TLS | `rustls`, `tokio-rustls`, `webpki-roots` | Needed to talk to sign-in providers; serving TLS reuses it. |
| Cryptography | `aws-lc-rs` | Reviewed implementations of signatures, encryption, HMAC, hashing and random numbers, including RSA key generation, which RS256 needs and `ring` lacks. |
| Passwords | `argon2` | `aws-lc-rs` has no Argon2. |
| Wiping secrets | `zeroize` | Clearing memory reliably needs care the compiler won't undo. |
| Database | `rusqlite` with bundled SQLite | SQLite is very well tested; we only need the binding. |
| JSON | `serde`, `serde_json` | Parsers are easy to get wrong. |
| QR codes | `qrcodegen` | Encoding QR codes correctly is a project of its own. |

Configuration comes from environment variables, so no configuration file format is needed; see
[configuration.md](configuration.md).

We write the small parts ourselves when that is easier to review than a dependency: JWS for the
algorithms we accept, base64 and base32, form decoding, TOTP, migrations, logging and HTML templates.

## Still to do

- Pushed authorization requests and DPoP.
- A run of the OpenID conformance suite, and certification.
- Fuzzing of the parsers.
- Release builds and packages.
