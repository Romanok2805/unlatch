# Architecture

How Unlatch works and why.

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
error value with a defined response. Every queue, cache and buffer has a size limit, so heavy
traffic can slow Unlatch down but can't make it run out of memory.

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

Applications use the authorization code flow with PKCE (S256). An administrator can let an older
confidential client go without PKCE; its secret then keeps a stolen code useless, and a code issued
without PKCE is never redeemed with a verifier, so nobody can strip PKCE from a request unnoticed
(RFC 9700). Public clients always need it. Unlatch also provides discovery, JWKS, userinfo, token
revocation (RFC 7009), introspection (RFC 7662), RP-initiated and back-channel logout, the client
credentials grant for services that call each other, and the `form_post` response mode.
Authorization responses include `iss` (RFC 9207), so a client can't be tricked into mixing up
responses from two providers. Browser apps may call the token, userinfo, revocation and PAR
endpoints from the origin of one of their redirect URIs.

An authorization request is checked, then carried sealed through sign-in and consent instead of
being stored, so requests that are never finished cost nothing. Each step checks it again against
the application as registered at that moment.

Left out on purpose:

- the implicit and hybrid flows and the password grant, which put tokens or passwords where they
  can leak;
- `alg: none` and ID tokens signed with the client secret;
- request objects and dynamic client registration, which add attack surface that a self-hosted
  setup doesn't need;
- front-channel logout, which relies on third-party frames.

A client can push its authorization request to `/par` first (RFC 9126) and send the browser only a
reference. Nobody on the way can then read or change the request, and a confidential client proves
who it is before the user sees anything. An application can be set to accept only pushed requests.
The reference is the request itself, sealed, so pushing stores nothing. Within its minute it can
be used more than once, as when a page is reloaded, which only repeats the same request of the
same client.

A redirect URI must match a registered one character for character. The only exception comes from
RFC 8252: a native app on the user's machine may use any port on a loopback address. When the client
or redirect URI is unknown, Unlatch shows an error page instead of redirecting, so it can't be used
as an open redirect. Any program on the device could claim the redirect URI of a native app
without a secret, so for such an app the user is asked every time, even after consenting before.

### Tokens

| Token | Format | Lifetime | If someone uses it twice |
|---|---|---|---|
| Authorization code | Random | 60 seconds | Everything issued from it is revoked |
| Access token | JWT | 5 minutes | Nothing happens, unless it is bound with DPoP |
| Refresh token | Sealed, not stored | Until the session ends | The grant is revoked |
| ID token | JWT | 5 minutes | Nothing happens; it only proves sign-in |

Access tokens have `typ: at+jwt` (RFC 9068). A service can check them without asking Unlatch, and an
ID token can't be passed off as one. A service that needs revocation to take effect at once can use
introspection instead. Userinfo and introspection refuse tokens of a session that has ended or of a
grant that was revoked.

Every access token names its audience: the client it was issued to, or an API the administrator
registered for that client (RFC 8707). A token for one service is useless at another, and refreshing
never widens the audience. A refresh also checks that the user is still active and still in a group
allowed to use the client, so removing someone from a group takes effect within five minutes.

With DPoP (RFC 9449) a client binds its tokens to a key it keeps and signs a fresh proof with it for
every request, so a stolen token is useless without the key. A bound access token names the key in
`cnf.jkt`, and userinfo accepts it only with a proof. Refresh tokens of public clients are bound as
well, because without a secret the key is all that tells the client from a thief. A proof is
accepted once, within a minute of the time it states. An application can be set to require DPoP.

The `sub` of a user is derived from the account with a key, so it is stable but reveals neither the
order of accounts nor how many there are.

ID tokens are signed with RS256 by default, because the OpenID Connect specification requires it. An
administrator can pick ES256 or EdDSA for an application instead. Signing keys rotate every 90 days:
a new key appears in JWKS a day before it signs anything, and an old one stays there for a week
after it stops.

## Signing in

Passwords are hashed with Argon2id. Each hash needs 19 MiB of memory for a moment, so only two run
at once and the rest wait their turn. This caps memory use and keeps the login form from being used
to overload the server. For a user name that doesn't exist, Unlatch hashes a dummy password anyway,
so the response time doesn't reveal which accounts exist. A password needs at least 12 characters
and must not be a common password or the user name; as NIST SP 800-63B-4 advises, there are no rules
about character classes. Password attempts are limited to 10 per account and 50 per address in a
quarter hour. Attempts past a limit are refused with a warning in the log, which names the account
and the address.

The second factor is a TOTP code from an authenticator app: RFC 6238 with six digits and 30-second
steps. Unlatch sets up SHA-1, because every app supports it, and also checks SHA-256 codes for
secrets moved from another provider. Codes from the previous and next step are
accepted to allow for clock drift. Each code works once, and attempts are limited per quarter hour
and per day. Users also get recovery codes.

People can also sign in with a passkey, which replaces both the password and the code. The device
that holds it proves it has the key, and must check the person's PIN or biometrics first, so a
passkey alone is two factors; ID tokens then carry the `amr` values `pop` and `mfa`. Browsers offer
saved passkeys in the username field. A passkey on a phone works on a computer too: a button of its
own asks the browser to show a QR code at once, and the phone that scans it answers over Bluetooth,
so it must be next to the computer and a photo of the code sent elsewhere is useless. A passkey
can be made on a phone from the computer the same way. A passkey works only on the site it was
made for, so a look-alike page can't use it, and it needs the issuer to be a host name rather than
an IP address. Unlatch asks for no attestation, so any authenticator works and its make isn't
checked; keys may be EdDSA, ES256 or RS256. Each challenge is sealed rather than stored, lasts
five minutes and is accepted once, and a passkey whose signature counter goes back is refused as
copied. Because a passkey is enough to sign in, adding or removing one needs a sign-in within the
last ten minutes, so whoever finds a session left open can't add their own.

People can sign in with any OpenID Connect provider, such as Google, and with GitHub through its
own OAuth API. An outside account is linked to a local one by provider and subject only, and only
by a user who is already signed in. Accounts are never matched by email address, because that
would let whoever controls the address at the provider take over the local account. Creating
accounts on the first outside sign-in is off by default. When the administrator lists email
domains for it, the provider must confirm the address and its domain must be on the list. With
Google the account must also belong to that domain's Google Workspace, because a personal Google
account can have a confirmed address at any domain. An account with TOTP still asks for a code
after an outside sign-in, unless the administrator trusts the provider to check a second factor
itself. Unlatch can't see whether it did, so such a session counts as one without the code: its
`amr` is only `fed`, administration asks for the code, and passkeys, which are enough for
administration, can't be added from it.

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

Administration needs TOTP, and a code or a passkey entered within the last 12 hours to look and the
last 30 minutes to change anything. To everyone else its pages don't exist. Every change is
recorded in the audit log.

Unlatch sends requests only to the sign-in providers and back-channel logout URIs an administrator
configured, and to the endpoints a provider's discovery document names.

The interface uses the system font, a small set of icons and light and dark themes, with an accent
colour the administrator can change. It comes in English and Russian.

## Forward authentication

Some services don't support OpenID Connect. For them, the reverse proxy asks Unlatch about each
request (nginx `auth_request`, Traefik `forwardAuth`, Caddy `forward_auth`) and passes the user on
to the service in the `Remote-User`, `Remote-Name`, `Remote-Email` and `Remote-Groups` headers.
Every one of these headers is in each answer that lets a request through, empty if there is
nothing to say, so a proxy that copies them can't leave one the client wrote in place. Unlatch
answers only proxies listed as trusted, because it relies on their `X-Forwarded-*` headers.

Each protected host gets its own cookie, so no cookie is shared between subdomains. After
sign-in Unlatch sends the browser to `/_unlatch/callback` on the protected host, which the proxy
routes to Unlatch, with a code that works once within a minute and is traded for a new token
there. A cookie set on the protected host when the sign-in starts ties the code to that browser,
so nobody can plant a code of their own session on someone else. The configuration of each proxy
is in [forward-auth.md](forward-auth.md).

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
file is not enough to use them. Of passkeys only the public keys are stored, which sign no one in.

Migrations only go forward and make a backup before they run. Audit log entries are deleted after
180 days, because they contain IP addresses.

## Network

By default Unlatch speaks plain HTTP/1.1 to a reverse proxy, which takes care of TLS, HTTP/2 and
certificates. Unlatch can also serve TLS itself with rustls from PEM files and picks up a renewed
certificate without a restart.

`X-Forwarded-For` and related headers are trusted only from proxy addresses listed in the
configuration, and by default from none. Otherwise anyone could fake their IP address and get
around the attempt limits. The issuer URL is set in the configuration too and never built from the
`Host` header.

Request and header sizes, the number of connections and every timeout are limited.

## Memory

Measured with the x86-64 Linux release: the binary is 8.8 MB, and the server holds 6.5 MiB of
memory at rest, about 1 MiB of it its own data and the rest its loaded code. With 20 clients asking
for the sign-in page at once, it peaks at 7.3 MiB. Password checks add up to 38 MiB for a moment,
two hashes of 19 MiB each, and it drops back when they finish. [The comparison](comparison.md)
measures Pocket ID and Authelia the same way.

The async runtime uses two worker threads. Static files are built into the binary and cached by
browsers under addresses that include a hash of their contents.

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

Configuration comes from environment variables, so no configuration file format is needed;
see [configuration.md](configuration.md).

We write the small parts ourselves when that is easier to review than a dependency: JWS for
the algorithms we accept, base64 and base32, form decoding, TOTP, the parts of CBOR and WebAuthn
that passkeys need, migrations, logging and HTML templates.
