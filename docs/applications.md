# Connecting applications

An application that supports OpenID Connect sends people to Unlatch to sign in and gets back who
they are. For services that don't support it, use [forward authentication](forward-auth.md).

## Adding an application

1. In administration, open *Applications*, choose *Add* and give the application a name and a
   Client ID, such as `grafana`. Check *Public client* only for a mobile or browser app, which
   can't keep a secret.
2. Copy the client secret into the application. Unlatch shows it only once;
   *Issue a new secret* replaces it, and the old one stops working at once.
3. Under *Redirect URIs*, enter the address the application's documentation names. It must match
   what the application sends character for character.
4. Under *Access*, choose *Everyone* or the [groups](users.md#groups) whose members may use it.

Those people see the application on their account page, with a link to the site of its https
redirect URI, or to its host with forward authentication.

The application then needs these values; most find everything from the issuer alone.

| Setting | Value |
|---|---|
| Issuer | `https://login.example.com` |
| Discovery | `https://login.example.com/.well-known/openid-configuration` |
| Authorization endpoint | `https://login.example.com/authorize` |
| Token endpoint | `https://login.example.com/token` |
| Userinfo endpoint | `https://login.example.com/userinfo` |
| Sign-out endpoint | `https://login.example.com/end-session` |
| Scopes | `openid profile email groups` |

## What applications learn

The application gets what the scopes it asks for allow, in the ID token and from userinfo:

| Scope | What the application gets |
|---|---|
| `openid` | `sub`, a stable identifier of the account |
| `profile` | `name` and `preferred_username`, the username |
| `email` | `email` and `email_verified`, if the user has an address |
| `groups` | `groups`, the names of the user's groups |
| `offline_access` | A refresh token, which works until the user's session ends |

The first time someone signs in to an application, Unlatch asks them to allow this and remembers
the answer. For your own applications, set *Consent* to *Don't ask*. A public client on the user's
device is asked every time, because another program could pose as it.

## Other settings

- *Enabled*: an application that isn't can't sign anyone in.
- *Addresses after sign-out*: where the application may send people after signing them out.
- *APIs*: the APIs the application may get access tokens for. A token names its API and is
  useless at any other ([tokens](architecture.md#tokens)). An application with a secret can also
  get a token for itself with the client credentials grant, to call one of these APIs.
- *ID token signature*: keep RS256 unless the application asks for ES256 or EdDSA.
- *Back-channel logout URI*: Unlatch tells the application there when a user's session ends.
- *Require PAR* and *Require DPoP*: for applications that support pushed authorization requests
  or DPoP-bound tokens ([OpenID Connect](architecture.md#openid-connect)).
- *Require PKCE*: turn it off only for an older application with a secret that can't use PKCE.

## Examples

### Forgejo

The redirect URI is `https://git.example.com/user/oauth2/unlatch/callback`, where `unlatch` is
the name of the authentication source. Add the source in *Site administration*,
*Authentication sources*, with the provider *OpenID Connect*, or with:

```sh
forgejo admin auth add-oauth --name unlatch --provider openidConnect \
  --key forgejo --secret "the secret from Unlatch" \
  --auto-discover-url https://login.example.com/.well-known/openid-configuration \
  --scopes profile,email,groups \
  --group-claim-name groups --admin-group admins
```

The last line makes members of the group `admins` administrators in Forgejo. Without an account
of their own, people choose on first sign-in between registering and linking an existing account;
to create accounts for them instead, set this in `app.ini`:

```ini
[oauth2_client]
ENABLE_AUTO_REGISTRATION = true
```

Gitea is set up the same way, but doesn't use PKCE: turn off *Require PKCE* for it.

### Grafana

The redirect URI is `https://grafana.example.com/login/generic_oauth`. In `grafana.ini`:

```ini
[auth.generic_oauth]
enabled = true
name = Unlatch
client_id = grafana
client_secret = the secret from Unlatch
scopes = openid profile email groups
auth_url = https://login.example.com/authorize
token_url = https://login.example.com/token
api_url = https://login.example.com/userinfo
use_pkce = true
login_attribute_path = preferred_username
role_attribute_path = contains(groups[*], 'admins') && 'Admin' || 'Viewer'
```

The last line makes members of the group `admins` administrators in Grafana
and everyone else viewers.

### Immich

Immich has to be served over https. Its redirect URIs are:

```text
https://photos.example.com/auth/login
https://photos.example.com/user-settings
https://photos.example.com/api/oauth/mobile-redirect
```

In *Administration*, *Settings*, *Authentication Settings*, *OAuth*:

| Setting | Value |
|---|---|
| `issuer_url` | `https://login.example.com` |
| `client_id` | `immich` |
| `client_secret` | the secret from Unlatch |
| `scope` | `openid email profile groups` |
| Role Claim | `groups` |
| Mobile redirect URI override | on, with `https://photos.example.com/api/oauth/mobile-redirect` |

Immich creates accounts only for users with an email address. Members of the group `admin` become
Immich administrators. The mobile app needs the override because Unlatch doesn't accept the
address it uses otherwise, `app.immich:///oauth-callback`.

### Nextcloud

Install the app *OpenID Connect user backend*. Its redirect URI is
`https://cloud.example.com/apps/user_oidc/code`, with `/index.php` before `/apps` if Nextcloud has
no pretty URLs; the app's settings page shows the exact one. Then:

```sh
occ user_oidc:provider Unlatch \
  --clientid=nextcloud \
  --clientsecret="the secret from Unlatch" \
  --discoveryuri=https://login.example.com/.well-known/openid-configuration \
  --scope="openid profile email groups" \
  --send-id-token-hint=1
```

Add `https://cloud.example.com/` under *Addresses after sign-out*: Nextcloud sends people there when
they sign out. Add `--group-provisioning=1` to copy their groups from Unlatch as well. To skip
Nextcloud's own login form and go straight to Unlatch:

```sh
occ config:app:set --type=string --value=0 user_oidc allow_multiple_user_backends
```

### Proxmox VE

The redirect URI is the address of the web interface, such as `https://pve.example.com:8006`,
without a slash at the end; add one for each address people open. Then:

```sh
pveum realm add unlatch --type openid --issuer-url https://login.example.com \
  --client-id proxmox --client-key "the secret from Unlatch" \
  --username-claim username --autocreate 1 \
  --scopes "email profile groups" --groups-claim groups
```

People get accounts such as `anna@unlatch`; the realm's username claim can't be changed later.
The accounts have no permissions of their own. Proxmox VE 8.4 and later adds people to its groups
named after their Unlatch groups with the realm appended, if such groups exist. This makes
members of `admins` administrators:

```sh
pveum group add admins-unlatch
pveum acl modify / --groups admins-unlatch --roles Administrator
```

### Vaultwarden

Vaultwarden supports this from version 1.35. The redirect URI is
`https://vault.example.com/identity/connect/oidc-signin`. In its environment:

```ini
DOMAIN=https://vault.example.com
SSO_ENABLED=true
SSO_AUTHORITY=https://login.example.com
SSO_CLIENT_ID=vaultwarden
SSO_CLIENT_SECRET=the secret from Unlatch
SSO_AUTH_ONLY_NOT_SESSION=true
```

Vaultwarden needs an email address that is marked as verified on the user's page. The last line
makes it keep sessions of its own after sign-in, because Unlatch's access tokens last five minutes,
too short for Bitwarden apps; signing out of Unlatch then doesn't sign people out of Vaultwarden.
People still unlock the vault with their master password.
