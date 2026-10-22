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

## Example: Grafana

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
