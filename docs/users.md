# Users and groups

Unlatch doesn't send email: people join and get back in through links you give them yourself.

## Inviting someone

In administration, open *Users* and choose *Invite*. Enter a username, a name and, if applications
need one, an email address. Unlatch shows an invitation link that works once, for three days.
Send it to the person; they open it and choose a password. Until then the user is listed as
*Invited, no password yet*.

People can also get an account by signing in with Google, GitHub or another provider, if you allow
it for their email domain; see [sign-in providers](providers.md#creating-accounts).

## A user's page

- *The address is verified*: applications may trust that the email address is the user's. Check
  it only if you know that it is.
- *Administrator*: can open administration. Administrators must use two-factor sign-in and can't
  turn it off.
- *Disabled*: the user can't sign in, and all their sessions end at once.
- *Groups*: the groups the user belongs to.
- *Password link*: a one-time link, valid for three days, for setting a new password.
- *Reset two-factor sign-in*: removes the user's authenticator app and recovery codes.
- *Remove passkeys*: removes all of the user's passkeys.
- *End all sessions*: signs the user out on every device.

## When someone can't get in

| Lost | What to do |
|---|---|
| The password | Give them a password link from their page. |
| The authenticator app | They can still sign in with a recovery code; each works once. To move to a new app, reset two-factor sign-in on their page, and they set it up again on their account page. |
| A device with a passkey | They sign in another way and remove that passkey on their account page. If they can't sign in, remove their passkeys on their page. |

## What users do themselves

On their account page, which they see after signing in, people find links to the
[applications](applications.md#adding-an-application) they may use, change their password, turn on
two-factor sign-in with an authenticator app, get new recovery codes, add
[passkeys](architecture.md#signing-in), see their sessions and end any of them, and
[link accounts](providers.md#linking-accounts) at sign-in providers.

## Groups

Groups decide who may use an application, and applications receive the names of the user's groups
in the `groups` claim, or in the `Remote-Groups` header with forward authentication.

Create a group under *Groups*, then add people to it on their pages. Group names use lowercase
letters, digits, dots, dashes and underscores. Renaming a group changes what applications see, so
update any rules there that use the old name. Deleting a group also removes the access it gave.

Someone removed from a group loses the applications it gave them within five minutes, when their
tokens next refresh.

## Sessions and the log

*Sessions* lists who is signed in, on which device and from which address; you can end any
session. *Log* records every sign-in and every change made in administration, for 180 days.
