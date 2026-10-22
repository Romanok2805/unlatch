# Sign-in providers

People can sign in with an account they already have at Google, GitHub or another OpenID Connect
provider. Why an outside account is tied to a local one only by the user, never by email address,
is in [the architecture](architecture.md#signing-in).

## Adding a provider

In administration, open *Sign-in providers* and choose *Add*. The provider needs the address
`https://login.example.com/login/<short name>/callback`, where the short name is the one you give
the provider in Unlatch, such as `google`. Register the address at the provider first, then enter
the client ID and secret it gives you.

### Google

1. In the Google Cloud console, create an OAuth client of the type *Web application* and add the
   address as an authorized redirect URI.
2. In Unlatch, keep the kind *OpenID Connect* and the issuer `https://accounts.google.com`, which
   a new provider starts with.

### GitHub

1. On GitHub, under *Settings*, *Developer settings*, *OAuth Apps*, register a new application
   with the address as its authorization callback URL.
2. In Unlatch, choose the kind *GitHub*. Unlatch asks GitHub for the `read:user` and `user:email`
   scopes and uses the account's primary email address.

### Another provider

Choose *OpenID Connect* and enter the provider's issuer, such as `https://auth.example.org`.
Unlatch finds the rest through discovery and asks for the `openid email profile` scopes.

## Linking accounts

The sign-in page shows a button for every enabled provider. Someone who already has an account
signs in with their password once, opens their account page and links the outside account under
*Sign-in providers*; from then on the button signs them in. With two-factor sign-in turned on,
Unlatch still asks for a code.

An outside account that isn't linked to anyone gets in only if Unlatch can create an account for
it, as below.

## Creating accounts

By default only people who already have an account can use a provider. To let others join through
it, list their email domains under *Create accounts for domains*, such as `example.com`. Whoever
signs in with an address the provider has verified in one of those domains gets an account. With
Google the account must also belong to the domain's Google Workspace.

The new account takes its username from the part of the address before `@`, with a number added
if that is taken, and its name from the provider. It belongs to no groups, so it can use only
applications open to everyone until you [add it to some](users.md#groups).
