# OpenID conformance

Unlatch is tested with the OpenID Foundation's
[conformance suite](https://gitlab.com/openid/conformance-suite), run locally. It is not certified.

## Results

Suite 5.3.3, 22 October 2026, OpenID Provider plans with discovery and static clients:

| Plan | Passed | Review | Warning | Skipped | Failed |
|---|---|---|---|---|---|
| Basic | 22 | 4 | 5 | 4 | 0 |
| Config | 1 | 0 | 0 | 0 | 0 |
| Form Post Basic | 22 | 4 | 5 | 3 | 1 |
| RP-Initiated Logout | 3 | 8 | 0 | 0 | 0 |

*Review* means the suite took a screenshot for a person to check: Unlatch had to show a page
instead of redirecting, or a fresh sign-in was due.

The warnings, the same in both plans that have them:

- `oidcc-scope-email`, `oidcc-alternate-happy-flow`: the email address is in the ID token too,
  not only in userinfo. This is on purpose: Kubernetes and some other clients read claims only
  from the ID token.
- `oidcc-scope-profile`: of the profile claims, Unlatch has only `name` and `preferred_username`.
- `oidcc-ensure-request-with-acr-values-succeeds`: there is no `acr` claim.
- `oidcc-claims-essential`: the `claims` request parameter isn't supported.

Skipped are the address and phone scopes, which Unlatch has no data for, and request objects.
The one failure, `oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported`
in the Form Post plan, expects the `request_not_supported` error to arrive in the response mode
named inside the request object, which Unlatch doesn't read.

The back-channel logout plan isn't run: Unlatch trusts only public certificate authorities for
its outgoing requests, and the suite's endpoint has a self-signed certificate.

## Running the tests

1. Start the suite with its prebuilt images. It serves `https://localhost.emobix.co.uk:8443`, a
   public name for 127.0.0.1.

   ```sh
   curl -O https://gitlab.com/openid/conformance-suite/-/raw/master/docker-compose-prebuilt.yml
   docker compose -f docker-compose-prebuilt.yml up -d
   ```

2. Start Unlatch where the suite's containers reach it, with TLS. A self-signed certificate for
   `host.docker.internal` will do; the suite doesn't check it. Docker Desktop forwards that name
   to the host's loopback.

   ```sh
   unlatch generate-key > conformance.key
   UNLATCH_ISSUER=https://host.docker.internal:9443 UNLATCH_LISTEN=127.0.0.1:9443 \
   UNLATCH_TLS_CERT=cert.pem UNLATCH_TLS_KEY=key.pem \
   UNLATCH_KEY_FILE=conformance.key UNLATCH_DATABASE=conformance.db unlatch
   ```

3. In administration, invite the user `tester` with an email address, open the invitation link
   and set the password `conformance suite password`. Leave two-factor sign-in off: the suite's
   browser can't enter codes. Add two OpenID Connect applications for everyone, with *Don't
   ask* on and *Require PKCE* off, since the suite sends PKCE in only one test. Both get
   these addresses:

   - redirect URI `https://localhost.emobix.co.uk:8443/test/a/unlatch/callback`
   - post-logout URI `https://localhost.emobix.co.uk:8443/test/a/unlatch/post_logout_redirect`

4. Write the suite's configuration with the two clients:

   ```sh
   python config.py <client id> <secret> <second client id> <second secret>
   ```

5. In this directory, run the plans with `scripts/run-test-plan.py` from a checkout of the suite,
   which needs the Python packages in its `scripts/requirements.txt`:

   ```sh
   python <suite>/scripts/run-test-plan.py --export-dir results \
     "oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]" unlatch.json \
     oidcc-config-certification-test-plan unlatch.json \
     "oidcc-formpost-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]" unlatch.json \
     "oidcc-rp-initiated-logout-certification-test-plan[response_type=code][client_registration=static_client]" unlatch.json
   ```

   Each module's log is at `https://localhost.emobix.co.uk:8443`.
