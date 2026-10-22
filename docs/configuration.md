# Configuration

Unlatch reads its configuration from environment variables when it starts.

| Variable | Default | Meaning |
|---|---|---|
| `UNLATCH_ISSUER` | required | The address people open, such as `https://login.example.com`. Every URL Unlatch sends is built from it. Plain `http` is accepted only on localhost, for trying Unlatch out. Passkeys need a host name, so they are off when this is an IP address. |
| `UNLATCH_KEY_FILE` | required | A file with the master key, which encrypts the secrets in the database; see [the master key](running.md#the-master-key). |
| `UNLATCH_LISTEN` | `127.0.0.1:8080` | The address and port to listen on. |
| `UNLATCH_DATABASE` | `unlatch.db` | The SQLite file. It is created if it doesn't exist. |
| `UNLATCH_TRUSTED_PROXIES` | none | Addresses or networks of your reverse proxies, separated by commas, such as `127.0.0.1, 10.0.0.0/8`. `X-Forwarded-For` is believed only from these. |
| `UNLATCH_LOG` | `info` | `error`, `warn` or `info`. |
| `UNLATCH_TLS_CERT`, `UNLATCH_TLS_KEY` | none | PEM files of a certificate chain and its key, to serve https without a reverse proxy. Unlatch reads them again within a minute of a change, so renewals need no restart. |
