# Running Unlatch

Each release on GitHub has static Linux binaries for x86-64 and ARM64 and a container image in
the GitHub container registry. The release lists their SHA-256 sums, and `gh attestation verify`
confirms that a file or image was built from this repository by its release workflow.

## The master key

Unlatch encrypts the secrets in its database with a master key, which lives in a file of its own.
Create it once, readable by its owner only:

```sh
(umask 077; unlatch generate-key > /etc/unlatch/key)
```

Keep a copy apart from the database backups.

## With systemd

The unit below runs Unlatch as a temporary user with no access to the rest of the system. The
master key is passed as a credential, so it never sits in the service's environment or in its state
directory next to the database.

```ini
[Unit]
Description=Unlatch single sign-on
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/unlatch
Environment=UNLATCH_ISSUER=https://login.example.com
Environment=UNLATCH_LISTEN=127.0.0.1:8080
Environment=UNLATCH_TRUSTED_PROXIES=127.0.0.1
Environment=UNLATCH_DATABASE=/var/lib/unlatch/unlatch.db
LoadCredential=key:/etc/unlatch/key
Environment=UNLATCH_KEY_FILE=%d/key
DynamicUser=yes
StateDirectory=unlatch
Restart=on-failure

NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallFilter=@system-service
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
```

systemd reads the key, which can stay readable by root only, and hands it to the service.

## In a container

The image holds nothing but the binary and runs as user 65532. It listens on port 8080 and keeps
its database in the volume `/data`. Releases publish it in this repository's packages on GitHub;
`docker build -t unlatch .` builds the same from source. Give it the key as a read-only file that
user can read:

```sh
chown 65532 /etc/unlatch/key
docker run -d --name unlatch -p 127.0.0.1:8080:8080 \
  -e UNLATCH_ISSUER=https://login.example.com \
  -e UNLATCH_TRUSTED_PROXIES=172.16.0.0/12 \
  -e UNLATCH_KEY_FILE=/run/secrets/unlatch-key \
  -v /etc/unlatch/key:/run/secrets/unlatch-key:ro \
  -v unlatch:/data \
  unlatch
```

`UNLATCH_TRUSTED_PROXIES` names the network the reverse proxy connects from; the example covers
Docker's default networks.

## Behind a reverse proxy

The proxy terminates TLS and forwards requests for the issuer's host to Unlatch. List its address
in `UNLATCH_TRUSTED_PROXIES`, so Unlatch sees the real client addresses in `X-Forwarded-For`.
With Caddy:

```caddy
login.example.com {
	reverse_proxy 127.0.0.1:8080
}
```

## Backups

Back up the database and the master key, separately. The database can be copied while Unlatch runs:

```sh
sqlite3 /var/lib/unlatch/unlatch.db "VACUUM INTO '/var/backups/unlatch.db'"
```

Before an upgrade changes the database, Unlatch saves a copy next to it, such as
`unlatch.db.v1-1792600000.bak`, named after the old schema version and the time.
