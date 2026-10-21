# Running Unlatch

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

Create the key once with `unlatch generate-key > /etc/unlatch/key` and make it readable by root
only; systemd hands it to the service.

## Behind a reverse proxy

The proxy terminates TLS and forwards requests for the issuer's host to Unlatch. List its address
in `UNLATCH_TRUSTED_PROXIES`, so Unlatch sees the real client addresses in `X-Forwarded-For`. With
Caddy:

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

Before an upgrade changes the database, Unlatch saves a copy next to it named after the old version.
