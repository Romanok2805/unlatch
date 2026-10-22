-- Version 3. Passkeys, which sign a user in on their own; see crate::crypto::passkey. Only public
-- keys are stored, which are of no use to whoever reads them.

CREATE TABLE passkeys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    credential_id BLOB NOT NULL UNIQUE,
    -- A COSE_Key (RFC 9052), as the authenticator sent it.
    public_key BLOB NOT NULL,
    -- The authenticator's signature counter; 0 for those that keep none, such as synced passkeys.
    sign_count INTEGER NOT NULL,
    -- Space-separated ways the browser can reach the authenticator, such as usb or internal.
    transports TEXT NOT NULL,
    name TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER
) STRICT;

CREATE INDEX passkeys_user ON passkeys (user_id);
