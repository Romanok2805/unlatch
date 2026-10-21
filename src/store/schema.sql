-- Version 1. Times are Unix seconds. Tokens are stored as SHA-256 hashes and secrets sealed with a
-- key derived from the master key; see docs/architecture.md.

CREATE TABLE settings (
    name TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;

CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    email TEXT,
    email_verified INTEGER NOT NULL DEFAULT 0,
    -- NULL until the user accepts their invitation.
    password_hash TEXT,
    totp_secret BLOB,
    -- The last time step a code was accepted for; older codes are refused.
    totp_last_step INTEGER,
    is_admin INTEGER NOT NULL DEFAULT 0,
    disabled INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE recovery_codes (
    user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash BLOB NOT NULL,
    PRIMARY KEY (user_id, code_hash)
) STRICT;

-- One-time links to set a password: invitations and resets.
CREATE TABLE password_links (
    token_hash BLOB PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
) STRICT;

CREATE TABLE groups (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE
) STRICT;

CREATE TABLE group_members (
    group_id INTEGER NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, user_id)
) STRICT;

CREATE INDEX group_members_user ON group_members (user_id);

-- Applications: OpenID Connect clients and hosts protected by forward authentication.
CREATE TABLE apps (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('oidc', 'proxy')),
    enabled INTEGER NOT NULL DEFAULT 1,
    -- Everyone may use it; otherwise only members of app_groups.
    all_users INTEGER NOT NULL DEFAULT 0,
    skip_consent INTEGER NOT NULL DEFAULT 0,
    client_id TEXT UNIQUE,
    -- NULL for public clients, which authenticate with PKCE alone.
    client_secret_hash BLOB,
    id_token_alg TEXT NOT NULL DEFAULT 'RS256',
    backchannel_logout_uri TEXT,
    host TEXT UNIQUE,
    created_at INTEGER NOT NULL,
    CHECK ((kind = 'oidc') = (client_id IS NOT NULL)),
    CHECK ((kind = 'proxy') = (host IS NOT NULL))
) STRICT;

CREATE TABLE app_uris (
    app_id INTEGER NOT NULL REFERENCES apps (id) ON DELETE CASCADE,
    purpose TEXT NOT NULL CHECK (purpose IN ('redirect', 'post_logout', 'resource')),
    uri TEXT NOT NULL,
    PRIMARY KEY (app_id, purpose, uri)
) STRICT;

CREATE TABLE app_groups (
    app_id INTEGER NOT NULL REFERENCES apps (id) ON DELETE CASCADE,
    group_id INTEGER NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
    PRIMARY KEY (app_id, group_id)
) STRICT;

CREATE TABLE consents (
    user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    app_id INTEGER NOT NULL REFERENCES apps (id) ON DELETE CASCADE,
    scope TEXT NOT NULL,
    PRIMARY KEY (user_id, app_id)
) STRICT;

CREATE TABLE sessions (
    id INTEGER PRIMARY KEY,
    token_hash BLOB NOT NULL UNIQUE,
    -- The `sid` claim. Unlike the token, it is safe to show and to send to applications.
    public_id TEXT NOT NULL UNIQUE,
    user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- Space-separated `amr` values: pwd, otp, fed.
    amr TEXT NOT NULL,
    auth_time INTEGER NOT NULL,
    -- When the second factor was last entered; administration asks again after a while.
    verified_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    ip TEXT NOT NULL,
    user_agent TEXT NOT NULL
) STRICT;

CREATE INDEX sessions_user ON sessions (user_id);

CREATE TABLE codes (
    code_hash BLOB PRIMARY KEY,
    app_id INTEGER NOT NULL REFERENCES apps (id) ON DELETE CASCADE,
    session_id INTEGER NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    scope TEXT NOT NULL,
    nonce TEXT,
    code_challenge TEXT NOT NULL,
    resource TEXT,
    expires_at INTEGER NOT NULL,
    -- Set when the code is redeemed. Redeeming it again revokes this grant.
    grant_id INTEGER REFERENCES grants (id) ON DELETE CASCADE
) STRICT;

-- What a session allowed an application to do. Refresh tokens aren't stored: each one is sealed
-- and names its grant and generation. Only the current generation is accepted, and an older one
-- means the token was copied, so the grant is revoked.
CREATE TABLE grants (
    id INTEGER PRIMARY KEY,
    session_id INTEGER NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    app_id INTEGER NOT NULL REFERENCES apps (id) ON DELETE CASCADE,
    scope TEXT NOT NULL,
    resource TEXT,
    generation INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
) STRICT;

CREATE INDEX grants_session ON grants (session_id);

-- Applications that received tokens in a session. They are told when it ends, even if their
-- grant was revoked earlier.
CREATE TABLE session_apps (
    session_id INTEGER NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    app_id INTEGER NOT NULL REFERENCES apps (id) ON DELETE CASCADE,
    PRIMARY KEY (session_id, app_id)
) STRICT;

-- One-time codes that carry a sign-in from Unlatch to a host behind forward authentication.
CREATE TABLE proxy_codes (
    code_hash BLOB PRIMARY KEY,
    session_id INTEGER NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    app_id INTEGER NOT NULL REFERENCES apps (id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    expires_at INTEGER NOT NULL
) STRICT;

-- Per-host sessions of forward authentication.
CREATE TABLE proxy_sessions (
    token_hash BLOB PRIMARY KEY,
    session_id INTEGER NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    app_id INTEGER NOT NULL REFERENCES apps (id) ON DELETE CASCADE
) STRICT;

CREATE TABLE signing_keys (
    kid TEXT PRIMARY KEY,
    alg TEXT NOT NULL,
    -- PKCS #8, sealed.
    private_key BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    -- Published in JWKS from creation, used for signing from here on.
    active_from INTEGER NOT NULL,
    -- No longer signs; stays published until its tokens have expired.
    retired_at INTEGER
) STRICT;

CREATE TABLE providers (
    id INTEGER PRIMARY KEY,
    -- Part of the callback URL registered at the provider.
    slug TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('oidc', 'github')),
    issuer TEXT,
    client_id TEXT NOT NULL,
    client_secret BLOB NOT NULL,
    -- Space-separated email domains whose users get an account on first sign-in. Empty: nobody.
    auto_create_domains TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    CHECK ((kind = 'oidc') = (issuer IS NOT NULL))
) STRICT;

CREATE TABLE provider_links (
    provider_id INTEGER NOT NULL REFERENCES providers (id) ON DELETE CASCADE,
    subject TEXT NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (provider_id, subject)
) STRICT;

CREATE INDEX provider_links_user ON provider_links (user_id);

-- Kept after the user or app is deleted, so references are copied as text.
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY,
    at INTEGER NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    ip TEXT NOT NULL
) STRICT;

CREATE INDEX audit_log_at ON audit_log (at);
