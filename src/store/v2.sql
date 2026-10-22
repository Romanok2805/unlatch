-- Version 2. The HMAC of each user's TOTP codes; see crate::crypto::totp. Unlatch sets up SHA-1;
-- SHA-256 comes with secrets moved from another provider.

ALTER TABLE users ADD COLUMN totp_algorithm TEXT NOT NULL DEFAULT 'SHA1'
    CHECK (totp_algorithm IN ('SHA1', 'SHA256'));
