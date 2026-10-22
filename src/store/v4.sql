-- Version 4. Providers the administrator trusts to check a second factor themselves: an account
-- with two-factor sign-in that signs in through one isn't asked for its code. Administration
-- and passkeys still ask for it; see crate::web::signin::after_provider.

ALTER TABLE providers ADD COLUMN skip_code INTEGER NOT NULL DEFAULT 0;
