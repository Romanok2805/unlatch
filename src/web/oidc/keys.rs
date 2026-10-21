//! The keys that sign tokens: creation, rotation and publication.
//!
//! Each algorithm has a current key. A new key is created every 90 days and published in JWKS a
//! day before it starts signing, so clients that cache JWKS know it in time. The key it replaces
//! stops signing then and stays published for a week, enough for anything it signed to expire
//! or be used as a logout hint.

use super::super::{App, Failure};
use crate::crypto::{Algorithm, CryptoError, Jwk, SealingKey, SigningKey, VerifyingKey};
use crate::store::Db;
use crate::store::signing_keys::{self, StoredKey};
use crate::time;

const ROTATE_AFTER: i64 = 90 * 24 * 60 * 60;
const PUBLISH_AHEAD: i64 = 24 * 60 * 60;
const KEEP_AFTER_RETIRING: i64 = 7 * 24 * 60 * 60;

pub(crate) struct KeyRing {
    keys: Vec<RingKey>,
}

struct RingKey {
    signing: SigningKey,
    active_from: i64,
    retired_at: Option<i64>,
}

impl KeyRing {
    /// The key that signs with `algorithm` now.
    pub(crate) fn current(&self, algorithm: Algorithm, now: i64) -> Option<&SigningKey> {
        self.keys
            .iter()
            .filter(|key| {
                key.signing.algorithm() == algorithm
                    && key.active_from <= now
                    && key.retired_at.is_none_or(|retired| retired > now)
            })
            .max_by_key(|key| key.active_from)
            .map(|key| &key.signing)
    }

    /// Every published key, for checking tokens we issued.
    pub(crate) fn verifying_keys(&self) -> Vec<VerifyingKey> {
        self.keys
            .iter()
            .map(|key| key.signing.verifying_key().clone())
            .collect()
    }

    pub(crate) fn jwks(&self) -> Vec<Jwk> {
        self.keys
            .iter()
            .map(|key| key.signing.verifying_key().jwk())
            .collect()
    }
}

/// Creates, retires and deletes keys as the schedule says, then loads them. Runs at start-up
/// and daily.
pub(crate) async fn maintain(db: &Db, sealing: &SealingKey) -> Result<KeyRing, Failure> {
    let now = time::now();
    let stored = db.run(|conn| signing_keys::all(conn)).await?;

    for algorithm in Algorithm::ALL {
        let newest = stored
            .iter()
            .filter(|key| key.alg == algorithm.name())
            .max_by_key(|key| key.created_at);
        let active_from = match newest {
            None => now,
            Some(key) if now.saturating_sub(key.created_at) >= ROTATE_AFTER => {
                now.saturating_add(PUBLISH_AHEAD)
            }
            Some(_) => continue,
        };
        // RSA key generation takes a noticeable moment; keep it off the async workers.
        let (key, der) = tokio::task::spawn_blocking(move || SigningKey::generate(algorithm))
            .await
            .map_err(|_| Failure::Crypto(CryptoError))??;
        let record = StoredKey {
            kid: key.kid().to_owned(),
            alg: algorithm.name().to_owned(),
            private_key: sealing.seal(der.expose(), key.kid().as_bytes())?,
            created_at: now,
            active_from,
            retired_at: None,
        };
        db.run(move |conn| signing_keys::insert(conn, &record))
            .await?;
    }

    db.run(move |conn| {
        let keys = signing_keys::all(conn)?;
        for algorithm in Algorithm::ALL {
            let of_algorithm = keys.iter().filter(|key| key.alg == algorithm.name());
            let Some(current) = of_algorithm
                .clone()
                .filter(|key| key.active_from <= now)
                .max_by_key(|key| key.active_from)
            else {
                continue;
            };
            for older in of_algorithm.filter(|key| key.active_from < current.active_from) {
                signing_keys::retire(conn, &older.kid, current.active_from)?;
            }
        }
        signing_keys::delete_retired_before(conn, now.saturating_sub(KEEP_AFTER_RETIRING))
    })
    .await?;

    let stored = db.run(|conn| signing_keys::all(conn)).await?;
    let mut keys = Vec::with_capacity(stored.len());
    for record in stored {
        let Some(algorithm) = Algorithm::from_name(&record.alg) else {
            continue;
        };
        let der = sealing
            .open(&record.private_key, record.kid.as_bytes())
            .ok_or(CryptoError)?;
        keys.push(RingKey {
            signing: SigningKey::from_pkcs8(algorithm, der.expose())?,
            active_from: record.active_from,
            retired_at: record.retired_at,
        });
    }
    Ok(KeyRing { keys })
}

impl App {
    /// Rotates keys if due and swaps in the new set. Requests already holding the old set
    /// finish with it.
    pub(crate) async fn refresh_keys(&self) -> Result<(), Failure> {
        let ring = maintain(&self.db, &self.keys.signing).await?;
        self.set_key_ring(ring);
        Ok(())
    }
}
