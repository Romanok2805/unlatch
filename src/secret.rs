//! Values that must never reach a log or a response and must be compared in constant time.

use zeroize::Zeroize;

/// A secret such as a password, a key or a TOTP seed.
///
/// It has no `Debug`, `Display`, `Clone` or `Serialize`, so it can't be printed, copied or sent by
/// accident, and its memory is wiped when it is dropped. `expose` is the one way to read it, and
/// every call is easy to find.
pub(crate) struct Secret<T: Zeroize>(T);

impl<T: Zeroize> Secret<T> {
    pub(crate) fn new(value: T) -> Self {
        Self(value)
    }

    pub(crate) fn expose(&self) -> &T {
        &self.0
    }

    pub(crate) fn expose_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T: Zeroize> Drop for Secret<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
