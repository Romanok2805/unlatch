//! Unlatch: a small, self-hosted OpenID Connect provider.
#![expect(
    dead_code,
    unused_imports,
    reason = "the HTTP layer that uses these modules comes in a later stage"
)]
#![cfg_attr(not(test), expect(unused_macros, reason = "the same"))]

mod crypto;
mod encoding;
mod form;
mod html;
mod secret;
mod store;
mod time;
mod uri;

fn main() {}
