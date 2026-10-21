#![no_main]

use url::{Host, Url};

// Two lines: a registered redirect URI and a requested one. A request that isn't the registered
// string itself may only differ in the port of a loopback address (RFC 8252, section 7.3), as a
// browser's parser sees it.
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let (registered, requested) = text.split_once('\n').unwrap_or((text, text));
    let Some(true) = unlatch::fuzz::redirect_uri_matches(registered, requested) else {
        return;
    };
    if registered == requested {
        return;
    }
    let (Ok(registered), Ok(requested)) = (Url::parse(registered), Url::parse(requested)) else {
        panic!("matched a URI a browser can't parse: {registered:?}, {requested:?}");
    };
    let loopback = match registered.host() {
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        _ => false,
    };
    assert!(loopback && registered.scheme() == "http", "{registered}");
    assert_eq!(
        (requested.scheme(), requested.host(), requested.path(), requested.query()),
        (registered.scheme(), registered.host(), registered.path(), registered.query()),
    );
});
