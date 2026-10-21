#![no_main]

use url::Url;

// An address we accept as a path on this server must keep a browser on our host, however the
// browser resolves it.
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Ok(path) = std::str::from_utf8(data) else {
        return;
    };
    if !unlatch::fuzz::is_local_path(path) {
        return;
    }
    let base = Url::parse("https://login.example.com/account").unwrap();
    if let Ok(target) = base.join(path) {
        assert_eq!(
            (target.scheme(), target.host_str(), target.port()),
            ("https", Some("login.example.com"), None),
            "{path:?}"
        );
    }
});
