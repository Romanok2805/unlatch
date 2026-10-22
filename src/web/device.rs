//! What a User-Agent header says about the device behind a session.

/// "Firefox, Windows" from a User-Agent header; enough to recognise one's own devices.
pub(crate) fn describe_device(user_agent: &str) -> String {
    let contains = |needle: &str| user_agent.contains(needle);
    let browser = if contains("Firefox/") {
        "Firefox"
    } else if contains("Edg/") {
        "Edge"
    } else if contains("OPR/") {
        "Opera"
    } else if contains("Chrome/") {
        "Chrome"
    } else if contains("Safari/") {
        "Safari"
    } else {
        ""
    };
    let system = if contains("Windows") {
        "Windows"
    } else if contains("iPhone") || contains("iPad") {
        "iOS"
    } else if contains("Mac OS X") {
        "macOS"
    } else if contains("Android") {
        "Android"
    } else if contains("Linux") {
        "Linux"
    } else {
        ""
    };
    match (browser, system) {
        ("", "") => user_agent.chars().take(40).collect(),
        (browser, "") | ("", browser) => browser.to_owned(),
        (browser, system) => format!("{browser}, {system}"),
    }
}

#[cfg(test)]
mod tests {
    use super::describe_device;

    #[test]
    fn names_common_browsers() {
        let firefox =
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0";
        let safari = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 \
                      (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1";
        assert_eq!(describe_device(firefox), "Firefox, Windows");
        assert_eq!(describe_device(safari), "Safari, iOS");
        assert_eq!(describe_device("curl/8.0"), "curl/8.0");
    }
}
