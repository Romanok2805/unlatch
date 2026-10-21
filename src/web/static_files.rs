//! The stylesheet and icons, compiled into the binary.
//!
//! Their URLs contain a hash of their contents, so browsers can cache them for good and still
//! fetch new versions after an upgrade.

use std::sync::OnceLock;

use hyper::{StatusCode, header};

use crate::crypto::sha256;
use crate::encoding::base64url;
use crate::http::Response;

struct Asset {
    name: &'static str,
    content_type: &'static str,
    body: &'static [u8],
}

const ASSETS: [Asset; 3] = [
    Asset {
        name: "style.css",
        content_type: "text/css; charset=utf-8",
        body: include_bytes!("../../assets/style.css"),
    },
    Asset {
        name: "app.js",
        content_type: "text/javascript; charset=utf-8",
        body: include_bytes!("../../assets/app.js"),
    },
    Asset {
        name: "icons.svg",
        content_type: "image/svg+xml",
        body: include_bytes!("../../assets/icons.svg"),
    },
];

fn version() -> &'static str {
    static VERSION: OnceLock<String> = OnceLock::new();
    VERSION.get_or_init(|| {
        let all: Vec<u8> = ASSETS
            .iter()
            .flat_map(|asset| asset.body.iter().copied())
            .collect();
        base64url(&sha256(&all)).chars().take(12).collect()
    })
}

pub(crate) fn url(name: &str) -> String {
    format!("/static/{}/{name}", version())
}

/// Serves `/static/<version>/<name>`. Another version is a 404 rather than today's file, so a
/// stale page can't cache new content under an old URL.
pub(crate) fn serve(path: &str) -> Option<Response> {
    let rest = path.strip_prefix("/static/")?;
    let (requested_version, name) = rest.split_once('/')?;
    if requested_version != version() {
        return None;
    }
    let asset = ASSETS.iter().find(|asset| asset.name == name)?;
    Some(
        Response::new(StatusCode::OK, asset.content_type, asset.body)
            .header(header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
    )
}
