//! QR codes as inline SVG, for setting up authenticator apps.

use std::fmt::Write as _;

use qrcodegen::{QrCode, QrCodeEcc};

use crate::html::{Html, html};

/// The code as an SVG image, or `None` if the text is too long to encode.
pub(crate) fn svg(text: &str, label: &str) -> Option<Html> {
    let code = QrCode::encode_text(text, QrCodeEcc::Medium).ok()?;
    let size = code.size();
    let mut path = String::new();
    for y in 0..size {
        for x in 0..size {
            if code.get_module(x, y) {
                // Writing to a String can't fail.
                let _ = write!(path, "M{x} {y}h1v1h-1z");
            }
        }
    }
    // Four modules of empty margin on each side, as scanners expect.
    let view = size.checked_add(8)?;
    let mut out = Html::new();
    html!(
        out,
        "<svg class=\"qr\" xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"-4 -4 ",
        { view },
        " ",
        { view },
        "\" role=\"img\" aria-label=\"",
        { label },
        "\"><path d=\"",
        { path },
        "\"/></svg>"
    );
    Some(out)
}
