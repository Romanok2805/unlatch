//! HTML that can't contain injected markup.
//!
//! The only way to add markup to [`Html`] is the [`html!`] macro, which accepts markup as string
//! literals written in our source code. Everything else, including any value computed at run
//! time, goes through [`Render`] and is escaped. A template therefore can't produce markup from
//! user input, however it is written.

use std::fmt::Write as _;

#[derive(Default)]
pub(crate) struct Html(String);

impl Html {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Appends markup from a string literal. Only [`html!`] calls this.
    #[doc(hidden)]
    pub(crate) fn push_literal(&mut self, markup: &'static str) {
        self.0.push_str(markup);
    }

    /// Appends text, escaped so it is safe both between tags and inside quoted attributes.
    pub(crate) fn push_text(&mut self, text: &str) {
        for c in text.chars() {
            match c {
                '&' => self.0.push_str("&amp;"),
                '<' => self.0.push_str("&lt;"),
                '>' => self.0.push_str("&gt;"),
                '"' => self.0.push_str("&quot;"),
                '\'' => self.0.push_str("&#39;"),
                _ => self.0.push(c),
            }
        }
    }

    pub(crate) fn into_string(self) -> String {
        self.0
    }
}

/// Something that can be written into a template.
pub(crate) trait Render {
    fn render(&self, out: &mut Html);
}

impl Render for Html {
    fn render(&self, out: &mut Html) {
        out.0.push_str(&self.0);
    }
}

impl Render for str {
    fn render(&self, out: &mut Html) {
        out.push_text(self);
    }
}

impl Render for String {
    fn render(&self, out: &mut Html) {
        out.push_text(self);
    }
}

impl<T: Render + ?Sized> Render for &T {
    fn render(&self, out: &mut Html) {
        (**self).render(out);
    }
}

impl<T: Render> Render for Option<T> {
    fn render(&self, out: &mut Html) {
        if let Some(value) = self {
            value.render(out);
        }
    }
}

macro_rules! render_display {
    ($($t:ty),*) => {$(
        impl Render for $t {
            fn render(&self, out: &mut Html) {
                // Numbers contain nothing to escape.
                let _ = write!(out.0, "{self}");
            }
        }
    )*};
}

render_display!(u8, u16, u32, u64, usize, i32, i64);

/// Appends parts to an [`Html`]: string literals as markup, `{expression}` as escaped text.
///
/// ```ignore
/// html!(page, "<h1>", { title }, "</h1>");
/// ```
macro_rules! html {
    ($out:expr, $($part:tt),* $(,)?) => {{
        let out: &mut $crate::html::Html = &mut $out;
        $( $crate::html::html!(@part out, $part); )*
    }};
    (@part $out:ident, $markup:literal) => {
        $out.push_literal($markup)
    };
    (@part $out:ident, { $value:expr }) => {
        $crate::html::Render::render(&$value, $out)
    };
}

pub(crate) use html;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_is_escaped_and_literals_are_not() {
        let mut page = Html::new();
        let name = "<script>alert('x')</script> & \"quotes\"";
        html!(page, "<p title=\"", { name }, "\">", { name }, "</p>", {
            42_u32
        });
        assert_eq!(
            page.into_string(),
            "<p title=\"&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt; &amp; &quot;quotes&quot;\">\
             &lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt; &amp; &quot;quotes&quot;</p>42"
        );
    }
}
