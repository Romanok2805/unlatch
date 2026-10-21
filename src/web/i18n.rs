//! The interface in English and Russian.
//!
//! Every string is a field of [`Text`], so a missing translation doesn't compile.

use crate::http::Request;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lang {
    En,
    Ru,
}

/// The cookie that remembers a language picked in the footer.
pub(crate) const COOKIE: &str = "lang";

impl Lang {
    /// The language picked in the footer, else the first supported one the browser asks for.
    pub(crate) fn of(request: &Request) -> Self {
        if let Some(lang) = request.cookie(COOKIE).and_then(Self::from_code) {
            return lang;
        }
        request
            .header("accept-language")
            .unwrap_or_default()
            .split(',')
            .filter(|entry| !entry.trim().ends_with(";q=0"))
            .find_map(|entry| {
                let tag = entry.split(';').next().unwrap_or_default().trim();
                Self::from_code(tag.split('-').next().unwrap_or_default())
            })
            .unwrap_or(Self::En)
    }

    pub(crate) fn from_code(code: &str) -> Option<Self> {
        match code.to_ascii_lowercase().as_str() {
            "en" => Some(Self::En),
            "ru" => Some(Self::Ru),
            _ => None,
        }
    }

    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::Ru => "ru",
        }
    }

    /// The other language, offered in the footer under its own name.
    pub(crate) const fn other(self) -> (Self, &'static str) {
        match self {
            Self::En => (Self::Ru, "Русский"),
            Self::Ru => (Self::En, "English"),
        }
    }

    pub(crate) const fn text(self) -> &'static Text {
        match self {
            Self::En => &EN,
            Self::Ru => &RU,
        }
    }
}

pub(crate) struct Text {
    pub(crate) not_found: &'static str,
    pub(crate) bad_request: &'static str,
    pub(crate) server_error: &'static str,
    pub(crate) home: &'static str,
}

static EN: Text = Text {
    not_found: "Page not found",
    bad_request: "This link doesn't work",
    server_error: "Something went wrong",
    home: "Home",
};

static RU: Text = Text {
    not_found: "Страница не найдена",
    bad_request: "Ссылка не работает",
    server_error: "Что-то пошло не так",
    home: "На главную",
};
