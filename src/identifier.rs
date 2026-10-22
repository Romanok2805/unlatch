//! Identifiers people type and other software matches: user names, group names, Client IDs and
//! the short names of sign-in providers.

/// Lowercase ASCII letters, digits, dots, dashes and underscores, starting with a letter or digit.
/// With one case and no look-alike characters, two different identifiers can't be mistaken for
/// each other on screen or collide after normalisation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Identifier(String);

impl Identifier {
    pub(crate) const MAX_LEN: usize = 64;

    pub(crate) fn parse(text: &str) -> Option<Self> {
        let valid = text.len() <= Self::MAX_LEN
            && text.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
            && text.chars().all(|c| {
                c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '-' | '_')
            });
        valid.then(|| Self(text.to_owned()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_have_one_spelling() {
        for good in ["anna", "a", "anna.k", "anna_k-2", "9lives"] {
            assert!(Identifier::parse(good).is_some(), "{good}");
        }
        for bad in [
            "",
            "Anna",
            ".anna",
            "-anna",
            "anna k",
            "аnna",
            "anna@lan",
            &"a".repeat(65),
        ] {
            assert!(Identifier::parse(bad).is_none(), "{bad}");
        }
    }
}
