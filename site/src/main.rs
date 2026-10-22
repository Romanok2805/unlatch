//! Builds unlatch.dev from the Markdown in this repository into `site/out`, so the documentation
//! is written once and reads the same on GitHub and on the site:
//!
//! ```sh
//! cargo run --manifest-path site/Cargo.toml
//! ```

use std::error::Error;
use std::fs;
use std::path::Path;

use pulldown_cmark::{CowStr, Event, HeadingLevel, Options, Parser, Tag, TagEnd, html};

const REPOSITORY: &str = "https://github.com/Romanok2805/unlatch";

/// Each page: its Markdown file and its address on the site. The menu lists them in this order.
/// The site is for people who run Unlatch; links to documents for contributors lead to GitHub.
const PAGES: [(&str, &str); 8] = [
    ("README.md", "/"),
    ("docs/running.md", "/docs/running/"),
    ("docs/configuration.md", "/docs/configuration/"),
    ("docs/applications.md", "/docs/applications/"),
    ("docs/users.md", "/docs/users/"),
    ("docs/providers.md", "/docs/providers/"),
    ("docs/forward-auth.md", "/docs/forward-auth/"),
    ("CHANGELOG.md", "/changelog/"),
];

const TEMPLATE: &str = include_str!("../page.html");
const STYLE: &str = include_str!("../style.css");

struct Page {
    address: &'static str,
    /// The text of the first heading.
    title: String,
    /// The text of the first paragraph, for search engines.
    summary: String,
    html: String,
    /// Images in the repository that the page shows, copied to the same paths on the site.
    images: Vec<String>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let site = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = site
        .parent()
        .ok_or("the site crate is not inside the repository")?;
    let out = site.join("out");

    let mut pages = Vec::new();
    for (source, address) in PAGES {
        let markdown =
            fs::read_to_string(root.join(source)).map_err(|error| format!("{source}: {error}"))?;
        pages.push(render(source, address, &markdown));
    }

    if out.exists() {
        fs::remove_dir_all(&out)?;
    }
    for page in &pages {
        let title = if page.address == "/" {
            page.title.clone()
        } else {
            format!("{} · Unlatch", page.title)
        };
        let html = TEMPLATE
            .replace("{title}", &escape(&title))
            .replace("{summary}", &escape(&page.summary))
            .replace("{repository}", REPOSITORY)
            .replace("{menu}", &menu(&pages, page.address))
            .replace("{content}", &page.html);
        let dir = out.join(page.address.trim_start_matches('/'));
        fs::create_dir_all(&dir)?;
        fs::write(dir.join("index.html"), html)?;
    }
    for image in pages.iter().flat_map(|page| &page.images) {
        let target = out.join(image);
        if let Some(dir) = target.parent() {
            fs::create_dir_all(dir)?;
        }
        fs::copy(root.join(image), target).map_err(|error| format!("{image}: {error}"))?;
    }
    fs::write(out.join("style.css"), STYLE)?;
    Ok(())
}

fn render(source: &str, address: &'static str, markdown: &str) -> Page {
    let mut events = without_badges(Parser::new_ext(markdown, Options::ENABLE_TABLES).collect());
    let mut title = None;
    let mut summary = None;
    let mut ids: Vec<String> = Vec::new();
    let mut images = Vec::new();

    for i in 0..events.len() {
        let text = match &events[i] {
            Event::Start(Tag::Heading { .. }) => text_of(&events[i + 1..]),
            Event::Start(Tag::Paragraph) if summary.is_none() => text_of(&events[i + 1..]),
            _ => String::new(),
        };
        match &mut events[i] {
            Event::Start(Tag::Heading { level, id, .. }) => {
                // GitHub's anchors, so links between documents work in both places.
                let mut anchor = slug(&text);
                let base = anchor.clone();
                let mut n = 0;
                while ids.contains(&anchor) {
                    n += 1;
                    anchor = format!("{base}-{n}");
                }
                ids.push(anchor.clone());
                *id = Some(CowStr::from(anchor));
                if *level == HeadingLevel::H1 && title.is_none() {
                    title = Some(text);
                }
            }
            Event::Start(Tag::Paragraph) if summary.is_none() => summary = Some(text),
            Event::Start(Tag::Link { dest_url, .. }) => {
                *dest_url = CowStr::from(link(source, dest_url));
            }
            Event::Start(Tag::Image { dest_url, .. }) if !dest_url.contains(':') => {
                let path = resolve(source, dest_url);
                *dest_url = CowStr::from(format!("/{path}"));
                images.push(path);
            }
            _ => {}
        }
    }

    let mut html = String::new();
    html::push_html(&mut html, events.into_iter());
    Page {
        address,
        title: title.unwrap_or_else(|| source.to_owned()),
        summary: summary.unwrap_or_default(),
        html,
        images,
    }
}

/// The plain text of the element whose children start `events`.
fn text_of(events: &[Event<'_>]) -> String {
    let mut text = String::new();
    let mut depth = 0_u32;
    for event in events {
        match event {
            Event::Start(_) => depth += 1,
            Event::End(_) if depth == 0 => break,
            Event::End(_) => depth -= 1,
            Event::Text(t) | Event::Code(t) => text.push_str(t),
            Event::SoftBreak | Event::HardBreak => text.push(' '),
            _ => {}
        }
    }
    text
}

fn slug(text: &str) -> String {
    text.chars()
        .filter(|c| c.is_alphanumeric() || matches!(c, ' ' | '-' | '_'))
        .flat_map(char::to_lowercase)
        .map(|c| if c == ' ' { '-' } else { c })
        .collect()
}

/// Where a link in `source` leads: another page of the site, or the file on GitHub.
fn link(source: &str, dest: &str) -> String {
    if dest.starts_with('#') || dest.contains(':') {
        return dest.to_owned();
    }
    let (path, fragment) = dest
        .split_once('#')
        .map_or((dest, None), |(p, f)| (p, Some(f)));
    let target = resolve(source, path);
    let mut url = PAGES
        .iter()
        .find(|(source, _)| *source == target)
        .map_or_else(
            || format!("{REPOSITORY}/blob/main/{target}"),
            |(_, a)| (*a).to_owned(),
        );
    if let Some(fragment) = fragment {
        url.push('#');
        url.push_str(fragment);
    }
    url
}

/// The file in the repository that `path`, written in `source`, points to.
fn resolve(source: &str, path: &str) -> String {
    let mut parts: Vec<&str> = source.split('/').collect();
    parts.pop();
    for part in path.split('/') {
        match part {
            ".." => {
                parts.pop();
            }
            "." | "" => {}
            part => parts.push(part),
        }
    }
    parts.join("/")
}

/// Leaves out paragraphs made only of linked images: the badges at the top of the README are for
/// GitHub, and the site already leads to the same places.
fn without_badges(events: Vec<Event<'_>>) -> Vec<Event<'_>> {
    let mut kept = Vec::with_capacity(events.len());
    let mut rest = events.into_iter();
    while let Some(event) = rest.next() {
        if !matches!(event, Event::Start(Tag::Paragraph)) {
            kept.push(event);
            continue;
        }
        let paragraph: Vec<Event<'_>> = rest
            .by_ref()
            .take_while(|event| !matches!(event, Event::End(TagEnd::Paragraph)))
            .collect();
        if !is_badges(&paragraph) {
            kept.push(event);
            kept.extend(paragraph);
            kept.push(Event::End(TagEnd::Paragraph));
        }
    }
    kept
}

fn is_badges(paragraph: &[Event<'_>]) -> bool {
    let (mut in_link, mut in_image, mut images) = (false, false, 0);
    for event in paragraph {
        match event {
            Event::Start(Tag::Link { .. }) => in_link = true,
            Event::End(TagEnd::Link) => in_link = false,
            Event::Start(Tag::Image { .. }) if in_link => {
                in_image = true;
                images += 1;
            }
            Event::End(TagEnd::Image) => in_image = false,
            Event::Text(_) if in_image => {}
            Event::SoftBreak => {}
            _ => return false,
        }
    }
    images > 0
}

fn menu(pages: &[Page], current: &str) -> String {
    let mut html = String::new();
    // The name in the header leads to the first page.
    for page in pages.iter().skip(1) {
        let attribute = if page.address == current {
            r#" aria-current="page""#
        } else {
            ""
        };
        html.push_str(&format!(
            "<li><a href=\"{}\"{attribute}>{}</a></li>",
            page.address,
            escape(&page.title)
        ));
    }
    html
}

fn escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            c => escaped.push(c),
        }
    }
    escaped
}
