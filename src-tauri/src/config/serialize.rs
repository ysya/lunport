use crate::config::model::{Directive, Item, Separator};

/// Render a single directive line (no trailing newline).
///
/// When the directive is not dirty, the original `raw` text is emitted verbatim so that
/// unedited lines round-trip byte-identically. Once any structured field has been edited
/// (`dirty == true`), the line is re-rendered from its fields instead.
pub fn render_directive(d: &Directive) -> String {
    if !d.dirty {
        return d.raw.clone();
    }

    let sep = match &d.separator {
        Separator::Space(s) => s.as_str(),
        Separator::Equals(s) => s.as_str(),
    };

    let body = format!(
        "{}{}{}{}{}",
        d.keyword,
        sep,
        d.value,
        d.trailing_ws,
        d.inline_comment.as_deref().unwrap_or("")
    );

    if d.enabled {
        format!("{}{}", d.indent, body)
    } else {
        // Disabled directives are serialized commented-out.
        format!("{}# {}", d.indent, body)
    }
}

/// Flatten items into ordered physical lines and join them with `'\n'`.
/// Appends a trailing `'\n'` iff `trailing_newline`.
pub fn serialize_items(items: &[Item], trailing_newline: bool) -> String {
    let mut lines: Vec<String> = Vec::new();
    push_items(items, &mut lines);

    let mut out = lines.join("\n");
    if trailing_newline {
        out.push('\n');
    }
    out
}

fn push_items(items: &[Item], lines: &mut Vec<String>) {
    for item in items {
        match item {
            Item::Blank(s) => lines.push(s.clone()),
            Item::Comment(s) => lines.push(s.clone()),
            Item::Directive(d) => lines.push(render_directive(d)),
            Item::Host(h) => {
                lines.push(render_directive(&h.header));
                push_items(&h.body, lines);
            }
            Item::Match(m) => {
                lines.push(render_directive(&m.header));
                push_items(&m.body, lines);
            }
        }
    }
}
