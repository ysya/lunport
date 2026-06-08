use crate::config::lexer::{classify_line, LineKind};
use crate::config::model::{HostBlock, Item, MatchBlock};

/// Parse a whole config file's text into top-level items + whether it ended with a newline.
///
/// The split is byte-faithful: a Host/Match directive becomes a block header and the following
/// lines (up to the next header or EOF) move into its body. Items before the first header stay
/// at top level (global scope).
pub fn parse_file(text: &str) -> (Vec<Item>, bool) {
    let trailing_newline = text.ends_with('\n');

    // Empty input => zero items.
    if text.is_empty() {
        return (Vec::new(), trailing_newline);
    }

    // Strip exactly one trailing '\n' (if present) so `split('\n')` yields exactly the physical
    // lines, with no phantom trailing empty element. Do NOT use `.lines()` — it would drop the
    // trailing-newline distinction and any trailing empty line.
    let body = if trailing_newline {
        &text[..text.len() - 1]
    } else {
        text
    };

    // Classify each physical line into a flat list of items. A directive whose key is "host" or
    // "match" is a block header; the grouping pass below consumes it.
    let flat: Vec<Item> = body
        .split('\n')
        .map(|line| match classify_line(line) {
            LineKind::Blank => Item::Blank(line.to_string()),
            LineKind::Comment => Item::Comment(line.to_string()),
            LineKind::Directive(d) => Item::Directive(d),
        })
        .collect();

    let items = group_blocks(flat);
    (items, trailing_newline)
}

/// Returns whether a flat item is a Host/Match block header directive.
fn header_kind(item: &Item) -> Option<HeaderKind> {
    if let Item::Directive(d) = item {
        match d.key.as_str() {
            "host" => return Some(HeaderKind::Host),
            "match" => return Some(HeaderKind::Match),
            _ => {}
        }
    }
    None
}

enum HeaderKind {
    Host,
    Match,
}

/// Group a flat item list into top-level items, folding lines following a Host/Match header into
/// that block's body until the next header or EOF.
fn group_blocks(flat: Vec<Item>) -> Vec<Item> {
    let mut out: Vec<Item> = Vec::new();
    let mut iter = flat.into_iter().peekable();

    while let Some(item) = iter.next() {
        match header_kind(&item) {
            Some(kind) => {
                // Pull out the header directive.
                let header = match item {
                    Item::Directive(d) => d,
                    _ => unreachable!("header_kind only matches Item::Directive"),
                };

                // Collect body: everything until the next header or EOF.
                let mut block_body: Vec<Item> = Vec::new();
                while let Some(next) = iter.peek() {
                    if header_kind(next).is_some() {
                        break;
                    }
                    block_body.push(iter.next().unwrap());
                }

                match kind {
                    HeaderKind::Host => {
                        let patterns = header
                            .value
                            .split_whitespace()
                            .map(String::from)
                            .collect();
                        out.push(Item::Host(HostBlock {
                            header,
                            patterns,
                            body: block_body,
                        }));
                    }
                    HeaderKind::Match => {
                        let criteria = header.value.clone();
                        out.push(Item::Match(MatchBlock {
                            header,
                            criteria,
                            body: block_body,
                        }));
                    }
                }
            }
            None => {
                // Global item before the first header (or a stray top-level item).
                out.push(item);
            }
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::model::Item;
    use crate::config::serialize::serialize_items;

    const FIXTURE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/");

    const FIXTURES: &[&str] = &[
        "simple.sshconfig",
        "comments_blanks.sshconfig",
        "equals_indent.sshconfig",
        "match_include.sshconfig",
        "unknown_dup.sshconfig",
        "disabled.sshconfig",
    ];

    fn read_fixture(name: &str) -> String {
        let path = format!("{}{}", FIXTURE_DIR, name);
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {}", path, e))
    }

    /// THE INVARIANT: parse -> serialize must be byte-identical for unedited files.
    #[test]
    fn golden_round_trip_all_fixtures() {
        for name in FIXTURES {
            let text = read_fixture(name);
            let (items, nl) = parse_file(&text);
            let out = serialize_items(&items, nl);
            assert_eq!(out, text, "round-trip mismatch for fixture {}", name);
        }
    }

    #[test]
    fn no_trailing_newline_round_trips() {
        let text = "Host x\n    User y";
        let (items, nl) = parse_file(text);
        assert!(!nl, "trailing_newline should be false");
        assert_eq!(serialize_items(&items, nl), text);
    }

    #[test]
    fn crlf_preserved_round_trips() {
        let text = "Host x\r\n    User y\r\n";
        let (items, nl) = parse_file(text);
        assert!(nl, "trailing_newline should be true");
        assert_eq!(serialize_items(&items, nl), text);
        // The CR survives in raw of the host header line.
        if let Item::Host(h) = &items[0] {
            assert!(h.header.raw.ends_with('\r'), "CR must survive in raw");
        } else {
            panic!("expected first item to be a Host block");
        }
    }

    #[test]
    fn empty_input() {
        let (items, nl) = parse_file("");
        assert!(items.is_empty());
        assert!(!nl);
        assert_eq!(serialize_items(&items, nl), "");
    }

    #[test]
    fn block_grouping_simple() {
        let text = read_fixture("simple.sshconfig");
        let (items, _) = parse_file(&text);

        let hosts: Vec<&HostBlock> = items
            .iter()
            .filter_map(|it| match it {
                Item::Host(h) => Some(h),
                _ => None,
            })
            .collect();
        assert_eq!(hosts.len(), 2, "expected exactly 2 Host blocks");

        // First host: patterns == ["web"], body contains the expected directives.
        assert_eq!(hosts[0].patterns, vec!["web".to_string()]);
        let first_keys: Vec<String> = hosts[0]
            .body
            .iter()
            .filter_map(|it| match it {
                Item::Directive(d) => Some(d.key.clone()),
                _ => None,
            })
            .collect();
        assert!(first_keys.contains(&"hostname".to_string()));
        assert!(first_keys.contains(&"user".to_string()));
        assert!(first_keys.contains(&"port".to_string()));
        assert!(first_keys.contains(&"identityfile".to_string()));

        // Second host.
        assert_eq!(hosts[1].patterns, vec!["db".to_string()]);
    }

    #[test]
    fn block_grouping_match_include() {
        let text = read_fixture("match_include.sshconfig");
        let (items, _) = parse_file(&text);

        // A Match block exists with non-empty criteria.
        let match_block = items.iter().find_map(|it| match it {
            Item::Match(m) => Some(m),
            _ => None,
        });
        let m = match_block.expect("expected a Match block");
        assert!(!m.criteria.is_empty(), "Match criteria must be non-empty");
        assert!(m.criteria.contains("bastion.example.com"));

        // The Include line is a TOP-LEVEL Directive with key "include".
        let include = items.iter().find_map(|it| match it {
            Item::Directive(d) if d.key == "include" => Some(d),
            _ => None,
        });
        let inc = include.expect("expected a top-level Include directive");
        assert_eq!(inc.value, "config.d/*.conf");

        // Host prod-* !prod-old yields patterns == ["prod-*", "!prod-old"].
        let prod = items.iter().find_map(|it| match it {
            Item::Host(h) if h.patterns.first().map(|p| p.as_str()) == Some("prod-*") => Some(h),
            _ => None,
        });
        let p = prod.expect("expected the prod-* Host block");
        assert_eq!(
            p.patterns,
            vec!["prod-*".to_string(), "!prod-old".to_string()]
        );

        // The Match block's body holds the indented directives (not the Include).
        let match_keys: Vec<String> = m
            .body
            .iter()
            .filter_map(|it| match it {
                Item::Directive(d) => Some(d.key.clone()),
                _ => None,
            })
            .collect();
        assert!(match_keys.contains(&"forwardagent".to_string()));
        assert!(!match_keys.contains(&"include".to_string()));
    }
}
