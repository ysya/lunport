use crate::config::model::{Directive, Separator};

pub enum LineKind {
    Blank,
    Comment,
    Directive(Directive),
}

/// Classify ONE physical line (without trailing newline) and, for directive lines, fully parse it.
pub fn classify_line(line: &str) -> LineKind {
    // --- Blank: empty or only whitespace ---
    if line.chars().all(|c| c.is_whitespace()) {
        return LineKind::Blank;
    }

    // --- Comment: first non-whitespace char is '#' ---
    let trimmed = line.trim_start();
    if trimmed.starts_with('#') {
        return LineKind::Comment;
    }

    // --- Directive ---
    // indent = leading whitespace
    let indent_len = line.len() - trimmed.len();
    let indent = &line[..indent_len];
    let rest = trimmed; // line after indent

    // keyword = rest up to first whitespace or '='
    let kw_end = rest
        .find(|c: char| c.is_whitespace() || c == '=')
        .unwrap_or(rest.len());
    let keyword = &rest[..kw_end];
    let after_kw = &rest[kw_end..];

    // separator = run of (whitespace | '=') with AT MOST one '='.
    // Consume chars while they are whitespace, and consume the first '=' encountered.
    let mut sep_end = 0;
    let mut saw_eq = false;
    for ch in after_kw.chars() {
        if ch == '=' && !saw_eq {
            saw_eq = true;
            sep_end += ch.len_utf8();
        } else if ch.is_whitespace() {
            sep_end += ch.len_utf8();
        } else {
            break;
        }
    }
    let sep_str = &after_kw[..sep_end];
    let separator = if saw_eq {
        Separator::Equals(sep_str.to_string())
    } else {
        Separator::Space(sep_str.to_string())
    };

    // valuepart = everything after the separator
    let valuepart = &after_kw[sep_end..];

    // Split valuepart into value + inline_comment, quote-aware.
    // Scan for the first '#' that is NOT inside a "..." span.
    let (value, inline_comment) = split_value_comment(valuepart);

    LineKind::Directive(Directive {
        keyword: keyword.to_string(),
        key: keyword.to_lowercase(),
        value,
        separator,
        indent: indent.to_string(),
        inline_comment,
        enabled: true,
        raw: line.to_string(),
        dirty: false,
    })
}

/// Split `valuepart` (everything after the separator) into:
/// - `value`: the actual value, trimmed of trailing whitespace
/// - `inline_comment`: the trailing whitespace + `#...` if any, else None
///
/// Only `"..."` double-quote spans suppress `#` detection (SSH config has no single-quote semantics).
fn split_value_comment(valuepart: &str) -> (String, Option<String>) {
    let mut in_dquote = false;
    let mut comment_byte_idx: Option<usize> = None;

    let bytes = valuepart.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let ch = bytes[i] as char;
        if ch == '"' {
            in_dquote = !in_dquote;
        } else if ch == '#' && !in_dquote {
            comment_byte_idx = Some(i);
            break;
        }
        i += 1;
    }

    match comment_byte_idx {
        None => {
            // No comment: value is valuepart with trailing whitespace stripped.
            (valuepart.trim_end().to_string(), None)
        }
        Some(idx) => {
            let before = &valuepart[..idx];
            let value = before.trim_end().to_string();
            // The whitespace between value and '#'
            let ws = &before[value.len()..];
            let comment_part = &valuepart[idx..];
            let inline_comment = format!("{}{}", ws, comment_part);
            (value, Some(inline_comment))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: reassemble structured fields back to the original line text (for round-trip checks).
    fn reassemble(d: &Directive) -> String {
        let sep_str = match &d.separator {
            Separator::Space(s) => s.clone(),
            Separator::Equals(s) => s.clone(),
        };
        format!(
            "{}{}{}{}{}",
            d.indent,
            d.keyword,
            sep_str,
            d.value,
            d.inline_comment.as_deref().unwrap_or("")
        )
    }

    // Test 1: indented HostName with space separator
    #[test]
    fn test_hostname_space_separator() {
        let input = "    HostName example.com";
        let kind = classify_line(input);
        match kind {
            LineKind::Directive(d) => {
                assert_eq!(d.keyword, "HostName");
                assert_eq!(d.key, "hostname");
                assert_eq!(d.value, "example.com");
                assert_eq!(d.separator, Separator::Space(" ".to_string()));
                assert_eq!(d.indent, "    ");
                assert_eq!(d.inline_comment, None);
                assert!(d.enabled);
                assert!(!d.dirty);
                assert_eq!(d.raw, input);
                // Round-trip
                assert_eq!(reassemble(&d), input);
            }
            _ => panic!("Expected Directive"),
        }
    }

    // Test 2: Port=22 with equals separator, no indent
    #[test]
    fn test_port_equals_separator() {
        let input = "Port=22";
        let kind = classify_line(input);
        match kind {
            LineKind::Directive(d) => {
                assert_eq!(d.keyword, "Port");
                assert_eq!(d.key, "port");
                assert_eq!(d.value, "22");
                assert_eq!(d.separator, Separator::Equals("=".to_string()));
                assert_eq!(d.indent, "");
                assert_eq!(d.inline_comment, None);
                assert!(d.enabled);
                assert!(!d.dirty);
                assert_eq!(d.raw, input);
                // Round-trip
                assert_eq!(reassemble(&d), input);
            }
            _ => panic!("Expected Directive"),
        }
    }

    // Test 3: User = bob  # login with equals+space separator, inline comment
    #[test]
    fn test_user_equals_with_spaces_and_inline_comment() {
        let input = "  User = bob  # login";
        let kind = classify_line(input);
        match kind {
            LineKind::Directive(d) => {
                assert_eq!(d.indent, "  ");
                assert_eq!(d.keyword, "User");
                assert_eq!(d.key, "user");
                assert_eq!(d.separator, Separator::Equals(" = ".to_string()));
                assert_eq!(d.value, "bob");
                assert_eq!(d.inline_comment, Some("  # login".to_string()));
                assert!(d.enabled);
                assert!(!d.dirty);
                assert_eq!(d.raw, input);
                // Round-trip
                assert_eq!(reassemble(&d), input);
            }
            _ => panic!("Expected Directive"),
        }
    }

    // Test 4: ProxyCommand with quoted # that is NOT a comment
    #[test]
    fn test_proxycommand_quoted_hash() {
        let input = r#"ProxyCommand sh -c "echo # not a comment""#;
        let kind = classify_line(input);
        match kind {
            LineKind::Directive(d) => {
                assert_eq!(d.keyword, "ProxyCommand");
                assert_eq!(d.key, "proxycommand");
                assert_eq!(d.value, r#"sh -c "echo # not a comment""#);
                assert_eq!(d.inline_comment, None);
                assert!(!d.dirty);
                assert_eq!(d.raw, input);
                // Round-trip
                assert_eq!(reassemble(&d), input);
            }
            _ => panic!("Expected Directive"),
        }
    }

    // Test 5: Host with multiple patterns
    #[test]
    fn test_host_patterns() {
        let input = "Host prod-* !prod-old";
        let kind = classify_line(input);
        match kind {
            LineKind::Directive(d) => {
                assert_eq!(d.keyword, "Host");
                assert_eq!(d.key, "host");
                assert_eq!(d.value, "prod-* !prod-old");
                assert!(!d.dirty);
                assert_eq!(d.raw, input);
                // Round-trip
                assert_eq!(reassemble(&d), input);
            }
            _ => panic!("Expected Directive"),
        }
    }

    // Test 6: Blank lines
    #[test]
    fn test_blank_empty() {
        let kind = classify_line("");
        assert!(matches!(kind, LineKind::Blank));
    }

    #[test]
    fn test_blank_whitespace_only() {
        let kind = classify_line("   ");
        assert!(matches!(kind, LineKind::Blank));
    }

    // Test 7: Comment lines
    #[test]
    fn test_comment_full_line() {
        let kind = classify_line("# just a note");
        assert!(matches!(kind, LineKind::Comment));
    }

    #[test]
    fn test_comment_indented() {
        let kind = classify_line("   #indented");
        assert!(matches!(kind, LineKind::Comment));
    }
}
