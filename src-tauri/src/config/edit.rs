use crate::config::model::{Directive, HostBlock, Item};

// ─── Finders ─────────────────────────────────────────────────────────────────

/// Find the first HostBlock whose `patterns` contains `alias` (exact token match).
pub fn find_host_mut<'a>(items: &'a mut [Item], alias: &str) -> Option<&'a mut HostBlock> {
    for item in items.iter_mut() {
        if let Item::Host(h) = item {
            if h.patterns.iter().any(|p| p == alias) {
                return Some(h);
            }
        }
    }
    None
}

// ─── Field operations ─────────────────────────────────────────────────────────

/// Set a field on a host: update the FIRST body directive whose `key == keyword.to_lowercase()`
/// (set its `value` and `dirty=true`), or, if none exists, append a new `Directive::new(keyword,value,indent)`
/// to the body using the block's inferred indent. Returns true if anything changed.
pub fn set_host_field(host: &mut HostBlock, keyword: &str, value: &str) -> bool {
    let key_lower = keyword.to_lowercase();
    // A value can never legally contain a newline; strip CR/LF so a malicious/garbled value
    // cannot inject a fabricated directive line into the user's live config on serialize.
    let value = sanitize_value(value);

    // Try to find and update existing directive.
    for item in host.body.iter_mut() {
        if let Item::Directive(d) = item {
            if d.key == key_lower {
                if d.value == value {
                    return false; // no change
                }
                d.value = value;
                d.dirty = true;
                return true;
            }
        }
    }

    // Not found — infer indent and insert AFTER the last directive (before any trailing
    // blank/comment run) so the new line stays visually inside the block.
    let indent = infer_indent(&host.body);
    let insert_at = host
        .body
        .iter()
        .rposition(|it| matches!(it, Item::Directive(_)))
        .map(|i| i + 1)
        .unwrap_or(host.body.len());
    host.body
        .insert(insert_at, Item::Directive(Directive::new(keyword, &value, &indent)));
    true
}

/// Strip CR/LF from a value so it can never inject extra physical lines on serialize.
fn sanitize_value(value: &str) -> String {
    value.replace(['\r', '\n'], "")
}

/// Infer the indent from the first Directive in a body; fall back to 4 spaces.
fn infer_indent(body: &[Item]) -> String {
    for item in body {
        if let Item::Directive(d) = item {
            return d.indent.clone();
        }
    }
    "    ".to_string()
}

/// Remove the first body directive whose `key == key_lower`. Returns true if one was removed.
pub fn remove_host_field(host: &mut HostBlock, key_lower: &str) -> bool {
    let key_lower = key_lower.to_lowercase();
    if let Some(pos) = host.body.iter().position(|item| {
        if let Item::Directive(d) = item {
            d.key == key_lower
        } else {
            false
        }
    }) {
        host.body.remove(pos);
        return true;
    }
    false
}

// ─── Enable/disable ───────────────────────────────────────────────────────────

/// Enable/disable a single directive (sets `enabled` and `dirty=true`).
pub fn set_directive_enabled(d: &mut Directive, enabled: bool) {
    d.enabled = enabled;
    d.dirty = true;
}

/// Enable/disable an entire host: applies to the header AND every directive in the body
/// (each gets enabled set + dirty=true). Blank/Comment items are untouched.
///
/// NOTE — one-way across reload: disabling serializes the block as `#`-commented lines. On a
/// subsequent parse those lines classify as Comments (not a disabled Host block), so the host
/// can no longer be re-enabled through this API after save+reload. The UI must not assume the
/// toggle is reversible across a reload.
pub fn set_host_enabled(host: &mut HostBlock, enabled: bool) {
    set_directive_enabled(&mut host.header, enabled);
    for item in host.body.iter_mut() {
        if let Item::Directive(d) = item {
            set_directive_enabled(d, enabled);
        }
    }
}

// ─── Add / Remove host ────────────────────────────────────────────────────────

/// Append a new Host block to `items`: a leading `Item::Blank(String::new())` for separation,
/// then `Item::Host` with header = Directive::new("Host", alias, "") and a body of
/// Directive::new(keyword, value, "    ") for each (keyword,value) in `fields`,
/// patterns = vec![alias].
pub fn add_host(items: &mut Vec<Item>, alias: &str, fields: &[(String, String)]) {
    items.push(Item::Blank(String::new()));

    let header = Directive::new("Host", alias, "");
    let body: Vec<Item> = fields
        .iter()
        .map(|(kw, val)| Item::Directive(Directive::new(kw, val, "    ")))
        .collect();

    items.push(Item::Host(HostBlock {
        header,
        patterns: vec![alias.to_string()],
        body,
    }));
}

/// Remove the first top-level `Item::Host` whose patterns contains `alias`. Returns true if removed.
pub fn remove_host(items: &mut Vec<Item>, alias: &str) -> bool {
    if let Some(pos) = items.iter().position(|item| {
        if let Item::Host(h) = item {
            h.patterns.iter().any(|p| p == alias)
        } else {
            false
        }
    }) {
        items.remove(pos);
        return true;
    }
    false
}

// ─── Reorder ──────────────────────────────────────────────────────────────────

/// Reorder top-level Host blocks so they appear in `alias_order` order. Non-Host top-level items
/// keep their absolute positions; only the Host slots are permuted to match the requested order.
/// Aliases not present are ignored; hosts not named keep their relative order after the named ones.
pub fn reorder_hosts(items: &mut Vec<Item>, alias_order: &[String]) {
    // Collect indices of all Host items (in their current order).
    let host_indices: Vec<usize> = items
        .iter()
        .enumerate()
        .filter_map(|(i, item)| {
            if matches!(item, Item::Host(_)) {
                Some(i)
            } else {
                None
            }
        })
        .collect();

    if host_indices.is_empty() {
        return;
    }

    // Extract all Host blocks from `items`, temporarily replacing them with a blank sentinel.
    // We'll place them back in the new order once determined.
    let hosts: Vec<Item> = host_indices
        .iter()
        .map(|&i| std::mem::replace(&mut items[i], Item::Blank(String::new())))
        .collect();

    // Build new_order: named aliases first (in alias_order sequence), then remaining in
    // their original relative order.
    let mut new_order: Vec<usize> = Vec::with_capacity(hosts.len());
    let mut used2 = vec![false; hosts.len()];

    for alias in alias_order {
        for (i, item) in hosts.iter().enumerate() {
            if used2[i] {
                continue;
            }
            if let Item::Host(h) = item {
                if h.patterns.iter().any(|p| p == alias) {
                    new_order.push(i);
                    used2[i] = true;
                    break;
                }
            }
        }
    }
    // Remaining hosts in original order.
    for i in 0..hosts.len() {
        if !used2[i] {
            new_order.push(i);
        }
    }

    // Build the reordered host list.
    // We need to move items out of hosts by new_order. Use Option to allow taking.
    let mut hosts_opt: Vec<Option<Item>> = hosts.into_iter().map(Some).collect();
    let reordered: Vec<Item> = new_order
        .iter()
        .map(|&i| hosts_opt[i].take().unwrap())
        .collect();

    // Place reordered hosts back into the sentinel positions.
    for (slot_idx, host_item) in host_indices.iter().zip(reordered.into_iter()) {
        items[*slot_idx] = host_item;
    }
}

// ─── Group / Tags sentinels ───────────────────────────────────────────────────

const GROUP_PREFIX: &str = "#group:";
const TAGS_PREFIX: &str = "#tags:";

/// Return the position of a body Comment sentinel matching `prefix`.
fn find_sentinel(body: &[Item], prefix: &str) -> Option<usize> {
    body.iter().position(|item| {
        if let Item::Comment(s) = item {
            s.trim_start().starts_with(prefix)
        } else {
            false
        }
    })
}

/// Set or clear the group sentinel for a host. The sentinel is a body Comment line `#group:<path>`
/// kept as the FIRST item of the body. `Some(path)` inserts/updates it; `None` removes it.
pub fn set_group(host: &mut HostBlock, group: Option<&str>) {
    match group {
        Some(path) => {
            let sentinel = format!("{}{}", GROUP_PREFIX, path);
            if let Some(pos) = find_sentinel(&host.body, GROUP_PREFIX) {
                host.body[pos] = Item::Comment(sentinel);
            } else {
                host.body.insert(0, Item::Comment(sentinel));
            }
        }
        None => {
            if let Some(pos) = find_sentinel(&host.body, GROUP_PREFIX) {
                host.body.remove(pos);
            }
        }
    }
}

/// Set or clear the tags sentinel: a body Comment `#tags:<comma-joined>` as the first body item
/// (after a group sentinel if present is acceptable; keep deterministic). Empty slice clears it.
pub fn set_tags(host: &mut HostBlock, tags: &[String]) {
    if tags.is_empty() {
        // Clear the sentinel.
        if let Some(pos) = find_sentinel(&host.body, TAGS_PREFIX) {
            host.body.remove(pos);
        }
        return;
    }

    let sentinel = format!("{}{}", TAGS_PREFIX, tags.join(","));

    if let Some(pos) = find_sentinel(&host.body, TAGS_PREFIX) {
        host.body[pos] = Item::Comment(sentinel);
    } else {
        // Insert after group sentinel if present, otherwise at position 0.
        let insert_pos = if let Some(g) = find_sentinel(&host.body, GROUP_PREFIX) {
            g + 1
        } else {
            0
        };
        host.body.insert(insert_pos, Item::Comment(sentinel));
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parser::parse_file;
    use crate::config::serialize::serialize_items;

    const FIXTURE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/");

    fn read_fixture(name: &str) -> String {
        let path = format!("{}{}", FIXTURE_DIR, name);
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {}", path, e))
    }

    // ── Test 1: THE INVARIANT — single-field edit changes only one line ──────

    #[test]
    fn test_single_field_edit_changes_only_one_line() {
        let original = read_fixture("simple.sshconfig");
        let (mut items, nl) = parse_file(&original);

        let host = find_host_mut(&mut items, "web").expect("host 'web' not found");
        let changed = set_host_field(host, "User", "newuser");
        assert!(changed, "set_host_field should return true");

        let edited = serialize_items(&items, nl);

        let orig_lines: Vec<&str> = original.lines().collect();
        let edit_lines: Vec<&str> = edited.lines().collect();

        assert_eq!(
            orig_lines.len(),
            edit_lines.len(),
            "line count must not change"
        );

        let diffs: Vec<usize> = orig_lines
            .iter()
            .zip(edit_lines.iter())
            .enumerate()
            .filter_map(|(i, (a, b))| if a != b { Some(i) } else { None })
            .collect();

        assert_eq!(diffs.len(), 1, "exactly one line should differ, got: {:?}\norig:\n{}\nedited:\n{}", diffs, original, edited);

        let changed_orig = orig_lines[diffs[0]];
        let changed_edit = edit_lines[diffs[0]];
        assert_eq!(changed_orig, "    User deploy");
        assert_eq!(changed_edit, "    User newuser");
    }

    // ── Test 2: Add missing field appends with inferred indent ───────────────

    #[test]
    fn test_add_missing_field_appends_with_inferred_indent() {
        let original = read_fixture("simple.sshconfig");
        let (mut items, nl) = parse_file(&original);

        let host = find_host_mut(&mut items, "web").expect("host 'web' not found");
        let changed = set_host_field(host, "ForwardAgent", "yes");
        assert!(changed, "set_host_field should return true for new field");

        let edited = serialize_items(&items, nl);

        // The new line should appear with 4-space indent.
        assert!(
            edited.contains("    ForwardAgent yes"),
            "edited output must contain '    ForwardAgent yes', got:\n{}",
            edited
        );

        // All original lines should still be present and unchanged.
        for line in original.lines() {
            assert!(
                edited.contains(line),
                "original line {:?} disappeared from edited output",
                line
            );
        }
    }

    // ── Test 3: remove_host_field removes exactly one line ───────────────────

    #[test]
    fn test_remove_host_field_removes_one_line() {
        let original = read_fixture("simple.sshconfig");
        let (mut items, nl) = parse_file(&original);

        let host = find_host_mut(&mut items, "web").expect("host 'web' not found");
        let removed = remove_host_field(host, "port");
        assert!(removed, "remove_host_field should return true");

        let edited = serialize_items(&items, nl);

        let orig_lines: Vec<&str> = original.lines().collect();
        let edit_lines: Vec<&str> = edited.lines().collect();

        // Edited output should have exactly one fewer line.
        assert_eq!(
            orig_lines.len(),
            edit_lines.len() + 1,
            "one line should be removed"
        );

        // The Port line for 'web' should be gone.
        assert!(
            !edited.contains("    Port 22\n") && {
                // More careful check: count occurrences of Port 22
                edited.lines().filter(|l| l.trim() == "Port 22").count() == 0
            },
            "Port 22 line should be removed from 'web' block"
        );

        // The db block's Port line should still be there.
        assert!(
            edited.contains("    Port 2222"),
            "db block Port line must remain"
        );
    }

    // ── Test 4: set_directive_enabled(false) changes only that line ──────────

    #[test]
    fn test_set_directive_enabled_false_changes_only_that_line() {
        let original = read_fixture("simple.sshconfig");
        let (mut items, nl) = parse_file(&original);

        let host = find_host_mut(&mut items, "web").expect("host 'web' not found");
        // Find the User directive and disable it.
        let user_dir = host.body.iter_mut().find_map(|item| {
            if let Item::Directive(d) = item {
                if d.key == "user" {
                    return Some(d);
                }
            }
            None
        });
        let d = user_dir.expect("User directive not found in 'web' block");
        set_directive_enabled(d, false);

        let edited = serialize_items(&items, nl);

        let orig_lines: Vec<&str> = original.lines().collect();
        let edit_lines: Vec<&str> = edited.lines().collect();

        assert_eq!(orig_lines.len(), edit_lines.len(), "line count must not change");

        let diffs: Vec<usize> = orig_lines
            .iter()
            .zip(edit_lines.iter())
            .enumerate()
            .filter_map(|(i, (a, b))| if a != b { Some(i) } else { None })
            .collect();

        assert_eq!(diffs.len(), 1, "exactly one line should differ");

        let changed_edit = edit_lines[diffs[0]];
        // Disabled directive renders as {indent}# {body}
        assert_eq!(changed_edit, "    # User deploy");
    }

    // ── Test 5: add_host then round-trip parse ───────────────────────────────

    #[test]
    fn test_add_host_round_trips() {
        let original = read_fixture("simple.sshconfig");
        let (mut items, nl) = parse_file(&original);

        let original_serialized = serialize_items(&items, nl);

        let fields = vec![
            ("HostName".to_string(), "jump.example.com".to_string()),
            ("User".to_string(), "root".to_string()),
        ];
        add_host(&mut items, "jump", &fields);

        let edited = serialize_items(&items, nl);

        // The prefix (everything before the new block) is byte-identical.
        assert!(
            edited.starts_with(&original_serialized),
            "existing content must be unchanged before the appended block"
        );

        // Re-parse and verify the new host is present with its fields.
        let (reparsed, _) = parse_file(&edited);
        let new_host = reparsed
            .iter()
            .find_map(|item| {
                if let Item::Host(h) = item {
                    if h.patterns.iter().any(|p| p == "jump") {
                        return Some(h);
                    }
                }
                None
            })
            .expect("newly added host 'jump' must be present after re-parse");

        assert_eq!(new_host.patterns, vec!["jump".to_string()]);

        let keys: Vec<&str> = new_host
            .body
            .iter()
            .filter_map(|it| {
                if let Item::Directive(d) = it {
                    Some(d.key.as_str())
                } else {
                    None
                }
            })
            .collect();
        assert!(keys.contains(&"hostname"), "HostName field missing");
        assert!(keys.contains(&"user"), "User field missing");
    }

    // ── Test 6: remove_host removes whole block, others unchanged ────────────

    #[test]
    fn test_remove_host_removes_block_others_unchanged() {
        let original = read_fixture("simple.sshconfig");
        let (mut items, nl) = parse_file(&original);

        let removed = remove_host(&mut items, "db");
        assert!(removed, "remove_host should return true");

        let edited = serialize_items(&items, nl);

        // No 'db' host references remain.
        assert!(
            !edited.contains("Host db"),
            "Host db should be removed"
        );
        assert!(
            !edited.contains("db.example.com"),
            "db.example.com should be removed"
        );

        // The 'web' block's lines are all still present.
        assert!(edited.contains("Host web"), "'web' host must remain");
        assert!(edited.contains("    HostName web.example.com"));
        assert!(edited.contains("    User deploy"));
        assert!(edited.contains("    Port 22"));
        assert!(edited.contains("    IdentityFile ~/.ssh/id_web"));
    }

    // ── Test 7: reorder_hosts swaps two blocks ────────────────────────────────

    #[test]
    fn test_reorder_hosts_swaps_web_db() {
        let original = read_fixture("simple.sshconfig");
        let (mut items, nl) = parse_file(&original);

        // Original order: web first, db second.
        let order_before: Vec<String> = items
            .iter()
            .filter_map(|it| {
                if let Item::Host(h) = it {
                    h.patterns.first().cloned()
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(order_before, vec!["web", "db"]);

        reorder_hosts(&mut items, &["db".to_string(), "web".to_string()]);

        let order_after: Vec<String> = items
            .iter()
            .filter_map(|it| {
                if let Item::Host(h) = it {
                    h.patterns.first().cloned()
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(order_after, vec!["db", "web"]);

        // Re-parse the serialized output and verify order.
        let serialized = serialize_items(&items, nl);
        let (reparsed, _) = parse_file(&serialized);
        let reparsed_order: Vec<String> = reparsed
            .iter()
            .filter_map(|it| {
                if let Item::Host(h) = it {
                    h.patterns.first().cloned()
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(reparsed_order, vec!["db", "web"]);
    }

    // ── Test 8: group / tags sentinels ────────────────────────────────────────

    #[test]
    fn test_group_and_tags_sentinels() {
        let original = read_fixture("simple.sshconfig");
        let (mut items, _nl) = parse_file(&original);

        let host = find_host_mut(&mut items, "web").expect("host 'web' not found");

        // Insert group sentinel.
        set_group(host, Some("Work/Prod"));
        {
            let first = host.body.first().expect("body must be non-empty");
            assert!(
                matches!(first, Item::Comment(s) if s == "#group:Work/Prod"),
                "first body item must be the group sentinel, got {:?}", first
            );
        }

        // Update group sentinel in-place.
        set_group(host, Some("Work/Staging"));
        {
            let group_item = find_sentinel(&host.body, "#group:");
            assert!(group_item.is_some(), "group sentinel must still be present");
            let pos = group_item.unwrap();
            assert!(
                matches!(&host.body[pos], Item::Comment(s) if s == "#group:Work/Staging"),
                "group sentinel must be updated"
            );
        }

        // Insert tags sentinel (after group).
        set_tags(host, &["a".to_string(), "b".to_string()]);
        {
            let tags_pos = find_sentinel(&host.body, "#tags:");
            assert!(tags_pos.is_some(), "tags sentinel must be present");
            let pos = tags_pos.unwrap();
            assert!(
                matches!(&host.body[pos], Item::Comment(s) if s == "#tags:a,b"),
                "tags sentinel must equal '#tags:a,b'"
            );
            // Group must still come first.
            let group_pos = find_sentinel(&host.body, "#group:").unwrap();
            assert!(group_pos < pos, "group sentinel must precede tags sentinel");
        }

        // Remove group sentinel — body must not contain #group: anymore.
        set_group(host, None);
        assert!(
            find_sentinel(&host.body, "#group:").is_none(),
            "group sentinel must be removed after set_group(None)"
        );

        // Tags sentinel still present.
        assert!(
            find_sentinel(&host.body, "#tags:").is_some(),
            "tags sentinel must survive group removal"
        );

        // Empty tags clears sentinel.
        set_tags(host, &[]);
        assert!(
            find_sentinel(&host.body, "#tags:").is_none(),
            "tags sentinel must be removed after set_tags(&[])"
        );
    }

    // ── Test 9: value newlines are stripped (no line injection) ──────────────
    #[test]
    fn test_set_field_strips_newlines_no_injection() {
        let original = "Host web\n    User deploy\n\nHost db\n    User admin\n";
        let (mut items, nl) = parse_file(original);
        let lines_before = serialize_items(&items, nl).lines().count();

        let host = find_host_mut(&mut items, "web").unwrap();
        // A malicious value carrying a newline + a fake directive must NOT inject a line.
        set_host_field(host, "User", "evil\n    ForwardAgent yes");
        let edited = serialize_items(&items, nl);

        assert_eq!(
            edited.lines().count(),
            lines_before,
            "a value newline must not inject a physical line:\n{edited}"
        );

        let host = find_host_mut(&mut items, "web").unwrap();
        let user = host.body.iter().find_map(|it| match it {
            Item::Directive(d) if d.key == "user" => Some(d),
            _ => None,
        });
        assert!(
            !user.unwrap().value.contains('\n'),
            "stored value must not contain a newline"
        );
    }

    // ── Test 10: appended field lands before a trailing blank, not orphaned ──
    #[test]
    fn test_append_field_goes_before_trailing_blank() {
        // The parser folds the inter-host blank into the FIRST block's body, so web's body
        // ends with Blank(""). An appended field must go before it (inside the block).
        let original = "Host web\n    User deploy\n\nHost db\n    User admin\n";
        let (mut items, nl) = parse_file(original);

        let host = find_host_mut(&mut items, "web").unwrap();
        set_host_field(host, "ForwardAgent", "yes"); // new field

        let edited = serialize_items(&items, nl);
        let lines: Vec<&str> = edited.lines().collect();
        let fa = lines
            .iter()
            .position(|l| l.contains("ForwardAgent yes"))
            .expect("ForwardAgent line present");
        assert_eq!(lines[fa], "    ForwardAgent yes");
        assert_eq!(
            lines[fa + 1],
            "",
            "appended field must sit before the trailing blank, got:\n{edited}"
        );
    }
}
