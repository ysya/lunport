use super::super::{
    validate_hosts, AuthKind, HostPayload, HostRecord, HostScope, ImportedSettings,
    UnsupportedSetting,
};
use super::source::{arguments, expand_path, Event, Snapshot};
use super::*;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Gate {
    Active,
    Inactive,
    Unknown,
}
struct Evaluated {
    defined: bool,
    payload: HostPayload,
    seen: BTreeSet<String>,
    keys: Vec<(String, SourceLocation)>,
    jump: Option<(String, SourceLocation)>,
    warnings: Vec<ImportWarning>,
}

pub(super) fn resolve(
    snapshot: Snapshot,
    options: &ImportOptions,
) -> Result<ImportPreview, ImportError> {
    let mut aliases = Vec::new();
    discover(&snapshot.events, &mut aliases);
    let mut preview = ImportPreview {
        provenance: snapshot.files,
        source_digest: snapshot.digest,
        ..Default::default()
    };
    let mut key_ids = options.key_ids.clone();
    let mut jumps = Vec::new();
    for (alias, location) in aliases {
        add_alias(
            &snapshot.events,
            alias,
            location,
            options,
            &mut preview,
            &mut key_ids,
            &mut jumps,
        )?;
    }
    link_jumps(&mut preview, jumps, options, true)?;
    validate_hosts(&preview.candidates).map_err(ImportError::InvalidRecords)?;
    Ok(preview)
}

pub(super) fn resolve_legacy_sources(
    sources: Vec<(String, Snapshot)>,
    options: &ImportOptions,
    space_id: &str,
) -> Result<ImportPreview, ImportError> {
    let mut preview = ImportPreview::default();
    let mut key_ids = options.key_ids.clone();
    let mut jumps = Vec::new();
    for (alias, snapshot) in sources {
        let mut aliases = Vec::new();
        discover(&snapshot.events, &mut aliases);
        let Some((_, location)) = aliases.into_iter().find(|(found, _)| found == &alias) else {
            return Err(ImportError::InvalidSource {
                location: SourceLocation {
                    path: std::path::PathBuf::from(format!("relay:{space_id}:{alias}")),
                    line: 1,
                },
                reason: "legacy record alias is not an explicit Host alias".into(),
            });
        };
        let before = preview.candidates.len();
        add_alias(
            &snapshot.events,
            alias,
            location.clone(),
            options,
            &mut preview,
            &mut key_ids,
            &mut jumps,
        )?;
        if preview.candidates.len() == before {
            return Err(ImportError::InvalidSource {
                location,
                reason: "legacy alias is excluded by its own Host patterns".into(),
            });
        }
        preview.provenance.extend(snapshot.files);
    }
    link_jumps(&mut preview, jumps, options, false)?;
    for host in &mut preview.candidates {
        host.scope = HostScope::Space {
            space_id: space_id.into(),
        };
    }
    preview.source_digest = source::snapshot_digest(&preview.provenance, options);
    validate_hosts(&preview.candidates).map_err(ImportError::InvalidRecords)?;
    Ok(preview)
}

fn add_alias(
    events: &[Event],
    alias: String,
    location: SourceLocation,
    options: &ImportOptions,
    preview: &mut ImportPreview,
    key_ids: &mut BTreeMap<String, String>,
    jumps: &mut Vec<(usize, (String, SourceLocation))>,
) -> Result<(), ImportError> {
    let id = options
        .host_ids
        .get(&alias)
        .cloned()
        .map(Ok)
        .unwrap_or_else(|| random_id(8))?;
    let mut evaluated = Evaluated {
        defined: false,
        payload: empty_payload(&alias, &location, options),
        seen: BTreeSet::new(),
        keys: vec![],
        jump: None,
        warnings: vec![],
    };
    evaluate(events, &alias, Gate::Active, &mut evaluated);
    if !evaluated.defined {
        return Ok(());
    }
    let explicit_auth = evaluated.seen.contains("preferredauthentications");
    let mut seen_keys = BTreeSet::new();
    for (value, key_location) in evaluated.keys.clone() {
        if value.eq_ignore_ascii_case("none") {
            continue;
        }
        let resolved = expand_path(&value, options, false).ok();
        let identity = resolved
            .as_ref()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| value.clone());
        if !seen_keys.insert(identity.clone()) {
            continue;
        }
        let key_id = if let Some(id) = key_ids.get(&identity) {
            id.clone()
        } else {
            let id = random_id(16)?;
            key_ids.insert(identity, id.clone());
            id
        };
        if evaluated.payload.key_id.is_none() {
            evaluated.payload.key_id = Some(key_id.clone());
            if !explicit_auth {
                evaluated.payload.auth = AuthKind::Key;
            }
        } else {
            unsupported(
                &mut evaluated,
                &alias,
                "IdentityFile",
                &value,
                &key_location,
                "the current host schema has one key reference; review additional keys",
                true,
            );
        }
        if resolved.is_none() || value.to_ascii_lowercase().ends_with(".pub") {
            unsupported(
                &mut evaluated,
                &alias,
                "IdentityFile",
                &value,
                &key_location,
                "key source is not a static private-key file path",
                true,
            );
        }
        preview.key_references.push(KeyReferenceSuggestion {
            host_id: id.clone(),
            key_id,
            value,
            resolved_path: resolved,
            fingerprint: None,
            will_copy: false,
        });
    }
    if evaluated.payload.auth == AuthKind::Key && evaluated.payload.key_id.is_none() {
        let identity = format!("missing key for {alias}");
        let key_id = key_ids
            .get(&identity)
            .cloned()
            .map(Ok)
            .unwrap_or_else(|| random_id(16))?;
        key_ids.insert(identity.clone(), key_id.clone());
        evaluated.payload.key_id = Some(key_id.clone());
        preview.key_references.push(KeyReferenceSuggestion {
            host_id: id.clone(),
            key_id,
            value: identity,
            resolved_path: None,
            fingerprint: None,
            will_copy: false,
        });
    }
    if let Some(jump) = evaluated.jump {
        jumps.push((preview.candidates.len(), jump));
    }
    preview.warnings.extend(evaluated.warnings);
    preview.host_ids.insert(alias, id.clone());
    preview.candidates.push(HostRecord {
        id,
        scope: HostScope::Local,
        payload: evaluated.payload,
    });
    Ok(())
}

fn link_jumps(
    preview: &mut ImportPreview,
    jumps: Vec<(usize, (String, SourceLocation))>,
    options: &ImportOptions,
    allow_new: bool,
) -> Result<(), ImportError> {
    for (index, (value, location)) in jumps {
        if value.eq_ignore_ascii_case("none") {
            continue;
        }
        for token in value.split(',') {
            let target = match parse_jump(token) {
                Some(target) => target,
                None => {
                    jump_warning(
                        preview,
                        index,
                        &value,
                        &location,
                        "ProxyJump endpoint is not static or has invalid syntax",
                    );
                    continue;
                }
            };
            let matching: Vec<_> = preview
                .candidates
                .iter()
                .enumerate()
                .filter(|(_, h)| h.payload.alias == target.name)
                .map(|(i, _)| i)
                .collect();
            let jump_index = if matching.len() == 1 {
                let found = matching[0];
                let saved = &preview.candidates[found];
                if target.port.is_some_and(|port| port != saved.payload.port)
                    || target
                        .user
                        .as_ref()
                        .is_some_and(|user| user != &saved.payload.user)
                {
                    jump_warning(
                        preview,
                        index,
                        &value,
                        &location,
                        "endpoint override does not match the saved jump host's identity",
                    );
                    continue;
                }
                found
            } else if allow_new
                && matching.is_empty()
                && target.user.is_some()
                && target.port.is_some()
            {
                let alias = if valid_alias(&target.name) {
                    target.name.clone()
                } else {
                    format!("jump-{}", source::hex(target.name.as_bytes()))
                };
                if preview.candidates.iter().any(|h| h.payload.alias == alias) {
                    jump_warning(
                        preview,
                        index,
                        &value,
                        &location,
                        "new jump endpoint has an ambiguous alias",
                    );
                    continue;
                }
                let id = options
                    .host_ids
                    .get(&alias)
                    .cloned()
                    .map(Ok)
                    .unwrap_or_else(|| random_id(8))?;
                let mut payload = empty_payload(&alias, &location, options);
                payload.hostname = target.name;
                payload.user = target.user.unwrap();
                payload.port = target.port.unwrap();
                preview.host_ids.insert(alias, id.clone());
                preview.candidates.push(HostRecord {
                    id,
                    scope: HostScope::Local,
                    payload,
                });
                preview.candidates.len() - 1
            } else {
                jump_warning(preview,index,&value,&location,"ProxyJump must refer to a saved host or an unambiguous complete user@hostname:port endpoint");
                continue;
            };
            let jump_id = preview.candidates[jump_index].id.clone();
            preview.candidates[index].payload.jump.push(jump_id);
        }
    }
    Ok(())
}

fn empty_payload(alias: &str, location: &SourceLocation, options: &ImportOptions) -> HostPayload {
    HostPayload {
        schema: 2,
        group_id: None,
        inherit: vec![],
        alias: alias.into(),
        hostname: alias.into(),
        port: 22,
        user: String::new(),
        auth: AuthKind::Password,
        key_id: None,
        jump: vec![],
        keepalive_secs: 30,
        keepalive_max_missed: 3,
        connect_timeout_secs: 15,
        host_key: None,
        tags: vec![],
        notes: String::new(),
        imported: Some(ImportedSettings {
            source: location.path.to_string_lossy().into_owned(),
            at_ms: options.at_ms,
            unsupported: vec![],
        }),
    }
}
fn valid_alias(alias: &str) -> bool {
    !alias.is_empty()
        && !alias.starts_with('-')
        && alias
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._@%-".contains(&b))
}
fn discover(events: &[Event], aliases: &mut Vec<(String, SourceLocation)>) {
    for event in events {
        if event.directive.key == "host" {
            if let Some(patterns) = arguments(&event.directive.value) {
                for pattern in patterns {
                    if !pattern.contains(['*', '?'])
                        && !pattern.starts_with('!')
                        && valid_alias(&pattern)
                        && !aliases.iter().any(|(alias, _)| alias == &pattern)
                    {
                        aliases.push((pattern, event.location.clone()));
                    }
                }
            }
        }
        for child in &event.children {
            discover(child, aliases);
        }
    }
}

fn evaluate(events: &[Event], alias: &str, inherited: Gate, evaluated: &mut Evaluated) {
    if inherited == Gate::Inactive {
        return;
    }
    let mut gate = inherited;
    for event in events {
        let d = &event.directive;
        if d.key == "host" {
            if let Some(patterns) = arguments(&d.value) {
                gate = if matches_patterns(&patterns, alias) {
                    inherited
                } else {
                    Gate::Inactive
                };
                if gate != Gate::Inactive && patterns.iter().any(|p| p == alias) {
                    evaluated.defined = true;
                }
            } else {
                gate = Gate::Unknown;
                unsupported(
                    evaluated,
                    alias,
                    &d.keyword,
                    &d.value,
                    &event.location,
                    "Host patterns cannot be evaluated statically",
                    true,
                );
            }
            continue;
        }
        if d.key == "match" {
            gate = Gate::Unknown;
            unsupported(
                evaluated,
                alias,
                &d.keyword,
                &d.value,
                &event.location,
                "Match conditions are preserved and never executed",
                true,
            );
            continue;
        }
        if gate == Gate::Inactive {
            continue;
        }
        if d.key == "include" {
            if let Some((reason, blocks)) = &event.issue {
                unsupported(
                    evaluated,
                    alias,
                    &d.keyword,
                    &d.value,
                    &event.location,
                    reason,
                    *blocks,
                );
            }
            // Each included file restores the containing file's active scope (OpenSSH readconf.c).
            for child in &event.children {
                evaluate(child, alias, gate, evaluated);
            }
            continue;
        }
        if gate == Gate::Unknown {
            unsupported(
                evaluated,
                alias,
                &d.keyword,
                &d.value,
                &event.location,
                "value depends on an unevaluated Match condition",
                true,
            );
            continue;
        }
        if d.key == "identityfile" {
            let value = scalar(&d.value);
            if let Some(value) = value {
                evaluated.keys.push((value, event.location.clone()));
            } else {
                unsupported(
                    evaluated,
                    alias,
                    &d.keyword,
                    &d.value,
                    &event.location,
                    "IdentityFile value cannot be parsed statically",
                    true,
                );
            }
            continue;
        }
        if evaluated.seen.contains(&d.key) {
            continue;
        }
        let value = scalar(&d.value);
        let handled = match d.key.as_str() {
            "hostname" | "user" => {
                if let Some(value) = value.filter(|v| {
                    !v.is_empty()
                        && !v.contains(['%', '$'])
                        && !v.chars().any(|c| c.is_whitespace() || c.is_control())
                }) {
                    if d.key == "hostname" {
                        evaluated.payload.hostname = value;
                    } else {
                        evaluated.payload.user = value;
                    }
                    true
                } else {
                    false
                }
            }
            "port" => {
                if let Some(port) = value
                    .and_then(|v| v.parse::<u16>().ok())
                    .filter(|port| *port != 0)
                {
                    evaluated.payload.port = port;
                    true
                } else {
                    false
                }
            }
            "connecttimeout" => {
                if let Some(seconds) = value
                    .and_then(|v| v.parse::<u32>().ok())
                    .filter(|n| *n != 0)
                {
                    evaluated.payload.connect_timeout_secs = seconds;
                    true
                } else {
                    false
                }
            }
            "serveraliveinterval" => {
                if let Some(seconds) = value.and_then(|v| v.parse::<u32>().ok()) {
                    evaluated.payload.keepalive_secs = seconds;
                    true
                } else {
                    false
                }
            }
            "serveralivecountmax" => {
                if let Some(count) = value.and_then(|v| v.parse::<u32>().ok()) {
                    evaluated.payload.keepalive_max_missed = count;
                    true
                } else {
                    false
                }
            }
            "proxyjump" => {
                if let Some(value) = value.filter(|v| !v.contains(['%', '$'])) {
                    evaluated.jump = Some((value, event.location.clone()));
                    true
                } else {
                    false
                }
            }
            "preferredauthentications" => match value.as_deref() {
                Some("publickey,password,keyboard-interactive") => {
                    evaluated.payload.auth = AuthKind::Key;
                    true
                }
                Some("password,keyboard-interactive") => {
                    evaluated.payload.auth = AuthKind::Password;
                    true
                }
                Some("keyboard-interactive") => {
                    evaluated.payload.auth = AuthKind::Interactive;
                    true
                }
                _ => false,
            },
            "loglevel" => {
                unsupported(
                    evaluated,
                    alias,
                    &d.keyword,
                    &d.value,
                    &event.location,
                    "logging annotation is preserved",
                    false,
                );
                true
            }
            _ => false,
        };
        if handled {
            evaluated.seen.insert(d.key.clone());
        } else {
            unsupported(
                evaluated,
                alias,
                &d.keyword,
                &d.value,
                &event.location,
                "setting is unsupported, invalid, or needs runtime/token evaluation",
                true,
            );
        }
    }
}
fn scalar(value: &str) -> Option<String> {
    let values = arguments(value)?;
    if values.len() == 1 {
        values.into_iter().next()
    } else {
        None
    }
}
fn unsupported(
    e: &mut Evaluated,
    alias: &str,
    keyword: &str,
    value: &str,
    location: &SourceLocation,
    reason: &str,
    blocks: bool,
) {
    e.payload
        .imported
        .as_mut()
        .unwrap()
        .unsupported
        .push(UnsupportedSetting {
            keyword: keyword.into(),
            value: value.into(),
            requires_review: blocks,
        });
    e.warnings.push(ImportWarning {
        location: location.clone(),
        keyword: keyword.into(),
        reason: reason.into(),
        blocks_connection: blocks,
        alias: Some(alias.into()),
    });
}
fn jump_warning(
    preview: &mut ImportPreview,
    index: usize,
    value: &str,
    location: &SourceLocation,
    reason: &str,
) {
    let host = &mut preview.candidates[index];
    host.payload
        .imported
        .as_mut()
        .unwrap()
        .unsupported
        .push(UnsupportedSetting {
            keyword: "ProxyJump".into(),
            value: value.into(),
            requires_review: true,
        });
    preview.warnings.push(ImportWarning {
        location: location.clone(),
        keyword: "ProxyJump".into(),
        reason: reason.into(),
        blocks_connection: true,
        alias: Some(host.payload.alias.clone()),
    });
}
fn random_id(bytes: usize) -> Result<String, ImportError> {
    let mut value = vec![0; bytes];
    getrandom::fill(&mut value).map_err(|_| ImportError::InvalidSource {
        location: SourceLocation {
            path: std::path::PathBuf::from("preview"),
            line: 0,
        },
        reason: "cannot create preview record id".into(),
    })?;
    Ok(source::hex(&value))
}
fn matches_patterns(patterns: &[String], alias: &str) -> bool {
    let mut positive = false;
    for pattern in patterns {
        if let Some(negative) = pattern.strip_prefix('!') {
            if wildcard(negative.as_bytes(), alias.as_bytes()) {
                return false;
            }
        } else if wildcard(pattern.as_bytes(), alias.as_bytes()) {
            positive = true;
        }
    }
    positive
}
fn wildcard(pattern: &[u8], value: &[u8]) -> bool {
    let (mut p, mut v, mut star, mut retry) = (0, 0, None, 0);
    while v < value.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == value[v]) {
            p += 1;
            v += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            p += 1;
            retry = v;
        } else if let Some(s) = star {
            retry += 1;
            v = retry;
            p = s + 1;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}
struct JumpTarget {
    name: String,
    user: Option<String>,
    port: Option<u16>,
}
fn parse_jump(value: &str) -> Option<JumpTarget> {
    if value.is_empty()
        || value.contains(['%', '$'])
        || value.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return None;
    }
    let (user, endpoint) = if let Some((user, endpoint)) = value.split_once('@') {
        if user.is_empty() || endpoint.contains('@') {
            return None;
        }
        (Some(user.to_string()), endpoint)
    } else {
        (None, value)
    };
    let (name, port) = if let Some(rest) = endpoint.strip_prefix('[') {
        let (name, tail) = rest.split_once(']')?;
        let port = if tail.is_empty() {
            None
        } else {
            Some(tail.strip_prefix(':')?.parse::<u16>().ok()?)
        };
        (name.to_string(), port)
    } else if let Some((name, port)) = endpoint.rsplit_once(':') {
        if name.contains(':') {
            return None;
        }
        (name.to_string(), Some(port.parse::<u16>().ok()?))
    } else {
        (endpoint.into(), None)
    };
    if name.is_empty() || port == Some(0) {
        return None;
    }
    Some(JumpTarget { name, user, port })
}
