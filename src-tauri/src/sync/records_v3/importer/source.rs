use super::*;
use crate::config::model::{Directive, Item};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Clone)]
pub(super) struct Event {
    pub directive: Directive,
    pub location: SourceLocation,
    pub children: Vec<Vec<Event>>,
    pub issue: Option<(String, bool)>,
}
pub(super) struct Snapshot {
    pub events: Vec<Event>,
    pub files: Vec<SourceFile>,
    pub digest: String,
}

pub(super) fn load(path: &Path, options: &ImportOptions) -> Result<Snapshot, ImportError> {
    let location = SourceLocation {
        path: path.into(),
        line: 1,
    };
    if !path.is_absolute() || !options.home.is_absolute() {
        return Err(ImportError::InvalidSource {
            location,
            reason: "source and home must be explicit absolute paths".into(),
        });
    }
    let mut loader = Loader {
        options,
        files: vec![],
        stack: BTreeSet::new(),
        visited: BTreeSet::new(),
        bytes: 0,
    };
    let (events, _) = loader.file(path, 0, &location)?;
    let digest = snapshot_digest(&loader.files, options);
    Ok(Snapshot {
        events,
        files: loader.files,
        digest,
    })
}

struct Loader<'a> {
    options: &'a ImportOptions,
    files: Vec<SourceFile>,
    stack: BTreeSet<PathBuf>,
    visited: BTreeSet<PathBuf>,
    bytes: usize,
}
impl Loader<'_> {
    fn file(
        &mut self,
        path: &Path,
        depth: usize,
        from: &SourceLocation,
    ) -> Result<(Vec<Event>, Option<(String, bool)>), ImportError> {
        if depth > MAX_DEPTH {
            return Err(ImportError::Limit {
                location: from.clone(),
                limit: "depth",
            });
        }
        let canonical = path.canonicalize().map_err(|e| io_error(from, e))?;
        if self.stack.contains(&canonical) {
            return Err(ImportError::Cycle {
                location: from.clone(),
            });
        }
        if self.options.excluded_sources.iter().any(|excluded| {
            excluded == path || excluded.canonicalize().is_ok_and(|p| p == canonical)
        }) {
            return Ok((
                vec![],
                Some((
                    "managed source is already represented by synced records".into(),
                    false,
                )),
            ));
        }
        if !self.visited.insert(canonical.clone()) {
            return Ok((
                vec![],
                Some((
                    "repeated physical Include was deduplicated; review conditional semantics"
                        .into(),
                    true,
                )),
            ));
        }
        if self.files.len() >= MAX_FILES {
            return Err(ImportError::Limit {
                location: from.clone(),
                limit: "files",
            });
        }
        let location = SourceLocation {
            path: path.into(),
            line: 1,
        };
        let metadata = canonical.metadata().map_err(|e| io_error(&location, e))?;
        if !metadata.is_file() {
            return Err(ImportError::InvalidSource {
                location,
                reason: "configuration source must be a regular file".into(),
            });
        }
        if metadata.len() > MAX_FILE_BYTES as u64 {
            return Err(ImportError::Limit {
                location,
                limit: "file bytes",
            });
        }
        if metadata.len() > (MAX_TOTAL_BYTES - self.bytes) as u64 {
            return Err(ImportError::Limit {
                location,
                limit: "total bytes",
            });
        }
        let cap = (MAX_FILE_BYTES + 1).min(MAX_TOTAL_BYTES - self.bytes + 1);
        let mut bytes = Vec::new();
        File::open(&canonical)
            .map_err(|e| io_error(&location, e))?
            .take(cap as u64)
            .read_to_end(&mut bytes)
            .map_err(|e| io_error(&location, e))?;
        if bytes.len() > MAX_FILE_BYTES {
            return Err(ImportError::Limit {
                location,
                limit: "file bytes",
            });
        }
        if self.bytes + bytes.len() > MAX_TOTAL_BYTES {
            return Err(ImportError::Limit {
                location,
                limit: "total bytes",
            });
        }
        // Reject private key containers before their text enters a public AST or preview.
        if bytes
            .windows(b"PRIVATE KEY-----".len())
            .any(|window| window == b"PRIVATE KEY-----")
        {
            return Err(ImportError::PrivateKeyContent { location });
        }
        let digest = hex(&Sha256::digest(&bytes));
        self.bytes += bytes.len();
        let text = String::from_utf8(bytes).map_err(|_| ImportError::InvalidSource {
            location: location.clone(),
            reason: "configuration must be UTF-8 text".into(),
        })?;
        self.files.push(SourceFile {
            path: path.into(),
            canonical_path: canonical.clone(),
            digest,
            bytes: text.len(),
        });
        self.stack.insert(canonical.clone());
        let mut line = 1;
        let mut events = flatten(crate::config::parser::parse_file(&text).0, path, &mut line);
        for event in &mut events {
            if event.directive.key != "include" {
                continue;
            }
            let Some(arguments) = arguments(&event.directive.value) else {
                event.issue = Some((
                    "Include arguments cannot be resolved statically".into(),
                    true,
                ));
                continue;
            };
            if arguments.is_empty() {
                event.issue = Some(("Include has no paths".into(), true));
            }
            for argument in arguments {
                let pattern = match expand_path(&argument, self.options, true) {
                    Ok(path) => path,
                    Err(reason) => {
                        event.issue = Some((reason, true));
                        continue;
                    }
                };
                let pattern = pattern.to_str().ok_or_else(|| ImportError::InvalidSource {
                    location: event.location.clone(),
                    reason: "Include pattern is not UTF-8".into(),
                })?;
                let mut matches = Vec::new();
                for entry in glob::glob(pattern).map_err(|_| ImportError::InvalidSource {
                    location: event.location.clone(),
                    reason: "invalid Include glob".into(),
                })? {
                    let path = entry.map_err(|e| ImportError::Io {
                        location: event.location.clone(),
                        message: e.to_string(),
                    })?;
                    if matches.len() >= MAX_FILES {
                        return Err(ImportError::Limit {
                            location: event.location.clone(),
                            limit: "files",
                        });
                    }
                    matches.push(path);
                }
                matches.sort();
                if matches.is_empty() {
                    event
                        .issue
                        .get_or_insert(("Include matched no files".into(), false));
                }
                for path in matches {
                    let (child, issue) = self.file(&path, depth + 1, &event.location)?;
                    if let Some(issue) = issue {
                        if event.issue.as_ref().is_none_or(|(_, blocks)| !blocks) {
                            event.issue = Some(issue);
                        }
                    }
                    event.children.push(child);
                }
            }
        }
        self.stack.remove(&canonical);
        Ok((events, None))
    }
}
fn io_error(location: &SourceLocation, error: std::io::Error) -> ImportError {
    ImportError::Io {
        location: location.clone(),
        message: error.to_string(),
    }
}

fn flatten(items: Vec<Item>, path: &Path, line: &mut usize) -> Vec<Event> {
    let mut out = Vec::new();
    for item in items {
        let (directive, body) = match item {
            Item::Directive(d) => (Some(d), vec![]),
            Item::Host(h) => (Some(h.header), h.body),
            Item::Match(m) => (Some(m.header), m.body),
            Item::Blank(_) | Item::Comment(_) => (None, vec![]),
        };
        if let Some(directive) = directive {
            out.push(Event {
                directive,
                location: SourceLocation {
                    path: path.into(),
                    line: *line,
                },
                children: vec![],
                issue: None,
            });
        }
        *line += 1;
        out.extend(flatten(body, path, line));
    }
    out
}

pub(super) fn arguments(value: &str) -> Option<Vec<String>> {
    if value.contains('\'')
        || value
            .as_bytes()
            .windows(2)
            .any(|pair| pair[0] == b'\\' && (pair[1].is_ascii_whitespace() || pair[1] == b'"'))
    {
        return None;
    }
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    for ch in value.chars() {
        if ch == '"' {
            quoted = !quoted;
        } else if ch.is_whitespace() && !quoted {
            if !current.is_empty() {
                out.push(std::mem::take(&mut current));
            }
        } else {
            current.push(ch);
        }
    }
    if quoted {
        return None;
    }
    if !current.is_empty() {
        out.push(current);
    }
    Some(out)
}

/// Static home and explicitly supplied ${VAR} only; host-specific tokens never become filesystem paths.
pub(super) fn expand_path(
    value: &str,
    options: &ImportOptions,
    relative_include: bool,
) -> Result<PathBuf, String> {
    let mut expanded = String::new();
    let mut rest = value;
    while let Some(start) = rest.find('$') {
        expanded.push_str(&rest[..start]);
        rest = &rest[start..];
        let Some(env) = rest.strip_prefix("${") else {
            return Err("unsupported environment expansion".into());
        };
        let Some(end) = env.find('}') else {
            return Err("unterminated environment expansion".into());
        };
        let name = &env[..end];
        let value = options
            .env
            .get(name)
            .ok_or_else(|| format!("explicit environment value is missing for {name}"))?;
        expanded.push_str(value);
        rest = &env[end + 1..];
    }
    expanded.push_str(rest);
    let home = options.home.to_string_lossy();
    expanded = expanded.replace("%d", &home);
    if expanded.contains('%') {
        return Err("host-dependent tokens require review".into());
    }
    if expanded == "~" {
        return Ok(options.home.clone());
    }
    if let Some(tail) = expanded.strip_prefix("~/") {
        return Ok(options.home.join(tail));
    }
    if expanded.starts_with('~') {
        return Err("another user's home requires review".into());
    }
    let path = PathBuf::from(expanded);
    if path.is_absolute() {
        Ok(path)
    } else if relative_include {
        Ok(options.home.join(".ssh").join(path))
    } else {
        Err("relative key paths require review".into())
    }
}

pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn snapshot_digest(files: &[SourceFile], options: &ImportOptions) -> String {
    let mut hash = Sha256::new();
    hash.update(b"sshelter-import-snapshot-v1");
    let mut field = |bytes: &[u8]| {
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    };
    field(options.home.as_os_str().as_encoded_bytes());
    for (name, value) in &options.env {
        field(name.as_bytes());
        field(value.as_bytes());
    }
    for file in files {
        field(file.path.as_os_str().as_encoded_bytes());
        field(file.canonical_path.as_os_str().as_encoded_bytes());
        field(file.digest.as_bytes());
    }
    hex(&hash.finalize())
}
