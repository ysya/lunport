use std::path::PathBuf;

use crate::fsutil::Fingerprint;

/// keyword 與 value 之間的分隔（含周邊空白，原樣保存）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Separator {
    Space(String),  // e.g. " ", "\t", "  "
    Equals(String), // e.g. "=", " = ", "= "
}

/// 一行 key/value 指令（可被停用＝註解掉）。
#[derive(Debug, Clone)]
pub struct Directive {
    pub keyword: String,                // original case, e.g. "HostName"
    pub key: String,                    // lowercased, for matching, e.g. "hostname"
    pub value: String,                  // value (without inline comment; quotes preserved)
    pub separator: Separator,
    pub indent: String,                 // leading whitespace
    pub inline_comment: Option<String>, // trailing comment incl its leading ws and '#'
    pub enabled: bool,                  // false => serialized commented-out
    pub raw: String,                    // original full line (no newline); emitted verbatim when !dirty
    pub dirty: bool,                    // true once a structured field is edited => serialize re-renders
}

/// 檔案內依序排列的元素。
#[derive(Debug, Clone)]
pub enum Item {
    Blank(String),   // original blank line (may contain whitespace)
    Comment(String), // full-line comment, original text incl indent and '#'
    Directive(Directive),
    Host(HostBlock),
    Match(MatchBlock),
}

#[derive(Debug, Clone)]
pub struct HostBlock {
    pub header: Directive,     // the `Host ...` line
    pub patterns: Vec<String>, // parsed patterns (matching / UI)
    pub body: Vec<Item>,       // lines until the next Host/Match
}

#[derive(Debug, Clone)]
pub struct MatchBlock {
    pub header: Directive, // the `Match ...` line
    pub criteria: String,
    pub body: Vec<Item>,
}

#[derive(Debug, Clone)]
pub struct ConfigFile {
    pub path: PathBuf,
    pub items: Vec<Item>,
    pub trailing_newline: bool,
    pub fingerprint: Fingerprint,
}

#[derive(Debug, Clone)]
pub struct SshConfigDoc {
    pub files: Vec<ConfigFile>,
}

/// Helper: build an OpenSSH directive `Directive` from structured fields with `dirty=true`,
/// for newly-created lines (raw is left empty; serialization will re-render because dirty).
impl Directive {
    pub fn new(keyword: &str, value: &str, indent: &str) -> Self {
        Directive {
            keyword: keyword.to_string(),
            key: keyword.to_lowercase(),
            value: value.to_string(),
            separator: Separator::Space(" ".to_string()),
            indent: indent.to_string(),
            inline_comment: None,
            enabled: true,
            raw: String::new(),
            dirty: true,
        }
    }
}
