//! 建立新的 config 檔案:決定放哪裡(既有 Include glob 是否已涵蓋)、
//! 需要時把 `Include` 行插到 main config 的正確位置。
//!
//! 正確性規則:`Include` 出現在 Host/Match 區塊之後會被 scope 進該區塊
//! (ssh_config 的 Include 是位置敏感的),所以插入點必須在 top-level、
//! 第一個 Host/Match 之前;已有 Include 行時接在最後一行 Include 之後,
//! 與使用者既有的排版習慣同群。

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::model::Item;
use crate::error::AppError;

/// 建檔計畫:UI 據此即時顯示「會建立在哪、會不會動 main config」。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub struct NewFilePlan {
    /// 實際會建立的完整路徑。
    pub path: String,
    /// 命中的既有 Include pattern(None = 需要插入 Include 行)。
    pub covered_by: Option<String>,
    /// 將插入 main config 的 Include「值」(covered_by 為 Some 時為 None)。
    pub include_value: Option<String>,
    /// 依 glob 字尾補齊後的最終檔名。
    pub final_name: String,
    /// 目標路徑已存在(由 command 層以檔案系統回填;純函式一律 false)。
    pub already_exists: bool,
}

/// 檔名 gate:單一路徑分段、無空白、無前導 `-`、非 `.`/`..`。
pub fn validate_file_name(name: &str) -> Result<(), AppError> {
    if name.is_empty() {
        return Err(AppError::Other("file name is empty".to_string()));
    }
    if name == "." || name == ".." {
        return Err(AppError::Other("file name is reserved".to_string()));
    }
    if name.contains('/') || name.contains('\\') {
        return Err(AppError::Other(
            "file name must not contain path separators".to_string(),
        ));
    }
    if name.chars().any(char::is_whitespace) {
        return Err(AppError::Other(
            "file name must not contain whitespace".to_string(),
        ));
    }
    if name.starts_with('-') {
        return Err(AppError::Other(
            "file name must not start with '-'".to_string(),
        ));
    }
    Ok(())
}

/// 一個 glob token 拆出的「可建檔家族」:目錄 + 檔名 prefix/suffix。
struct GlobFamily {
    dir: PathBuf,
    prefix: String,
    suffix: String,
}

/// 解析單一 Include token 成 glob 家族。回 None 的情況:無 glob 字元
/// (固定檔 Include)、目錄部含 glob(太花,不指定為建檔目標)、展開失敗。
fn glob_family(token: &str, main_dir: &Path, home: Option<&Path>) -> Option<GlobFamily> {
    let expanded = if let Some(rest) = token.strip_prefix("~/") {
        home?.join(rest).to_string_lossy().into_owned()
    } else if token == "~" {
        return None;
    } else {
        token.to_string()
    };

    let p = Path::new(&expanded);
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        main_dir.join(p)
    };

    let file_part = abs.file_name()?.to_string_lossy().into_owned();
    let dir = abs.parent()?.to_path_buf();
    if dir.to_string_lossy().contains(['*', '?', '[']) {
        return None;
    }
    if !file_part.contains('*') {
        return None; // 固定檔 Include,不是家族
    }
    let star = file_part.find('*')?;
    let last_star = file_part.rfind('*')?;
    Some(GlobFamily {
        dir,
        prefix: file_part[..star].to_string(),
        suffix: file_part[last_star + 1..].to_string(),
    })
}

/// 名稱套進家族後的最終檔名;prefix/suffix 已滿足就原樣,否則自動補齊。
fn family_name(family: &GlobFamily, name: &str) -> String {
    let already =
        name.len() >= family.prefix.len() + family.suffix.len()
            && name.starts_with(&family.prefix)
            && name.ends_with(&family.suffix);
    if already {
        name.to_string()
    } else {
        format!("{}{}{}", family.prefix, name, family.suffix)
    }
}

/// 決定新檔案的落點。`include_patterns` 是 main config top-level 的
/// Include 指令值(依文件順序,值內可含多個空白分隔的 pattern)。
/// 位於 main config 目錄底下的 glob 家族優先;否則取第一個家族;
/// 都沒有 → 檔案放 main config 旁,並回傳要插入的 Include 值
/// (main_dir 在 home 下用 `~/` 寫法,否則絕對路徑)。
pub fn plan_new_file(
    name: &str,
    main_dir: &Path,
    include_patterns: &[String],
    home: Option<&Path>,
) -> Result<NewFilePlan, AppError> {
    validate_file_name(name)?;

    let mut families: Vec<(String, GlobFamily)> = Vec::new();
    for value in include_patterns {
        for token in value.split_whitespace() {
            if let Some(f) = glob_family(token, main_dir, home) {
                families.push((token.to_string(), f));
            }
        }
    }

    let picked = families
        .iter()
        .find(|(_, f)| f.dir.starts_with(main_dir))
        .or_else(|| families.first());

    if let Some((token, family)) = picked {
        let final_name = family_name(family, name);
        validate_file_name(&final_name)?;
        return Ok(NewFilePlan {
            path: family.dir.join(&final_name).to_string_lossy().into_owned(),
            covered_by: Some(token.clone()),
            include_value: None,
            final_name,
            already_exists: false,
        });
    }

    let path = main_dir.join(name);
    let include_value = match home {
        Some(h) if main_dir.starts_with(h) => format!(
            "~/{}",
            path.strip_prefix(h).unwrap_or(&path).to_string_lossy()
        ),
        _ => path.to_string_lossy().into_owned(),
    };
    Ok(NewFilePlan {
        path: path.to_string_lossy().into_owned(),
        covered_by: None,
        include_value: Some(include_value),
        final_name: name.to_string(),
        already_exists: false,
    })
}

/// `Include` 行的插入索引:最後一個 top-level Include 之後;一個都沒有時,
/// 第一個 Host/Match 區塊之前;連區塊都沒有就檔尾。
pub fn include_insert_index(items: &[Item]) -> usize {
    let last_include = items.iter().rposition(|item| {
        matches!(item, Item::Directive(d) if d.key == "include" && d.enabled)
    });
    if let Some(i) = last_include {
        return i + 1;
    }
    items
        .iter()
        .position(|item| matches!(item, Item::Host(_) | Item::Match(_)))
        .unwrap_or(items.len())
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::model::{Directive, HostBlock};

    fn pat(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn rejects_bad_names() {
        assert!(validate_file_name("").is_err());
        assert!(validate_file_name("a/b").is_err());
        assert!(validate_file_name("a\\b").is_err());
        assert!(validate_file_name("a b").is_err());
        assert!(validate_file_name("-x").is_err());
        assert!(validate_file_name("..").is_err());
        assert!(validate_file_name("work.conf").is_ok());
    }

    #[test]
    fn directory_glob_covers_any_name() {
        let plan = plan_new_file(
            "work",
            Path::new("/home/f/.ssh"),
            &pat(&["~/.ssh/config.d/*"]),
            Some(Path::new("/home/f")),
        )
        .unwrap();
        assert_eq!(plan.path, "/home/f/.ssh/config.d/work");
        assert_eq!(plan.covered_by.as_deref(), Some("~/.ssh/config.d/*"));
        assert_eq!(plan.include_value, None);
        assert_eq!(plan.final_name, "work");
    }

    #[test]
    fn suffix_glob_appends_the_suffix() {
        let plan = plan_new_file(
            "work",
            Path::new("/home/f/.ssh"),
            &pat(&["conf.d/*.conf"]),
            Some(Path::new("/home/f")),
        )
        .unwrap();
        assert_eq!(plan.final_name, "work.conf");
        assert_eq!(plan.path, "/home/f/.ssh/conf.d/work.conf");
    }

    #[test]
    fn name_already_matching_the_suffix_is_kept() {
        let plan = plan_new_file(
            "work.conf",
            Path::new("/home/f/.ssh"),
            &pat(&["conf.d/*.conf"]),
            Some(Path::new("/home/f")),
        )
        .unwrap();
        assert_eq!(plan.final_name, "work.conf");
    }

    #[test]
    fn fixed_file_includes_are_not_families() {
        // `Include ~/.orbstack/ssh/config` 是固定檔,不是可建檔家族 → 落到插入。
        let plan = plan_new_file(
            "work",
            Path::new("/home/f/.ssh"),
            &pat(&["~/.orbstack/ssh/config"]),
            Some(Path::new("/home/f")),
        )
        .unwrap();
        assert_eq!(plan.covered_by, None);
        assert_eq!(plan.path, "/home/f/.ssh/work");
        assert_eq!(plan.include_value.as_deref(), Some("~/.ssh/work"));
    }

    #[test]
    fn non_home_main_dir_gets_an_absolute_include_value() {
        let plan = plan_new_file(
            "work",
            Path::new("/etc/opt/ssh"),
            &[],
            Some(Path::new("/home/f")),
        )
        .unwrap();
        assert_eq!(plan.include_value.as_deref(), Some("/etc/opt/ssh/work"));
    }

    #[test]
    fn multi_token_pattern_values_are_split() {
        let plan = plan_new_file(
            "work",
            Path::new("/home/f/.ssh"),
            &pat(&["~/.orbstack/ssh/config ~/.ssh/config.d/*"]),
            Some(Path::new("/home/f")),
        )
        .unwrap();
        assert_eq!(plan.covered_by.as_deref(), Some("~/.ssh/config.d/*"));
    }

    #[test]
    fn prefers_a_family_under_the_main_config_dir() {
        let plan = plan_new_file(
            "work",
            Path::new("/home/f/.ssh"),
            &pat(&["/srv/shared/*", "~/.ssh/config.d/*"]),
            Some(Path::new("/home/f")),
        )
        .unwrap();
        assert_eq!(plan.covered_by.as_deref(), Some("~/.ssh/config.d/*"));
    }

    // ── include_insert_index ─────────────────────────────────────────────────

    fn inc(value: &str) -> Item {
        Item::Directive(Directive::new("Include", value, ""))
    }

    fn host(alias: &str) -> Item {
        Item::Host(HostBlock {
            header: Directive::new("Host", alias, ""),
            patterns: vec![alias.to_string()],
            body: vec![],
        })
    }

    #[test]
    fn inserts_after_the_last_existing_include() {
        let items = vec![inc("~/.ssh/a"), inc("~/.ssh/b"), host("web")];
        assert_eq!(include_insert_index(&items), 2);
    }

    #[test]
    fn inserts_before_the_first_host_when_no_include_exists() {
        let items = vec![
            Item::Comment("# managed".to_string()),
            Item::Blank(String::new()),
            host("web"),
        ];
        assert_eq!(include_insert_index(&items), 2);
    }

    #[test]
    fn inserts_at_position_zero_when_the_file_starts_with_a_host() {
        let items = vec![host("web")];
        assert_eq!(include_insert_index(&items), 0);
    }

    #[test]
    fn appends_when_the_file_has_no_blocks_at_all() {
        let items = vec![Item::Comment("# empty".to_string())];
        assert_eq!(include_insert_index(&items), 1);
    }

    #[test]
    fn a_disabled_include_does_not_anchor_the_insertion() {
        let mut d = Directive::new("Include", "~/.ssh/x", "");
        d.enabled = false;
        let items = vec![Item::Directive(d), host("web")];
        assert_eq!(include_insert_index(&items), 1);
    }
}
