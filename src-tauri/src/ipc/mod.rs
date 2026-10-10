//! 本機 IPC 的傳輸層(own-ssh spec §4):Unix socket 或 Windows named pipe 的伺服器(`server`、`pipe_windows`),以及連上來的程式是誰(`peer`)。
//! 這一層不認得任何協定:同一使用者的連線來了就交給呼叫端給的 `Handler`。第 0 期從 `agent/` 搬過來,`agent/` 暫時是唯一的使用者(1.0 會刪掉它),
//! 所以這裡的程式(連測試和註解也是)不能引用 `agent`:下面的測試守著。
pub mod peer;
#[cfg(windows)]
pub mod pipe_windows;
pub mod server;

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    /// `dir` 底下所有的 `.rs` 檔(遞迴),排序過,讓失敗訊息每次的順序一樣。
    fn rust_files(dir: &Path) -> Vec<PathBuf> {
        let mut found = Vec::new();
        for entry in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("cannot list {}: {e}", dir.display())) {
            let path = entry.unwrap_or_else(|e| panic!("cannot list {}: {e}", dir.display())).path();
            if path.is_dir() {
                found.extend(rust_files(&path));
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                found.push(path);
            }
        }
        found.sort();
        found
    }

    /// 這一行有沒有把 `name` 當成路徑的一段:後面接兩個冒號(從 `crate` 或 `super` 往下走、寫在 `use` 的大括號裡都一樣),
    /// 或前面接兩個冒號(`use` 它、或給它取別名)。`name` 緊貼著英數字或底線就不算(例如前面還連著 `ssh_`、後面多一個 `s`),那是別的識別字。
    fn names_the_module(line: &str, name: &str) -> bool {
        let is_identifier = |c: char| c.is_ascii_alphanumeric() || c == '_';
        line.match_indices(name).any(|(start, _)| {
            let (before, after) = (&line[..start], &line[start + name.len()..]);
            !before.ends_with(is_identifier) && !after.starts_with(is_identifier) && (after.starts_with("::") || before.ends_with("::"))
        })
    }

    /// 之後留下來的是 `ipc/`,不是 `agent/`:`ipc/` 底下的每個檔案都不能把 `agent` 當路徑寫出來。程式、測試和註解都算(註解裡的舊指標也該讓它失敗);
    /// 掃的是整個目錄,之後加進 `ipc/` 的檔案自動被管到。要找的名字在執行時才由兩半拼起來,這個檔案裡不會出現那個寫法,不會自己抓到自己。
    #[test]
    fn the_ipc_module_does_not_reach_into_the_agent() {
        // 路徑在編譯時由 `env!` 決定:在別台機器跑 `cargo nextest archive` 的產物找不到這個目錄(目前只用 `cargo test`)。
        let dir = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src/ipc"));
        let files = rust_files(dir);
        let this_file = dir.join("mod.rs");
        assert!(files.contains(&this_file), "the scan did not find {}: it would pass without looking at anything", this_file.display());

        let name = ["ag", "ent"].concat();
        let mut offenders = Vec::new();
        for file in &files {
            let source = std::fs::read_to_string(file).unwrap_or_else(|e| panic!("cannot read {}: {e}", file.display()));
            for (index, line) in source.lines().enumerate() {
                if names_the_module(line, &name) {
                    offenders.push(format!("ipc/{}:{}: {}", file.strip_prefix(dir).unwrap_or(file).display(), index + 1, line.trim()));
                }
            }
        }
        assert!(offenders.is_empty(), "ipc/ must not depend on the {name} module, but it names it in {} place(s):\n{}", offenders.len(), offenders.join("\n"));
    }
}
