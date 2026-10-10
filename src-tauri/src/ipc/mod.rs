//! 本機 IPC 的傳輸層(own-ssh spec §4):Unix socket 或 Windows named pipe 的伺服器(`server`、`pipe_windows`),以及連上來的程式是誰(`peer`)。
//! 這一層不認得任何協定:同一使用者的連線來了就交給呼叫端給的 `Handler`。第 0 期從 `agent/` 搬過來,`agent/` 暫時是唯一的使用者(1.0 會刪掉它),
//! 所以這裡的程式(連測試也是)不能引用 `agent`:下面的測試守著。
pub mod peer;
#[cfg(windows)]
pub mod pipe_windows;
pub mod server;

#[cfg(test)]
mod tests {
    /// 之後留下來的是 `ipc/`,不是 `agent/`:`ipc/` 的程式不能依賴 `agent`。要找的字串在執行時才組起來,免得這個檔案自己出現它。
    #[test]
    fn the_ipc_module_does_not_reach_into_the_agent() {
        let needle = ["crate", "agent"].join("::");
        for (file, source) in [
            ("mod.rs", include_str!("mod.rs")),
            ("peer.rs", include_str!("peer.rs")),
            ("pipe_windows.rs", include_str!("pipe_windows.rs")),
            ("server.rs", include_str!("server.rs")),
        ] {
            assert!(!source.contains(&needle), "ipc/{file} mentions {needle}");
        }
    }
}
