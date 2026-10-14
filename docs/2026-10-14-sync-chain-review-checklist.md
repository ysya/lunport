# SSHelter sync chain 檢視清單

本輪完成範圍：own SSH phase 1c 的 active records runtime，以及可操作的最小切換介面。功能分支 `codex/own-ssh-phase1c` 已依使用者 2026-10-14 的指示合併至 `next/own-ssh`，最初發布 `v1.0.0-1` beta；後續介面、設定與主機信任確認修正已發布為 `v1.0.0-2`。

## 設計方向

沿用你要的 sync chain 體驗：不需要信箱或登入服務，以 24 個單字的同步碼加入同一組裝置。這裡的 chain 是同步鏈。

每台裝置保有自己的加密 vault 與 master key。Relay 保存端對端加密的主機記錄，以及使用者明確選擇同步的私鑰；SSH 密碼與 key passphrase 留在各裝置。私鑰預設只在本機，匯入來源不被移動或刪除。持有同步碼的人可以讀取共享內容，因此同步碼需要妥善保存。

## 已完成

- [x] 新資料開啟 records workspace；舊版資料先暫停，經明確選擇才使用 legacy 或遷移。
- [x] 主機建立、編輯、刪除、Local／space 搬移，以及以穩定 ID 連線。
- [x] 自有 SSH engine、跳板路由、host-key pin、CLI 與 tray 的 records 整合。
- [x] 本機 vault 金鑰匯入／產生、明確發布同步、下載及本機啟用；使用前檢查實際金鑰身分。
- [x] 建立／加入同步鏈、spaces 選擇與管理、typed merge、重試及不認識新版資料的保護。
- [x] SSH 設定唯讀匯入預覽、確認、取消與中斷後接續。
- [x] 舊版 v1／v2 遷移預覽、受保護備份、journal、密碼引用及相同端點的 pin 搬移、確認與接續。
- [x] 離開同步鏈：可用主機複製至 Local，重映射 ID／jump／密碼引用，保留已有本機私鑰；無法完整取得資料時回報未完成。
- [x] 更換同步碼：先驗證 relay freeze 支援，再凍結舊來源並接續發布新同步鏈。
- [x] 主機、Keys、同步帳戶、匯入及遷移／離開／換碼的原生介面。
- [x] 最終獨立審查的兩項 Important/P1 修正：取得鎖後重讀狀態，以及阻止未知新版主機的舊快取繞過寫入保護；限定範圍複查確認皆已修正，沒有新增重大問題。

更換同步碼後，舊同步碼仍可能讀取舊鏈上的歷史資料；後續更新使用新鏈。這個流程不會收回別人已下載的資料。

## 驗證結果

最後修正版 Rust：2,451 個通過、0 個失敗；排除 3 個實際 OS Keychain 測試。針對性驗證：engine 22 個、records 模組 268 個通過。前端已有 63 個測試檔、942 個測試通過，TypeScript 與 Vite build 通過；修正只涉及後端。

最後修正版 macOS Dev bundle 打包成功，實際重啟後原測試主機仍保留，重新整理後狀態一致。這是本機 debug bundle 驗收。

測試使用暫存資料、記憶體 Keychain 與假 relay，包含兩裝置主機／私鑰同步及中斷恢復。沒有執行真實帳戶建立、真實資料遷移、外部 SSH 連線或正式 relay 部署。

## 起床後檢視

- [ ] 開啟本機的 `SSHelter Dev.app`，查看 Hosts、Keys、Sync account、Import。
- [ ] 確認測試主機 `development-smoke-test`（`example.invalid`）在重新整理後仍存在。
- [ ] 若要驗收真正跨裝置同步，先設定測試 relay，使用測試主機與測試金鑰建立同步鏈，再在另一台加入。
- [ ] 真正遷移前確認舊 app 已退出，並已安裝相容版／新版；未修正舊客戶端不能視為安全。
- [ ] 檢視下列尚未執行項目，再決定下一步。

本機開發 bundle：`/Users/ysya/project/sideproj/sshelter/src-tauri/target/debug/bundle/macos/SSHelter Dev.app`。使用 Development 的資料、憑證及 IPC 位置；updater 與自動啟動關閉。測試主機沒有私鑰、密碼或 host-key pin。

## 尚未執行與功能邊界

- 已依使用者授權合併、推送並發布 beta；跨平台 CI、Windows 安裝包驗證與 publish beta workflow 全部成功。
- 已合併到 `next/own-ssh`；Stable 正式發版、真實帳戶遷移及正式 relay 部署尚未執行。
- macOS／Linux／Windows 原生 CI 已通過，包含 Linux PAM、Windows 實際 OpenSSH 與 debug／Production console。四平台的最佳化 beta 安裝包建置成功；真實使用者裝置更新與資料遷移驗收仍待進行。
- Records 模式的 MCP 遠端執行與 key deployment 留在 phase 2；目前入口明確回報不可用。Legacy 原有功能依模式保留。
- 本輪是同步與切換基礎完成，不代表 Termius 所有功能已具備。

## 本輪決策

1. 主機 ID 可跨編輯保留，pin 與使用檢查必須綁定當次解析出的端點，防止舊信任套到新端點。
2. 路由與公開金鑰權威由同一份快照提供；每個金鑰認證 hop 都驗證實際 vault 材料，僅有 metadata 不代表可用。
3. 已相同的 pin 仍完成持久化，避免未存檔的記憶體值被當成已保存信任。
4. 金鑰預設留在 Local；遷移保留來源及舊密碼項目；換碼保留凍結舊鏈的歷史讀取語意。

詳細實作與測試紀錄：[active integration ledger](superpowers/plans/2026-10-14-own-ssh-phase1c-active-integration-ledger.md)、[final review fix ledger](superpowers/plans/2026-10-14-own-ssh-phase1c-final-review-fixes-ledger.md)。

Beta 安裝前注意事項與功能限制：[1.0.0-1 release notes](releases/1.0.0-1.md)。

首次原生 Windows CI 發現的路徑與測試假設，以及後續 console fixture profile 問題均已修正；針對性測試、整合 Rust suite 與最終跨平台 CI 全部通過。詳細：[beta validation](releases/1.0.0-1-validation.md)。

## 已發布 beta

- [v1.0.0-1 下載與 release notes](https://github.com/ysya/sshelter/releases/tag/v1.0.0-1)
- [發布流程](https://github.com/ysya/sshelter/actions/runs/38542143759)
- 來源：`22855e70c8b8fdf46b4539cadb16c4c2f1983d4f`，與最終 CI 相同。
- macOS universal、Linux x86_64／ARM64、Windows x64；共 20 個 release assets。
- Beta manifest 與新 release manifest 相同，15 個 platform entries 的下載資產存在且非空，簽章欄位存在；未宣稱另外下載所有安裝包並驗證其內容或密碼學簽章。
- 首次發布時 Beta 通道提供 `1.0.0-1`；現已更新至下列 `1.0.0-2`，Stable 仍為 `v0.16.0`。
- 舊資料先暫停，遷移仍需要明確確認；更換同步碼後的歷史讀取與 phase 2 限制見 release notes。

## UI 與設定修正（1.0.0-2）

- [x] 修正主機側欄、固定儲存列、切頁保留草稿及捨棄確認。
- [x] 將進階 SSH 設定與管理動作收合，scrollbar 改為細、低對比樣式。
- [x] 補回設定選單、MCP 入口、常用偏好與快捷選單；設定分類不載入舊 SSH config。
- [x] MCP 主機授權改用 stable ID，支援主機清單與連線資訊。撤銷權限不等待執行鎖。
- [x] 確認線上 relay 為 0.2.0，支援 pull-batch、freeze；本次不需更新。
- [ ] Records MCP 遠端指令執行與 key deployment 仍未完成；不是補回介面就代表可用。
- [x] 1.0.0-2 跨平台 CI、四平台 beta 安裝包、發布及 manifest 核對全部通過。

- [x] 主機信任確認改為資訊卡：endpoint、key type、完整指紋可複製，金鑰變更可比對新舊值；預設焦點在取消／拒絕，信任延遲不變。
- [ ] Group 尚未實作：建議 Local／Space → 可巢狀 Group → Host，主機可覆寫群組預設並顯示來源；tags 提供交叉篩選。移動群組不暗中切換同步範圍，刪除群組預設保留主機。參考 [Termius 官方資料模型](https://docs.termius.com/getting-started/what-is-termius)。

新版下載：[v1.0.0-2](https://github.com/ysya/sshelter/releases/tag/v1.0.0-2)。來源 `07e669a7682b4550d006e9e3ee6e1523502be424` 與最後 CI 相同；共 20 個已上傳且非空的 assets，15 個 manifest platform entries 指向存在且非空的資產，Release 與 Beta manifest 一致。Stable 維持 `v0.16.0`。完整紀錄：[1.0.0-2 validation](releases/1.0.0-2-validation.md)。

本次前端 65 檔／950 個測試通過；macOS、Linux（含 PAM）、Windows（含 console 與實際 OpenSSH）CI 全部通過。新的信任確認畫面以實際元件在 480×320 的亮色首次連線、暗色金鑰變更情境檢查；Development bundle 打包成功。尚未宣稱原生剪貼簿執行或 Windows／Linux 的逐畫面視覺驗收。
