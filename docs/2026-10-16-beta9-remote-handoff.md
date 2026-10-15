# SSHelter Beta 9 遠端接手

[Beta 9 已發布](https://github.com/ysya/sshelter/releases/tag/v1.0.0-9)，四平台、更新 manifest 與公開收據均完成核對。不要重複 dispatch 此版本。

本輪完成主機右鍵操作、同步進度提示、選單寬度、可調整 Connection details、灰階配色及整體捲軸整理。以這份文件與 [Beta 9 檢視清單](releases/1.0.0-9-validation.md) 為準；Beta 3 文件保留作歷史紀錄。

2026-10-16 後續：Mac 更新後曾因 CoreAudio 卡住造成 WebKit 全黑；服務及應用程式恢復後，已在 `codex/macos-coreaudio-startup-guard` 實作原生啟動檢查、提示／診斷與有限次 WebContent 恢復，並隨 [Beta 10 發布](releases/1.0.0-10-validation.md)。繼續工作請先看 [macOS 黑畫面調查與接手](2026-10-16-macos-black-screen-handoff.md) 及 [修補驗證紀錄](2026-10-16-macos-startup-guard-validation.md)。這能避免可偵測的啟動前故障變成無提示黑畫面，不代表根除了系統死鎖或完成正式版裝置驗收。

## 來源

- Repository：`ysya/sshelter`
- 分支：`codex/host-menu-sync-feedback`
- 凍結應用來源：`ba4ede60ce4ab59aaa91935034febdf95ec3bd67`
- 基底：Beta 8 `49239cb267c0429e74ff4d1f4afb5a3edbbbc63f`
- 發布與 CI：見檢視清單；文件提交可讓分支繼續前進，不代表安裝包來源變更。

先確認遠端 checkout 乾淨；保留別人的修改，不要 reset 或 clean：

```bash
git status --short --branch
git fetch origin
git switch codex/host-menu-sync-feedback
git pull --ff-only origin codex/host-menu-sync-feedback
git show --no-patch --format=fuller ba4ede60ce4ab59aaa91935034febdf95ec3bd67
```

要執行隔離的 Development app：

```bash
pnpm install --frozen-lockfile
pnpm tauri:dev
```

使用 Development profile；不需要搬原機的 node_modules、target、vault、OS 憑證或 Codex 暫存檔。不要把一般 Production build 當隔離測試環境。

## 正式版候選

本輪程式碼與跨平台 CI 已通過，可作 1.0.0 正式候選。正式通道仍為 0.16.0；先完成舊版升級資料保留、雙裝置 Hosts／Groups 同步、Windows 原生介面與更新重啟驗收，再升正式通道。本輪僅發布 Beta。

## 裝置驗收

- [ ] Windows 原生 select popup 深淺主題、長 Group／terminal 名稱及勾選標記。
- [ ] 800×560、1100×720 與大字級的列表、Details、Settings、MCP、主機與 Group 編輯；無頁面水平溢出或動作被遮擋。
- [ ] 各捲動區的細圓角滑塊、hover／拖動提示；高對比模式使用系統尺寸與顏色。
- [ ] Details 可拖曳、方向鍵／Home／End／雙擊重設；重啟記住偏好。縮窗至受限寬度後只點分隔線，放大仍還原原偏好。
- [ ] 主機右鍵／Shift+F10、編輯／搬 Group／標籤／刪除確認、草稿保護及取消後焦點。
- [ ] 真實裝置間 Hosts、Groups 與繼承同步；新設定進行中不誤標失敗，重試中的既有錯誤在整輪完成前保留。
- [ ] 正式安裝版在 Settings → Updates 選 Beta，開啟自動檢查；實際安裝與重啟完成。Development app 不啟用 updater。正式版自動檢查由 Records 工作區掛載，無需開啟設定面板；啟動約 5 秒、執行中每 4 小時，重新取得焦點至多每小時檢查。發現更新後仍需選擇安裝／重啟。

Groups 屬於統一 Library，啟用 Sync 後與 Hosts 同步。舊本機記錄需納入／檢視完成，私鑰另有明確分享控制；密碼與 passphrase 留本機。

Repository 未設定內建 relay URL。已儲存的同步設定沿用；新裝置在 Sync 輸入先前指定的 `https://sshelter-relay.ysyavv.workers.dev`。本輪未重新部署 relay。不要擅自變更 repo variable、relay 或共享格式。

本輪的瀏覽器證據採實際元件與假資料；CI／manifest 通過不代表上面這些實機項目已驗收。發布結果補齊後，不要重複 dispatch 相同版本或覆蓋 tag。
