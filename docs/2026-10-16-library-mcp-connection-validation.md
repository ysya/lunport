# Library sync、連線編輯器與 MCP 連線設定修補

本輪接續已發布的 Beta 10，工作分支為 `codex/library-sync-host-dialog-fixes`，程式碼凍結提交 `21759b76801fe2be77fc196f1a651a9dfae75cd9`。修補尚未發布成新版 Beta；Beta 10 的安裝包不包含本文件描述的新功能。

## Library sync

使用者回報 macOS、Windows 都在已加入 sync chain 後，點擊 Enable library sync 出現相同的包含失敗訊息。原介面把所有錯誤都換成同一段重名／資料不可用提示，無法分辨下載失敗、資料版本、重名或記錄身分衝突。本機沒有使用者該次正式同步狀態，因此沒有宣稱已重現其正式資料的確切根因。

新增 prepare／review／include 流程：

- 先取得必要 baseline，檢查完整包含候選。下載或版本／記錄問題會顯示有明確重試方向的分類訊息。
- 如果本機 host alias 或同一父層 Group 名稱與同步資料衝突，列出本機記錄、建議新名稱及可編輯欄位；使用者明確按 Rename and include library 才套用。
- 候選保留既有記錄 ID、連線設定、Group 繼承、路由及金鑰。雲端記錄不改名；不合併、刪除記錄或私人金鑰。Host alias 改變會影響 CLI Connect，介面有明確提示。
- 審核 token 綁定包含權限與相關資料快照。審核後資料改變即拒絕，保留尚未送出的文字並提供 Refresh review。重新整理明確取得新建議。取消不包含記錄、不改名。
- 不可讀取的同步身分與相同 ID 的不同記錄仍保守拒絕，提供不同錯誤；不以猜測方式自動合併。

14 項 library 測試涵蓋兩台已加入同一 chain 的裝置：第二台的同名、不同 ID 本機 host／Group 先被舊流程拒絕，審核本身不 opt-in 或改名，明確同意後兩台保留兩組獨立 ID 與正確繼承。另涵蓋 stale review、無效改名、ID 衝突、opaque／baseline 不可用、Unicode 長 Group 名稱與別名保留。

瀏覽器實際操作涵蓋取消、明確改名、成功包含、下載失敗及過期審核。這些 UI 測試使用真實 React 元件搭配假 IPC／測試資料；未連到正式 relay。

## 新增連線對話框

移除重複的 Connection settings 工具列與黑色 sticky 標題，改用單一標題、固定底部操作列及單一表單捲動區。統一欄位高度、背景與間距；新增時先 Create host，存檔後才提供 Connect。焦點落在 Alias，取消仍遵守未儲存草稿確認。

已操作驗證 800 × 560、小視窗 17px 字體、1100 × 720、深淺色及 Windows 平台顯示分支。標準尺寸對話框為 630 × 648，無橫向溢出；捲動時標題及操作列保持可用。另在實際 macOS WKWebView 的 Development app 建立 loopback 測試連線。Windows 顯示分支的瀏覽器測試不等於 Windows WebView2 實機驗收。

[深色版面](review/library-sync-dialog/new-host-dark-1100.jpg)、[小視窗大字體](review/library-sync-dialog/new-host-light-800-17px.jpg)、[原生 macOS](review/library-sync-dialog/native-new-host-macos.jpg)。

## MCP 新增連線與指紋

Records 模式現在提供 `list_hosts`、`get_host`、`ssh_exec`、`create_host`、`verify_host_key`；Legacy 三個工具維持既有相容行為。安裝含修補的版本後，需重新連線／重啟 MCP client 以取得新的工具清單；已發布的 Beta 10 尚未包含它們。

`create_host` 接受公開連線欄位及既有金鑰／Group／跳板 ID，不接受密碼、私人金鑰、host-key pin 或額外欄位。即使在 Auto-log 也必須在 SSHelter 審核完整設定並明確核准。等待期間取消、停用 MCP、改變模式、儲存目的地或相關設定，都不能套用舊核准；重名仍由 repository 的原子驗證拒絕。儲存只回傳新記錄的公開欄位，不授予 AI 權限、不登入、不信任指紋、不執行命令。

一般連線可能在 host-key 握手之前準備密碼或解鎖金鑰，缺少金鑰或取消密碼可能因此先結束。Auto-log 的 `ssh_exec` 也刻意不開互動／信任視窗。本輪保留這些規則，另加入：

- 已儲存主機的 Edit → Server identity → Verify server fingerprint。
- `verify_host_key` 只適用已個別允許 AI 存取的主機。新／變更的指紋仍由既有原生 host-key 視窗明確核准；工具不接受 trust answer。
- 透過同一 Connector、native confirmer 與 endpoint／previous-pin CAS 流程處理未知及變更的指紋。已知相符指紋不重複詢問；成功回覆前再次確認目前保存的目的端 pin 仍相符，期間遭替換則拒絕回報已信任，不覆寫較新的 pin、不自動重試。
- 握手在目的端驗證後即停止，不準備目的端登入憑證、不開 session 或執行命令。跳板若需登入仍可要求其憑證。目的端缺少登入金鑰時也可以先核對指紋，保存流程在準備階段綁定金鑰缺失狀態，準備至提交期間新增／替換公開金鑰資料會使快照失效。指紋核對本身不授予目的端登入金鑰的使用權。
- 路由、目的地、用於跳板登入的公開金鑰、AI 權限或取消狀態改變都不能沿用先前核准；取消／拒絕／錯誤指紋不新增信任。Quit barrier 仍可取消進行中工作。

實機 Development 驗證：僅綁定 127.0.0.1 的臨時 OpenSSH，使用新生成的測試 host key，沒有允許任何登入憑證。GUI 按鈕及真實 MCP stdio 都顯示原生視窗，與獨立 `ssh-keygen -lf` 指紋一致。先取消確認沒有 pin，後明確信任才保存。MCP 新建連線先顯示核准視窗，回傳 `ai_access_allowed: false`；再僅允許此拋棄式主機，`verify_host_key` 在目的端登入金鑰不存在時仍最終回傳 `isError: false`、`trusted: true`。sshd DEBUG1 紀錄沒有 userauth、接受登入或啟動 session。

第一次端到端 MCP 試驗曾發現共用 pin 保存檢查錯誤地要求目的端登入金鑰；已修補並新增實際持久化回歸測試，重新建置後重跑成功。不是只以「視窗有出現」判定成功。最終提交另外在同一 loopback endpoint 換上新的測試 host key，驗證原生視窗正確顯示新舊指紋、明確替換後保存新 pin；再次核對相符 pin 不彈窗，仍無目的端登入／session。見 [最終換 key 畫面](review/library-sync-dialog/native-final-changed-fingerprint.jpg) 及 [保存結果](review/library-sync-dialog/native-final-pin-saved.jpg)。

[原生指紋視窗](review/library-sync-dialog/native-fingerprint-prompt.jpg)、[MCP 指紋視窗](review/library-sync-dialog/native-mcp-fingerprint-prompt.jpg)、[MCP 新增連線審核](review/library-sync-dialog/native-mcp-create-review.jpg)、[最終 MCP 回覆](review/library-sync-dialog/mcp-verify-result.json)、[原生驗證收據](review/library-sync-dialog/native-verification.json)。

這裡的「原生指紋視窗」是既有獨立 Tauri host-key 視窗，內容仍使用 WebView，由 Rust 核准 hub 管理；不是新建的 AppKit 指紋 UI。macOS 建立視窗前的 CoreAudio 保護仍涵蓋它，檢查失敗時的 AppKit 提示不依賴 WebKit。畫面驗證包含實際截圖，沒有以 mounted、loaded 或 accessibility 文字單獨推定繪圖正常。

MCP 工具宣告、`structuredContent`／`isError` 與使用者核准遵循現有 [官方 MCP tools specification](https://modelcontextprotocol.io/specification/2025-06-18/server/tools)。沒有改變 `ssh_exec` 的 Auto-log 無互動／不自動信任規則。

## 測試與限制

- 前端 81 個測試檔、1,060 項通過；TypeScript 與 Vite build 通過，仍有原有的 chunk size 提示。
- macOS complete safe Rust suite：最終提交 2,590 項通過、0 失敗、10 filtered；`SSHELTER_REQUIRE_OPENSSH=1`，依現有 CI 排除會操作真實 Keychain 的測試及不可用的 PAM 測試。
- 其中新增的管理／握手／持久化測試涵蓋明確同意、拒絕、取消、過期、撤權、設定／儲存目的地變更、未知／變更指紋、錯誤答案、跳板、最終握手期間的 pin 替換，以及真實 OpenSSH 握手。最初完整 suite 有一項既有 shell 等待 prompt 的暫時失敗；單獨重跑及最終完整 suite 均通過，未修改該測試或實作。
- Development app 建置及實際 WKWebView／MCP stdio 操作通過。Clippy 成功，仍有既有警告；本輪新增檔案沒有 Clippy 警告。
- 正常 library 的 debug profile 測試 3 項通過；[Windows CI 38826962440](https://github.com/ysya/sshelter/actions/runs/38826962440) 對同一凍結提交的完整安全 suite（2,398 passed、1 ignored、9 filtered）、三種 profile（各 3 passed）、整體 app／CLI helper 建置、實際 console、OpenSSH client 登入與 engine 連線檢查全部成功；workflow 整體成功。[Windows 收據](review/library-sync-dialog/windows-ci.json) 保留各步驟狀態，[測試總數](review/library-sync-dialog/windows-test-results.json) 由成功 job log 擷取。尚未在 Windows WebView2 進行真人互動驗收。沒有取得使用者兩平台的正式同步狀態，仍需其實際資料驗收。
- 本輪未安裝／更新正式 app、修改正式資料或正式 MCP 權限，未重置 vault、修改音訊服務或 WebKit defaults。測試使用 Development profile 與拋棄式 loopback server。完成後已撤回測試主機 AI 權限、關閉 Development MCP、Development app 及 loopback server，恢復測試瀏覽器尺寸並移除暫時 harness。Development 保留兩筆無登入憑證的測試連線及公開稽核紀錄。
- Beta 10 的 CoreAudio 啟動防護維持原行為；本輪沒有聲稱根除系統音訊死鎖或驗證任何私有 API 根治方式。

[本機檢查收據](review/library-sync-dialog/local-checks.json) 綁定凍結的程式碼提交；後續文件提交不改變該次建置／CI 來源。
