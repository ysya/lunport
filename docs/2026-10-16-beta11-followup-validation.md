# Beta 11 後續：指紋保存競態與遷移資料阻擋 Library sync

工作分支 `codex/library-sync-host-dialog-fixes`，最終程式碼來源 `99fb2ed7a09f0029b5417a56a7b911f4f911bbaa`。包含 `995ceef` 的指紋修補與 `99fb2ed` 的 Library 修補。Beta 11 安裝包來源為較早的 `095abce`，不包含本文件的兩項後續修補。兩項修補已隨 [Beta 12 發布](releases/1.0.0-12-validation.md)，四平台建置、更新通道與九個 updater 套件簽章均通過核對。

## 指紋同意後無法連線

使用者在指紋視窗同意後，終端顯示 `sync round superseded by a newer sync state` 並結束。已以故障注入重現同一錯誤：在保存指紋的帳號憑證／relay 準備期間，讓一輪正常背景同步完成。舊實作要求全域 generation 及完整狀態快照不變，連無關的同步進度或 upload receipt 都使核准失效。

改為在最新狀態上原子地比較本次核准相關的身分並保存 pin。仍綁定裝置、relay、帳號、主機完整 revision／scope／繼承路由、使用中公開金鑰身分與既有 pin；來源或安全內容改變就拒絕。帳號 proof 仍須即時驗證並與目前相同帳號合併，指紋提交前再次檢查最新身分。背景同步進度與其他主機的變更會被保留，不用舊快照覆寫。沒有自動接受新指紋、重複彈窗或無限重試。

測試涵蓋完整同步輪次插入、保留其他 host 與已接受的 seq receipt、durable save、scope／帳號／relay／裝置／端點／使用中公開金鑰／既有 pin 變更、取消及取消選取空間。MCP allow 後插入同步仍可執行；停用／撤權仍取消且不能 pin 或 exec。

另以真實 loopback OpenSSH、正式 Connector／FormatDirectory／RecordDirectory／pin 保存路徑驗證未知與變更指紋：每次只核准一次，隨後實際登入並執行 `printf sync-pin-ok`；再次連線使用保存的指紋、不重複詢問。此回歸測試的視窗回答與憑證儲存使用測試 double，沒有改動正式 app 或登入真實遠端主機。

## 已加入 chain 仍不能啟用 Library sync

兩張回報截圖顯示兩台在相同 chain，啟用時顯示 library 資料尚未下載或不可讀。使用者已確認 Mac 截圖來自另一台，這裡無法直接讀取其正式狀態；沒有取得、重置或修改該 chain／vault，不能把 fixture 結果當成使用者正式資料根因已確診。

已在測試 chain 重現完整相同錯誤：遷移刻意保留的舊版 `schema: 1` alias／text host 密文沒有 typed public identity，原本包含流程將它視為不可讀的新 host 身分，因而拒絕所有現有記錄。

修補使用既有、已推導的 transport keys 認證原始密文，只辨識既有 decoder 已支援辨認的確切舊版來源格式；保留原始加密資料，不把它當成新連線，不合併 ID，也不改寫來源。若其 wire 身分與任何 typed host（含準備包含的本機 ID）碰撞，仍拒絕。未知／擴充格式、無法認證的密文及真正缺少 baseline 仍拒絕。審核 token 仍綁定相關記錄及完整 sealed 內容；自動包含後續 import 也使用同一檢查，不在 core 鎖內讀 keychain、vault 或網路。不同的 baseline／身分阻擋現在有較明確的訊息。

兩裝置同 chain 測試確認原本失敗、修補後可啟用與互傳兩筆獨立 host 及既有 Group，繼承值正確，保留的舊來源密文逐筆相同且沒有把解密後 text 寫進 state。另驗證後續 import 能原子包含；密文改一個 byte、未支援格式與 ID shadow 都仍拒絕並保留本機記錄。

## 驗證

- [指紋修補前失敗](review/beta11-followup/host-key-regression-before.txt)、[Library 修補前失敗](review/beta11-followup/library-regression-before.txt)。兩者均是行為斷言失敗，不是以編譯錯誤當作 bug 重現。
- [實際 OpenSSH 回歸](review/beta11-followup/openssh-regression.txt) 通過；[Library suite](review/beta11-followup/library-tests.txt) 16 項通過。
- 最終 macOS complete safe Rust suite：2,594 passed、0 failed、10 filtered，174.35 秒；[本機收據](review/beta11-followup/local-checks.json)、[關鍵結果](review/beta11-followup/macos-test-results.txt)。Clippy `--lib --tests` 成功，既有程式仍有警告，修改的產品程式碼沒有 Clippy 警告。
- [Windows CI 38839305132](https://github.com/ysya/sshelter/actions/runs/38839305132) 對相同凍結提交整體成功：complete safe suite 2,401 passed、0 failed、1 ignored、9 filtered，三種 profile 各 3 passed，整體 app／CLI helper、實際 console 及 OpenSSH client／engine 連線均成功。[CI 收據](review/beta11-followup/windows-ci.json)、[實際測試總數](review/beta11-followup/windows-test-results.txt)。
- [可重跑指令](review/beta11-followup/commands.json)。安全 suite 沿用既有 CI 排除三項會操作真實 OS credential 的測試及此處不可用的 PAM 測試。初次在受限 sandbox 直接跑完整 suite 時 socket／ps 被環境禁止，改在獲准使用本機測試資源的環境執行；沒有為此放寬產品權限。測試開發期間曾修正新 OpenSSH fixture 的 pin metadata／端點初始化順序；最終結果以凍結來源的完整重跑為準。

沒有修改前端／MCP 協定宣告或 UI，Beta 11 原有版面與核准視窗驗證仍適用。使用者另一台 Mac 與 Windows 的正式資料仍待更新後驗收。CoreAudio 原生啟動保護維持原設計；本次不涉及系統音訊根因，也不表示已根除音訊死鎖。
