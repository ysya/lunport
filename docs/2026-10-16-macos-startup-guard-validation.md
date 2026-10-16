# macOS 原生啟動保護：實作與驗證

日期：2026-10-16，Asia/Taipei。工作分支：`codex/macos-coreaudio-startup-guard`，基底為接手提交 `654b984a919cf11857b2556a4ac9572bd65ee27f`。原修補階段沒有版本發布、正式 app 更新或系統音訊設定變更。

後續發布：修補驗證完成後，使用者另行要求發布；[Beta 10 已發布](releases/1.0.0-10-validation.md)，四平台及 Beta 通道全部核對成功。原修補階段與後續發布分開記錄；沒有安裝或啟動使用者正式 GUI。

後續 Windows 啟動修補：Beta 13 亦停用 Windows 的 Tauri 自動主 WebView 建立，以明確捕捉 WebView2 建立失敗並顯示原生診斷提示；不在 Windows 執行 CoreAudio 檢查。以下實作與故障注入證據描述原本的 macOS 修補；[Windows 後續驗證](2026-10-16-windows-startup-diagnostics.md) 另列新行為。

這個修補讓**啟動前可偵測到的 CoreAudio 無回應／錯誤，改以原生提示呈現，避免直接建立可能全黑的 WebView**。它沒有根除 CoreAudio 死鎖，不能識別造成死鎖的驅動，也不能保證檢查通過後 GPU 永遠能繪圖。

## 實作

- 只有 macOS 停止 Tauri 自動建立設定中的 WebView。正常前景啟動、tray、Dock Reopen、single-instance、MCP 的主視窗要求與全域快捷鍵，均經過原生 health queue。
- authentication、hostkey、approval 的非空請求也經過同一個 queue；檢查完成後重新讀取 hub，過期／取消的請求不會重播。空清單直接銷毀既有提示，不會繞過檢查建立另一個 WebView。
- 同一時間只有一個檢查 worker、一個 helper 及一個 health NSAlert。同類開窗要求合併；沒有快取健康結果，也沒有不可取消的 CoreAudio 查詢 thread。
- 使用目前 executable 的 `--coreaudio-probe` 早期模式，只查詢公開 CoreAudio 預設輸出裝置；沒有播放、錄音或切換裝置。沒有輸出裝置但查詢成功也算通過。
- 父程序期限 2 秒，失敗／逾時／錯誤展開均 kill 並 wait 回收 helper。helper 另有 3 秒 SIGALRM watchdog，避免父程序崩潰後留下無限等待的孤兒。期限同時比較 monotonic 與 wall clock，處理部分平台睡眠期間 monotonic 暫停的情況。
- 原生提示使用小型 Objective-C AppKit `NSAlert` bridge，明確在主執行緒執行。沒有父視窗時也不依賴 WebKit。沒有採用 rfd 的 parentless 分支，因鎖定版本該分支實際走 `CFUserNotification`。
- Retry 才重新檢查；Diagnostics 返回後仍停在提示，不暗中重試。Keep Running 保留後端及既有視窗，拒絕待處理的認證、host key、金鑰核准；沒有新增信任或記住核准。
- 診斷入口位於原生 Help、tray，亦可執行 `sshelter --window-diagnostics`。報告保存在目前 profile 的 `diagnostics/window-health.txt`，內容為檢查狀態與取樣指引，不記錄主機、金鑰、密碼或草稿。檔案以現有 profile write policy 與 0600 原子寫入。
- `sshelter --check-window-health` 是有期限、無 GUI 的支援指令。ASKPASS 優先於任何參數解析；即使 SSH challenge 恰好等於內部選項，也依原本拒絕規則處理。
- broker／sync／agent 先初始化，背景 `--host` 完全不建立 WebView、不執行 health query。CLI Connect、MCP stdio、ASKPASS 的原本早期模式不受 GUI gate 阻擋。
- 全域快捷鍵改由 native plugin 註冊，避免延後 WebView 後背景 app 失去開窗入口。使用者的設定在成功載入前端後鏡射到目前 profile 的 `quick-connect-enabled`；新 WebView 掛載時可取回尚未消耗的 quick-connect 意圖。舊 Beta 的純 localStorage 偏好，需先成功開窗一次才完成鏡射；首次升級就背景啟動時仍可用 Dock／tray 開窗。

## 執行中恢復的界線

已核對鎖定的 tauri-runtime-wry 2.11.2 原始碼：未提供 termination handler 時會自動 reload。本修補以自己的 handler **取代**此預設，不疊加第二套自動 reload。

WebContent 結束時拒絕待處理的安全提示，顯示原生說明；由使用者決定 Keep Window 或 Reload Window。每個 window label 在整個 app run 只允許一次使用者同意的重載，且重載前再檢查 CoreAudio。page load、heartbeat 都不會重設額度。流程不呼叫 broker quit／end_all、不重啟 app、不重置 vault 或同步資料。

GPU 停滯與 WebContent 結束分開處理。本輪沒有宣稱能自動可靠偵測 GPU 無法繪圖；原生診斷在 GPU 暫停時仍可用。未採用私有媒體／GPU API、autoplay 開關、snapshot 或 JS heartbeat 作為根治或繪圖成功的判定。

健康檢查失敗不會重載仍活著的頁面，因此保留該頁面未儲存草稿。**WebContent 程序本身死亡時，純記憶體草稿仍可能已遺失**；提示明確說明重載可能丟失編輯，本輪未新增草稿自動儲存機制。

## 本機驗證結果

環境：macOS 27.0.1（26A434）、Apple Silicon aarch64、WebKit 22625.1.29.11.28。僅使用 `org.homelab.sshelter.dev`、空白 Development library 與假資料。

| 項目 | 結果與證據 |
| --- | --- |
| 前端 | 80 files、1,056 tests 通過；TypeScript／Vite build 通過，保留既有 large-chunk warning。 |
| Rust 安全 suite | 2,566 tests 通過，0 failed；依 CI 指令排除 Keychain／PAM 等 10 個案例。使用暫存 localhost SSH server；受 sandbox 限制的首次測試中止後，在允許這些本機操作的環境重跑完成。之後以 CI 相同的 `SSHELTER_REQUIRE_OPENSSH=1`、預設 build features 再跑，仍為 2,566 passed，168.70 秒，避免 OpenSSH 測試因環境而靜默跳過。 |
| Profile／靜態檢查 | 3 項 Development profile integration tests 通過；cargo clippy --lib 完成，保留既有 66 項 warnings；git diff --check 通過。 |
| health 測試 | 5 項通過：成功／非零／spawn 失敗區分、逾時 kill + wait 並確認 ECHILD、恢復後再查詢、sleep clock expiry、queue 合併及 reload budget、三種安全請求拒絕規則。部分項目同屬一個 test。 |
| 真實 CoreAudio helper | 連續 8 次成功；第一次 executable/query 約 1.113 秒，其餘約 8–9 ms。後續完整父／子診斷的暖啟動約 20 ms。這些數據不是跨裝置冷啟動保證。 |
| fault file | success → error（exit 70）→ timeout（約 2.01 秒）→ success 全部符合預期；只改 Development helper 的回應。可重跑腳本見下方。 |
| 原生提示與重試 | 實際 NSAlert 的截圖確認可見且可操作；Diagnostics 可開啟、保存報告；模擬服務已恢復時關閉 Diagnostics 不會開窗，必須點 Retry，之後截圖確認 Hosts 畫面實際繪出。 |
| 已有草稿 | 新增未儲存假主機草稿，第二次啟動注入錯誤，Keep Running 後 Alias／Hostname 值完整保留；沒有重載。假草稿已用正常 Discard 流程移除。 |
| 背景啟動 | fault=timeout 下 `SSHELTER_START_HIDDEN=1 ... --host` 沒有視窗、helper 或 WebKit 程序；原生 broker socket 已建立並成功回覆 `mode: records`。使用者開窗才出現 health 提示。 |
| CLI／ASKPASS／MCP | Connect usage、ASKPASS 假密碼及 MCP initialize 都可獨立返回；不執行 GUI 檢查。ASKPASS 的內部選項字串拒絕與 helper orphan watchdog 由腳本另驗證。 |
| WebContent 終止 | 確認背景 baseline 無 WebKit，再只開 Development，對該次唯一 WebContent 做兩次終止注入。第一次出現原生詢問，點 Reload 後實際畫面恢復；第二次只剩 Keep Running，沒有 reload loop。Help 診斷在 WebContent 不存在時仍可用。 |
| GPU 停滯 | 暫停隔離 app 唯一 WebKit GPU，另設 25 秒自動 SIGCONT watchdog；暫停期間 Help 與 NSAlert 仍可操作、截圖確認診斷有繪出。之後明確 SIGCONT，既有頁面可繼續操作。這是 GPU 停滯注入，沒有重現或改變系統音訊死鎖。 |
| 快捷鍵設定 | Development UI 開關可同步到原生偏好，測後還原 off。UI 工具的合成按鍵未觸發 OS global shortcut，實體鍵盤及首次背景啟動驗收仍待完成。 |
| 睡眠／喚醒 | 暫停 monotonic、前進 wall time 的 deadline 測試通過；每次顯示都重新查詢，沒有沿用睡前成功快取。未讓整台共用 Mac 實際睡眠，實際硬體循環仍待驗收。 |

實際觀察使用原生 accessibility 配合畫面截圖；沒有把 accessibility tree、React mounted 或 page loaded 單獨當成繪圖證據。原始程序 sample、測試 log 及畫面留在本機／工作對話，不把可能含本機資料的原始紀錄加入 Git。

## 遠端 CI 收據

測試來源固定為 [`f9ad05afe79452f4d1deb112d06971c7b6934a48`](https://github.com/ysya/sshelter/commit/f9ad05afe79452f4d1deb112d06971c7b6934a48)。手動執行的只有既有測試 workflow，沒有 dispatch 發布。之後補上的收據文件不改變這個程式碼來源。

- [SSH engine workflow 38808771989](https://github.com/ysya/sshelter/actions/runs/38808771989)：frontend、Linux（安全 suite、profile、PAM）通過。第一次 macOS 超過設定的 45 分鐘仍停在 `Complete safe Rust suite`，之後取消；沒有取得該次完整 log，不能判定卡住原因。2026-10-16 發布 Beta 10 時重跑該 macOS job，第二次已成功，整個 workflow 現為 success；[收據](releases/1.0.0-10-review/publication/engine-ci.json) 保留 attempt 2 與來源 SHA。本機相同 required-OpenSSH 條件的補跑也已通過，兩者分開記錄。
- [Windows workflow 38808775339](https://github.com/ysya/sshelter/actions/runs/38808775339)：整個 workflow 通過，包含安全 suite、profile、完整 app 編譯、console helper、獨立 console 與 OpenSSH 登入／engine 測試。

CI 的編譯／測試結果與上方原生畫面、故障注入證據分別記錄；跨平台 CI 通過也不代表完成實體裝置 UI 驗收。

## 重跑方式

```bash
pnpm test
pnpm tauri build --debug --no-bundle \
  --config src-tauri/tauri.dev.conf.json --features development-profile
python3 docs/research/macos-webkit/verify-startup-guard.py \
  src-tauri/target/debug/sshelter
```

完整 Rust 安全 suite（與既有 macOS CI 的排除項目相同）：

```bash
cd src-tauri
cargo test --locked --lib --features development-profile -- \
  --skip secrets::tests::round_trip_set_get_delete \
  --skip askpass::tests::env_secret_takes_priority_over_keychain \
  --skip askpass::tests::missing_account_and_no_env_yields_none \
  --skip ssh::engine_tests::login_methods::pam
```

原生 fault injection：先正常退出先前的 Development app，避免 single-instance 把新環境變數交給舊 instance。不要關閉正式 app 或它的 sessions。

```bash
printf 'timeout\n' > /tmp/sshelter-coreaudio-fault.txt
SSHELTER_TEST_COREAUDIO_FILE=/tmp/sshelter-coreaudio-fault.txt \
  src-tauri/target/debug/sshelter
# 另一個 Terminal：模擬服務恢復，然後在 NSAlert 點 Retry。
printf 'success\n' > /tmp/sshelter-coreaudio-fault.txt
```

fault file 只在編譯選定的 Development profile 讀取，值限定為 `success`、`error`、`timeout`、`real`；Production 忽略此變數。正常啟動不設定此變數。**不要直接把內部 `--coreaudio-probe` 當成支援指令；使用有父程序期限的 `--check-window-health`。**

## 尚待裝置驗收

實際睡眠／喚醒後續可依下列步驟驗收；本輪沒有執行整台 Mac 的睡眠動作：

1. 不設定 fault file，啟動 Development app；只使用測試資料與已授權的測試主機。
2. 保持一條 CLI SSH 連線，另在主視窗輸入可拋棄的未儲存草稿。
3. 手動讓 Mac 睡眠並喚醒，再分別用 Dock、tray、已啟用的實體全域快捷鍵開窗。
4. 以截圖確認畫面真正繪出，檢查草稿欄位及原 SSH terminal 的輸入／輸出仍正常；若出現原生提示，先保留診斷，確認服務恢復後明確 Retry。
5. 用目前 Development executable 的 `--check-window-health` 記錄有期限的查詢結果，連同 macOS／裝置版本及睡眠情境記錄。這個結果不能代替畫面驗證。

- Intel macOS、其他 macOS 版本及真正冷開機／無輸出裝置的誤判率；2 秒門檻仍需更多樣本。
- 真實睡眠／喚醒、藍牙及輸出裝置切換。保留音訊正常的環境，不故意破壞 coreaudiod。
- 實體全域快捷鍵在背景冷啟動、視窗隱藏／最小化時的操作；舊偏好首次鏡射流程。
- 真實 SSH session 在每種原生故障提示期間持續互動；本輪有 broker 活性與 session suite 證據，沒有把新 gate 與一條實際遠端長連線聯合驗收。
- authentication／hostkey／approval 實際視窗的跨裝置互動；本輪完成共用 gate、過期請求重讀與三種 hub 拒絕規則測試，沒有在真實遠端金鑰請求中操作每一個故障組合。
- Windows／Linux 的 native UI；CoreAudio／NSAlert 邏輯由 macOS cfg 隔離，快捷鍵的共用原生註冊需跨平台 CI／裝置補驗。
- 檢查成功後才發生的 GPU／CoreAudio 故障仍可能造成黑畫面；本輪提供原生診斷與保守的 WebContent 恢復，未宣稱可靠的自動 GPU 故障偵測或系統死鎖根治。

原修補驗證階段沒有 sudo、coreaudiod 重啟、正式 WebKit defaults 寫入、驅動移除、vault 重置或發布動作；後續 Beta 10 發布收據另見上方連結。
