# SSHelter macOS 黑畫面調查與接手

更新日期：2026-10-16，時間均為 Asia/Tokyo。接手分支為 `codex/host-menu-sync-feedback`；本次調查起點是 `854512370c180fce9ef588c1a4f7f865486b51ed`，已安裝的應用程式是 Beta 9 `1.0.0-9`。

**原生啟動保護已隨 Beta 10 發布。** 修補分支為 `codex/macos-coreaudio-startup-guard`，[發布與公開收據](releases/1.0.0-10-validation.md) 已核對四平台安裝包與 Beta 通道；Stable 維持 0.16.0。實作、可重跑指令、原生故障注入與未驗證限制見 [啟動保護驗證紀錄](2026-10-16-macos-startup-guard-validation.md)。以下保留 `654b984` 接手時的研究證據；後續驗證日期採 Asia/Taipei。

本次直接阻塞點是 CoreAudio 服務無回應，WebKit GPU 程序等待音訊初始化而無法繪圖。系統服務最初為何卡住仍未確定，不能把恢復成功或啟動保護當成系統死鎖的永久修正，也不能認定某個第三方驅動就是元兇。

原接手提交 `654b984` 只保存研究、探測程式與接手指引；後續修補已變更產品程式碼，修補階段未發布。之後經使用者明確要求發布 Beta 10；沒有安裝正式 app、變更 vault 或同步設定。Beta 9 既有發布、來源和跨平台 CI 收據見 [Beta 9 接手文件](2026-10-16-beta9-remote-handoff.md)。

## 本次故障與恢復證據

環境為 macOS `27.0.1 (26A434)`；系統 WebKit 的 `CFBundleVersion` 是 `22625.1.29.11.28`。程式碼鎖定 Tauri `2.11.2`、tauri-runtime-wry `2.11.2`、Wry `0.55.1`、objc2-web-kit `0.3.2`。

- 05:23:58，WebKit 記錄 GPU 程序因 `Unresponsive` 結束；05:24:10，記錄 `RemoteRenderingBackendProxy::didBecomeUnresponsive`。
- GPU 程序的主執行緒在全部 1,773 次取樣中都停留於同一條呼叫鏈：`GPUConnectionToWebProcess::enableMediaPlaybackIfNecessary` → `RemoteAudioSessionProxyManager` → `AudioSessionMac::defaultDevice` → `AudioObjectGetPropertyData` → `HALC_ProxySystem` → Mach IPC 等待。
- 獨立 C 程式只查詢 CoreAudio 預設輸出裝置，不使用 SSHelter 或 WebKit，也在 8 秒後逾時。這項證據把問題範圍縮小到系統音訊服務。
- 使用者先執行 `sudo killall coreaudiod`。指令沒有報錯，但服務沒有退出；紀錄持續顯示 `Remaining transactions after SIGTERM: 2`，獨立查詢仍逾時。因此「指令成功返回」不能作為服務已恢復的驗證。
- 使用者再執行 `sudo killall -9 coreaudiod`。05:34:23 出現新的服務程序，獨立查詢以 status 0、exit 0 在 0.339 秒內完成。
- 舊 SSHelter 視窗的 accessibility tree 已包含 Hosts 和 Groups，但截圖仍全黑。正常 Command-Q 後重開 `/Applications/SSHelter.app`，原生截圖確認 Hosts、Groups、Settings 入口及主機卡片已實際繪製。

沒有重置 vault、重裝 SSHelter、清除 WebKit cache 或變更同步設定。原始系統紀錄和畫面含本機資料，未加入 Git；上面保存了後續判斷所需的摘要。

## 已查到的上游行為

### WebKit 在建立 GPU 連線時初始化音訊

WebKit 官方原始碼的 `GPUConnectionToWebProcess` 建構流程會呼叫 `enableMediaPlaybackIfNecessary()`，在啟用 routing arbitration 的組態下建立音訊 session manager。`AudioSessionMac` 取得預設輸出裝置時會同步呼叫 `AudioObjectGetPropertyData`。這與本次實際取樣一致，解釋了沒有主動播放音訊的視窗為何仍可能受影響。

研究下載的上游 main 固定於 commit `fe83c3131ed22bd81781abf7fe24a8857fd8e683`；它提供架構佐證，並非宣稱與本機系統 WebKit 二進位逐行相同。

- [GPU 連線建構與音訊初始化](https://github.com/WebKit/WebKit/blob/fe83c3131ed22bd81781abf7fe24a8857fd8e683/Source/WebKit/GPUProcess/GPUConnectionToWebProcess.cpp)
- [AudioSessionMac 的預設裝置查詢](https://github.com/WebKit/WebKit/blob/fe83c3131ed22bd81781abf7fe24a8857fd8e683/Source/WebCore/platform/audio/mac/AudioSessionMac.mm)
- [WebKit 私有偏好 API](https://github.com/WebKit/WebKit/blob/fe83c3131ed22bd81781abf7fe24a8857fd8e683/Source/WebKit/UIProcess/API/Cocoa/WKPreferencesPrivate.h)

### 關閉自動播放不足以證明能避開問題

Wry `0.55.1` 的 `src/wkwebview/mod.rs` 透過 `mediaTypesRequiringUserActionForPlayback` 控制自動播放；這個公開 API 控制播放所需的使用者操作，並不承諾停止音訊系統初始化。[Apple API 說明](https://developer.apple.com/documentation/webkit/wkwebviewconfiguration/mediatypesrequiringuseractionforplayback)

本機用獨立 Objective-C 探測程式檢查記憶體內的 WKWebViewConfiguration，沒有建立 WebView 或寫入 defaults：

| 偏好 | 預設 | 公開 API 要求所有媒體由使用者啟動 | 私有 API 停用媒體相關功能 |
| --- | --- | --- | --- |
| GPU DOM rendering | true | true | true |
| GPU Canvas rendering | true | true | true |
| GPU WebGL | true | true | true |
| GPU media | true | true | false |
| Media playback | true | true | false |

實測原始碼和輸出保存在 [研究附件](research/macos-webkit/)。私有 `_disableMediaPlaybackRelatedFeatures` 在本機存在，但仍保留 GPU 繪圖。因此目前沒有證據可保證「停用媒體」就能避開 GPU 連線初始化。這項實驗只驗證偏好值，沒有在 CoreAudio 再次卡住時驗證畫面，不能當成防黑畫面測試通過。

### 其他產品有相同故障回報

[Bambu Studio issue 12575](https://github.com/bambulab/BambuStudio/issues/12575) 記錄相同 macOS 版本上的 CoreAudio 初始化等待與 WebView 全黑。回報者同時重啟音訊服務並修改多個 WebKit 私有偏好後恢復，無法從該結果單獨推導任一偏好的效果。討論也指出，系統音訊仍卡住時重建 GPU 程序可能再次卡住。這是同類問題的旁證，不是 SSHelter 的修正驗收。

### Tauri 已有部分恢復機制

鎖定版本的 Tauri 提供 macOS `Builder::on_web_content_process_terminate`；tauri-runtime-wry 未提供自訂 handler 時，已有 WebContent 結束後 reload 的預設處理。這個 hook 處理的是 WebContent 結束，不能直接當作 GPU 卡住或畫面成功繪製的通知。

本次 accessibility tree 有內容但畫面仍全黑，也說明 `on_page_load`、React mounted 或 JavaScript heartbeat 不能單獨證明畫面已顯示。

- [Tauri 2.11.2 原始碼](https://docs.rs/crate/tauri/2.11.2/source/src/app.rs)，`on_web_content_process_terminate`。
- [tauri-runtime-wry 2.11.2 原始碼](https://docs.rs/crate/tauri-runtime-wry/2.11.2/source/src/lib.rs)，WebContent termination 的預設 reload。

## 主機環境線索

本機安裝 SoundSource `6.1.4`，ARK HAL 驅動為 `13.5.4`。官方在 2026-10-05 發布 SoundSource `6.1.5`，包含 ARK `13.5.5` 與音訊處理改善。[官方 release notes](https://rogueamoeba.com/support/releasenotes/?product=SoundSource)

本次較早的 CoreAudio 紀錄有 ARK 裝置的正常啟停活動，但沒有找到能指認其持鎖或造成死鎖的證據。更新 SoundSource 是合理的風險降低措施；官方更新說明沒有確認修正本次死鎖，不能承諾更新後不再發生。本輪沒有更新或移除任何音訊工具／驅動。

## 建議接續順序

此節為原調查的建議；第 2 點及第 3 點中的 WebContent 有限次恢復，已由後續修補實作與部分實機驗證。完整結果及未完成的裝置驗收以 [驗證紀錄](2026-10-16-macos-startup-guard-validation.md) 為準，不要再次直接套用本節描述的舊啟動流程。

1. **先降低主機風險。** 在使用者安排的時段更新 SoundSource，確認實際載入的 ARK 版本，再觀察睡眠喚醒、藍牙／輸出裝置切換與 SSHelter 啟動。若復發，在重啟服務前取得 coreaudiod 的 sample 和同時段紀錄，才有機會查到持鎖來源。不要因為安裝了某個驅動就直接移除它。
2. **優先補上原生啟動保護。** 在建立 macOS WebView 前，用可終止的子程序做 CoreAudio 存活查詢，設定有限期限；逾時顯示原生 AppKit 提示及重試入口。這能讓已卡住的系統服務獲得明確提示，不能保證阻止系統服務本身死鎖。探測不能跑在 UI 執行緒，也不能只丟到不可取消的 thread 後無限堆積。期限可先以 2 秒作實驗起點，再用冷啟動與睡眠喚醒資料調整。
3. **再驗證執行中的繪圖故障處理。** 以公開 WebContent termination hook 加入有次數上限的處理；另研究 GPU 仍無法繪製時的可靠判定。任何 snapshot／繪圖探測方案都須經 GPU 停滯情境驗證；單靠前端 ready 或 heartbeat 不足。恢復動作不能自動結束 SSH sessions、略過金鑰核准或丟棄未儲存編輯。
4. **私有偏好只保留為實驗候選。** 不要直接對正式 app 執行大範圍 `defaults write`、把所有 GPU 功能永久關閉，或把自動播放開關宣稱為根治。先用隔離 Development app 驗證實際故障、效能與跨版本相容性，再決定是否有必要採用。

原生提示必須不依賴 WebKit，不能用另一個 React／WebView 視窗代替。後續實作確認 rfd `0.16.0` 只在有父視窗的路徑使用 `NSAlert`，parentless 路徑實際使用 `CFUserNotification`；最終修補改採明確的 AppKit NSAlert bridge。Tauri 的 `create: false` 與 `WebviewWindowBuilder::from_config` 已用於延後 macOS WebView 建立。

## 實作邊界與驗收

接手時主視窗從設定自動建立，`src-tauri/src/lib.rs` 的 setup 隨即 show，沒有上述前置檢查。後續修補已把 tray、single-instance、Reopen、全域快捷鍵的主視窗入口，以及 authentication／hostkey／approval 視窗納入檢查；背景 MCP／SSH broker、CLI connect 與 ASKPASS helper 維持獨立。具體測試與尚待驗收項目見新驗證紀錄。

後續至少驗證：

- 正常啟動的額外延遲與冷啟動誤判；背景啟動不出現意外提示。
- 用隔離測試子程序模擬查詢成功、錯誤、永不返回；逾時能終止並回收子程序。
- CoreAudio 不可用時，原生提示仍可見且可操作，不會留下無提示黑畫面。
- 系統服務恢復後，明確重試能重建可繪圖的視窗；不無限 reload。
- WebContent 結束、GPU 繪圖停滯、睡眠喚醒分別驗證；不得把前兩者混為一種錯誤。
- 已存在的 SSH sessions、未儲存草稿及待核准金鑰請求的保留與拒絕規則。
- macOS Intel／Apple Silicon 驗收；Windows／Linux 啟動行為不受 macOS 專用邏輯影響。

原研究沒有故意把已恢復的系統音訊服務再次卡住；後續也只對 Development helper／WebContent／GPU 做隔離故障注入，沒有破壞系統音訊。正式版候選仍需原接手文件及新驗證紀錄中的裝置驗收。

## 在另一台電腦接手

先保留該機器既有修改；下列指令若遇到 dirty checkout、分支衝突或無法 fast-forward，先處理差異，不要 reset 或 clean：

```bash
git status --short --branch
git fetch origin
git switch codex/host-menu-sync-feedback
git pull --ff-only origin codex/host-menu-sync-feedback
```

接著閱讀本文件與 Beta 9 接手文件。若要驗證 CoreAudio，只能在 macOS 執行，並保留查詢期限：

```bash
sshelter_probe_dir="$(mktemp -d /tmp/sshelter-audio-probe.XXXXXX)"
clang docs/research/macos-webkit/coreaudio-probe.c \
  -framework CoreAudio -o "$sshelter_probe_dir/coreaudio-probe"
python3 - "$sshelter_probe_dir/coreaudio-probe" <<'PY'
import subprocess
import sys
import time

started = time.monotonic()
try:
    result = subprocess.run([sys.argv[1]], timeout=8, check=False)
    print(f"Elapsed: {time.monotonic() - started:.3f} seconds; exit: {result.returncode}")
except subprocess.TimeoutExpired:
    print("CoreAudio query timed out after 8 seconds; probe was killed and reaped.")
    sys.exit(124)
PY
```

這個探測程式不播放／錄製音訊，不變更預設裝置。不要在主執行緒直接呼叫它的 CoreAudio 函式。若要重啟系統音訊服務，先告知使用者會中斷所有應用程式的音訊，並由使用者完成管理員驗證；不要把 sudo 重啟加入 SSHelter 自動啟動流程。

偏好實驗可獨立編譯，僅用於研究；它會查詢私有 API 並修改自己程序記憶體中的偏好，不建立 WebView、不寫入系統設定：

```bash
clang -fobjc-arc docs/research/macos-webkit/preferences-probe.m \
  -framework Foundation -framework WebKit \
  -o "$sshelter_probe_dir/preferences-probe"
"$sshelter_probe_dir/preferences-probe"
```

私有 API 不存在時會回傳非零狀態；跨版本結果以當地輸出為準。後續產品實驗請使用 `pnpm tauri:dev` 的隔離 Development profile，不要用 Production identifier、vault 或 Keychain 作可拋棄測試資料。

## 2026-10-16：後續 Library／MCP 修補

Beta 10 發布後回報的 Library sync、連線對話框與 MCP 建立連線／核對指紋另於 `codex/library-sync-host-dialog-fixes` 完成；[實作與驗證](2026-10-16-library-mcp-connection-validation.md) 記錄行為、安全規則及實機收據。此批已隨 [Beta 11 發布](releases/1.0.0-11-validation.md)，四平台建置、Beta 通道與九個 updater 安裝包簽章均已核對；Beta 10 不含這批功能。CoreAudio 啟動防護維持既有設計，仍未聲稱根除系統音訊死鎖。

## 2026-10-16：Beta 12 後續修補

Beta 11 發布後，使用者回報同意指紋仍因全域同步狀態更新而結束連線，以及同一 chain 的 Library sync 被保留的舊版來源密文阻擋。已修補並隨 [Beta 12 發布](releases/1.0.0-12-validation.md)；[修補與故障注入驗證](2026-10-16-beta11-followup-validation.md) 記錄修補前失敗、實際 OpenSSH 連線、兩裝置同步及安全拒絕案例。macOS 2,594 項及 Windows 2,401 項安全測試通過，四平台產物與 Beta 通道均已核對。正式資料在另一台 Mac，仍待使用者兩平台更新驗收；沒有重建 chain 或重置 vault，CoreAudio 系統根因仍未確定。

## 2026-10-16：Windows 啟動與錯誤 log

使用者確認原本有錯誤的電腦更新後已成功同步，另回報 Windows Beta 12 在啟動時閃退，尚無足以確認根因的 exception／module 證據。已完成 Windows tray 執行緒／啟動順序修補、明確處理主 WebView 建立失敗與本機有限輪替的錯誤／panic／原生例外 log；[來源、實機與 Windows CI 驗證](2026-10-16-windows-startup-diagnostics.md) 記錄完整結果及限制。不是以事件 10000／10010 或上游 issue 代替故障機證據；CoreAudio 系統死鎖根因仍未確認。

上述修補已隨 [Beta 13 發布](releases/1.0.0-13-validation.md)；四平台、Beta 通道與九個 updater 套件簽章均核對成功，Stable v0.16.0 未變。
