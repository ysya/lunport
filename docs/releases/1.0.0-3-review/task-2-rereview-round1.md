# Task 2 scoped re-review round 1

- Base：`f071333f8889f690e455c277e775e717937d588a`。
- Head：`a3ce927276769d544e1e2ca749730e572a4d44bc`。
- 只審查 `review-f071333..a3ce927.diff` 的六個修正路徑，對照原 `task-2-review.md` Important 原文及 appended task-2-report。未重新展開 Task 2 全面審查，未重跑套件，未派遣子代理，未修改產品程式碼／index／HEAD；本報告是唯一新增審查產物。

## I1：ADDRESSED

原 finding：

> [P2] 刪除確認期間 overview 刷新會更換已確認候選的 CAS token

- `GroupEditor.tsx:83` 現在持有 `GroupDeletionCandidate | null`；`:540` 於開啟確認時建立 candidate；`:564` 顯示 candidate 的 counts；`:583` 只交給 `submitGroupDeletion(deleting, state)`，不再以當下 `state.revision` 替換已審閱 token。
- `group-editor.ts:162` clone／freeze revision 和 counts；`:174` 僅檢查目前 editor 的身份與 availability，實際刪除固定送 candidate ID/revision。Pristine refresh 仍可更新 editor，但不能改 candidate；stale revision 交給 native CAS 拒絕。失敗不清除 candidate／draft，關閉再開才取得新候選。
- 新測試直接串接實際 production helpers，確認 editor 已變成 `999` 但 IPC 仍送原 decimal-string revision、原 counts，並觀察 CAS reject；另核對 mutable source 不影響 candidate。Component 已直接使用這兩個 helper，未看到修正 wiring 的缺口。
- 自動化證據是 helper transition，不是 mounted React interaction。Controller 的 mounted fixture 檢查另列於 cannot-verify，沒有將它誤算成已執行的測試。

## I2：ADDRESSED

原 finding：

> [P2] 已儲存 Group 診斷遮住修復後的草稿有效值與來源

- `HostEditor.tsx:174` 改用實際 production `previewHostDraft`；`inheritance.ts:74` 先依 raw draft 解出 preview，只有同 scope／同 Group dependency 才保留 saved winning-record diagnostic。
- 改成有效 Group 或 detach 為 app defaults 時，舊 Group 錯誤不再蓋掉草稿結果；改成另一個仍無效的 Group 時顯示新 dependency 的診斷，沒有回退成可用設定。
- notes-only／同 dependency 仍保留權威 saved diagnostic，避免 stale readable Group cache 取代 opaque winning record。既有 Connect guard 未移除，修復成功保存前仍拒絕 saved diagnostic host。
- Literal tests 核對 replacement 的 `ops`／Group ID、detach 的空 OS-username sentinel／`default`、raw `fallback`／inherit 保存、unchanged opaque protection、invalid replacement 診斷，以及 saved diagnostic 的零 Connect IPC。原 I2 的 replacement／detach 情境已被直接覆蓋。

## Windows native select 的授權修正

- `src/index.css:66`、`:104` 僅新增 `:root` 的 `color-scheme: light` 與 `.dark` 的 `color-scheme: dark`，沒有改自訂色票、控制項或增加依賴，符合 controller 給定範圍。
- `windows-select-diagnosis.md` baseline 記錄 app Light／Dark 時 root/select 都是 `normal`。本次已讀取 [MDN color-scheme 文件](https://developer.mozilla.org/en-US/docs/Web/CSS/Reference/Properties/color-scheme)，確認屬性會繼承並作用於 UA form-control/default scrollbar colors；此最小修改與已診斷原因一致。
- Controller handoff 已記錄修正後 root／所有 selects 的 computed scheme 隨實際 app theme 呈 light／dark。IAB AX 可觀察 popup 展開，但 tab screenshot 不包含 OS overlay；此處不宣稱已驗證真正 Windows native popup。

## Fix-diff 新問題

- Critical：無。
- Important：無。
- Minor：無。

修正限制在候選保存、diagnostic/preview 分離與兩項 CSS 宣告，未看到 raw payload 被 flatten、saved connection guard 被移除、CAS token 被重新取代或新的錯誤復原缺口。

## 驗證證據

- `/private/tmp/sshelter-task2-fix1-red.log`：**4 failed / 2 passed**；失敗均為實際行為 assertion：更新後 revision 被送出而未 reject、replacement／detach 仍帶舊錯誤、invalid replacement 仍顯示舊 diagnosis。沒有用缺 module／function 算這次 RED。
- `/private/tmp/sshelter-task2-fix1-green.log`：**6 files / 63 tests passed**、497 ms，與 report 所列六檔 focused command 一致。
- `/private/tmp/sshelter-task2-fix1-tsc.log`：明確記錄 **`tsc exit_code=0`**，解決原審查空 log 無法獨立判定 exit code 的證據限制。
- `/private/tmp/sshelter-task2-fix1-vite.log`：成功 **built in 15.49s**，CSS 102.03 kB／gzip 16.56 kB、JS 974.69 kB／gzip 284.87 kB；既有 >500 kB advisory 被如實記錄。
- reviewer 的 `git diff --check <base>..<head>` 成功。沒有重跑完整套件；原 66 files／972 tests 屬 base，不能當成此 fix head 的完整套件紀錄。

## Out-of-scope／cannot-verify

- Controller 正在進行 mounted Group review-open → overview-refresh → confirm、broken-host replacement/detach preview 互動；本 reviewer 沒有自行執行這些 fixture，也沒有把 helper transition 稱為 mounted coverage。
- 真正 Windows native dropdown overlay／WebView2 顯示尚未由本 reviewer 驗證；computed styles、AX expansion 與 screenshots 不等於 Windows OS popup 視覺證據。
- 全分支 integration suite、normal/minimum light/dark 最終視覺、native 資料整合／publication 仍屬 Task 6；Rust、MCP、真實 host／credential 等未重新審查或操作。

## Verdict

**Spec：Approved（本次 Task 2 修正範圍）。Task quality：Approved。**

I1／I2 的原程式缺口皆已修正，修正差異沒有新增 blocker，具備 meaningful RED 與 focused GREEN 證據。此 verdict 不代替 controller 的 mounted 行為與 Task 6 的平台／整合驗證。
