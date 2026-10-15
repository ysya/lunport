# SSHelter Beta 3 遠端接手

使用者最新指示：先收尾、推送本次工作並交接到遠端機器執行。原先的「完成後直接 merge 與發布 Beta」授權仍有效；本機此次交接沒有啟動 Beta 3 發布。接手者應先核對下列 CI 與遠端狀態，再完成發布。

## 原始碼與目前狀態

| 項目 | 狀態 |
| --- | --- |
| Repository | `ysya/sshelter` |
| 整合分支 | `next/own-ssh`；已完成 fast-forward merge 與推送 |
| 凍結發布分支 | `codex/groups-mcp-beta3`，必須維持下列發布 SHA |
| 發布 SHA | `d1642a8b5c57dc9eb1f8e23d5c36645d5082e056` |
| 最後 runtime 修正 | `30c4a4c689b86a95bb17b8cc4fae90bb3469b686`；到發布 SHA 只有文件變更 |
| 後續交接提交 | 僅文件、公開視覺證據與唯讀發布核對工具；不改 runtime，位於 `next/own-ssh` |
| 待發布版本 | `v1.0.0-3`；交接時尚未 dispatch、建立 tag 或發布 |
| 目前 Beta | 最後核對為 `v1.0.0-2`；接手時重新查詢 |
| Stable | 最後核對 `v0.16.0` / release ID `400974628`；發布前重新保存 baseline |

不要只用 `next/own-ssh` 最新 HEAD 當發布來源：交接文件會讓這個分支前進。Beta 必須從凍結分支的 `d1642a8…` dispatch，才能對應已經跑的原生 CI。不要把新功能修正在未重驗的情況下加到這個凍結分支。

## 已完成與證據

- 巢狀 Local／Space Groups、逐欄位繼承與來源、有效設定、跨範圍搬移、刪除保留主機設定。刪除確認綁定完整公開設定快照；並行修改會拒絕舊確認並要求重新檢視。
- Records MCP `ssh_exec`、逐主機授權、Ask／Auto-log、OS 觀察到的來源、原生認證問題、逾時與取消、公開稽核記錄。實際目標與已核准身分會重新核對。
- Keys 公鑰部署到 POSIX 遠端，單次有效預覽、明確確認、路由與指紋。保留原有 `authorized_keys`、限制選項及 CRLF；防重複、拒絕 symlink，未知結果不冒稱成功。
- 設定與 AI Access 入口、精簡主機信任確認、較細 scrollbar 已包含；Windows select 的主題 `color-scheme` 已修正。
- 本機最終 Rust **2551 passed / 0 failed / 3 個真實 OS 憑證測試排除**；前端 **74 檔 / 1006 tests**，TypeScript、Vite、Development bundle 均 exit 0。Dev bundle 沒有啟動，未更新安裝中的 Production。
- 完成全分支獨立複查、一次最終修正波與 scoped 複查。I1／M1／M2 已解決；M3 排版、既有 dead-code warnings 與 Vite chunk advisory 保留。
- 本機及 macOS／Linux CI 有實際一次性 SSH 安裝 fixture；未操作使用者的真實主機、憑證或 AI 授權。

入口：

- [繁體中文功能檢視清單](releases/1.0.0-3-review-checklist.md)
- [完整整合驗證](releases/1.0.0-3-review/integration-verification.md)
- [最終複查](releases/1.0.0-3-review/final-review.md)、[修正報告](releases/1.0.0-3-review/final-fix-report.md)、[限定複查](releases/1.0.0-3-review/final-scoped-review.md)
- [全部代理決策與代價](releases/1.0.0-3-review/rulings.md)、[持久化進度 ledger](releases/1.0.0-3-review/progress.md)
- [可攜式 UI 截圖](releases/1.0.0-3-review/screenshots/README.md)：實際 React 元件與公開 fake native fixture，並非真實主機或 Windows popup 驗收。

## 遠端先做這些

先確認工作目錄沒有別人的未提交修改；不要 reset、clean、覆蓋或刪除其他 worktree。

```bash
gh auth status
git status --short --branch
git fetch origin
git switch next/own-ssh
git pull --ff-only origin next/own-ssh
git rev-parse origin/codex/groups-mcp-beta3
```

最後一行必須是 `d1642a8b5c57dc9eb1f8e23d5c36645d5082e056`。若遠端沒有 checkout，可先 `gh repo clone ysya/sshelter`。全部交接資料已在 Git；原機的 `/private/tmp`、Codex session、node_modules、target、真實 vault／OS 憑證與測試 app 資料都不需要搬過去。

僅接續 GitHub CI／發布需要 Git、已登入的 `gh`、Node 與 Python 3。要跑介面才安裝 pnpm（CI 使用 11.3.0）、Rust 與平台原生依賴：

```bash
pnpm install --frozen-lockfile
pnpm tauri:dev
```

`tauri:dev` 使用 Development profile，與 Production 分開。不要拿使用者 Production 資料做 fixture。一般 `pnpm tauri build` 是 Production profile；不要把它當成本機隔離測試指令。

## 第一優先：核對 exact-source CI

這兩個 run 的 `headSha` 都必須是 `d1642a8…`，且整個 workflow `completed / success`。交接時的公開快照在 [handoff-ci-snapshot.json](releases/1.0.0-3-review/handoff-ci-snapshot.json)；即時結果以 GitHub 為準。

```bash
gh run view 38678695179 --repo ysya/sshelter --json headSha,status,conclusion,jobs,url
gh run view 38678695106 --repo ysya/sshelter --json headSha,status,conclusion,jobs,url
```

- [ssh engine：38678695179](https://github.com/ysya/sshelter/actions/runs/38678695179)：**已成功**。frontend 74 檔／1006 tests；macOS 與 Linux 各 2544 tests，profile 各 3×3；Linux 真實 PAM 7 tests。safe suite 將 7 個 PAM 放到獨立 Linux step，另排除 3 個真實 OS 憑證測試。[摘要](releases/1.0.0-3-review/handoff-engine-summary.txt)
- [windows key slots：38678695106](https://github.com/ysya/sshelter/actions/runs/38678695106)：**已成功**。safe suite 2359 passed／1 ignored／9 filtered out；該 ignored 的實際 console 測試在獨立 step 1 passed。profile 3×3、console helper 8＋3 tests、app build、helper 使用訊息／exit 2、實際 console、OpenSSH client 登入與自有 engine 連線 1 test 全通過。[摘要](releases/1.0.0-3-review/handoff-windows-summary.txt)。Windows 本身不跑 POSIX scratch sshd／部署 fixture；原生 select popup 視覺仍待裝置驗收。

若失敗，先 `gh run view RUN_ID --repo ysya/sshelter --log-failed`。修正必須保留既有工作、使用 Conventional Commit、跑受影響測試與限定複查。runtime 有新提交就重新跑相應原生 CI，並明確更新凍結發布來源；不得沿用舊 SHA 的成功結果。

## 接著發布 Beta

以下 shell 範例供 bash／zsh 使用；Windows 可用 Git Bash，依環境將 `python3` 換為 Python 3 的實際命令。不要先發布再補 CI。

1. 重新核對兩個 run 全部成功、凍結分支仍是指定 SHA。查是否已有人啟動發布：

   ```bash
   gh run list --repo ysya/sshelter --workflow beta.yml --branch codex/groups-mcp-beta3 --event workflow_dispatch --limit 5 --json databaseId,headSha,status,conclusion,url,createdAt
   gh release list --repo ysya/sshelter --limit 10
   git ls-remote --exit-code --tags origin refs/tags/v1.0.0-3
   ```

   `ls-remote` exit **2** 表示 tag 不存在；0 表示已存在，其他表示檢查失敗。已存在就先檢查是否是同一次發布；不可刪除或覆蓋 tag。已啟動的失敗 run 使用 **Re-run failed jobs**，保留原 inputs／SHA，不重新 dispatch 同版本。

2. 使用新的收據目錄，在 dispatch **之前**保存當下 Stable；不要用交接時的舊快照冒充 baseline。

   ```bash
   task_receipt_dir="$(mktemp -d "${TMPDIR:-/tmp}/sshelter-beta3-publication.XXXXXX")"
   gh api repos/ysya/sshelter/releases/latest > "$task_receipt_dir/stable-before.json"
   python3 -c 'import json; from pathlib import Path; Path("/tmp/sshelter-beta3-inputs.json").write_text(json.dumps({"version":"1.0.0-3","notes":Path("docs/releases/1.0.0-3.md").read_text()}))'
   gh api repos/ysya/sshelter/git/ref/heads/codex/groups-mcp-beta3 --jq '.object.sha'
   ```

   baseline 的 `prerelease` 必須是 false；最後 SHA 再次必須等於 `d1642a8…`。若任一步失敗先處理，不繼續發布。

3. 原使用者已授權 merge／push／Beta，無需再次詢問。使用凍結來源，保留完整 release notes 的實際換行：

   ```bash
   gh workflow run beta.yml --repo ysya/sshelter --ref codex/groups-mcp-beta3 --json < /tmp/sshelter-beta3-inputs.json
   gh run list --repo ysya/sshelter --workflow beta.yml --branch codex/groups-mcp-beta3 --event workflow_dispatch --limit 5 --json databaseId,headSha,status,conclusion,url,createdAt
   ```

   記下本次 run ID 與建立時間，核對 `headSha`。等待 `prepare`、**macOS universal／Linux x86_64／Linux ARM64／Windows x64** 四個 installer job，以及 `beta-manifest` 全部成功。不要只等 tag 出現就宣稱完成。

4. 成功後用已推送的唯讀工具收集並驗證：

   ```bash
   python3 docs/releases/1.0.0-3-review/fetch-publication.py "$task_receipt_dir" v1.0.0-3 d1642a8b5c57dc9eb1f8e23d5c36645d5082e056
   ```

   工具會檢查 tag 指向、prerelease／draft、四平台、所有 assets 已上傳且非空、Release／Beta manifest canonical 相同、manifest 簽章與下載的 `.sig` 檔一致、Stable ID／tag 未改變，並保存 JSON 與 `verification.log`。這是公開 metadata 與簽章檔一致性驗證，**不是**逐一下載安裝包做獨立密碼學驗證。

   工具已對既有 Beta 2 公開資料做過成功驗證，並證明本機修改過的簽章檔會被拒絕；這不是 Beta 3 已發布的證據。詳見 [工具驗證收據](releases/1.0.0-3-review/handoff-tools-verification.md)。

5. 寫 `docs/releases/1.0.0-3-validation.md`，更新中文功能清單、這份交接與 Task 6 checklist／ledger。保存實際 CI／發布 run URL、release URL、原始碼 SHA、平台／asset 數、Stable 前後值與仍未做的裝置驗收。僅文件 commit／push 到 `next/own-ssh`，不要移動凍結發布分支或 tag。

不要手動 bump package.json／Cargo／Tauri 的 0.16.0；`beta.yml` 僅在 CI workspace stamp `1.0.0-3`。不要使用 `build-platform.yml` 發布 Beta。若 `v1.0.0-3` 已被另一輪佔用，先了解狀態，再選新 suffix 並同步 release notes，絕不刪 tag 重用。

## 接手時仍須保留的限制

- 這是 Brave 類型的免帳號 E2E chain，不是區塊鏈。Vault／master key 留裝置；relay 保存 E2E 共享 records 與明確選擇共享的私鑰。SSH 密碼／passphrase 留本機。
- 首次 Group／繼承需 state 4／account 4 明確升級。先停止或更新其他舊客戶端；受保護 state 備份不包含 vault／OS 憑證，也不能只還原本機檔案撤回共享升級。
- Auto-log 不開任何新認證／主機身分提示。免提示既存憑證讀取僅 Windows 有已驗證實作；macOS／Linux 需要憑證的 Auto-log 拒絕並要求 Ask。
- MCP 是同一 OS 使用者的 IPC 入口，不能隔離同使用者的其他程式。Group 不自動授予整組 AI 權限。
- 遠端公鑰部署目前是 POSIX；Windows 客戶端可以連 POSIX，但未以真實 Windows→POSIX 使用者裝置驗收。遠端 Windows 安裝未支援。
- Windows native select 實際 popup、原生 OS 憑證／剪貼簿、睡眠恢復、真實主機的 Ask／跳板／首次與變更指紋、公鑰部署、裝置 Beta 自動更新，仍需使用者裝置驗收；CI 不代表逐畫面驗收。
- relay `https://sshelter-relay.ysyavv.workers.dev/v1/info` 已只讀核對為 **0.2.0 / pull-batch / freeze**；本次未部署也不需更新。GitHub repo 的 `SSHELTER_RELAY_URL` variable 最後讀取為未設定，既有本機設定保留；無內建預設的新裝置需在 Sync account 輸入 HTTPS relay。不要擅自修改 repo variable。
- 更換 sync code 不撤回歷史密文或已下載內容。不要在 release notes 中承諾撤回能力。

## 收尾界線

本機自己的 preview Vite 已停止、viewport 已重設、實際 QA tab 已關閉。另一個已失效的 agent 暫存錯誤頁無法透過 URL policy 重新綁定，未繞過限制；它不屬於 app 或遠端執行必要狀態。原 phase-1c worktree、使用者安裝中的 app、真實 vault／主機／授權皆保留。

原機這個計畫的 ignored scratch 先保留；遠端以已提交的 ledger 為準，Task 1–5 不要重做，Task 6 接續 CI／發布。完成後如需清理，只能可回復地封存本計畫 scratch，不能 `rm -rf`、`git clean` 或刪除其他計畫／worktree。所有決策與代價已保存，後續新增決策也要追加到 ledger 與 rulings。
