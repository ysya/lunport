# 自動同步：Passkey 登入與同步密碼

2026-10-21 使用者決策：本版統一使用 **Passkey 登入帳號＋同步解鎖密碼**。PRF 延後；現有資料恢復與歷史帳號升級不納入本版。

## 使用流程

1. 本機模式直接管理主機、群組和金鑰，免登入。同步服務網址預設空白，由使用者自行部署 Cloudflare 或 Docker 後填入。
2. 第一台選擇「Sign in and sync with Passkey」，由系統瀏覽器登入並授權 App。返回 Lunport 設定並確認至少 12 字元的同步解鎖密碼。
3. App 自動建立加密資料庫、完成密文封套讀回、同步本機資料及管理中的 SSH 私鑰。一般流程不再顯示建立 Vault、保存 recovery kit、配對碼或完整資料庫審閱步驟。
4. B 裝置使用相同服務及帳號登入，輸入同一組同步密碼一次；App 自動驗證完整歷史、加入裝置、合併資料並開始同步。
5. 日常介面顯示同步狀態、待上傳數量與可重試錯誤。服務網址、裝置及撤銷控制收進帳號與裝置設定。

參考 Termius 的 [加密設計](https://docs.termius.com/security/encryption-overview.md) 與 [新裝置自動同步流程](https://docs.termius.com/getting-started/sync-to-mobile.md)：登入後以使用者密碼解鎖加密資料，自動接續同步。Lunport 保留已選定的 Passkey 帳號登入、自架服務與本機免登入，不複製其帳號認證協定。

## 信任邊界

- 解鎖密碼只在桌面 App 處理，不傳到登入網頁或 relay，不寫入日誌或查詢快取。瀏覽器登入只授權帳號。
- 原生封套使用固定成本 Argon2id（64 MiB、3 次、1 lane）、HKDF 與 XChaCha20-Poly1305，AAD 綁定服務、帳號、genesis、方法與世代。它保護獨立 recovery authority，不保存 Vault 主金鑰或 SSH 私鑰。
- 首台完成獨立密文讀回及解密核對後才刪除暫存 authority；中斷可繼續。新裝置必須解密封套、完整驗證歷史並提供綁定本機 enrollment 的簽章證明。一般登入不能直接取得裝置權限。
- 加入使用獨立 `unlock` 操作，只追加裝置，保留其他裝置；不借用會接管與輪替的 Recover 操作。
- 獨立安全服務保存簽章密文登錄，使用單調 revision、previous digest 及 CAS。OS 安全儲存的公開 highwater 不受 workspace 備份還原影響。Cloudflare 與 Docker 使用相同協定。
- 明確的「登入並同步」同意另存 OS 安全儲存，綁定服務、帳號與裝置；公開 workspace 的排程旗標不能單獨授權自動發布。來源變更檢查、驗證、原子發布及錯誤退避保留。
- 密碼遺失不能靠 Passkey 還原。使用者應保存於密碼管理器。正常裝置僅保存自身受 OS 保護的憑證，不長期保存同步密碼或解鎖 authority。

## 交付門檻

首次設定、B 裝置解鎖與自動合併、錯誤密碼、竄改／回退封套、撤銷、斷線及遺失回覆重試須驗證；三平台 CI 與 Worker／Docker 隔離測試通過後才部署發版。服務需宣告 `account-unlock-v1`，舊服務提供更新提示。部署保留現有 namespace／volume，不刪除真實資料。
