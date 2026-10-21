# Passkey 登入後自動同步：已確認的改版方向

決策：使用者已確認採用方案 A，Passkey PRF 優先；不相容時提供首次替代解鎖。方案 B 保留為設計比較，不是預設流程。此確認授權進行相容性原型與實作；正式切換仍須通過下列安全與跨平台驗證。

目標：A 與 B 裝置登入同一帳號後，自動建立或解鎖加密資料庫、加入裝置、拉取與同步；一般畫面不再要求手動建立 Vault、貼配對碼、按 Continue preparing 或反覆審閱完整資料庫。本機使用仍免登入。舊資料恢復是獨立、明確選擇的匯入流程。

## 可直接簡化的部分

- 將新帳號 Vault 初始化、正常資料接收、重試、進度與首次同步串成自動流程。登入按鈕說明將同步目前資料庫及管理中的 SSH 金鑰。
- 裝置清單、撤銷與進階修復放在管理頁；進度頁只顯示同步中、已同步及可採取行動的錯誤。
- 保留本機資料、來源不變的匯入與合併機制。新帳號首次同步不要求遷移已退役服務的完整帳號／歷史。

## A：Passkey PRF 自動解鎖（貼近 Passkey-only 的目標）

使用支援 WebAuthn PRF 的同一把可同步 Passkey，在用戶端取得解鎖秘密，保護獨立產生的 Vault 金鑰與新增裝置授權能力。伺服器只保存加密封套。B 裝置使用這把 Passkey 時，自動解鎖並完成裝置加入，無需回到 A 貼碼。

這會更改目前「既有裝置簽章批准新裝置」的授權邊界。必須同時設計帳號層級加入裝置證明、金鑰世代、撤銷、防重播及舊帳號升級，不能只刪除核准檢查。新的另一把 Passkey 需要由已解鎖的用戶端建立獨立封套。

PRF 是選配功能。必須實測 macOS／Windows／Linux 的瀏覽器與 Passkey 儲存者；一般 Passkey 登入成功不代表可以解密。在不支援 PRF 的環境，需要一次性替代解鎖方式，或改用相容的 Passkey。不能承諾所有裝置與所有 Passkey 都只有一次登入。

目前登入經由可自架網域的瀏覽器頁面。設計前須處理 PRF 秘密的執行信任邊界，不能宣稱受攻擊的服務供應網頁仍無法取得瀏覽器解鎖秘密。原生可信任解鎖、網域關聯與各平台 API 的可行性需先驗證；敏感值不得傳給 relay、記錄到日誌或放入可序列化登入 DTO。

## B：Passkey 登入，加一次同步密碼

隨機 Vault 金鑰另以用戶端從同步密碼推導的金鑰保護。新裝置先以 Passkey 登入，再輸入一次同步密碼，之後交由 OS 安全儲存自動同步；不再貼配對碼。這提供較一致的跨平台與自架部署體驗，但 B 初次登入多一個解鎖步驟。密碼不交給伺服器，遺失全部解鎖途徑仍無法復原明文。

Termius 公開文件描述的 Vault 保護是使用用戶端的 master/encryption password，不能將它視為所有環境皆支援 Passkey-only 解密的證據。

## 驗證與界線

現有端對端加密與本機免登入保留。完成相容性原型、首次建立、B 裝置登入、撤銷、遺失／新增 Passkey、斷線重試、伺服器重播封套及三平台驗證後，才切換正式登入架構。Host-only 恢復與測試加速先獨立完成，不等待本決策。

參考：
- https://termius.com/security
- https://www.termius.com/vault
- https://www.w3.org/TR/webauthn-3/#prf-extension
- https://bitwarden.com/help/login-with-passkeys/

## 已確認後的實作順序與信任邊界

1. 原生加密解鎖封套：PRF 與首次同步密碼只在可信任的桌面程式處理；以獨立隨機鹽、HKDF／Argon2id 與 XChaCha20-Poly1305 保護現有 recovery authority，封套綁定服務、帳號、genesis、credential 與版本。封套不保存 Vault 主金鑰。解鎖的帳號加入能力只留在操作記憶體，正常裝置只保留自身 OS 憑證。
2. 明確的 account-unlock enrollment：新增簽章加入操作，需目前 recovery authority、仍有效且綁定新裝置的 enrollment、最新控制 head、一次性 nonce 與成功的帳號登入；只追加新裝置，不撤銷其他裝置。不能將現有 Recover（會接管與輪替）的操作當作多裝置加入。
3. 權威服務保存密文封套與單調版本，檢查簽章及 CAS；舊應用備份不得覆蓋撤銷或封套版本。Cloudflare 與 Docker 共用相同協定。
4. 使用受信任原生 adapter 取得 PRF；macOS 任意自架網域不符合 associated-domain 時走替代解鎖，不能改成執行遠端網頁並宣稱有相同的服務端失陷防護。Windows 原生 hmac-secret/PRF 與瀏覽器 PRF 的 domain separation 須核對且互不混用。支援狀態來自實際 API 結果，不偽造成功。
5. 成功解鎖後自動初始化／接納／同步及 bounded retry；登入按鈕明示同步整個本機資料庫與管理中的 SSH 金鑰。保留來源變更檢查、衝突與進階恢復，移除正常路徑的手動 Vault、配對碼及 Continue preparing。
6. 回歸驗證：A 註冊、B 新裝置加入、跨平台 fallback、不同 Passkey、撤銷與重入、錯誤密碼、封套竄改／重播、舊帳號升級、還原備份、離線重試及 Worker／Docker 隔離部署。完成後才發版；目前未切換正式服務。

平台依據：Apple `Supporting passkeys` 明確要求 `webcredentials` associated domain；目前安裝的 macOS SDK 亦確認 PRF API 自 macOS 15 起存在。API 存在不代表任意自架網域有權使用。
- https://developer.apple.com/documentation/authenticationservices/supporting-passkeys
- https://learn.microsoft.com/en-us/windows/win32/api/_webauthn/
- https://developers.yubico.com/WebAuthn/Concepts/PRF_Extension/CTAP2_HMAC_Secret_Deep_Dive.html

## 2026-10-21 實作檢查點（尚未接上日常流程，尚未部署或發版）

- 原生解鎖封套已完成：固定成本 Argon2id 密碼替代方案、獨立 native PRF domain、XChaCha20-Poly1305；AAD 綁定帳號、服務、根、方法、世代及鹽。封套只加密 recovery authority，不存 Vault／SSH 私鑰。
- 加入裝置使用獨立 `unlock` 簽章操作。必須持有目前 recovery authority、有效的本裝置 enrollment 與完整資料讀取證明，保留舊裝置；不能把一般登入或破壞性的 Recover 接管當成自動加入。
- `GET/POST /v2/unlock` 的密文登錄保存於既有獨立安全服務的 AccountStore，Cloudflare 與 Docker 共用。僅目前核准裝置可簽章更新；已登入但尚未加入的裝置只能讀取密文。簽章綁定 current head／authorization epoch／recovery authority。單調 revision、previous digest 及 CAS 防止覆蓋或回退，精確重試可重複執行；最多八種有界密文解鎖方式。
- 每種方式有獨立的 envelope generation，新增另一把 Passkey 時可原樣保留既有封套，不需要知道其他 Passkey 的 PRF。變更封套必須使用此次新 revision；authority 輪替時不能沿用原 authority 的舊封套。
- 桌面端已驗證同一份合成 fixture 的 canonical bytes、簽章與 digest，並新增 OS 安全儲存的公開 highwater；不能用還原的 workspace 狀態降低該紀錄。這個紀錄不保存密碼或 recovery seed。
- 已通過：32 項 Worker 成員／帳號／密文登錄測試及 TypeScript 檢查；7 項原生 unlock 測試、3 項原生 pairing、5 項 client state、5 項 membership 與 1 項 trust 回歸測試。測試均使用合成憑證。

仍須完成：可信任 PRF adapter 與實際平台相容性、舊帳號 recovery authority 的安全更新、首次建立封套完成讀回後才刪除暫存 kit、B 裝置解鎖後完整讀取及可恢復加入、首次 library 的自動遷移／接納與重試、簡化介面及三平台／Worker／Docker 驗證。目前未在 `/v2/info` 宣告新能力，現行 UI 與正式服務不會啟用未完成的流程。

使用者已確認可以保留系統瀏覽器登入並授權 App。瀏覽器登入只提供帳號授權；替代解鎖密碼在原生 App 輸入與處理，不傳給登入頁或 relay。PRF 仍須遵守上方已確認的可信任執行邊界；不能把伺服器供應的 PRF 網頁當成已完成原生 adapter，或宣稱能抵抗該網頁主機主動失陷。
