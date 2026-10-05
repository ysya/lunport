//! Sync(Sync v2 spaces spec):端對端加密的多 space 同步。各子模組單一責任、皆可單元測試:
//! - `crypto`: 同步碼、金鑰推導、記錄加密
//! - `record`: 記錄模型與 LWW 合併
//! - `planner`: 本機變更偵測
//! - `hosts_file`: 同步檔的區塊操作、主 config 的 Include 清單、禁用的 directive
//! - `space_files`: space 檔命名、Include 清單順序與建立 / 移除 / 改名的順序規則
//! - `approval`: 危險設定的核准簽章
//! - `slot_rules`: 金鑰插槽(SP3)的型別、名稱與檔名規則、OpenSSH 私鑰檢查、`IdentityFile` 值的解析
//! - `slot_files`: 金鑰插槽的檔案系統動作:目錄與私鑰的權限、原子寫入、連結(symlink / hard link / 複製)、內容雜湊、移除與改名保留
//! - `slot_files_windows`(只在 Windows):owner-only、不繼承上層的 DACL
//! - `slot_setup`: 金鑰插槽(SP3)的建立:還沒設定的金鑰(候選)、建立或沿用插槽、無損改寫主機的 `IdentityFile`
//! - `slots`: 金鑰插槽(SP3)的引擎:帳戶裡 `keyslot` 與 `key` 記錄的讀寫、每一輪在這台維護插槽(`reconcile`)、給 UI 的插槽檢視(`views`)
//! - `relay`: relay HTTP client(`RelayApi`)與輪詢間隔
//! - `reconcile`: 記錄的加解密編碼與套到檔案的效果
//! - `merge`: 帳戶與 space 區段的本機 diff、合併、上傳(純函式)
//! - `state`: v1 狀態(只為了升級)、狀態檔路徑、同步碼的 keychain account
//! - `state_v2`: 本機狀態(`version: 2`)與 v1 狀態檔的偵測
//! - `runtime`: `SyncCore`(generation / 狀態 / 帳戶金鑰)與局部提交
//! - `env`: 引擎與外界的邊界(keychain、relay、事件、時鐘)
//! - `files`: space 檔的準備、讀取、套用 + 發布交易、存檔 hook
//! - `account`: 帳戶生命週期與 relay 設定
//! - `spaces`: space 操作與核准
//! - `round`: 一輪同步
//! - `upgrade`: 從 v1 升級
//! - `rotation`: 更換同步碼
//! - `migrate`: 主機搬進 space、跨檔案的同名主機
//! - `dto`: 給前端的事件與狀態形狀
//! - `engine`: Tauri 外殼(同步鎖、啟動、背景執行緒、存檔 hook、commands)
//! - `fake_relay`、`testkit`(只在測試):記憶體假 relay 與測試裝置

pub mod account;
pub mod approval;
pub mod crypto;
pub mod dto;
pub mod engine;
pub mod env;
#[cfg(test)]
pub mod fake_relay;
pub mod files;
pub mod hosts_file;
pub mod merge;
pub mod migrate;
pub mod planner;
pub mod reconcile;
pub mod record;
pub mod relay;
pub mod rotation;
pub mod round;
pub mod runtime;
pub mod slot_files;
#[cfg(windows)]
pub mod slot_files_windows;
pub mod slot_rules;
pub mod slot_setup;
pub mod slots;
pub mod space_files;
pub mod spaces;
pub mod state;
pub mod state_v2;
#[cfg(test)]
pub mod testkit;
pub mod upgrade;
