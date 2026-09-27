//! Sync chain: Brave 式免帳號端對端同步。各子模組單一責任、皆可單元測試:
//! - `crypto`: 助記詞、金鑰派生、記錄加密
//! - `record`: 記錄模型與 LWW 合併(Task 2)
//! - `hosts_file`: 受管同步檔的區塊操作(Task 3)
//! - `state`: 本機同步狀態持久化(Task 4)
//! - `relay`: 中繼 HTTP client(Task 5)

pub mod crypto;
pub mod hosts_file;
pub mod record;
