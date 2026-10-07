//! SP3 金鑰插槽的純函式與型別(spec `docs/superpowers/specs/2026-10-05-sp3-key-slots-design.md` §4、§5、§6.2):
//! 帳戶記錄的 payload、插槽 id/名稱/檔名規則、OpenSSH 私鑰的檢查(不需要 passphrase、不寫任何檔案),以及
//! `IdentityFile` 值的解析。這裡不碰檔案系統與同步狀態。

use std::path::{Path, PathBuf};

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::AppError;

/// 插槽目錄,相對於家目錄。主機的 `IdentityFile` 一律寫成 `~/` 加上這個路徑。
pub const SLOT_DIR: &str = ".ssh/sshelter/keys";
/// 可以同步的私鑰檔大小上限(spec §4.1)。
pub const MAX_PRIVATE_KEY_BYTES: usize = 16 * 1024;
/// `keyslot`、`key` payload 的 schema。
pub const SLOT_SCHEMA: u32 = 1;

// 以 `concat!` 組出標頭:原始碼裡不出現完整的字面(避免被祕密掃描誤判)。
const OPENSSH_BEGIN: &str = concat!("-----BEGIN ", "OPENSSH", " PRIVATE KEY-----");
const OPENSSH_END: &str = concat!("-----END ", "OPENSSH", " PRIVATE KEY-----");
const AUTH_MAGIC: &[u8] = b"openssh-key-v1\0";

/// 插槽的共用方式(spec §2):同步私鑰,或每台電腦用自己的金鑰。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../../src/bindings/"))]
pub enum SlotMode {
    Synced,
    Own,
}

/// `keyslot` 記錄的 payload(帳戶 chain,id = 插槽 id;spec §4.1)。`mode = Synced` 時後四項必填,`Own` 時都是 None
/// (每台電腦的金鑰不同)。刪除 = tombstone。
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct KeySlotPayload {
    pub schema: u32,
    pub name: String,
    pub mode: SlotMode,
    pub origin_device_id: String,
    pub created_at_ms: u64,
    pub public_key: Option<String>,
    pub fingerprint: Option<String>,
    pub key_type: Option<String>,
    pub has_passphrase: Option<bool>,
}

/// `key` 記錄的 payload(祕密;帳戶 chain,id = 插槽 id):私鑰檔內容原樣,passphrase 不在這裡。`Debug` 不印內容。
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyPayload {
    pub schema: u32,
    pub private_key: String,
}

impl std::fmt::Debug for KeyPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPayload")
            .field("schema", &self.schema)
            .field("private_key", &format_args!("<redacted>"))
            .finish()
    }
}

/// `device` 記錄的 `slots`(spec §4.1):這台的插槽裡是哪把金鑰、是不是同步來的副本。只含公開資訊。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceSlot {
    pub slot_id: String,
    pub fingerprint: Option<String>,
    pub synced_copy: bool,
    /// 這台的金鑰在 SSHelter 的保管庫裡(`SlotSource::Vault`;金鑰保管庫 spec §7.3,別台的明細寫「in SSHelter」)。只在 true 時寫出:
    /// 其他插槽的 `device` 記錄和 SP3 寫的一樣。SP3 讀到會略過這個欄位;它寫的記錄沒有這個欄位 → false。
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub in_vault: bool,
}

/// 插槽 id:32 字元小寫 hex(隨機 16 bytes)。
pub fn is_slot_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn new_slot_id() -> Result<String, AppError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|e| AppError::Other(format!("cannot create a key slot id: {e}")))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// 名稱規則(spec §4.1):`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`,不得以 `.pub` 結尾(不分大小寫)。
pub fn valid_slot_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else { return false };
    name.len() <= 64
        && first.is_ascii_alphanumeric()
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        && !name.to_ascii_lowercase().ends_with(".pub")
}

/// 由金鑰檔名產生預設名稱:不合規的字元換成 `-`,去掉開頭的非英數字元與結尾的 `-`、去掉 `.pub`,最長 64;
/// 結果不合規就用 `key`。
pub fn default_slot_name(file_name: &str) -> String {
    let mapped: String = file_name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') { c } else { '-' })
        .collect();
    let mut name: String = mapped.trim_start_matches(|c: char| !c.is_ascii_alphanumeric()).chars().take(64).collect();
    while name.to_ascii_lowercase().ends_with(".pub") {
        name.truncate(name.len() - 4);
    }
    let name = name.trim_end_matches('-').to_string();
    if valid_slot_name(&name) {
        name
    } else {
        "key".to_string()
    }
}

/// 插槽檔名:`<name>-<插槽 id 前 8 字元>`(同 space 檔名,不需跨裝置協調唯一性)。
pub fn slot_file_name(name: &str, slot_id: &str) -> String {
    format!("{name}-{}", &slot_id[..slot_id.len().min(8)])
}

/// 主機的 `IdentityFile` 要寫的值。
pub fn slot_value(file_name: &str) -> String {
    format!("~/{SLOT_DIR}/{file_name}")
}

/// 插槽旁的公鑰檔(`<slot>.pub`)。
pub fn public_path(slot: &Path) -> PathBuf {
    let mut name = slot.as_os_str().to_owned();
    name.push(".pub");
    PathBuf::from(name)
}

/// 去掉成對的雙引號(ssh_config 的值可以加引號,`Directive.value` 原樣保留引號)。
pub fn unquote(value: &str) -> &str {
    let v = value.trim();
    if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
        &v[1..v.len() - 1]
    } else {
        v
    }
}

/// 一個 `IdentityFile` 值若指到插槽,回傳插槽檔名:`~/.ssh/sshelter/keys/<file>` 或 `%d/.ssh/sshelter/keys/<file>`
/// (可加引號),`<file>` 不得含路徑分隔字元。
pub fn slot_file_of_value(value: &str) -> Option<String> {
    let v = unquote(value);
    let rest = ["~/", "%d/"].iter().find_map(|p| v.strip_prefix(p))?;
    let file = rest.strip_prefix(SLOT_DIR)?.strip_prefix('/')?;
    (!file.is_empty() && !file.contains(['/', '\\'])).then(|| file.to_string())
}

/// 一個 `IdentityFile` 值在這台電腦上指到什麼(spec §5)。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdentityTarget {
    /// 指到插槽(插槽檔名)。
    Slot(String),
    /// 指到這台電腦上的一個檔案(不保證存在)。
    File(PathBuf),
    /// 無法自動設定;原因給使用者看。
    Unsupported(&'static str),
}

pub const REASON_PUBLIC_KEY: &str = "points at a public key (an agent provides the private key)";
pub const REASON_TOKENS: &str = "uses % tokens or environment variables";
pub const REASON_RELATIVE: &str = "is a relative path";

/// 解析一個 `IdentityFile` 值:`~`、`%d`(`/` 或 `\` 分隔)、Unix 與 Windows 的絕對路徑;其他 token、環境變數、
/// 指向 `.pub` 的值、相對路徑都不處理(計畫裁定 6)。
pub fn resolve_identity_value(value: &str, home: &Path) -> IdentityTarget {
    let v = unquote(value);
    if let Some(file) = slot_file_of_value(v) {
        return IdentityTarget::Slot(file);
    }
    if v.to_ascii_lowercase().ends_with(".pub") {
        return IdentityTarget::Unsupported(REASON_PUBLIC_KEY);
    }
    if let Some(rest) = ["~/", "~\\", "%d/", "%d\\"].iter().find_map(|p| v.strip_prefix(p)) {
        if rest.contains('%') || rest.contains("${") {
            return IdentityTarget::Unsupported(REASON_TOKENS);
        }
        // 另一種平台寫下的分隔字元:兩種平台的 PathBuf 都接受 `/`。
        return IdentityTarget::File(home.join(rest.replace('\\', "/")));
    }
    if v.contains('%') || v.contains("${") {
        return IdentityTarget::Unsupported(REASON_TOKENS);
    }
    if is_absolute_path(v) {
        return IdentityTarget::File(PathBuf::from(v));
    }
    IdentityTarget::Unsupported(REASON_RELATIVE)
}

/// Unix 的 `/…`、Windows 的 `C:\…` / `C:/…` 與 UNC `\\server\…`(同步的設定可能來自另一種平台,兩種都認得)。
fn is_absolute_path(v: &str) -> bool {
    let b = v.as_bytes();
    v.starts_with('/')
        || v.starts_with("\\\\")
        || (b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/'))
}

/// 從 OpenSSH 私鑰讀出的公開資訊。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyFacts {
    /// `<type> <base64>`(沒有 comment)。
    pub public_key: String,
    /// `SHA256:<base64 無補位>`(同 `ssh-keygen -l`)。
    pub fingerprint: String,
    pub key_type: String,
    pub has_passphrase: bool,
}

/// 不能同步的原因(訊息給使用者;不含金鑰內容)。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unsyncable {
    TooLarge,
    NotOpenSsh,
    Unreadable,
}

impl Unsyncable {
    pub fn message(self) -> &'static str {
        match self {
            Unsyncable::TooLarge => "This key is larger than 16 KiB, so it can't be synced. Keep it on this computer.",
            Unsyncable::NotOpenSsh => "This key isn't in the OpenSSH format, so it can't be synced. Convert it with ssh-keygen -p -f <file>, or keep it on this computer.",
            Unsyncable::Unreadable => "This file couldn't be read as an OpenSSH private key.",
        }
    }
}

/// 檢查 OpenSSH 格式的私鑰(PROTOCOL.key):讀出未加密的公鑰段、指紋、類型,以及 ciphername 是不是 `none`。
/// 不需要 passphrase、不寫任何檔案。只接受一個檔案一把金鑰。
pub fn inspect_private_key(text: &str) -> Result<KeyFacts, Unsyncable> {
    if text.len() > MAX_PRIVATE_KEY_BYTES {
        return Err(Unsyncable::TooLarge);
    }
    let lines: Vec<&str> = text.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    let first = lines.first().copied().unwrap_or("");
    if first != OPENSSH_BEGIN {
        return Err(if first.starts_with("-----BEGIN ") && first.contains("PRIVATE KEY") {
            Unsyncable::NotOpenSsh
        } else {
            Unsyncable::Unreadable
        });
    }
    if lines.len() < 3 || lines.last().copied() != Some(OPENSSH_END) {
        return Err(Unsyncable::Unreadable);
    }
    let data = STANDARD.decode(lines[1..lines.len() - 1].concat()).map_err(|_| Unsyncable::Unreadable)?;
    let mut reader = Reader(data.strip_prefix(AUTH_MAGIC).ok_or(Unsyncable::Unreadable)?);
    let cipher = reader.string()?;
    reader.string()?; // kdfname
    reader.string()?; // kdfoptions
    if reader.u32()? != 1 {
        return Err(Unsyncable::Unreadable);
    }
    let blob = reader.string()?;
    let mut inner = Reader(blob);
    let key_type = std::str::from_utf8(inner.string()?).map_err(|_| Unsyncable::Unreadable)?;
    if key_type.is_empty() || !key_type.bytes().all(|c| c.is_ascii_graphic()) {
        return Err(Unsyncable::Unreadable);
    }
    Ok(KeyFacts {
        public_key: format!("{key_type} {}", STANDARD.encode(blob)),
        fingerprint: blob_fingerprint(blob),
        key_type: key_type.to_string(),
        has_passphrase: cipher != b"none",
    })
}

/// OpenSSH 的指紋:`SHA256:` + blob 的 SHA-256(base64、不補位)。
pub fn blob_fingerprint(blob: &[u8]) -> String {
    format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(blob)))
}

/// 一行公鑰(`<type> <base64> [comment]`)→(`<type> <base64>`、指紋)。類型欄位必須和 blob 裡寫的一致。
pub fn parse_public_key(line: &str) -> Option<(String, String)> {
    let mut parts = line.split_whitespace();
    let key_type = parts.next()?;
    let b64 = parts.next()?;
    let blob = STANDARD.decode(b64).ok()?;
    if Reader(&blob).string().ok()? != key_type.as_bytes() {
        return None;
    }
    Some((format!("{key_type} {b64}"), blob_fingerprint(&blob)))
}

/// `keyslot` payload 能不能進快取(spec §4.1):schema、名稱、來源裝置;`mode` 與四個金鑰欄位一致;`Synced` 的
/// `public_key` 必須剛好是 `<type> <base64>`(沒有 comment、沒有第二行、沒有多餘的空白:其他電腦會把它原樣寫進 `.pub`,
/// 帳戶裡的惡意成員不得借此夾帶別的內容),而且它的指紋要等於 `fingerprint`。
pub fn valid_slot_payload(p: &KeySlotPayload) -> bool {
    if p.schema != SLOT_SCHEMA || !valid_slot_name(&p.name) || p.origin_device_id.is_empty() {
        return false;
    }
    match p.mode {
        SlotMode::Own => {
            p.public_key.is_none() && p.fingerprint.is_none() && p.key_type.is_none() && p.has_passphrase.is_none()
        }
        SlotMode::Synced => match (&p.public_key, &p.fingerprint, &p.key_type, p.has_passphrase) {
            (Some(public), Some(fingerprint), Some(_), Some(_)) => {
                parse_public_key(public).is_some_and(|(normalized, f)| &normalized == public && &f == fingerprint)
            }
            _ => false,
        },
    }
}

/// `key` payload 能不能進快取:schema 與大小(內容與指紋的比對在落地時做,spec §6.2)。
pub fn valid_key_payload(p: &KeyPayload) -> bool {
    p.schema == SLOT_SCHEMA && !p.private_key.is_empty() && p.private_key.len() <= MAX_PRIVATE_KEY_BYTES
}

/// SSH wire 格式的讀取器(uint32 big-endian;string = 長度 + 內容)。
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn u32(&mut self) -> Result<u32, Unsyncable> {
        if self.0.len() < 4 {
            return Err(Unsyncable::Unreadable);
        }
        let (head, tail) = self.0.split_at(4);
        self.0 = tail;
        Ok(u32::from_be_bytes([head[0], head[1], head[2], head[3]]))
    }

    fn string(&mut self) -> Result<&'a [u8], Unsyncable> {
        let n = self.u32()? as usize;
        if self.0.len() < n {
            return Err(Unsyncable::Unreadable);
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }
}

#[cfg(test)]
pub(crate) mod test_keys {
    //! 只給測試用的金鑰(寫計畫時產生,沒有在任何地方使用)。指紋由 `ssh-keygen -l` 核對過。
    pub const BEGIN: &str = concat!("-----BEGIN ", "OPENSSH", " PRIVATE KEY-----");
    pub const END: &str = concat!("-----END ", "OPENSSH", " PRIVATE KEY-----");

    /// 標頭 + base64 本體 + 結尾,每行以 `\n` 結束(同 ssh-keygen 的輸出)。
    pub fn armor(body: &[&str]) -> String {
        let mut text = format!("{BEGIN}\n");
        for line in body {
            text.push_str(line);
            text.push('\n');
        }
        text.push_str(END);
        text.push('\n');
        text
    }

    /// ed25519,沒有 passphrase,comment `sp3-test`。
    pub const PLAIN_BODY: &[&str] = &[
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW",
        "QyNTUxOQAAACBeTPcXX309Kd9wQ9S4ixU4hL647+CGTBQAwvNXseJ3XwAAAJD8YIOG/GCD",
        "hgAAAAtzc2gtZWQyNTUxOQAAACBeTPcXX309Kd9wQ9S4ixU4hL647+CGTBQAwvNXseJ3Xw",
        "AAAEBIKVUPhG+FZbzpyXbI6YwCJdusAIAdT6he8GYE/GBAtF5M9xdffT0p33BD1LiLFTiE",
        "vrjv4IZMFADC81ex4ndfAAAACHNwMy10ZXN0AQIDBAU=",
    ];
    pub const PLAIN_PUBLIC: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF5M9xdffT0p33BD1LiLFTiEvrjv4IZMFADC81ex4ndf";
    pub const PLAIN_FINGERPRINT: &str = "SHA256:9Q3QMhBJBcoUNE88XYEQbCPlcFByPPyVPJ6enJtQ+ew";

    /// ed25519,passphrase `test-passphrase`(aes256-ctr / bcrypt),comment `sp3-enc`。
    pub const ENC_BODY: &[&str] = &[
        "b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABAkYULw+o",
        "iDv11WqAPDdElfAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIJSEH6Vd1hjhpqq0",
        "z2zGJIQJG79kGlcIWqul53zwVaNNAAAAkC/r9CLPKPu1IJXPuu+UkwdfrDNh8vFxuo8PcI",
        "EMnUqZ/CrnnXRNdYFMp+tCsL0mXqDLa79kRN91YRyBFjyRjeLMAtTBCc6wtqfRK5Lh8bla",
        "2Vp25Stdqeaj1VV4bsn/Vpdh0CVtMU8B+uOLmaFig6Y0G7bN7b3StHzLx07OtnAOFaajRG",
        "gPtXuPP1MoRi3kkQ==",
    ];
    pub const ENC_PUBLIC: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJSEH6Vd1hjhpqq0z2zGJIQJG79kGlcIWqul53zwVaNN";
    pub const ENC_FINGERPRINT: &str = "SHA256:WZW83czQjcboddNwGO5ZP5Kvf7gt1ONldkA+inshlZM";

    /// ecdsa-sha2-nistp256,沒有 passphrase,comment `sp3-ecdsa`。
    pub const ECDSA_BODY: &[&str] = &[
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS",
        "1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQRIxTSlQ+YP54DPsfKBEqMLIXXX3x47",
        "4fpeDGMslw2TH516c8pU+sY5E4jKKdP/CtSjdfi8rHgXV5S4+o+ZvJr1AAAAqAWjAiQFow",
        "IkAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEjFNKVD5g/ngM+x",
        "8oESowshddffHjvh+l4MYyyXDZMfnXpzylT6xjkTiMop0/8K1KN1+LyseBdXlLj6j5m8mv",
        "UAAAAhAOjBMQ46KiYFnSOdrHUgOWwcziDFP1KSy0a92A/T1zX/AAAACXNwMy1lY2RzYQEC",
        "AwQFBg==",
    ];
    pub const ECDSA_PUBLIC: &str = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEjFNKVD5g/ngM+x8oESowshddffHjvh+l4MYyyXDZMfnXpzylT6xjkTiMop0/8K1KN1+LyseBdXlLj6j5m8mvU=";
    pub const ECDSA_FINGERPRINT: &str = "SHA256:vUthAmDZoxYXCTAPEZUn5qtWSMHWQCEcUfpnyM05mMs";

    /// rsa 2048,沒有 passphrase,comment `sp3-rsa`(金鑰保管庫計畫 Task 2 產生,沒有在任何地方使用)。指紋由 `ssh-keygen -l` 核對過。
    pub const RSA_BODY: &[&str] = &[
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn",
        "NhAAAAAwEAAQAAAQEA2LN0JUt3ulLhhwkHP9LqkMwtBGyB5tBCHH89TW85tUNw4yKFEO18",
        "DeQL4LOpCUcq7nF/yMv8YA3jZMr4EsKKu9mwem3Sd41hDLO/HwuntOXkS2vsYrotq4+Sz2",
        "0u+G8QnQekpzkQW7UxPLvZOKqU0xH67DkWhG+5rRxS2wFVrZ9eG4CzDpLbBqTLXSAyk8hv",
        "7/AcXQyXs7SgCxf5jdlUKh9kP4Zudv/OQytkpmlYuaOIKmTY6ljWbYLccVD8njaAigTc+j",
        "IXAZoVmLK0xN4myXNVmyB5VGC/zdJvIpIVR+xoMeZuk7MBKzDNGPpbGav4sRlzszujvek9",
        "nq7K5P2vqwAAA8A4lbvqOJW76gAAAAdzc2gtcnNhAAABAQDYs3QlS3e6UuGHCQc/0uqQzC",
        "0EbIHm0EIcfz1Nbzm1Q3DjIoUQ7XwN5Avgs6kJRyrucX/Iy/xgDeNkyvgSwoq72bB6bdJ3",
        "jWEMs78fC6e05eRLa+xiui2rj5LPbS74bxCdB6SnORBbtTE8u9k4qpTTEfrsORaEb7mtHF",
        "LbAVWtn14bgLMOktsGpMtdIDKTyG/v8BxdDJeztKALF/mN2VQqH2Q/hm52/85DK2SmaVi5",
        "o4gqZNjqWNZtgtxxUPyeNoCKBNz6MhcBmhWYsrTE3ibJc1WbIHlUYL/N0m8ikhVH7Ggx5m",
        "6TswErMM0Y+lsZq/ixGXOzO6O96T2ersrk/a+rAAAAAwEAAQAAAQAGLTdGSNxkxy/+dVdr",
        "jkt5TRiLY7xgI9d+kHHi3yS58e4pyzYXwW0jyDg+c2CCDzE+EqYdxxKuejbdDJv9jOX/bL",
        "kHBFJXbgQyJH1yGRbypQrYy361YbEjjrgUiXwpQKEsmKcszQeWVZfNr10FrHcJfR211fq6",
        "U6TrNj92Vpdml3LZJW1V4w9B29oHvFWrlGgulker1FqTVHdv+m4epQsg1jBelC/BxwezFe",
        "JhRtsu12T/K/cMgAZJEkXV1X/DN6bEFOtNr1WlP4PpTCozCWgVQzTtmOTHT9wTWRpxCSxB",
        "AbX5Oq2o5UgDK+B7V0Xa8QS6IaIKKLk4Rwg2tOCEIQYhAAAAgCmXIM/YGNVQOsYU/ds9mz",
        "+IcZbeSoOLgho/JxdwU775k2Kd312C/02vMGsUMRhVmmu6hi7LIpL3prb+mYmKWRll0U4I",
        "W9HZ8Y9gW5+jBbaNOGc9PHQLHrTkRX74If3GVoOVxS/ln5eTm42SRNCj84g1HmJQsI228s",
        "WjOIzsmR/nAAAAgQD4TsMKXXcufC93uQNZPCLArxzKQvZ/M6v1VGd6oZxc6Wpb2c9dRf8j",
        "RAPeuT0r+GrBzxOgTActA2/qcHSoLM1PgfNqXA4YlsgJmyoyfXNIzIzQlQ7qHDeZOlWkEt",
        "K+qFuI0mhw3T7f3ipYLiCjlFVRkuICMY4DQhJyfYtBuV8eVQAAAIEA32oH3w4+mcbhVVeX",
        "ctgvT3WpWXzBWK42Va9OodvoTZuGRbAw/bxoElARZSaP4Wvmke2Mqx/RAYVoECN8uk5oXx",
        "19hf7Okcw8yHPt/bqW15eVoxA7/exsqSbJSwrd3BSbbX8yfpfmk0Kf/p4jjqbui0cBssS5",
        "xZ9vqxjEQlE7lf8AAAAHc3AzLXJzYQECAwQ=",
    ];
    pub const RSA_PUBLIC: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDYs3QlS3e6UuGHCQc/0uqQzC0EbIHm0EIcfz1Nbzm1Q3DjIoUQ7XwN5Avgs6kJRyrucX/Iy/xgDeNkyvgSwoq72bB6bdJ3jWEMs78fC6e05eRLa+xiui2rj5LPbS74bxCdB6SnORBbtTE8u9k4qpTTEfrsORaEb7mtHFLbAVWtn14bgLMOktsGpMtdIDKTyG/v8BxdDJeztKALF/mN2VQqH2Q/hm52/85DK2SmaVi5o4gqZNjqWNZtgtxxUPyeNoCKBNz6MhcBmhWYsrTE3ibJc1WbIHlUYL/N0m8ikhVH7Ggx5m6TswErMM0Y+lsZq/ixGXOzO6O96T2ersrk/a+r";
    pub const RSA_FINGERPRINT: &str = "SHA256:uPzZ3UuFWT885udlYuahqchYLpT+ZyjhQqBnoICqfcU";

    pub fn plain() -> String {
        armor(PLAIN_BODY)
    }
    pub fn encrypted() -> String {
        armor(ENC_BODY)
    }
    pub fn ecdsa() -> String {
        armor(ECDSA_BODY)
    }
    pub fn rsa() -> String {
        armor(RSA_BODY)
    }

    /// 把一個 SSH string(`uint32` 長度 + 內容)接到 `out` 後面。
    fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(bytes);
    }

    /// 把一個二進位的 OpenSSH 私鑰內容包成文字(每 70 字元一行)。
    fn armor_bytes(bytes: &[u8]) -> String {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let b64 = STANDARD.encode(bytes);
        let lines: Vec<&str> = b64.as_bytes().chunks(70).map(|c| std::str::from_utf8(c).unwrap()).collect();
        armor(&lines)
    }

    /// 組一行公鑰:演算法名稱,後面每個欄位都是一個 SSH string(sk 金鑰的公鑰與 application、DSA 的四個 mpint 都是)。
    pub fn public_line(algorithm: &str, fields: &[&[u8]]) -> String {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let mut blob = Vec::new();
        put_string(&mut blob, algorithm.as_bytes());
        for field in fields {
            put_string(&mut blob, field);
        }
        format!("{algorithm} {}", STANDARD.encode(blob))
    }

    /// `sk-ssh-ed25519@openssh.com`(FIDO 安全金鑰)的公鑰那一行。
    pub fn sk_public() -> String {
        public_line("sk-ssh-ed25519@openssh.com", &[&[7; 32], b"ssh:"])
    }

    /// `ssh-dss`(DSA)的公鑰那一行(四個 mpint 隨便填,`ssh-key` 讀得懂就好)。
    pub fn dsa_public() -> String {
        public_line("ssh-dss", &[&[1], &[2], &[3], &[4]])
    }

    /// 沒有加密的 `sk-ssh-ed25519@openssh.com` 私鑰檔,照 OpenSSH 的 `openssh-key-v1` 格式手工組出來(私鑰段:公鑰、application、flags、key handle、
    /// reserved、comment,補到 8 的倍數)。`inspect_private_key` 讀得懂,但 SSHelter 的 agent 簽不了這種金鑰。
    pub fn security_key() -> String {
        let mut public = Vec::new();
        put_string(&mut public, b"sk-ssh-ed25519@openssh.com");
        put_string(&mut public, &[7; 32]);
        put_string(&mut public, b"ssh:");
        let mut body = b"openssh-key-v1\0".to_vec();
        put_string(&mut body, b"none"); // 加密方式(cipher)
        put_string(&mut body, b"none"); // kdf 名稱
        put_string(&mut body, b""); // kdf 選項
        body.extend_from_slice(&1u32.to_be_bytes()); // 一把金鑰
        put_string(&mut body, &public);
        let mut private = vec![1, 2, 3, 4, 1, 2, 3, 4]; // 兩個相同的 checkint
        put_string(&mut private, b"sk-ssh-ed25519@openssh.com");
        put_string(&mut private, &[7; 32]);
        put_string(&mut private, b"ssh:");
        private.push(1); // flags(要求使用者在場)
        put_string(&mut private, b"handle"); // key handle(硬體金鑰的代號)
        put_string(&mut private, b""); // reserved(保留欄位)
        put_string(&mut private, b"sp3-sk"); // comment(註解)
        let mut pad = 1u8;
        while private.len() % 8 != 0 {
            private.push(pad);
            pad += 1;
        }
        put_string(&mut body, &private);
        armor_bytes(&body)
    }

    /// 沒有加密的 ed25519 私鑰(同 `plain()`),comment 換成不是 UTF-8 的位元組(長度不變,金鑰本身不動):`inspect_private_key` 只看標頭與公鑰段,讀得懂;
    /// `ssh-key` 把 comment 當字串讀,讀不懂,所以 agent 打不開它。
    pub fn unreadable_comment() -> String {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let mut bytes = STANDARD.decode(PLAIN_BODY.concat()).unwrap();
        let comment = bytes.windows(8).rposition(|w| w == b"sp3-test").expect("the fixture ends with its comment");
        bytes[comment + 4..comment + 8].copy_from_slice(&[0xff, 0xfe, 0xfd, 0xfc]);
        armor_bytes(&bytes)
    }

    /// 加密過的測試私鑰,標頭裡的加密方式改標成 `3des-cbc`(`ssh-key` 0.6.7 讀得懂、但解不開)。只換標頭裡的名稱,金鑰的位元組不動。
    pub fn encrypted_with_3des_label() -> String {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let bytes = STANDARD.decode(ENC_BODY.concat()).unwrap();
        let (magic, rest) = bytes.split_at(b"openssh-key-v1\0".len());
        let (old_len, after_len) = rest.split_at(4);
        assert_eq!(old_len, 10u32.to_be_bytes(), "the fixture is expected to start with `aes256-ctr`");
        let (old_name, tail) = after_len.split_at(10);
        assert_eq!(old_name, b"aes256-ctr");
        let mut relabelled = magic.to_vec();
        put_string(&mut relabelled, b"3des-cbc");
        relabelled.extend_from_slice(tail);
        armor_bytes(&relabelled)
    }
}

#[cfg(test)]
mod tests {
    use super::test_keys::*;
    use super::*;
    use base64::engine::general_purpose::STANDARD;

    /// 把 OpenSSH 私鑰的二進位內容包回文字(每 70 字元一行)。
    fn rearmor(bytes: &[u8]) -> String {
        let b64 = STANDARD.encode(bytes);
        let lines: Vec<&str> = b64.as_bytes().chunks(70).map(|c| std::str::from_utf8(c).unwrap()).collect();
        armor(&lines)
    }

    fn plain_bytes() -> Vec<u8> {
        STANDARD.decode(PLAIN_BODY.concat()).unwrap()
    }

    #[test]
    fn inspects_an_unencrypted_ed25519_key() {
        let facts = inspect_private_key(&plain()).unwrap();
        assert_eq!(facts.public_key, PLAIN_PUBLIC);
        assert_eq!(facts.fingerprint, PLAIN_FINGERPRINT);
        assert_eq!(facts.key_type, "ssh-ed25519");
        assert!(!facts.has_passphrase);
    }

    #[test]
    fn inspects_an_encrypted_key_without_its_passphrase() {
        let facts = inspect_private_key(&encrypted()).unwrap();
        assert_eq!(facts.public_key, ENC_PUBLIC);
        assert_eq!(facts.fingerprint, ENC_FINGERPRINT);
        assert!(facts.has_passphrase);
    }

    #[test]
    fn inspects_an_ecdsa_key_and_crlf_text() {
        let facts = inspect_private_key(&ecdsa().replace('\n', "\r\n")).unwrap();
        assert_eq!(facts.public_key, ECDSA_PUBLIC);
        assert_eq!(facts.fingerprint, ECDSA_FINGERPRINT);
        assert_eq!(facts.key_type, "ecdsa-sha2-nistp256");
    }

    #[test]
    fn pem_and_pkcs8_keys_are_not_openssh() {
        let pem = format!("{}\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n{}\n", concat!("-----BEGIN RSA ", "PRIVATE KEY-----"), concat!("-----END RSA ", "PRIVATE KEY-----"));
        assert_eq!(inspect_private_key(&pem), Err(Unsyncable::NotOpenSsh));
        let pkcs8 = format!("{}\nMC4CAQAwBQYDK2VwBCIEIA==\n{}\n", concat!("-----BEGIN ", "PRIVATE KEY-----"), concat!("-----END ", "PRIVATE KEY-----"));
        assert_eq!(inspect_private_key(&pkcs8), Err(Unsyncable::NotOpenSsh));
    }

    #[test]
    fn garbled_and_oversized_keys_are_refused() {
        // 沒有結尾、base64 壞掉、魔術字不對、兩把金鑰、公鑰段被截斷。
        let no_end = plain().replace(END, "");
        assert_eq!(inspect_private_key(&no_end), Err(Unsyncable::Unreadable));
        assert_eq!(inspect_private_key(&armor(&["!!!not base64!!!"])), Err(Unsyncable::Unreadable));
        let mut wrong_magic = plain_bytes();
        wrong_magic[0] = b'X';
        assert_eq!(inspect_private_key(&rearmor(&wrong_magic)), Err(Unsyncable::Unreadable));
        let mut two_keys = plain_bytes();
        // "openssh-key-v1\0" (15) + "none" (4+4) + "none" (4+4) + "" (4) = 35:金鑰數量的 u32 從這裡開始。
        two_keys[35..39].copy_from_slice(&2u32.to_be_bytes());
        assert_eq!(inspect_private_key(&rearmor(&two_keys)), Err(Unsyncable::Unreadable));
        assert_eq!(inspect_private_key(&rearmor(&plain_bytes()[..50])), Err(Unsyncable::Unreadable));
        assert_eq!(inspect_private_key("not a key at all"), Err(Unsyncable::Unreadable));
        assert_eq!(inspect_private_key(&"A".repeat(MAX_PRIVATE_KEY_BYTES + 1)), Err(Unsyncable::TooLarge));
    }

    #[test]
    fn reads_public_key_lines() {
        assert_eq!(
            parse_public_key(&format!("{PLAIN_PUBLIC} sp3-test")),
            Some((PLAIN_PUBLIC.to_string(), PLAIN_FINGERPRINT.to_string()))
        );
        // 類型欄位和 blob 裡寫的不一樣、不是 base64、少欄位。
        let mislabelled = PLAIN_PUBLIC.replacen("ssh-ed25519", "ssh-rsa", 1);
        assert_eq!(parse_public_key(&mislabelled), None);
        assert_eq!(parse_public_key("ssh-ed25519 !!!"), None);
        assert_eq!(parse_public_key("ssh-ed25519"), None);
    }

    #[test]
    fn slot_ids_names_and_paths() {
        assert!(is_slot_id("0123456789abcdef0123456789abcdef"));
        assert!(!is_slot_id("0123456789ABCDEF0123456789abcdef"));
        assert!(!is_slot_id("0123456789abcdef"));
        let (a, b) = (new_slot_id().unwrap(), new_slot_id().unwrap());
        assert!(is_slot_id(&a) && is_slot_id(&b) && a != b);

        for ok in ["id_ed25519", "work", "a", "Key.2026_v-1"] {
            assert!(valid_slot_name(ok), "{ok}");
        }
        let too_long = "a".repeat(65);
        for bad in ["", "-x", ".x", "a b", "a/b", "a\\b", "id.pub", "ID.PUB", too_long.as_str(), "\u{9375}"] {
            assert!(!valid_slot_name(bad), "{bad}");
        }
        assert_eq!(default_slot_name("id_ed25519"), "id_ed25519");
        assert_eq!(default_slot_name("my key"), "my-key");
        assert_eq!(default_slot_name(".hidden"), "hidden");
        assert_eq!(default_slot_name("id_rsa.pub"), "id_rsa");
        assert_eq!(default_slot_name("\u{9375}"), "key");
        assert_eq!(default_slot_name(&"k".repeat(80)), "k".repeat(64));

        let id = "3fa2c1d90123456789abcdef01234567";
        assert_eq!(slot_file_name("id_mac", id), "id_mac-3fa2c1d9");
        assert_eq!(slot_value("id_mac-3fa2c1d9"), "~/.ssh/sshelter/keys/id_mac-3fa2c1d9");
        assert_eq!(public_path(Path::new("/k/id_mac-3fa2c1d9")), PathBuf::from("/k/id_mac-3fa2c1d9.pub"));
    }

    #[test]
    fn recognises_slot_values_in_every_spelling() {
        assert_eq!(slot_file_of_value("~/.ssh/sshelter/keys/id_mac-3fa2c1d9").as_deref(), Some("id_mac-3fa2c1d9"));
        assert_eq!(slot_file_of_value("\"~/.ssh/sshelter/keys/id_mac-3fa2c1d9\"").as_deref(), Some("id_mac-3fa2c1d9"));
        assert_eq!(slot_file_of_value("%d/.ssh/sshelter/keys/x-00000000").as_deref(), Some("x-00000000"));
        assert_eq!(slot_file_of_value("~/.ssh/sshelter/keys/sub/x"), None);
        assert_eq!(slot_file_of_value("~/.ssh/sshelter/keys/"), None);
        assert_eq!(slot_file_of_value("~/.ssh/id_mac"), None);
        assert_eq!(slot_file_of_value("/home/f/.ssh/sshelter/keys/x"), None);
    }

    #[test]
    fn resolves_identity_values_from_either_platform() {
        let home = Path::new("/home/f");
        let file = |p: &str| IdentityTarget::File(PathBuf::from(p));
        assert_eq!(resolve_identity_value("~/.ssh/id_mac", home), file("/home/f/.ssh/id_mac"));
        assert_eq!(resolve_identity_value("\"~/.ssh/id work\"", home), file("/home/f/.ssh/id work"));
        assert_eq!(resolve_identity_value("%d/.ssh/k", home), file("/home/f/.ssh/k"));
        assert_eq!(resolve_identity_value("~\\.ssh\\id_win", home), file("/home/f/.ssh/id_win"));
        assert_eq!(resolve_identity_value("/Users/x/.ssh/k", home), file("/Users/x/.ssh/k"));
        assert_eq!(resolve_identity_value("C:\\Users\\x\\.ssh\\k", home), file("C:\\Users\\x\\.ssh\\k"));
        assert_eq!(resolve_identity_value("~/.ssh/sshelter/keys/a-12345678", home), IdentityTarget::Slot("a-12345678".into()));
        assert_eq!(resolve_identity_value("~/.ssh/id.pub", home), IdentityTarget::Unsupported(REASON_PUBLIC_KEY));
        assert_eq!(resolve_identity_value("~/.ssh/%h", home), IdentityTarget::Unsupported(REASON_TOKENS));
        assert_eq!(resolve_identity_value("${HOME}/.ssh/k", home), IdentityTarget::Unsupported(REASON_TOKENS));
        assert_eq!(resolve_identity_value("id_rsa", home), IdentityTarget::Unsupported(REASON_RELATIVE));
    }

    fn synced_payload() -> KeySlotPayload {
        KeySlotPayload {
            schema: SLOT_SCHEMA,
            name: "id_mac".into(),
            mode: SlotMode::Synced,
            origin_device_id: "a".repeat(32),
            created_at_ms: 5,
            public_key: Some(PLAIN_PUBLIC.into()),
            fingerprint: Some(PLAIN_FINGERPRINT.into()),
            key_type: Some("ssh-ed25519".into()),
            has_passphrase: Some(false),
        }
    }

    #[test]
    fn validates_slot_payloads() {
        assert!(valid_slot_payload(&synced_payload()));
        let own = KeySlotPayload { mode: SlotMode::Own, public_key: None, fingerprint: None, key_type: None, has_passphrase: None, ..synced_payload() };
        assert!(valid_slot_payload(&own));
        // own 不得帶金鑰欄位;synced 的指紋要等於公鑰的指紋;名稱、schema、來源裝置。
        assert!(!valid_slot_payload(&KeySlotPayload { fingerprint: Some(PLAIN_FINGERPRINT.into()), ..own.clone() }));
        assert!(!valid_slot_payload(&KeySlotPayload { fingerprint: Some(ENC_FINGERPRINT.into()), ..synced_payload() }));
        assert!(!valid_slot_payload(&KeySlotPayload { key_type: None, ..synced_payload() }));
        assert!(!valid_slot_payload(&KeySlotPayload { name: "../x".into(), ..synced_payload() }));
        assert!(!valid_slot_payload(&KeySlotPayload { schema: 2, ..synced_payload() }));
        assert!(!valid_slot_payload(&KeySlotPayload { origin_device_id: String::new(), ..synced_payload() }));

        // synced 的 public_key 只能是剛好 `<type> <base64>`:其他電腦會把它原樣寫進 `.pub`,
        // 帳戶裡的惡意成員不得夾帶 comment、第二行或多餘的空白。
        let accepts = |public_key: &str| {
            valid_slot_payload(&KeySlotPayload { public_key: Some(public_key.to_string()), ..synced_payload() })
        };
        assert!(accepts(PLAIN_PUBLIC));
        let wrongly_accepted: Vec<String> = [
            format!("{PLAIN_PUBLIC} me@host"),
            format!("{PLAIN_PUBLIC}\n{ECDSA_PUBLIC}"),
            format!("{PLAIN_PUBLIC}\n"),
            format!(" {PLAIN_PUBLIC}"),
            PLAIN_PUBLIC.replacen(' ', "  ", 1),
        ]
        .into_iter()
        .filter(|public_key| accepts(public_key))
        .collect();
        assert!(wrongly_accepted.is_empty(), "{wrongly_accepted:?}");
        // 帶 `=` 補位的 ecdsa 公鑰照常通過。
        assert!(valid_slot_payload(&KeySlotPayload {
            public_key: Some(ECDSA_PUBLIC.into()),
            fingerprint: Some(ECDSA_FINGERPRINT.into()),
            key_type: Some("ecdsa-sha2-nistp256".into()),
            ..synced_payload()
        }));

        assert!(valid_key_payload(&KeyPayload { schema: SLOT_SCHEMA, private_key: plain() }));
        assert!(!valid_key_payload(&KeyPayload { schema: SLOT_SCHEMA, private_key: String::new() }));
        assert!(!valid_key_payload(&KeyPayload { schema: SLOT_SCHEMA, private_key: "A".repeat(MAX_PRIVATE_KEY_BYTES + 1) }));
    }

    #[test]
    fn key_payload_debug_hides_the_key() {
        let shown = format!("{:?}", KeyPayload { schema: SLOT_SCHEMA, private_key: plain() });
        assert!(!shown.contains(PLAIN_BODY[0]), "{shown}");
        assert!(shown.contains("<redacted>"));
    }

    /// 這三句會原樣顯示在 UI(計畫的 UI 字串表):不能悄悄改字。
    #[test]
    fn unsyncable_reasons_have_the_user_facing_messages() {
        assert_eq!(Unsyncable::TooLarge.message(), "This key is larger than 16 KiB, so it can't be synced. Keep it on this computer.");
        assert_eq!(
            Unsyncable::NotOpenSsh.message(),
            "This key isn't in the OpenSSH format, so it can't be synced. Convert it with ssh-keygen -p -f <file>, or keep it on this computer."
        );
        assert_eq!(Unsyncable::Unreadable.message(), "This file couldn't be read as an OpenSSH private key.");
    }

    /// `in_vault` 只在 true 時寫出:沒放進保管庫的插槽,`device` 記錄和 SP3 寫的一模一樣;SP3 寫的(沒有這個欄位)讀成 false。
    #[test]
    fn a_device_slot_names_the_vault_only_when_the_key_is_in_it() {
        let sp3 = serde_json::json!({ "slot_id": "0".repeat(32), "fingerprint": null, "synced_copy": true });
        let file = DeviceSlot { slot_id: "0".repeat(32), fingerprint: None, synced_copy: true, in_vault: false };
        assert_eq!(serde_json::to_value(&file).unwrap(), sp3);
        assert_eq!(serde_json::from_value::<DeviceSlot>(sp3).unwrap(), file);
        let vault = DeviceSlot { in_vault: true, ..file };
        assert_eq!(serde_json::to_value(&vault).unwrap()["in_vault"], true);
    }
}
