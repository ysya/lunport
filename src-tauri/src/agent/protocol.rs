//! agent 協定的訊框與訊息(RFC 9987,加上 OpenSSH 的 `session-bind@openssh.com`;金鑰保管庫 spec §5.2)。只用 `ssh-encoding` 0.2 與 `ssh-key` 0.6.7,
//! 不用 `ssh-agent-lib`(spec §15:它遇到未知訊息會斷線、沒有長度上限、回不了 SHA-1 RSA 簽章)。

use std::io::{self, Read, Write};

use ssh_encoding::{Decode, Encode, Reader};
use ssh_key::public::KeyData;
use ssh_key::Signature;

/// 同 OpenSSH 的 `AGENT_MAX_LEN`。
pub const MAX_MESSAGE: usize = 256 * 1024;
pub const SSH_AGENT_FAILURE: u8 = 5;
pub const SSH_AGENT_SUCCESS: u8 = 6;
pub const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
pub const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
pub const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
pub const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
pub const SSH_AGENTC_EXTENSION: u8 = 27;
pub const SSH_AGENT_EXTENSION_FAILURE: u8 = 28;
pub const SESSION_BIND: &str = "session-bind@openssh.com";

/// 讀一個訊框(`uint32` 長度 + 內容)。對方關閉 → `Ok(None)`。長度 0 或超過上限 → `Err`(呼叫端關閉連線)。
pub fn read_frame(r: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > MAX_MESSAGE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("bad agent frame length {len}")));
    }
    let mut msg = vec![0u8; len];
    r.read_exact(&mut msg)?;
    Ok(Some(msg))
}

/// 寫一個訊框(`uint32` 長度 + 內容)並 flush。
pub fn write_frame(w: &mut impl Write, body: &[u8]) -> io::Result<()> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    w.write_all(&out)?;
    w.flush()
}

/// agent 收到的請求。
#[derive(Debug)]
pub enum Request {
    Identities,
    Sign { key: KeyData, data: Vec<u8>, flags: u32 },
    SessionBind { host_key: KeyData, session_id: Vec<u8>, signature: Signature, forwarding: bool },
    /// session-bind 以外的擴充(名稱)。
    Extension(String),
    /// 不支援的種類,或讀不懂的內容。
    Unsupported,
}

/// 讀一個帶長度的欄位(`string`)並解成 `T`,內容必須剛好用完:`Reader::read_prefixed` 自己不檢查,沒讀完的位元組會被當成下一個欄位。
fn read_prefixed_exact<T: Decode<Error = ssh_key::Error>>(r: &mut impl Reader) -> ssh_key::Result<T> {
    r.read_prefixed(|nested| {
        let value = T::decode(nested)?;
        if nested.is_finished() {
            Ok(value)
        } else {
            Err(ssh_encoding::Error::TrailingData { remaining: nested.remaining_len() }.into())
        }
    })
}

/// 解析一則 agent 訊息(不含長度);讀不懂的內容(包括多出來的資料)一律是 `Unsupported`。
pub fn parse_request(msg: &[u8]) -> Request {
    let Some((&kind, mut body)) = msg.split_first() else { return Request::Unsupported };
    // `KeyData::decode` 與 `Signature::decode` 的錯誤是 `ssh_key::Error`(它收得下 `ssh_encoding::Error`,反過來不行),所以用 `ssh_key::Result`。
    let parsed = (|| -> ssh_key::Result<Request> {
        Ok(match kind {
            SSH_AGENTC_REQUEST_IDENTITIES => body.finish(Request::Identities)?,
            SSH_AGENTC_SIGN_REQUEST => {
                let key = read_prefixed_exact::<KeyData>(&mut body)?;
                let data = Vec::<u8>::decode(&mut body)?;
                let flags = u32::decode(&mut body)?;
                body.finish(Request::Sign { key, data, flags })?
            }
            SSH_AGENTC_EXTENSION => {
                let name = String::decode(&mut body)?;
                if name != SESSION_BIND {
                    return Ok(Request::Extension(name));
                }
                let host_key = read_prefixed_exact::<KeyData>(&mut body)?;
                let session_id = Vec::<u8>::decode(&mut body)?;
                let signature = read_prefixed_exact::<Signature>(&mut body)?;
                let forwarding = u8::decode(&mut body)? != 0;
                body.finish(Request::SessionBind { host_key, session_id, signature, forwarding })?
            }
            _ => Request::Unsupported,
        })
    })();
    parsed.unwrap_or(Request::Unsupported)
}

/// `SSH_AGENT_IDENTITIES_ANSWER` 的內容:金鑰數量,接著每把金鑰的公鑰與註解。
pub fn identities_answer(keys: &[(KeyData, String)]) -> Vec<u8> {
    let mut out = vec![SSH_AGENT_IDENTITIES_ANSWER];
    // 寫進 Vec 不會失敗。
    (keys.len() as u32).encode(&mut out).expect("writing to a Vec");
    for (key, comment) in keys {
        key.encode_prefixed(&mut out).expect("writing to a Vec");
        comment.encode(&mut out).expect("writing to a Vec");
    }
    out
}

/// `SSH_AGENT_SIGN_RESPONSE` 的內容:signature blob 包成一個 `string`。
pub fn sign_response(signature_blob: &[u8]) -> Vec<u8> {
    let mut out = vec![SSH_AGENT_SIGN_RESPONSE];
    signature_blob.encode(&mut out).expect("writing to a Vec");
    out
}

/// 被簽的 userauth 資料(RFC 4252 §7;OpenSSH 的 `publickey-hostbound-v00@openssh.com` 在公鑰之後多一個主機金鑰)。
#[derive(Debug)]
pub struct Userauth {
    pub session_id: Vec<u8>,
    pub user: String,
    pub key: KeyData,
    pub hostbound_host_key: Option<KeyData>,
}

/// 不是對 `ssh-connection` 服務的 userauth(例如 `ssh-keygen -Y sign` 的 SSHSIG)或讀不懂 → None。多出來的資料一律拒絕(同 OpenSSH 的 agent),
/// 帶長度的欄位也必須剛好讀完。
pub fn parse_userauth(data: &[u8]) -> Option<Userauth> {
    let mut r = data;
    let parsed = (|| -> ssh_key::Result<Option<Userauth>> {
        let session_id = Vec::<u8>::decode(&mut r)?;
        if u8::decode(&mut r)? != 50 {
            return Ok(None);
        }
        let user = String::decode(&mut r)?;
        let service = String::decode(&mut r)?;
        if service != "ssh-connection" {
            return Ok(None);
        }
        let method = String::decode(&mut r)?;
        let hostbound = match method.as_str() {
            "publickey" => false,
            "publickey-hostbound-v00@openssh.com" => true,
            _ => return Ok(None),
        };
        if u8::decode(&mut r)? != 1 {
            return Ok(None);
        }
        let _algorithm = String::decode(&mut r)?;
        let key = read_prefixed_exact::<KeyData>(&mut r)?;
        let hostbound_host_key = if hostbound { Some(read_prefixed_exact::<KeyData>(&mut r)?) } else { None };
        Ok(r.finish(Some(Userauth { session_id, user, key, hostbound_host_key }))?)
    })();
    parsed.ok().flatten()
}
