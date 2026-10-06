//! 一條 agent 連線(金鑰保管庫 spec §5.2、§5.3):記住這條連線綁定的主機(session-bind)與是否轉送,把每個簽章請求交給 `SignAuthority` 決定。

use std::io::{self, Read, Write};

use ssh_key::public::KeyData;

use crate::agent::protocol::{
    identities_answer, parse_request, parse_userauth, read_frame, sign_response, write_frame, Request, SSH_AGENT_EXTENSION_FAILURE,
    SSH_AGENT_FAILURE, SSH_AGENT_SUCCESS,
};

/// 交給 `SignAuthority` 的一個簽章請求。`host_key` 只在 userauth 資料的 session id 等於這條連線最後一次 bind 的(hostbound 方法的主機金鑰也相同)
/// 時才有;其他情況主機未知。
pub struct SignRequest {
    pub key: KeyData,
    pub data: Vec<u8>,
    pub flags: u32,
    pub user: Option<String>,
    pub host_key: Option<KeyData>,
    /// 這條連線曾經 bind 過轉送(`is_forwarding`):agent 被轉送到遠端了。
    pub forwarded: bool,
}

/// 決定給哪些金鑰、簽不簽(`agent::broker::Connection`)。
pub trait SignAuthority {
    fn identities(&self) -> Vec<(KeyData, String)>;
    /// 要簽就回傳 signature blob(`string 演算法, string 簽章`),不簽回 None。可能等核准視窗(最多 60 秒)。
    fn sign(&self, request: &SignRequest) -> Option<Vec<u8>>;
}

#[derive(Default)]
pub struct Session {
    bound_host: Option<KeyData>,
    session_id: Option<Vec<u8>>,
    forwarded: bool,
}

impl Session {
    /// 處理一則訊息,回傳回應的內容(不含長度)。
    pub fn handle(&mut self, authority: &dyn SignAuthority, msg: &[u8]) -> Vec<u8> {
        match parse_request(msg) {
            Request::Identities => identities_answer(&authority.identities()),
            Request::Sign { key, data, flags } => {
                let userauth = parse_userauth(&data);
                let host_key = match (&userauth, &self.bound_host, &self.session_id) {
                    (Some(u), Some(host), Some(sid))
                        if &u.session_id == sid && u.hostbound_host_key.as_ref().is_none_or(|h| h == host) =>
                    {
                        Some(host.clone())
                    }
                    _ => None,
                };
                let request = SignRequest { key, data, flags, user: userauth.map(|u| u.user), host_key, forwarded: self.forwarded };
                match authority.sign(&request) {
                    Some(blob) => sign_response(&blob),
                    None => vec![SSH_AGENT_FAILURE],
                }
            }
            Request::SessionBind { host_key, session_id, signature, forwarding } => {
                use signature::Verifier;
                if host_key.verify(&session_id, &signature).is_err() {
                    return vec![SSH_AGENT_EXTENSION_FAILURE];
                }
                self.bound_host = Some(host_key);
                self.session_id = Some(session_id);
                self.forwarded |= forwarding;
                vec![SSH_AGENT_SUCCESS]
            }
            Request::Extension(_) | Request::Unsupported => vec![SSH_AGENT_FAILURE],
        }
    }
}

/// 處理一條連線直到對方關閉;訊框不對就斷線(回 Err)。
pub fn serve(stream: &mut (impl Read + Write), authority: &dyn SignAuthority) -> io::Result<()> {
    let mut session = Session::default();
    while let Some(msg) = read_frame(stream)? {
        let reply = session.handle(authority, &msg);
        write_frame(stream, &reply)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::protocol::*;
    use crate::sync::slot_rules::test_keys;
    use crate::vault::material::{open, public_key_data};
    use ssh_encoding::{Decode, Encode};
    use std::sync::Mutex;

    struct Fake {
        keys: Vec<(KeyData, String)>,
        seen: Mutex<Vec<SignRequestSummary>>,
        answer: Option<Vec<u8>>,
    }

    #[derive(Clone, Debug, PartialEq)]
    struct SignRequestSummary {
        user: Option<String>,
        host: Option<KeyData>,
        forwarded: bool,
        flags: u32,
    }

    impl SignAuthority for Fake {
        fn identities(&self) -> Vec<(KeyData, String)> {
            self.keys.clone()
        }
        fn sign(&self, r: &SignRequest) -> Option<Vec<u8>> {
            self.seen.lock().unwrap().push(SignRequestSummary { user: r.user.clone(), host: r.host_key.clone(), forwarded: r.forwarded, flags: r.flags });
            self.answer.clone()
        }
    }

    fn fake() -> Fake {
        Fake { keys: vec![(public_key_data(test_keys::PLAIN_PUBLIC).unwrap(), "id_mac".into())], seen: Mutex::new(vec![]), answer: Some(b"sig".to_vec()) }
    }

    fn sign_request(key: &KeyData, data: &[u8], flags: u32) -> Vec<u8> {
        let mut msg = vec![SSH_AGENTC_SIGN_REQUEST];
        key.encode_prefixed(&mut msg).unwrap();
        data.encode(&mut msg).unwrap();
        flags.encode(&mut msg).unwrap();
        msg
    }

    fn userauth(session_id: &[u8], user: &str, key: &KeyData, hostbound: Option<&KeyData>) -> Vec<u8> {
        let mut d = Vec::new();
        session_id.encode(&mut d).unwrap();
        50u8.encode(&mut d).unwrap();
        user.encode(&mut d).unwrap();
        "ssh-connection".encode(&mut d).unwrap();
        (if hostbound.is_some() { "publickey-hostbound-v00@openssh.com" } else { "publickey" }).encode(&mut d).unwrap();
        1u8.encode(&mut d).unwrap();
        "ssh-ed25519".encode(&mut d).unwrap();
        key.encode_prefixed(&mut d).unwrap();
        if let Some(host) = hostbound {
            host.encode_prefixed(&mut d).unwrap();
        }
        d
    }

    /// A session-bind signed by the ECDSA test key acting as the server's host key.
    fn bind(session_id: &[u8], forwarding: bool, tamper: bool) -> (Vec<u8>, KeyData) {
        let host = open(&test_keys::ecdsa(), None).unwrap();
        let mut signed = session_id.to_vec();
        if tamper {
            signed.push(0);
        }
        let blob = host.sign(&signed, 0).unwrap();
        let signature = ssh_key::Signature::decode(&mut &blob[..]).unwrap();
        let mut msg = vec![SSH_AGENTC_EXTENSION];
        SESSION_BIND.encode(&mut msg).unwrap();
        host.key_data().encode_prefixed(&mut msg).unwrap();
        session_id.encode(&mut msg).unwrap();
        signature.encode_prefixed(&mut msg).unwrap();
        (forwarding as u8).encode(&mut msg).unwrap();
        (msg, host.key_data())
    }

    #[test]
    fn identities_are_listed() {
        let mut s = Session::default();
        let reply = s.handle(&fake(), &[SSH_AGENTC_REQUEST_IDENTITIES]);
        assert_eq!(reply[0], SSH_AGENT_IDENTITIES_ANSWER);
        let mut r = &reply[1..];
        assert_eq!(u32::decode(&mut r).unwrap(), 1);
    }

    #[test]
    fn a_bound_session_names_the_host_and_the_user() {
        let authority = fake();
        let mut s = Session::default();
        let (bind_msg, host) = bind(b"session-1", false, false);
        assert_eq!(s.handle(&authority, &bind_msg), vec![SSH_AGENT_SUCCESS]);
        let key = public_key_data(test_keys::PLAIN_PUBLIC).unwrap();
        let reply = s.handle(&authority, &sign_request(&key, &userauth(b"session-1", "root", &key, Some(&host)), 4));
        assert_eq!(reply[0], SSH_AGENT_SIGN_RESPONSE);
        let seen = authority.seen.lock().unwrap()[0].clone();
        assert_eq!(seen, SignRequestSummary { user: Some("root".into()), host: Some(host), forwarded: false, flags: 4 });
    }

    #[test]
    fn a_session_id_or_host_key_that_does_not_match_the_bind_leaves_the_host_unknown() {
        let authority = fake();
        let mut s = Session::default();
        let (bind_msg, host) = bind(b"session-1", false, false);
        s.handle(&authority, &bind_msg);
        let key = public_key_data(test_keys::PLAIN_PUBLIC).unwrap();
        s.handle(&authority, &sign_request(&key, &userauth(b"other-session", "root", &key, None), 0));
        let other_host = public_key_data(test_keys::PLAIN_PUBLIC).unwrap();
        s.handle(&authority, &sign_request(&key, &userauth(b"session-1", "root", &key, Some(&other_host)), 0));
        let seen = authority.seen.lock().unwrap().clone();
        assert_eq!(seen[0].host, None);
        assert_eq!(seen[1].host, None);
        let _ = host;
    }

    #[test]
    fn a_bad_bind_signature_is_an_extension_failure_and_is_not_kept() {
        let authority = fake();
        let mut s = Session::default();
        let (bind_msg, _) = bind(b"session-1", false, true);
        assert_eq!(s.handle(&authority, &bind_msg), vec![SSH_AGENT_EXTENSION_FAILURE]);
        let key = public_key_data(test_keys::PLAIN_PUBLIC).unwrap();
        s.handle(&authority, &sign_request(&key, &userauth(b"session-1", "root", &key, None), 0));
        assert_eq!(authority.seen.lock().unwrap()[0].host, None);
    }

    #[test]
    fn a_forwarded_bind_marks_the_rest_of_the_connection() {
        let authority = fake();
        let mut s = Session::default();
        s.handle(&authority, &bind(b"hop-1", true, false).0);
        s.handle(&authority, &bind(b"hop-2", false, false).0);
        let key = public_key_data(test_keys::PLAIN_PUBLIC).unwrap();
        s.handle(&authority, &sign_request(&key, &userauth(b"hop-2", "root", &key, None), 0));
        assert!(authority.seen.lock().unwrap()[0].forwarded);
    }

    #[test]
    fn unsupported_requests_fail_and_a_refusal_is_a_failure() {
        let mut authority = fake();
        let mut s = Session::default();
        assert_eq!(s.handle(&authority, &[99]), vec![SSH_AGENT_FAILURE], "unknown type");
        assert_eq!(s.handle(&authority, &[17, 1, 2, 3]), vec![SSH_AGENT_FAILURE], "add identity is refused");
        assert_eq!(s.handle(&authority, &[22]), vec![SSH_AGENT_FAILURE], "lock is refused");
        let mut other = vec![SSH_AGENTC_EXTENSION];
        "query".encode(&mut other).unwrap();
        assert_eq!(s.handle(&authority, &other), vec![SSH_AGENT_FAILURE], "other extensions");
        authority.answer = None;
        let key = public_key_data(test_keys::PLAIN_PUBLIC).unwrap();
        assert_eq!(s.handle(&authority, &sign_request(&key, b"x", 0)), vec![SSH_AGENT_FAILURE], "refused");
    }

    /// An in-memory duplex for `serve`.
    struct Duplex {
        input: std::io::Cursor<Vec<u8>>,
        output: Vec<u8>,
    }
    impl std::io::Read for Duplex {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.input.read(buf)
        }
    }
    impl std::io::Write for Duplex {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.output.write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn frame(body: &[u8]) -> Vec<u8> {
        let mut out = (body.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn serve_answers_every_frame_and_keeps_going_after_an_unknown_one() {
        let mut input = frame(&[99]);
        input.extend(frame(&[SSH_AGENTC_REQUEST_IDENTITIES]));
        let mut d = Duplex { input: std::io::Cursor::new(input), output: vec![] };
        serve(&mut d, &fake()).unwrap();
        let mut r = &d.output[..];
        assert_eq!(read_frame(&mut r).unwrap().unwrap(), vec![SSH_AGENT_FAILURE]);
        assert_eq!(read_frame(&mut r).unwrap().unwrap()[0], SSH_AGENT_IDENTITIES_ANSWER);
    }

    #[test]
    fn an_oversized_or_empty_frame_closes_the_connection() {
        let mut d = Duplex { input: std::io::Cursor::new(((MAX_MESSAGE + 1) as u32).to_be_bytes().to_vec()), output: vec![] };
        assert!(serve(&mut d, &fake()).is_err());
        let mut d = Duplex { input: std::io::Cursor::new(0u32.to_be_bytes().to_vec()), output: vec![] };
        assert!(serve(&mut d, &fake()).is_err());
    }
}
