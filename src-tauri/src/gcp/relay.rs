//! The SSH Relay v4 wire format as Google's IAP TCP-forwarding relay speaks it, without any I/O: the connect and reconnect URLs, the four
//! frame kinds, and the bookkeeping of what was received, acknowledged, sent and confirmed. Ported from gcloud's
//! `iap_tunnel_websocket_utils.py` and the `_ConfirmData`/`_MaybeSendAck` logic of `iap_tunnel_websocket.py` (Apache License 2.0, see
//! `NOTICE.md`); the numbers below are gcloud's.

use std::collections::VecDeque;
use std::fmt;

/// The WebSocket subprotocol the relay requires (`Sec-WebSocket-Protocol`).
pub const SUBPROTOCOL: &str = "relay.tunnel.cloudproxy.app";
/// The `Origin` header gcloud sends; the relay refuses a browser-looking origin.
pub const ORIGIN: &str = "bot:iap-tunneler";
/// Scheme, host and path root of Google's relay; tests point `Endpoint::url_root` at a fake one.
pub const DEFAULT_URL_ROOT: &str = "wss://tunnel.cloudproxy.app/v4";
/// The most payload a client puts in one DATA frame.
pub const MAX_DATA_FRAME: usize = 16384;
/// An ACK is owed once this many received bytes are unacknowledged (gcloud waits for twice the frame size "to avoid wasting CPU cycles
/// on both ends").
pub const ACK_THRESHOLD: u64 = 2 * MAX_DATA_FRAME as u64;
/// How many frames may wait to be sent while the WebSocket is down or slow; past that the writer is held back.
pub const MAX_UNSENT_FRAMES: usize = 5;
/// A frame whose length prefix claims more than this is refused before anything is allocated. A server may legitimately send more than
/// `MAX_DATA_FRAME` (gcloud takes whatever arrives); a length in the gigabytes is a broken or hostile peer.
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;

const TAG_CONNECT_SUCCESS_SID: u16 = 0x0001;
const TAG_RECONNECT_SUCCESS_ACK: u16 = 0x0002;
const TAG_DATA: u16 = 0x0004;
const TAG_ACK: u16 = 0x0007;

/// Where a tunnel goes: one port of one network interface of one GCE instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub project: String,
    pub zone: String,
    pub instance: String,
    /// `nic0` for the first interface.
    pub interface: String,
    pub port: u16,
    /// Replaces `DEFAULT_URL_ROOT` (scheme, host and path root), the way gcloud's `--iap-tunnel-url-override` does. Tests only.
    pub url_root: Option<String>,
}

impl Endpoint {
    /// `…/connect?project=…&port=…&newWebsocket=True&zone=…&instance=…&interface=…`, the parameters in gcloud's order.
    pub fn connect_url(&self) -> String {
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("project", &self.project)
            .append_pair("port", &self.port.to_string())
            .append_pair("newWebsocket", "True")
            .append_pair("zone", &self.zone)
            .append_pair("instance", &self.instance)
            .append_pair("interface", &self.interface)
            .finish();
        self.url("connect", &query)
    }

    /// `…/reconnect?sid=…&ack=…&newWebsocket=True&zone=…`: `sid` is the session id the relay gave at connect time (opaque bytes, form-encoded
    /// as gcloud's `urlencode` does), `ack` the bytes received from the relay so far.
    pub fn reconnect_url(&self, sid: &[u8], ack: u64) -> String {
        let sid: String = url::form_urlencoded::byte_serialize(sid).collect();
        let rest = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("ack", &ack.to_string())
            .append_pair("newWebsocket", "True")
            .append_pair("zone", &self.zone)
            .finish();
        self.url("reconnect", &format!("sid={sid}&{rest}"))
    }

    fn url(&self, action: &str, query: &str) -> String {
        let root = self.url_root.as_deref().unwrap_or(DEFAULT_URL_ROOT);
        let (base, path_root) = split_root(root);
        format!("{base}{path_root}/{action}?{query}")
    }
}

/// Scheme and host of a URL root, and its path root (`/v4` when the override has none, as gcloud's `_CreateWebSocketUrl` does).
fn split_root(root: &str) -> (String, String) {
    match url::Url::parse(root) {
        Ok(parsed) if parsed.host_str().is_some() => {
            let mut base = format!("{}://{}", parsed.scheme(), parsed.host_str().unwrap_or_default());
            if let Some(port) = parsed.port() {
                base.push_str(&format!(":{port}"));
            }
            let path = parsed.path().trim_end_matches('/');
            let path_root = if path.is_empty() { "/v4".to_string() } else { path.to_string() };
            (base, path_root)
        }
        _ => (root.trim_end_matches('/').to_string(), String::new()),
    }
}

/// One message from the relay. The relay may add tags; those decode as `Unknown` and are ignored, as the protocol asks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    /// The first message of a `connect` session: its id, for a later `reconnect`.
    ConnectSuccess { sid: Vec<u8> },
    /// The first message of a `reconnect` session: how many of our bytes the relay had received.
    ReconnectSuccess { ack: u64 },
    Data(Vec<u8>),
    /// How many of our bytes the relay has received in all.
    Ack(u64),
    Unknown(u16),
}

/// What is wrong with a frame or with the relay's acknowledgements. Every variant ends the tunnel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelayError {
    /// The frame ends before its header or its announced length.
    Incomplete,
    /// The length prefix is over `MAX_FRAME_BYTES`.
    Oversized(usize),
    /// An ACK below what was already confirmed.
    OutOfOrderAck { ack: u64, confirmed: u64 },
    /// An ACK beyond what was sent.
    AckBeyondSent { ack: u64, sent: u64 },
}

impl fmt::Display for RelayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RelayError::Incomplete => f.write_str("The relay sent a cut frame."),
            RelayError::Oversized(length) => write!(f, "The relay announced a frame of {length} bytes, over the {MAX_FRAME_BYTES}-byte cap."),
            RelayError::OutOfOrderAck { ack, confirmed } => write!(f, "The relay acknowledged {ack} bytes after {confirmed} were already confirmed."),
            RelayError::AckBeyondSent { ack, sent } => write!(f, "The relay acknowledged {ack} bytes but only {sent} were sent."),
        }
    }
}

impl std::error::Error for RelayError {}

/// A DATA frame: `u16 tag || u32 length || bytes`, big-endian. Callers cut their data into pieces of at most `MAX_DATA_FRAME`.
pub fn encode_data(payload: &[u8]) -> Vec<u8> {
    debug_assert!(payload.len() <= MAX_DATA_FRAME, "a DATA frame carries at most {MAX_DATA_FRAME} bytes");
    let mut frame = Vec::with_capacity(6 + payload.len());
    frame.extend(TAG_DATA.to_be_bytes());
    frame.extend((payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// An ACK frame: `u16 tag || u64 bytes received`, big-endian.
pub fn encode_ack(ack: u64) -> Vec<u8> {
    let mut frame = Vec::with_capacity(10);
    frame.extend(TAG_ACK.to_be_bytes());
    frame.extend(ack.to_be_bytes());
    frame
}

/// Reads one frame. Bytes after a complete frame are ignored, as gcloud ignores them.
pub fn decode(frame: &[u8]) -> Result<Frame, RelayError> {
    let tag = u16::from_be_bytes(fixed::<2>(frame)?);
    let rest = &frame[2..];
    match tag {
        TAG_CONNECT_SUCCESS_SID => array(rest).map(|sid| Frame::ConnectSuccess { sid }),
        TAG_RECONNECT_SUCCESS_ACK => fixed::<8>(rest).map(|bytes| Frame::ReconnectSuccess { ack: u64::from_be_bytes(bytes) }),
        TAG_DATA => array(rest).map(Frame::Data),
        TAG_ACK => fixed::<8>(rest).map(|bytes| Frame::Ack(u64::from_be_bytes(bytes))),
        other => Ok(Frame::Unknown(other)),
    }
}

fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], RelayError> {
    bytes.get(..N).and_then(|head| head.try_into().ok()).ok_or(RelayError::Incomplete)
}

/// A length-prefixed byte array, refused before allocation when the prefix is over the cap.
fn array(bytes: &[u8]) -> Result<Vec<u8>, RelayError> {
    let length = u32::from_be_bytes(fixed::<4>(bytes)?) as usize;
    if length > MAX_FRAME_BYTES {
        return Err(RelayError::Oversized(length));
    }
    bytes.get(4..4 + length).map(<[u8]>::to_vec).ok_or(RelayError::Incomplete)
}

/// The counters of one tunnel session, kept across reconnects: what the relay sent us (and how much of it we acknowledged), and what we
/// sent the relay (and how much of it the relay confirmed). Our unconfirmed frames stay here until an ACK covers them, so that a
/// reconnect can send again what the relay never got.
#[derive(Debug, Default)]
pub struct Bookkeeping {
    received: u64,
    acked: u64,
    sent: u64,
    confirmed: u64,
    unconfirmed: VecDeque<Vec<u8>>,
}

impl Bookkeeping {
    /// A DATA frame of `len` bytes arrived from the relay.
    pub fn note_received(&mut self, len: usize) {
        self.received += len as u64;
    }

    /// `Some(total received)` when enough has arrived unacknowledged that an ACK should go out now.
    pub fn ack_due(&self) -> Option<u64> {
        (self.received - self.acked > ACK_THRESHOLD).then_some(self.received)
    }

    /// An ACK for `total` received bytes was sent.
    pub fn mark_acked(&mut self, total: u64) {
        self.acked = self.acked.max(total);
    }

    /// `payload` was sent to the relay in one DATA frame, for the first time.
    pub fn note_sent(&mut self, payload: Vec<u8>) {
        self.sent += payload.len() as u64;
        self.unconfirmed.push_back(payload);
    }

    /// `payload`, taken from `take_unconfirmed` after a reconnect, was sent again: it waits for its confirmation as before and is not
    /// counted as new bytes.
    pub fn requeue(&mut self, payload: Vec<u8>) {
        self.unconfirmed.push_back(payload);
    }

    /// The relay has received `ack` of our bytes in all: whole frames up to there are dropped, a frame the ack ends inside is cut.
    pub fn confirm(&mut self, ack: u64) -> Result<(), RelayError> {
        if ack < self.confirmed {
            return Err(RelayError::OutOfOrderAck { ack, confirmed: self.confirmed });
        }
        if ack > self.sent {
            return Err(RelayError::AckBeyondSent { ack, sent: self.sent });
        }
        let mut remaining = ack - self.confirmed;
        while remaining > 0 {
            let Some(mut chunk) = self.unconfirmed.pop_front() else { break };
            let length = chunk.len() as u64;
            if length > remaining {
                let rest = chunk.split_off(remaining as usize);
                self.unconfirmed.push_front(rest);
                self.confirmed += remaining;
                remaining = 0;
            } else {
                self.confirmed += length;
                remaining -= length;
            }
        }
        Ok(())
    }

    /// The frames the relay has not confirmed, oldest first, to send again after a reconnect (`requeue` each as it goes out). Leaves the
    /// queue empty.
    pub fn take_unconfirmed(&mut self) -> Vec<Vec<u8>> {
        self.unconfirmed.drain(..).collect()
    }

    pub fn total_received(&self) -> u64 {
        self.received
    }

    pub fn total_confirmed(&self) -> u64 {
        self.confirmed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint() -> Endpoint {
        Endpoint {
            project: "eng-dev-396409".into(),
            zone: "asia-east1-b".into(),
            instance: "jumpbox".into(),
            interface: "nic0".into(),
            port: 22,
            url_root: None,
        }
    }

    #[test]
    fn a_data_frame_is_tag_4_length_and_bytes() {
        assert_eq!(encode_data(b"hi"), [0, 4, 0, 0, 0, 2, b'h', b'i']);
    }

    #[test]
    fn an_ack_frame_is_tag_7_and_a_big_endian_u64() {
        assert_eq!(encode_ack(0x0102030405060708), [0, 7, 1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn every_frame_kind_decodes_and_trailing_bytes_are_ignored() {
        assert_eq!(decode(&[0, 1, 0, 0, 0, 3, b'a', b'b', b'c', 9, 9]), Ok(Frame::ConnectSuccess { sid: b"abc".to_vec() }));
        assert_eq!(decode(&[0, 2, 0, 0, 0, 0, 0, 0, 0, 5]), Ok(Frame::ReconnectSuccess { ack: 5 }));
        assert_eq!(decode(&[0, 4, 0, 0, 0, 2, 7, 8, 1]), Ok(Frame::Data(vec![7, 8])));
        assert_eq!(decode(&[0, 7, 0, 0, 0, 0, 0, 1, 0, 0]), Ok(Frame::Ack(65536)));
        assert_eq!(decode(&[0, 9]), Ok(Frame::Unknown(9)));
        // A server may send more than a client's frame size; gcloud takes it, and so does the port (within the cap).
        let mut big = vec![0, 4, 0, 0, 0x4e, 0x20];
        big.extend(std::iter::repeat(1u8).take(20000));
        assert_eq!(decode(&big), Ok(Frame::Data(vec![1; 20000])));
    }

    #[test]
    fn a_cut_frame_is_incomplete() {
        assert_eq!(decode(&[0, 4, 0, 0, 0, 5, 1, 2]), Err(RelayError::Incomplete));
        assert_eq!(decode(&[0]), Err(RelayError::Incomplete));
        assert_eq!(decode(&[0, 7, 1, 2]), Err(RelayError::Incomplete));
        assert_eq!(decode(&[0, 1, 0, 0]), Err(RelayError::Incomplete));
    }

    #[test]
    fn a_frame_longer_than_the_cap_is_a_protocol_error() {
        assert_eq!(decode(&[0, 4, 0xff, 0xff, 0xff, 0xff]), Err(RelayError::Oversized(4294967295)));
        let length = (MAX_FRAME_BYTES + 1) as u32;
        let mut frame = vec![0, 1];
        frame.extend(length.to_be_bytes());
        frame.extend(std::iter::repeat(0u8).take(MAX_FRAME_BYTES + 1));
        assert_eq!(decode(&frame), Err(RelayError::Oversized(MAX_FRAME_BYTES + 1)));
    }

    #[test]
    fn connect_and_reconnect_urls_match_gcloud() {
        let endpoint = endpoint();
        assert_eq!(
            endpoint.connect_url(),
            "wss://tunnel.cloudproxy.app/v4/connect?project=eng-dev-396409&port=22&newWebsocket=True&zone=asia-east1-b&instance=jumpbox&interface=nic0"
        );
        assert_eq!(
            endpoint.reconnect_url(b"s id/1", 70000),
            "wss://tunnel.cloudproxy.app/v4/reconnect?sid=s+id%2F1&ack=70000&newWebsocket=True&zone=asia-east1-b"
        );
    }

    #[test]
    fn a_url_root_override_replaces_scheme_host_and_path() {
        let overridden = Endpoint { url_root: Some("ws://127.0.0.1:4321/v4".into()), ..endpoint() };
        assert_eq!(
            overridden.connect_url(),
            "ws://127.0.0.1:4321/v4/connect?project=eng-dev-396409&port=22&newWebsocket=True&zone=asia-east1-b&instance=jumpbox&interface=nic0"
        );
        assert!(overridden.reconnect_url(b"x", 1).starts_with("ws://127.0.0.1:4321/v4/reconnect?sid=x&ack=1&"));
        let bare = Endpoint { url_root: Some("ws://relay.test".into()), ..endpoint() };
        assert!(bare.connect_url().starts_with("ws://relay.test/v4/connect?"), "{}", bare.connect_url());
    }

    #[test]
    fn an_ack_is_owed_only_past_twice_the_frame_size() {
        let mut books = Bookkeeping::default();
        books.note_received(32768);
        assert_eq!(books.ack_due(), None);
        books.note_received(1);
        assert_eq!(books.ack_due(), Some(32769));
        assert_eq!(books.total_received(), 32769);
        books.mark_acked(32769);
        assert_eq!(books.ack_due(), None);
    }

    #[test]
    fn confirming_drops_whole_chunks_and_splits_a_partial_one() {
        let mut books = Bookkeeping::default();
        books.note_sent(vec![1; 10]);
        books.note_sent(vec![2; 10]);
        assert_eq!(books.confirm(15), Ok(()));
        assert_eq!(books.total_confirmed(), 15);
        let unconfirmed = books.take_unconfirmed();
        assert_eq!(unconfirmed, vec![vec![2; 5]]);
        assert_eq!(books.take_unconfirmed(), Vec::<Vec<u8>>::new(), "taking the queue empties it");
        assert_eq!(books.confirm(15), Ok(()), "the same ack again confirms nothing and is fine");
        // Sent again after a reconnect: the same bytes wait again, and the total sent does not grow.
        for chunk in unconfirmed {
            books.requeue(chunk);
        }
        assert_eq!(books.confirm(20), Ok(()));
        assert_eq!(books.total_confirmed(), 20);
        assert_eq!(books.confirm(21), Err(RelayError::AckBeyondSent { ack: 21, sent: 20 }));
    }

    #[test]
    fn a_backwards_or_oversized_ack_is_an_error() {
        let mut books = Bookkeeping::default();
        books.note_sent(vec![0; 10]);
        assert_eq!(books.confirm(5), Ok(()));
        assert_eq!(books.confirm(3), Err(RelayError::OutOfOrderAck { ack: 3, confirmed: 5 }));
        assert_eq!(books.confirm(100), Err(RelayError::AckBeyondSent { ack: 100, sent: 10 }));
    }

    #[test]
    fn the_constants_are_gclouds() {
        assert_eq!((SUBPROTOCOL, ORIGIN), ("relay.tunnel.cloudproxy.app", "bot:iap-tunneler"));
        assert_eq!(DEFAULT_URL_ROOT, "wss://tunnel.cloudproxy.app/v4");
        assert_eq!((MAX_DATA_FRAME, ACK_THRESHOLD, MAX_UNSENT_FRAMES), (16384, 32768, 5));
        assert!(RelayError::Incomplete.to_string().ends_with('.'), "errors are sentences");
    }
}
