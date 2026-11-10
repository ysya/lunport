//! The start-up phase of the PostgreSQL wire protocol, which the local port of a database speaks twice: in plain text with the app that
//! connects to it (DataGrip, psql) and over TLS with Cloud SQL, to which the app's start-up message is passed on rewritten.
//!
//! The first message of a connection has no type byte: its length (which counts itself), then a request code or a protocol version. Every
//! later message has a type byte, a length (which counts itself and not the type byte) and a body. This module reads and writes the few
//! messages a start-up needs and follows the server's stream far enough to tell when a session is idle. It never reads a byte more than the
//! message it was asked for, so whatever follows is left in the stream for the caller to copy.

use std::io;

use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt};
use zeroize::Zeroizing;

/// The code of an SSLRequest, with which an app asks to encrypt the connection.
pub const SSL_REQUEST: u32 = 80877103;
/// The code of a GSSENCRequest, with which an app asks for GSSAPI encryption.
pub const GSSENC_REQUEST: u32 = 80877104;
/// The code of a CancelRequest, which an app sends on a connection of its own to cancel what another connection runs.
pub const CANCEL_REQUEST: u32 = 80877102;
/// Protocol version 3.0: the major version, 3, in the high 16 bits and the minor version, 0, in the low ones.
pub const PROTOCOL_3: u32 = 196608;
/// The most bytes a start-up message may have, its length included.
pub const MAX_STARTUP_BYTES: usize = 10_240;
/// The most bytes a password may have, its terminating zero byte not counted.
pub const MAX_PASSWORD_BYTES: usize = 1_024;
/// The switch that makes a Cloud SQL for PostgreSQL session read-only for good: the session cannot undo it.
pub const READ_ONLY_OPTION: &str = "-c cloudsql_session_read_only=locked";

/// The setting `READ_ONLY_OPTION` sets.
const READ_ONLY_SETTING: &str = "cloudsql_session_read_only";
/// A CancelRequest is its length, its code, the process id of the session and a secret key of 4 to 256 bytes.
const MIN_CANCEL_BYTES: usize = 16;
const MAX_CANCEL_BYTES: usize = 12 + 256;
/// The most bytes one message of the server's first answer may have, its length included. They are authentication requests and the
/// errors that refuse a connection, which are short.
const MAX_SERVER_MESSAGE_BYTES: usize = 65_536;

// The types of the messages after the first one.
const AUTHENTICATION: u8 = b'R';
const ERROR_RESPONSE: u8 = b'E';
const NEGOTIATE_PROTOCOL_VERSION: u8 = b'v';
const PASSWORD_MESSAGE: u8 = b'p';
const READY_FOR_QUERY: u8 = b'Z';
// What the server can send to a session that is idle.
const NOTICE_RESPONSE: u8 = b'N';
const PARAMETER_STATUS: u8 = b'S';
const NOTIFICATION_RESPONSE: u8 = b'A';

// The codes of the authentication messages the start-up tells apart.
const AUTH_OK: u32 = 0;
const AUTH_CLEARTEXT_PASSWORD: u32 = 3;
const AUTH_MD5_PASSWORD: u32 = 5;
const AUTH_SASL: u32 = 10;

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

/// The first message of a connection.
#[derive(Debug, PartialEq, Eq)]
pub enum FirstMessage {
    /// The app asks to encrypt the connection. Answering `N` makes it go on with a start-up message.
    Ssl,
    /// The app asks for GSSAPI encryption. Answering `N` makes it go on with a start-up message.
    GssEnc,
    /// The app cancels what another connection runs. These are the bytes of the whole request as the app sent them (length, code, process
    /// id and secret key), to be passed on to the server as they are.
    Cancel(Vec<u8>),
    /// The app starts a session.
    Startup(Startup),
}

/// A start-up message: the protocol version the app asked for and its parameters (`user`, `database`, `options`, settings, and the
/// protocol options that begin with `_pq_.`), in the order it sent them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Startup {
    version: u32,
    pub params: Vec<(String, String)>,
}

/// Reads the first message of a connection. Only the eight bytes that tell what it is are read before a message is refused for its
/// length or its code, so nothing is allocated for one that is too long.
///
/// Anything that is not an encryption request, a cancel request or a start-up message for protocol 3 (of any minor version, which the
/// server negotiates down) is `InvalidData`, as is a length that its kind of message cannot have and a start-up message that is not well
/// formed.
pub async fn read_first<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<FirstMessage> {
    let mut head = [0u8; 8];
    r.read_exact(&mut head).await?;
    let [l0, l1, l2, l3, c0, c1, c2, c3] = head;
    let length = u32::from_be_bytes([l0, l1, l2, l3]) as usize;
    let code = u32::from_be_bytes([c0, c1, c2, c3]);
    if !(8..=MAX_STARTUP_BYTES).contains(&length) {
        return Err(invalid("The first message of the connection has a length that no message has."));
    }
    match code {
        SSL_REQUEST if length == 8 => Ok(FirstMessage::Ssl),
        GSSENC_REQUEST if length == 8 => Ok(FirstMessage::GssEnc),
        SSL_REQUEST | GSSENC_REQUEST => Err(invalid("An encryption request has more than its code.")),
        CANCEL_REQUEST => {
            if !(MIN_CANCEL_BYTES..=MAX_CANCEL_BYTES).contains(&length) {
                return Err(invalid("A cancel request has a secret key of a length that no key has."));
            }
            let mut request = head.to_vec();
            request.resize(length, 0);
            r.read_exact(&mut request[8..]).await?;
            Ok(FirstMessage::Cancel(request))
        }
        version if version >> 16 == 3 => {
            let mut body = vec![0u8; length - 8];
            r.read_exact(&mut body).await?;
            Startup::parse(version, &body).map(FirstMessage::Startup)
        }
        _ => Err(invalid("The app asked for a protocol that Lunport does not speak.")),
    }
}

impl Startup {
    /// A start-up message for protocol 3.0 with these parameters.
    pub fn new(params: Vec<(String, String)>) -> Startup {
        Startup { version: PROTOCOL_3, params }
    }

    /// Reads the parameters in `body`, which is what follows the protocol version.
    fn parse(version: u32, body: &[u8]) -> io::Result<Startup> {
        // The last byte is the zero byte that ends the list of parameters, and what is before it is whole pairs of names and values.
        let Some((&0, mut rest)) = body.split_last() else {
            return Err(invalid("The start-up message does not end with a zero byte."));
        };
        let mut params = Vec::new();
        while !rest.is_empty() {
            let (name, after_name) = take_text(rest)?;
            if name.is_empty() {
                return Err(invalid("The start-up message goes on after its end."));
            }
            if after_name.is_empty() {
                return Err(invalid("A start-up parameter has no value."));
            }
            let (value, after_value) = take_text(after_name)?;
            params.push((name, value));
            rest = after_value;
        }
        Ok(Startup { version, params })
    }

    /// The protocol version of the message: the major version in the high 16 bits, the minor version in the low ones.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// The user the session signs in as: the last `user` parameter, which is the one the server takes.
    pub fn user(&self) -> Option<&str> {
        self.param("user")
    }

    /// The database the session opens: the last `database` parameter, which is the one the server takes.
    pub fn database(&self) -> Option<&str> {
        self.param("database")
    }

    fn param(&self, name: &str) -> Option<&str> {
        self.params.iter().rev().find(|(key, _)| key == name).map(|(_, value)| value.as_str())
    }

    /// The message with `user` as its only `user` parameter, in the place of the first one the app sent, else at the end.
    pub fn with_user(mut self, user: &str) -> Startup {
        let first = self.params.iter().position(|(name, _)| name == "user");
        self.params.retain(|(name, _)| name != "user");
        let user = ("user".to_string(), user.to_string());
        match first {
            Some(at) => self.params.insert(at, user),
            None => self.params.push(user),
        }
        self
    }

    /// The message with Cloud SQL's read-only lock on the session, which nothing else in the message can undo:
    ///
    /// - PostgreSQL takes the switches of the last `options` parameter only, so every `options` parameter ends with `READ_ONLY_OPTION` (one
    ///   is added when there is none). It comes last in each, where it overrides a switch of the app's own for the same setting.
    /// - PostgreSQL applies every other start-up parameter as a setting after those switches, and setting names do not distinguish ASCII
    ///   case, so a parameter named for the lock's setting would be applied after the lock. They are all taken out.
    pub fn with_read_only_lock(mut self) -> Startup {
        self.params.retain(|(name, _)| !name.eq_ignore_ascii_case(READ_ONLY_SETTING));
        let mut locked = false;
        for (name, value) in &mut self.params {
            if name.as_str() == "options" {
                if !value.is_empty() {
                    value.push(' ');
                }
                value.push_str(READ_ONLY_OPTION);
                locked = true;
            }
        }
        if !locked {
            self.params.push(("options".to_string(), READ_ONLY_OPTION.to_string()));
        }
        self
    }

    /// The message as it goes to the server: its length, its protocol version, each parameter as a name and a value that end with a zero
    /// byte, and a last zero byte.
    pub fn encode(&self) -> Vec<u8> {
        let mut message = vec![0u8; 4];
        message.extend_from_slice(&self.version.to_be_bytes());
        for (name, value) in &self.params {
            push_text(&mut message, name);
            push_text(&mut message, value);
        }
        message.push(0);
        let length = length_bytes(message.len());
        message[..4].copy_from_slice(&length);
        message
    }
}

/// The text before the first zero byte of `bytes`, and what follows that byte.
fn take_text(bytes: &[u8]) -> io::Result<(String, &[u8])> {
    let end = bytes.iter().position(|byte| *byte == 0).ok_or_else(|| invalid("A start-up parameter is not closed by a zero byte."))?;
    let text = std::str::from_utf8(&bytes[..end]).map_err(|_| invalid("A start-up parameter is not text."))?;
    Ok((text.to_owned(), &bytes[end + 1..]))
}

/// Appends `text` and the zero byte that ends it. A zero byte inside the text would end it early, so none is written.
fn push_text(message: &mut Vec<u8>, text: &str) {
    message.extend(text.bytes().filter(|byte| *byte != 0));
    message.push(0);
}

/// The four bytes of a message's length. A message of more bytes than they count is not made.
fn length_bytes(len: usize) -> [u8; 4] {
    u32::try_from(len).unwrap_or(u32::MAX).to_be_bytes()
}

/// The request for a clear-text password, with which the local port asks the app for the password Lunport made for the database: the
/// type `R`, a length of 8 and the code 3.
pub fn auth_cleartext() -> [u8; 9] {
    [b'R', 0, 0, 0, 8, 0, 0, 0, 3]
}

/// Reads the app's answer to a password request: a message of type `p` that holds the password and its terminating zero byte, and has
/// nothing else in it. The password is text of at most `MAX_PASSWORD_BYTES` bytes. Nothing of it is ever put in an error.
pub async fn read_password<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Zeroizing<String>> {
    let mut head = [0u8; 5];
    r.read_exact(&mut head).await?;
    let [kind, l0, l1, l2, l3] = head;
    if kind != PASSWORD_MESSAGE {
        return Err(invalid("The app did not answer with a password."));
    }
    let body_len = (u32::from_be_bytes([l0, l1, l2, l3]) as usize)
        .checked_sub(4)
        .filter(|len| (1..=MAX_PASSWORD_BYTES + 1).contains(len))
        .ok_or_else(|| invalid("The password message has a length that no password has."))?;
    // The password is wiped from the buffer it was read into as from the string it is copied to.
    let mut body = Zeroizing::new(vec![0u8; body_len]);
    r.read_exact(&mut body[..]).await?;
    let Some((&0, text)) = body.split_last() else {
        return Err(invalid("The password does not end with a zero byte."));
    };
    if text.contains(&0) {
        return Err(invalid("The password message holds more than one text."));
    }
    let text = std::str::from_utf8(text).map_err(|_| invalid("The password is not text."))?;
    Ok(Zeroizing::new(text.to_owned()))
}

/// An ErrorResponse that ends the connection: severity `FATAL`, the SQLSTATE `sqlstate` and `message`. A zero byte inside either would end
/// its field early, so none is written.
pub fn error_response(sqlstate: &str, message: &str) -> Vec<u8> {
    let mut response = vec![ERROR_RESPONSE, 0, 0, 0, 0];
    for (field, text) in [(b'S', "FATAL"), (b'V', "FATAL"), (b'C', sqlstate), (b'M', message)] {
        response.push(field);
        push_text(&mut response, text);
    }
    response.push(0);
    // The length counts itself and not the type byte.
    let length = length_bytes(response.len() - 1);
    response[1..5].copy_from_slice(&length);
    response
}

/// What the server's first answer to a start-up message is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerAuth {
    /// The session is signed in.
    Ok,
    /// The server asks for a password: in clear text, as an MD5 hash or by SASL.
    NeedsPassword,
    /// The server refuses the connection.
    Error,
}

/// Reads the server's first answer to a start-up message and returns what it is with all the bytes that were read, to be passed on to
/// the app as they are. A NegotiateProtocolVersion message may come first, which says the server has a lower minor version than the app
/// asked for or does not know some of its protocol options; it is part of the bytes and the answer is the message after it. Nothing is
/// read past the answer.
///
/// An answer of any other kind, a sign-in method that is neither accepted nor a password, and a message of a length no such message has
/// are `InvalidData`.
pub async fn read_server_auth<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<(ServerAuth, Vec<u8>)> {
    let mut raw = Vec::new();
    let mut negotiated = false;
    loop {
        let (kind, body) = read_server_message(r, &mut raw).await?;
        match kind {
            NEGOTIATE_PROTOCOL_VERSION if !negotiated => negotiated = true,
            ERROR_RESPONSE => return Ok((ServerAuth::Error, raw)),
            AUTHENTICATION => {
                let &[a, b, c, d, ..] = &raw[body..] else {
                    return Err(invalid("Cloud SQL sent a sign-in message with no code."));
                };
                let answer = match u32::from_be_bytes([a, b, c, d]) {
                    AUTH_OK => ServerAuth::Ok,
                    AUTH_CLEARTEXT_PASSWORD | AUTH_MD5_PASSWORD | AUTH_SASL => ServerAuth::NeedsPassword,
                    _ => return Err(invalid("Cloud SQL asked for a way to sign in that Lunport does not use.")),
                };
                return Ok((answer, raw));
            }
            _ => return Err(invalid("Cloud SQL answered with a message that Lunport does not expect.")),
        }
    }
}

/// Reads one message of the server into `raw`, as its bytes came, and returns its type and the place in `raw` where its body begins.
async fn read_server_message<R: AsyncRead + Unpin>(r: &mut R, raw: &mut Vec<u8>) -> io::Result<(u8, usize)> {
    let mut head = [0u8; 5];
    r.read_exact(&mut head).await?;
    let [kind, l0, l1, l2, l3] = head;
    let length = u32::from_be_bytes([l0, l1, l2, l3]) as usize;
    if !(4..=MAX_SERVER_MESSAGE_BYTES).contains(&length) {
        return Err(invalid("Cloud SQL sent a message with a length that no message has."));
    }
    raw.extend_from_slice(&head);
    let body = raw.len();
    raw.resize(body + length - 4, 0);
    r.read_exact(&mut raw[body..]).await?;
    Ok((kind, body))
}

/// Follows the messages a server sends a session, to tell when the session is idle: when the stream is between two messages, the last
/// ReadyForQuery said so and the server has begun no answer since. A notice, a setting that changed and a notification can come to a
/// session that is idle and leave it so once the message is whole; any other message answers a query.
///
/// It is fed the stream from the start of a message (the server's first answer to the start-up message, or whatever follows it), as it
/// comes, in reads of any size. It keeps a few bytes of state, never a message: it follows the framing (a type byte and a four-byte
/// length) and counts off the body of each message it has no use for, so that a result of any size costs the same. A stream that breaks
/// the framing is never idle again.
///
/// It sees only what the server sends: a query that was sent and has not been answered yet does not show.
#[derive(Debug, Default)]
pub struct ReadyTracker {
    position: Position,
    idle: bool,
}

/// Where in the framing of the server's stream the next byte is.
#[derive(Clone, Copy, Debug, Default)]
enum Position {
    /// The type byte of a message.
    #[default]
    Type,
    /// The length of a message of type `kind`: `got` of its four bytes are in `length`.
    Length { kind: u8, got: u8, length: u32 },
    /// The body of a message that does not matter: `left` bytes of it to go.
    Skip { left: usize },
    /// The status byte of a ReadyForQuery.
    Status,
    /// The stream broke the framing: where its messages begin is not known any more.
    Lost,
}

impl ReadyTracker {
    /// Takes the next bytes of the server's stream.
    pub fn feed(&mut self, mut bytes: &[u8]) {
        while let Some((&byte, rest)) = bytes.split_first() {
            match self.position {
                Position::Lost => return,
                Position::Skip { left } => {
                    // The body of a message that is of no use: its bytes are counted off, not looked at.
                    let skipped = left.min(bytes.len());
                    bytes = &bytes[skipped..];
                    self.position = if skipped == left { Position::Type } else { Position::Skip { left: left - skipped } };
                }
                Position::Type => {
                    if !matches!(byte, NOTICE_RESPONSE | PARAMETER_STATUS | NOTIFICATION_RESPONSE) {
                        self.idle = false;
                    }
                    self.position = Position::Length { kind: byte, got: 0, length: 0 };
                    bytes = rest;
                }
                Position::Length { kind, got, length } => {
                    let length = (length << 8) | u32::from(byte);
                    self.position = if got < 3 { Position::Length { kind, got: got + 1, length } } else { self.after_length(kind, length) };
                    bytes = rest;
                }
                Position::Status => {
                    self.idle = byte == b'I';
                    self.position = Position::Type;
                    bytes = rest;
                }
            }
        }
    }

    /// Whether the session is idle: the stream is between two messages, the last ReadyForQuery had the status `I`, outside a transaction,
    /// and no answer to a query has begun since. A notice, a changed setting or a notification that comes to an idle session does not end
    /// that, but while one is half read the stream is not between messages and the session is not idle. Before the first ReadyForQuery it
    /// is not.
    pub fn idle(&self) -> bool {
        self.idle && matches!(self.position, Position::Type)
    }

    /// Where the tracker is once the length of a message of type `kind` is in: `length` counts its own four bytes.
    fn after_length(&mut self, kind: u8, length: u32) -> Position {
        let Some(body) = length.checked_sub(4) else { return self.lose() };
        match kind {
            // A ReadyForQuery is one status byte.
            READY_FOR_QUERY if body == 1 => Position::Status,
            READY_FOR_QUERY => self.lose(),
            _ if body == 0 => Position::Type,
            _ => Position::Skip { left: body as usize },
        }
    }

    /// The stream is not what it was taken for, so the session is never said to be idle again.
    fn lose(&mut self) -> Position {
        self.idle = false;
        Position::Lost
    }
}

/// Whether the password the app gave is the one expected. Two passwords of the same length are compared by the constant-time equality of
/// the `subtle` crate, which goes over every byte and has no way out at the first difference, so the time does not tell where they
/// differ; only a difference of length is told at once, and the generated password has a fixed length. Nobody gets in when no password is
/// expected.
pub fn passwords_match(expected: &str, given: &str) -> bool {
    let (expected, given) = (expected.as_bytes(), given.as_bytes());
    if expected.is_empty() || expected.len() != given.len() {
        return false;
    }
    bool::from(expected.ct_eq(given))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What libpq 18 (`psql` as `frank` on `orders`) sent a server that had refused to encrypt the connection: a start-up message for
    /// protocol 3.0 with `user`, `database` and `application_name`.
    const LIBPQ_STARTUP: &str = "0000003a0003000075736572006672616e6b006461746162617365006f7264657273006170706c69636174696f6e5f6e616d65007073716c0000";
    /// The same start-up message from libpq with `max_protocol_version=3.2`: only the protocol version differs.
    const LIBPQ_STARTUP_3_2: &str = "0000003a0003000275736572006672616e6b006461746162617365006f7264657273006170706c69636174696f6e5f6e616d65007073716c0000";
    /// The request to encrypt the connection that libpq sends first when it prefers encryption.
    const LIBPQ_SSL_REQUEST: &str = "0000000804d2162f";
    /// The version number of protocol 3.2, which libpq 18 can ask for.
    const PROTOCOL_3_2: u32 = 196610;

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len()).step_by(2).map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex digits")).collect()
    }

    fn owned(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs.iter().map(|(name, value)| (name.to_string(), value.to_string())).collect()
    }

    fn startup_of(pairs: &[(&str, &str)]) -> Startup {
        Startup::new(owned(pairs))
    }

    /// The parameters of `startup` as pairs of text to compare with.
    fn params_of(startup: &Startup) -> Vec<(&str, &str)> {
        startup.params.iter().map(|(name, value)| (name.as_str(), value.as_str())).collect()
    }

    /// A message with no type byte, as the first message of a connection has none: its length, which counts itself, and `body`.
    fn untyped(body: &[u8]) -> Vec<u8> {
        let mut message = ((body.len() + 4) as u32).to_be_bytes().to_vec();
        message.extend_from_slice(body);
        message
    }

    /// A start-up message written out byte by byte, apart from the codec, so that what the codec reads and writes is held against the
    /// protocol and not against itself.
    fn startup_wire(version: u32, pairs: &[(&str, &str)]) -> Vec<u8> {
        let mut body = version.to_be_bytes().to_vec();
        for (name, value) in pairs {
            body.extend_from_slice(name.as_bytes());
            body.push(0);
            body.extend_from_slice(value.as_bytes());
            body.push(0);
        }
        body.push(0);
        untyped(&body)
    }

    /// A message with a type byte: the type, the length, which counts itself and not the type byte, and `body`.
    fn typed(kind: u8, body: &[u8]) -> Vec<u8> {
        let mut message = vec![kind];
        message.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
        message.extend_from_slice(body);
        message
    }

    /// The first eight bytes of a message with no type byte: a length and a code.
    fn head(length: u32, code: u32) -> Vec<u8> {
        [length.to_be_bytes(), code.to_be_bytes()].concat()
    }

    fn ready(status: u8) -> Vec<u8> {
        typed(b'Z', &[status])
    }

    /// An authentication request or answer of the server.
    fn auth_message(code: u32, extra: &[u8]) -> Vec<u8> {
        typed(b'R', &[&code.to_be_bytes()[..], extra].concat())
    }

    /// A NegotiateProtocolVersion message: the newest protocol version the server has, and the protocol options it did not recognise.
    fn negotiate(newest: u32, unrecognized: &[&str]) -> Vec<u8> {
        let mut body = newest.to_be_bytes().to_vec();
        body.extend_from_slice(&(unrecognized.len() as u32).to_be_bytes());
        for option in unrecognized {
            body.extend_from_slice(option.as_bytes());
            body.push(0);
        }
        typed(b'v', &body)
    }

    /// The fields of an ErrorResponse, which is checked to be framed right: the length counts itself, and the zero byte that ends the
    /// fields is the last byte.
    fn error_fields(message: &[u8]) -> Vec<(char, String)> {
        assert_eq!(message[0], b'E');
        assert_eq!(u32::from_be_bytes([message[1], message[2], message[3], message[4]]) as usize, message.len() - 1);
        let (mut rest, mut fields) = (&message[5..], Vec::new());
        while rest[0] != 0 {
            let end = rest[1..].iter().position(|byte| *byte == 0).expect("a field ends with a zero byte") + 1;
            fields.push((rest[0] as char, String::from_utf8(rest[1..end].to_vec()).expect("a field is text")));
            rest = &rest[end + 1..];
        }
        assert_eq!(rest, [0], "the zero byte that ends the fields is the last byte");
        fields
    }

    async fn read(bytes: &[u8]) -> io::Result<FirstMessage> {
        let mut input = bytes;
        read_first(&mut input).await
    }

    async fn read_startup(bytes: &[u8]) -> Startup {
        match read(bytes).await.expect("the message is read") {
            FirstMessage::Startup(startup) => startup,
            other => panic!("not a start-up message: {other:?}"),
        }
    }

    async fn server_auth(bytes: &[u8]) -> io::Result<(ServerAuth, Vec<u8>)> {
        let mut input = bytes;
        read_server_auth(&mut input).await
    }

    async fn password_of(bytes: &[u8]) -> io::Result<Zeroizing<String>> {
        let mut input = bytes;
        read_password(&mut input).await
    }

    fn kind_of<T: std::fmt::Debug>(result: io::Result<T>) -> io::ErrorKind {
        result.expect_err("the read fails").kind()
    }

    #[tokio::test]
    async fn the_ssl_request_is_recognized() {
        assert_eq!(SSL_REQUEST.to_be_bytes(), [4, 210, 22, 47]);
        assert_eq!(read(&hex(LIBPQ_SSL_REQUEST)).await.unwrap(), FirstMessage::Ssl);
        // An app that is told no goes on with its start-up message on the same connection: what follows stays in the stream.
        let wire = [hex(LIBPQ_SSL_REQUEST), hex(LIBPQ_STARTUP)].concat();
        let mut input = &wire[..];
        assert_eq!(read_first(&mut input).await.unwrap(), FirstMessage::Ssl);
        assert!(matches!(read_first(&mut input).await.unwrap(), FirstMessage::Startup(_)));
        assert!(input.is_empty());
    }

    #[tokio::test]
    async fn the_gssenc_request_is_recognized() {
        let wire = head(8, GSSENC_REQUEST);
        assert_eq!(wire, [0, 0, 0, 8, 4, 210, 22, 48]);
        assert_eq!(read(&wire).await.unwrap(), FirstMessage::GssEnc);
    }

    #[tokio::test]
    async fn a_cancel_request_is_passed_on_whole() {
        assert_eq!(CANCEL_REQUEST.to_be_bytes(), [4, 210, 22, 46]);
        // Before protocol 3.2 the secret key has 4 bytes; 3.2 allows up to 256.
        for key_len in [4usize, 32, 256] {
            let mut body = CANCEL_REQUEST.to_be_bytes().to_vec();
            body.extend_from_slice(&4242u32.to_be_bytes());
            body.resize(body.len() + key_len, 0xAB);
            let wire = untyped(&body);
            let mut input = &wire[..];
            assert_eq!(read_first(&mut input).await.unwrap(), FirstMessage::Cancel(wire.clone()), "a key of {key_len} bytes");
            assert!(input.is_empty());
        }
    }

    #[tokio::test]
    async fn a_startup_message_round_trips_its_parameters() {
        let pairs = [("user", "frank@example.com"), ("database", "orders"), ("application_name", "psql"), ("client_encoding", "UTF8")];
        let wire = startup_wire(PROTOCOL_3, &pairs);
        let startup = read_startup(&wire).await;
        assert_eq!(params_of(&startup), pairs);
        assert_eq!(startup.user(), Some("frank@example.com"));
        assert_eq!(startup.database(), Some("orders"));
        assert_eq!(startup.encode(), wire, "what was read is written back byte for byte");
        assert_eq!(startup_of(&pairs).encode(), wire, "a start-up message that is built here is for protocol 3.0");
        assert_eq!(startup_of(&pairs).version(), PROTOCOL_3);

        // The bytes libpq sends.
        let libpq = hex(LIBPQ_STARTUP);
        let startup = read_startup(&libpq).await;
        assert_eq!(params_of(&startup), [("user", "frank"), ("database", "orders"), ("application_name", "psql")]);
        assert_eq!(startup.encode(), libpq);

        // What Cloud SQL is sent: the IAM user, and the lock when the database is locked.
        let sent = startup.clone().with_user("frank@example.com");
        assert_eq!(sent.encode(), startup_wire(PROTOCOL_3, &[("user", "frank@example.com"), ("database", "orders"), ("application_name", "psql")]));
        assert_eq!(
            sent.with_read_only_lock().encode(),
            startup_wire(PROTOCOL_3, &[("user", "frank@example.com"), ("database", "orders"), ("application_name", "psql"), ("options", READ_ONLY_OPTION)])
        );
    }

    #[test]
    fn the_read_only_lock_is_appended_to_existing_options() {
        assert_eq!(READ_ONLY_OPTION, "-c cloudsql_session_read_only=locked");
        let locked = startup_of(&[("user", "frank@example.com"), ("options", "-c search_path=orders"), ("database", "orders")]).with_read_only_lock();
        assert_eq!(
            params_of(&locked),
            [("user", "frank@example.com"), ("options", "-c search_path=orders -c cloudsql_session_read_only=locked"), ("database", "orders")]
        );

        // With no `options` parameter, one is added after the others.
        let locked = startup_of(&[("user", "frank@example.com"), ("database", "orders")]).with_read_only_lock();
        assert_eq!(params_of(&locked), [("user", "frank@example.com"), ("database", "orders"), ("options", READ_ONLY_OPTION)]);

        // An empty value is just the lock, with no space before it.
        let locked = startup_of(&[("options", "")]).with_read_only_lock();
        assert_eq!(params_of(&locked), [("options", READ_ONLY_OPTION)]);

        // The value is not trimmed: a space the app escaped with a backslash at its end is part of what it set.
        let locked = startup_of(&[("options", "-c application_name=a\\ ")]).with_read_only_lock();
        assert_eq!(params_of(&locked), [("options", "-c application_name=a\\  -c cloudsql_session_read_only=locked")]);
    }

    #[test]
    fn a_separate_read_only_parameter_cannot_undo_the_lock() {
        // PostgreSQL applies the switches in `options` first and then each other start-up parameter as a setting, and setting names do not
        // distinguish ASCII case: such a parameter would be applied after the lock.
        let locked = startup_of(&[
            ("user", "frank@example.com"),
            ("CloudSQL_Session_Read_Only", "off"),
            ("database", "orders"),
            ("cloudsql_session_read_only", "on"),
            ("CLOUDSQL_SESSION_READ_ONLY", "off"),
            ("cloudsql_session_read_only_mode", "kept: another name"),
        ])
        .with_read_only_lock();
        assert_eq!(
            params_of(&locked),
            [("user", "frank@example.com"), ("database", "orders"), ("cloudsql_session_read_only_mode", "kept: another name"), ("options", READ_ONLY_OPTION)]
        );
    }

    #[test]
    fn every_options_entry_carries_the_lock() {
        // PostgreSQL keeps only the last `options` entry, and an app may send several.
        let locked = startup_of(&[("options", "-c search_path=a"), ("user", "frank@example.com"), ("options", "-c cloudsql_session_read_only=off")])
            .with_read_only_lock();
        assert_eq!(
            params_of(&locked),
            [
                ("options", "-c search_path=a -c cloudsql_session_read_only=locked"),
                ("user", "frank@example.com"),
                ("options", "-c cloudsql_session_read_only=off -c cloudsql_session_read_only=locked"),
            ]
        );
    }

    #[tokio::test]
    async fn the_lock_survives_the_wire() {
        // An app that sends the lock's setting both ways and two `options` entries, read from bytes and written back.
        let wire = startup_wire(
            PROTOCOL_3,
            &[
                ("user", "frank"),
                ("options", "-c cloudsql_session_read_only=off"),
                ("cloudsql_session_read_only", "off"),
                ("database", "orders"),
                ("options", "-c work_mem=64MB"),
            ],
        );
        let sent = read_startup(&wire).await.with_user("frank@example.com").with_read_only_lock().encode();
        let sent = read_startup(&sent).await;
        assert_eq!(sent.user(), Some("frank@example.com"));
        assert!(sent.params.iter().all(|(name, _)| !name.eq_ignore_ascii_case("cloudsql_session_read_only")));
        let options: Vec<&str> = sent.params.iter().filter(|(name, _)| name == "options").map(|(_, value)| value.as_str()).collect();
        assert_eq!(options.len(), 2);
        assert!(options.iter().all(|value| value.ends_with(READ_ONLY_OPTION)), "{options:?}");
    }

    #[tokio::test]
    async fn a_protocol_3_2_startup_keeps_its_version() {
        assert_eq!(PROTOCOL_3_2, (3 << 16) | 2);
        let wire = hex(LIBPQ_STARTUP_3_2);
        let startup = read_startup(&wire).await;
        assert_eq!(startup.version(), PROTOCOL_3_2);
        assert_eq!(startup.encode(), wire, "the version it asked for is the version it is written with");
        let rewritten = startup.with_user("frank@example.com").with_read_only_lock().encode();
        assert_eq!(rewritten[4..8], PROTOCOL_3_2.to_be_bytes(), "the rewrites keep it");

        // Every minor version of protocol 3 is read and written back as it came; the server negotiates it down.
        for minor in [0u32, 1, 2, 3, 65535] {
            let wire = startup_wire((3 << 16) | minor, &[("user", "frank")]);
            let startup = read_startup(&wire).await;
            assert_eq!(startup.version(), (3 << 16) | minor);
            assert_eq!(startup.encode(), wire);
        }
    }

    #[tokio::test]
    async fn a_zero_byte_in_a_parameter_cannot_add_another_one() {
        // Text with a zero byte inside would end its parameter early and let the rest pass for parameters of their own, after the lock.
        let sent = startup_of(&[("database", "orders")]).with_user("frank@example.com\0options\0-c cloudsql_session_read_only=off").with_read_only_lock();
        let read = read_startup(&sent.encode()).await;
        assert_eq!(read.user(), Some("frank@example.comoptions-c cloudsql_session_read_only=off"));
        let options: Vec<&str> = read.params.iter().filter(|(name, _)| name == "options").map(|(_, value)| value.as_str()).collect();
        assert_eq!(options, [READ_ONLY_OPTION]);
        assert_eq!(read.params.len(), 3);
    }

    #[tokio::test]
    async fn protocol_option_parameters_are_kept_as_they_are() {
        let wire = startup_wire(PROTOCOL_3_2, &[("user", "frank"), ("_pq_.test_extension", "1"), ("database", "orders")]);
        let startup = read_startup(&wire).await;
        assert_eq!(startup.encode(), wire);
        let rewritten = startup.with_user("frank@example.com").with_read_only_lock();
        assert_eq!(params_of(&rewritten), [("user", "frank@example.com"), ("_pq_.test_extension", "1"), ("database", "orders"), ("options", READ_ONLY_OPTION)]);
    }

    #[test]
    fn user_and_database_are_the_last_ones_sent() {
        // The server takes the last `user` and the last `database`.
        let startup = startup_of(&[("user", "nobody"), ("database", "other"), ("user", "frank"), ("database", "orders")]);
        assert_eq!(startup.user(), Some("frank"));
        assert_eq!(startup.database(), Some("orders"));
        let none = startup_of(&[("application_name", "psql")]);
        assert_eq!((none.user(), none.database()), (None, None));
        // Names are matched as they are written: `User` is a setting, not the user.
        assert_eq!(startup_of(&[("User", "frank")]).user(), None);
    }

    #[test]
    fn with_user_leaves_exactly_one_user_parameter() {
        let replaced = startup_of(&[("user", "frank"), ("database", "orders")]).with_user("frank@example.com");
        assert_eq!(params_of(&replaced), [("user", "frank@example.com"), ("database", "orders")]);

        // However many the app sent, one is left, where the first was.
        let replaced =
            startup_of(&[("database", "orders"), ("user", "nobody"), ("application_name", "psql"), ("user", "frank")]).with_user("frank@example.com");
        assert_eq!(params_of(&replaced), [("database", "orders"), ("user", "frank@example.com"), ("application_name", "psql")]);
        assert_eq!(replaced.user(), Some("frank@example.com"));

        let added = startup_of(&[("database", "orders")]).with_user("frank@example.com");
        assert_eq!(params_of(&added), [("database", "orders"), ("user", "frank@example.com")]);
    }

    #[tokio::test]
    async fn oversized_or_unknown_first_messages_are_rejected() {
        // A message is refused for its length or its code from its first eight bytes, and only those are given: it is refused without
        // reading on.
        for (what, wire) in [
            ("a length below eight", head(7, PROTOCOL_3)),
            ("a length of zero", head(0, PROTOCOL_3)),
            ("a length past the limit", head(MAX_STARTUP_BYTES as u32 + 1, PROTOCOL_3)),
            ("the largest length", head(u32::MAX, PROTOCOL_3)),
            ("text of another protocol", b"GET / HT".to_vec()),
            ("protocol 2.0", head(16, 2 << 16)),
            ("protocol 4.0", head(16, 4 << 16)),
            ("a request code nobody knows", head(8, 80877105)),
            ("an encryption request with a body", head(12, SSL_REQUEST)),
            ("a GSSAPI request with a body", head(12, GSSENC_REQUEST)),
            ("a cancel request with a key of three bytes", head(15, CANCEL_REQUEST)),
            ("a cancel request with a key of 257 bytes", head(269, CANCEL_REQUEST)),
        ] {
            assert_eq!(kind_of(read(&wire).await), io::ErrorKind::InvalidData, "{what}");
        }

        // A start-up message of exactly the limit is read, one byte more is not.
        let bare = startup_wire(PROTOCOL_3, &[("user", "frank"), ("application_name", "")]).len();
        let name = "a".repeat(MAX_STARTUP_BYTES - bare);
        let at_limit = startup_wire(PROTOCOL_3, &[("user", "frank"), ("application_name", &name)]);
        assert_eq!(at_limit.len(), MAX_STARTUP_BYTES);
        assert_eq!(read_startup(&at_limit).await.params.len(), 2);
        let over = startup_wire(PROTOCOL_3, &[("user", "frank"), ("application_name", &format!("{name}a"))]);
        assert_eq!(kind_of(read(&over).await), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn malformed_startup_messages_are_invalid_data() {
        let message = |rest: &[u8]| untyped(&[&PROTOCOL_3.to_be_bytes()[..], rest].concat());
        // Each case with a word of the sentence it must be refused with, so that every check is shown to refuse what it is for and not
        // to be covered by another one.
        for (what, wire, reason) in [
            ("no parameters and no terminator", message(b""), "does not end"),
            ("a parameter list with no terminator", message(b"user\0frank\0databas"), "does not end"),
            ("a value that is not terminated", message(b"user\0frank"), "does not end"),
            ("a last value whose zero byte is taken for the terminator", message(b"user\0frank\0"), "not closed"),
            ("a last name whose zero byte is taken for the terminator", message(b"user\0frank\0abc\0"), "not closed"),
            ("a name without a value", message(b"user\0\0"), "no value"),
            ("bytes after the terminator", message(b"user\0frank\0\0junk\0"), "goes on after"),
            ("an empty name before the end", message(b"user\0frank\0\0\0"), "goes on after"),
            ("more parameters after the terminator", message(b"user\0frank\0\0c\0d\0e\0\0"), "goes on after"),
            ("a name that is not text", message(b"us\xFFr\0frank\0\0"), "not text"),
            ("a value that is not text", message(b"user\0fr\xFFnk\0\0"), "not text"),
        ] {
            let error = read(&wire).await.expect_err(what);
            assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{what}");
            assert!(error.to_string().contains(reason), "{what}: {error}");
        }
    }

    #[tokio::test]
    async fn a_message_shorter_than_its_length_ends_the_read() {
        let wire = hex(LIBPQ_STARTUP);
        for cut in [0, 3, 7, 8, 20, wire.len() - 1] {
            assert_eq!(kind_of(read(&wire[..cut]).await), io::ErrorKind::UnexpectedEof, "cut at {cut}");
        }
    }

    #[tokio::test]
    async fn mutated_or_cut_startup_messages_never_panic() {
        let valid = hex(LIBPQ_STARTUP);
        for cut in 0..=valid.len() {
            let _ = read(&valid[..cut]).await;
        }
        for at in 0..valid.len() {
            for byte in [0u8, 1, b'a', 0x7F, 0x80, 0xFF] {
                let mut mutated = valid.clone();
                mutated[at] = byte;
                if let Ok(FirstMessage::Startup(startup)) = read(&mutated).await {
                    // Whatever is accepted is written back so that it is read as the same message.
                    assert_eq!(read_startup(&startup.encode()).await, startup);
                }
            }
        }
    }

    #[test]
    fn the_cleartext_request_is_exact() {
        assert_eq!(auth_cleartext(), [b'R', 0, 0, 0, 8, 0, 0, 0, 3]);
    }

    #[tokio::test]
    async fn a_password_message_is_read_as_text() {
        let wire = [typed(b'p', b"example-password-1\0"), typed(b'X', b"")].concat();
        let mut input = &wire[..];
        let password = read_password(&mut input).await.unwrap();
        assert_eq!(*password, "example-password-1");
        assert_eq!(input, typed(b'X', b""), "what follows the password is not read");
        // The longest password allowed.
        let longest = "a".repeat(MAX_PASSWORD_BYTES);
        assert_eq!(*password_of(&typed(b'p', format!("{longest}\0").as_bytes())).await.unwrap(), longest);
    }

    #[tokio::test]
    async fn a_malformed_or_oversized_password_message_is_invalid_data() {
        let too_long = typed(b'p', format!("{}\0", "a".repeat(MAX_PASSWORD_BYTES + 1)).as_bytes());
        for (what, wire) in [
            ("a password past the limit (only its head is given)", too_long[..5].to_vec()),
            ("another kind of message", typed(b'X', b"")),
            ("an empty body", typed(b'p', b"")),
            ("a password that is not terminated", typed(b'p', b"example")),
            ("a zero byte inside the password", typed(b'p', b"exa\0mple\0")),
            ("bytes after the terminator", typed(b'p', b"example\0junk")),
            ("a length below four", vec![b'p', 0, 0, 0, 3]),
            ("a password that is not text", typed(b'p', b"ex\xFFmple\0")),
        ] {
            assert_eq!(kind_of(password_of(&wire).await), io::ErrorKind::InvalidData, "{what}");
        }
        let cut = typed(b'p', b"example\0");
        assert_eq!(kind_of(password_of(&cut[..cut.len() - 3]).await), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn an_error_response_carries_the_sqlstate() {
        let message = error_response("28P01", "Wrong password for orders-pg. Copy the password from Lunport.");
        assert_eq!(
            error_fields(&message),
            [
                ('S', "FATAL".to_string()),
                ('V', "FATAL".to_string()),
                ('C', "28P01".to_string()),
                ('M', "Wrong password for orders-pg. Copy the password from Lunport.".to_string())
            ]
        );
        let body = b"SFATAL\0VFATAL\0C28P01\0MWrong password for orders-pg. Copy the password from Lunport.\0\0";
        assert_eq!(message, typed(b'E', body));
    }

    #[test]
    fn an_error_response_never_holds_a_zero_byte_inside_a_field() {
        let fields = error_fields(&error_response("08006", "Lunport could\0 not reach orders-pg"));
        assert_eq!(fields[3], ('M', "Lunport could not reach orders-pg".to_string()));
    }

    #[tokio::test]
    async fn a_server_password_request_is_detected() {
        for (what, wire) in [
            ("a clear-text password", auth_message(3, b"")),
            ("an MD5 password", auth_message(5, &[1, 2, 3, 4])),
            ("SASL", auth_message(10, b"SCRAM-SHA-256\0\0")),
        ] {
            let (answer, raw) = server_auth(&wire).await.unwrap();
            assert_eq!(answer, ServerAuth::NeedsPassword, "{what}");
            assert_eq!(raw, wire, "{what}: the bytes to pass on are the ones read");
        }
    }

    #[tokio::test]
    async fn authentication_ok_and_errors_are_forwarded_and_nothing_more_is_read() {
        let ok = auth_message(0, b"");
        assert_eq!(ok, [b'R', 0, 0, 0, 8, 0, 0, 0, 0]);
        let after = typed(b'S', b"server_version\x0018.6\0");
        let wire = [ok.clone(), after.clone()].concat();
        let mut input = &wire[..];
        let (answer, raw) = read_server_auth(&mut input).await.unwrap();
        assert_eq!((answer, raw), (ServerAuth::Ok, ok));
        assert_eq!(input, after, "the bytes after the answer are left for the copy that follows");

        let refused = error_response("28000", "Cloud SQL refused the connection.");
        assert_eq!(server_auth(&refused).await.unwrap(), (ServerAuth::Error, refused));
    }

    #[tokio::test]
    async fn a_negotiate_protocol_version_message_before_authentication_is_forwarded() {
        // What a server answers to a start-up message that asks for a newer minor version or for protocol options it does not know.
        let negotiation = negotiate(PROTOCOL_3_2, &["_pq_.test_extension"]);
        let after = typed(b'K', &[0; 8]);
        for (answer, request) in
            [(ServerAuth::Ok, auth_message(0, b"")), (ServerAuth::NeedsPassword, auth_message(3, b"")), (ServerAuth::Error, error_response("28000", "no"))]
        {
            let wire = [negotiation.clone(), request.clone(), after.clone()].concat();
            let mut input = &wire[..];
            let (got, raw) = read_server_auth(&mut input).await.unwrap();
            assert_eq!(got, answer);
            assert_eq!(raw, [negotiation.clone(), request].concat(), "both messages go to the app, in the order they came");
            assert_eq!(input, after);
        }
    }

    #[tokio::test]
    async fn an_unexpected_first_answer_from_the_server_is_invalid_data() {
        let negotiation = negotiate(PROTOCOL_3_2, &[]);
        let mut too_long = vec![b'R'];
        too_long.extend_from_slice(&((MAX_SERVER_MESSAGE_BYTES + 1) as u32).to_be_bytes());
        for (what, wire) in [
            ("a ready for query", ready(b'I')),
            ("a parameter status", typed(b'S', b"server_version\x0018.6\0")),
            ("a Kerberos request", auth_message(2, b"")),
            ("a GSSAPI request", auth_message(7, b"")),
            ("a SASL continuation", auth_message(11, b"x")),
            ("an authentication message with no code", typed(b'R', b"")),
            ("a second negotiation", [negotiation.clone(), negotiation, auth_message(0, b"")].concat()),
            ("a message past the limit (only its head is given)", too_long),
            ("a length below four", vec![b'R', 0, 0, 0, 3]),
        ] {
            assert_eq!(kind_of(server_auth(&wire).await), io::ErrorKind::InvalidData, "{what}");
        }
        assert_eq!(kind_of(server_auth(b"").await), io::ErrorKind::UnexpectedEof);
        assert_eq!(kind_of(server_auth(&auth_message(3, b"")[..6]).await), io::ErrorKind::UnexpectedEof);
    }

    /// A server's stream from its first answer on, as messages with whether the session is idle after each of them: idle after a
    /// ReadyForQuery that says so, and not after the messages that answer a query. Notices, settings and notifications can come to a
    /// session that is idle and leave it so.
    fn session() -> Vec<(Vec<u8>, bool)> {
        let row_description = typed(b'T', &[0, 1, b'n', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 23, 0, 4, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0]);
        let row = |value: &[u8]| typed(b'D', &[&[0, 1][..], &(value.len() as u32).to_be_bytes(), value].concat());
        vec![
            (auth_message(0, b""), false),
            (typed(b'S', b"server_version\x0018.6\0"), false),
            (typed(b'K', &[0, 0, 0x10, 0x92, 0xDE, 0xAD, 0xBE, 0xEF]), false),
            (ready(b'I'), true),
            (row_description.clone(), false),
            (row(b"1"), false),
            (row(b"2"), false),
            (typed(b'C', b"SELECT 2\0"), false),
            (ready(b'I'), true),
            (typed(b'C', b"BEGIN\0"), false),
            (ready(b'T'), false),
            (error_response("22012", "division by zero"), false),
            (ready(b'E'), false),
            (typed(b'C', b"ROLLBACK\0"), false),
            (ready(b'I'), true),
            (typed(b'N', b"SNOTICE\0Mhello\0\0"), true),
            (typed(b'S', b"TimeZone\0UTC\0"), true),
            (typed(b'A', &[0, 0, 0, 1, b'c', 0, 0]), true),
            (typed(b'I', b""), false),
            (ready(b'I'), true),
            (row_description, false),
            (ready(b'I'), true),
        ]
    }

    #[test]
    fn ready_for_query_is_tracked_across_split_reads() {
        let mut tracker = ReadyTracker::default();
        assert!(!tracker.idle(), "nothing is idle before the first ReadyForQuery");

        // One message at a time.
        for (message, idle) in session() {
            tracker.feed(&message);
            assert_eq!(tracker.idle(), idle, "after {:?}", message[0] as char);
        }

        // A ReadyForQuery split inside its type, its length and its status, a byte at a time.
        let mut tracker = ReadyTracker::default();
        let wire = ready(b'I');
        for (fed, byte) in wire.iter().enumerate() {
            assert!(!tracker.idle(), "{fed} bytes in");
            tracker.feed(&[*byte]);
        }
        assert!(tracker.idle());
        tracker.feed(&ready(b'T')[..5]);
        assert!(!tracker.idle(), "a ReadyForQuery that says nothing yet is not idle");
        tracker.feed(b"T");
        assert!(!tracker.idle());
        tracker.feed(&ready(b'I'));
        assert!(tracker.idle());
        tracker.feed(&ready(b'E'));
        assert!(!tracker.idle());
        tracker.feed(&ready(b'X'));
        assert!(!tracker.idle(), "only a status of I is idle");
    }

    #[test]
    fn a_frame_split_anywhere_is_followed() {
        let messages = session();
        let wire: Vec<u8> = messages.iter().flat_map(|(message, _)| message.clone()).collect();
        let mut end = 0;
        let boundaries: Vec<(usize, bool)> = messages
            .iter()
            .map(|(message, idle)| {
                end += message.len();
                (end, *idle)
            })
            .collect();

        // Each size of read, so that every split of every message happens, in its type, its length and its body. Between messages the
        // session is idle as the stream says, and inside a message it never is.
        for size in 1..=wire.len() {
            let mut tracker = ReadyTracker::default();
            let mut fed = 0;
            for piece in wire.chunks(size) {
                tracker.feed(piece);
                fed += piece.len();
                match boundaries.iter().find(|(end, _)| *end == fed) {
                    Some((_, idle)) => assert_eq!(tracker.idle(), *idle, "reads of {size} bytes, after {fed}"),
                    None => assert!(!tracker.idle(), "reads of {size} bytes: {fed} is inside a message"),
                }
            }
        }

        // Two reads, split at each byte.
        for split in 0..=wire.len() {
            let mut tracker = ReadyTracker::default();
            tracker.feed(&wire[..split]);
            tracker.feed(&wire[split..]);
            assert!(tracker.idle(), "split at {split}");
        }
    }

    #[test]
    fn a_query_in_progress_is_not_idle() {
        let mut tracker = ReadyTracker::default();
        tracker.feed(&ready(b'I'));
        assert!(tracker.idle());
        // The first byte of the answer to a query is enough, and a notice does not make an idle session busy.
        for quiet in [typed(b'N', b"SNOTICE\0\0"), typed(b'S', b"TimeZone\0UTC\0"), typed(b'A', &[0, 0, 0, 1, 0, 0])] {
            tracker.feed(&quiet);
            assert!(tracker.idle(), "{:?}", quiet[0] as char);
        }
        tracker.feed(b"D");
        assert!(!tracker.idle());
    }

    #[test]
    fn an_idle_session_is_idle_only_between_messages() {
        // A notice, a setting or a notification that is half read leaves the stream inside a message, however it is cut.
        for (what, quiet) in [
            ("a notice", typed(b'N', b"SNOTICE\0Mhello\0\0")),
            ("a setting that changed", typed(b'S', b"TimeZone\0UTC\0")),
            ("a notification", typed(b'A', &[0, 0, 0, 1, b'c', 0, 0])),
            ("a notice with no body", typed(b'N', b"")),
        ] {
            for cut in 1..quiet.len() {
                let mut tracker = ReadyTracker::default();
                tracker.feed(&ready(b'I'));
                assert!(tracker.idle(), "{what}: before it");
                tracker.feed(&quiet[..cut]);
                assert!(!tracker.idle(), "{what}: cut after {cut} of {} bytes", quiet.len());
                tracker.feed(&quiet[cut..]);
                assert!(tracker.idle(), "{what}: whole, cut at {cut}");
            }
        }
    }

    #[test]
    fn a_large_data_stream_costs_no_memory() {
        // A DataRow of a billion bytes is skipped as it goes by: the tracker keeps a count, not the message.
        let payload = 1_000_000_000usize;
        let mut tracker = ReadyTracker::default();
        tracker.feed(&ready(b'I'));
        tracker.feed(&[&b"D"[..], &((payload + 4) as u32).to_be_bytes()].concat());
        let chunk = vec![0xEEu8; 1 << 16];
        let mut left = payload;
        while left > 0 {
            let size = left.min(chunk.len());
            tracker.feed(&chunk[..size]);
            left -= size;
            assert!(!tracker.idle());
        }
        tracker.feed(&typed(b'C', b"SELECT 1\0"));
        assert!(!tracker.idle());
        tracker.feed(&ready(b'I'));
        assert!(tracker.idle(), "the ReadyForQuery after the big message is found");
    }

    #[test]
    fn a_stream_that_breaks_the_framing_is_never_idle_again() {
        for (what, broken) in [
            ("a length below four", vec![b'D', 0, 0, 0, 3]),
            ("a notice with a length below four", vec![b'N', 0, 0, 0, 2]),
            ("a ReadyForQuery that is longer than one status", typed(b'Z', b"II")),
            ("a ReadyForQuery with no status", vec![b'Z', 0, 0, 0, 4]),
            // Read as a status of I and then a notice of no body, this would leave the session idle.
            ("a ReadyForQuery of two bytes that reads as a short one", vec![b'Z', 0, 0, 0, 6, b'I', b'N', 0, 0, 0, 4]),
        ] {
            let mut tracker = ReadyTracker::default();
            tracker.feed(&ready(b'I'));
            assert!(tracker.idle());
            tracker.feed(&broken);
            assert!(!tracker.idle(), "{what}");
            tracker.feed(&ready(b'I'));
            assert!(!tracker.idle(), "{what}: the boundaries of messages are lost");
        }
    }

    #[test]
    fn passwords_match_only_equal_passwords() {
        let expected = "Zm9vYmFyYmF6cXV4Zm9vYmFyYmF6cXV4MTIzNA";
        assert!(passwords_match(expected, expected));
        let copy: String = expected.chars().collect();
        assert!(passwords_match(expected, &copy), "equal text kept in another place");
        // One byte different, at the start, in the middle and at the end.
        for at in [0, expected.len() / 2, expected.len() - 1] {
            let mut wrong = expected.as_bytes().to_vec();
            wrong[at] ^= 1;
            assert!(!passwords_match(expected, &String::from_utf8(wrong).unwrap()), "differs at {at}");
        }
        // A prefix, an extension and nothing at all.
        assert!(!passwords_match(expected, &expected[..expected.len() - 1]));
        assert!(!passwords_match(expected, &format!("{expected}x")));
        assert!(!passwords_match(expected, ""));
        // Text that is not ASCII is compared by its bytes.
        assert!(passwords_match("pässword", "pässword"));
        assert!(!passwords_match("pässword", "passw\u{f6}rd"));
        // No password is expected: nobody gets in with an empty one.
        assert!(!passwords_match("", ""));
    }
}
