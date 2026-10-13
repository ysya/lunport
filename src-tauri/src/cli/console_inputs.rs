//! What `sshelter connect` takes from and gives to the Windows console, apart from the Windows calls (`inputs_windows.rs` makes them):
//! the keys read as UTF-16 turned into the UTF-8 the remote takes, the remote's UTF-8 cut into pieces the console is given whole
//! characters of, and the console's control events turned into the inputs the loop knows (own-ssh spec §7.3, the Windows bullet).
//! Compiled on Windows and in the tests of every platform.

use zeroize::Zeroizing;

use super::client::Input;
use super::signal;

/// U+FFFD, the replacement character, in UTF-8.
const REPLACEMENT: [u8; 3] = [0xEF, 0xBF, 0xBD];

/// Turns what the console's reads give (`ReadConsoleW`: UTF-16) into the UTF-8 the remote takes, a read at a time. A surrogate pair
/// split between two reads is joined: the first half waits for the next read. A half without its other half becomes U+FFFD.
#[derive(Default)]
pub struct Utf16Decoder {
    /// The first half of a surrogate pair, at the end of the last read.
    high: Option<u16>,
}

impl Utf16Decoder {
    /// The UTF-8 of the read `units`, after what the last read left. It is built in a buffer that has room for all of it from the start
    /// and is wiped when it is dropped: what was typed may be a password, and a `Vec` that grows frees its old allocation unwiped.
    pub fn decode(&mut self, units: &[u16]) -> Zeroizing<Vec<u8>> {
        // A unit becomes at most three bytes, and a pair (two units) four; U+FFFD is three. The half carried over adds one unit.
        let mut text = Zeroizing::new(Vec::with_capacity(3 * (units.len() + 1)));
        for &unit in units {
            if let Some(high) = self.high.take() {
                if is_low(unit) {
                    let code = 0x10000 + ((u32::from(high) - 0xD800) << 10) + (u32::from(unit) - 0xDC00);
                    push_char(&mut text, char::from_u32(code).unwrap_or(char::REPLACEMENT_CHARACTER));
                    continue;
                }
                text.extend_from_slice(&REPLACEMENT);
            }
            if is_high(unit) {
                self.high = Some(unit);
            } else if is_low(unit) {
                text.extend_from_slice(&REPLACEMENT);
            } else {
                push_char(&mut text, char::from_u32(u32::from(unit)).unwrap_or(char::REPLACEMENT_CHARACTER));
            }
        }
        text
    }

    /// Forgets a first half that waits for its other half: the next read does not continue this one (the mode it was read in is over).
    pub fn reset(&mut self) {
        self.high = None;
    }
}

fn is_high(unit: u16) -> bool {
    (0xD800..=0xDBFF).contains(&unit)
}

fn is_low(unit: u16) -> bool {
    (0xDC00..=0xDFFF).contains(&unit)
}

fn push_char(text: &mut Vec<u8>, c: char) {
    let mut utf8 = [0u8; 4];
    text.extend_from_slice(c.encode_utf8(&mut utf8).as_bytes());
}

/// How much of `bytes` ends at a character boundary: all of it but the start of a character the next bytes may complete (one, two or
/// three bytes of it, at the end). Bytes that cannot be part of a character count as whole: they are shown as they are (U+FFFD).
pub fn whole_characters(bytes: &[u8]) -> usize {
    let mut start = 0;
    loop {
        match std::str::from_utf8(&bytes[start..]) {
            Ok(_) => return bytes.len(),
            // The end of the bytes cut a character short.
            Err(error) if error.error_len().is_none() => return start + error.valid_up_to(),
            // Bytes that are no character: whole as they are; look on after them.
            Err(error) => start += error.valid_up_to() + error.error_len().unwrap_or(1),
        }
    }
}

/// The remote's output for the console, a piece at a time, so that no character is cut between two writes to the console: a character
/// cut at the end of a piece waits for the next piece. At the end what waits is written as it is.
#[derive(Default)]
pub struct Utf8Pieces {
    /// The start of a character, from the end of the last piece.
    rest: Vec<u8>,
}

impl Utf8Pieces {
    /// What to write of `piece` now: what the last piece left, and `piece` up to its last whole character.
    pub fn next(&mut self, piece: &[u8]) -> Vec<u8> {
        let mut bytes = std::mem::take(&mut self.rest);
        bytes.extend_from_slice(piece);
        let whole = whole_characters(&bytes);
        self.rest = bytes.split_off(whole);
        bytes
    }

    /// What waits for the rest of its character, at the end: written as it is.
    pub fn end(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.rest)
    }
}

// The console's control events (wincon.h), as plain numbers so that this builds everywhere; on Windows they are pinned against
// windows-sys (`inputs_windows.rs`).

/// Ctrl-C, while the input is processed (not raw: in raw mode Ctrl-C is a key like any other).
pub const CTRL_C_EVENT: u32 = 0;
/// Ctrl-Break.
pub const CTRL_BREAK_EVENT: u32 = 1;
/// The console is being closed (its window, or the terminal's tab).
pub const CTRL_CLOSE_EVENT: u32 = 2;
/// The user logs off (a service's event: an interactive console program does not get it).
pub const CTRL_LOGOFF_EVENT: u32 = 5;
/// The system shuts down (a service's event too).
pub const CTRL_SHUTDOWN_EVENT: u32 = 6;

/// What a console control event is to the program.
#[derive(Debug, PartialEq, Eq)]
pub struct Control {
    /// The signal it stands for, as on Unix: its number makes the exit status (128 + n).
    pub signal: i32,
    /// It ends the program: the watchdog is armed, and the handler does not return before the program has put the console back, since
    /// Windows ends the process when it does.
    pub ends: bool,
}

/// The signal a console control event stands for (spec §7.3): Ctrl-C and Ctrl-Break are SIGINT (130), the console closed is SIGHUP
/// (129), log-off and shut-down are SIGTERM (143). `None` for an event the program leaves to the next handler.
pub fn control(event: u32) -> Option<Control> {
    match event {
        CTRL_C_EVENT | CTRL_BREAK_EVENT => Some(Control { signal: signal::INT, ends: false }),
        CTRL_CLOSE_EVENT => Some(Control { signal: signal::HUP, ends: true }),
        CTRL_LOGOFF_EVENT | CTRL_SHUTDOWN_EVENT => Some(Control { signal: signal::TERM, ends: true }),
        _ => None,
    }
}

impl Control {
    /// The input the loop is told: Ctrl-C cancels a question (and ends the program when there is none), as SIGINT does on Unix; the others
    /// end the program.
    pub fn input(&self) -> Input {
        if self.signal == signal::INT {
            Input::Interrupt
        } else {
            Input::Stop(self.signal)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    fn decoded(decoder: &mut Utf16Decoder, units: &[u16]) -> String {
        String::from_utf8(decoder.decode(units).to_vec()).expect("always UTF-8")
    }

    /// Spec §7.3: what the console reads (UTF-16) reaches the remote as UTF-8: ASCII, a character of the basic plane, and one outside it
    /// (a surrogate pair) read whole.
    #[test]
    fn a_read_becomes_utf_8() {
        let mut decoder = Utf16Decoder::default();
        assert_eq!(decoded(&mut decoder, &utf16("ls -l\r")), "ls -l\r");
        assert_eq!(decoded(&mut decoder, &utf16("\u{e9}\u{5bc6}\u{78bc}")), "\u{e9}\u{5bc6}\u{78bc}");
        assert_eq!(decoded(&mut decoder, &utf16("key \u{1f511}!")), "key \u{1f511}!");
        assert_eq!(decoded(&mut decoder, &[]), "");
    }

    /// A surrogate pair that two reads split: the first half waits for the second, and the character arrives whole with it.
    #[test]
    fn a_surrogate_pair_split_between_two_reads_is_joined() {
        let pair = utf16("\u{1f511}");
        assert_eq!(pair.len(), 2);
        let mut decoder = Utf16Decoder::default();
        assert_eq!(decoded(&mut decoder, &[u16::from(b'a'), pair[0]]), "a", "the first half waits");
        assert_eq!(decoded(&mut decoder, &[pair[1], u16::from(b'b')]), "\u{1f511}b");
        assert_eq!(decoded(&mut decoder, &[pair[0]]), "");
        assert_eq!(decoded(&mut decoder, &[pair[1]]), "\u{1f511}", "a read of one half each");
    }

    /// A half without its other half is U+FFFD, wherever it is: a second half alone, a first half followed by something else (in the same
    /// read or the next), and a first half the program forgot (its mode is over).
    #[test]
    fn a_lone_surrogate_becomes_the_replacement_character() {
        let pair = utf16("\u{1f511}");
        let mut decoder = Utf16Decoder::default();
        assert_eq!(decoded(&mut decoder, &[pair[1]]), "\u{fffd}");
        assert_eq!(decoded(&mut decoder, &[pair[0], u16::from(b'x')]), "\u{fffd}x");
        assert_eq!(decoded(&mut decoder, &[pair[0]]), "");
        assert_eq!(decoded(&mut decoder, &[u16::from(b'y')]), "\u{fffd}y", "the next read did not complete it");
        assert_eq!(decoded(&mut decoder, &[pair[0], pair[0], pair[1]]), "\u{fffd}\u{1f511}", "a first half after a first half");
        assert_eq!(decoded(&mut decoder, &[pair[0]]), "");
        decoder.reset();
        assert_eq!(decoded(&mut decoder, &[pair[1]]), "\u{fffd}", "forgotten: the second half is alone");
    }

    /// What was typed may be a password: the buffer it is turned into never grows (and frees an unwiped allocation), whatever the read.
    #[test]
    fn the_utf_8_of_a_read_fits_the_buffer_it_is_built_in() {
        let pair = utf16("\u{1f511}");
        let reads: [Vec<u16>; 4] = [utf16("\u{5bc6}".repeat(100).as_str()), vec![pair[1]; 50], [pair[0], u16::from(b'a')].repeat(40), pair.repeat(30)];
        for read in reads {
            let mut decoder = Utf16Decoder { high: Some(pair[0]) };
            let text = decoder.decode(&read);
            assert!(text.len() <= 3 * (read.len() + 1) && text.capacity() >= 3 * (read.len() + 1), "{} bytes", text.len());
        }
    }

    #[test]
    fn whole_characters_stop_before_a_character_the_end_cut_short() {
        let key = "\u{1f511}".as_bytes();
        assert_eq!(whole_characters(b"plain"), 5);
        assert_eq!(whole_characters(b""), 0);
        for cut in 1..key.len() {
            let mut bytes = b"ab".to_vec();
            bytes.extend_from_slice(&key[..cut]);
            assert_eq!(whole_characters(&bytes), 2, "{cut} bytes of a four-byte character");
        }
        assert_eq!(whole_characters("\u{e9}".as_bytes()), 2);
        // Bytes that are no character are whole as they are; a cut character after them still waits.
        assert_eq!(whole_characters(b"\xff\xfe"), 2);
        assert_eq!(whole_characters(b"a\xffb\xe5\xaf"), 3);
        assert_eq!(whole_characters(b"\xe5\x41"), 2, "a character broken off, not cut short");
    }

    /// Spec §7.3: the console is never given a part of a character: a character cut at the end of a piece waits for the next piece, the
    /// rest is written at once, and nothing is lost: at the end what waits is written as it is.
    #[test]
    fn a_character_cut_between_two_pieces_waits_for_the_second() {
        let text = "a\u{e9}b\u{5bc6}c\u{1f511}d".as_bytes();
        for size in 1..=text.len() {
            let mut pieces = Utf8Pieces::default();
            let mut written: Vec<Vec<u8>> = text.chunks(size).map(|piece| pieces.next(piece)).collect();
            for part in &written {
                assert!(std::str::from_utf8(part).is_ok(), "pieces of {size}: {part:?} is whole characters");
            }
            written.push(pieces.end());
            assert_eq!(written.concat(), text, "pieces of {size}: nothing lost");
        }
        let mut pieces = Utf8Pieces::default();
        assert_eq!(pieces.next(b"ab\xe5\xaf"), b"ab");
        assert_eq!(pieces.end(), b"\xe5\xaf", "at the end, as it is");
        assert_eq!(pieces.end(), b"");
        assert_eq!(pieces.next(b"\xffz"), b"\xffz", "bytes that are no character go at once");
    }

    /// Spec §7.3: Ctrl-C and Ctrl-Break are SIGINT (130: a question is cancelled, the program ends without one), the console closed is
    /// SIGHUP (129) and log-off and shut-down SIGTERM (143); those three end the program: the watchdog is armed, and the handler waits
    /// for the console to be put back. Any other event is left to the next handler.
    #[test]
    fn each_control_event_is_the_signal_spec_7_3_gives_it() {
        let interrupt = Control { signal: 2, ends: false };
        assert_eq!(control(CTRL_C_EVENT), Some(Control { signal: 2, ends: false }));
        assert_eq!(control(CTRL_BREAK_EVENT), Some(interrupt));
        assert_eq!(control(CTRL_CLOSE_EVENT), Some(Control { signal: 1, ends: true }));
        assert_eq!(control(CTRL_LOGOFF_EVENT), Some(Control { signal: 15, ends: true }));
        assert_eq!(control(CTRL_SHUTDOWN_EVENT), Some(Control { signal: 15, ends: true }));
        for other in [3, 4, 7, 100] {
            assert_eq!(control(other), None, "event {other}");
        }
        let inputs: Vec<String> = [CTRL_C_EVENT, CTRL_BREAK_EVENT, CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT]
            .into_iter()
            .map(|event| format!("{:?}", control(event).unwrap().input()))
            .collect();
        assert_eq!(inputs, ["Interrupt", "Interrupt", "Stop(1)", "Stop(15)"]);
    }
}
