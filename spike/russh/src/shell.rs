//! Interactive-shell helpers: open a PTY shell, type into it, read until something shows up.

use russh::client::Msg;
use russh::{Channel, ChannelMsg};

use crate::client::SpikeHandler;

/// Session channel, `pty-req` (no terminal modes), then `shell`. Nothing waits for the replies.
pub async fn open_shell(handle: &russh::client::Handle<SpikeHandler>, term: &str, cols: u32, rows: u32) -> Result<Channel<Msg>, russh::Error> {
    let channel = handle.channel_open_session().await?;
    channel.request_pty(true, term, cols, rows, 0, 0, &[]).await?;
    channel.request_shell(true).await?;
    Ok(channel)
}

/// Types `line` and presses Enter.
pub async fn type_line(channel: &Channel<Msg>, line: &str) -> Result<(), russh::Error> {
    let bytes = format!("{line}\n");
    channel.data(bytes.as_bytes()).await
}

/// Reads (stdout and stderr arrive merged on a PTY) until `find` returns something for everything read so far.
/// `Err` carries what was read when the channel ended first.
pub async fn read_until_found<T>(channel: &mut Channel<Msg>, find: impl Fn(&str) -> Option<T>) -> Result<T, String> {
    let mut seen = String::new();
    while let Some(message) = channel.wait().await {
        if let ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. } = message {
            seen.push_str(&String::from_utf8_lossy(&data));
            if let Some(found) = find(&seen) {
                return Ok(found);
            }
        }
    }
    Err(format!("the channel closed first; read so far: {seen:?}"))
}

pub async fn read_until(channel: &mut Channel<Msg>, needle: &str) -> Result<String, String> {
    read_until_found(channel, |seen| seen.contains(needle).then(|| seen.to_string())).await
}

/// Asks the shell for the terminal size and returns "<rows> <cols>". The command echoed back by the PTY reads `SIZE[%s]`, the answer
/// `SIZE[40 120]`: only the answer has two numbers between the brackets.
pub async fn stty_size(channel: &mut Channel<Msg>) -> Result<String, String> {
    type_line(channel, "printf 'SIZE[%s]\\n' \"$(stty size)\"").await.map_err(|error| error.to_string())?;
    read_until_found(channel, size_in).await
}

fn size_in(output: &str) -> Option<String> {
    output.split("SIZE[").skip(1).find_map(|rest| {
        let inside = rest.split(']').next()?;
        let numbers: Vec<&str> = inside.split(' ').collect();
        let digits = |text: &&str| !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit());
        (numbers.len() == 2 && numbers.iter().all(digits)).then(|| inside.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::size_in;

    #[test]
    fn only_the_answer_counts_not_the_echoed_command() {
        assert_eq!(size_in("printf 'SIZE[%s]\\n' \"$(stty size)\"\r\nSIZE[40 120]\r\n"), Some("40 120".to_string()));
        assert_eq!(size_in("printf 'SIZE[%s]\\n' \"$(stty size)\"\r\n"), None);
        assert_eq!(size_in("SIZE[0 0]"), Some("0 0".to_string()));
        assert_eq!(size_in("SIZE[40]"), None);
        assert_eq!(size_in("SIZE[40 12x]"), None);
    }
}
