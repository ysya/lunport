//! The local username comes from the process identity, never USER/USERNAME environment values.
use std::io;

fn checked_name(name: String) -> io::Result<String> {
    if name.is_empty() || name.chars().any(|c| c.is_control() || c.is_whitespace()) {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the operating system returned an invalid username",
        ))
    } else {
        Ok(name)
    }
}
#[cfg(unix)]
pub fn current_username() -> io::Result<String> {
    use std::ffi::CStr;
    // SAFETY: sysconf and getuid require no pointers and do not modify process identity.
    let suggested = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let mut size = if suggested > 0 {
        suggested as usize
    } else {
        16 * 1024
    };
    const MAX: usize = 1024 * 1024;
    loop {
        if size > MAX {
            return Err(io::Error::other(
                "the OS identity lookup needs an oversized buffer",
            ));
        }
        let mut buffer = vec![0u8; size];
        // SAFETY: passwd consists of integer and pointer fields, all valid when zeroed.
        let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result = std::ptr::null_mut();
        // SAFETY: entry/result are writable aligned structs; buffer remains alive through copying pw_name.
        let status = unsafe {
            libc::getpwuid_r(
                libc::getuid(),
                &mut entry,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if status == libc::ERANGE {
            size = size.saturating_mul(2);
            continue;
        }
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status));
        }
        if result.is_null() || entry.pw_name.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "the process user has no OS account name",
            ));
        }
        // SAFETY: a successful getpwuid_r gives a NUL-terminated name within the live lookup buffer.
        let name = unsafe { CStr::from_ptr(entry.pw_name) }
            .to_str()
            .map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "the OS username is not UTF-8")
            })?
            .to_string();
        return checked_name(name);
    }
}
#[cfg(windows)]
pub fn current_username() -> io::Result<String> {
    use windows_sys::Win32::Foundation::{GetLastError, ERROR_INSUFFICIENT_BUFFER};
    use windows_sys::Win32::Security::{LookupAccountSidW, SidTypeUser, TOKEN_USER};
    let token = crate::sync::slot_files_windows::current_user_token()?;
    // SAFETY: the existing token helper returns an aligned TOKEN_USER whose SID lives in token.
    let sid = unsafe { (*(token.as_ptr().cast::<TOKEN_USER>())).User.Sid };
    let (mut name_len, mut domain_len) = (0u32, 0u32);
    let mut kind = SidTypeUser;
    // SAFETY: the first call obtains sizes, both zero-sized output buffers are null.
    let ok = unsafe {
        LookupAccountSidW(
            std::ptr::null(),
            sid,
            std::ptr::null_mut(),
            &mut name_len,
            std::ptr::null_mut(),
            &mut domain_len,
            &mut kind,
        )
    };
    if ok == 0 && unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
        return Err(io::Error::last_os_error());
    }
    if name_len == 0 || name_len > 65536 || domain_len > 65536 {
        return Err(io::Error::other(
            "the OS identity lookup needs an invalid buffer",
        ));
    }
    let mut name = vec![0u16; name_len as usize];
    let mut domain = vec![0u16; domain_len.max(1) as usize];
    // SAFETY: both buffers are writable and sized from the first lookup; token keeps SID valid.
    let ok = unsafe {
        LookupAccountSidW(
            std::ptr::null(),
            sid,
            name.as_mut_ptr(),
            &mut name_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut kind,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let end = name.iter().position(|n| *n == 0).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "the OS username has no terminator",
        )
    })?;
    checked_name(String::from_utf16(&name[..end]).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "the OS username is not valid Unicode",
        )
    })?)
}
#[cfg(not(any(unix, windows)))]
pub fn current_username() -> io::Result<String> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "OS identity lookup is unavailable",
    ))
}
#[cfg(test)]
mod tests {
    #[test]
    fn native_identity_lookup_provides_a_nonempty_name() {
        let name = super::current_username().unwrap();
        assert!(!name.is_empty());
        assert!(!name.chars().any(char::is_control));
    }
    #[test]
    fn invalid_names_are_refused_without_substitution() {
        for invalid in ["", "name\n", " name", "a\0b"] {
            assert!(super::checked_name(invalid.into()).is_err());
        }
        assert_eq!(super::checked_name("os-user".into()).unwrap(), "os-user");
    }
}
