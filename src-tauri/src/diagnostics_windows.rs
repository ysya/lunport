//! Last-chance metadata only. No heap allocation, mutex, unwinding, dump or exception recovery
//! inside the filter. Continue searching so Windows Error Reporting retains its normal behavior.
use super::*;
use std::{
    os::windows::io::IntoRawHandle,
    sync::atomic::{AtomicBool, AtomicIsize},
};
use windows_sys::Win32::{
    Storage::FileSystem::WriteFile,
    System::Diagnostics::Debug::{SetUnhandledExceptionFilter, EXCEPTION_POINTERS},
};

static HANDLE: AtomicIsize = AtomicIsize::new(0);
static WRITTEN: AtomicBool = AtomicBool::new(false);
static PREVIOUS: OnceLock<
    windows_sys::Win32::System::Diagnostics::Debug::LPTOP_LEVEL_EXCEPTION_FILTER,
> = OnceLock::new();

pub(super) fn install(directory: &Path) -> io::Result<()> {
    rotate(directory, "native-crash.log", 512)?;
    let mut file = open_log(&directory.join("native-crash.log"))?;
    writeln!(
        file,
        "launch version={} pid={} time_ms={}",
        env!("CARGO_PKG_VERSION"),
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    )?;
    // The handle deliberately lives until process exit, so a fatal callback never opens a file.
    HANDLE.store(file.into_raw_handle() as isize, Ordering::Release);
    let previous = unsafe { SetUnhandledExceptionFilter(Some(exception_filter)) };
    let _ = PREVIOUS.set(previous);
    Ok(())
}

unsafe extern "system" fn exception_filter(info: *const EXCEPTION_POINTERS) -> i32 {
    if WRITTEN.swap(true, Ordering::Relaxed) {
        return forward(info);
    }
    let handle = HANDLE.load(Ordering::Acquire);
    if handle == 0 {
        return forward(info);
    }
    let mut bytes = *b"native_exception code=0x00000000 address=0x0000000000000000 stage=00\r\n";
    let record = info.as_ref().and_then(|info| info.ExceptionRecord.as_ref());
    if let Some(record) = record {
        hex(&mut bytes[24..32], record.ExceptionCode as u64);
        hex(&mut bytes[43..59], record.ExceptionAddress as usize as u64);
    }
    let stage = STAGE.load(Ordering::Relaxed);
    bytes[66] = b'0' + stage / 10;
    bytes[67] = b'0' + stage % 10;
    let mut written = 0;
    WriteFile(
        handle as _,
        bytes.as_ptr(),
        bytes.len() as u32,
        &mut written,
        std::ptr::null_mut(),
    );
    forward(info)
}

unsafe fn forward(info: *const EXCEPTION_POINTERS) -> i32 {
    if let Some(Some(previous)) = PREVIOUS.get() {
        previous(info)
    } else {
        0
    } // EXCEPTION_CONTINUE_SEARCH: never treat a fatal fault as recovered.
}

fn hex(output: &mut [u8], mut value: u64) {
    for byte in output.iter_mut().rev() {
        *byte = b"0123456789abcdef"[(value & 15) as usize];
        value >>= 4;
    }
}
