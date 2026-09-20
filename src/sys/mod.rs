pub mod acl;
pub mod certs;
pub mod actions;
pub mod com;
pub mod crashes;
pub mod detail;
pub mod devpath;
pub mod dialogs;
pub mod disks;
pub mod handles;
pub mod icons;
pub mod modules;
pub mod mounts;
pub mod net;
pub mod netconfig;
pub mod netdrives;
pub mod privilege;
pub mod reg;
pub mod resources;
pub mod process;
pub mod drivers;
pub mod dumpan;
pub mod eventlog;
pub mod services;
pub mod shares;
pub mod accounts;
pub mod sessions;
pub mod software;
pub mod firewall;
pub mod signature;
pub mod sysinfo;
pub mod startup;
pub mod tasks;
pub mod updates;
pub mod version;
pub mod winerr;

use std::ffi::OsString;
use std::os::windows::ffi::{OsStrExt, OsStringExt};

pub fn wide(s: &str) -> Vec<u16> {
    OsString::from(s).encode_wide().chain(Some(0)).collect()
}

pub fn pw(p: windows::core::PWSTR) -> String {
    if p.is_null() { String::new() } else { unsafe { p.to_string().unwrap_or_default() } }
}

pub struct SecretWide(pub Vec<u16>);

impl SecretWide {
    pub fn new(s: &str) -> Self {
        SecretWide(wide(s))
    }
}

impl Drop for SecretWide {
    fn drop(&mut self) {
        for c in self.0.iter_mut() {
            unsafe { std::ptr::write_volatile(c, 0) };
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

static DRIVE_KINDS: parking_lot::Mutex<Vec<(u8, bool)>> = parking_lot::Mutex::new(Vec::new());

pub fn local_path(path: &str) -> bool {
    let b = path.as_bytes();
    if path.starts_with("\\\\") || b.len() < 3 || !b[0].is_ascii_alphabetic() || b[1] != b':' {
        return false;
    }
    let letter = b[0].to_ascii_uppercase();
    if let Some((_, local)) = DRIVE_KINDS.lock().iter().find(|(l, _)| *l == letter) {
        return *local;
    }
    let root = wide(&format!("{}:\\", letter as char));
    let kind = unsafe { windows::Win32::Storage::FileSystem::GetDriveTypeW(windows::core::PCWSTR(root.as_ptr())) };
    let local = kind == 3 || kind == 6;
    DRIVE_KINDS.lock().push((letter, local));
    local
}

pub fn from_wide(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    OsString::from_wide(&buf[..end]).to_string_lossy().into_owned()
}

pub fn filetime_to_unix_ms(ft: i64) -> i64 {
    if ft <= 0 {
        return 0;
    }
    (ft - 116_444_736_000_000_000) / 10_000
}

pub fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    if head.eq_ignore_ascii_case(prefix) { s.get(prefix.len()..) } else { None }
}

pub fn starts_with_ci(s: &str, prefix: &str) -> bool {
    strip_prefix_ci(s, prefix).is_some()
}

pub fn processor_count() -> u32 {
    use windows::Win32::System::Threading::{ALL_PROCESSOR_GROUPS, GetActiveProcessorCount};
    let all = unsafe { GetActiveProcessorCount(ALL_PROCESSOR_GROUPS) };
    if all > 0 {
        return all;
    }
    let mut info = windows::Win32::System::SystemInformation::SYSTEM_INFO::default();
    unsafe { windows::Win32::System::SystemInformation::GetSystemInfo(&mut info) };
    info.dwNumberOfProcessors.max(1)
}

pub fn system_root() -> String {
    std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into())
}

pub fn system_drive() -> String {
    std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into())
}

pub fn program_files_roots() -> Vec<String> {
    let mut out = Vec::new();
    for var in ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"] {
        if let Ok(v) = std::env::var(var) {
            let v = v.trim_end_matches('\\').to_lowercase();
            if !v.is_empty() && !out.contains(&v) {
                out.push(v);
            }
        }
    }
    if let Ok(v) = std::env::var("ProgramData") {
        out.push(format!("{}\\microsoft", v.trim_end_matches('\\').to_lowercase()));
    }
    out
}

pub fn in_windows_dir(path: &str) -> bool {
    !path.is_empty() && starts_with_ci(path, &format!("{}\\", system_root()))
}

static SYSTEM_AREAS: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();

pub fn is_system_area(path: &str) -> bool {
    let areas = SYSTEM_AREAS.get_or_init(|| {
        let mut v = vec![system_root().to_lowercase()];
        v.extend(program_files_roots());
        v.into_iter().map(|r| format!("{}\\", r)).collect()
    });
    let lower = path.to_lowercase();
    areas.iter().any(|r| lower.starts_with(r.as_str()))
}

pub fn local_stamp() -> String {
    let t = unsafe { windows::Win32::System::SystemInformation::GetLocalTime() };
    format!("{:04}{:02}{:02}-{:02}{:02}{:02}", t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond)
}

pub fn local_time_text(unix_ms: i64) -> String {
    use windows::Win32::Foundation::{FILETIME, SYSTEMTIME};
    use windows::Win32::Globalization::{DATE_SHORTDATE, GetDateFormatEx, GetTimeFormatEx, TIME_NOSECONDS};
    use windows::Win32::System::Time::{FileTimeToSystemTime, SystemTimeToTzSpecificLocalTime};
    use windows::core::PCWSTR;
    if unix_ms <= 0 {
        return String::new();
    }
    let ticks = (unix_ms as u64 * 10_000).wrapping_add(116_444_736_000_000_000);
    let ft = FILETIME { dwLowDateTime: ticks as u32, dwHighDateTime: (ticks >> 32) as u32 };
    let mut utc = SYSTEMTIME::default();
    let mut local = SYSTEMTIME::default();
    unsafe {
        if FileTimeToSystemTime(&ft, &mut utc).is_err() || SystemTimeToTzSpecificLocalTime(None, &utc, &mut local).is_err() {
            return String::new();
        }
        let mut date = [0u16; 64];
        let mut time = [0u16; 64];
        let dl = GetDateFormatEx(PCWSTR::null(), DATE_SHORTDATE, Some(&local), PCWSTR::null(), Some(&mut date), PCWSTR::null());
        let tl = GetTimeFormatEx(PCWSTR::null(), TIME_NOSECONDS, Some(&local), PCWSTR::null(), Some(&mut time));
        if dl <= 0 || tl <= 0 {
            return format!("{:04}-{:02}-{:02} {:02}:{:02}", local.wYear, local.wMonth, local.wDay, local.wHour, local.wMinute);
        }
        format!("{} {}", from_wide(&date), from_wide(&time))
    }
}
