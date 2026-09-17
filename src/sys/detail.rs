use crate::nt::*;
use crate::sys::from_wide;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::ffi::c_void;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, LookupAccountSidW, SID_NAME_USE,
    PSID, TOKEN_ELEVATION, TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TOKEN_USER, TokenElevation,
    TokenIntegrityLevel, TokenUser,
};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::SystemInformation::IMAGE_FILE_MACHINE;
use windows::Win32::System::Threading::{
    IsWow64Process2, OpenProcess, OpenProcessToken, PROCESS_DUP_HANDLE,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT,
};
use windows::core::{PCWSTR, PWSTR};

#[derive(Clone, Default)]
pub struct ProcessDetail {
    pub image_path: String,
    pub command_line: String,
    pub working_dir: String,
    pub user: String,
    pub integrity: String,
    pub elevated: bool,
    pub arch: String,
    pub accessible: bool,
    pub protection: String,
    pub handles_readable: bool,
    pub critical: bool,
    pub note: String,
    pub groups: Vec<String>,
    pub privileges: Vec<(String, bool)>,
}

pub struct DetailCache {
    map: Mutex<HashMap<(u32, i64), ProcessDetail>>,
    sids: Mutex<HashMap<String, String>>,
}

impl Default for DetailCache {
    fn default() -> Self {
        Self::new()
    }
}

impl DetailCache {
    pub fn new() -> Self {
        DetailCache {
            map: Mutex::new(HashMap::new()),
            sids: Mutex::new(HashMap::new()),
        }
    }

    pub fn get(&self, pid: u32, create_time: i64, deep: bool) -> ProcessDetail {
        let key = (pid, create_time);
        if !deep
            && let Some(d) = self.map.lock().get(&key) {
                return d.clone();
            }
        let d = collect(pid, deep, self);
        if !deep {
            self.map.lock().insert(key, d.clone());
        }
        d
    }

    pub fn prune(&self, live: &[(u32, i64)]) {
        let set: std::collections::HashSet<(u32, i64)> = live.iter().copied().collect();
        self.map.lock().retain(|k, _| set.contains(k));
    }

    fn lookup_sid(&self, sid: PSID, text: &str) -> String {
        if let Some(v) = self.sids.lock().get(text) {
            return v.clone();
        }
        let mut name = vec![0u16; 256];
        let mut domain = vec![0u16; 256];
        let mut name_len = name.len() as u32;
        let mut domain_len = domain.len() as u32;
        let mut use_kind = SID_NAME_USE::default();
        let resolved = unsafe {
            LookupAccountSidW(
                PCWSTR::null(),
                sid,
                Some(PWSTR(name.as_mut_ptr())),
                &mut name_len,
                Some(PWSTR(domain.as_mut_ptr())),
                &mut domain_len,
                &mut use_kind,
            )
        };
        let value = if resolved.is_ok() {
            let d = from_wide(&domain);
            let n = from_wide(&name);
            if d.is_empty() { n } else { format!("{}\\{}", d, n) }
        } else {
            text.to_string()
        };
        self.sids.lock().insert(text.to_string(), value.clone());
        value
    }
}

fn collect(pid: u32, deep: bool, cache: &DetailCache) -> ProcessDetail {
    let mut d = ProcessDetail::default();
    if pid == 0 {
        d.user = "NT AUTHORITY\\SYSTEM".into();
        d.integrity = "System".into();
        d.accessible = true;
        return d;
    }

    let access = if deep {
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ
    } else {
        PROCESS_QUERY_LIMITED_INFORMATION
    };

    let h = match unsafe { OpenProcess(access, false, pid) } {
        Ok(h) => h,
        Err(_) => match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
            Ok(h) => h,
            Err(e) => {
                d.note = format!("cannot open process: {}", short_error(&e));
                return d;
            }
        },
    };
    d.accessible = true;

    let mut buf = vec![0u16; 32768];
    let mut len = buf.len() as u32;
    if unsafe {
        QueryFullProcessImageNameW(h, PROCESS_NAME_FORMAT(0), PWSTR(buf.as_mut_ptr()), &mut len)
    }
    .is_ok()
    {
        d.image_path = from_wide(&buf[..len as usize]);
    }

    d.command_line = query_command_line(h);
    d.arch = query_arch(h);
    d.protection = query_protection(h);
    let image_name = d.image_path.rsplit('\\').next().unwrap_or("");
    d.critical = crate::sys::actions::is_critical(pid) || crate::sys::actions::CRITICAL_NAMES.iter().any(|n| n.eq_ignore_ascii_case(image_name));
    d.handles_readable = match unsafe { OpenProcess(PROCESS_DUP_HANDLE, false, pid) } {
        Ok(dh) => {
            unsafe {
                let _ = CloseHandle(dh);
            }
            true
        }
        Err(_) => false,
    };
    if !d.handles_readable {
        d.note = if d.protection.is_empty() {
            "handles unavailable: this process refuses PROCESS_DUP_HANDLE".into()
        } else {
            format!(
                "protected process ({}): handles and modules cannot be read even when elevated",
                d.protection
            )
        };
    }

    if pid == 4 {
        d.user = "NT AUTHORITY\\SYSTEM".into();
        d.integrity = "System".into();
    }
    let mut token = HANDLE::default();
    if unsafe { OpenProcessToken(h, TOKEN_QUERY, &mut token) }.is_ok() {
        d.user = token_user(token, cache);
        d.integrity = token_integrity(token);
        d.elevated = token_elevated(token);
        if deep {
            d.groups = token_groups(token, cache);
            d.privileges = token_privileges(token);
        }
        unsafe {
            let _ = CloseHandle(token);
        }
    }

    if deep
        && let Some(cwd) = read_peb_strings(h) {
            d.working_dir = cwd;
        }

    unsafe {
        let _ = CloseHandle(h);
    }
    d
}

fn short_error(e: &windows::core::Error) -> String {
    crate::sys::winerr::describe(e)
}

fn query_command_line(h: HANDLE) -> String {
    let mut buf = vec![0u8; 4096];
    let mut needed = 0u32;
    let mut status = unsafe {
        NtQueryInformationProcess(
            h.0,
            ProcessCommandLineInformation,
            buf.as_mut_ptr() as *mut c_void,
            buf.len() as u32,
            &mut needed,
        )
    };
    if status == STATUS_INFO_LENGTH_MISMATCH || status == STATUS_BUFFER_OVERFLOW {
        buf.resize(needed as usize + 64, 0);
        status = unsafe {
            NtQueryInformationProcess(
                h.0,
                ProcessCommandLineInformation,
                buf.as_mut_ptr() as *mut c_void,
                buf.len() as u32,
                &mut needed,
            )
        };
    }
    if !nt_ok(status) {
        return String::new();
    }
    let us = unsafe { &*(buf.as_ptr() as *const UNICODE_STRING) };
    unsafe { us.to_string() }
}

fn query_protection(h: HANDLE) -> String {
    let mut value: u8 = 0;
    let mut needed = 0u32;
    let status = unsafe {
        NtQueryInformationProcess(
            h.0,
            ProcessProtectionInformation,
            &mut value as *mut u8 as *mut c_void,
            1,
            &mut needed,
        )
    };
    if nt_ok(status) {
        protection_label(value)
    } else {
        String::new()
    }
}

fn query_arch(h: HANDLE) -> String {
    let mut process_machine = IMAGE_FILE_MACHINE(0);
    let mut native_machine = IMAGE_FILE_MACHINE(0);
    if unsafe { IsWow64Process2(h, &mut process_machine, Some(&mut native_machine)) }.is_err() {
        return String::new();
    }
    let effective = if process_machine.0 == 0 {
        native_machine.0
    } else {
        process_machine.0
    };
    match effective {
        0x014c => "x86".into(),
        0x8664 => "x64".into(),
        0xaa64 => "ARM64".into(),
        0x01c4 => "ARM".into(),
        _ => String::new(),
    }
}

fn token_user(token: HANDLE, cache: &DetailCache) -> String {
    unsafe {
        let mut size = 0u32;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut size);
        if size == 0 {
            return String::new();
        }
        let mut buf = vec![0u8; size as usize];
        if GetTokenInformation(
            token,
            TokenUser,
            Some(buf.as_mut_ptr() as *mut c_void),
            size,
            &mut size,
        )
        .is_err()
        {
            return String::new();
        }
        let tu = &*(buf.as_ptr() as *const TOKEN_USER);
        let text = crate::sys::privilege::sid_text(tu.User.Sid);
        cache.lookup_sid(tu.User.Sid, &text)
    }
}

fn token_integrity(token: HANDLE) -> String {
    unsafe {
        let mut size = 0u32;
        let _ = GetTokenInformation(token, TokenIntegrityLevel, None, 0, &mut size);
        if size == 0 {
            return String::new();
        }
        let mut buf = vec![0u8; size as usize];
        if GetTokenInformation(
            token,
            TokenIntegrityLevel,
            Some(buf.as_mut_ptr() as *mut c_void),
            size,
            &mut size,
        )
        .is_err()
        {
            return String::new();
        }
        let label = &*(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL);
        let count = *GetSidSubAuthorityCount(label.Label.Sid);
        if count == 0 {
            return String::new();
        }
        let rid = *GetSidSubAuthority(label.Label.Sid, (count - 1) as u32);
        match rid {
            0x0000 => "Untrusted".into(),
            0x1000 => "Low".into(),
            0x2000 => "Medium".into(),
            0x2100 => "Medium+".into(),
            0x3000 => "High".into(),
            0x4000 => "System".into(),
            0x5000 => "Protected".into(),
            _ => format!("0x{:X}", rid),
        }
    }
}

fn token_elevated(token: HANDLE) -> bool {
    unsafe {
        let mut elevation = TOKEN_ELEVATION::default();
        let mut size = 0u32;
        GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        )
        .is_ok()
            && elevation.TokenIsElevated != 0
    }
}

fn read_peb32_cwd(h: HANDLE) -> Option<String> {
    unsafe {
        let mut peb32: usize = 0;
        let mut needed = 0u32;
        let status = NtQueryInformationProcess(h.0, 26, &mut peb32 as *mut _ as *mut c_void, std::mem::size_of::<usize>() as u32, &mut needed);
        if !nt_ok(status) || peb32 == 0 {
            return None;
        }
        let mut params: u32 = 0;
        if ReadProcessMemory(h, (peb32 + 0x10) as *const c_void, &mut params as *mut _ as *mut c_void, 4, None).is_err() || params == 0 {
            return None;
        }
        let mut dos = [0u8; 8];
        if ReadProcessMemory(h, (params as usize + 0x24) as *const c_void, dos.as_mut_ptr() as *mut c_void, 8, None).is_err() {
            return None;
        }
        let length = u16::from_le_bytes([dos[0], dos[1]]) as usize;
        let buffer = u32::from_le_bytes([dos[4], dos[5], dos[6], dos[7]]) as usize;
        if length == 0 || length > 32768 || buffer == 0 {
            return None;
        }
        let mut text = vec![0u16; length / 2];
        if ReadProcessMemory(h, buffer as *const c_void, text.as_mut_ptr() as *mut c_void, length, None).is_err() {
            return None;
        }
        Some(String::from_utf16_lossy(&text))
    }
}

fn read_peb_strings(h: HANDLE) -> Option<String> {
    if let Some(cwd) = read_peb32_cwd(h) {
        return Some(cwd);
    }
    unsafe {
        let mut pbi = PROCESS_BASIC_INFORMATION {
            ExitStatus: 0,
            PebBaseAddress: std::ptr::null_mut(),
            AffinityMask: 0,
            BasePriority: 0,
            UniqueProcessId: 0,
            InheritedFromUniqueProcessId: 0,
        };
        let mut needed = 0u32;
        let status = NtQueryInformationProcess(
            h.0,
            ProcessBasicInformation,
            &mut pbi as *mut _ as *mut c_void,
            std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut needed,
        );
        if !nt_ok(status) || pbi.PebBaseAddress.is_null() {
            return None;
        }

        let mut params_ptr: usize = 0;
        if ReadProcessMemory(
            h,
            (pbi.PebBaseAddress as usize + PEB_OFFSET_PROCESS_PARAMETERS) as *const c_void,
            &mut params_ptr as *mut _ as *mut c_void,
            std::mem::size_of::<usize>(),
            None,
        )
        .is_err()
            || params_ptr == 0
        {
            return None;
        }

        let mut params = std::mem::zeroed::<RTL_USER_PROCESS_PARAMETERS>();
        if ReadProcessMemory(
            h,
            params_ptr as *const c_void,
            &mut params as *mut _ as *mut c_void,
            std::mem::size_of::<RTL_USER_PROCESS_PARAMETERS>(),
            None,
        )
        .is_err()
        {
            return None;
        }

        Some(read_unicode_string(h, &params.CurrentDirectory.DosPath))
    }
}

fn read_unicode_string(h: HANDLE, us: &UNICODE_STRING) -> String {
    if us.Buffer.is_null() || us.Length == 0 || us.Length > 32768 {
        return String::new();
    }
    let mut buf = vec![0u16; (us.Length / 2) as usize];
    let ok = unsafe {
        ReadProcessMemory(
            h,
            us.Buffer as *const c_void,
            buf.as_mut_ptr() as *mut c_void,
            us.Length as usize,
            None,
        )
    }
    .is_ok();
    if !ok {
        return String::new();
    }
    String::from_utf16_lossy(&buf)
}

fn token_groups(token: HANDLE, cache: &DetailCache) -> Vec<String> {
    use windows::Win32::Security::{TOKEN_GROUPS, TokenGroups};
    const SE_GROUP_ENABLED: u32 = 0x4;
    const SE_GROUP_LOGON_ID: u32 = 0xC000_0000;
    const SE_GROUP_USE_FOR_DENY_ONLY: u32 = 0x10;
    unsafe {
        let mut size = 0u32;
        let _ = GetTokenInformation(token, TokenGroups, None, 0, &mut size);
        if size == 0 {
            return Vec::new();
        }
        let mut buf = vec![0u8; size as usize];
        if GetTokenInformation(token, TokenGroups, Some(buf.as_mut_ptr() as *mut c_void), size, &mut size).is_err() {
            return Vec::new();
        }
        let tg = &*(buf.as_ptr() as *const TOKEN_GROUPS);
        let groups = std::slice::from_raw_parts(tg.Groups.as_ptr(), tg.GroupCount as usize);
        let mut out = Vec::new();
        for g in groups {
            let attrs = g.Attributes;
            if attrs & SE_GROUP_LOGON_ID != 0 {
                continue;
            }
            let text = crate::sys::privilege::sid_text(g.Sid);
            let mut name = cache.lookup_sid(g.Sid, &text);
            if name.is_empty() {
                continue;
            }
            if attrs & SE_GROUP_USE_FOR_DENY_ONLY != 0 {
                name.push_str(" (deny only)");
            } else if attrs & SE_GROUP_ENABLED == 0 {
                name.push_str(" (disabled)");
            }
            out.push(name);
        }
        out.sort_by_key(|a| a.to_lowercase());
        out
    }
}

fn token_privileges(token: HANDLE) -> Vec<(String, bool)> {
    use windows::Win32::Security::{LookupPrivilegeNameW, SE_PRIVILEGE_ENABLED, TOKEN_PRIVILEGES, TokenPrivileges};
    unsafe {
        let mut size = 0u32;
        let _ = GetTokenInformation(token, TokenPrivileges, None, 0, &mut size);
        if size == 0 {
            return Vec::new();
        }
        let mut buf = vec![0u8; size as usize];
        if GetTokenInformation(token, TokenPrivileges, Some(buf.as_mut_ptr() as *mut c_void), size, &mut size).is_err() {
            return Vec::new();
        }
        let tp = &*(buf.as_ptr() as *const TOKEN_PRIVILEGES);
        let privs = std::slice::from_raw_parts(tp.Privileges.as_ptr(), tp.PrivilegeCount as usize);
        let mut out = Vec::new();
        for p in privs {
            let mut name = vec![0u16; 128];
            let mut len = name.len() as u32;
            if LookupPrivilegeNameW(PCWSTR::null(), &p.Luid, Some(PWSTR(name.as_mut_ptr())), &mut len).is_err() {
                continue;
            }
            out.push((from_wide(&name), p.Attributes.0 & SE_PRIVILEGE_ENABLED.0 != 0));
        }
        out.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        out
    }
}
