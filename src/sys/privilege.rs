use super::wide;
use windows::Win32::Foundation::{CloseHandle, HANDLE, LUID};
use windows::Win32::Security::{
    AdjustTokenPrivileges, GetTokenInformation, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW,
    SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_ELEVATION, TOKEN_PRIVILEGES, TOKEN_QUERY,
    TokenElevation,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::PCWSTR;

pub fn is_elevated() -> bool {
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut size = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        )
        .is_ok();
        let _ = CloseHandle(token);
        ok && elevation.TokenIsElevated != 0
    }
}

pub fn enable_privilege(name: &str) -> bool {
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
        .is_err()
        {
            return false;
        }
        let wname = wide(name);
        let mut luid = LUID::default();
        if LookupPrivilegeValueW(PCWSTR::null(), PCWSTR(wname.as_ptr()), &mut luid).is_err() {
            let _ = CloseHandle(token);
            return false;
        }
        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        let applied = AdjustTokenPrivileges(token, false, Some(&tp), 0, None, None).is_ok()
            && windows::Win32::Foundation::GetLastError().is_ok();
        let _ = CloseHandle(token);
        applied
    }
}

pub fn enable_debug_privilege() -> bool {
    let _ = enable_privilege("SeImpersonatePrivilege");
    enable_privilege("SeDebugPrivilege")
}

pub fn sid_text(sid: windows::Win32::Security::PSID) -> String {
    use windows::Win32::Foundation::LocalFree;
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    unsafe {
        let mut out = windows::core::PWSTR::null();
        if ConvertSidToStringSidW(sid, &mut out).is_err() || out.is_null() {
            return String::new();
        }
        let s = out.to_string().unwrap_or_default();
        let _ = LocalFree(Some(windows::Win32::Foundation::HLOCAL(out.0 as *mut std::ffi::c_void)));
        s
    }
}

pub fn current_user_sid() -> Option<String> {
    use windows::Win32::Security::{GetTokenInformation, TOKEN_USER, TokenUser};
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return None;
        }
        let mut size = 0u32;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut size);
        if size == 0 {
            let _ = CloseHandle(token);
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        let ok = GetTokenInformation(token, TokenUser, Some(buf.as_mut_ptr() as *mut _), size, &mut size).is_ok();
        let _ = CloseHandle(token);
        if !ok {
            return None;
        }
        let tu = &*(buf.as_ptr() as *const TOKEN_USER);
        let s = sid_text(tu.User.Sid);
        if s.is_empty() { None } else { Some(s) }
    }
}

pub fn desktop_user_sid() -> Option<String> {
    use windows::Win32::Security::{TOKEN_DUPLICATE, TOKEN_LINKED_TOKEN, TOKEN_USER, TokenLinkedToken, TokenUser};
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &mut token).is_err() {
            return None;
        }
        let mut linked = TOKEN_LINKED_TOKEN::default();
        let mut size = 0u32;
        let got = GetTokenInformation(token, TokenLinkedToken, Some(&mut linked as *mut _ as *mut _), std::mem::size_of::<TOKEN_LINKED_TOKEN>() as u32, &mut size).is_ok();
        let _ = CloseHandle(token);
        if !got || linked.LinkedToken.is_invalid() {
            return None;
        }
        let mut needed = 0u32;
        let _ = GetTokenInformation(linked.LinkedToken, TokenUser, None, 0, &mut needed);
        if needed == 0 {
            let _ = CloseHandle(linked.LinkedToken);
            return None;
        }
        let mut buf = vec![0u8; needed as usize];
        let ok = GetTokenInformation(linked.LinkedToken, TokenUser, Some(buf.as_mut_ptr() as *mut _), needed, &mut needed).is_ok();
        let _ = CloseHandle(linked.LinkedToken);
        if !ok {
            return None;
        }
        let tu = &*(buf.as_ptr() as *const TOKEN_USER);
        let s = sid_text(tu.User.Sid);
        if s.is_empty() { None } else { Some(s) }
    }
}

pub fn desktop_session_id() -> Option<String> {
    use windows::Win32::Security::{TOKEN_DUPLICATE, TOKEN_LINKED_TOKEN, TOKEN_STATISTICS, TokenLinkedToken, TokenStatistics};
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &mut token).is_err() {
            return None;
        }
        let mut linked = TOKEN_LINKED_TOKEN::default();
        let mut size = 0u32;
        let got = GetTokenInformation(token, TokenLinkedToken, Some(&mut linked as *mut _ as *mut _), std::mem::size_of::<TOKEN_LINKED_TOKEN>() as u32, &mut size).is_ok();
        let _ = CloseHandle(token);
        if !got || linked.LinkedToken.is_invalid() {
            return None;
        }
        let mut stats = TOKEN_STATISTICS::default();
        let ok = GetTokenInformation(linked.LinkedToken, TokenStatistics, Some(&mut stats as *mut _ as *mut _), std::mem::size_of::<TOKEN_STATISTICS>() as u32, &mut size).is_ok();
        let _ = CloseHandle(linked.LinkedToken);
        if ok { Some(format!("{:08x}-{:08x}", stats.AuthenticationId.HighPart, stats.AuthenticationId.LowPart)) } else { None }
    }
}
