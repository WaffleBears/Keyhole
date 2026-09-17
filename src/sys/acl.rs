use super::from_wide;
use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT};
use windows::Win32::Security::{ACCESS_ALLOWED_ACE, ACL, ACL_SIZE_INFORMATION, AclSizeInformation, DACL_SECURITY_INFORMATION, GetAce, GetAclInformation, GetSecurityDescriptorDacl, LookupAccountSidW, PSECURITY_DESCRIPTOR, PSID, SID_NAME_USE};
use windows::core::{PCWSTR, PWSTR};

#[derive(Clone, Debug)]
pub struct AceRow {
    pub who: String,
    pub sid: String,
    pub allow: bool,
    pub rights: String,
    pub inherited: bool,
}

pub fn sid_to_string(sid: PSID) -> String {
    let mut text = PWSTR::null();
    unsafe {
        if ConvertSidToStringSidW(sid, &mut text).is_err() {
            return String::new();
        }
        let s = text.to_string().unwrap_or_default();
        let _ = LocalFree(Some(HLOCAL(text.0 as *mut _)));
        s
    }
}

static NAMES: std::sync::OnceLock<parking_lot::Mutex<std::collections::HashMap<String, String>>> = std::sync::OnceLock::new();

pub fn sid_to_name(sid: PSID) -> String {
    let key = sid_to_string(sid);
    let cache = NAMES.get_or_init(|| parking_lot::Mutex::new(std::collections::HashMap::new()));
    if let Some(hit) = cache.lock().get(&key) {
        return hit.clone();
    }
    let value = lookup_sid_name(sid, &key);
    let mut c = cache.lock();
    if c.len() > 20_000 {
        c.clear();
    }
    c.insert(key, value.clone());
    value
}

fn lookup_sid_name(sid: PSID, text: &str) -> String {
    let mut name = vec![0u16; 256];
    let mut domain = vec![0u16; 256];
    let mut name_len = name.len() as u32;
    let mut domain_len = domain.len() as u32;
    let mut kind = SID_NAME_USE::default();
    let ok = unsafe { LookupAccountSidW(PCWSTR::null(), sid, Some(PWSTR(name.as_mut_ptr())), &mut name_len, Some(PWSTR(domain.as_mut_ptr())), &mut domain_len, &mut kind) }.is_ok();
    if !ok {
        return text.to_string();
    }
    let d = from_wide(&domain);
    let n = from_wide(&name);
    if d.is_empty() { n } else { format!("{}\\{}", d, n) }
}

pub fn share_rights(mask: u32) -> String {
    if mask & 0x001F01FF == 0x001F01FF {
        "Full control".into()
    } else if mask & 0x001301BF == 0x001301BF {
        "Change".into()
    } else if mask & 0x001200A9 == 0x001200A9 {
        "Read".into()
    } else {
        format!("0x{:X}", mask)
    }
}

pub fn file_rights(mask: u32) -> String {
    if mask & 0x001F01FF == 0x001F01FF || mask & 0x10000000 != 0 {
        "Full control".into()
    } else if mask & 0x001301BF == 0x001301BF {
        "Modify".into()
    } else if mask & 0x001200A9 == 0x001200A9 && mask & 0x00000116 != 0 {
        "Read, write".into()
    } else if mask & 0x001200A9 == 0x001200A9 {
        "Read & execute".into()
    } else if mask & 0x00000116 != 0 {
        "Write".into()
    } else if mask & 0x00120089 == 0x00120089 {
        "Read".into()
    } else {
        format!("0x{:X}", mask)
    }
}

fn dacl_rows(dacl: *const ACL, rights: fn(u32) -> String) -> Vec<AceRow> {
    let mut out = Vec::new();
    if dacl.is_null() {
        return out;
    }
    let mut info = ACL_SIZE_INFORMATION::default();
    if unsafe { GetAclInformation(dacl, &mut info as *mut _ as *mut _, std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32, AclSizeInformation) }.is_err() {
        return out;
    }
    for i in 0..info.AceCount {
        let mut ace: *mut std::ffi::c_void = std::ptr::null_mut();
        if unsafe { GetAce(dacl, i, &mut ace) }.is_err() || ace.is_null() {
            continue;
        }
        let header = unsafe { &*(ace as *const ACCESS_ALLOWED_ACE) };
        let kind = header.Header.AceType;
        if kind != 0 && kind != 1 {
            continue;
        }
        let sid = PSID(unsafe { (ace as *mut u8).add(std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart)) } as *mut _);
        out.push(AceRow { who: sid_to_name(sid), sid: sid_to_string(sid), allow: kind == 0, rights: rights(header.Mask), inherited: header.Header.AceFlags & 0x10 != 0 });
    }
    out
}

pub fn descriptor_rows(sd: PSECURITY_DESCRIPTOR, rights: fn(u32) -> String) -> Option<Vec<AceRow>> {
    if sd.is_invalid() {
        return None;
    }
    let mut present = windows::core::BOOL(0);
    let mut defaulted = windows::core::BOOL(0);
    let mut dacl: *mut ACL = std::ptr::null_mut();
    if unsafe { GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted) }.is_err() || present.0 == 0 || dacl.is_null() {
        return None;
    }
    Some(dacl_rows(dacl, rights))
}

pub fn folder_rows(path: &str) -> Vec<AceRow> {
    let w = super::wide(path);
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    let rc = unsafe { GetNamedSecurityInfoW(PCWSTR(w.as_ptr()), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, None, None, Some(&mut dacl), None, &mut sd) };
    if rc.0 != 0 {
        return Vec::new();
    }
    let rows = dacl_rows(dacl, file_rights);
    unsafe {
        let _ = LocalFree(Some(HLOCAL(sd.0)));
    }
    rows
}

pub fn share_summary(name: &str, rows: &[AceRow], note: &str) -> String {
    if !note.is_empty() {
        return note.to_string();
    }
    if rows.is_empty() {
        return if name.ends_with('$') { "Administrators only (built-in)".to_string() } else { "Everyone: Full control (no share permissions set)".to_string() };
    }
    summary(rows)
}

pub fn summary(rows: &[AceRow]) -> String {
    let mut parts: Vec<String> = Vec::new();
    for r in rows {
        let who = r.who.rsplit('\\').next().unwrap_or(&r.who);
        let piece = format!("{}{}: {}", if r.allow { "" } else { "DENY " }, who, r.rights);
        if !parts.contains(&piece) {
            parts.push(piece);
        }
    }
    parts.join("  ·  ")
}
