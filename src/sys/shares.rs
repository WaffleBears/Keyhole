use super::{pw, wide};
use windows::Win32::NetworkManagement::NetManagement::NetApiBufferFree;
use windows::Win32::Storage::FileSystem::{FILE_INFO_3, NetFileClose, NetFileEnum, NetSessionDel, NetSessionEnum, NetShareDel, NetShareEnum, NetShareGetInfo, PERM_FILE_CREATE, PERM_FILE_READ, PERM_FILE_WRITE, SESS_GUEST, SESSION_INFO_502, SHARE_INFO_2, SHARE_INFO_502, STYPE_DEVICE, STYPE_DISKTREE, STYPE_IPC, STYPE_MASK, STYPE_PRINTQ};
use windows::core::PCWSTR;

#[derive(Clone, Debug)]
pub struct ShareRow {
    pub name: String,
    pub kind: String,
    pub path: String,
    pub remark: String,
    pub current_uses: u32,
    pub max_uses: u32,
    pub hidden: bool,
    pub share_acl: Vec<super::acl::AceRow>,
    pub share_acl_note: String,
    pub folder_acl: Vec<super::acl::AceRow>,
}

#[derive(Clone, Debug)]
pub struct SmbSession {
    pub client: String,
    pub user: String,
    pub opens: u32,
    pub connected_secs: u32,
    pub idle_secs: u32,
    pub guest: bool,
    pub transport: String,
}

#[derive(Clone, Debug)]
pub struct SmbFile {
    pub id: u32,
    pub path: String,
    pub user: String,
    pub share: String,
    pub read: bool,
    pub write: bool,
    pub create: bool,
    pub locks: u32,
    pub clients: Vec<String>,
}

#[derive(Default, Clone, Debug)]
pub struct SharesData {
    pub shares: Vec<ShareRow>,
    pub sessions: Vec<SmbSession>,
    pub files: Vec<SmbFile>,
    pub mounts: super::mounts::MountsData,
    pub error: Option<String>,
}

pub fn net_error(code: u32) -> String {
    match code {
        0 => String::new(),
        5 => "Windows refused access".into(),
        2114 => "the Server service is not running, so nothing is shared".into(),
        1722 | 1717 => "the Server service is not responding".into(),
        2310 => "the share does not exist".into(),
        2312 => "the session no longer exists".into(),
        2314 => "the file is no longer open".into(),
        2220 => "the group does not exist".into(),
        2221 => "the user does not exist".into(),
        2226 | 1376 | 1377 => "the member is not in that group".into(),
        1378 => "the member is already in that group".into(),
        1387 => "the member could not be found".into(),
        1388 => "that kind of account cannot be a member".into(),
        other => super::winerr::text(other).to_string(),
    }
}

pub fn enum_all<T, R>(mut call: impl FnMut(*mut *mut u8, &mut u32, &mut u32) -> u32, convert: impl Fn(&T) -> R) -> Result<Vec<R>, u32> {
    let mut out = Vec::new();
    loop {
        let mut buf: *mut u8 = std::ptr::null_mut();
        let mut read = 0u32;
        let mut total = 0u32;
        let rc = call(&mut buf, &mut read, &mut total);
        if rc != 0 && rc != 234 {
            if !buf.is_null() {
                unsafe {
                    NetApiBufferFree(Some(buf as *const _));
                }
            }
            return Err(rc);
        }
        if !buf.is_null() {
            let items = unsafe { std::slice::from_raw_parts(buf as *const T, read as usize) };
            out.extend(items.iter().map(&convert));
            unsafe {
                NetApiBufferFree(Some(buf as *const _));
            }
        }
        if rc != 234 || read == 0 {
            break;
        }
    }
    Ok(out)
}

pub fn enum_once<T, R>(call: impl FnOnce(*mut *mut u8, &mut u32, &mut u32) -> u32, convert: impl Fn(&T) -> R) -> Result<Vec<R>, u32> {
    let mut out = Vec::new();
    let mut buf: *mut u8 = std::ptr::null_mut();
    let mut read = 0u32;
    let mut total = 0u32;
    let rc = call(&mut buf, &mut read, &mut total);
    if !buf.is_null() {
        if rc == 0 || rc == 234 {
            let items = unsafe { std::slice::from_raw_parts(buf as *const T, read as usize) };
            out.extend(items.iter().map(&convert));
        }
        unsafe {
            NetApiBufferFree(Some(buf as *const _));
        }
    }
    if rc != 0 && rc != 234 {
        return Err(rc);
    }
    Ok(out)
}

pub fn list() -> SharesData {
    let mut data = SharesData::default();
    let mut resume = 0u32;
    let shares = enum_all(|buf, read, total| unsafe { NetShareEnum(PCWSTR::null(), 2, buf, u32::MAX, read, total, Some(&mut resume)) }, |s: &SHARE_INFO_2| {
        let name = pw(s.shi2_netname);
        let kind = match s.shi2_type.0 & STYPE_MASK.0 {
            x if x == STYPE_DISKTREE.0 => "Disk",
            x if x == STYPE_PRINTQ.0 => "Printer",
            x if x == STYPE_DEVICE.0 => "Device",
            x if x == STYPE_IPC.0 => "IPC",
            _ => "Other",
        };
        ShareRow { hidden: name.ends_with('$'), name, kind: kind.into(), path: pw(s.shi2_path), remark: pw(s.shi2_remark), current_uses: s.shi2_current_uses, max_uses: s.shi2_max_uses, share_acl: Vec::new(), share_acl_note: String::new(), folder_acl: Vec::new() }
    });
    match shares {
        Ok(mut list) => {
            for sh in &mut list {
                (sh.share_acl, sh.share_acl_note) = share_acl(&sh.name);
                if sh.kind == "Disk" && !sh.path.is_empty() {
                    sh.folder_acl = super::acl::folder_rows(&sh.path);
                }
            }
            data.shares = list;
        }
        Err(code) => {
            data.error = Some(net_error(code));
            return data;
        }
    }
    let mut resume_s = 0u32;
    let sessions = enum_all(|buf, read, total| unsafe { NetSessionEnum(PCWSTR::null(), PCWSTR::null(), PCWSTR::null(), 502, buf, u32::MAX, read, total, Some(&mut resume_s)) }, |s: &SESSION_INFO_502| SmbSession {
        client: pw(s.sesi502_cname).trim_start_matches('\\').to_string(),
        user: pw(s.sesi502_username),
        opens: s.sesi502_num_opens,
        connected_secs: s.sesi502_time,
        idle_secs: s.sesi502_idle_time,
        guest: s.sesi502_user_flags.0 & SESS_GUEST.0 != 0,
        transport: pw(s.sesi502_transport),
    });
    match sessions {
        Ok(list) => data.sessions = list,
        Err(code) => data.error = Some(format!("sessions: {}", net_error(code))),
    }
    let mut resume_f = 0usize;
    let files = enum_all(|buf, read, total| unsafe { NetFileEnum(PCWSTR::null(), PCWSTR::null(), PCWSTR::null(), 3, buf, u32::MAX, read, total, Some(&mut resume_f)) }, |f: &FILE_INFO_3| (f.fi3_id, pw(f.fi3_pathname), pw(f.fi3_username), f.fi3_permissions.0, f.fi3_num_locks));
    match files {
        Ok(list) => {
            let mut shares_by_len: Vec<&ShareRow> = data.shares.iter().filter(|s| !s.path.is_empty()).collect();
            shares_by_len.sort_by_key(|s| std::cmp::Reverse(s.path.len()));
            let mut files = Vec::new();
            for (id, path, user, perm, locks) in list {
                let lower = path.to_lowercase();
                let share = shares_by_len
                    .iter()
                    .find(|s| {
                        let root = s.path.to_lowercase().trim_end_matches('\\').to_string();
                        lower.starts_with(&root) && (lower.len() == root.len() || lower.as_bytes().get(root.len()) == Some(&b'\\'))
                    })
                    .map(|s| s.name.clone())
                    .unwrap_or_default();
                let clients: Vec<String> = data.sessions.iter().filter(|s| s.user.eq_ignore_ascii_case(&user)).map(|s| s.client.clone()).collect();
                files.push(SmbFile { id, path, user, share, read: perm & PERM_FILE_READ.0 != 0, write: perm & PERM_FILE_WRITE.0 != 0, create: perm & PERM_FILE_CREATE.0 != 0, locks, clients });
            }
            data.files = files;
        }
        Err(code) => data.error = Some(format!("open files: {}", net_error(code))),
    }
    data.mounts = super::mounts::list();
    data
}

fn share_acl(name: &str) -> (Vec<super::acl::AceRow>, String) {
    let w = wide(name);
    let mut buf: *mut u8 = std::ptr::null_mut();
    let rc = unsafe { NetShareGetInfo(PCWSTR::null(), PCWSTR(w.as_ptr()), 502, &mut buf) };
    if rc != 0 || buf.is_null() {
        return (Vec::new(), format!("permissions could not be read: {}", net_error(rc)));
    }
    let info = unsafe { &*(buf as *const SHARE_INFO_502) };
    let rows = super::acl::descriptor_rows(info.shi502_security_descriptor, super::acl::share_rights);
    unsafe {
        NetApiBufferFree(Some(buf as *const _));
    }
    match rows {
        None => (Vec::new(), String::new()),
        Some(rows) if rows.is_empty() => (rows, "No one (the permission list is empty)".to_string()),
        Some(rows) => (rows, String::new()),
    }
}

pub fn stop_sharing(name: &str) -> Result<(), String> {
    let w = wide(name);
    let rc = unsafe { NetShareDel(PCWSTR::null(), PCWSTR(w.as_ptr()), None) };
    if rc == 0 { Ok(()) } else { Err(net_error(rc)) }
}

pub fn close_file(id: u32) -> Result<(), String> {
    let rc = unsafe { NetFileClose(PCWSTR::null(), id) };
    if rc == 0 { Ok(()) } else { Err(net_error(rc)) }
}

pub fn disconnect(client: &str, user: &str) -> Result<(), String> {
    let c = wide(&if client.starts_with("\\\\") { client.to_string() } else { format!("\\\\{}", client) });
    let u = wide(user);
    let rc = unsafe { NetSessionDel(PCWSTR::null(), PCWSTR(c.as_ptr()), PCWSTR(u.as_ptr())) };
    if rc == 0 { Ok(()) } else { Err(net_error(rc)) }
}

pub fn computer_name() -> String {
    super::accounts::computer_name()
}
