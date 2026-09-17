use crate::sys::{from_wide, pw, wide};
use parking_lot::Mutex;
use std::ffi::c_void;
use std::time::{Duration, Instant};
use windows::Win32::NetworkManagement::WNet::{
    NETRESOURCEW, RESOURCE_CONNECTED, RESOURCETYPE_DISK, WNetCloseEnum, WNetEnumResourceW, WNetGetConnectionW, WNetOpenEnumW,
};
use windows::Win32::Foundation::HANDLE;
use windows::core::{PCWSTR, PWSTR};

#[derive(Clone, Default, serde::Serialize)]
pub struct NetConnection {
    pub local: String,
    pub remote: String,
    pub provider: String,
    pub visible: bool,
    pub desktop: bool,
}

static CACHE: Mutex<Option<(Vec<NetConnection>, Instant)>> = Mutex::new(None);
const TTL: Duration = Duration::from_secs(30);

pub fn connections() -> Vec<NetConnection> {
    let mut cache = CACHE.lock();
    if let Some((list, at)) = cache.as_ref()
        && at.elapsed() < TTL {
            return list.clone();
        }
    let fresh = enumerate();
    *cache = Some((fresh.clone(), Instant::now()));
    fresh
}

#[derive(Clone, Debug)]
pub struct SessionMapping {
    pub session: String,
    pub local: String,
    pub remote: String,
}

pub fn object_dir_entries(path: &str) -> Vec<(String, String)> {
    use crate::nt::{DIRECTORY_QUERY, NtClose, NtOpenDirectoryObject, NtQueryDirectoryObject, OBJECT_DIRECTORY_INFORMATION, attributes, nt_ok, unicode};
    let mut out = Vec::new();
    let w = wide(path);
    let name = unicode(&w);
    let attrs = attributes(&name, std::ptr::null_mut());
    unsafe {
        let mut h: *mut c_void = std::ptr::null_mut();
        if !nt_ok(NtOpenDirectoryObject(&mut h, DIRECTORY_QUERY, &attrs)) {
            return out;
        }
        let mut buf = vec![0u8; 64 * 1024];
        let mut context = 0u32;
        let mut restart = 1u8;
        loop {
            let mut returned = 0u32;
            let status = NtQueryDirectoryObject(h, buf.as_mut_ptr() as *mut c_void, buf.len() as u32, 0, restart, &mut context, &mut returned);
            restart = 0;
            if !nt_ok(status) || status == 0x8000001Au32 as i32 || returned == 0 {
                break;
            }
            let mut p = buf.as_ptr() as *const OBJECT_DIRECTORY_INFORMATION;
            let end = buf.as_ptr().add((returned as usize).min(buf.len()));
            loop {
                if (p as *const u8).add(std::mem::size_of::<OBJECT_DIRECTORY_INFORMATION>()) > end {
                    break;
                }
                let e = &*p;
                if e.Name.Length == 0 || e.Name.Buffer.is_null() {
                    break;
                }
                out.push((e.Name.to_string(), e.TypeName.to_string()));
                p = p.add(1);
            }
            if status != 0x105 {
                break;
            }
        }
        let _ = NtClose(h);
    }
    out
}

pub fn symlink_target(path: &str) -> Option<String> {
    use crate::nt::{NtClose, NtOpenSymbolicLinkObject, NtQuerySymbolicLinkObject, SYMBOLIC_LINK_QUERY, attributes, nt_ok, unicode};
    let w = wide(path);
    let name = unicode(&w);
    let attrs = attributes(&name, std::ptr::null_mut());
    unsafe {
        let mut h: *mut c_void = std::ptr::null_mut();
        if !nt_ok(NtOpenSymbolicLinkObject(&mut h, SYMBOLIC_LINK_QUERY, &attrs)) {
            return None;
        }
        let mut target = vec![0u16; 1024];
        let mut us = unicode(&target);
        us.Length = 0;
        us.MaximumLength = (target.len() * 2) as u16;
        us.Buffer = target.as_mut_ptr();
        let mut returned = 0u32;
        let ok = nt_ok(NtQuerySymbolicLinkObject(h, &mut us, &mut returned));
        let _ = NtClose(h);
        if ok { Some(us.to_string()) } else { None }
    }
}

pub fn session_mappings() -> Vec<SessionMapping> {
    let mut out = Vec::new();
    for (session, kind) in object_dir_entries("\\Sessions\\0\\DosDevices") {
        if kind != "Directory" {
            continue;
        }
        for (letter, kind) in object_dir_entries(&format!("\\Sessions\\0\\DosDevices\\{}", session)) {
            if kind != "SymbolicLink" || letter.len() != 2 || !letter.ends_with(':') {
                continue;
            }
            let Some(target) = symlink_target(&format!("\\Sessions\\0\\DosDevices\\{}\\{}", session, letter)) else { continue };
            let lower = target.to_lowercase();
            let remote = if let Some(rest) = lower.strip_prefix("\\device\\lanmanredirector\\") {
                super::devpath::unc_from_redirector(&target[target.len() - rest.len()..])
            } else if let Some(rest) = lower.strip_prefix("\\device\\mup\\") {
                format!("\\\\{}", &target[target.len() - rest.len()..])
            } else if lower.contains("\\device\\") && lower.contains("network") {
                target.clone()
            } else {
                continue;
            };
            out.push(SessionMapping { session: session.clone(), local: letter.to_uppercase(), remote });
        }
    }
    out
}

pub fn own_session_id() -> String {
    use windows::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_STATISTICS, TokenStatistics};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return String::new();
        }
        let mut stats = TOKEN_STATISTICS::default();
        let mut size = 0u32;
        let ok = GetTokenInformation(token, TokenStatistics, Some(&mut stats as *mut _ as *mut _), std::mem::size_of::<TOKEN_STATISTICS>() as u32, &mut size).is_ok();
        let _ = windows::Win32::Foundation::CloseHandle(token);
        if ok { format!("{:08x}-{:08x}", stats.AuthenticationId.HighPart, stats.AuthenticationId.LowPart) } else { String::new() }
    }
}

pub fn connections_fresh() -> Vec<NetConnection> {
    let fresh = enumerate();
    *CACHE.lock() = Some((fresh.clone(), Instant::now()));
    fresh
}

pub fn remote_of(letter: &str) -> String {
    let key = letter.trim_end_matches('\\').to_uppercase();
    if let Some(c) = connections().into_iter().find(|c| c.local.eq_ignore_ascii_case(&key)) {
        return c.remote;
    }
    let w = wide(&key);
    let mut buf = vec![0u16; 1024];
    let mut len = buf.len() as u32;
    let rc = unsafe { WNetGetConnectionW(PCWSTR(w.as_ptr()), Some(PWSTR(buf.as_mut_ptr())), &mut len) };
    if rc.0 == 0 { from_wide(&buf) } else { String::new() }
}

pub fn share_root(unc: &str) -> String {
    let body = unc.trim_start_matches('\\');
    let mut parts = body.splitn(3, '\\');
    match (parts.next(), parts.next()) {
        (Some(server), Some(share)) if !server.is_empty() && !share.is_empty() => format!("\\\\{}\\{}", server, share),
        (Some(server), _) if !server.is_empty() => format!("\\\\{}", server),
        _ => String::new(),
    }
}

fn enumerate() -> Vec<NetConnection> {
    let mut out = wnet_connected();
    let own = own_session_id();
    for m in session_mappings() {
        if m.session == own || out.iter().any(|o| o.local.eq_ignore_ascii_case(&m.local)) {
            continue;
        }
        out.push(NetConnection { local: m.local, remote: m.remote, provider: "Microsoft Windows Network".into(), visible: true, desktop: true });
    }
    for (letter, remote, provider) in persistent_mappings() {
        if !out.iter().any(|c| c.local.eq_ignore_ascii_case(&letter)) {
            out.push(NetConnection { local: letter, remote, provider, visible: false, desktop: false });
        }
    }
    out.sort_by(|a, b| a.local.cmp(&b.local).then(a.remote.to_lowercase().cmp(&b.remote.to_lowercase())));
    out.dedup_by(|a, b| a.local == b.local && a.remote.eq_ignore_ascii_case(&b.remote));
    out
}

fn wnet_connected() -> Vec<NetConnection> {
    let mut out = Vec::new();
    unsafe {
        let mut h = HANDLE::default();
        if WNetOpenEnumW(RESOURCE_CONNECTED, RESOURCETYPE_DISK, windows::Win32::NetworkManagement::WNet::WNET_OPEN_ENUM_USAGE(0), None, &mut h).0 != 0 {
            return out;
        }
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let mut count = u32::MAX;
            let mut size = buf.len() as u32;
            let rc = WNetEnumResourceW(h, &mut count, buf.as_mut_ptr() as *mut c_void, &mut size);
            if rc.0 != 0 {
                break;
            }
            let items = std::slice::from_raw_parts(buf.as_ptr() as *const NETRESOURCEW, count as usize);
            for r in items {
                let remote = pw(r.lpRemoteName);
                if remote.is_empty() {
                    continue;
                }
                out.push(NetConnection {
                    local: pw(r.lpLocalName).trim_end_matches('\\').to_uppercase(),
                    remote,
                    provider: pw(r.lpProvider),
                    visible: true,
                    desktop: false,
                });
            }
        }
        let _ = WNetCloseEnum(h);
    }
    out
}

pub fn persistent_letters() -> Vec<String> {
    persistent_mappings().into_iter().map(|(l, _, _)| l).collect()
}

fn persistent_mappings() -> Vec<(String, String, String)> {
    use crate::sys::reg;
    use windows::Win32::System::Registry::HKEY_CURRENT_USER;
    let mut out = Vec::new();
    let Some(key) = reg::open(HKEY_CURRENT_USER, "Network") else { return out };
    for sub in reg::subkeys(&key) {
        if sub.len() != 1 || !sub.as_bytes()[0].is_ascii_alphabetic() {
            continue;
        }
        let Some(k) = reg::open(HKEY_CURRENT_USER, &format!("Network\\{}", sub)) else { continue };
        let Some(remote) = reg::string(&k, "RemotePath") else { continue };
        let provider = reg::string(&k, "ProviderName").unwrap_or_default();
        out.push((format!("{}:", sub.to_uppercase()), remote, provider));
    }
    out
}
